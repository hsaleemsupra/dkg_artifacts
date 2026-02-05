use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use log::{debug, error, info, trace};
use socrypto::{Identity};
use soruntime::RuntimeError;
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use crate::codeword::Codeword;
use crate::messages::DeliverProtocolMessage;
use crate::node::DeliverNode;
use crate::types::deliver_event::{DeliverEvent, DeliverEventData, DeliverEventType};

pub struct WaitForMsgs;

#[allow(clippy::too_many_arguments)]
impl DeliverNode<WaitForMsgs> {

    pub fn new(
        node: Identity,
        num_nodes: u32,
        f_byzantine: u32,
        mut committee_members: Vec<Identity>,
    ) -> DeliverNode<WaitForMsgs> {
        debug!("Deliver node:{} with config: n: {:?}, f: {:?}", node, num_nodes, f_byzantine);

        //generate node index using node pubkey sorted order
        committee_members.sort_unstable_by(|a_pk, b_pk| a_pk.cmp(b_pk));
        let committee_members: Vec<_> = committee_members
            .into_iter()
            .enumerate()
            .map(|(index, identity)| (index as u32, identity))
            .collect();

        let committee_members: BTreeMap<Identity, u32> = committee_members
            .into_iter()
            .map(|(index, identity)| {
                (
                    identity,
                    index
                )
            })
            .collect();

        debug!(
            "Start Deliver with committee:{}",
            committee_members
                .keys()
                .enumerate()
                .map(|(index, n)| format!("{index}:{}/", n))
                .fold(String::new(), |s, v| s + &v)
        );

        DeliverNode {
            node,
            num_of_nodes: num_nodes,
            f_byzantine,
            committee: committee_members,
            code_words: BTreeMap::new(),
            reconstructed_data: BTreeMap::new(),
            state: PhantomData,
        }
    }

    pub(crate) fn handle_individual_codewords(
        &mut self,
        codewords: &Vec<Codeword>,
    ) -> Vec<Action<DeliverEventData, DeliverEventType>> {
        info!("Generated {} individual codewords node:{}", codewords.len(), self.node);

        let this_node = self.identity();
        let mut actions = Vec::new();

        codewords.iter().for_each( |codeword|{
            let target_node =
                self.get_node_identity_by_index(codeword.chunk_with_merkle_proof.get_chunk_index() as u32).unwrap();

            if target_node == this_node {
                self.handle_own_codeword(codeword.clone());
                actions.push(Action::SendMessage(DeliverProtocolMessage::Echo(codeword.clone()).to_vec()));
            }
            else{
                actions.push(Action::SendMessageTo(target_node, DeliverProtocolMessage::Codeword(codeword.clone()).to_vec()));
            }
        });

        actions
    }

    fn handle_own_codeword(&mut self, codeword: Codeword) {
        self.code_words.insert(codeword.merkle_root.clone(), BTreeSet::new());
        let msg_codewords = self.code_words.get_mut(&codeword.merkle_root).unwrap();
        msg_codewords.insert(codeword.clone());
    }
}

impl Subscriber<DeliverEventData, DeliverEventType> for DeliverNode<WaitForMsgs> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data =DeliverEventData, EventType =DeliverEventType>,
        _event_register: &mut dyn EventRegister<DeliverEventData, EventType =DeliverEventType>,
    ) -> (
        Box<dyn Subscriber<DeliverEventData, DeliverEventType>>,
        Result<Vec<Action<DeliverEventData, DeliverEventType>>, RuntimeError>,
    ) {

        match event.data(){
            DeliverEventData::ReceiveNewDataToBroadcast(data) => {
                if data.is_empty(){
                    (self, Ok(vec![]))
                }
                else {
                    let node = self.node;
                    if let Ok(data_codewords) = self.generate_data_codewords(&data){
                        info!("DeliverNode: {} received new data to broadcast", node);
                        let mut post_actions = self.handle_individual_codewords(&data_codewords);
                        info!("DeliverNode: {} notify return codeword actions: {}", node, post_actions.len() );

                        //since we have the data already, we can add it to reconstructed data
                        let root = data_codewords[0].clone().merkle_root.clone();
                        self.reconstructed_data.insert(root.clone(), data.clone());
                        let data_reconstructed_event = DeliverEvent::create_data_reconstructed_event(&root, data);
                        post_actions.push(Action::SendEventOut(Box::new(data_reconstructed_event)));
                        info!("DeliverNode: {} reconstructed data: {}", node, root );

                        (self, Ok(post_actions))
                    }
                    else{
                        (self, Err(RuntimeError::EventError("Error during generate_data_codewords".to_string())))
                    }
                }
            }

            DeliverEventData::ReceiveCodeword(codeword) => {

                info!("DeliverNode: {:?} State ReceiveCodeword", self.node);

                let res = self.consume_codeword(codeword.clone());
                if let Ok(flag) = res{
                    let mut post_actions = Vec::new();
                    if flag{
                        post_actions.push(Action::SendMessage(DeliverProtocolMessage::Echo(codeword.clone()).to_vec()));
                    }
                    (self, Ok(post_actions))
                }
                else{
                    error!("DeliverNode: {:?} Error during consume_codeword: {:?}", self.node, res.err());
                    (self, Ok(vec![]))
                }
            }

            DeliverEventData::ReceiveEcho(codeword) => {

                info!("DeliverNode: {:?} State ReceiveEcho", self.node);

                let res = self.consume_codeword(codeword.clone());
                if let Ok(_) = res{
                    let mut post_actions = Vec::new();

                    // try to reconstruct data from codewords
                    let res = self.try_reconstruct_data(codeword.merkle_root.clone());
                    if let Ok(flag) = res{
                        if flag {
                            info!("DeliverNode: Node: {:?} reconstructed data {:?} ", self.node, codeword.merkle_root.clone());
                            let reconstructed_data = self.reconstructed_data.get(&codeword.merkle_root).unwrap();
                            let data_reconstructed_event = DeliverEvent::create_data_reconstructed_event(&codeword.merkle_root, reconstructed_data);
                            post_actions.push(Action::SendEventOut(Box::new(data_reconstructed_event)));
                        }
                    }
                    else{
                        error!("DeliverNode: {:?} Error during try_reconstruct_data: {:?}", self.node, res.err());
                    }
                    (self, Ok(post_actions))
                }
                else{
                    error!("DeliverNode: {:?} Error during consume_codeword: {:?}", self.node, res.err());
                    (self, Ok(vec![]))
                }
            }
            _ => {
                error!(
                    "Deliver Event not handled in waiting_for_msgs state:{:?}",
                    event.event_type()
                );
                (self, Ok(vec![]))
            }
        }
    }
    fn get_permanent_event_to_register(&self) -> Vec<DeliverEventType> {
        vec![
            DeliverEventType::ReceivedNewDataToBroadcast,
            DeliverEventType::ReceivedCodeword,
            DeliverEventType::ReceivedEcho,
        ]
    }
    fn get_id(&self) -> usize {
        trace!("Subscriber WaitForMsgs get_id");
        0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
