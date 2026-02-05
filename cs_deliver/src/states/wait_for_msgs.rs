use std::any::Any;
use std::collections::{BTreeMap};
use std::marker::PhantomData;
use log::{debug, error, info, trace};
use socrypto::{Identity};
use soruntime::RuntimeError;
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use crate::codeword::CodewordWithSignature;
use crate::messages::CSDeliverProtocolMessage;
use crate::node::CSDeliverNode;
use crate::types::deliver_data::CSDeliverData;
use crate::types::deliver_event::{CSDeliverEvent, CSDeliverEventData, CSDeliverEventType};
use ed25519_dalek::{
    SigningKey as SecretKey,
    VerifyingKey as PublicKey,
};

pub struct WaitForMsgs;

#[allow(clippy::too_many_arguments)]
impl CSDeliverNode<WaitForMsgs> {

    pub fn new(
        node: Identity,
        num_nodes: u32,
        f_byzantine: u32,
        fc_byzantine: u32,
        secret_key: SecretKey,
        mut committee_members: Vec<(Identity, PublicKey)>,
    ) -> CSDeliverNode<WaitForMsgs> {
        debug!("CS Deliver node:{} with config: n: {:?}, f_byzantine: {:?}, fc_byzantine: {:?}", node, num_nodes, f_byzantine, fc_byzantine);

        //generate node index using node pubkey sorted order
        committee_members.sort_unstable_by(|(a_pk, _a_vk), (b_pk, _b_vk)| a_pk.cmp(b_pk));
        let committee_members: Vec<_> = committee_members
            .into_iter()
            .enumerate()
            .map(|(index, (identity,vk))| (index as u32, (identity,vk)))
            .collect();

        let committee_members: BTreeMap<Identity, CSDeliverData> = committee_members
            .into_iter()
            .map(|(index, (identity,vk))| {
                (
                    identity,
                    CSDeliverData::new(
                        index,
                        vk
                    ),
                )
            })
            .collect();

        debug!(
            "Start CSDeliverNode with committee:{}",
            committee_members
                .values()
                .enumerate()
                .map(|(index, n)| format!("{index}:{}/", n.node_number))
                .fold(String::new(), |s, v| s + &v)
        );

        CSDeliverNode {
            node,
            num_of_nodes: num_nodes,
            f_byzantine,
            fc_byzantine,
            signing_key: secret_key,
            committee: committee_members,
            code_words: BTreeMap::new(),
            verified_code_words: BTreeMap::new(),
            reconstructed_data: Vec::new(),
            state: PhantomData,
        }
    }

    pub(crate) fn handle_individual_codewords(
        &mut self,
        codewords: Vec<CodewordWithSignature>,
    ) -> Vec<Action<CSDeliverEventData, CSDeliverEventType>> {
        info!("CSDeliverNode Generated {} individual codewords node:{}", codewords.len(), self.node);

        let this_node = self.identity();
        let mut actions = Vec::new();

        codewords.iter().for_each( |codeword|{
            let target_node =
                self.get_node_identity_by_index(codeword.codeword.chunk_with_merkle_proof.get_chunk_index() as u32).unwrap();

            if target_node == this_node {
                if let Some(codeword) = self.handle_own_codeword(codeword.clone()){
                    actions.push(Action::SendMessage(CSDeliverProtocolMessage::Echo(codeword.clone()).to_vec()));
                }
            }
            else{
                actions.push(Action::SendMessageTo(target_node, CSDeliverProtocolMessage::Codeword(codeword.clone()).to_vec()));
            }
        });

        actions
    }

    fn handle_own_codeword(&mut self, codeword: CodewordWithSignature) -> Option<CodewordWithSignature>{
        self.consume_codeword(codeword).unwrap()
    }

    fn try_reconstruction(&mut self) -> Option<Action<CSDeliverEventData, CSDeliverEventType>> {

        if let Ok(data_reconstructed) = self.try_reconstruct_data(){
            if data_reconstructed{
                info!("DeliverNode: {} data reconstruction successful", self.node);
                let reconstructed_data = self.reconstructed_data.clone();
                let data_reconstructed_event = CSDeliverEvent::create_data_reconstructed_event(&reconstructed_data);
                return Some(Action::SendEventOut(Box::new(data_reconstructed_event)));
            }
        }
        None
    }

    fn handle_received_codeword(&mut self, codeword: &CodewordWithSignature, is_echo_msg: bool) -> Vec<Action<CSDeliverEventData, CSDeliverEventType>> {
        let res = self.consume_codeword(codeword.clone());

        if let Ok(codeword) = res{
            let mut post_actions = Vec::new();
            if !is_echo_msg{
                //if we have received f_c+1 identical codewords
                if codeword.is_some(){
                    post_actions.push(Action::SendMessage(CSDeliverProtocolMessage::Echo(codeword.unwrap()).to_vec()));
                }
            }

            if let Some(action) = self.try_reconstruction(){
                post_actions.push(action);
            }

            post_actions
        }
        else{
            error!("CSDeliverNode: {:?} Error during consume_codeword: {:?}", self.node, res.err());
            vec![]
        }
    }
}

impl Subscriber<CSDeliverEventData, CSDeliverEventType> for CSDeliverNode<WaitForMsgs> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data = CSDeliverEventData, EventType = CSDeliverEventType>,
        _event_register: &mut dyn EventRegister<CSDeliverEventData, EventType =CSDeliverEventType>,
    ) -> (
        Box<dyn Subscriber<CSDeliverEventData, CSDeliverEventType>>,
        Result<Vec<Action<CSDeliverEventData, CSDeliverEventType>>, RuntimeError>,
    ) {

        match event.data(){
            CSDeliverEventData::ReceiveNewDataToBroadcast(data) => {
                if data.is_empty(){
                    (self, Ok(vec![]))
                }
                else {
                    let node = self.node;
                    if let Ok(data_codewords) = self.generate_data_codewords(&data){
                        let mut post_actions = self.handle_individual_codewords(data_codewords);
                        info!("CSDeliverNode: {} notify return codeword actions: {}", node, post_actions.len() );
                        info!("CSDeliverNode: {} received new data to broadcast", node );

                        if let Some(action) = self.try_reconstruction(){
                            post_actions.push(action);
                        }
                        (self, Ok(post_actions))
                    }
                    else{
                        (self, Err(RuntimeError::EventError("Error during generate_data_codewords".to_string())))
                    }
                }
            }

            CSDeliverEventData::ReceiveCodeword(codeword) => {
                info!("CSDeliverNode: {:?} State ReceiveCodeword", self.node);
                let post_actions = self.handle_received_codeword(codeword, false);
                (self, Ok(post_actions))
            }

            CSDeliverEventData::ReceiveEcho(codeword) => {
                info!("CSDeliverNode: {:?} State ReceiveEcho", self.node);
                let post_actions = self.handle_received_codeword(codeword, true);
                (self, Ok(post_actions))
            }
            _ => {
                info!(
                    "CSDeliverNode Event not handled in waiting_for_msgs state:{:?}",
                    event.event_type()
                );
                (self, Ok(vec![]))
            }
        }
    }
    fn get_permanent_event_to_register(&self) -> Vec<CSDeliverEventType> {
        vec![
            CSDeliverEventType::ReceivedNewDataToBroadcast,
            CSDeliverEventType::ReceivedCodeword,
            CSDeliverEventType::ReceivedEcho,
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
