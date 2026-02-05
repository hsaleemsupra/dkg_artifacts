use crate::sosmr_types::SignedSmrTransaction;
use std::any::Any;
use log::{info, trace};
use soruntime::RuntimeError;
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use crate::{DkgEvent, DkgEventData, DkgEventType, DkgNode};
use crate::class_group_dkg::messages::DKGProtocolMessage;
use crate::class_group_dkg::node;
use crate::class_group_dkg::states::done::Done;
use crate::class_group_dkg::states::vote_dkg_meta::VoteDKGMeta;
use crate::class_group_dkg::states::wait_aggregation::WaitAggregation;

pub struct VoteDealingMeta;

/// Only family node can be in this state

impl DkgNode<VoteDealingMeta> {

    pub fn to_vote_dkg_meta(self) -> DkgNode<VoteDKGMeta> {
        info!("DkgNode node:{} to_vote_dkg_meta", self.node,);

        DkgNode {
            ..node::change_state(self)
        }
    }

    pub fn to_done(self) -> DkgNode<Done> {
        info!("DkgNode node:{} to_done", self.node,);

        DkgNode {
            ..node::change_state(self)
        }
    }

    pub fn to_wait_aggregation(self) -> DkgNode<WaitAggregation> {
        info!("DkgNode node:{} wait_aggregation", self.node);
        DkgNode {
            ..node::change_state(self)
        }
    }
}

impl Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction> for DkgNode<VoteDealingMeta> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
        _event_register: &mut dyn EventRegister<DkgEventData, SignedSmrTransaction, EventType = DkgEventType>,
    ) -> (
        Box<dyn Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction>>,
        Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, RuntimeError>,
    ) {
        trace!("DkgNode<VoteDealingMeta> notify");

        if let Some(cs_deliver_event) = self.convert_dkg_event_to_cs_deliver_event(event) {
            if let Some(cs_deliver_processor) = self.cs_deliver_processor.as_mut(){
                let cs_deliver_actions = cs_deliver_processor.process_event(Box::new(cs_deliver_event));
                let (converted_actions, _) = self.convert_cs_deliver_actions_to_dkg(cs_deliver_actions);
                return (self, Ok(converted_actions));
            }
        }

        if let DkgEventData::ReceiveDealing(node_id, dealing) = event.data() {
            info!("DkgNode<VoteDealingMeta> received dealing. Sending back signature");
            match self.add_dealing(*node_id, dealing) {
                Ok(val) => {
                        return (
                            self,
                            Ok(vec![Action::SendMessageTo(*node_id, val.to_vec())]),
                        );
                }
                Err(err) => {
                    return (
                        self,
                        Err(RuntimeError::EventError(format!(
                            "Error during add_dealing:{}",
                            err
                        ))),
                    );
                }
            }
        }
        else if let DkgEventData::ReceiveVoteOnDealingMeta(node_id, dealing_meta_signature) = event.data() {

            info!("DkgNode<VoteDealingMeta> received dealing meta vote");
            match self.add_dealing_meta_signature(*node_id, dealing_meta_signature){
                Ok(result) => {
                    if let Some(dkg_meta) = result{
                        info!("DkgNode<VoteDealingMeta> Sending DKG Meta to Clan");

                        let mut post_actions = Vec::new();
                        let dkg_clan_nodes = self.get_all_dkg_clan_nodes();
                        dkg_clan_nodes.iter().for_each(|clan_node_id| {
                            post_actions.push(
                                Action::SendMessageTo(
                                    *clan_node_id,
                                    DKGProtocolMessage::DKGMeta(dkg_meta.clone()).to_vec(),
                                )
                            );
                        });
                        let vote_dkg_meta = self.to_vote_dkg_meta();

                        return (
                            Box::new(vote_dkg_meta),
                            Ok(post_actions),
                        );
                    }
                }
                Err(err) => {
                    return (
                        self,
                        Err(RuntimeError::GeneralError(format!(
                            "Error during add dealing meta signature:{}",
                            err
                        ))),
                    );
                }
            }
        }
        else if let DkgEventData::ReceiveAggregateEncryptedShareEvent(node_id, enc_share) = event.data() {
            info!("DkgNode<VoteDealingMeta> received enc share");
            match self.add_aggregate_encrypted_share(*node_id, enc_share){
                true => {
                    let done = self.to_done();
                    return (Box::new(done), Ok(vec![
                        Action::SendEventOut(Box::new(
                            DkgEvent::new_end_dkg_event(),
                        ))
                    ]))
                },
                false => return (self, Ok(vec![])),
            }
        }
        else if let DkgEventData::ReceiveDKGMetaQC(dkg_meta_qc) = event.data() {
            info!("DkgNode<VoteDealingMeta> received dkg meta from SMR");
            //todo: fix this
            let first_family_node = self.get_first_family_node_index();
            if dkg_meta_qc.family_node_index == first_family_node {
                info!("DkgNode<VoteDealingMeta> Adding DKG Meta SMR, family node: {}", dkg_meta_qc.family_node_index);

                match self.add_dkg_meta_qc(dkg_meta_qc) {
                    Ok(()) => {
                        let wait_aggregation = self.to_wait_aggregation();
                        return (Box::new(wait_aggregation), Ok(vec![]));
                    }
                    Err(err) => {
                        return (
                            self,
                            Err(RuntimeError::EventError(format!(
                                "Error during add DKG MetaQC:{}",
                                err
                            ))),
                        )
                    }
                }
            }
        } else {
            trace!(
                "Event not handled in aggregate state:{:?}",
                event.event_type()
            );
        }
        (self, Ok(vec![]))
    }

    fn get_permanent_event_to_register(&self) -> Vec<DkgEventType> {
        vec![
            DkgEventType::ReceivedCSDeliverEvent,
            DkgEventType::ReceivedDealingEvent,
            DkgEventType::ReceivedVoteOnDealingMeta,
            DkgEventType::ReceivedDKGMetaQC,
            DkgEventType::ReceivedAggregateEncryptedShareEvent
        ]
    }

    fn get_id(&self) -> usize {
        2
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
