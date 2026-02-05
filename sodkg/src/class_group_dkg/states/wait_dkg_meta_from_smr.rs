use crate::sosmr_types::SignedSmrTransaction;
use std::any::Any;
use log::{error, info, trace};
use nidkg_helper::cgdkg::validate_and_sign_encrypted_dealing;
use soruntime::RuntimeError;
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use crate::{DkgEvent, DkgEventData, DkgEventType, DkgNode};
use crate::class_group_dkg::messages::DKGProtocolMessage;
use crate::class_group_dkg::node;
use crate::class_group_dkg::states::done::Done;
use crate::class_group_dkg::states::wait_aggregation::WaitAggregation;

pub struct WaitDKGMetaFromSMR;

/// Clan node receives dealings from other clan nodes and verified dealer lists from various family nodes
/// The clan node sends their vote on a verified dealer list if all dealer_ids are subset of their valid dealings set
/// All node types wait for VerifiedDealerSetQC from the SMR.
/// After receiving VerifiedDealerSetQC, they can aggregate dealings in the VerifiedDealerSet
/// and transition to Generated state
impl DkgNode<WaitDKGMetaFromSMR> {

    pub fn to_wait_aggregation(self) -> DkgNode<WaitAggregation> {
        info!("DkgNode node:{} wait_aggregation", self.node);
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
}

impl Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction> for DkgNode<WaitDKGMetaFromSMR> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
        _event_register: &mut dyn EventRegister<DkgEventData, SignedSmrTransaction, EventType = DkgEventType>,
    ) -> (
        Box<dyn Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction>>,
        Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, RuntimeError>,
    ) {
        trace!("DkgNode<WaitDKGMetaFromSMR> notify");
       if let Some(cs_deliver_event) = self.convert_dkg_event_to_cs_deliver_event(event) {
            if let Some(cs_deliver_processor) = self.cs_deliver_processor.as_mut(){
                let cs_deliver_actions = cs_deliver_processor.process_event(Box::new(cs_deliver_event));
                let (converted_actions, _)  = self.convert_cs_deliver_actions_to_dkg(cs_deliver_actions);
                return (self, Ok(converted_actions));
            }
        }

        if let DkgEventData::ReceiveDealing(node_id, dealing) = event.data() {
            info!("DkgNode<WaitDKGMetaFromSMR> received dealing. Sending back signature");
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
        else if let DkgEventData::ReceiveEncryptedDealing(node_id, enc_dealing) = event.data() {

            info!("DkgNode<WaitDKGMetaFromSMR> received encrypted dealing. Processing in a new thread");
            let node_index = self.get_node_index(*node_id).unwrap();
            let committee_pks = self.dkg_committee
                .values()
                .map(|dkg_data| (dkg_data.node_number, dkg_data.identity.cg_pubkey.clone()))
                .collect();

            let enc_dealing = enc_dealing.clone();
            let epoch = self.epoch_number;
            let num_of_nodes = self.cg_dkg.num_of_nodes;
            let threshold = self.cg_dkg.threshold;
            let num_of_dealer_clan_nodes = self.cg_dkg.num_of_dealer_clan_nodes;
            let threshold_clan = self.cg_dkg.threshold_clan;
            let node_type = self.cg_dkg.node_type();
            let cg_private_key = self.cg_dkg.get_cg_private_key().clone();

            let future = async move {
                let result = tokio::task::spawn_blocking(move || {
                    validate_and_sign_encrypted_dealing(
                        enc_dealing,
                        node_index,
                        epoch,
                        committee_pks,
                        num_of_nodes,
                        threshold,
                        num_of_dealer_clan_nodes,
                        threshold_clan,
                        node_type,
                        cg_private_key,
                    )
                })
                    .await
                    .unwrap(); // In production, handle JoinError properly

                if let Ok((accumulation_value, dealing_commitment_with_ciphers, dealing_meta_signature)) = result {
                    Box::new(DkgEvent {
                        event_type: DkgEventType::EncryptedDealingProcessed,
                        data: DkgEventData::EncryptedDealingProcessed(
                            accumulation_value,
                            dealing_commitment_with_ciphers,
                            dealing_meta_signature,
                        ),
                    }) as Box<dyn Event<Data = DkgEventData, EventType = DkgEventType>>
                } else {
                    error!("Error processing encrypted dealing: {:?}", result.err());
                    // For simplicity, return a null event; enhance error handling as needed
                    Box::new(DkgEvent {
                        event_type: DkgEventType::None,
                        data: DkgEventData::None,
                    }) as Box<dyn Event<Data = DkgEventData, EventType = DkgEventType>>
                }
            };

            let action = Action::ExecAsync(Box::pin(future));
            return (self, Ok(vec![action]));
        }
        else if let DkgEventData::EncryptedDealingProcessed(accumulation_value, dealing_commitment_with_ciphers, dealing_meta_signature) = event.data() {
            info!("DkgNode<WaitDKGMetaFromSMR> processed encrypted dealing. Sending signature to the family");

            self.cg_dkg.encrypted_dealing.insert(accumulation_value.clone(), dealing_commitment_with_ciphers.clone());
            let dkg_family_nodes = self.get_all_family_nodes();
            let actions = dkg_family_nodes.iter().map(|family_node_id| {
                Action::SendMessageTo(
                    *family_node_id,
                    DKGProtocolMessage::VoteOnDealingMeta(dealing_meta_signature.clone()).to_vec(),
                )
            }).collect();
            return (self, Ok(actions));
        }
        else if let DkgEventData::ReceiveDKGMetaQC(dkg_meta_qc) = event.data() {
            info!("DkgNode<WaitDKGMetaFromSMR> received DKG Meta from SMR, family node: {}", dkg_meta_qc.family_node_index);

            //todo: fix this
            let first_family_node = self.get_first_family_node_index();
            if dkg_meta_qc.family_node_index == first_family_node{
                info!("DkgNode<WaitDKGMetaFromSMR> Adding DKG Meta SMR, family node: {}", dkg_meta_qc.family_node_index);

                match self.add_dkg_meta_qc(dkg_meta_qc){
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
        }
        else if let DkgEventData::ReceiveAggregateEncryptedShareEvent(node_id, enc_share) = event.data() {
            info!("DkgNode<WaitDKGMetaFromSMR> received enc share");

            match self.add_aggregate_encrypted_share(*node_id, enc_share){
                true => {
                    let done = self.to_done();
                    return (Box::new(done), Ok(vec![
                        Action::SendEventOut(Box::new(
                        DkgEvent::new_end_dkg_event(),
                    ))]))
                },
                false => return (self, Ok(vec![])),
            }
        }
        else {
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
            DkgEventType::ReceivedEncryptedDealingEvent,
            DkgEventType::ReceivedAggregateEncryptedShareEvent,
            DkgEventType::ReceivedDKGMetaQC,
            DkgEventType::EncryptedDealingProcessed,
        ]
    }

    fn get_id(&self) -> usize {
        4
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
