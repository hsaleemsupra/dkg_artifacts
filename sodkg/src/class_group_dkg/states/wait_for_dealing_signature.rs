use crate::sosmr_types::SignedSmrTransaction;
use crate::class_group_dkg::messages::DKGProtocolMessage;
use crate::class_group_dkg::node;
use crate::class_group_dkg::types::dkg_event::{DkgEventData, DkgEventType};
use crate::{DkgEvent, DkgNode};
use log::{error, info, trace};
use nidkg_helper::cgdkg::{validate_and_sign_dkg_meta, validate_and_sign_encrypted_dealing, CGIndividualDealing};
use socrypto::{Hash, Identity};
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use soruntime::RuntimeError;
use std::any::Any;
use std::pin::Pin;
use crypto::dealing::EncryptedDealingWithProof;
use crate::errors::DkgError;
use tokio::time::{sleep, Duration};
use crate::class_group_dkg::states::wait_aggregation::WaitAggregation;

pub struct WaitForDealingSig;

/// only DealerClanNode can be in this state
/// The DealerClanNode waits to receive threshold number of signatures on their dealing
/// Once they have received threshold number of signatures, they generate the encrypted dealing and broadcast it
/// And transition to WaitDKGMetaFromSMR
impl DkgNode<WaitForDealingSig> {
    pub fn generate_dealing(&mut self) -> Result<Vec<(Identity, CGIndividualDealing)>, DkgError> {
        info!("DkgNode node:{} generate_dealing", self.node,);
        let individual_dealing_vec = self.cg_dkg.generate_individual_dealing(self.epoch_number)?;
        Ok(individual_dealing_vec
            .into_iter()
            .enumerate()
            .map(|(index, cg_dealing)| {
                // should not panic as always create same number of
                // dealings where the committee numbers are
                let identity = self.get_node_identity_by_index(index as u32).unwrap();
                (identity, cg_dealing)
            })
            .collect())
    }

    pub(crate) fn handle_individual_dealings(
        &mut self,
        dealings: Vec<(Identity, CGIndividualDealing)>,
    ) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        info!("Generated {} individual dealings", dealings.len());

        let mut actions = Vec::new();

        for (target_node, individual_dealing) in dealings {
            if target_node == self.identity() {
                self.handle_own_dealing(target_node, individual_dealing);
            } else {
                actions.push(Action::SendMessageTo(
                    target_node,
                    DKGProtocolMessage::Dealing(individual_dealing).to_vec(),
                ));
            }
        }

        // start the timer for signatures collection
        let timeout_ms = self.cg_dkg.dealing_sig_collection_timeout_ms;
        actions.push(Action::ExecAsync(Pin::from(Box::new(async move {
            // Sleep for the configured duration
            sleep(Duration::from_millis(timeout_ms)).await;
            // Return a TimerExpired event
            Box::new(DkgEvent{
                event_type: DkgEventType::SignatureCollectionTimerExpired,
                data: DkgEventData::SignatureCollectionTimerExpired,
            }) as Box<dyn Event<Data=DkgEventData, EventType=DkgEventType>>
        }))));

        actions
    }

    fn handle_own_dealing(&mut self, identity: Identity, dealing: CGIndividualDealing) {

        // this step is essential as commitment to the dealing are only computed during deserialization
        // After which signature on the commitment can be computed
        let dealing = CGIndividualDealing::try_from(dealing.to_vec().as_slice()).unwrap();

        let signature = self
            .add_dealing(identity, &dealing)
            .expect("Successful handling of own dealing");
        if let DKGProtocolMessage::DealingSignature(sig) = signature {
            let _ = self
                .add_dealing_sig(identity, sig)
                .expect("Successful processing of own signature on own dealing.");
        } else {
            panic!("Internal DKG Protocol error. Expected dealing signature for own individual dealing, got: {:?}", signature);
        }
    }

    pub fn generate_encrypted_dealing_with_proof(&mut self) -> Result<EncryptedDealingWithProof, DkgError> {
        info!("DkgNode node:{} generate_encrypted_dealing_with_proof", self.node,);

        let node_encryption_keys = self.dkg_committee
            .values()
            .map(|dkg_data|
                (dkg_data.node_number,
                 dkg_data.identity.cg_pubkey.encryption_key_bls12381().key().clone()))
            .collect();

        let encrypted_dealing = self.cg_dkg.generate_encrypted_dealings_with_proof(&node_encryption_keys)?;
        if self.cg_dkg.add_self_encrypted_dealing(encrypted_dealing.clone()).is_err() {
            info!("DkgNode node:{} Error while adding storing encrypted dealing", self.node,);
        }
        Ok(encrypted_dealing)
    }

    pub(crate) fn handle_encrypted_dealings(
        &mut self,
        encrypted_dealing: &EncryptedDealingWithProof,
    ) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {

        let dealer_clan_nodes = self.get_all_dkg_clan_nodes_but_self();
        dealer_clan_nodes.iter()
            .map(|target_node| {
                Action::SendMessageTo(
                    *target_node,
                    DKGProtocolMessage::EncryptedDealing(encrypted_dealing.clone()).to_vec(),
                )
            }).collect()
    }

    pub fn to_wait_aggregation(self) -> DkgNode<WaitAggregation> {
        info!("DkgNode node:{} wait_aggregation", self.node);
        DkgNode {
            ..node::change_state(self)
        }
    }
}

impl Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction> for DkgNode<WaitForDealingSig> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
        _event_register: &mut dyn EventRegister<DkgEventData, SignedSmrTransaction, EventType = DkgEventType>,
    ) -> (
        Box<dyn Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction>>,
        Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, RuntimeError>,
    ) {
        trace!("DkgNode<WaitForDealingSig> notify");
        if let Some(deliver_event) = self.convert_dkg_event_to_deliver_event(event) {
            if let Some(deliver_processor) = self.deliver_processor.as_mut(){
                let deliver_actions = deliver_processor.process_event(Box::new(deliver_event));
                let converted_actions = self.convert_deliver_actions_to_dkg(deliver_actions);
                return (self, Ok(converted_actions));
            }
        }
        else if let Some(cs_deliver_event) = self.convert_dkg_event_to_cs_deliver_event(event) {
            if let Some(cs_deliver_processor) = self.cs_deliver_processor.as_mut(){
                let cs_deliver_actions = cs_deliver_processor.process_event(Box::new(cs_deliver_event));
                let (converted_actions, _) = self.convert_cs_deliver_actions_to_dkg(cs_deliver_actions);
                return (self, Ok(converted_actions));
            }
        }

        let received_enough_sigs_and_timer_expired = match event.data() {
            DkgEventData::ReceiveDealing(node_id, dealing) => {
                //send signature back to the dealer
                info!("DkgNode<WaitForDealingSig> received dealing. Sending back signature");
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
                        )
                    }
                }
            }
            DkgEventData::ReceiveEncryptedDealing(node_id, enc_dealing) => {
                info!("DkgNode<WaitForDealingSig> received encrypted dealing. Processing in a new thread");
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
            DkgEventData::EncryptedDealingProcessed(accumulation_value, dealing_commitment_with_ciphers, dealing_meta_signature) => {
                info!("DkgNode<WaitForDealingSig> processed encrypted dealing");
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

            DkgEventData::ReceiveDKGMeta(node_id, dkg_meta) => {
                info!("DkgNode<WaitForDealingSig>: Received DKG Meta from Family. Processing in a new thread!");

                let committee_pks = self.dkg_committee
                    .values()
                    .map(|dkg_data| (dkg_data.node_number, dkg_data.identity.cg_pubkey.verification_key_bls.clone()))
                    .collect();
                let epoch = self.epoch_number;
                let num_of_dealer_clan_nodes = self.cg_dkg.num_of_dealer_clan_nodes;
                let threshold_clan = self.cg_dkg.threshold_clan;
                let node_type = self.cg_dkg.node_type();
                let cg_private_key = self.cg_dkg.get_cg_private_key().clone();
                let node = *node_id;
                let dkg_meta = dkg_meta.clone();

                let future = async move {
                    let result = tokio::task::spawn_blocking(move || {
                        validate_and_sign_dkg_meta(&dkg_meta,
                                                   &committee_pks,
                                                   epoch,
                                                   node_type,
                                                   num_of_dealer_clan_nodes,
                                                   threshold_clan,
                                                   cg_private_key)
                    })
                        .await
                        .unwrap(); // In production, handle JoinError properly

                    if let Ok((accumulation_value, dkg_meta_zis, dkg_meta_signature)) = result {
                        Box::new(DkgEvent {
                            event_type: DkgEventType::DKGMetaProcessed,
                            data: DkgEventData::DKGMetaProcessed(
                                node,
                                accumulation_value,
                                dkg_meta_zis,
                                dkg_meta_signature,
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
            DkgEventData::DKGMetaProcessed(node_id, accumulation_value, dkg_meta_zis, dkg_meta_signature) => {
                info!("DkgNode<WaitForDealingSig> processed DKGMeta");
                if let Some(voted_dkg_metas) = self.cg_dkg.voted_dkg_metas.as_mut(){
                    voted_dkg_metas.insert(accumulation_value.clone(), dkg_meta_zis.clone());
                }
                return (
                    self,
                    Ok(vec![Action::SendMessageTo(*node_id, DKGProtocolMessage::VoteOnDKGMeta(dkg_meta_signature.clone()).to_vec())]),
                );
            }
            DkgEventData::ReceiveDealingSig(node_id, signature) => {
                let result = self
                    .add_dealing_sig(*node_id, signature.clone())
                    .map_err(|e| RuntimeError::GeneralError(format!("adding_sig error: {}", e)));
                if let Err(err) = result {
                    return (self, Err(err));
                }
                info!("DkgNode<WaitForDealingSig> total sigs:{}", self.cg_dkg.dealing_vote_len());
                result.unwrap()
            }
            DkgEventData::SignatureCollectionTimerExpired =>{
                info!("Signature Collection Timer Expired for node : {:?}", self.node);
                self.dealing_sig_collection_timer_expired = true;
                self.cg_dkg.has_enough_dealing_votes()
            }
            DkgEventData::ReceiveDKGMetaQC(dkg_meta_qc) => {
                info!("DkgNode<WaitForDealingSig>: Received DKG Meta from SMR");

                //todo: fix this
                let first_family_node = self.get_first_family_node_index();
                if dkg_meta_qc.family_node_index == first_family_node {
                    info!("DkgNode<WaitForDealingSig> Adding DKG Meta SMR, family node: {}", dkg_meta_qc.family_node_index);

                    match self.add_dkg_meta_qc(dkg_meta_qc) {
                        Ok(()) => {
                            // if self is clan node, invoke deliver to propagate the zis
                            // corresponding to the zm accumulation in DKGMeta
                            if let Some(zis_to_broadcast) =
                                self.cg_dkg.get_voted_dkg_meta_zis(&Hash(dkg_meta_qc.dkg_meta.accumulation_value)) {
                                let actions = self.broadcast_data_with_deliver(&zis_to_broadcast.to_vec());
                                let wait_aggregation = self.to_wait_aggregation();
                                return (Box::new(wait_aggregation), Ok(actions));
                            } else {
                                let wait_aggregation = self.to_wait_aggregation();
                                return (Box::new(wait_aggregation), Ok(vec![]));
                            }
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
            false
            }
            _ => {
                trace!(
                    "Event not handled in waiting_for_dealing_sig state:{:?}",
                    event.event_type()
                );
                false
            }
        };
        if received_enough_sigs_and_timer_expired
            && !self.cg_dkg.is_self_encrypted_dealing_generated() {

            info!("DkgNode<WaitForDealingSig>: Received enough sigs and timer expired");
            return match self.generate_encrypted_dealing_with_proof(){

                Ok(encrypted_dealing) => {
                    let actions = self.handle_encrypted_dealings(&encrypted_dealing);
                    (self, Ok(actions))
                }
                Err(err) => {
                    let error = Err(RuntimeError::EventError(format!(
                        "Error during encrypted dealing generation:{}",
                        err
                    )));
                    (self, error)
                }
            };
        }
        (self, Ok(vec![]))
    }

    fn get_permanent_event_to_register(&self) -> Vec<DkgEventType> {
        vec![
            DkgEventType::ReceivedDeliverEvent,
            DkgEventType::ReceivedCSDeliverEvent,
            DkgEventType::ReceivedDealingEvent,
            DkgEventType::ReceivedEncryptedDealingEvent,
            DkgEventType::ReceivedDealingSign,
            DkgEventType::ReceivedDKGMeta,
            DkgEventType::SignatureCollectionTimerExpired,
            DkgEventType::ReceivedDKGMetaQC,
            DkgEventType::EncryptedDealingProcessed,
            DkgEventType::DKGMetaProcessed
        ]
    }

    fn get_id(&self) -> usize {
        1
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
