use crate::sosmr_types::SignedSmrTransaction;
use crate::class_group_dkg::messages::DKGProtocolMessage;
use crate::class_group_dkg::transaction::create_dkg_meta_qc_tx;
use crate::class_group_dkg::types::dkg_data::DKGData;
use crate::errors::DkgError;
use crate::sosmr_types::SmrDkgCommitteeType;
use crate::{class_group_dkg, DkgEventData, DkgEventType};
use crypto::dealing::DealingCommitmentwithCiphers;
use cs_deliver::messages::CSDeliverProtocolMessage;
use cs_deliver::types::deliver_event::{CSDeliverEvent, CSDeliverEventData, CSDeliverEventType};
use deliver::messages::DeliverProtocolMessage;
use deliver::types::deliver_event::{DeliverEvent, DeliverEventData, DeliverEventType};
use log::{debug, error, info, trace};
use nidkg_helper::cgdkg::dkg_meta::{
    AggregateCommitment, AggregateEncryptedShare, DKGMeta, DKGMetaWithAggregateSignature,
    DKGMetaWithSignature, DKGMetaZis, DealingMetaWithSignature,
};
use nidkg_helper::cgdkg::{
    CGDkg, CGIndividualDealing, DealingSignature, EncryptedDealingWithProof, NodeType,
};
use nidkg_helper::BlsPublicKey;
use nidkg_helper::{BlsPrivateKey, PublicEvals};
use socrypto::{Hash, Identity, SecretKey};
use soruntime::state::{Action, Event, EventProcessor};
use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;

/// Describes Distributed Key Generator participant general state in different phases/states of protocol
pub struct DkgNode<State> {
    /// Identity of the node in scope of which DKG process has been initiated
    pub node: Identity,
    /// Type of the higher level protocol for which threshold signing key generation is requested.
    pub(crate) dkg_type: SmrDkgCommitteeType,
    /// Zero based node index of the current node in the committee
    pub(crate) node_index: u32,
    /// Node public keys ordered by their identity.
    pub(crate) dkg_committee: BTreeMap<Identity, DKGData>,
    /// Shared group public key. Set by the local node when enough partial shares have been collected to aggregate them.
    pub(crate) committee_publickey: Option<BlsPublicKey>,
    /// Flag indicating if the timer for dealer's signature collection on their dealing has expired
    pub(crate) dealing_sig_collection_timer_expired: bool,
    /// Public Evals generated based on the aggregated set of dealings.
    /// Source of the group public key and means to verify public key shares.
    pub(crate) public_evals: Option<PublicEvals>,
    /// Local node ThresholdSigning private key share generated base on the aggregated dealings
    pub(crate) bls_privkey: Option<BlsPrivateKey>,
    /// current node's distributed key generator state based on class-group cryptography
    pub(crate) cg_dkg: CGDkg,
    /// deliver protocol is run by clan nodes to distribute messages to other nodes within the clan
    pub(crate) deliver_processor:
        Option<EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType>>,
    /// deliver protocol is run by all tribe nodes to distribute messages from clan nodes to all other nodes
    pub(crate) cs_deliver_processor:
        Option<EventProcessor<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType>>,
    /// cached data from deliver protocol
    pub(crate) cached_deliver_data: Option<HashMap<Hash, Vec<u8>>>,
    /// Epoch number for during which DKG process has been initiated.
    pub(crate) epoch_number: u64,
    pub(crate) state: PhantomData<State>,
}

impl<State> DkgNode<State> {
    pub fn identity(&self) -> Identity {
        self.node
    }

    pub fn get_committee_identity_list(&self) -> Vec<Identity> {
        self.dkg_committee
            .values()
            .map(|ni| ni.identity.id)
            .collect()
    }

    pub fn convert_dkg_event_to_deliver_event(
        &self,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
    ) -> Option<DeliverEvent> {
        // Ensure the event is of type ReceivedDeliverEvent
        if event.event_type() == DkgEventType::ReceivedDeliverEvent {
            if let DkgEventData::ReceiveDeliverEvent(deliver_data) = event.data() {
                // Convert DeliverEventData to DeliverEventType
                let deliver_event_type = match deliver_data {
                    DeliverEventData::ReceiveCodeword(_) => DeliverEventType::ReceivedCodeword,
                    DeliverEventData::ReceiveEcho(_) => DeliverEventType::ReceivedEcho,
                    _ => DeliverEventType::None,
                };

                return Some(DeliverEvent {
                    event_type: deliver_event_type,
                    data: deliver_data.clone(),
                });
            }
        }
        None
    }

    pub fn convert_dkg_event_to_cs_deliver_event(
        &self,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
    ) -> Option<CSDeliverEvent> {
        // Ensure the event is of type ReceivedCSDeliverEvent
        if event.event_type() == DkgEventType::ReceivedCSDeliverEvent {
            if let DkgEventData::ReceiveCSDeliverEvent(cs_deliver_data) = event.data() {
                // Convert CSDeliverEventData to CSDeliverEventType
                let cs_deliver_event_type = match cs_deliver_data {
                    CSDeliverEventData::ReceiveCodeword(_) => CSDeliverEventType::ReceivedCodeword,
                    CSDeliverEventData::ReceiveEcho(_) => CSDeliverEventType::ReceivedEcho,
                    _ => CSDeliverEventType::None,
                };

                return Some(CSDeliverEvent {
                    event_type: cs_deliver_event_type,
                    data: cs_deliver_data.clone(),
                });
            }
        }
        None
    }

    pub fn broadcast_data_with_deliver(
        &mut self,
        data: &Vec<u8>,
    ) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        let mut dkg_actions = Vec::new();
        if let Some(deliver_processor) = self.deliver_processor.as_mut() {
            let data_broadcast_event = DeliverEvent::create_data_broadcast_event(data);
            let deliver_actions = deliver_processor.process_event(Box::new(data_broadcast_event));
            dkg_actions = self.convert_deliver_actions_to_dkg(deliver_actions);
        }
        dkg_actions
    }

    pub fn broadcast_data_with_cs_deliver(
        &mut self,
        data: &Vec<u8>,
    ) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        let mut dkg_actions = Vec::new();
        if let Some(cs_deliver_processor) = self.cs_deliver_processor.as_mut() {
            let data_broadcast_event = CSDeliverEvent::create_data_broadcast_event(data);
            let cs_deliver_actions =
                cs_deliver_processor.process_event(Box::new(data_broadcast_event));
            (dkg_actions, _) = self.convert_cs_deliver_actions_to_dkg(cs_deliver_actions);
        }
        dkg_actions
    }

    pub fn convert_deliver_actions_to_dkg(
        &mut self,
        deliver_actions: Vec<Action<DeliverEventData, DeliverEventType>>,
    ) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        let mut dkg_actions: Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> = Vec::new();
        for action in deliver_actions {
            match action {
                Action::SendMessage(msg) => {
                    let clan_nodes = self.get_all_dkg_clan_nodes_but_self();
                    dkg_actions.push(Action::SendMessageToPeers(
                        clan_nodes,
                        DKGProtocolMessage::DeliverMessage(
                            DeliverProtocolMessage::try_from(msg.as_slice()).unwrap(),
                        )
                        .to_vec(),
                    ));
                }
                Action::SendMessageTo(target, msg) => {
                    dkg_actions.push(Action::SendMessageTo(
                        target,
                        DKGProtocolMessage::DeliverMessage(
                            DeliverProtocolMessage::try_from(msg.as_slice()).unwrap(),
                        )
                        .to_vec(),
                    ));
                }
                Action::SendEventOut(event) => {
                    info!("Node:{:?} reconstructed Deliver data", self.cg_dkg.index());

                    if let DeliverEventData::DataReconstructed(accumulation_value, data_ser) =
                        event.data()
                    {
                        let actions = self.handle_deliver_data(accumulation_value, data_ser);
                        dkg_actions.extend(actions);
                    }
                }
                _ => {
                    info!("Deliver Action not handled:{:?}", action.to_string());
                }
            }
        }
        dkg_actions
    }

    pub fn convert_cs_deliver_actions_to_dkg(
        &mut self,
        cs_deliver_actions: Vec<Action<CSDeliverEventData, CSDeliverEventType>>,
    ) -> (Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, bool) {
        let mut flag_completed = false;
        let mut dkg_actions: Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> = Vec::new();
        for action in cs_deliver_actions {
            match action {
                Action::SendMessage(msg) => {
                    let all_nodes_but_self = self.get_all_nodes_excluding_self();
                    dkg_actions.push(Action::SendMessageToPeers(
                        all_nodes_but_self,
                        DKGProtocolMessage::CSDeliverMessage(
                            CSDeliverProtocolMessage::try_from(msg.as_slice()).unwrap(),
                        )
                        .to_vec(),
                    ));
                }
                Action::SendMessageTo(target, msg) => {
                    dkg_actions.push(Action::SendMessageTo(
                        target,
                        DKGProtocolMessage::CSDeliverMessage(
                            CSDeliverProtocolMessage::try_from(msg.as_slice()).unwrap(),
                        )
                        .to_vec(),
                    ));
                }
                Action::SendEventOut(event) => {
                    if let CSDeliverEventData::DataReconstructed(commitment_ser) = event.data() {
                        info!(
                            "Node:{:?} reconstructed CS Deliver data",
                            self.cg_dkg.index()
                        );

                        if let Ok(commitment) =
                            AggregateCommitment::try_from(commitment_ser.as_slice())
                        {
                            info!(
                                "Node:{:?} completed CS Deliver for AggregateCommitment",
                                self.cg_dkg.index()
                            );
                            if self.cg_dkg.node_type() == NodeType::DealerClanNode {
                                flag_completed = true;
                            }

                            if let Ok(result) =
                                self.cg_dkg.add_finalized_aggregate_commitment(&commitment)
                            {
                                if let Some((bls_priv_key, bls_pub_key)) = result {
                                    self.bls_privkey = Some(bls_priv_key);
                                    self.committee_publickey = Some(bls_pub_key);
                                    flag_completed = true;
                                }
                            } else {
                                error!(
                                    "Node:{:?} failed to add AggregateCommitment",
                                    self.cg_dkg.index()
                                );
                            }
                        } else {
                            info!("Unable to deserialize aggregate commitment");
                        }
                    }
                }
                _ => {
                    info!("CS Deliver Action not handled:{:?}", action.to_string());
                }
            }
        }
        (dkg_actions, flag_completed)
    }

    fn handle_deliver_data(
        &mut self,
        accumulation_value: &Hash,
        data_ser: &Vec<u8>,
    ) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        let mut dkg_actions = Vec::new();

        if let Some(dkg_meta_z) = self.cg_dkg.get_dkg_meta_accumulation() {
            if dkg_meta_z == accumulation_value.clone() {
                info!(
                    "Node:{:?} Deliver trying to deserialize DKGMetaZis",
                    self.cg_dkg.index()
                );

                if let Ok(dkg_meta_zis) = DKGMetaZis::try_from(data_ser.as_slice()) {
                    info!(
                        "Node:{:?} completed Deliver for DKGMetaZis",
                        self.cg_dkg.index()
                    );

                    // Once the propagation of zi's is complete, the clan node will propagate
                    // all commitments and ciphers corresponding to the zis using deliver
                    if self.cg_dkg.add_dkg_meta_zis(&dkg_meta_zis).is_ok() {
                        let all_ciphers_and_comms =
                            self.cg_dkg.get_all_ciphers_and_comms_in_meta_dkg();

                        info!(
                            "Node:{:?} starting Deliver for {:?} DealingCommitmentwithCiphers",
                            self.cg_dkg.index(),
                            all_ciphers_and_comms.len()
                        );

                        for cipher_and_comm in &all_ciphers_and_comms {
                            let actions =
                                self.broadcast_data_with_deliver(&cipher_and_comm.to_vec());
                            dkg_actions.extend(actions);
                        }
                    }
                } else {
                    info!(
                        "Unable to deserialize data with accumulation_value: {}",
                        accumulation_value
                    );
                }
            } else {
                info!(
                    "Node:{:?} Deliver trying to deserialize DealingCommitmentwithCiphers",
                    self.cg_dkg.index()
                );

                if let Ok(dealing_comm_with_cipher) =
                    DealingCommitmentwithCiphers::try_from(data_ser.as_slice())
                {
                    info!(
                        "Node:{:?} completed Deliver for DealingCommitmentwithCiphers",
                        self.cg_dkg.index()
                    );

                    // if we have received (commitments, ciphers) >= zis in dkg meta
                    // we can try to aggregate dealings
                    if self.cg_dkg.add_dkg_meta_dealing_comm_with_cipher(
                        &accumulation_value,
                        &dealing_comm_with_cipher,
                    ) >= self.cg_dkg.get_dkg_meta_zis_len()
                    {
                        info!("Node:{:?} try aggregate dealings", self.cg_dkg.index());
                        let actions = self.try_aggregate_dealing();

                        dkg_actions.extend(actions);
                    }
                } else {
                    info!(
                        "Unable to deserialize data with accumulation_value: {}",
                        accumulation_value
                    );
                }
            }
        }
        //otherwise cache for later
        else {
            if self.cached_deliver_data.is_none() {
                self.cached_deliver_data = Some(HashMap::new());
            }
            if let Some(cached_deliver_data) = self.cached_deliver_data.as_mut() {
                cached_deliver_data.insert(accumulation_value.clone(), data_ser.clone());
            }
        }

        dkg_actions
    }

    fn try_aggregate_dealing(&mut self) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        let mut dkg_actions = Vec::new();
        match self.cg_dkg.try_aggregate_dealings() {
            Ok((bls_priv_key, bls_pub_key, agg_comm_with_ciphers)) => {
                info!(
                    "Node:{:?} try aggregate dealings completed",
                    self.cg_dkg.index()
                );

                if self.bls_privkey.is_none() {
                    self.bls_privkey = Some(bls_priv_key);
                }
                if self.committee_publickey.is_none() {
                    self.committee_publickey = Some(bls_pub_key);
                }

                let all_nodes_excluding_dealer_clan = self.get_all_nodes_excluding_dkg_clan();
                all_nodes_excluding_dealer_clan
                    .iter()
                    .for_each(|(index, identity)| {
                        if let Some((dealers, cipher)) =
                            agg_comm_with_ciphers.ciphers_12381.get(index)
                        {
                            let agg_enc_share = AggregateEncryptedShare {
                                cipher_12381: cipher.clone(),
                                dealer_ids: dealers.clone(),
                            };

                            dkg_actions.push(Action::SendMessageTo(
                                identity.clone(),
                                DKGProtocolMessage::AggregatedEncryptedShare(agg_enc_share)
                                    .to_vec(),
                            ));

                            info!("Sending Enc cipher share for node: {:?}", index.clone());
                        } else {
                            info!("Enc cipher share not found for node: {:?}", index.clone());
                        }
                    });

                if let Some(agg_commitment_to_broadcast) =
                    self.cg_dkg.get_finalized_aggregate_commitments()
                {
                    let actions =
                        self.broadcast_data_with_cs_deliver(&agg_commitment_to_broadcast.to_vec());
                    dkg_actions.extend(actions);
                    info!("Starting CS Deliver for Agg Commitment");
                } else {
                    error!("Agg Commitment not found");
                }
            }
            Err(e) => {
                info!("Error while trying to aggregate dealings: {:?}", e);
            }
        }
        dkg_actions
    }

    pub fn add_aggregate_encrypted_share(
        &mut self,
        node_identity: Identity,
        aggregate_encrypted_share: &AggregateEncryptedShare,
    ) -> bool {
        if let Some(node_index) = self.get_node_index(node_identity.clone()) {
            if self.bls_privkey.is_none() {
                if let Ok(result) = self
                    .cg_dkg
                    .add_finalized_aggregate_encrypted_share(aggregate_encrypted_share, node_index)
                {
                    if let Some((bls_priv_key, bls_pub_key)) = result {
                        self.bls_privkey = Some(bls_priv_key);
                        self.committee_publickey = Some(bls_pub_key);
                        return true;
                    }
                } else {
                    error!("Unable to add finalized_aggregate_encrypted_share");
                }
            }
        }
        false
    }

    pub fn add_dealing(
        &mut self,
        node_id: Identity,
        dealing: &CGIndividualDealing,
    ) -> Result<DKGProtocolMessage, DkgError> {
        info!(
            "DkgNode node:{} add_dealing for:{node_id} total dealing:{}",
            self.node,
            self.cg_dkg.dealing_len() + 1
        );
        if let Some(node_index) = self.get_node_index(node_id) {
            let signature = self.cg_dkg.sign_and_store_dealing(
                dealing.clone(),
                node_index,
                self.epoch_number,
            )?;
            return Ok(DKGProtocolMessage::DealingSignature(signature));
        }
        Err(DkgError::GeneralError(
            "CGDKG Public key not found for give node id".to_string(),
        ))
    }

    pub fn add_encrypted_dealing(
        &mut self,
        node_id: Identity,
        encrypted_dealing: &EncryptedDealingWithProof,
    ) -> Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, DkgError> {
        if let Some(node_index) = self.get_node_index(node_id) {
            let committee_pks = self
                .dkg_committee
                .values()
                .map(|dkg_data| (dkg_data.node_number, dkg_data.identity.cg_pubkey.clone()))
                .collect();

            let dealing_meta_signature = self
                .cg_dkg
                .validate_and_sign_encrypted_dealing(
                    encrypted_dealing.clone(),
                    node_index,
                    self.epoch_number,
                    &committee_pks,
                )
                .map_err(|err| DkgError::EncryptedDealingVerificationError(err.to_string()))?;

            info!(
                "DkgNode node:{} add encrypted dealing for:{node_id} total dealings:{}",
                self.node,
                self.cg_dkg.encrypted_dealing_len()
            );

            // the dealer clan node sends the signature on dealing meta to all family nodes
            let mut post_actions = Vec::new();
            let dkg_family_nodes = self.get_all_family_nodes();
            dkg_family_nodes.iter().for_each(|family_node_id| {
                post_actions.push(Action::SendMessageTo(
                    *family_node_id,
                    DKGProtocolMessage::VoteOnDealingMeta(dealing_meta_signature.clone()).to_vec(),
                ));
            });

            return Ok(post_actions);
        }

        Err(DkgError::GeneralError(
            "CGDKG Public key not found for give node id".to_string(),
        ))
    }

    pub fn add_dealing_meta_signature(
        &mut self,
        node_id: Identity,
        dealing_meta: &DealingMetaWithSignature,
    ) -> Result<Option<DKGMeta>, DkgError> {
        if let Some(data) = self.dkg_committee.get(&node_id) {
            let cg_public_key = data.identity.cg_pubkey.clone();
            let node_index = data.node_number;
            return self
                .cg_dkg
                .consume_dealing_meta_vote(
                    dealing_meta,
                    &cg_public_key,
                    node_index,
                    self.epoch_number,
                )
                .map_err(|e| DkgError::GeneralError(e.to_string()));
        }
        Err(DkgError::GeneralError(
            "CGDKG Public key not found for give node id".to_string(),
        ))
    }

    pub fn add_dkg_meta_qc(
        &mut self,
        dkg_meta_qc: &DKGMetaWithAggregateSignature,
    ) -> Result<(), DkgError> {
        let committee_pks = self
            .dkg_committee
            .values()
            .map(|dkg_data| (dkg_data.node_number, dkg_data.identity.cg_pubkey.clone()))
            .collect();
        let result = self
            .cg_dkg
            .add_dkg_meta_qc(&dkg_meta_qc, &committee_pks)
            .map_err(|e| DkgError::GeneralError(e.to_string()));

        if result.is_ok() && self.cg_dkg.node_type() == NodeType::DealerClanNode {
            if let Some(cache_deliver_data) = self.cached_deliver_data.as_ref() {
                if self.cg_dkg.get_dkg_meta_accumulation().is_some() {
                    let deliver_data_vec: Vec<(Hash, Vec<u8>)> = cache_deliver_data
                        .iter()
                        .map(|(acc_val, data_ser)| (acc_val.clone(), data_ser.clone()))
                        .collect();

                    for (accumulation_val, data_ser) in deliver_data_vec {
                        self.handle_deliver_data(&accumulation_val, &data_ser);
                    }
                }
            }
        }

        result
    }

    //todo: fix this
    pub fn add_dkg_meta_signature(
        &mut self,
        node_id: Identity,
        dkg_meta_signature: &DKGMetaWithSignature,
    ) -> Result<Option<DKGMetaWithAggregateSignature>, DkgError> {
        if let Some(data) = self.dkg_committee.get(&node_id) {
            let cg_public_key = data.identity.cg_pubkey.clone();
            let node_index = data.node_number;

            match self.cg_dkg.consume_vote_on_dkg_meta(
                dkg_meta_signature,
                &cg_public_key,
                node_index,
            ) {
                Ok(result) => {
                    if let Some(dkg_meta_qc) = result {
                        info!("DkgNode<VoteDkgMeta> Creating DKG Meta Transaction");
                        let secret_key = SecretKey::from(
                            self.cg_dkg.get_cg_private_key().signing_key().to_bytes(),
                        );
                        let _transaction = create_dkg_meta_qc_tx(
                            &secret_key,
                            self.dkg_type,
                            dkg_meta_qc.to_vec(),
                        )?;
                        Ok(Some(dkg_meta_qc))
                    } else {
                        Ok(None)
                    }
                }
                Err(e) => Err(DkgError::GeneralError(e.to_string())),
            }
        } else {
            Err(DkgError::GeneralError(
                "CGDKG Public key not found for give node id".to_string(),
            ))
        }
    }

    pub fn verify_dkg_meta(
        &mut self,
        dkg_meta: &DKGMeta,
    ) -> Result<DKGMetaWithSignature, DkgError> {
        let committee_pks = self
            .dkg_committee
            .values()
            .map(|dkg_data| {
                (
                    dkg_data.node_number,
                    dkg_data.identity.cg_pubkey.verification_key_bls.clone(),
                )
            })
            .collect();

        self.cg_dkg
            .validate_and_sign_dkg_meta(dkg_meta, &committee_pks, self.epoch_number)
            .map_err(|err| DkgError::GeneralError(err.to_string()))
    }

    pub fn add_dealing_sig(
        &mut self,
        node_id: Identity,
        cgdkg_signature: DealingSignature,
    ) -> Result<bool, DkgError> {
        if let Some(dkg_data) = self.dkg_committee.get(&node_id) {
            self.cg_dkg
                .consume_dealing_vote(
                    cgdkg_signature,
                    (dkg_data.node_number, &dkg_data.identity.cg_pubkey),
                )
                .map_err(|e| {
                    DkgError::GeneralError(format!(
                        "Error while consuming dealing signature: {:?}",
                        e
                    ))
                })?;
            Ok((self.cg_dkg.has_enough_dealing_votes()
                && self.dealing_sig_collection_timer_expired)
                || self.cg_dkg.has_all_dealing_votes())
        } else {
            Err(DkgError::GeneralError(
                "CGDKG Public key not found for give node id".to_string(),
            ))
        }
    }

    pub fn cache_public_key_share(&mut self, node_id: Identity, share: BlsPublicKey) {
        trace!(
            "DkgNode node:{} cache_public_key_share for:{} nb pub share:{}",
            self.node,
            node_id,
            self.count(|ni| ni.cached_public_share.is_some()) + 1
        );
        self.update_node(node_id, |dkg_data| {
            dkg_data.cached_public_share = Some(share);
        })
    }

    pub fn hash_committee_pubkey(&self) -> Option<Hash> {
        self.committee_publickey
            .as_ref()
            .map(|pk| socrypto::digest(pk.to_vec()))
    }

    pub(crate) fn get_node_index(&self, node_id: Identity) -> Option<u32> {
        self.dkg_committee.get(&node_id).map(|n| n.node_number)
    }

    pub(crate) fn get_first_family_node_index(&self) -> u32 {
        let all_family_nodes = self.get_all_family_nodes_index();
        all_family_nodes.iter().min().unwrap().clone()
    }

    pub(crate) fn get_all_dkg_clan_nodes(&self) -> Vec<Identity> {
        self.dkg_committee
            .iter()
            .filter(|(_, dkg_data)| dkg_data.identity.node_type == NodeType::DealerClanNode)
            .map(|(id, _node)| id.clone())
            .collect()
    }

    pub(crate) fn get_all_dkg_clan_nodes_but_self(&self) -> Vec<Identity> {
        self.dkg_committee
            .iter()
            .filter(|(id, dkg_data)| {
                (dkg_data.identity.node_type == NodeType::DealerClanNode) && (*(*id) != self.node)
            })
            .map(|(id, _node)| id.clone())
            .collect()
    }

    pub(crate) fn get_all_family_nodes(&self) -> Vec<Identity> {
        self.dkg_committee
            .iter()
            .filter(|(_, dkg_data)| dkg_data.identity.node_type == NodeType::FamilyNode)
            .map(|(id, _node)| id.clone())
            .collect()
    }

    pub(crate) fn get_all_family_nodes_index(&self) -> Vec<u32> {
        self.dkg_committee
            .iter()
            .filter(|(_, dkg_data)| dkg_data.identity.node_type == NodeType::FamilyNode)
            .map(|(_id, dkg_data)| dkg_data.node_number)
            .collect()
    }

    pub(crate) fn get_all_nodes_excluding_dkg_clan(&self) -> Vec<(u32, Identity)> {
        self.dkg_committee
            .iter()
            .filter(|(_, dkg_data)| dkg_data.identity.node_type != NodeType::DealerClanNode)
            .map(|(id, dkg_data)| (dkg_data.node_number, id.clone()))
            .collect()
    }

    pub(crate) fn get_all_nodes_excluding_self(&self) -> Vec<Identity> {
        self.dkg_committee
            .iter()
            .filter(|(id, _dkg_data)| *(*id) != self.node)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub(crate) fn get_node_identity_by_index(&self, index: u32) -> Option<Identity> {
        for (pub_key, dkg_data) in self.dkg_committee.iter() {
            if dkg_data.node_number == index {
                return Some(*pub_key);
            }
        }
        None
    }

    pub(crate) fn update_node<U>(&mut self, node_id: Identity, update: U)
    where
        U: FnOnce(&mut DKGData),
    {
        self.dkg_committee.get_mut(&node_id).map(update);
    }

    fn count<P>(&self, predicate: P) -> usize
    where
        P: FnMut(&&DKGData) -> bool,
    {
        self.dkg_committee.values().filter(predicate).count()
    }

    pub fn into_persistence_data(&self) -> Option<class_group_dkg::persistence::DkgData> {
        let dkg_committee = self
            .dkg_committee
            .values()
            .map(|n| {
                debug!(
                    "node into_persistence_data node:{} number:{} contains partial pubkey:{}",
                    n.identity.id,
                    n.node_number,
                    n.public_share.is_some()
                );
                class_group_dkg::persistence::DkgNode {
                    identity: n.identity.id,
                    node_number: n.node_number,
                    cg_pubkey: (&n.identity.cg_pubkey).into(),
                    public_share: n.public_share.as_ref().map(|s| s.into()),
                }
            })
            .collect();

        self.bls_privkey
            .as_ref()
            .and_then(|privkey| self.committee_publickey.as_ref().map(|th| (privkey, th)))
            .map(
                |(bls_privkey, threshold_pubkey)| class_group_dkg::persistence::DkgData {
                    bls_privkey: bls_privkey.into(),
                    threshold_pubkey: threshold_pubkey.into(),
                    dkg_committee,
                },
            )
    }
}

pub(crate) fn change_state<INPUT, OUTPUT>(input: DkgNode<INPUT>) -> DkgNode<OUTPUT> {
    DkgNode {
        node: input.node,
        dkg_type: input.dkg_type,
        node_index: input.node_index,
        dkg_committee: input.dkg_committee,
        public_evals: input.public_evals,
        bls_privkey: input.bls_privkey,
        committee_publickey: input.committee_publickey,
        epoch_number: input.epoch_number,
        state: PhantomData,
        cg_dkg: input.cg_dkg,
        deliver_processor: input.deliver_processor,
        cs_deliver_processor: input.cs_deliver_processor,
        cached_deliver_data: input.cached_deliver_data,
        dealing_sig_collection_timer_expired: input.dealing_sig_collection_timer_expired,
    }
}
