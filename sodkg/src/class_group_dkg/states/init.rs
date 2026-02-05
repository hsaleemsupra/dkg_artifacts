use crate::sosmr_types::SignedSmrTransaction;
use crate::class_group_dkg::config::DkgConfig;
use crate::class_group_dkg::node;
use crate::class_group_dkg::states::done::Done;
use crate::class_group_dkg::states::vote_dealing_meta::VoteDealingMeta;
use crate::class_group_dkg::states::wait_dkg_meta_from_smr::WaitDKGMetaFromSMR;
use crate::class_group_dkg::states::wait_for_dealing_signature::WaitForDealingSig;
use crate::class_group_dkg::types::dkg_data::{DKGData, DkgNodeIdentify};
use crate::class_group_dkg::types::dkg_event::{DkgEventData, DkgEventType};
use crate::sosmr_types::SmrDkgCommitteeType;
use crate::DkgNode;
use log::{debug, info, trace};
use nidkg_helper::cgdkg::{CGDkg, CGPublicKey, CGSecretKey, NodeType};
use socrypto::Identity;
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use soruntime::RuntimeError;
use std::any::Any;
use std::collections::BTreeMap;
use std::marker::PhantomData;

//DKG states
pub struct Init;

#[allow(clippy::too_many_arguments)]
impl DkgNode<Init> {
    pub fn new(
        node: Identity,
        cg_secret_key: CGSecretKey,
        dkg_type: SmrDkgCommitteeType,
        config: DkgConfig,
        mut dkg_members: Vec<(Identity, NodeType, CGPublicKey)>,
        epoch_number: u64,
    ) -> DkgNode<Init> {
        debug!("DkgNode node:{} Init with config:{:?}", node, config);

        //generate node index using node pubkey sorted order
        dkg_members.sort_unstable_by(|(a_pk, _, _), (b_pk, _, _)| a_pk.cmp(b_pk));
        let dkg_members: Vec<_> = dkg_members
            .into_iter()
            .enumerate()
            .map(|(index, (identity, node_type, epk))| (index as u32, identity, node_type, epk))
            .collect();

        let mut my_index = 0;
        let mut my_type = NodeType::NormalTribeNode;
        let dkg_committee: BTreeMap<Identity, DKGData> = dkg_members
            .into_iter()
            .map(|(index, identity, node_type, cg_pubkey)| {
                if identity == node {
                    my_index = index;
                    my_type = node_type.clone();
                }
                (
                    identity,
                    DKGData::new(
                        index,
                        DkgNodeIdentify {
                            id: identity,
                            node_type,
                            cg_pubkey,
                        },
                    ),
                )
            })
            .collect();

        debug!(
            "Start DKG with committee:{}",
            dkg_committee
                .values()
                .enumerate()
                .map(|(index, n)| format!(
                    "{index}:{}:{}:{}/",
                    n.identity.id, n.identity.node_type, n.identity.cg_pubkey
                ))
                .fold(String::new(), |s, v| s + &v)
        );

        //todo: make threshold inputs consistent for deliver and cs-deliver

        let mut deliver_processor = None;
        // Only dealer clan nodes run the Deliver protocol
        if my_type == NodeType::DealerClanNode {
            let deliver_committee: Vec<Identity> = dkg_committee
                .iter()
                .filter(|(_, dkg_data)| dkg_data.identity.node_type == NodeType::DealerClanNode)
                .map(|(identity, _)| identity.clone())
                .collect();

            deliver_processor = Some(deliver::state::init_state(
                node,
                config.total_nodes_clan,
                config.threshold_clan - 1,
                deliver_committee,
            ));
        }

        let cs_deliver_committee: Vec<_> = dkg_committee
            .iter()
            .map(|(identity, data)| {
                (
                    identity.clone(),
                    data.identity.cg_pubkey.verification_key.clone(),
                )
            })
            .collect();

        let cs_deliver_processor = Some(cs_deliver::state::init_state(
            node,
            config.total_nodes,
            (config.threshold - 1) / 2,
            config.threshold_clan - 1,
            cg_secret_key.signing_key().clone(),
            cs_deliver_committee,
        ));

        DkgNode {
            node,
            dkg_type,
            dkg_committee,
            node_index: my_index,
            public_evals: None,
            committee_publickey: None,
            bls_privkey: None,
            cg_dkg: CGDkg::new(
                config.total_nodes,
                config.total_nodes_clan,
                config.threshold,
                config.threshold_clan,
                config.dealing_sig_collection_timeout_ms,
                cg_secret_key,
                my_index,
                my_type,
            ),
            deliver_processor,
            cs_deliver_processor,
            cached_deliver_data: None,
            epoch_number,
            state: PhantomData,
            dealing_sig_collection_timer_expired: false,
        }
    }

    pub fn to_wait_for_dealing_sig(self) -> DkgNode<WaitForDealingSig> {
        info!("DkgNode node:{} to_wait_for_dealing_sig", self.node,);

        DkgNode {
            committee_publickey: None,
            ..node::change_state(self)
        }
    }

    pub fn to_vote_meta_dkg(self) -> DkgNode<VoteDealingMeta> {
        info!("DkgNode node:{} to_vote_meta_dkg", self.node,);
        DkgNode {
            committee_publickey: None,
            ..node::change_state(self)
        }
    }

    pub fn to_wait_dkg_meta(self) -> DkgNode<WaitDKGMetaFromSMR> {
        info!("DkgNode node:{} to_wait_dkg_meta", self.node,);

        DkgNode {
            committee_publickey: None,
            ..node::change_state(self)
        }
    }

    pub fn to_done(self) -> DkgNode<Done> {
        info!("DkgNode<Init> node:{} to_done", self.node,);
        DkgNode {
            node_index: self.node_index,
            committee_publickey: None,
            ..node::change_state(self)
        }
    }
}

/// All nodes wait for IniDkg event
/// If the node is DealerClanNode, they generate dealings and transition to WaitForDealingSig
/// If the node is FamilyNode, they transition to VoteMetaDkg
/// If the node is a normal Tribe node, they transition to WaitMetaDkg
impl Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction> for DkgNode<Init> {
    fn notify(
        self: Box<Self>,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
        _event_register: &mut dyn EventRegister<DkgEventData, SignedSmrTransaction, EventType = DkgEventType>,
    ) -> (
        Box<dyn Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction>>,
        Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, RuntimeError>,
    ) {
        info!("DkgNode<Init> initialized");

        if let DkgEventType::InitDkg = event.event_type() {
            let node_type = self.cg_dkg.node_type();

            // If the node belongs to the dealer clan, we need to create and send dealings
            if node_type == NodeType::DealerClanNode {
                let mut wait_for_dealing_sig = self.to_wait_for_dealing_sig();
                if let Ok(individual_dealings_with_id) = wait_for_dealing_sig.generate_dealing() {
                    let post_actions = wait_for_dealing_sig
                        .handle_individual_dealings(individual_dealings_with_id);
                    info!(
                        "DkgNode<Init> notify return dealing actions: {}",
                        !post_actions.is_empty()
                    );
                    (Box::new(wait_for_dealing_sig), Ok(post_actions))
                } else {
                    (
                        Box::new(wait_for_dealing_sig),
                        Err(RuntimeError::EventError(format!(
                            "Error during generate_dealing"
                        ))),
                    )
                }
            } else if node_type == NodeType::FamilyNode {
                let vote_for_dkg_meta = self.to_vote_meta_dkg();
                (Box::new(vote_for_dkg_meta), Ok(vec![]))
            } else {
                let wait_for_dkg_meta = self.to_wait_dkg_meta();
                (Box::new(wait_for_dkg_meta), Ok(vec![]))
            }
        } else {
            (self, Ok(vec![]))
        }
    }
    fn get_permanent_event_to_register(&self) -> Vec<DkgEventType> {
        vec![DkgEventType::InitDkg]
    }
    fn get_id(&self) -> usize {
        trace!("Subscriber INIT get_id");
        0
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
