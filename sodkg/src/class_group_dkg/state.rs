use crate::class_group_dkg::config::DkgConfig;
use crate::class_group_dkg::DkgNode;
use crate::sosmr_types::SignedSmrTransaction;
use crate::sosmr_types::SmrDkgCommitteeType;
use socrypto::Identity;
use soruntime::state::EventProcessor;

use crate::class_group_dkg::types::dkg_event::{DkgEvent, DkgEventData, DkgEventType};
use nidkg_helper::cgdkg::{CGPublicKey, CGSecretKey, NodeType};

pub fn init_states(
    node: Identity,
    cg_secret_key: CGSecretKey,
    dkg_type: SmrDkgCommitteeType,
    dkgconfig: DkgConfig,
    epoch_number: u64,
    dkg_members: Vec<(Identity, NodeType, CGPublicKey)>,
) -> EventProcessor<DkgEventData, DkgEvent, DkgEventType, SignedSmrTransaction> {
    init_states_for_dkg(
        node,
        cg_secret_key,
        dkg_type,
        dkgconfig,
        dkg_members,
        epoch_number,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn init_states_for_dkg(
    node: Identity,
    cg_secret_key: CGSecretKey,
    dkg_type: SmrDkgCommitteeType,
    dkgconfig: DkgConfig,
    dkg_members: Vec<(Identity, NodeType, CGPublicKey)>,
    epoch_number: u64,
) -> EventProcessor<DkgEventData, DkgEvent, DkgEventType, SignedSmrTransaction> {
    let mut event_processor =
        EventProcessor::<DkgEventData, DkgEvent, DkgEventType, SignedSmrTransaction>::new();
    //init DKG
    let dkg_node = DkgNode::new(
        node,
        cg_secret_key,
        dkg_type,
        dkgconfig,
        dkg_members,
        epoch_number,
    );
    //register dkg to event processing
    event_processor.register_subscriber(Box::new(dkg_node));
    event_processor
}
