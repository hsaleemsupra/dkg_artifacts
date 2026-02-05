use socrypto::{Identity};
use soruntime::state::EventProcessor;
use crate::node::CSDeliverNode;
use crate::types::deliver_event::{CSDeliverEvent, CSDeliverEventData, CSDeliverEventType};
use ed25519_dalek::{
    SigningKey as SecretKeyEd,
    VerifyingKey as PublicKeyEd,
};

pub fn init_state(
    node: Identity,
    num_nodes: u32,
    f_byzantine: u32,
    fc_byzantine: u32,
    secret_key: SecretKeyEd,
    members: Vec<(Identity, PublicKeyEd)>,
) -> EventProcessor<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType> {
    init_state_for_cs_deliver(
        node,
        num_nodes,
        f_byzantine,
        fc_byzantine,
        secret_key,
        members,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn init_state_for_cs_deliver(
    node: Identity,
    num_nodes: u32,
    f_byzantine: u32,
    fc_byzantine: u32,
    secret_key: SecretKeyEd,
    members: Vec<(Identity, PublicKeyEd)>,
) -> EventProcessor<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType> {

    let mut event_processor = EventProcessor::<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType>::new();
    //deliver node
    let deliver_node = CSDeliverNode::new(
        node,
        num_nodes,
        f_byzantine,
        fc_byzantine,
        secret_key,
        members,
    );
    //register deliver to event processing
    event_processor.register_subscriber(Box::new(deliver_node));
    event_processor
}
