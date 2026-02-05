use socrypto::Identity;
use soruntime::state::EventProcessor;
use crate::node::DeliverNode;
use crate::types::deliver_event::{DeliverEvent, DeliverEventData, DeliverEventType};

pub fn init_state(
    node: Identity,
    num_nodes: u32,
    f_byzantine: u32,
    members: Vec<Identity>,
) -> EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType> {
    init_state_for_deliver(
        node,
        num_nodes,
        f_byzantine,
        members,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn init_state_for_deliver(
    node: Identity,
    num_nodes: u32,
    f_byzantine: u32,
    members: Vec<Identity>,
) -> EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType> {
    let mut event_processor = EventProcessor::<DeliverEventData, DeliverEvent, DeliverEventType>::new();
    //deliver
    let deliver_node = DeliverNode::new(
        node,
        num_nodes,
        f_byzantine,
        members,
    );
    //register deliver to event processing
    event_processor.register_subscriber(Box::new(deliver_node));
    event_processor
}
