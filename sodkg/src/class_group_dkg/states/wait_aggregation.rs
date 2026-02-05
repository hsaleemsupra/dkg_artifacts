use crate::sosmr_types::SignedSmrTransaction;
use crate::class_group_dkg::node;
use crate::class_group_dkg::types::dkg_event::{DkgEventData, DkgEventType};
use crate::{DkgEvent, DkgNode};
use log::{info, trace};
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use soruntime::RuntimeError;
use std::any::Any;
use crate::class_group_dkg::states::done::Done;

/// This state indicates that public and private share of the threshold key has been generated.
/// Transitions to [Identity] when enough public key shares has been collected.
pub struct WaitAggregation;

impl DkgNode<WaitAggregation> {

    pub fn to_done(self) -> DkgNode<Done> {

        info!("DkgNode node:{} to_done", self.node_index);

        DkgNode {
            ..node::change_state(self)
        }
    }
}

impl Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction> for DkgNode<WaitAggregation> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
        _event_register: &mut dyn EventRegister<DkgEventData, SignedSmrTransaction, EventType = DkgEventType>,
    ) -> (
        Box<dyn Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction>>,
        Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, RuntimeError>,
    ) {
        trace!("DkgNode<WaitAggregation> node:{} notify", self.get_node_index(self.node).unwrap(),);

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
                let (mut converted_actions, flag_completed) = self.convert_cs_deliver_actions_to_dkg(cs_deliver_actions);

                if flag_completed{
                    let done = self.to_done();
                    converted_actions.push(Action::SendEventOut(Box::new(
                        DkgEvent::new_end_dkg_event(),
                    )));

                    return (Box::new(done), Ok(converted_actions));
                }

                return (self, Ok(converted_actions));
            }
        }

        if let DkgEventData::ReceiveAggregateEncryptedShareEvent(node_id, enc_share) = event.data() {
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

        (self, Ok(vec![]))
    }
    fn get_permanent_event_to_register(&self) -> Vec<DkgEventType> {
        vec![
            DkgEventType::ReceivedDeliverEvent,
            DkgEventType::ReceivedCSDeliverEvent,
            DkgEventType::ReceivedAggregateEncryptedShareEvent,
        ]
    }
    fn get_id(&self) -> usize {
        5
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
