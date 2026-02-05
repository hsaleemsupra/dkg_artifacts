use crate::sosmr_types::SignedSmrTransaction;
use crate::class_group_dkg::types::dkg_event::{DkgEvent, DkgEventData, DkgEventType};
use crate::DkgNode;
use log::trace;
use soruntime::state::{Action, Event, EventRegister, Subscriber};
use soruntime::RuntimeError;
use std::any::Any;
use crate::class_group_dkg::persistence::DKG_DATA_KEY;

pub struct Done;

impl DkgNode<Done> {

    pub fn prepare_update_notifications(&self) -> Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>> {
        self.into_persistence_data()
            .and_then(|data| {
                let bin = bincode::serialize(&data).ok()?;
                let key = DKG_DATA_KEY.as_bytes();
                Some(vec![
                    Action::SendEventOut(Box::new(DkgEvent::new_update_dkg((&data).into()))),
                    Action::<DkgEventData, DkgEventType, SignedSmrTransaction>::Store(key.into(), bin),
                ])
            })
            .unwrap_or_default()
    }
}

impl Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction> for DkgNode<Done> {
    fn notify(
        mut self: Box<Self>,
        event: &dyn Event<Data = DkgEventData, EventType = DkgEventType>,
        _event_register: &mut dyn EventRegister<DkgEventData, SignedSmrTransaction, EventType = DkgEventType>,
    ) -> (
        Box<dyn Subscriber<DkgEventData, DkgEventType, SignedSmrTransaction>>,
        Result<Vec<Action<DkgEventData, DkgEventType, SignedSmrTransaction>>, RuntimeError>,
    ) {
        trace!("DkgNode<Done> notify");

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

        (self, Ok(vec![]))
    }
    fn get_permanent_event_to_register(&self) -> Vec<DkgEventType> {
        vec![
            DkgEventType::ReceivedDeliverEvent,
            DkgEventType::ReceivedCSDeliverEvent,
        ]
    }
    fn get_id(&self) -> usize {
        6
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
