use crate::RuntimeError;
use socrypto::Identity;
use std::any::Any;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;

pub enum Action<ED: Send, ET: Send, Tx: Send = ()> {
    //store key/value
    Store(Vec<u8>, Vec<u8>),
    SendMessage(Vec<u8>),
    SendSMRTx(Box<Tx>),
    SendMessageToPeers(Vec<Identity>, Vec<u8>),
    SendMessageTo(Identity, Vec<u8>),
    SendEventOut(Box<dyn Event<Data = ED, EventType = ET>>),
    ExecAsync(
        Pin<Box<dyn Future<Output = Box<dyn Event<Data = ED, EventType = ET>>> + Send + 'static>>,
    ),
}

impl<ED: Send, ET: Send, Tx: Send> Display for Action<ED, ET, Tx> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Action::Store(_, _) => "Store",
            Action::SendMessage(_) => "SendMessage",
            Action::SendSMRTx(_) => "SendSMRTx",
            Action::SendMessageToPeers(_, _) => "SendMessageToPeers",
            Action::SendMessageTo(_, _) => "SendMessageTo",
            Action::SendEventOut(_) => "SendEventOut",
            Action::ExecAsync(_) => "ExecAsync",
        };
        write!(f, "{}", msg)
    }
}

pub trait Event: Send + Debug {
    type Data: std::marker::Send;
    type EventType: Hash + Ord + Eq;

    fn data(&self) -> &Self::Data;
    fn event_type(&self) -> Self::EventType;
    fn as_any(&self) -> &dyn Any;
}

pub trait EventRegister<EventData: std::marker::Send, Tx: Send = ()> {
    type EventType: Hash + Ord;
    fn regsiter_event(&mut self, subscriber_id: usize, events: Vec<Self::EventType>);
    fn send_event(
        &mut self,
        event: Box<dyn Event<Data = EventData, EventType = Self::EventType>>,
    ) -> Vec<Action<EventData, Self::EventType, Tx>>
    where
        <Self as EventRegister<EventData, Tx>>::EventType: Send;
}

pub trait Subscriber<EventData: std::marker::Send, ET: std::marker::Send, Tx: Send = ()>:
    Send
{
    #[allow(clippy::type_complexity)]
    fn notify(
        self: Box<Self>,
        event: &dyn Event<Data = EventData, EventType = ET>,
        event_register: &mut dyn EventRegister<EventData, Tx, EventType = ET>,
    ) -> (
        Box<dyn Subscriber<EventData, ET, Tx>>,
        Result<Vec<Action<EventData, ET, Tx>>, RuntimeError>,
    );

    fn get_permanent_event_to_register(&self) -> Vec<ET>;

    fn get_id(&self) -> usize;

    //to downcast to the base type.
    fn as_any(&self) -> &dyn Any;
}

#[derive(Debug)]
pub struct EventNotifier<E: Event> {
    events_type: HashSet<E::EventType>,
    subscriber_id: usize,
}

pub struct EventProcessor<Data, E: Event, ET, Tx: Send = ()>
where
    ET: std::fmt::Debug,
{
    event_list: HashMap<usize, EventNotifier<E>>,
    subscriber_list: HashMap<usize, Box<dyn Subscriber<Data, ET, Tx>>>,
}

impl<
        EventData: std::marker::Send,
        E: Event + Event<EventType = ET> + std::fmt::Debug,
        ET: Hash + Ord + PartialOrd + Eq + PartialEq + std::marker::Send + std::fmt::Debug,
        Tx: Send,
    > fmt::Display for EventProcessor<EventData, E, ET, Tx>
where
    ET: std::fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(EventProcessor: subscriber_list ids:{:?} notifier:{:?})",
            self.subscriber_list.keys().copied().collect::<Vec<usize>>(),
            self.event_list
                .values()
                .map(|n| format!(
                    " sub_id:{}/{:?}",
                    n.subscriber_id,
                    n.events_type
                        .iter()
                        .map(|e| format!("{:?}-", e))
                        .collect::<Vec<String>>()
                ))
                .collect::<Vec<String>>()
        )
    }
}

impl<
        EventData: std::marker::Send,
        E: Event + Event<EventType = ET> + std::fmt::Debug,
        ET: Hash + Ord + PartialOrd + Eq + PartialEq + std::marker::Send + std::fmt::Debug,
        Tx: Send,
    > Default for EventProcessor<EventData, E, ET, Tx>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        EventData: std::marker::Send,
        E: Event + Event<EventType = ET> + std::fmt::Debug,
        ET: Hash + Ord + PartialOrd + Eq + PartialEq + std::marker::Send + std::fmt::Debug,
        Tx: Send,
    > EventProcessor<EventData, E, ET, Tx>
{
    pub fn new() -> EventProcessor<EventData, E, ET, Tx> {
        EventProcessor {
            event_list: HashMap::new(),
            subscriber_list: HashMap::new(),
        }
    }

    pub fn get_subscriber(&self, id: usize) -> Option<&dyn Subscriber<EventData, ET, Tx>> {
        self.subscriber_list.get(&id).map(|s| s.as_ref())
    }

    pub fn register_subscriber(&mut self, sub: Box<dyn Subscriber<EventData, ET, Tx>>) {
        log::trace!("EventProcessor register_subscriber sub:{}", sub.get_id());
        let event_list = sub.get_permanent_event_to_register();
        let sub_id = sub.get_id();
        self.subscriber_list.insert(sub_id, sub);
        self.regsiter_event(sub_id, event_list);
    }

    ///Process an incoming event. When an event is processed, it's removed. The subscriber must register it  during notification to be notified another time.
    pub fn process_event(
        &mut self,
        event: Box<dyn Event<Data = EventData, EventType = ET>>,
    ) -> Vec<Action<EventData, ET, Tx>> {
        //        log::trace!("EventProcessor process event BEGIN:{}", self);

        //Get subscriber id for the event and remove the event.
        let indexes: Vec<usize> = self
            .event_list
            .values_mut()
            .filter_map(|en| {
                en.events_type
                    .remove(&event.event_type())
                    .then_some(en.subscriber_id)
            })
            // .map(|(sub_index, ev_index, sub)| {
            //     sub.nofity(&*event, self).map(|_| (sub_index, ev_index))
            // })
            .collect();

        log::trace!(
            "EventProcessor process_event indexes:{:?}: {:?}",
            indexes,
            event.event_type()
        );
        //notify the event
        let mut action_list = vec![];
        for sub_id in indexes {
            match self.subscriber_list.remove(&sub_id) {
                Some(subscriber) => {
                    let (subscriber, res) = subscriber.notify(&*event, self);
                    let new_sub_id = match res {
                        Ok(mut actions) => {
                            action_list.append(&mut actions);
                            subscriber.get_id()
                        }
                        Err(err) => {
                            log::error!("Event processor, error during event notification:{}", err);
                            sub_id
                        }
                    };
                    //if new one remove the event of old one and
                    if sub_id != new_sub_id {
                        self.event_list.remove(&sub_id);
                    }
                    //register the return subscriber and its events
                    let event_list = subscriber.get_permanent_event_to_register();
                    self.subscriber_list.insert(new_sub_id, subscriber);
                    self.regsiter_event(new_sub_id, event_list);
                }
                None => {
                    log::error!("Event processor, error registered subscriber for event not found")
                }
            }
        }
        log::trace!("EventProcessor self:{}", self);
        action_list
    }
}

impl<
        EventData,
        E: Event + Event<EventType = ET>,
        ET: Hash + Ord + PartialOrd + Eq + PartialEq + std::marker::Send + std::fmt::Debug,
        Tx: Send,
    > EventRegister<EventData, Tx> for EventProcessor<EventData, E, ET, Tx>
where
    HashSet<<E as Event>::EventType>: FromIterator<ET>,
    EventData: std::marker::Send,
{
    type EventType = ET;
    fn regsiter_event(&mut self, subscriber_id: usize, events_type: Vec<Self::EventType>) {
        log::trace!(
            "regsiter_event subscriber_id:{} events_type:{:?}",
            subscriber_id,
            events_type
        );
        let events = self
            .event_list
            .entry(subscriber_id)
            .or_insert(EventNotifier {
                events_type: HashSet::new(),
                subscriber_id,
            });
        events_type.into_iter().for_each(|e| {
            events.events_type.insert(e);
        });
    }

    fn send_event(
        &mut self,
        event: Box<dyn Event<Data = EventData, EventType = ET>>,
    ) -> Vec<Action<EventData, ET, Tx>> {
        self.process_event(event)
    }
}
