use std::any::Any;
use socrypto::{Hash};
use soruntime::state::Event;
use std::fmt;
use crate::codeword::Codeword;

#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum DeliverEventType {
    ReceivedCodeword,
    ReceivedEcho,
    ReceivedNewDataToBroadcast,
    DataReconstructed,
    None,
}

impl fmt::Display for DeliverEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = match self {
            DeliverEventType::ReceivedCodeword => "ReceivedCodeword",
            DeliverEventType::ReceivedEcho => "ReceivedEcho",
            DeliverEventType::ReceivedNewDataToBroadcast => "ReceivedNewDataToBroadcast",
            DeliverEventType::DataReconstructed => "DataReconstructed",
            DeliverEventType::None => "None",
        };
        write!(f, "{}", val)
    }
}

#[derive(Debug, Clone)]
pub enum DeliverEventData {
    ReceiveCodeword(Codeword),
    ReceiveEcho(Codeword),
    ReceiveNewDataToBroadcast(Vec<u8>),
    DataReconstructed(Hash, Vec<u8>),
    None,
}

impl From<&DeliverEventData> for DeliverEventType {
    fn from(value: &DeliverEventData) -> Self {
        match value {
            DeliverEventData::ReceiveCodeword(_) => DeliverEventType::ReceivedCodeword,
            DeliverEventData::ReceiveEcho(_) => DeliverEventType::ReceivedEcho,
            DeliverEventData::ReceiveNewDataToBroadcast(_) => DeliverEventType::ReceivedNewDataToBroadcast,
            DeliverEventData::DataReconstructed(_, _) => DeliverEventType::DataReconstructed,
            DeliverEventData::None => DeliverEventType::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeliverEvent {
    pub event_type: DeliverEventType,
    pub data: DeliverEventData,
}

impl DeliverEvent {
    pub fn create_data_broadcast_event(data: &Vec<u8>) -> Self {
        DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data.clone()),
        }
    }

    pub fn create_data_reconstructed_event(accumulation_val: &Hash, data: &Vec<u8>) -> Self {
        DeliverEvent {
            event_type: DeliverEventType::DataReconstructed,
            data: DeliverEventData::DataReconstructed(accumulation_val.clone(), data.clone()),
        }
    }

}

impl Event for DeliverEvent {
    type Data = DeliverEventData;
    type EventType = DeliverEventType;

    fn data(&self) -> &Self::Data {
        &self.data
    }

    fn event_type(&self) -> Self::EventType {
        self.event_type
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
