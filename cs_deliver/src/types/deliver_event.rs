use std::any::Any;
use soruntime::state::Event;
use std::fmt;
use crate::codeword::CodewordWithSignature;

#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum CSDeliverEventType {
    ReceivedCodeword,
    ReceivedEcho,
    ReceivedNewDataToBroadcast,
    DataReconstructed,
    None,
}

impl fmt::Display for CSDeliverEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = match self {
            CSDeliverEventType::ReceivedCodeword => "ReceivedCodeword",
            CSDeliverEventType::ReceivedEcho => "ReceivedEcho",
            CSDeliverEventType::ReceivedNewDataToBroadcast => "ReceivedNewDataToBroadcast",
            CSDeliverEventType::DataReconstructed => "DataReconstructed",
            CSDeliverEventType::None => "None",
        };
        write!(f, "{}", val)
    }
}

#[derive(Debug, Clone)]
pub enum CSDeliverEventData {
    ReceiveCodeword(CodewordWithSignature),
    ReceiveEcho(CodewordWithSignature),
    ReceiveNewDataToBroadcast(Vec<u8>),
    DataReconstructed(Vec<u8>),
    None,
}

impl From<&CSDeliverEventData> for CSDeliverEventType {
    fn from(value: &CSDeliverEventData) -> Self {
        match value {
            CSDeliverEventData::ReceiveCodeword(_) => CSDeliverEventType::ReceivedCodeword,
            CSDeliverEventData::ReceiveEcho(_) => CSDeliverEventType::ReceivedEcho,
            CSDeliverEventData::ReceiveNewDataToBroadcast(_) => CSDeliverEventType::ReceivedNewDataToBroadcast,
            CSDeliverEventData::DataReconstructed(_) => CSDeliverEventType::DataReconstructed,
            CSDeliverEventData::None => CSDeliverEventType::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CSDeliverEvent {
    pub event_type: CSDeliverEventType,
    pub data: CSDeliverEventData,
}

impl CSDeliverEvent {
    pub fn create_data_broadcast_event(data: &Vec<u8>) -> Self {
        CSDeliverEvent {
            event_type: CSDeliverEventType::ReceivedNewDataToBroadcast,
            data: CSDeliverEventData::ReceiveNewDataToBroadcast(data.clone()),
        }
    }

    pub fn create_data_reconstructed_event(data: &Vec<u8>) -> Self {
        CSDeliverEvent {
            event_type: CSDeliverEventType::DataReconstructed,
            data: CSDeliverEventData::DataReconstructed(data.clone()),
        }
    }

}

impl Event for CSDeliverEvent {
    type Data = CSDeliverEventData;
    type EventType = CSDeliverEventType;

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
