use log::trace;
use socrypto::{Identity};
use enum_kinds::EnumKind;
use crate::codeword::CodewordWithSignature;
use crate::errors::CSDeliverError;
use crate::types::deliver_event::CSDeliverEventData;

/// CS Deliver protocol messages used for communication between 2 counterparts of the protocol during different
/// stages.
#[derive(Debug, Clone, EnumKind)]
#[enum_kind(CSDeliverProtocolMessageKind)]
pub enum CSDeliverProtocolMessage {
    // Data Messages
    Codeword(CodewordWithSignature),
    Echo(CodewordWithSignature),
}

impl CSDeliverProtocolMessageKind {
    const fn index(self) -> u8 {
        match self {
            CSDeliverProtocolMessageKind::Codeword => 0,
            CSDeliverProtocolMessageKind::Echo => 1,
        }
    }
}

impl TryFrom<u8> for CSDeliverProtocolMessageKind {
    type Error = CSDeliverError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CSDeliverProtocolMessageKind::Codeword),
            1 => Ok(CSDeliverProtocolMessageKind::Echo),
            _ => Err(CSDeliverError::GeneralError(
                "Invalid deliver message kind raw representation".to_string(),
            )),
        }
    }
}

impl CSDeliverProtocolMessage {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_vec = Vec::new();
        let kind = CSDeliverProtocolMessageKind::from(self).index();
        final_vec.push(kind);
        let mut payload_raw = match self {
            CSDeliverProtocolMessage::Codeword(data) => data.to_vec(),
            CSDeliverProtocolMessage::Echo(data) => data.to_vec(),
        };
        final_vec.append(&mut payload_raw);
        final_vec
    }
}

impl TryFrom<&[u8]> for CSDeliverProtocolMessage {
    type Error = CSDeliverError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let kind = CSDeliverProtocolMessageKind::try_from(value[0])?;
        trace!("Deliver Message kind: {kind:?}");
        let data_raw = &value[1..];
        match kind {
            CSDeliverProtocolMessageKind::Codeword => CodewordWithSignature::try_from(data_raw)
                .map(CSDeliverProtocolMessage::Codeword),
            CSDeliverProtocolMessageKind::Echo => CodewordWithSignature::try_from(data_raw)
                .map(CSDeliverProtocolMessage::Echo),
        }
    }
}

impl From<(Identity, CSDeliverProtocolMessage)> for CSDeliverEventData {
    fn from(value: (Identity, CSDeliverProtocolMessage)) -> Self {
        let (_sender, message) = value;
        match message {
            CSDeliverProtocolMessage::Codeword(data) => CSDeliverEventData::ReceiveCodeword(data),
            CSDeliverProtocolMessage::Echo(data) => CSDeliverEventData::ReceiveEcho(data),
        }
    }
}
