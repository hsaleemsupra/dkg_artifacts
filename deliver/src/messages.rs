use log::trace;
use socrypto::{Identity};
use enum_kinds::EnumKind;
use crate::codeword::Codeword;
use crate::errors::DeliverError;
use crate::types::deliver_event::DeliverEventData;

/// Deliver protocol messages used for communication between 2 counterparts of the protocol during different
/// stages.
#[derive(Debug, Clone, EnumKind)]
#[enum_kind(DeliverProtocolMessageKind)]
pub enum DeliverProtocolMessage {
    // Data Messages
    Codeword(Codeword),
    Echo(Codeword),
}

impl DeliverProtocolMessageKind {
    const fn index(self) -> u8 {
        match self {
            DeliverProtocolMessageKind::Codeword => 0,
            DeliverProtocolMessageKind::Echo => 1,
        }
    }
}

impl TryFrom<u8> for DeliverProtocolMessageKind {
    type Error = DeliverError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DeliverProtocolMessageKind::Codeword),
            1 => Ok(DeliverProtocolMessageKind::Echo),
            _ => Err(DeliverError::GeneralError(
                "Invalid deliver message kind raw representation".to_string(),
            )),
        }
    }
}

impl DeliverProtocolMessage {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_vec = Vec::new();
        let kind = DeliverProtocolMessageKind::from(self).index();
        final_vec.push(kind);
        let mut payload_raw = match self {
            DeliverProtocolMessage::Codeword(data) => data.to_vec(),
            DeliverProtocolMessage::Echo(data) => data.to_vec(),
        };
        final_vec.append(&mut payload_raw);
        final_vec
    }
}

impl TryFrom<&[u8]> for DeliverProtocolMessage {
    type Error = DeliverError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let kind = DeliverProtocolMessageKind::try_from(value[0])?;
        trace!("Deliver Message kind: {kind:?}");
        let data_raw = &value[1..];
        match kind {
            DeliverProtocolMessageKind::Codeword => Codeword::try_from(data_raw)
                .map(DeliverProtocolMessage::Codeword),
            DeliverProtocolMessageKind::Echo => Codeword::try_from(data_raw)
                .map(DeliverProtocolMessage::Echo),
        }
    }
}

impl From<(Identity, DeliverProtocolMessage)> for DeliverEventData {
    fn from(value: (Identity, DeliverProtocolMessage)) -> Self {
        let (_sender, message) = value;
        match message {
            DeliverProtocolMessage::Codeword(data) => DeliverEventData::ReceiveCodeword(data),
            DeliverProtocolMessage::Echo(data) => DeliverEventData::ReceiveEcho(data),
        }
    }
}
