use crate::types::messages::available::Available;
use primitives::types::header::MessageMeta;
use primitives::{Origin, Stringify};
use std::fmt::{Debug, Display, Formatter};

// Feedback message to be sent to RBCTaskManager/SupraDeliver
#[derive(PartialEq)]
pub enum FeedbackMessage {
    Done(MessageMeta),
    Error(MessageMeta, Origin),
    InternalError(MessageMeta, String),
    Available(Available),
}

impl Display for FeedbackMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedbackMessage::Done(id) => {
                write!(f, "Done ({})", id)
            }
            FeedbackMessage::Error(id, origin) => {
                write!(f, "Error ({}, {})", id, origin.hex_display())
            }
            FeedbackMessage::InternalError(id, msg) => {
                write!(f, "InternalError ({}, {})", id, msg)
            }
            FeedbackMessage::Available(avail) => {
                write!(f, "Available ({})", avail)
            }
        }
    }
}

impl Debug for FeedbackMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl FeedbackMessage {
    pub fn done_msg(meta: MessageMeta) -> FeedbackMessage {
        FeedbackMessage::Done(meta)
    }

    pub fn err_msg(meta: MessageMeta, origin: Origin) -> FeedbackMessage {
        Self::Error(meta, origin)
    }

    pub fn internal_error(meta: MessageMeta, message: String) -> FeedbackMessage {
        Self::InternalError(meta, message)
    }
}
