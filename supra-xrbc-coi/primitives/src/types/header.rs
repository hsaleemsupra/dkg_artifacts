use crate::crypto::Hashers;
use crate::{Origin, Stringify, HASH32, ID};
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, MetricTag, Timestamp};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fmt::{Debug, Display, Formatter};

pub trait HeaderIfc {
    fn id(&self) -> &ID {
        self.header().id()
    }

    fn origin(&self) -> &Origin {
        self.header().origin()
    }

    fn commitment(&self) -> &HASH32 {
        self.header().commitment()
    }

    fn header(&self) -> &Header;

    fn get_header(&self) -> Header {
        self.header().clone()
    }

    fn meta(&self) -> &MessageMeta {
        self.header().meta()
    }

    fn get_meta(&self) -> MessageMeta {
        self.header().get_meta()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct MessageMeta {
    #[serde(with = "BigArray")]
    id: ID,
    origin: Origin,
}

impl Display for MessageMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MessageMeta ({}, {})",
            self.id.hex_display(),
            self.origin.hex_display()
        )
    }
}

impl Debug for MessageMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl MessageMeta {
    pub fn new(id: ID, origin: Origin) -> Self {
        Self { id, origin }
    }

    pub fn id(&self) -> &ID {
        &self.id
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }
}

impl Default for MessageMeta {
    fn default() -> Self {
        MessageMeta {
            id: [0; 64],
            origin: [0; 32],
        }
    }
}

#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct Header {
    message_meta: MessageMeta,
    commitment: HASH32,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, Header);

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Header ({}, {})",
            self.message_meta,
            self.commitment.hex_display()
        )
    }
}

impl MetricTag for Header {
    fn key(&self) -> String {
        "header".to_string()
    }
}

impl Debug for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Header {
    pub fn new(id: ID, origin: Origin, commitment: HASH32) -> Header {
        Self {
            message_meta: MessageMeta::new(id, origin),
            commitment,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    ///
    /// Calculates header hash based on the static data excluding time-stamp
    ///
    pub fn hash(&self) -> HASH32 {
        Hashers::keccak256_collection(vec![self.commitment(), self.id(), self.origin()])
    }
}

impl HeaderIfc for Header {
    fn id(&self) -> &ID {
        self.message_meta.id()
    }

    fn origin(&self) -> &Origin {
        self.message_meta.origin()
    }

    fn commitment(&self) -> &HASH32 {
        &self.commitment
    }

    fn header(&self) -> &Header {
        self
    }

    fn meta(&self) -> &MessageMeta {
        &self.message_meta
    }

    fn get_meta(&self) -> MessageMeta {
        self.message_meta.clone()
    }
}
