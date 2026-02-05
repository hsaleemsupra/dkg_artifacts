use crate::types::helpers::sender_extractor::SenderIfc;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::{Header, HeaderIfc};
use primitives::{Origin, Payload};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

///
/// Part of the Committee deliverable to be sent to assignee peer by broadcaster/leader
///
#[derive(Serialize, Deserialize)]
pub struct PayloadData {
    header: Header,
    data: Payload,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, PayloadData);

impl Display for PayloadData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Payload ({}, {})", self.data.len(), self.header())
    }
}

impl Debug for PayloadData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl PayloadData {
    pub(crate) fn new(header: Header, data: Payload) -> Self {
        Self {
            header,
            data,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn split(self) -> (Header, Payload) {
        (self.header, self.data)
    }
}

impl HeaderIfc for PayloadData {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl SenderIfc for PayloadData {
    fn sender(&self) -> &Origin {
        self.header.origin()
    }
}
