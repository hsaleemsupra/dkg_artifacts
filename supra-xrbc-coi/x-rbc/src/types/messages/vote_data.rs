use crypto::PartialShare;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

///
/// Vote from a peer on the committee deliverable data
///
#[derive(Serialize, Deserialize)]
pub struct VoteData {
    /// Header of the data
    header: Header,
    /// Vote on the data
    vote: PartialShare,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, VoteData);

impl Display for VoteData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vote ({}, {})", self.header(), self.vote)
    }
}

impl Debug for VoteData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl VoteData {
    pub fn new(header: Header, vote: PartialShare) -> Self {
        Self {
            header,
            vote,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub fn vote(&self) -> &PartialShare {
        &self.vote
    }

    pub fn index(&self) -> u32 {
        self.vote.index()
    }

    pub fn split(self) -> (Header, PartialShare) {
        (self.header, self.vote)
    }
}

impl HeaderIfc for VoteData {
    fn header(&self) -> &Header {
        &self.header
    }
}
