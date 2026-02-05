use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;
use primitives::{Origin, Stringify};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

#[derive(Serialize, Deserialize, Clone)]
pub struct PullRequest {
    sync: SyncRequest,
    sender: Origin,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, PullRequest);

impl PullRequest {
    pub(crate) fn new(sender: Origin, sync_request: SyncRequest) -> Self {
        Self {
            sync: sync_request,
            sender,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn sender(&self) -> &Origin {
        &self.sender
    }

    pub(crate) fn split(self) -> (SyncRequest, Origin) {
        (self.sync, self.sender)
    }

    pub(crate) fn get_qc(&self) -> QuorumCertificate {
        self.sync.get_qc()
    }

    pub(crate) fn get_header(&self) -> Header {
        self.header().clone()
    }
}

impl Display for PullRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PullRequest ({}, {})",
            self.header(),
            self.sender.hex_display()
        )
    }
}
impl Debug for PullRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl HeaderIfc for PullRequest {
    fn header(&self) -> &Header {
        self.sync.header()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SyncRequest {
    header: Header,
    qc: QuorumCertificate,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, SyncRequest);

impl SyncRequest {
    pub(crate) fn new(header: Header, qc: QuorumCertificate) -> Self {
        Self {
            header,
            qc,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn split(self) -> (Header, QuorumCertificate) {
        (self.header, self.qc)
    }

    pub(crate) fn get_qc(&self) -> QuorumCertificate {
        self.qc.clone()
    }

    pub(crate) fn get_header(&self) -> Header {
        self.header().clone()
    }
}

impl HeaderIfc for SyncRequest {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl Display for SyncRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SyncRequest ({})", self.header(),)
    }
}
impl Debug for SyncRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
