use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;
use primitives::HASH64;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fmt::{Debug, Display, Formatter};

///
/// Message availability information
///
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Available {
    /// Header of the message/data
    header: Header,
    #[serde(with = "BigArray")]
    /// Proof of the certificate from the deliverable broadcaster
    proof: HASH64,
    /// Threshold signature of the committee on the data produced by committee
    qc: QuorumCertificate,
}

impl Display for Available {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Available ({}, {})", self.header, self.qc)
    }
}

impl Debug for Available {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Available {
    pub fn new(header: Header, proof: HASH64, qc: QuorumCertificate) -> Self {
        Self { header, proof, qc }
    }

    ///
    /// Returns integrity certificate information
    ///
    pub fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    pub fn split(self) -> (Header, HASH64, QuorumCertificate) {
        (self.header, self.proof, self.qc)
    }
}

impl HeaderIfc for Available {
    fn header(&self) -> &Header {
        &self.header
    }
}
