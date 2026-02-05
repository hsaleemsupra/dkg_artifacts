use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;
use primitives::{Stringify, HASH64};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::fmt::{Debug, Display, Formatter};

///
/// Certificate data for the deliverable along with the broadcaster proof/signature
///
#[derive(Serialize, Deserialize)]
pub struct QuorumCertificateData {
    /// Header of the deliverable
    header: Header,
    /// Broadcaster signature on the Quorum Certificate
    #[serde(with = "BigArray")]
    proof: HASH64,
    /// Quorum Certificate of the broadcaster clan on the deliverable
    qc: QuorumCertificate,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, QuorumCertificateData);

impl Display for QuorumCertificateData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QuorumCertificateData({}, {}, {})",
            self.header,
            self.qc,
            self.proof.hex_display(),
        )
    }
}

impl Debug for QuorumCertificateData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl HeaderIfc for QuorumCertificateData {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl QuorumCertificateData {
    pub fn new(header: Header, proof: HASH64, qc: QuorumCertificate) -> Self {
        Self {
            header,
            proof,
            qc,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn proof(&self) -> &HASH64 {
        &self.proof
    }

    pub(crate) fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    pub(crate) fn split(self) -> (Header, HASH64, QuorumCertificate) {
        (self.header, self.proof, self.qc)
    }
}
