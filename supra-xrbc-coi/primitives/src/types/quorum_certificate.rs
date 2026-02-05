use crate::{Stringify, HASH96};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

///
/// Data structure representing Quorum Certificate on the data created based on the
/// threshold signature by distributed key
///
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct QuorumCertificate {
    /// Threshold signature on deliverable data
    #[serde(with = "BigArray")]
    data: HASH96,
    /// List of participants (nodes' positions in the clan) contributed in threshold signature
    participants: BTreeSet<u32>,
}

impl Display for QuorumCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QuorumCertificate ({}, {:?})",
            self.data.hex_display(),
            self.participants
        )
    }
}

impl Debug for QuorumCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl QuorumCertificate {
    pub fn new(data: HASH96, participants: BTreeSet<u32>) -> Self {
        Self { data, participants }
    }

    pub fn data(&self) -> &HASH96 {
        &self.data
    }

    pub fn participants(&self) -> &BTreeSet<u32> {
        &self.participants
    }
}

impl Default for QuorumCertificate {
    fn default() -> Self {
        Self {
            data: [0; 96],
            participants: Default::default(),
        }
    }
}
