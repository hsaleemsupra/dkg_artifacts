use serde::{Deserialize, Serialize};

/// Type for the identifier of a single run of the protocol.
///
/// Note: If we want to increase the size of this type then we also need to do the same for
/// the type used by the MoveVM.
pub type ChainId = u8;
/// Type for the identifier of an epoch within the context of a single run of the protocol.
pub type Epoch = u64;

use sha3::Digest as Sha3Digest;
use socrypto::Digest as SoDigest;
use std::fmt;
use utoipa::ToSchema;

/// Unique identifier for a single epoch across multiple runs of the protocol.
#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ToSchema,
)]
pub struct EpochId {
    /// Unique identifier for this instance of the SMR.
    #[schema(value_type = u8, format = "uint8")]
    chain_id: ChainId,
    /// Identifier of the epoch within the context of `chain_id`.
    #[schema(value_type = u64, format = "uint64")]
    epoch: Epoch,
}

impl EpochId {
    pub const GENESIS_EPOCH: Epoch = 0;

    pub fn new(chain_id: ChainId, epoch: Epoch) -> Self {
        Self { chain_id, epoch }
    }

    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn is_genesis(&self) -> bool {
        self.epoch == Self::GENESIS_EPOCH
    }
}

impl SoDigest for EpochId {
    fn feed_to<THasher: Sha3Digest>(&self, hasher: &mut THasher) {
        hasher.update(self.chain_id.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{self:?}")
    }
}

/// Implemented by types that have [EpochId]s to avoid code duplication.
pub trait TEpochId {
    fn epoch_id(&self) -> &EpochId;

    /// Unique identifier for this instance of the SMR.
    fn chain_id(&self) -> ChainId {
        self.epoch_id().chain_id()
    }

    /// Unique identifier (within this run of the protocol) of the related epoch.
    fn epoch(&self) -> Epoch {
        self.epoch_id().epoch()
    }
}
