use crate::sosmr_types::{ChainId, Epoch, EpochId, TEpochId};
use serde::{Deserialize, Serialize};
use sha3::Digest as Sha3Digest;
use socrypto::Digest as SoDigest;
use std::fmt;
use utoipa::ToSchema;

/// The consensus round number.
pub type Round = u64;

/// Unique identifier for a single view across multiple runs of the protocol.
///
/// // The ordering of the fields in this struct and in [EpochId] are important as the define
/// // the ranking of each element in the PartialEq implementation. The intended ranking is
/// // equivalent to that for the triple containing (chain id, epoch, round)---i.e., lexicographic
/// // comparison with the chain id having the highest rank and the round the lowest.
/// //
/// // TODO: Define API types and remove ToSchema derive.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    ToSchema,
)]
pub struct View {
    /// Identifier of the consensus epoch.
    pub epoch_id: EpochId,
    /// Identifier of the consensus round.
    #[schema(value_type = u64, format = "uint64")]
    pub round: Round,
}

impl View {
    pub const GENESIS_ROUND: Round = 0;

    //----------------------------------------Constructors----------------------------------------

    pub fn new(chain_id: ChainId, epoch: Epoch, round: Round) -> Self {
        Self {
            epoch_id: EpochId::new(chain_id, epoch),
            round,
        }
    }

    //-----------------------------------------Accessors-----------------------------------------

    /// The related consensus round within the related epoch.
    pub fn round(&self) -> Round {
        self.round
    }

    //------------------------------------------General------------------------------------------

    pub fn is_first_in_epoch(&self) -> bool {
        self.round == 0
    }

    pub fn is_genesis(&self) -> bool {
        self.epoch_id.is_genesis() && self.round == Self::GENESIS_ROUND
    }
}

impl SoDigest for View {
    fn feed_to<THasher: Sha3Digest>(&self, hasher: &mut THasher) {
        self.epoch_id.feed_to(hasher);
        hasher.update(self.round.to_le_bytes());
    }
}

impl fmt::Display for View {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{self:?}")
    }
}

impl TEpochId for View {
    /// Unique identifier (across all runs of the protocol) of the related epoch.
    fn epoch_id(&self) -> &EpochId {
        &self.epoch_id
    }
}

impl<T: TView> TEpochId for T {
    fn epoch_id(&self) -> &EpochId {
        self.view().epoch_id()
    }
}

/// Implemented by types that contain [View]s. Reduces code duplication.
pub trait TView {
    /// View for which the implementing type was proposed.
    fn view(&self) -> &View;

    /// Round for which the implementing type was proposed.
    fn round(&self) -> Round {
        self.view().round()
    }
}
