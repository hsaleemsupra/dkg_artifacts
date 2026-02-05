use crate::sosmr_types::{SmrDkgCommitteeType, SmrTransactionPayload};
use enum_kinds::EnumKind;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::hash::Hash;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq, Hash, EnumKind, ToSchema)]
#[enum_kind(SmrTransactionProtocolName, derive(Hash))]
#[repr(u8)]
pub enum SmrTransactionProtocol {
    Move = 1,
    Dkg(SmrDkgCommitteeType),
    Oracle(u64),
}

impl SmrTransactionProtocol {
    pub fn name(&self) -> SmrTransactionProtocolName {
        SmrTransactionProtocolName::from(self)
    }
}

impl From<&SmrTransactionPayload> for SmrTransactionProtocol {
    fn from(value: &SmrTransactionPayload) -> Self {
        match value {
            SmrTransactionPayload::Dkg(data) => SmrTransactionProtocol::Dkg(data.committee()),
            SmrTransactionPayload::Oracle(data) => {
                SmrTransactionProtocol::Oracle(data.committee_index())
            }
        }
    }
}

impl PartialOrd<Self> for SmrTransactionProtocol {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Agreed on the following priority of the protocols unless otherwise is defined DKG - Oracle - Move (from high to low)
impl Ord for SmrTransactionProtocol {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            SmrTransactionProtocol::Dkg(_) => {
                if !matches!(other, SmrTransactionProtocol::Dkg(_)) {
                    return Ordering::Greater;
                }
            }
            SmrTransactionProtocol::Oracle(_) => {
                if !matches!(other, SmrTransactionProtocol::Oracle(_)) {
                    return other.cmp(self).reverse();
                }
            }
            SmrTransactionProtocol::Move => {
                if !self.eq(other) {
                    return Ordering::Less;
                }
            }
        }
        Ordering::Equal
    }
}
