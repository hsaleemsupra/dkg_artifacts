use crate::sosmr_types::{SmrSerialize, SmrTransactionProtocol};
use enum_kinds::EnumKind;
use serde::{Deserialize, Serialize};
use socrypto::{Digest, Identity};
use soserde::impl_size_in_bytes;
use std::fmt::{Debug, Display, Formatter};
use utoipa::ToSchema;

/// Defines supported committee types for which distributed key generation can be conducted.
#[derive(
    Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, ToSchema,
)]
pub enum SmrDkgCommitteeType {
    Smr,
    OracleCommittee(u64),
}

impl Digest for SmrDkgCommitteeType {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(self.to_bytes());
    }
}

impl Display for SmrDkgCommitteeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Coverts [SmrTransactionProtocol] to DKG committee type which output(ThresholdPublicKey) might
/// be required from protocol data verification
impl From<SmrTransactionProtocol> for SmrDkgCommitteeType {
    fn from(value: SmrTransactionProtocol) -> Self {
        match value {
            // Conditionally for now we assume that Move transactions will ever require
            // distributed key generated for SMR committee.
            SmrTransactionProtocol::Move => SmrDkgCommitteeType::Smr,
            SmrTransactionProtocol::Dkg(committee) => committee,
            SmrTransactionProtocol::Oracle(idx) => SmrDkgCommitteeType::OracleCommittee(idx),
        }
    }
}

/// Defines DKG transaction payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgTransactionPayload {
    /// Committee type for which the DKG is being conducted.
    committee: SmrDkgCommitteeType,
    /// Identity of the committee party which created this payload
    party_identity: Identity,
    /// Actual payload
    data: DkgData,
}

impl_size_in_bytes!(DkgTransactionPayload);

impl DkgTransactionPayload {
    pub fn new(committee: SmrDkgCommitteeType, party_identity: Identity, data: DkgData) -> Self {
        Self {
            committee,
            party_identity,
            data,
        }
    }

    pub fn committee(&self) -> SmrDkgCommitteeType {
        self.committee
    }

    pub fn identity(&self) -> &Identity {
        &self.party_identity
    }

    pub fn data(&self) -> &DkgData {
        &self.data
    }

    pub fn data_type(&self) -> DkgDataType {
        DkgDataType::from(&self.data)
    }
}

impl Digest for DkgTransactionPayload {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        self.committee.feed_to(hasher);
        hasher.update(self.party_identity);
        self.data.feed_to(hasher);
    }
}

impl Display for DkgTransactionPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Defines payload type of DKG transaction.
#[derive(Clone, PartialEq, EnumKind, Serialize, Deserialize)]
#[enum_kind(DkgDataType, derive(Serialize, Deserialize))]
pub enum DkgData {
    NoType,
    DKGMetaQC(Vec<u8>),
    //ThresholdSignatureOnThresholdPublicKey(Vec<u8>),
}

impl_size_in_bytes!(DkgData);

impl Debug for DkgData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for DkgData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let len = self.inner().map(|bytes| bytes.len()).unwrap_or(0);
        let data_type = DkgDataType::from(self);
        write!(f, "{:?}({})", data_type, len)
    }
}

impl DkgData {
    pub fn dkg_meta_qc(inner: Vec<u8>) -> Self {
        DkgData::DKGMetaQC(inner)
    }

    /*pub fn threshold_public_key(inner: Vec<u8>) -> Self {
        DkgData::ThresholdSignatureOnThresholdPublicKey(inner)
    }*/

    pub fn inner(&self) -> Option<&Vec<u8>> {
        match self {
            DkgData::DKGMetaQC(inner) => Some(inner),
            //DkgData::ThresholdSignatureOnThresholdPublicKey(data) => Some(data),
            DkgData::NoType => None,
        }
    }
}

impl Digest for DkgData {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(DkgDataType::from(self).to_bytes());
        match self {
            DkgData::DKGMetaQC(data) => data.as_slice().feed_to(hasher),
            /*DkgData::ThresholdSignatureOnThresholdPublicKey(data) => {
                data.as_slice().feed_to(hasher)
            }*/
            DkgData::NoType => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sosmr_types::{SmrDkgCommitteeType, SmrTransactionProtocol};

    #[test]
    fn dkg_committee_type_from_protocol() {
        assert_eq!(
            SmrDkgCommitteeType::from(SmrTransactionProtocol::Move),
            SmrDkgCommitteeType::Smr
        );
        assert_eq!(
            SmrDkgCommitteeType::from(SmrTransactionProtocol::Dkg(SmrDkgCommitteeType::Smr)),
            SmrDkgCommitteeType::Smr
        );
        assert_eq!(
            SmrDkgCommitteeType::from(SmrTransactionProtocol::Dkg(
                SmrDkgCommitteeType::OracleCommittee(16)
            )),
            SmrDkgCommitteeType::OracleCommittee(16)
        );
        assert_eq!(
            SmrDkgCommitteeType::from(SmrTransactionProtocol::Oracle(45)),
            SmrDkgCommitteeType::OracleCommittee(45)
        );
    }

    /*#[test]
    fn dkg_data_api_checks() {
        let proof = [1; 32].to_vec();
        let threshold = [2; 32].to_vec();
        let end = [2; 32].to_vec();
        let threshold_data = DkgData::threshold_public_key(threshold.clone());
        let no_type = DkgData::NoType;
        assert_eq!(
            DkgDataType::ThresholdSignatureOnThresholdPublicKey,
            DkgDataType::from(&threshold_data)
        );
        assert_eq!(&threshold, threshold_data.inner().expect("Valid payload"));
        assert!(no_type.inner().is_none());
        println!("{}", SmrDkgCommitteeType::OracleCommittee(15));
        println!("{:?}", DkgDataType::ThresholdSignatureOnThresholdPublicKey);
    }*/
}
