//! Defines supported payload types of [SmrTransaction]

use crate::sosmr_types::transactions::dkg_payload::DkgTransactionPayload;
use crate::sosmr_types::transactions::oracle_payload::OracleTransactionPayload;
use crate::sosmr_types::{SmrSerialize, SmrTransactionProtocol, SmrTransactionProtocolName};
use serde::{Deserialize, Serialize};
use socrypto::Digest;
use soserde::impl_size_in_bytes;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

/// Defines in-house transaction payload types/options.
#[derive(Clone, Serialize, Deserialize)]
pub enum SmrTransactionPayload {
    Dkg(Box<DkgTransactionPayload>),
    Oracle(Box<OracleTransactionPayload>),
}

impl_size_in_bytes!(SmrTransactionPayload);

/// Generic API for owners of [SmrTransactionPayload]
pub trait TTransactionPayload {
    fn payload(&self) -> &SmrTransactionPayload;

    fn is_dkg(&self) -> bool {
        matches!(self.protocol(), SmrTransactionProtocol::Dkg(_))
    }
    fn is_oracle(&self) -> bool {
        matches!(self.protocol(), SmrTransactionProtocol::Oracle(_))
    }

    fn protocol(&self) -> SmrTransactionProtocol {
        SmrTransactionProtocol::from(self.payload())
    }

    fn protocol_name(&self) -> SmrTransactionProtocolName {
        self.protocol().name()
    }

    fn dkg_transaction_payload(&self) -> Option<&DkgTransactionPayload> {
        match self.payload() {
            SmrTransactionPayload::Dkg(data) => Some(data.as_ref()),
            SmrTransactionPayload::Oracle(_) => None,
        }
    }

    fn oracle_transaction_payload(&self) -> Option<&OracleTransactionPayload> {
        match self.payload() {
            SmrTransactionPayload::Oracle(data) => Some(data.as_ref()),
            SmrTransactionPayload::Dkg(_) => None,
        }
    }
}

impl TTransactionPayload for SmrTransactionPayload {
    fn payload(&self) -> &SmrTransactionPayload {
        self
    }
}

impl Digest for SmrTransactionPayload {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(SmrTransactionProtocol::from(self).to_bytes());
        match self {
            SmrTransactionPayload::Dkg(data) => data.feed_to(hasher),
            SmrTransactionPayload::Oracle(data) => data.feed_to(hasher),
        }
    }
}

impl From<DkgTransactionPayload> for SmrTransactionPayload {
    fn from(value: DkgTransactionPayload) -> Self {
        SmrTransactionPayload::Dkg(value.into())
    }
}

impl From<OracleTransactionPayload> for SmrTransactionPayload {
    fn from(value: OracleTransactionPayload) -> Self {
        SmrTransactionPayload::Oracle(value.into())
    }
}

impl Display for SmrTransactionPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            SmrTransactionPayload::Dkg(data) => data.to_string(),
            SmrTransactionPayload::Oracle(data) => data.to_string(),
        };
        write!(f, "{}", value)
    }
}

impl Debug for SmrTransactionPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[cfg(test)]
mod tests {
    use crate::sosmr_types::transactions::oracle_payload::tests::generate_signed_coherent_cluster;
    use crate::sosmr_types::transactions::oracle_payload::OracleTransactionPayload;
    use crate::sosmr_types::{
        DkgData, DkgTransactionPayload, SmrDkgCommitteeType, SmrTransactionPayload,
        SmrTransactionProtocol, TTransactionPayload,
    };
    use socrypto::Identity;

    #[test]
    fn check_smr_transaction_payload_api() {
        let proof = [1; 32].to_vec();
        let proof_data = DkgData::dkg_meta_qc(proof.clone());
        let dkg_payload = DkgTransactionPayload::new(
            SmrDkgCommitteeType::Smr,
            Identity::from([5; 32]),
            proof_data,
        );
        let smr_dkg_payload: SmrTransactionPayload = dkg_payload.into();
        assert!(smr_dkg_payload.is_dkg());
        assert!(!smr_dkg_payload.is_oracle());
        assert!(smr_dkg_payload.dkg_transaction_payload().is_some());
        assert!(smr_dkg_payload.oracle_transaction_payload().is_none());
        assert_eq!(
            smr_dkg_payload.protocol(),
            SmrTransactionProtocol::Dkg(SmrDkgCommitteeType::Smr)
        );

        let oracle_data = generate_signed_coherent_cluster();
        let oracle_payload = OracleTransactionPayload::new(15, oracle_data);
        let smr_oracle_payload: SmrTransactionPayload = oracle_payload.into();
        assert!(!smr_oracle_payload.is_dkg());
        assert!(smr_oracle_payload.is_oracle());
        assert!(smr_oracle_payload.dkg_transaction_payload().is_none());
        assert!(smr_oracle_payload.oracle_transaction_payload().is_some());
        assert_eq!(
            smr_oracle_payload.protocol(),
            SmrTransactionProtocol::Oracle(15)
        );
    }
}
