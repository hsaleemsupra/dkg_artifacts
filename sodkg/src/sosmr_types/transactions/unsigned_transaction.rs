//! Defines unsigned version of the [SignedSmrTransaction]

use crate::sosmr_types::transactions::header::{SmrTransactionHeader, TTransactionHeader};
use crate::sosmr_types::transactions::payload::{SmrTransactionPayload, TTransactionPayload};
use crate::sosmr_types::transactions::signed_transaction::SignedSmrTransaction;
use crate::sosmr_types::transactions::signer_data::SignerData;
use crate::sosmr_types::TSigner;
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Keccak256};
use socrypto::{Digest, Hash, HasherBuilder, PublicKey, Signature};
use soserde::impl_size_in_bytes;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ops::DerefMut;
use std::sync::OnceLock;

/// Defines unsigned transaction enclosing only header and payload information.
#[derive(Clone, Serialize, Deserialize)]
pub struct UnsignedSmrTransaction {
    /// Header of the transaction containing meta information of transaction. See [SmrTransactionHeader]
    header: SmrTransactionHeader,
    /// Actual payload of the transaction tagged based on the protocol type.
    payload: SmrTransactionPayload,
    /// One time precalculated digest of the transaction.
    #[serde(skip)]
    digest: OnceLock<Hash>,
}

impl_size_in_bytes!(UnsignedSmrTransaction);

impl UnsignedSmrTransaction {
    pub fn new(header: SmrTransactionHeader, payload: SmrTransactionPayload) -> Self {
        Self {
            header,
            payload,
            digest: Default::default(),
        }
    }

    /// Signs the transaction with provided signer and converts it to [SignedSmrTransaction]
    pub fn into_signed_transaction<Signer: TSigner<Signature, VerificationKey = PublicKey>>(
        self,
        signer: &Signer,
    ) -> SignedSmrTransaction {
        let signature = signer.sign(&self.digest());
        let signer_data = SignerData::new(signer.verification_key(), signature);
        SignedSmrTransaction::new(signer_data, self)
    }
}

impl TTransactionHeader for UnsignedSmrTransaction {
    fn header(&self) -> &SmrTransactionHeader {
        &self.header
    }
}

impl TTransactionPayload for UnsignedSmrTransaction {
    fn payload(&self) -> &SmrTransactionPayload {
        &self.payload
    }
}

impl Digest for UnsignedSmrTransaction {
    fn digest(&self) -> Hash {
        *self.digest.get_or_init(|| {
            let mut hasher = HasherBuilder::<Keccak256>::get_hasher();
            self.feed_to(hasher.deref_mut());
            Hash(hasher.hash())
        })
    }

    fn feed_to<THasher: Sha3Digest>(&self, hasher: &mut THasher) {
        self.header.feed_to(hasher);
        self.payload.feed_to(hasher);
    }
}

impl From<UnsignedSmrTransaction> for SmrTransactionPayload {
    fn from(t: UnsignedSmrTransaction) -> Self {
        t.payload
    }
}

impl PartialEq for UnsignedSmrTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.digest().eq(&other.digest())
    }
}

impl Display for UnsignedSmrTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}, {})", self.digest(), self.header, self.payload)
    }
}

impl Debug for UnsignedSmrTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
#[cfg(test)]
mod tests {
    use crate::sosmr_types::{
        AccountAddress, DkgData, DkgTransactionPayload, SequenceNumber, SmrDkgCommitteeType,
        SmrTimestamp, SmrTransactionHeader, SmrTransactionHeaderBuilder, Storable, TSignerData,
        TTransactionHeaderProperties, TTransactionPayload, UnsignedSmrTransaction,
    };
    use socrypto::{Digest, Identity, SecretKey};

    pub(crate) fn create_transaction_header(
        address: AccountAddress,
        sequence_number: SequenceNumber,
    ) -> SmrTransactionHeader {
        SmrTransactionHeaderBuilder::new()
            .with_sender(address)
            .with_sequence_number(sequence_number)
            .with_expiration_timestamp(SmrTimestamp::seconds_from_now(10))
            .with_chain_id(0)
            .with_gas_price(5)
            .with_max_gas_amount(10)
            .build()
            .expect("Regression in constructing DKG TXN Header")
    }

    fn create_dkg_transaction(
        account_address: AccountAddress,
        identity: Identity,
        dkg_type: SmrDkgCommitteeType,
        dkg_data: DkgData,
        sequence_number: SequenceNumber,
    ) -> UnsignedSmrTransaction {
        let dkg_txn_payload = DkgTransactionPayload::new(dkg_type, identity, dkg_data);
        let header = create_transaction_header(account_address, sequence_number);
        UnsignedSmrTransaction::new(header, dkg_txn_payload.into())
    }
    #[test]
    fn check_unsigned_smr_transaction_apis() {
        let sk = SecretKey::new();
        let pk = sk.gen_vk();
        let pk_bytes = pk.to_bytes();
        let identity = Identity::new(pk_bytes);
        let address = AccountAddress::supra_address(pk_bytes);

        let dkg_data = DkgData::dkg_meta_qc([0, 1, 2, 3].to_vec());
        let committee_type = SmrDkgCommitteeType::Smr;
        let seq = 3;
        let dkg_txn = create_dkg_transaction(address, identity, committee_type, dkg_data, seq);
        assert!(dkg_txn.is_dkg());
        assert!(dkg_txn.dkg_transaction_payload().is_some());
        assert_eq!(address, dkg_txn.sender());
        assert_eq!(seq, dkg_txn.sequence_number());

        let signed_dkg_txn = dkg_txn.clone().into_signed_transaction(&sk);

        assert_eq!(signed_dkg_txn.digest(), dkg_txn.digest());
        assert_eq!(signed_dkg_txn.signer(), &pk);
        assert!(signed_dkg_txn.is_dkg());
        assert!(dkg_txn.dkg_transaction_payload().is_some());
        assert_eq!(address, dkg_txn.sender());
        assert_eq!(seq, dkg_txn.sequence_number());
        assert_eq!(signed_dkg_txn.protocol(), dkg_txn.protocol());
        assert_eq!(signed_dkg_txn.store_key(), signed_dkg_txn.digest());

        let expected_signature = sk.sign(&dkg_txn.digest());
        assert_eq!(signed_dkg_txn.signature(), &expected_signature);
    }
}
