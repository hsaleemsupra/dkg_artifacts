//! Defines signed version of SMR transaction

use crate::sosmr_types::transactions::header::{SmrTransactionHeader, TTransactionHeader};
use crate::sosmr_types::transactions::oracle_payload::SignedCoherentCluster;
use crate::sosmr_types::transactions::payload::{SmrTransactionPayload, TTransactionPayload};
use crate::sosmr_types::transactions::signer_data::{SignerData, TSignerData};
use crate::sosmr_types::transactions::unsigned_transaction::UnsignedSmrTransaction;
use crate::sosmr_types::{SmrError, Storable, Verifier};
use nidkg_helper::BlsPublicKey;
use serde::{Deserialize, Serialize};
use socrypto::{Digest, Hash};
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hasher;
use utoipa::ToSchema;

/// Defines internal transactions(DKG and Oracle) coupled with signer data.
#[derive(Clone, Serialize, Deserialize, ToSchema)]
pub struct SignedSmrTransaction {
    /// Signer data on the transaction.
    #[schema(value_type = Object)]
    signer_data: SignerData,
    /// Unsigned internal transaction.
    #[schema(value_type = Object)]
    transaction: UnsignedSmrTransaction,
}

impl SignedSmrTransaction {
    pub(crate) fn new(signer_data: SignerData, transaction: UnsignedSmrTransaction) -> Self {
        Self {
            signer_data,
            transaction,
        }
    }

    pub fn unsigned_transaction(&self) -> &UnsignedSmrTransaction {
        &self.transaction
    }
}

impl TTransactionHeader for SignedSmrTransaction {
    fn header(&self) -> &SmrTransactionHeader {
        self.transaction.header()
    }
}

impl TTransactionPayload for SignedSmrTransaction {
    fn payload(&self) -> &SmrTransactionPayload {
        self.transaction.payload()
    }
}

impl TSignerData for SignedSmrTransaction {
    fn signer_data(&self) -> &SignerData {
        &self.signer_data
    }
}

impl PartialOrd for SignedSmrTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SignedSmrTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.signature() == other.signature()
    }
}

impl Ord for SignedSmrTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.signature()
            .to_bytes()
            .cmp(&other.signature().to_bytes())
    }
}

impl Eq for SignedSmrTransaction {}

impl std::hash::Hash for SignedSmrTransaction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature().hash(state);
    }
}

impl Digest for SignedSmrTransaction {
    /// Returns the digest of the internal unsigned transaction.
    fn digest(&self) -> Hash {
        self.transaction.digest()
    }
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(self.digest())
    }
}

impl Storable for SignedSmrTransaction {
    type StoreKey = Hash;

    fn store_key(&self) -> Self::StoreKey {
        self.digest()
    }
}

impl From<SignedSmrTransaction> for SmrTransactionPayload {
    fn from(t: SignedSmrTransaction) -> Self {
        SmrTransactionPayload::from(t.transaction)
    }
}

impl Verifier<SignedSmrTransaction> for Option<&BlsPublicKey> {
    /// TODO: Need to improve the generality of the implementation.
    fn verify(&self, t: &SignedSmrTransaction) -> Result<(), SmrError> {
        // Ensure that the signature is derived from the digest of the transaction and belongs
        // to the author of the transaction.
        t.signer_data.verify_on_message(&t.digest())?;

        // Verify the payload.
        // TODO: Should have a separate verifier class for each type of transaction.
        // This implementation needs work.

        if t.is_oracle() {
            let oracle_payload = t.payload().oracle_transaction_payload().unwrap();
            self.ok_or_else(|| SmrError::CertificateBlsThresholdPublicKeyMissing)
                .and_then(|key| {
                    <&BlsPublicKey as Verifier<SignedCoherentCluster>>::verify(
                        &key,
                        oracle_payload.cluster_data(),
                    )
                })?;
        }
        Ok(())
    }
}

impl Debug for SignedSmrTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedSmrTransaction({}, {})",
            self.transaction, self.signer_data
        )
    }
}
impl Display for SignedSmrTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
