/// Multisig implementation on BLS12381 curve.
pub mod bls12381;

use crate::types::schemes::aggregated_signature_scheme::{
    multisig_scheme::{GenericMultiSignature, GenericPublicParameters, MultiSignatureScheme},
    AggregateSignatureScheme,
};
