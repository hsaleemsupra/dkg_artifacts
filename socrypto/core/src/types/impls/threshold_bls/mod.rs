// NOTE once we use generics we can combine bn254 and bls12381

/// BLS Threshold Signatures on BLS12381 Curve
pub mod bls12381;
// /// BLS Threshold Signatures on BLS12381 Curve for verification with mcl library
/// (uses different G2 generator and hash_to_ecp function)
pub mod mcl;
/// BLS Threshold Signatures on BLS12381 Curve with reversed groups (signatures in G2)
pub mod rev_bls12381;

use crate::types::schemes::aggregated_signature_scheme::{
    threshold_sig_scheme::GenericPublicParameters, AggregateSignatureScheme, TPublicParameters,
    ThresholdSignatureScheme,
};

/// placeholder struct for not yet implemented cgdkg types
pub struct PlaceholderCgKeys;
