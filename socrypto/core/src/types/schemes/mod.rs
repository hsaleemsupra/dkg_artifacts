/// Defines trait representing multi-part aggregated signature scheme in cryptographic layer.
#[cfg(feature = "agg_sig")]
pub mod aggregated_signature_scheme;
/// Defines trait representing single signer signature scheme in cryptographic layer.
/// also provides wrapper structs which define application layer api
#[cfg(feature = "sig")]
pub mod single_sig_scheme;
