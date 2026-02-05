use crate::types::schemes::single_sig_scheme::SignatureScheme;

/// Contains wrapper struct for proof of possession of signing key for single signer scheme
/// as well as associated implemented functions.
pub mod pop;
/// Contains wrapper struct for public parameters for single signer scheme as well as
/// associated implemented functions.
pub mod public_parameters;
/// Contains wrapper struct for signature for single signer scheme as well as
/// associated implemented functions.
pub mod signature;
/// Contains wrapper struct for signing key for single signer scheme as well as
/// associated implemented functions.
pub mod signing_key;
/// Contains wrapper struct for verification key for single signer scheme as well as
/// associated implemented functions.
pub mod verification_key;

#[cfg(test)]
mod mock_signature_schema;

pub use pop::PopWrapperSig;
pub use public_parameters::PublicParametersWrapperSig;
pub use signature::SignatureWrapper;
pub use signing_key::SigningKeyWrapperSig;
pub use verification_key::VerificationKeyWrapperSig;
