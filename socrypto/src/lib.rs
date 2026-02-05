pub use socrypto_core::types::impls::sig_ecdsa_ed25519::PUBLIC_KEY_LENGTH;
pub use socrypto_core::types::impls::sig_ecdsa_ed25519::SECRET_KEY_LENGTH;
pub use socrypto_core::types::impls::sig_ecdsa_ed25519::SIGNATURE_LENGTH;

use socrypto_core::api::instances::ecdsa_sig_ed25519::SignatureEd25519Sig;
use socrypto_core::api::instances::ecdsa_sig_ed25519::SigningKeyEd25519Sig;
use socrypto_core::api::instances::ecdsa_sig_ed25519::VerificationKeyEd25519Sig;

pub use socrypto_core::types::digest::{digest, Digest, Hash, HASH_LENGTH};
pub use socrypto_core::types::error::CryptoError as SupraCryptoError;
pub use socrypto_core::types::identity::{Identity, IDENTITY_LENGTH};
pub use socrypto_core::types::impls::helpers::hasher::HasherBuilder;

pub type SecretKey = SigningKeyEd25519Sig;
pub type PublicKey = VerificationKeyEd25519Sig;
pub type Signature = SignatureEd25519Sig;
