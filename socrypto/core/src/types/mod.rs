/// Defines type Digest which represents hashed object as well as our own `Hash` trait.
pub mod digest;
/// Defines `pub enum CryptoError` as well as `pub type CryptoResult<T> = Result<T, CryptoError>`.
pub mod error;
/// Defines generic interfaces which helps to implement serde api on higher level wrapper data structures.
pub mod serde;

pub use digest::{Digest, Hash};
pub use error::{CryptoError, CryptoResult};
pub use identity::Identity;
pub use order::Order;

/// Defines ownable trait for private data.
pub mod ownable;

/// Provides concrete implementations of cryptographic schemes.
pub mod impls;

/// Provides definition of unique identity concept.
pub mod identity;
/// Provides definition of the order of the party in the set of similar
pub mod order;

/// Provides trait for struct with unique string identifier.
pub mod domain;

/// Defines traits representing cryptographic schemes.
pub mod schemes;
