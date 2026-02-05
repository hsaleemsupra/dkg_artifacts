use crate::sosmr_types::{SmrError, SmrSerialize};
// General traits. Could be split into their own modules, but this does not seem necessary yet.

/// This trait is implemented by structures that can be written to the persistent store.
pub trait Storable {
    /// The type used for the keys of items stored in persistent storage.
    type StoreKey: SmrSerialize;

    fn store_key(&self) -> Self::StoreKey;
}

/// This trait is implemented for structs that can be verified by the data that can verify them.
/// It is primarily intended for SMR messages.
///
/// Taking this approach allows us to create ref-based [Verifier]s without complicating other
/// definitions with additional lifetime constraints. We often prefer to use ref-based verifiers
/// because the underlying structs (e.g. [Committee]) are large so we prefer to avoid cloning them.
pub trait Verifier<D> {
    fn verify(&self, data: &D) -> Result<(), SmrError>;
}
