use crate::errors::SoSerdeError;
use serde::{Deserialize, Serialize};
use std::any::type_name;

/// Interface to define data conversion to bytes.
///
/// Note all the types that implement [Serialize] trait will have default implementation where [bcs::to_bytes]
/// will be used to convert the data to bytes.
pub trait SmrSerialize {
    // Returns the canonical bytes representation of `self`.
    fn to_bytes(&self) -> Vec<u8>;

    /// Returns the canonical bytes representation of `self` or an [SoSerdeError] if serialization fails.
    fn try_to_bytes(&self) -> Result<Vec<u8>, SoSerdeError>;
}

/// Implements `SmrSerialize` for all types by default that implement [Serialize].
impl<T: Serialize> SmrSerialize for T {
    /// Generic `into` for serializing any type that implements `serde::Serialize` into bytes,
    /// via `bcs`, returning the related bytes and panicking if serialization fails. This
    /// function assumes that `bcs` will never fail to serialize any type that implements
    /// `serde::Serialize`, which may be untrue, so should be used with caution.
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Generic `try_into` for serializing any type that implements `serde::Serialize` into bytes,
    /// via `bcs`, returning a result containing the related bytes if serialization succeeds,
    /// or an error that includes the name of the related type if it fails.
    fn try_to_bytes(&self) -> Result<Vec<u8>, SoSerdeError> {
        bcs::to_bytes(self)
            .map_err(|e| SoSerdeError::BcsSerializationError(type_name::<T>().to_string(), e))
    }
}

/// Interface to define data construction from bytes.
///
/// Note all the types that implement [Deserialize] trait will have default implementation where [bcs::from_bytes]
/// will be used to convert the bytes to in-memory object model.
pub trait SmrDeserialize<T>
where
    T: for<'a> Deserialize<'a>,
{
    /// Generic `try_from` for deserializing arbitrary bytes into any type that implements
    /// `serde::Deserialize`, via `bcs`, returning a result containing an instance of
    /// the related type if deserialization succeeds, or an error that includes the name of
    /// the related type if it fails.
    fn try_from_bytes(bytes: &[u8]) -> Result<T, SoSerdeError> {
        bcs::from_bytes(bytes)
            .map_err(|e| SoSerdeError::BcsDeserializationError(type_name::<T>().to_string(), e))
    }
}

/// Implements `SmrDeserialize` for all types by default which implement [Deserialize].
impl<T> SmrDeserialize<T> for T where T: for<'a> Deserialize<'a> {}
