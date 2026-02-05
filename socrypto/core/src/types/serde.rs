use crate::types::{CryptoError, CryptoResult};
use serde::de::Error as D_Error;
use serde::{Deserializer, Serializer};
use soserde::HexHumanReadableSerdeWithoutPrefix;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Marker trait which by default requires Zeroize feature from the types implementing [TCryptoSerde].
pub trait TCryptoSecureSerde {}

impl<T> TCryptoSecureSerde for T
where
    T: TCryptoSerde,
    <T as TRawRepresentation>::Raw: Zeroize + ZeroizeOnDrop,
{
}

/// Generic interface providing means to convert a data type to its raw representation to make
/// serde of the object strait-forward.
/// Provides default API to serialize and deserialize an object based on its raw representation.
pub trait TCryptoSerde: TRawRepresentation {
    /// API to deserialize a concrete object in two phases
    /// 1. deserialize to raw representation of the object
    /// 2. from raw to the concrete object
    fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
        Self: Sized,
    {
        let data = <Self as TRawRepresentation>::deserialize(deserializer)?;
        <Self as TRawRepresentation>::from_raw(data).map_err(|e| D::Error::custom(e.to_string()))
    }

    /// API to serialize a concrete object in two phases
    /// 1. from the concrete object to a raw representation
    /// 2. serialize raw representation
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <Self as TRawRepresentation>::serialize(&self.to_raw(), serializer)
    }
}

impl<T> TCryptoSerde for T where T: TRawRepresentation {}

/// Generic interface defining RAW representation of the data
pub trait TRawRepresentation {
    /// Type defining raw representation of the object
    type Raw: AsRef<[u8]> + AsMut<[u8]>;
    /// Creates dummy object of [Self::Raw] type
    fn create() -> Self::Raw;

    /// Creates a concrete object based on its defined raw representation.
    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized;

    /// Converts an object to its defined raw representation.
    fn to_raw(&self) -> Self::Raw;

    /// Constructs [Self::Raw] from input slice
    /// Returns error if size of the slice does not match the size of [Self::Raw] in bytes
    fn from(data: &[u8]) -> CryptoResult<Self::Raw> {
        let mut raw = Self::create();
        if raw.as_ref().len() != data.len() {
            Err(CryptoError::ConversionSizeError {
                expected: raw.as_ref().len(),
                actual: data.len(),
            })
        } else {
            raw.as_mut().copy_from_slice(data);
            Ok(raw)
        }
    }

    /// Describes deserialization of [Self::Raw] type object
    fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self::Raw, D::Error> {
        HexHumanReadableSerdeWithoutPrefix::deserialize_into_vec::<'de, D>(deserializer)
            .and_then(|bytes| Self::from(bytes.as_slice()).map_err(D::Error::custom))
    }
    /// Describes serialization of [Self::Raw] type object
    fn serialize<S: Serializer>(raw: &Self::Raw, serializer: S) -> Result<S::Ok, S::Error> {
        HexHumanReadableSerdeWithoutPrefix::serialize(raw, serializer)
    }
}

/// Const size array serde wrapper
pub struct DefaultRawRepresentation<const N: usize>;

impl<const N: usize> TRawRepresentation for DefaultRawRepresentation<N> {
    type Raw = [u8; N];

    fn create() -> Self::Raw {
        [0; N]
    }

    fn from_raw(_src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        Ok(DefaultRawRepresentation)
    }

    fn to_raw(&self) -> Self::Raw {
        Self::create()
    }
}

#[cfg(test)]
mod tests {
    use crate::types::serde::{DefaultRawRepresentation, TRawRepresentation};

    #[test]
    fn check_default_from_implementation() {
        let vec_5 = [0u8, 1, 2, 5, 8];
        let default_5 = <DefaultRawRepresentation<5> as TRawRepresentation>::from(vec_5.as_ref());
        assert!(default_5.is_ok());

        let default_7 = <DefaultRawRepresentation<7> as TRawRepresentation>::from(vec_5.as_ref());
        assert!(default_7.is_err())
    }
}
