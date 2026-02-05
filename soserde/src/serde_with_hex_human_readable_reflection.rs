//! Defines means to serialize/deserialize slice types reflecting on serde interface human-readable factor.
//!
use crate::errors::SoSerdeError;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use std::fmt::Display;

pub const HEX_ENCODE_PREFIX: &str = "0x";

/// Provides means to serde types which have internal slice representation based on the serde
/// human-readable configuration property.
///
/// If serde is configured to be human-readable then hex codec is used on data before serializing it.
/// Otherwise, no encoding is applied on data, and it is serialized/deserialized using default logic
/// of the passed serde on the slice.
///
/// Generic parameter provides means to configure [HEX_ENCODE_PREFIX] prefix to the hex-encoded string.
pub struct HexHumanReadableSerde<const PREFIXED: bool> {}
impl<const PREFIXED: bool> HexHumanReadableSerde<PREFIXED> {
    /// Trys to decode input string using hex decoder.
    /// [HEX_ENCODE_PREFIX] prefix is trimmed if any observed.
    pub fn try_decode_hex(input: &str) -> Result<Vec<u8>, SoSerdeError> {
        // If no prefix is available returns input as it is
        let encoded_input = input.trim_start_matches(HEX_ENCODE_PREFIX);
        hex::decode(encoded_input).map_err(SoSerdeError::HexDecode)
    }

    /// Encodes input type ot hex string.
    /// [HEX_ENCODE_PREFIX] is added iif [PREFIXED] is true.
    pub fn encode_hex<T: AsRef<[u8]>>(value: &T) -> String {
        let encoded_value = hex::encode(value);
        if PREFIXED {
            [HEX_ENCODE_PREFIX, encoded_value.as_str()]
                .join("")
                .to_string()
        } else {
            encoded_value
        }
    }

    pub fn deserialize_into_vec<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            String::deserialize(deserializer)
                .and_then(|str| Self::try_decode_hex(str.as_str()).map_err(Error::custom))
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
    pub fn deserialize<'de, D, T: for<'a> TryFrom<&'a [u8]>>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        for<'a> <T as TryFrom<&'a [u8]>>::Error: Display,
    {
        Self::deserialize_into_vec(deserializer)
            .and_then(|bytes| T::try_from(bytes.as_slice()).map_err(Error::custom))
    }

    pub fn serialize<S, T: AsRef<[u8]>>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(Self::encode_hex::<T>(value).as_str())
        } else {
            serializer.serialize_bytes(value.as_ref())
        }
    }
}

/// Shortcut type for human-readable serde APIs to have [HEX_ENCODE_PREFIX] during serialization.
pub type HexHumanReadableSerdeWithPrefix = HexHumanReadableSerde<true>;
/// Shortcut type for human-readable serde APIs with no prefix during serialization.
pub type HexHumanReadableSerdeWithoutPrefix = HexHumanReadableSerde<false>;

#[cfg(test)]
mod tests {
    use crate::{
        HexHumanReadableSerdeWithPrefix, HexHumanReadableSerdeWithoutPrefix, SmrSerialize,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::de::StrRead;
    use serde_json::{Deserializer, Serializer};

    #[test]
    fn check_encode_and_serialize_human_readable() {
        let data = "test_encode_serialize";
        // prepare expected data
        let encoded = hex::encode(data);
        let expected_data = format!(r#""0x{encoded}""#);

        // prepare serializer
        let mut ser_data = Vec::<u8>::new();
        let mut serializer = Serializer::new(&mut ser_data);

        let result = HexHumanReadableSerdeWithPrefix::serialize(&data, &mut serializer);
        assert!(result.is_ok());

        let actual_result = unsafe { String::from_utf8_unchecked(ser_data) };
        assert_eq!(actual_result, expected_data);
    }

    #[test]
    fn check_deserialize_and_decode_human_readable() {
        // prepare test data
        let data = "test_encode_serialize";
        let encoded = hex::encode(data.as_bytes());
        let serialized_data = format!(r#""{encoded}""#);

        // prepare deserializer
        let reader = StrRead::new(serialized_data.as_str());
        let mut deserializer = Deserializer::new(reader);

        let result = HexHumanReadableSerdeWithPrefix::deserialize(&mut deserializer);
        assert!(result.is_ok());
        let actual_result = unsafe { String::from_utf8_unchecked(result.unwrap()) };
        assert_eq!(actual_result, data);
    }

    #[test]
    fn check_negative_deserialize_and_decode_human_readable() {
        // prepare test data
        let data = "test_encode_serialize";
        let serialized_data = format!(r#""{data}""#);

        // prepare deserializer
        let reader = StrRead::new(serialized_data.as_str());
        let mut deserializer = Deserializer::new(reader);

        let result: Result<Vec<u8>, _> =
            HexHumanReadableSerdeWithPrefix::deserialize(&mut deserializer);
        assert!(result.is_err(), "{:?}", result);
    }

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    struct ArrayWrapperWithHexPrefixSerde(
        #[serde(with = "HexHumanReadableSerdeWithPrefix")] [u8; 32],
    );

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    struct ArrayWrapperWithoutHexPrefixSerde(
        #[serde(with = "HexHumanReadableSerdeWithoutPrefix")] [u8; 32],
    );
    #[test]
    fn check_encode_and_serialize_non_human_readable() {
        let inner_data: [u8; 32] = "test_encode_serialize_make_it_32"
            .as_bytes()
            .try_into()
            .expect("Valid 32 bytes static array");
        let data = ArrayWrapperWithHexPrefixSerde(inner_data);
        // prepare expected data, size and bytes
        let mut expected_data = vec![32];
        expected_data.extend(data.0);

        let actual_result = bcs::to_bytes(&data).expect("Successful serialization");
        assert_eq!(actual_result, expected_data);
        // Check that decoding is successful with non-human-readable deserializer
        // if [HexHumanReadableSerde] is specified as serde API
        let result = bcs::from_bytes::<ArrayWrapperWithHexPrefixSerde>(&expected_data);
        assert_eq!(result, Ok(data));

        let data = ArrayWrapperWithoutHexPrefixSerde(inner_data);

        let actual_result = bcs::to_bytes(&data).expect("Successful serialization");
        assert_eq!(actual_result, expected_data);

        // Check that decoding is successful with non-human-readable deserializer
        // if [HexHumanReadableSerde] is specified as serde API
        let result = bcs::from_bytes::<ArrayWrapperWithoutHexPrefixSerde>(&expected_data);
        assert_eq!(result, Ok(data));

        // Check that hex encoded data will not be parsed by non-human readable deserializer
        // even if [HexHumanReadableSerde] is specified as serde API.
        let hex_encoded_data = hex::encode(expected_data).to_bytes();

        assert!(bcs::from_bytes::<ArrayWrapperWithHexPrefixSerde>(&hex_encoded_data).is_err());
        assert!(bcs::from_bytes::<ArrayWrapperWithoutHexPrefixSerde>(&hex_encoded_data).is_err());
    }
}
