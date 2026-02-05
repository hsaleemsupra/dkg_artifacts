use crate::types::{CryptoError, CryptoResult};
use base64::engine::general_purpose::URL_SAFE as BASE64_ENGINE;
use base64::Engine;

/// Number of characters returned by pretty encode
const PRETTY_ENCODE_LENGTH: usize = 8;

/// Encodes input type into base64 string
pub fn encode_base64<T: AsRef<[u8]>>(src: &T) -> String {
    BASE64_ENGINE.encode(src)
}

/// Encodes input type into hex string
pub fn encode_hex<T: AsRef<[u8]>>(src: &T) -> String {
    hex::encode(src)
}

/// Encodes input type into base64 string and returns first 8 characters
pub fn pretty_encode_base64<T: AsRef<[u8]>>(src: &T) -> String {
    BASE64_ENGINE.encode(src)[0..PRETTY_ENCODE_LENGTH].to_string()
}

/// Encodes input type into base64 string and returns first 8 characters
pub fn pretty_encode_hex<T: AsRef<[u8]>>(src: &T) -> String {
    hex::encode(src)[0..PRETTY_ENCODE_LENGTH].to_string()
}

/// Decodes input string assuming it is base64 encoded string
pub fn decode_base64(src: &str) -> CryptoResult<Vec<u8>> {
    BASE64_ENGINE.decode(src).map_err(CryptoError::from)
}

/// Decodes input string assuming it is base64 encoded string
pub fn decode_hex(src: &str) -> CryptoResult<Vec<u8>> {
    hex::decode(src).map_err(CryptoError::from)
}
