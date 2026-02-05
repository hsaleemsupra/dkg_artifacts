use bcs::Error as BcsError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SoSerdeError {
    #[error("Failed to serialize {0} due to {1}")]
    BcsSerializationError(String, BcsError),
    #[error("Failed to deserialize {0} due to {1}")]
    BcsDeserializationError(String, BcsError),

    /// Hex decoder error
    #[error("HexDecode: {0}")]
    HexDecode(#[from] FromHexError),

    // Old errors. Need to be reviewed and potentially refactored.
    #[error("General err: {0}")]
    GeneralError(String),
}
