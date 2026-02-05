use bincode::Error as BincodeError;
use std::io::Error as IOError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommonError {
    #[error("{0}")]
    SerdeError(#[from] BincodeError),

    #[error("{0}")]
    UnboundSendError(String),

    #[error("{0}")]
    InvalidData(String),
}

impl From<CommonError> for IOError {
    fn from(e: CommonError) -> Self {
        match e {
            CommonError::SerdeError(_) => IOError::new(std::io::ErrorKind::InvalidData, e),
            CommonError::InvalidData(_) => IOError::new(std::io::ErrorKind::InvalidData, e),
            CommonError::UnboundSendError(_) => IOError::new(std::io::ErrorKind::Interrupted, e),
        }
    }
}
