use crate::Request;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::oneshot::error::RecvError;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("General Error: {0}")]
    GeneralError(String),

    #[error("{0}")]
    ConfigEmptyValue(String),

    #[error("there was a problem while querying the database '{0}'")]
    DatabaseError(#[from] rocksdb::Error),

    #[error("{0}")]
    RequestSenderError(#[from] SendError<Request>),

    #[error("{0}")]
    ReceiverError(#[from] RecvError),
}
