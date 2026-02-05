use crate::error::StorageError;
use crate::{Request, StorageKey, StorageReadIfc, StorageResult, StorageValue, StorageWriteIfc};
use async_trait::async_trait;
use log::error;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone)]
pub struct StorageClient {
    tx: UnboundedSender<Request>,
}

impl StorageClient {
    pub fn new(tx: UnboundedSender<Request>) -> Self {
        Self { tx }
    }
}

impl StorageWriteIfc for StorageClient {
    fn write(&self, key: StorageKey, value: StorageValue) {
        self.tx
            .send(Request::Write(key, value))
            .unwrap_or_else(|e| log::error!("SendError {}", e));
    }
}

#[async_trait]
impl StorageReadIfc for StorageClient {
    async fn has_key(&self, key: StorageKey) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        match self.tx.send(Request::Probe(key, tx)) {
            Ok(_) => rx.await.unwrap_or(false),
            Err(e) => {
                error!("Failed to probe the storage: {:?}", e);
                false
            }
        }
    }

    fn has_key_blocking(&self, key: StorageKey) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        match self.tx.send(Request::Probe(key, tx)) {
            Ok(_) => rx.blocking_recv().unwrap_or(false),
            Err(e) => {
                error!("Failed to probe the storage: {:?}", e);
                false
            }
        }
    }

    async fn read(&self, key: StorageKey) -> Option<StorageValue> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        match self.tx.send(Request::Read(key, tx)) {
            Ok(_) => rx.await.unwrap_or(None),
            Err(e) => {
                error!("Failed to read from storage: {:?}", e);
                None
            }
        }
    }

    fn read_blocking(&self, key: StorageKey) -> Option<StorageValue> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        match self.tx.send(Request::Read(key, tx)) {
            Ok(_) => rx.blocking_recv().unwrap_or(None),
            Err(e) => {
                error!("Failed to read from storage: {:?}", e);
                None
            }
        }
    }

    async fn subscribe(&self, key: StorageKey) -> StorageResult<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(Request::Subscribe(key, tx))?;
        rx.await.map_err(StorageError::ReceiverError)
    }

    fn subscribe_blocking(&self, key: StorageKey) -> StorageResult<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx.send(Request::Subscribe(key, tx))?;
        rx.blocking_recv().map_err(StorageError::ReceiverError)
    }
}
