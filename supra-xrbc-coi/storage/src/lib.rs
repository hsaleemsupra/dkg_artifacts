use crate::config::StorageConfig;
use crate::error::StorageError;
use crate::storage_client::StorageClient;
use async_trait::async_trait;
use primitives::{NotificationSender, Payload, HASH32};
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;

pub mod config;
pub mod error;
pub mod rocksdb_store;
pub mod storage_client;
#[cfg(test)]
mod tests;
pub type ColumnFamilyName = &'static str;
pub type Entry<V> = (HASH32, V);
pub type Entries<V> = Vec<Entry<V>>;
pub type StorageResult<T> = Result<T, StorageError>;

pub type StorageKey = HASH32;
pub type StorageValue = Payload;

#[async_trait]
pub trait StorageReadIfc {
    async fn has_key(&self, key: StorageKey) -> bool;

    fn has_key_blocking(&self, key: StorageKey) -> bool;

    async fn read(&self, key: StorageKey) -> Option<StorageValue>;

    fn read_blocking(&self, key: StorageKey) -> Option<StorageValue>;

    async fn subscribe(&self, key: StorageKey) -> StorageResult<()>;

    fn subscribe_blocking(&self, key: StorageKey) -> StorageResult<()>;
}

pub trait StorageWriteIfc {
    fn write(&self, key: StorageKey, value: StorageValue);
}

pub trait Engine
where
    Self: Sized,
{
    fn spawn(config: &StorageConfig<Self>) -> StorageResult<StorageClient>;
    fn spawn_blocking(config: &StorageConfig<Self>) -> StorageResult<StorageClient>;
}

#[derive(Debug)]
pub enum Request {
    Write(StorageKey, StorageValue),
    Read(StorageKey, NotificationSender<Option<StorageValue>>),
    Subscribe(StorageKey, NotificationSender<()>),
    Probe(StorageKey, NotificationSender<bool>),
}

impl Display for Request {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Write(_, _) => {
                write!(f, "Write")
            }
            Request::Read(_, _) => {
                write!(f, "Read")
            }
            Request::Subscribe(_, _) => {
                write!(f, "Sub")
            }
            Request::Probe(_, _) => {
                write!(f, "Probe")
            }
        }
    }
}

pub struct EngineFactory<DB: Engine> {
    marker: PhantomData<DB>,
}

impl<DB: Engine> EngineFactory<DB> {
    pub fn get_client(config: &StorageConfig<DB>) -> StorageResult<StorageClient> {
        DB::spawn_blocking(config)
    }
}
