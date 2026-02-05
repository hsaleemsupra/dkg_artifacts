use crate::config::StorageConfig;
use crate::storage_client::StorageClient;
use crate::{
    Engine, Request, StorageKey, StorageReadIfc, StorageResult, StorageValue, StorageWriteIfc,
};
use async_trait::async_trait;
use dashmap::DashMap;
use log::{info, warn};
use primitives::NotificationSender;
use primitives::Stringify;
use rocksdb::{DBWithThreadMode, MultiThreaded, Options};
use std::path::Path;
use std::thread::current;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
pub struct RocksDBEngine {
    store: DBWithThreadMode<MultiThreaded>,
    channel: UnboundedReceiver<Request>,
    subscribers: DashMap<StorageKey, Vec<NotificationSender<()>>>,
}

impl RocksDBEngine {
    async fn run(mut self) {
        while let Some(msg) = self.channel.recv().await {
            match msg {
                Request::Write(key, val) => {
                    self.write(key, val);
                }
                Request::Read(key, sender) => {
                    let res = self.read(key).await;
                    sender
                        .send(res)
                        .unwrap_or_else(|e| log::error!("SendError {:?}", e));
                }
                Request::Subscribe(key, sender) => {
                    if self.has_key(key).await {
                        sender.send(()).unwrap();
                    } else {
                        self.add_subscriber(key, sender);
                    }
                }
                Request::Probe(key, sender) => {
                    let res = self.has_key(key).await;
                    sender
                        .send(res)
                        .unwrap_or_else(|e| log::error!("SendError {:?}", e));
                }
            }
        }
    }

    fn run_blocking(mut self) {
        while let Some(msg) = self.channel.blocking_recv() {
            info!("{:?} - {}", current().id(), msg);
            match msg {
                Request::Write(key, val) => {
                    self.write(key, val);
                }
                Request::Read(key, sender) => {
                    let res = self.read_blocking(key);
                    sender
                        .send(res)
                        .unwrap_or_else(|e| log::error!("SendError {:?}", e));
                }
                Request::Subscribe(key, sender) => {
                    if self.has_key_blocking(key) {
                        let _ = sender
                            .send(())
                            .unwrap_or_else(|_| warn!("Subscriber is not available"));
                    } else {
                        self.add_subscriber(key, sender);
                    }
                }
                Request::Probe(key, sender) => {
                    let res = self.has_key_blocking(key);
                    sender
                        .send(res)
                        .unwrap_or_else(|e| log::error!("SendError {:?}", e));
                }
            }
        }
    }
    fn notify_subscribers(&self, key: StorageKey) {
        if let Some((_, subscribers)) = self.subscribers.remove(&key) {
            for subscriber in subscribers {
                if subscriber.is_closed() {
                    continue;
                }
                let res = { subscriber.send(()) };
                if res.is_err() {
                    log::error!(
                        "Cannot notify storage subscriber {:?} for {}",
                        res.err(),
                        key.hex_display()
                    );
                }
            }
        }
    }

    fn add_subscriber(&self, key: StorageKey, subscriber: NotificationSender<()>) {
        if let Some(mut item) = self.subscribers.get_mut(&key) {
            item.value_mut().push(subscriber);
        } else {
            self.subscribers.insert(key, vec![subscriber]);
        }
    }
}

impl RocksDBEngine {
    fn try_create(config: &StorageConfig<Self>) -> StorageResult<(Self, StorageClient)> {
        let path = format!("db/{}", config.collection());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let rocks_db = DBWithThreadMode::<MultiThreaded>::open(&opts, Path::new(path.as_str()))?;
        let (tx, rx) = unbounded_channel::<Request>();
        let storage_instance = Self {
            store: rocks_db,
            channel: rx,
            subscribers: Default::default(),
        };
        let client = StorageClient::new(tx);
        Ok((storage_instance, client))
    }
}
impl Engine for RocksDBEngine {
    fn spawn(config: &StorageConfig<Self>) -> StorageResult<StorageClient> {
        let (storage_instance, client) = RocksDBEngine::try_create(config)?;
        tokio::spawn(async move {
            storage_instance.run().await;
        });
        Ok(client)
    }

    fn spawn_blocking(config: &StorageConfig<Self>) -> StorageResult<StorageClient> {
        let (storage_instance, client) = RocksDBEngine::try_create(config)?;
        tokio::task::spawn_blocking(|| storage_instance.run_blocking());
        Ok(client)
    }
}

#[async_trait]
impl StorageReadIfc for RocksDBEngine {
    async fn has_key(&self, key: StorageKey) -> bool {
        self.has_key_blocking(key)
    }

    fn has_key_blocking(&self, key: StorageKey) -> bool {
        self.store
            .get_pinned(key)
            .map(|d| d.is_some())
            .map_err(|e| log::error!("Failed to probe the storage: {}", e))
            .unwrap_or(false)
    }

    async fn read(&self, key: StorageKey) -> Option<StorageValue> {
        self.read_blocking(key)
    }

    fn read_blocking(&self, key: StorageKey) -> Option<StorageValue> {
        self.store.get(key).unwrap_or(None)
    }

    async fn subscribe(&self, key: StorageKey) -> StorageResult<()> {
        let _ = key;
        Ok(())
    }

    fn subscribe_blocking(&self, key: StorageKey) -> StorageResult<()> {
        let _ = key;
        Ok(())
    }
}

impl StorageWriteIfc for RocksDBEngine {
    fn write(&self, key: StorageKey, value: StorageValue) {
        self.store
            .put(key, value)
            .map(|_| self.notify_subscribers(key))
            .unwrap_or_else(|e| log::error!("{}", e.to_string()));
    }
}
