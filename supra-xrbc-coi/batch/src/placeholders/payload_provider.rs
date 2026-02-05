use crate::{BatchCreationRule, PayloadGeneratorConfig};
use log::{error, info};
use primitives::Subscriber;
use rand::Rng;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use storage::storage_client::StorageClient;
use storage::{StorageKey, StorageReadIfc};
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use x_rbc::tasks::messages::PayloadRequest;

const CHAIN_READY: &str = ".chain_ready";

pub struct PayloadProvider<T: Subscriber<PayloadRequest> + 'static> {
    tx: T,
    storage_client: StorageClient,
    config: PayloadGeneratorConfig,
    qty: usize,
}

impl<T: Subscriber<PayloadRequest> + 'static> PayloadProvider<T> {
    pub fn spawn(
        config: PayloadGeneratorConfig,
        tx: T,
        storage_client: StorageClient,
    ) -> JoinHandle<()> {
        let provider = PayloadProvider {
            tx,
            storage_client,
            config,
            qty: 0,
        };
        tokio::spawn(PayloadProvider::run(provider))
    }

    pub fn spawn_blocking(config: PayloadGeneratorConfig, tx: T, storage_client: StorageClient) {
        let provider = PayloadProvider {
            tx,
            storage_client,
            config,
            qty: 0,
        };
        tokio::task::spawn_blocking(|| PayloadProvider::run_blocking(provider));
    }

    async fn run(mut provider: PayloadProvider<T>) {
        let chain_ready = PathBuf::from_str(CHAIN_READY).unwrap();
        let rule = provider.config.rule().clone();

        match rule {
            BatchCreationRule::Infinite(interval) => loop {
                sleep(interval.timeout_in_sec()).await;
                let _ = provider.try_commit_payload(&chain_ready, None);
            },
            BatchCreationRule::Finite(interval, mut count) => loop {
                if count < 1 {
                    break;
                }
                sleep(interval.timeout_in_sec()).await;
                let _ = provider
                    .try_commit_payload(&chain_ready, None)
                    .map(|_| count -= 1);
            },
            BatchCreationRule::InfiniteLoopBack => loop {
                let (tx, rx) = oneshot::channel::<StorageKey>();
                let _ = provider.try_commit_payload(&chain_ready, Some(tx));

                let notification = rx.await;
                if let Ok(storage_key) = notification {
                    let res = provider.storage_client.subscribe(storage_key).await;
                    if res.is_err() {
                        log::error!("InfiniteLoopBack batch creation error")
                    }
                }
            },
            BatchCreationRule::FiniteLoopBack(mut count) => loop {
                if count < 1 {
                    break;
                }
                let (tx, rx) = oneshot::channel::<StorageKey>();
                let commit = provider.try_commit_payload(&chain_ready, Some(tx));
                if commit.is_ok() {
                    let subscribe =
                        Self::try_subscribe_to_storage(&mut provider, rx, &mut count).await;
                    if subscribe.is_err() {
                        log::error!("{:?}", subscribe.err().unwrap());
                        break;
                    }
                }
            },
        }
    }

    fn run_blocking(mut provider: PayloadProvider<T>) {
        use std::thread::sleep;
        let chain_ready = PathBuf::from_str(CHAIN_READY).unwrap();
        let rule = provider.config.rule().clone();

        match rule {
            BatchCreationRule::Infinite(interval) => loop {
                sleep(interval.timeout_in_sec());
                let _ = provider.try_commit_payload(&chain_ready, None);
            },
            BatchCreationRule::Finite(interval, mut count) => loop {
                if count < 1 {
                    break;
                }
                sleep(interval.timeout_in_sec());
                let _ = provider
                    .try_commit_payload(&chain_ready, None)
                    .map(|_| count -= 1);
            },
            BatchCreationRule::InfiniteLoopBack => loop {
                let (tx, rx) = oneshot::channel::<StorageKey>();
                let _ = provider.try_commit_payload(&chain_ready, Some(tx));

                let notification = rx.blocking_recv();
                if let Ok(storage_key) = notification {
                    let res = provider.storage_client.subscribe_blocking(storage_key);
                    if res.is_err() {
                        log::error!("InfiniteLoopBack batch creation error")
                    }
                }
            },
            BatchCreationRule::FiniteLoopBack(mut count) => loop {
                if count < 1 {
                    break;
                }
                let (tx, rx) = oneshot::channel::<StorageKey>();
                let commit = provider.try_commit_payload(&chain_ready, Some(tx));
                if commit.is_ok() {
                    let subscribe =
                        Self::try_subscribe_to_storage_blocking(&mut provider, rx, &mut count);
                    if subscribe.is_err() {
                        log::error!("{:?}", subscribe.err().unwrap());
                        break;
                    }
                }
            },
        }
    }

    async fn try_subscribe_to_storage(
        provider: &mut PayloadProvider<T>,
        rx: Receiver<StorageKey>,
        count: &mut usize,
    ) -> Result<(), String> {
        let notification = rx.await;
        if let Ok(storage_key) = notification {
            let res = provider
                .storage_client
                .subscribe(storage_key)
                .await
                .map_err(|e| e.to_string());
            res.map(|_| *count -= 1)
        } else {
            Err("storage receiver error".to_string())
        }
    }

    fn try_subscribe_to_storage_blocking(
        provider: &mut PayloadProvider<T>,
        rx: Receiver<StorageKey>,
        count: &mut usize,
    ) -> Result<(), String> {
        let notification = rx.blocking_recv();
        if let Ok(storage_key) = notification {
            let res = provider
                .storage_client
                .subscribe_blocking(storage_key)
                .map_err(|e| e.to_string());
            res.map(|_| *count -= 1)
        } else {
            Err("storage receiver error".to_string())
        }
    }

    fn try_commit_payload(
        &mut self,
        chain_ready: &Path,
        notification_sender: Option<oneshot::Sender<StorageKey>>,
    ) -> Result<(), &str> {
        if chain_ready.exists() {
            self.commit_payload(notification_sender);
            Ok(())
        } else {
            Err("chain is not ready")
        }
    }

    fn commit_payload(&mut self, notification_sender: Option<oneshot::Sender<StorageKey>>) {
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; self.config.size_in_bytes()];
        (0..u8::MAX).for_each(|_| {
            let idx = rng.gen_range(0..self.config.size_in_bytes());
            payload[idx] = (idx % (u8::MAX as usize)) as u8;
        });
        self.qty += 1;
        info!("New Payload - {}", self.qty);
        let payload_req = PayloadRequest::new(payload, notification_sender);
        let _ = self
            .tx
            .send(payload_req)
            .map_err(|e| error!("Failed to submit payload: {:?}", e));
    }
}
