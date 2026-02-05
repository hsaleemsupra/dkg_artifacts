use crate::synchronizer::request::SyncResponse;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::tests::header_with_origin;
use crate::{DeliverableSynchronizer, InternalSyncRequest, SupraDeliveryClient};
use block::{Block, BlockEntry, BlockIfc, CertifiedBlock};
use primitives::error::CommonError;
use primitives::types::{Header, HeaderIfc, QuorumCertificate};
use primitives::{RxChannel, Subscriber, TxChannel};
use rand::{thread_rng, RngCore};
use std::time::Duration;
use storage::config::StorageConfig;
use storage::rocksdb_store::RocksDBEngine;
use storage::storage_client::StorageClient;
use storage::{EngineFactory, StorageReadIfc, StorageWriteIfc};
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::timeout;
//
#[derive(Clone)]
struct SyncSubscriber {
    tx: TxChannel<InternalSyncRequest>,
}
impl Subscriber<InternalSyncRequest> for SyncSubscriber {
    fn send(&self, msg: InternalSyncRequest) -> Result<(), CommonError> {
        self.tx
            .send(msg)
            .map_err(|e| CommonError::UnboundSendError(e.to_string()))
    }
}

struct SynchronizerTestResources {
    block_tx: TxChannel<CertifiedBlock>,
    block_consumer_rx: RxChannel<CertifiedBlock>,
    subscriber_rx: RxChannel<InternalSyncRequest>,
    storage_client: StorageClient,
    db_name: String,
}

impl Drop for SynchronizerTestResources {
    fn drop(&mut self) {
        let db_path = "db/".to_string() + &self.db_name;
        let _ = std::fs::remove_dir_all(db_path);
    }
}

impl SynchronizerTestResources {
    fn new() -> (Self, DeliverableSynchronizer<SyncSubscriber>) {
        let (block_tx, block_rx) = unbounded_channel();
        let (block_consumer_tx, block_consumer_rx) = unbounded_channel();
        let db_name = format!("synchronizer_test_{}", thread_rng().next_u64());
        let storage_config = StorageConfig::<RocksDBEngine>::new(db_name.clone()).unwrap();
        let storage_client = EngineFactory::get_client(&storage_config).unwrap();
        let (subscriber_tx, subscriber_rx) = unbounded_channel();
        let subscriber = SyncSubscriber { tx: subscriber_tx };
        let synchronizer = DeliverableSynchronizer::new(
            subscriber,
            block_rx,
            block_consumer_tx,
            storage_client.clone(),
        );
        (
            Self {
                block_tx,
                block_consumer_rx,
                subscriber_rx,
                storage_client,
                db_name,
            },
            synchronizer,
        )
    }
}

fn get_block(size: usize) -> Block {
    let rnd_u8 = (thread_rng().next_u64() % 256) as u8;
    let mut block = Block::new([rnd_u8; 32], [rnd_u8 + 1; 32]);
    for i in 0..size {
        let entry = BlockEntry::new(
            header_with_origin([rnd_u8 + i as u8; 32]),
            QuorumCertificate::default(),
        );
        block.add_entry(entry);
    }
    block
}

fn get_certified_block(size: usize) -> CertifiedBlock {
    let block = get_block(size);
    let rnd_u8 = (thread_rng().next_u64() % 256) as u8;
    CertifiedBlock::new([rnd_u8; 96], block)
}

#[tokio::test]
async fn test_get_missing_entries() {
    let block = get_certified_block(2);
    let (sync_test_resources, synchronizer) = SynchronizerTestResources::new();

    // Check missing entries with empty storage
    let result = synchronizer.get_missing_entries(&block).await;
    assert_eq!(result.len(), block.entries().len());

    // Write one entry into the storage
    let first_entry_hash = block.entries()[0].header().hash();
    sync_test_resources
        .storage_client
        .write(first_entry_hash, [10; 32].to_vec());
    let wait_for_write = timeout(
        Duration::from_secs(2),
        sync_test_resources
            .storage_client
            .subscribe(first_entry_hash),
    )
    .await;
    assert!(wait_for_write.is_ok());
    assert!(wait_for_write.unwrap().is_ok());

    // Check missing entries with non-empty storage
    let result = synchronizer.get_missing_entries(&block).await;
    assert_eq!(result.len(), 1);
    assert_ne!(result[0].header().hash(), first_entry_hash);
}

#[tokio::test]
async fn test_schedule_sync_request_with_error_feedback() {
    let missing_size = 1;
    let (mut sync_test_resources, mut synchronizer) = SynchronizerTestResources::new();

    let block = get_certified_block(missing_size);
    let entry = block.entries().first().cloned().unwrap();

    // schedule
    synchronizer.schedule_sync_request(*block.id(), entry.clone());

    // send request to delivery
    let result_list = synchronizer.post_sync_requests();

    // wait of the request at delivery side
    let (header, qc, feedback) = timeout(
        Duration::from_secs(2),
        sync_test_resources.subscriber_rx.recv(),
    )
    .await
    .expect("Request is post to delivery")
    .unwrap()
    .split();

    assert_eq!(&header, entry.header());
    assert_eq!(&qc, entry.qc());

    // Simulate error feedback
    feedback
        .send(SyncResponse::Err("something went wrong".to_string()))
        .unwrap();

    // Wait of the feedback as synchronizer side
    let mut request_result = vec![];

    for header_result in result_list {
        request_result.push(
            timeout(Duration::from_secs(2), header_result)
                .await
                .unwrap(),
        )
    }
    assert_eq!(request_result.len(), missing_size);
    for t in request_result {
        assert!(t.is_err())
    }
}

#[tokio::test]
async fn test_schedule_sync_request_with_ok_feedback() {
    let missing_size = 1;
    let (mut sync_test_resources, mut synchronizer) = SynchronizerTestResources::new();

    let block = get_certified_block(missing_size);
    let entry = block.entries().first().cloned().unwrap();

    // schedule
    synchronizer.schedule_sync_request(*block.id(), entry.clone());

    // send request to delivery
    let result_list = synchronizer.post_sync_requests();

    // wait of the request at delivery side
    let (header, qc, feedback) = timeout(
        Duration::from_secs(2),
        sync_test_resources.subscriber_rx.recv(),
    )
    .await
    .expect("Request is post to delivery")
    .unwrap()
    .split();

    assert_eq!(&header, entry.header());
    assert_eq!(&qc, entry.qc());

    // Simulate ok feedback
    feedback.send(SyncResponse::Ok(())).unwrap();

    // Wait of the feedback as synchronizer side
    let mut request_result = vec![];

    for header_result in result_list {
        request_result.push(
            timeout(Duration::from_secs(2), header_result)
                .await
                .unwrap(),
        )
    }
    assert_eq!(request_result.len(), missing_size);
    for t in request_result {
        assert!(t.is_ok())
    }
}

#[tokio::test]
async fn test_schedule_missing_entries_with_insufficient_feedbacks() {
    let missing_size = 2;
    let (mut sync_test_resources, mut synchronizer) = SynchronizerTestResources::new();

    let block = get_certified_block(missing_size);
    let missing_entries = synchronizer.get_missing_entries(&block).await;

    let header_hashes = missing_entries
        .iter()
        .map(|e| e.header().hash())
        .collect::<Vec<_>>();

    // schedule missing entries of the block
    missing_entries
        .into_iter()
        .for_each(|block_entry| synchronizer.schedule_sync_request(*block.id(), block_entry));

    // send request to delivery for missing entries of the block
    let result_list = synchronizer.post_sync_requests();

    // wait of the requests at delivery side
    let (header_1, _, feedback_1) = timeout(
        Duration::from_secs(2),
        sync_test_resources.subscriber_rx.recv(),
    )
    .await
    .expect("Request is post to delivery")
    .unwrap()
    .split();
    assert!(header_hashes.contains(&header_1.hash()));

    let (header_2, _, _feedback_2) = timeout(
        Duration::from_secs(2),
        sync_test_resources.subscriber_rx.recv(),
    )
    .await
    .expect("Request is post to delivery")
    .unwrap()
    .split();
    assert!(header_hashes.contains(&header_2.hash()));

    // send feedback
    feedback_1.send(SyncResponse::Ok(())).unwrap();

    // block-sync-request is not done yet
    let mut request_result = vec![];

    for header_result in result_list {
        request_result.push(timeout(Duration::from_secs(2), header_result).await)
    }
    assert_eq!(request_result.len(), missing_size);
    let mut count = 0;
    request_result
        .into_iter()
        .flatten()
        .flatten()
        .for_each(|header| {
            assert_eq!(header, header_1);
            count += 1
        });

    assert_eq!(count, missing_size - 1);
}

#[tokio::test]
async fn test_schedule_missing_entries() {
    let missing_size = 2;
    let (mut sync_test_resources, mut synchronizer) = SynchronizerTestResources::new();

    let block = get_certified_block(missing_size);
    let missing_entries = synchronizer.get_missing_entries(&block).await;

    let header_hashes = missing_entries
        .iter()
        .map(|e| e.header().hash())
        .collect::<Vec<_>>();

    // schedule missing entries of the block
    missing_entries
        .into_iter()
        .for_each(|block_entry| synchronizer.schedule_sync_request(*block.id(), block_entry));

    // send request to delivery for missing entries of the block
    let result_list = synchronizer.post_sync_requests();

    // wait of the requests at delivery side
    let (header_1, _, feedback_1) = timeout(
        Duration::from_secs(2),
        sync_test_resources.subscriber_rx.recv(),
    )
    .await
    .expect("Request is post to delivery")
    .unwrap()
    .split();
    assert!(header_hashes.contains(&header_1.hash()));

    let (header_2, _, feedback_2) = timeout(
        Duration::from_secs(2),
        sync_test_resources.subscriber_rx.recv(),
    )
    .await
    .expect("Request is post to delivery")
    .unwrap()
    .split();
    assert!(header_hashes.contains(&header_2.hash()));

    // send feedbacks for both
    feedback_1.send(SyncResponse::Ok(())).unwrap();
    feedback_2.send(SyncResponse::Ok(())).unwrap();

    // block-sync-request is done
    let mut request_result = vec![];

    for header_result in result_list {
        request_result.push(
            timeout(Duration::from_secs(2), header_result)
                .await
                .unwrap(),
        )
    }
    assert_eq!(request_result.len(), missing_size);
    for t in request_result {
        assert!(t.is_ok())
    }
}

#[tokio::test]
async fn test_handle_batch_header_wrt_storage() {
    let missing_size = 1;
    let (sync_test_resources, mut synchronizer) = SynchronizerTestResources::new();

    let block = get_certified_block(missing_size);
    let block_entry = block.entries().first().cloned().unwrap();

    let header_hashes = block
        .entries()
        .iter()
        .map(|e| e.header().hash())
        .collect::<Vec<_>>();

    synchronizer.schedule_sync_request(*block.id(), block_entry);

    let result_list = synchronizer.post_sync_requests();

    let st_client = sync_test_resources.storage_client.clone();

    // schedule & send request to delivery for missing entries of the block
    let _ = tokio::spawn(async move {
        for hash in header_hashes {
            st_client.write(hash, [5; 1024].to_vec());
            st_client.subscribe(hash).await.unwrap();
        }
    })
    .await;

    let mut request_result = vec![];

    for header_result in result_list {
        request_result.push(
            timeout(Duration::from_secs(2), header_result)
                .await
                .unwrap(),
        )
    }
    assert_eq!(request_result.len(), missing_size);
    for t in request_result {
        assert!(t.is_ok())
    }
}

#[tokio::test]
async fn test_run() {
    let _ = env_logger::try_init();
    let block1 = get_certified_block(2);
    let block1_hash = *block1.id();
    let block2 = get_certified_block(1);
    let block2_hash = *block2.id();
    let (mut sync_test_resources, synchronizer) = SynchronizerTestResources::new();
    tokio::spawn(DeliverableSynchronizer::run(synchronizer));
    let header_hashes_1 = block1
        .entries()
        .iter()
        .map(|e| e.header().hash())
        .collect::<Vec<_>>();

    let header_hashes_2 = block2
        .entries()
        .iter()
        .map(|e| e.header().hash())
        .collect::<Vec<_>>();

    sync_test_resources
        .block_tx
        .send(block1)
        .expect("Block successfully sent");
    sync_test_resources
        .block_tx
        .send(block2)
        .expect("Block successfully sent");

    let st_client1 = sync_test_resources.storage_client.clone();
    let st_client2 = sync_test_resources.storage_client.clone();
    // schedule & send request to delivery for missing entries of the block
    let _ = tokio::spawn(async move {
        for hash in header_hashes_2 {
            st_client1.write(hash, [5; 1024].to_vec());
            st_client1.subscribe(hash).await.unwrap();
        }
    })
    .await;
    // schedule & send request to delivery for missing entries of the block
    let _ = tokio::spawn(async move {
        for hash in header_hashes_1 {
            st_client2.write(hash, [4; 1024].to_vec());
            st_client2.subscribe(hash).await.unwrap();
        }
    })
    .await;
    let synced_block2 = timeout(
        Duration::from_secs(3),
        sync_test_resources.block_consumer_rx.recv(),
    )
    .await
    .expect("Block received at output")
    .unwrap();
    assert_eq!(synced_block2.id(), &block2_hash);

    let synced_block1 = timeout(
        Duration::from_secs(3),
        sync_test_resources.block_consumer_rx.recv(),
    )
    .await
    .expect("Block received at output")
    .unwrap();
    assert_eq!(synced_block1.id(), &block1_hash);
}

#[tokio::test]
async fn test_handle_sync_response() {
    let total_block = 1;
    let total_missing_batch = 2;
    let (mut sync_test_resources, mut synchronizer) = SynchronizerTestResources::new();

    let block = get_certified_block(total_missing_batch);
    let missing_entries = synchronizer.get_missing_entries(&block).await;

    assert_eq!(synchronizer.pending_blocks.len(), 0);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 0);
    let _ = synchronizer.handle_incoming_block(block).await;
    assert_eq!(synchronizer.pending_blocks.len(), 1);
    assert_eq!(synchronizer.ready_queue.len(), 2);
    assert_eq!(synchronizer.running_sync_request.len(), 0);

    let _ = synchronizer.post_sync_requests();
    assert_eq!(synchronizer.pending_blocks.len(), 1);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 2);
    let resp = synchronizer.handle_sync_response(Ok(missing_entries[0].header().clone()));
    assert!(resp.is_ok());
    assert_eq!(synchronizer.pending_blocks.len(), 1);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 1);

    let _ = synchronizer.post_sync_requests();
    assert_eq!(synchronizer.pending_blocks.len(), 1);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 1);
    let resp = synchronizer.handle_sync_response(Err(missing_entries[1].header().clone()));
    assert!(resp.is_ok());
    assert_eq!(synchronizer.pending_blocks.len(), 1);
    assert_eq!(synchronizer.ready_queue.len(), 1);
    assert_eq!(synchronizer.running_sync_request.len(), 0);

    let _ = synchronizer.post_sync_requests();
    assert_eq!(synchronizer.pending_blocks.len(), 1);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 1);
    let resp = synchronizer.handle_sync_response(Ok(missing_entries[1].header().clone()));
    assert!(resp.is_ok());
    assert_eq!(synchronizer.pending_blocks.len(), 0);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 0);

    let _ = synchronizer.post_sync_requests();
    assert_eq!(synchronizer.pending_blocks.len(), 0);
    assert_eq!(synchronizer.ready_queue.len(), 0);
    assert_eq!(synchronizer.running_sync_request.len(), 0);
}
