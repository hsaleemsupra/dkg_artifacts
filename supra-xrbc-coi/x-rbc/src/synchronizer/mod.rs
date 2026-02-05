pub mod request;
#[cfg(test)]
mod synchronizer_test;

use crate::synchronizer::request::{InternalSyncRequest, SyncResponse};
use block::{BlockEntry, BlockIfc, CertifiedBlock};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::{debug, error, info};
use primitives::error::CommonError;
use primitives::types::{Header, HeaderIfc, QuorumCertificate};
use primitives::{RxChannel, Subscriber, TxChannel, HASH32};
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use storage::storage_client::StorageClient;
use storage::StorageReadIfc;
use tokio::sync::oneshot::Receiver;

const SYNC_LIMIT: usize = 5;

pub struct DeliverableSynchronizer<T: Subscriber<InternalSyncRequest> + 'static> {
    tx: T,
    certified_block_rx: RxChannel<CertifiedBlock>,
    certified_block_tx: TxChannel<CertifiedBlock>,
    pending_blocks: HashMap<HASH32, (CertifiedBlock, usize)>,
    /// Requests ready to be posted
    /// Block-hash, batch-header, Internal_request, Feedback_channel
    ready_queue: VecDeque<(HASH32, Header, InternalSyncRequest, Receiver<SyncResponse>)>,
    /// Requests already posted
    /// Header, Block-Hash, QC of the header
    running_sync_request: HashMap<Header, (HASH32, QuorumCertificate)>,
    storage_client: StorageClient,
}

impl<T: Subscriber<InternalSyncRequest> + 'static> DeliverableSynchronizer<T> {
    pub fn new(
        tx: T,
        block_rx: RxChannel<CertifiedBlock>,
        block_tx: TxChannel<CertifiedBlock>,
        storage_client: StorageClient,
    ) -> Self {
        Self {
            tx,
            certified_block_rx: block_rx,
            certified_block_tx: block_tx,
            pending_blocks: Default::default(),
            ready_queue: Default::default(),
            running_sync_request: Default::default(),
            storage_client,
        }
    }

    pub fn spawn(
        tx: T,
        block_rx: RxChannel<CertifiedBlock>,
        block_tx: TxChannel<CertifiedBlock>,
        storage_client: StorageClient,
    ) {
        let synchronizer = DeliverableSynchronizer::new(tx, block_rx, block_tx, storage_client);
        tokio::spawn(DeliverableSynchronizer::run(synchronizer));
    }

    ///
    /// Entry point of the delivery synchronizer component
    ///
    async fn run(mut synchronizer: DeliverableSynchronizer<T>) {
        let mut waiting_list = FuturesUnordered::new();
        loop {
            let _ = tokio::select! {
                Some(block) = synchronizer.certified_block_rx.recv() => {
                    info!("Received block: {:?}", block);
                    synchronizer.handle_incoming_block(block).await
                }

                Some(res) = waiting_list.next() => {
                    synchronizer.handle_sync_response(res)
                }

            };
            let new_sync_tasks = synchronizer.post_sync_requests();
            new_sync_tasks
                .into_iter()
                .for_each(|task| waiting_list.push(task));
        }
    }

    async fn handle_incoming_block(&mut self, block: CertifiedBlock) -> Result<(), CommonError> {
        let missing_entries = self.get_missing_entries(&block).await;
        if missing_entries.is_empty() {
            return self.send_block(block);
        }
        let block_id = *block.id();
        let _ = self
            .pending_blocks
            .insert(block_id, (block, missing_entries.len()));
        missing_entries
            .into_iter()
            .for_each(|block_entry| self.schedule_sync_request(block_id, block_entry));
        Ok(())
    }

    fn handle_sync_response(&mut self, result: Result<Header, Header>) -> Result<(), CommonError> {
        let maybe_ready_block = match result {
            Ok(header) => self.handle_ok_response(header),
            Err(header) => self.handle_err_response(header),
        };
        maybe_ready_block
            .map(|block| self.send_block(block))
            .unwrap_or(Ok(()))
    }

    fn handle_ok_response(&mut self, header: Header) -> Option<CertifiedBlock> {
        self.running_sync_request
            .remove(&header)
            .and_then(|(block_id, _)| self.pending_blocks.remove(&block_id))
            .and_then(|(block, mut missing)| {
                missing -= 1;
                if missing == 0 {
                    Some(block)
                } else {
                    self.pending_blocks.insert(*block.id(), (block, missing));
                    None
                }
            })
    }

    fn handle_err_response(&mut self, header: Header) -> Option<CertifiedBlock> {
        self.running_sync_request
            .remove(&header)
            .and_then(|(block_id, qc)| {
                self.reschedule_sync_request(block_id, BlockEntry::new(header, qc));
                None
            })
    }

    fn post_sync_requests(&mut self) -> Vec<impl Future<Output = Result<Header, Header>>> {
        let sync_slots = SYNC_LIMIT - self.running_sync_request.len();
        if sync_slots == 0 || self.ready_queue.is_empty() {
            return vec![];
        }
        let split_idx = min(self.ready_queue.len(), sync_slots);
        let wait_list = self.ready_queue.split_off(split_idx);
        let mut to_be_posted = VecDeque::new();
        std::mem::swap(&mut self.ready_queue, &mut to_be_posted);
        self.ready_queue = wait_list;
        to_be_posted
            .into_iter()
            .map(|(block_id, header, request, feedback)| {
                self.running_sync_request
                    .insert(header.clone(), (block_id, request.get_qc()));
                self.send_request(request);
                Self::create_sync_waiting_future(header, self.storage_client.clone(), feedback)
            })
            .collect()
    }

    async fn create_sync_waiting_future(
        header: Header,
        storage_client: StorageClient,
        feedback_rx: Receiver<SyncResponse>,
    ) -> Result<Header, Header> {
        tokio::select! {
            storage_subscriber = storage_client.subscribe(header.hash()) => {
                storage_subscriber.map(|_| header.clone()).map_err(|_| header)
            }
            feed_back = feedback_rx => {
                debug!("Delivery feedback is available");
                feed_back.map_err(|_| header.clone())?.map(|_| header.clone()).map_err(|_| header)
            }
        }
    }

    fn schedule_sync_request(&mut self, block_hash: HASH32, block_entry: BlockEntry) {
        info!("Schedule");
        let (header, qc) = block_entry.split();
        let (internal_req_tx, internal_req_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
        let internal_request = InternalSyncRequest::new(header.clone(), qc, internal_req_tx);
        self.ready_queue
            .push_back((block_hash, header, internal_request, internal_req_rx));
    }

    fn reschedule_sync_request(&mut self, block_hash: HASH32, block_entry: BlockEntry) {
        info!("Reschedule");
        let (header, qc) = block_entry.split();
        let (internal_req_tx, internal_req_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
        let internal_request = InternalSyncRequest::new(header.clone(), qc, internal_req_tx);
        self.ready_queue
            .push_front((block_hash, header, internal_request, internal_req_rx));
    }

    ///
    /// Check and returns the block-entries which are missing from the node storage
    ///
    async fn get_missing_entries(&self, block: &CertifiedBlock) -> Vec<BlockEntry> {
        let mut missing_entries = vec![];
        for entry in block.entries() {
            if !self.storage_client.has_key(entry.header().hash()).await {
                missing_entries.push(entry.clone())
            }
        }
        missing_entries
    }

    fn send_block(&self, block: CertifiedBlock) -> Result<(), CommonError> {
        self.certified_block_tx
            .send(block)
            .map_err(|e| CommonError::UnboundSendError(format!("{:?}", e)))
    }

    fn send_request(&self, request: InternalSyncRequest) {
        let _ = self
            .tx
            .send(request)
            .map_err(|e| error!("Failed to send sync request: {:?}", e));
    }
}
