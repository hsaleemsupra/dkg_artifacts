use crate::config::BlockProposerConfig;
use crate::{Block, BlockEntry};
use log::{error, info, warn};
use primitives::crypto::Hashers;
use primitives::types::HeaderIfc;
use primitives::{RxChannel, TxChannel, HASH32};
use std::cmp::min;
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;

pub trait BlockProviderSchema: Send {
    type Input: Send + Debug;
    type Output: Send + Debug;

    fn to_block_entry(input: Self::Input) -> BlockEntry;
    fn to_output(block: Block) -> Self::Output;
}

pub struct BlockProvider<Schema: BlockProviderSchema + 'static> {
    /// Block Provider input channel
    rx: RxChannel<Schema::Input>,
    output: TxChannel<Schema::Output>,
    /// Hashes of the block-entries consumed by block-producer so far
    entry_hashes: HashSet<HASH32>,
    /// Candidate block entries
    block_entries: VecDeque<BlockEntry>,
    /// Latest block hash/ID
    last_block_hash: HASH32,
    /// Block provider configuration
    config: BlockProposerConfig,

    /// Number of blocks produced so far
    counter: usize,
}

impl<Schema: BlockProviderSchema + 'static> BlockProvider<Schema> {
    pub fn spawn(
        config: BlockProposerConfig,
        output: TxChannel<Schema::Output>,
    ) -> (BlockProviderClient<Schema::Input>, JoinHandle<()>) {
        let (tx, rx) = unbounded_channel::<Schema::Input>();
        let provider = BlockProvider::<Schema>::new(config, rx, output);
        let handler = tokio::spawn(BlockProvider::<Schema>::run(provider));
        (BlockProviderClient::new(tx), handler)
    }

    pub fn new(
        config: BlockProposerConfig,
        rx: RxChannel<Schema::Input>,
        output: TxChannel<Schema::Output>,
    ) -> Self {
        BlockProvider {
            rx,
            output,
            entry_hashes: Default::default(),
            block_entries: Default::default(),
            last_block_hash: Hashers::keccak256("GenesisBlock".as_bytes()),
            config,
            counter: 0,
        }
    }

    async fn run(mut provider: BlockProvider<Schema>) {
        let mut ticker = tokio::time::interval(provider.config.get_timeout_in_secs());
        loop {
            let result = tokio::select! {
               msg = provider.rx.recv() =>  {
                    if let Some(data) = msg {
                        provider.handle_input(Schema::to_block_entry(data))
                    } else {
                        warn!("Input channel is closed. stop the proposer");
                        break;
                    }
               }
               _ = ticker.tick() => {
                    provider.generate_block()
               }
            };
            let _ = result.map_err(|e| error!("{:?}", e));
        }
    }

    fn handle_input(&mut self, new_entry: BlockEntry) -> Result<(), String> {
        info!("New Entry: {}", new_entry);
        let hash = new_entry.header().hash();
        if self.entry_hashes.contains(&hash) {
            return Err(format!(
                "Potential protocol error. Received duplicate block entry: {}. Ignoring entry",
                new_entry.header()
            ));
        }
        self.entry_hashes.insert(hash);
        self.block_entries.push_back(new_entry);
        Ok(())
    }

    fn generate_block(&mut self) -> Result<(), String> {
        if self.block_entries.is_empty() {
            return Ok(());
        }
        let block_id = Hashers::keccak256(format!("Block:{}", self.counter + 1).as_bytes());
        let mut block = Block::new(block_id, self.last_block_hash);
        let count = min(self.block_entries.len(), self.config.get_batch_count());
        for _ in 0..count {
            let _ = self.block_entries.pop_front().map(|d| block.add_entry(d));
        }
        self.last_block_hash = block_id;
        self.counter += 1;
        info!("Generated Block: {}", block);
        self.output
            .send(Schema::to_output(block))
            .map_err(|e| format!("Failed to send block: {}", e))
    }
}

pub struct BlockProviderClient<Input: Debug> {
    input: Option<TxChannel<Input>>,
}

impl<Input: Debug> Default for BlockProviderClient<Input> {
    fn default() -> Self {
        BlockProviderClient { input: None }
    }
}

impl<Input: Debug> BlockProviderClient<Input> {
    pub fn new(input: TxChannel<Input>) -> Self {
        Self { input: Some(input) }
    }

    pub fn send(&self, data: Input) -> Result<(), String> {
        self.input
            .as_ref()
            .map(|tx| {
                tx.send(data)
                    .map_err(|e| format!("Failed to send block proposer input: {:?}", e))
            })
            .unwrap_or(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use crate::config::BlockProposerConfig;
    use crate::proposer::{BlockProvider, BlockProviderSchema};
    use crate::{Block, BlockEntry, BlockIfc};
    use primitives::types::{Header, HeaderIfc, QuorumCertificate};
    use std::collections::BTreeSet;
    use std::time::Duration;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::sleep;

    struct TestBlockProviderSchema;
    impl BlockProviderSchema for TestBlockProviderSchema {
        type Input = BlockEntry;
        type Output = Block;

        fn to_block_entry(input: Self::Input) -> BlockEntry {
            input
        }

        fn to_output(block: Block) -> Self::Output {
            block
        }
    }

    fn generate_entry(id: u8) -> BlockEntry {
        let header = Header::new([id; 64], [id + 1; 32], [id + 2; 32]);
        let entry = BlockEntry::new(
            header,
            QuorumCertificate::new([id + 3; 96], BTreeSet::from([1, 2])),
        );
        entry
    }

    #[test]
    fn check_new() {
        let (_in_tx, in_rx) = unbounded_channel::<BlockEntry>();
        let (out_tx, _out_rx) = unbounded_channel::<Block>();
        let config = BlockProposerConfig::default();
        let block_provider = BlockProvider::<TestBlockProviderSchema>::new(config, in_rx, out_tx);
        assert!(block_provider.block_entries.is_empty());
        assert_eq!(block_provider.counter, 0);
        assert!(block_provider.entry_hashes.is_empty());
    }

    #[test]
    fn check_handle_input() {
        let (_in_tx, in_rx) = unbounded_channel::<BlockEntry>();
        let (out_tx, _out_rx) = unbounded_channel::<Block>();
        let config = BlockProposerConfig::new(10.0, 2);
        let mut block_provider =
            BlockProvider::<TestBlockProviderSchema>::new(config, in_rx, out_tx);

        let header1 = Header::new([1; 64], [2; 32], [3; 32]);
        let entry_1 = BlockEntry::new(
            header1.clone(),
            QuorumCertificate::new([4; 96], BTreeSet::from([1, 2])),
        );

        let result = block_provider.handle_input(entry_1);
        assert!(result.is_ok());
        assert!(block_provider.entry_hashes.contains(&header1.hash()));
        assert_eq!(block_provider.block_entries[0].header(), &header1);

        // Entry with duplicate header
        let entry_1_dup = BlockEntry::new(header1.clone(), QuorumCertificate::default());

        let result = block_provider.handle_input(entry_1_dup);
        assert!(result.is_err());
        assert_eq!(block_provider.entry_hashes.len(), 1);
        assert_eq!(block_provider.block_entries.len(), 1);
        assert_eq!(
            block_provider.block_entries.front().unwrap().qc().data(),
            &[4; 96]
        );

        let header2 = Header::new([2; 64], [3; 32], [4; 32]);
        let entry_2 = BlockEntry::new(
            header2.clone(),
            QuorumCertificate::new([5; 96], BTreeSet::from([1, 2])),
        );

        let result = block_provider.handle_input(entry_2);
        assert!(result.is_ok());
        assert!(block_provider.entry_hashes.contains(&header2.hash()));
        assert_eq!(
            block_provider.block_entries.back().unwrap().header(),
            &header2
        );
    }
    #[tokio::test]
    async fn check_generate_block() {
        let (_in_tx, in_rx) = unbounded_channel::<BlockEntry>();
        let (out_tx, mut _out_rx) = unbounded_channel::<Block>();
        let config = BlockProposerConfig::new(10.0, 2);
        let mut block_provider =
            BlockProvider::<TestBlockProviderSchema>::new(config, in_rx, out_tx);
        let genesis_block_id = block_provider.last_block_hash;

        // No entry no block
        let result = block_provider.generate_block();
        assert!(result.is_ok());
        let output = _out_rx.try_recv();
        assert!(output.is_err());
        assert_eq!(output.unwrap_err(), TryRecvError::Empty);

        // single entry -> block with single entry
        let entry_1 = generate_entry(1);
        let header_1 = entry_1.get_header();
        let result = block_provider.handle_input(entry_1);
        assert!(result.is_ok());

        let result = block_provider.generate_block();
        assert!(result.is_ok());
        assert!(block_provider.block_entries.is_empty());
        assert_eq!(block_provider.entry_hashes.len(), 1);
        let output = _out_rx.try_recv();
        assert!(output.is_ok());
        let block = output.unwrap();
        assert_eq!(block.previous_id(), &genesis_block_id);
        assert_eq!(block.entries().len(), 1);

        // multiple entry -> block with max-batch-count
        let entry_2 = generate_entry(2);
        let entry_3 = generate_entry(3);
        let entry_4 = generate_entry(4);

        let result = block_provider.handle_input(entry_2);
        assert!(result.is_ok());
        let result = block_provider.handle_input(entry_3);
        assert!(result.is_ok());
        let result = block_provider.handle_input(entry_4);
        assert!(result.is_ok());

        let result = block_provider.generate_block();
        assert!(result.is_ok());
        assert_eq!(block_provider.block_entries.len(), 1);
        assert_eq!(block_provider.entry_hashes.len(), 4);
        let output = _out_rx.try_recv();
        assert!(output.is_ok());
        let block_2 = output.unwrap();
        assert_eq!(block_2.previous_id(), block.id());
        assert_eq!(
            block_2.entries().len(),
            block_provider.config.get_batch_count()
        );

        // even though entry_1 was included in block and removed from entry list, second time
        // it will not be accepted by block-provider
        let entry_1_dup = BlockEntry::new(header_1, QuorumCertificate::default());
        let result = block_provider.handle_input(entry_1_dup);
        assert!(result.is_err());
        assert_eq!(block_provider.block_entries.len(), 1);
        assert_eq!(block_provider.entry_hashes.len(), 4);
    }

    #[tokio::test]
    async fn check_run() {
        let (out_tx, mut out_rx) = unbounded_channel::<Block>();
        let config = BlockProposerConfig::new(10.0, 2);
        let (client, handler) = BlockProvider::<TestBlockProviderSchema>::spawn(config, out_tx);

        tokio::spawn(async move {
            let entry_1 = generate_entry(1);
            let _ = client.send(entry_1).expect("Failed to send entry");

            let _ = sleep(Duration::from_secs(15)).await;
            assert!(out_rx.try_recv().is_ok());
        });
        let r = tokio::time::timeout(Duration::from_secs(20), handler).await;
        assert!(r.is_ok());
    }
}
