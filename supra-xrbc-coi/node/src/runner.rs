use crate::chain_parameters::SupraDeliveryConfigParameters;
use crate::cli::RunArgs;
use crate::helpers::load;
use crate::ChainParameters;
use async_trait::async_trait;
use batch::{BatchCreationRule, PayloadConsumer, PayloadProvider};
use block::config::BlockProposerConfig;
use block::proposer::{BlockProvider, BlockProviderClient, BlockProviderSchema};
use block::{Block, BlockEntry, CertifiedBlock};
use bytes::Bytes;
use crypto::dkg::generate_distributed_key_for_chain;
use crypto::traits::NodeIdentityInterface;
use crypto::{Authenticator, NodeIdentity};
use log::{info, warn};
use metrics::influx_collector::backend::InfluxBackend;
use metrics_logger::Tags;
use network::topology::config::NetworkConfig;
use network::topology::peer_info::{PeerInfo, Role};
use network::topology::ChainTopology;
use network::{MessageHandler, NetworkSender, Receiver, Writer};
use primitives::error::CommonError;
use primitives::placeholders::consumer::Consumer;
use primitives::{Origin, PeerGlobalIndex, Protocol, RxChannel, Subscriber, TxChannel};
use std::error::Error;
use storage::config::StorageConfig;
use storage::rocksdb_store::RocksDBEngine;
use storage::storage_client::StorageClient;
use storage::EngineFactory;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;
use x_rbc::arbiter::clients::ArbiterClient;
use x_rbc::arbiter::messages::CoIMessages;
use x_rbc::arbiter::Arbiter;
use x_rbc::tasks::messages::PayloadRequest;
use x_rbc::{
    Available, DeliverableSynchronizer, FeedbackMessage, InternalSyncRequest,
    RBCNetworkServiceSchema, SupraDelivery, SupraDeliveryClient, SupraDeliveryErasureRs16Schema,
    SupraDeliveryErasureRs8Schema, SupraDeliveryRs16Schema, SupraDeliveryRs8Schema,
};

pub struct NodeRunner;

struct NodeBlockProposerSchema;
impl BlockProviderSchema for NodeBlockProposerSchema {
    type Input = Available;
    type Output = CoIMessages;

    fn to_block_entry(input: Self::Input) -> BlockEntry {
        let (header, _proof, qc) = input.split();
        BlockEntry::new(header, qc)
    }

    fn to_output(block: Block) -> Self::Output {
        CoIMessages::Block(block)
    }
}

impl NodeRunner {
    fn load(run_args: RunArgs) -> (ChainParameters, NodeIdentity, Vec<PeerInfo>) {
        let identity = load::<NodeIdentity>(run_args.identity_config).expect("Valid node identity");
        let chain_params =
            ChainParameters::load(run_args.chain_param_file).expect("Valid chain parameters");
        let peers = load::<Vec<PeerInfo>>(run_args.peers_config).expect("Valid peer data");
        if chain_params.network_config().total_nodes() != peers.len() {
            panic!("Number of peers does not correspond to number of total nodes in chain");
        }
        (chain_params, identity, peers)
    }

    fn get_host_metric_tag(
        node_global_index: PeerGlobalIndex,
        is_proposer: bool,
        batch_size: usize,
        rule: &BatchCreationRule,
    ) -> Tags {
        let mut tags = Tags::new();
        tags.insert("host".to_string(), node_global_index.to_string());
        tags.insert("is_proposer".to_string(), is_proposer.to_string());
        tags.insert("payload_size".to_string(), batch_size.to_string());
        tags.insert("batch_creation_rule".to_string(), rule.to_string());
        tags
    }

    async fn setup_metric_registry(
        node_global_index: PeerGlobalIndex,
        is_proposer: bool,
        batch_size: usize,
        rule: &BatchCreationRule,
    ) {
        let tags = Self::get_host_metric_tag(node_global_index, is_proposer, batch_size, rule);
        let influx = metrics_logger::try_init_with_tags::<InfluxBackend>(tags).await;
        if let Some(e) = influx.err() {
            warn!("InfluxDB failed to initialized {:?}", e);
            info!("logging with no-register");
            let _ = metrics_logger::try_init();
        }
    }

    pub(crate) async fn start(run_args: RunArgs) -> JoinHandle<()> {
        let (chain_params, identity, peers) = NodeRunner::load(run_args);
        let origin = identity.public_key();
        let chain_topology =
            NodeRunner::prepare_chain_topology(peers, chain_params.network_config(), &origin);
        let node_global_index = chain_topology.current_node().global_index();
        let role = *chain_topology.current_node().role();

        Self::setup_metric_registry(
            node_global_index,
            chain_topology.current_node().is_proposer(),
            chain_params.batch_config().size_in_bytes(),
            chain_params.batch_config().rule(),
        )
        .await;

        let authenticator =
            NodeRunner::create_authenticator(&chain_params, node_global_index, identity);
        let xrbc_address = chain_topology
            .current_node()
            .get_address(Protocol::XRBC)
            .unwrap();
        info!("NodeRunner {}", chain_topology.current_node());
        info!("BlockProposer {}", chain_topology.get_block_proposer_info());
        let (consumer_tx, handle) = PayloadConsumer::spawn("Payload");
        let (sync_tx, sync_rx) = unbounded_channel();
        let (arbiter_tx, arbiter_rx) = unbounded_channel();
        let block_proposer_client = NodeRunner::start_block_proposer_if_required(
            chain_params.block_config(),
            role,
            arbiter_tx.clone(),
        );
        let arbiter_client = Arbiter::spawn(
            chain_topology.clone(),
            authenticator.clone(),
            arbiter_rx,
            arbiter_tx,
            sync_tx,
            block_proposer_client,
        );
        let storage_client = NodeRunner::start_storage(&node_global_index);
        let delivery_client = NodeRunner::start_delivery(
            &chain_params,
            consumer_tx,
            arbiter_client,
            authenticator,
            chain_topology,
            storage_client.clone(),
        );
        NodeRunner::start_delivery_synchronizer(
            sync_rx,
            storage_client.clone(),
            delivery_client.clone(),
        );
        // No Payload provider for basic nodes
        if role == Role::Leader {
            PayloadProvider::<DeliveryClient>::spawn_blocking(
                chain_params.batch_config().clone(),
                delivery_client.clone(),
                storage_client,
            );
        }

        // Listener address for other peers to connect
        Receiver::spawn(xrbc_address, delivery_client);
        handle
    }

    fn prepare_chain_topology(
        peers: Vec<PeerInfo>,
        nt_config: &NetworkConfig,
        origin: &Origin,
    ) -> ChainTopology {
        let peers = peers.into_iter().map(|peer| (*peer.id(), peer)).collect();

        ChainTopology::new(nt_config, peers, origin).unwrap_or_else(|_| {
            panic!(
                "Valid topology from input configurations: Origin: {:?}",
                origin
            )
        })
    }

    fn create_authenticator(
        chain_params: &ChainParameters,
        node_index: PeerGlobalIndex,
        identity: NodeIdentity,
    ) -> Authenticator {
        let (clan_identities, dist_key_pair) = generate_distributed_key_for_chain(
            chain_params.network_config().tribes(),
            chain_params.network_config().clans(),
            chain_params.dkg_config(),
            &node_index,
        )
        .expect("Distributed key generation for chain is successful");
        Authenticator::new(identity, dist_key_pair, clan_identities)
    }

    fn start_block_proposer_if_required(
        config: &BlockProposerConfig,
        role: Role,
        block_tx: TxChannel<CoIMessages>,
    ) -> BlockProviderClient<Available> {
        if role == Role::BlockProposer {
            let (client, _handler) =
                BlockProvider::<NodeBlockProposerSchema>::spawn(config.clone(), block_tx);
            return client;
        }
        BlockProviderClient::<Available>::default()
    }

    fn start_storage(node_global_index: &PeerGlobalIndex) -> StorageClient {
        let db_dir = format!(
            "{}-{}-{}",
            node_global_index.tribe(),
            node_global_index.clan(),
            node_global_index.position()
        );
        let storage_config = StorageConfig::<RocksDBEngine>::new(db_dir).unwrap();
        EngineFactory::get_client(&storage_config).unwrap()
    }

    fn start_delivery_synchronizer(
        block_rx: RxChannel<CertifiedBlock>,
        storage_client: StorageClient,
        delivery_client: DeliveryClient,
    ) {
        let (block_tx, _) = Consumer::<CertifiedBlock>::spawn("Block");
        DeliverableSynchronizer::<DeliveryClient>::spawn(
            delivery_client,
            block_rx,
            block_tx,
            storage_client,
        )
    }

    fn start_delivery(
        chain_params: &ChainParameters,
        consumer_tx: TxChannel<FeedbackMessage>,
        arbiter_client: ArbiterClient,
        authenticator: Authenticator,
        chain_topology: ChainTopology,
        storage_client: StorageClient,
    ) -> DeliveryClient {
        match chain_params.delivery_config() {
            SupraDeliveryConfigParameters::Rs16(config) => {
                let network_service_ifc =
                    NetworkSender::new::<RBCNetworkServiceSchema<SupraDeliveryErasureRs16Schema>>();
                DeliveryClient::Rs16(SupraDelivery::<SupraDeliveryRs16Schema>::spawn_blocking(
                    config.clone(),
                    consumer_tx,
                    arbiter_client,
                    authenticator,
                    chain_topology,
                    network_service_ifc,
                    storage_client,
                ))
            }
            SupraDeliveryConfigParameters::Rs8(config) => {
                let network_service_ifc =
                    NetworkSender::new::<RBCNetworkServiceSchema<SupraDeliveryErasureRs8Schema>>();
                DeliveryClient::Rs8(SupraDelivery::<SupraDeliveryRs8Schema>::spawn_blocking(
                    config.clone(),
                    consumer_tx,
                    arbiter_client,
                    authenticator,
                    chain_topology,
                    network_service_ifc,
                    storage_client,
                ))
            }
        }
    }
}

#[derive(Clone)]
enum DeliveryClient {
    Rs16(SupraDeliveryClient<SupraDeliveryErasureRs16Schema>),
    Rs8(SupraDeliveryClient<SupraDeliveryErasureRs8Schema>),
}

#[async_trait]
impl MessageHandler for DeliveryClient {
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        match self {
            DeliveryClient::Rs16(client) => client.dispatch(writer, message).await,
            DeliveryClient::Rs8(client) => client.dispatch(writer, message).await,
        }
    }
}

impl Subscriber<PayloadRequest> for DeliveryClient {
    fn send(&self, msg: PayloadRequest) -> Result<(), CommonError> {
        match self {
            DeliveryClient::Rs16(client) => client.send(msg),
            DeliveryClient::Rs8(client) => client.send(msg),
        }
    }
}

impl Subscriber<InternalSyncRequest> for DeliveryClient {
    fn send(&self, msg: InternalSyncRequest) -> Result<(), CommonError> {
        match self {
            DeliveryClient::Rs16(client) => client.send(msg),
            DeliveryClient::Rs8(client) => client.send(msg),
        }
    }
}
