use crate::arbiter::clients::ArbiterClient;
use crate::arbiter::tests::ArbiterTestResources;
use crate::arbiter::Arbiter;
use crate::tasks::client::RBCTaskState;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::config::{GarbageCollectorConfig, RBCTaskStateTimeConfig};
use crate::tasks::messages::{PayloadRequest, RBCMessage};
use crate::tasks::supra_delivery::SupraDeliverySchema;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::{
    Available, DeliverableSynchronizer, FeedbackMessage, RBCNetworkServiceSchema, SupraDelivery,
    SupraDeliveryClient, SupraDeliveryConfig,
};
use block::CertifiedBlock;
use erasure::utils::codec_trait::{Codec, Setting};
use network::client::{Action, NetworkServiceIFC};
use network::topology::peer_info::Role;
use primitives::types::header::MessageMeta;
use primitives::{Payload, PeerGlobalIndex, RxChannel, TxChannel};
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;
use vec_commitment::txn_generator::GeneratorType;

mod codec_test;
mod config_tests;
mod consumer_test;
mod messages_tests;
mod rbc_task_tests;
mod supra_delivery_test;
mod sync_task_flow_test;
mod unit_test_garbage_collection;

pub(crate) struct TestSupraDeliveryResources<C: SupraDeliverySchema> {
    pub resource_provider: TestResources,
    pub delivery_manager: SupraDelivery<C>,
    pub arbiter: Arbiter,
    pub network_rx: RxChannel<Action>,
    pub arbiter_network_sender_rx: RxChannel<Action>,
    pub arbiter_client: ArbiterClient,
    pub payload_tx: TxChannel<Payload>,
    pub block_rx: RxChannel<CertifiedBlock>,
    pub block_proposer_rx: RxChannel<Available>,
    pub payload_consumer: RxChannel<FeedbackMessage>,
    pub synchronizer: DeliverableSynchronizer<SupraDeliveryClient<C::CodecSchema>>,
}

impl<C: SupraDeliverySchema> TestSupraDeliveryResources<C> {
    pub fn new_with_broadcaster(broadcaster: PeerGlobalIndex, peer_index: PeerGlobalIndex) -> Self {
        let resource_provider = TestResources::new(Role::Leader, broadcaster);
        TestSupraDeliveryResources::new_with_resource_provider(resource_provider, peer_index)
    }

    pub fn new(peer_index: PeerGlobalIndex, role: Role) -> Self {
        let resource_provider = TestResources::new(role, peer_index);
        TestSupraDeliveryResources::new_with_resource_provider(resource_provider, peer_index)
    }

    pub fn new_with_resource_provider(
        mut resource_provider: TestResources,
        peer_index: PeerGlobalIndex,
    ) -> Self {
        let gc = GarbageCollectorConfig {
            task_stale_timeout: Duration::from_secs(5),
            garbage_collection_timeout: Duration::from_secs(5),
        };
        let comittee_stgs = resource_provider.committee_settings();
        let nt_stgs = resource_provider.network_settings();
        let delivery_config = SupraDeliveryConfig::<C::CodecSchema> {
            committee_erasure_config: <<<C as SupraDeliverySchema>::CodecSchema as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting::new(comittee_stgs.0, comittee_stgs.1),
            network_erasure_config: Some(<<<C as SupraDeliverySchema>::CodecSchema as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting::new(nt_stgs.0, nt_stgs.1)),
            garbage_collector_config: gc,
            state_idle_time_config: RBCTaskStateTimeConfig::new(Duration::from_secs(5)),
            dissemination_rule: Default::default(),
        };

        let (payload_tx, payload_rx) = unbounded_channel::<Payload>();
        let (consumer_tx, consumer_rx) = unbounded_channel::<FeedbackMessage>();

        let (network_tx, network_rx) = unbounded_channel::<Action>();
        let (block_consumer_tx, block_consumer_rx) = unbounded_channel::<CertifiedBlock>();
        let network_service_ifc =
            NetworkServiceIFC::<RBCNetworkServiceSchema<C::CodecSchema>>::new(network_tx);

        let (chain_topology, authenticator, storage_client) =
            resource_provider.get_resources(peer_index).split();

        let (arbiter, arbiter_client, arbiter_to_sync, arbiter_network_rx, arbiter_to_block) =
            ArbiterTestResources::get_arbiter(chain_topology.clone(), authenticator.clone());
        let (_client, sd_obj) = SupraDelivery::<C>::new(
            delivery_config,
            consumer_tx,
            arbiter_client.clone(),
            authenticator,
            chain_topology,
            network_service_ifc,
            storage_client.clone(),
        );
        let synchronizer = DeliverableSynchronizer::new(
            _client,
            arbiter_to_sync,
            block_consumer_tx,
            storage_client,
        );

        Self {
            resource_provider,
            delivery_manager: sd_obj,
            arbiter,
            network_rx,
            arbiter_network_sender_rx: arbiter_network_rx,
            arbiter_client,
            payload_tx,
            block_rx: block_consumer_rx,
            block_proposer_rx: arbiter_to_block,
            payload_consumer: consumer_rx,
            synchronizer,
        }
    }
}

fn consume_random_payload<S: SupraDeliverySchema>(
    test_resources: &mut TestSupraDeliveryResources<S>,
) {
    let payload_1 =
        bincode::serialize(&GeneratorType::Gibberish.spawn_the_generator(1000, 50)).unwrap();
    let payload_req = PayloadRequest::new(payload_1, None);
    let _ = test_resources
        .delivery_manager
        .handle_new_payload(payload_req);
}

fn consume_random_message<S: SupraDeliverySchema>(
    test_resources: &mut TestSupraDeliveryResources<S>,
    msg: RBCMessage<S::CodecSchema>,
) {
    let _ = test_resources.delivery_manager.handle_message(msg);
}

fn check_task_state_is_done<S: SupraDeliverySchema>(
    test_resources: &TestSupraDeliveryResources<S>,
    task_id: &MessageMeta,
) {
    assert!(matches!(
        test_resources
            .delivery_manager
            .tasks()
            .get(task_id)
            .unwrap(),
        RBCTaskState::<S::CodecSchema>::Done(..)
    ));
}

fn check_task_state_is_in_progress<S: SupraDeliverySchema>(
    test_resources: &TestSupraDeliveryResources<S>,
    task_id: &MessageMeta,
) {
    assert!(matches!(
        test_resources
            .delivery_manager
            .tasks()
            .get(task_id)
            .unwrap(),
        RBCTaskState::<S::CodecSchema>::InProgress(..)
    ));
}

fn task_list<S: SupraDeliverySchema>(
    test_resources: &TestSupraDeliveryResources<S>,
) -> Vec<MessageMeta> {
    println!("{:?}", test_resources.delivery_manager.tasks());
    test_resources
        .delivery_manager
        .tasks()
        .keys()
        .cloned()
        .collect()
}

fn sync_list<S: SupraDeliverySchema>(
    test_resources: &TestSupraDeliveryResources<S>,
) -> Vec<MessageMeta> {
    println!("{:?}", test_resources.delivery_manager.sync_requests());
    test_resources
        .delivery_manager
        .sync_requests()
        .keys()
        .cloned()
        .collect()
}
