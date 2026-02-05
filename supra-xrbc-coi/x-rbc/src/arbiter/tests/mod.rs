mod arbiter_test;

use crate::arbiter::clients::ArbiterClient;
use crate::arbiter::messages::CoIMessages;
use crate::arbiter::{Arbiter, ArbiterServiceSchema};
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::types::messages::available::Available;
use block::proposer::BlockProviderClient;
use block::CertifiedBlock;
use crypto::Authenticator;
use network::client::{Action, NetworkServiceIFC};
use network::topology::peer_info::Role;
use network::topology::ChainTopology;
use primitives::{PeerGlobalIndex, RxChannel};
use tokio::sync::mpsc::unbounded_channel;

pub(crate) struct ArbiterTestResources {
    pub resource_provider: TestResources,
    pub arbiter: Arbiter,
    pub arbiter_client: ArbiterClient,
    pub block_rx: RxChannel<CertifiedBlock>,
    pub available_rx: RxChannel<Available>,
    pub arbiter_network_sender_rx: RxChannel<Action>,
}

impl ArbiterTestResources {
    pub fn new(peer_index: PeerGlobalIndex, role: Role) -> Self {
        let mut resource_provider = TestResources::new(role, peer_index);
        let (chain_topology, authenticator, _s) =
            resource_provider.get_resources(peer_index).split();
        let (arbiter, arbiter_client, block_rx, arbiter_network_rx, available_rx) =
            ArbiterTestResources::get_arbiter(chain_topology, authenticator);
        Self {
            resource_provider,
            arbiter,
            arbiter_client,
            block_rx,
            available_rx,
            arbiter_network_sender_rx: arbiter_network_rx,
        }
    }

    pub fn get_arbiter(
        topology: ChainTopology,
        authenticator: Authenticator,
    ) -> (
        Arbiter,
        ArbiterClient,
        RxChannel<CertifiedBlock>,
        RxChannel<Action>,
        RxChannel<Available>,
    ) {
        let (network_sender_tx, network_sender_rx) = unbounded_channel::<Action>();
        let (block_proposer_tx, block_proposer_rx) = unbounded_channel::<Available>();
        let network_sender_ifc = NetworkServiceIFC::<ArbiterServiceSchema>::new(network_sender_tx);
        let (tx, rx) = unbounded_channel::<CoIMessages>();
        let (certificate_tx, certificate_rx) = unbounded_channel::<CertifiedBlock>();
        let block_proposer_client = BlockProviderClient::<Available>::new(block_proposer_tx);
        let arbiter = Arbiter::new(
            topology,
            authenticator,
            network_sender_ifc,
            rx,
            certificate_tx,
            block_proposer_client,
        );
        (
            arbiter,
            ArbiterClient::new(tx),
            certificate_rx,
            network_sender_rx,
            block_proposer_rx,
        )
    }
}
