pub mod clients;
mod errors;
pub mod messages;
#[cfg(test)]
pub(crate) mod tests;

use crate::arbiter::clients::ArbiterClient;
use crate::arbiter::errors::ArbiterError;
use crate::arbiter::messages::CoIMessages;
use crate::types::messages::available::Available;
use block::proposer::BlockProviderClient;
use block::{Block, BlockIfc, CertifiedBlock};
use crypto::Authenticator;
use log::{error, info};
use network::client::{NetworkServiceIFC, NetworkServiceSchema};
use network::topology::{ChainTopology, PeerFilterPredicate};
use network::{NetworkSender, Receiver};
use primitives::types::HeaderIfc;
use primitives::{Protocol, RxChannel, TxChannel};

#[derive(Clone)]
pub struct ArbiterServiceSchema {}

impl NetworkServiceSchema for ArbiterServiceSchema {
    type TargetType = CoIMessages;
}

pub struct Arbiter {
    topology: ChainTopology,
    authenticator: Authenticator,
    network_tx: NetworkServiceIFC<ArbiterServiceSchema>,
    input: RxChannel<CoIMessages>,
    synchronizer_tx: TxChannel<CertifiedBlock>,
    block_provider_tx: BlockProviderClient<Available>,
}

impl Arbiter {
    pub fn new(
        topology: ChainTopology,
        authenticator: Authenticator,
        network_tx: NetworkServiceIFC<ArbiterServiceSchema>,
        input: RxChannel<CoIMessages>,
        synchronizer_tx: TxChannel<CertifiedBlock>,
        block_provider_tx: BlockProviderClient<Available>,
    ) -> Self {
        Self {
            topology,
            authenticator,
            network_tx,
            input,
            synchronizer_tx,
            block_provider_tx,
        }
    }

    async fn run(mut self) {
        info!("Arbiter Started");
        loop {
            self.run_step().await;
        }
    }

    async fn run_step(&mut self) {
        let result = tokio::select! {
            Some(coi_message) = self.input.recv() => {
              self.handle_coi_message(coi_message).await
            }
        };
        let _ = result.map_err(|e| error!("{:?}", e));
    }

    fn validate_available_message(&self, available: &Available) -> Result<(), ArbiterError> {
        let message_origin = available.origin();
        let mut error_msg = String::new();
        if !self.topology.is_proposer(message_origin) {
            error_msg = format!("Available message is not from proposer");
        } else if !self.topology.current_node().is_block_proposer()
            && message_origin != self.topology.origin()
        {
            error_msg = format!("Unexpected Available message, node is not block proposer");
        } else if !self.topology.current_node().is_proposer()
            && message_origin == self.topology.origin()
        {
            error_msg = format!(
                "Unexpected Available message, node is basic but produced Available message"
            );
        }
        if error_msg.is_empty() {
            Ok(())
        } else {
            Err(ArbiterError::InvalidMessage(error_msg))
        }
    }

    async fn handle_coi_message(&self, message: CoIMessages) -> Result<(), ArbiterError> {
        match message {
            CoIMessages::Available(available) => self.handle_available_message(available).await,
            CoIMessages::CertifiedBlock(certified_block) => {
                self.handle_certified_block(certified_block)
            }
            CoIMessages::Block(block) => self.handle_block(block).await,
        }
    }

    async fn handle_available_message(&self, available: Available) -> Result<(), ArbiterError> {
        self.validate_available_message(&available)?;
        if available.origin().eq(self.topology.origin()) {
            let block_proposer = self
                .topology
                .get_block_proposer_info()
                .get_address(Protocol::COI)
                .unwrap();
            let _ = self
                .network_tx
                .send(block_proposer, available.clone())
                .await
                .map_err(|e| error!("Failed to broadcast message: {}", e));
        }
        self.block_provider_tx
            .send(available)
            .map_err(|e| ArbiterError::SendError(e))
    }

    fn handle_certified_block(&self, certified_block: CertifiedBlock) -> Result<(), ArbiterError> {
        self.synchronizer_tx
            .send(certified_block)
            .map_err(|e| ArbiterError::SendError(format!("{}", e)))
    }

    async fn handle_block(&self, block: Block) -> Result<(), ArbiterError> {
        if !self.topology.current_node().is_block_proposer() {
            return Err(ArbiterError::InvalidMessage(
                "Not a block-proposer node received block data".to_string(),
            ));
        }

        let signature = self
            .authenticator
            .sign(block.id())
            .map_err(|e| ArbiterError::CryptoError(e))?;
        let mut certificate = [0; 96];
        certificate[32..].copy_from_slice(&signature);
        let certified_block = CertifiedBlock::new(certificate, block);
        self.broadcast_message(certified_block.clone()).await?;
        self.handle_certified_block(certified_block)
    }

    async fn broadcast_message<T: Into<CoIMessages>>(&self, msg: T) -> Result<(), ArbiterError> {
        let addresses = self
            .topology
            .get_nodes_addresses(Protocol::COI, PeerFilterPredicate::Pass);
        self.network_tx
            .broadcast(addresses, msg)
            .await
            .map_err(ArbiterError::CommonError)
    }

    pub fn spawn(
        topology: ChainTopology,
        authenticator: Authenticator,
        arbiter_rx: RxChannel<CoIMessages>,
        arbiter_tx: TxChannel<CoIMessages>,
        synchronizer_tx: TxChannel<CertifiedBlock>,
        block_provider_tx: BlockProviderClient<Available>,
    ) -> ArbiterClient {
        let arbiter_client = ArbiterClient::new(arbiter_tx);
        // Network Sender interface to send CoI Messages
        let network_sender_ifc = NetworkSender::new::<ArbiterServiceSchema>();
        let arbiter = Arbiter::new(
            topology,
            authenticator,
            network_sender_ifc,
            arbiter_rx,
            synchronizer_tx,
            block_provider_tx,
        );

        let coi_socket = arbiter
            .topology
            .current_node()
            .get_address(Protocol::COI)
            .unwrap();
        tokio::spawn(Arbiter::run(arbiter));
        info!("Arbiter: listen interface: {}", coi_socket);
        Receiver::spawn(coi_socket, arbiter_client.clone());
        arbiter_client
    }
}
