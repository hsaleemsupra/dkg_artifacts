use crate::arbiter::errors::ArbiterError;
use crate::arbiter::messages::CoIMessages;
use crate::arbiter::tests::ArbiterTestResources;
use crate::types::context::ResourcesApi;
use crate::types::messages::available::Available;
use crate::types::tests::header_with_origin;
use block::{Block, BlockIfc, CertifiedBlock};
use network::client::Action;
use network::topology::peer_info::Role;
use primitives::serde::bincode_deserialize;
use primitives::types::QuorumCertificate;
use primitives::{Origin, PeerGlobalIndex, Protocol};
use std::collections::BTreeSet;

fn generate_available(resource: &ArbiterTestResources) -> Available {
    generate_available_with_origin(*resource.arbiter.topology.origin())
}

fn generate_available_with_origin(origin: Origin) -> Available {
    let header = header_with_origin(origin);
    Available::new(
        header,
        [0; 64],
        QuorumCertificate::new([4; 96], BTreeSet::from([1, 2, 3])),
    )
}

#[tokio::test]
async fn check_available_message_handling_broadcaster() {
    let mut resources = ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::Leader);
    let unexpected_avail = generate_available_with_origin([3; 32]);
    let result = resources
        .arbiter
        .handle_available_message(unexpected_avail)
        .await;
    assert!(result.is_err());
    let data_to_block_handler = resources.available_rx.try_recv();
    assert!(data_to_block_handler.is_err());
    let data_to_broadcast = resources.arbiter_network_sender_rx.try_recv();
    assert!(data_to_broadcast.is_err());

    let avail = generate_available(&resources);
    let result = resources.arbiter.handle_available_message(avail).await;
    assert!(result.is_ok());
    let data_to_block_handler = resources.available_rx.try_recv();
    assert!(data_to_block_handler.is_ok());

    // avail is broadcast
    let has_broadcast = resources.arbiter_network_sender_rx.try_recv();
    assert!(has_broadcast.is_ok());
    let action = has_broadcast.unwrap();
    if let Action::Unicast(addresses, _) = action {
        let expected_address = resources
            .arbiter
            .topology
            .get_block_proposer_info()
            .get_address(Protocol::COI)
            .unwrap();
        assert_eq!(addresses, expected_address);
    } else {
        assert!(false, "Expected unicast, got: {:?}", action);
    }
}

#[tokio::test]
async fn check_available_message_handling_basic() {
    let mut resources = ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::Basic);
    let unexpected_avail = generate_available_with_origin([3; 32]);
    let result = resources
        .arbiter
        .handle_available_message(unexpected_avail)
        .await;
    assert!(matches!(result, Err(ArbiterError::InvalidMessage(_))));

    // non-leader can not receive internal avail message
    let avail = generate_available(&resources);
    let result = resources.arbiter.handle_available_message(avail).await;
    assert!(matches!(result, Err(ArbiterError::InvalidMessage(_))));

    // basic node should reject avail messages from broadcaster as well.
    // By current placeholder implementation Avail is sent only to block-proposer
    let batch_proposer_res = resources.resource_provider.get_broadcaster_resources();
    let avail = generate_available_with_origin(*batch_proposer_res.topology().origin());
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::Available(avail))
        .await;
    assert!(result.is_err());
    // avail is not broadcast
    let has_broadcast = resources.arbiter_network_sender_rx.try_recv();
    assert!(has_broadcast.is_err());
}

#[tokio::test]
async fn check_available_message_handling_block_proposer() {
    let mut resources =
        ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::BlockProposer);
    let avail = generate_available_with_origin([3; 32]);
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::Available(avail))
        .await;
    assert!(result.is_err());
    // avail is not broadcast
    let has_broadcast = resources.arbiter_network_sender_rx.try_recv();
    assert!(has_broadcast.is_err());

    let batch_proposer_res = resources.resource_provider.get_broadcaster_resources();
    let avail = generate_available_with_origin(*batch_proposer_res.topology().origin());
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::Available(avail))
        .await;
    assert!(result.is_ok(), "{:?}", result);
    // Avail is sent to block-proposer
    let data_to_block_handler = resources.available_rx.try_recv();
    assert!(data_to_block_handler.is_ok());
    // avail is not broadcast
    let has_broadcast = resources.arbiter_network_sender_rx.try_recv();
    assert!(has_broadcast.is_err());
}

#[tokio::test]
async fn check_handling_of_block() {
    let mut resources =
        ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::BlockProposer);
    let block = Block::new([1; 32], [2; 32]);
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::Block(block.clone()))
        .await;
    assert!(result.is_ok());
    // Certified Block is broadcast
    let has_broadcast = resources.arbiter_network_sender_rx.try_recv();
    assert!(has_broadcast.is_ok());
    let action = has_broadcast.unwrap();
    if let Action::Broadcast(addresses, data) = action {
        let message = bincode_deserialize::<CoIMessages>(&data).unwrap();
        match message {
            CoIMessages::CertifiedBlock(certified_block) => {
                assert_eq!(certified_block.id(), block.id());
                assert_eq!(certified_block.previous_id(), block.previous_id());
            }
            _ => {
                assert!(false, "Expected certified block got: {:?}", message)
            }
        }
        assert_eq!(
            addresses.len(),
            resources.arbiter.topology.get_chain_size() - 1
        );
    }
    // Certified block is also sent to internal synchronizer
    let sync_rx_data = resources.block_rx.try_recv();
    assert!(sync_rx_data.is_ok());

    // Basic node can not handle block messages currently
    let resources = ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::Basic);
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::Block(block.clone()))
        .await;
    assert!(result.is_err());

    // Leader node can not handle block messages currently
    let resources = ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::Leader);
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::Block(block))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_handling_of_certified_block() {
    let mut resources = ArbiterTestResources::new(PeerGlobalIndex::new(0, 0, 1), Role::Leader);
    let block = Block::new([1; 32], [2; 32]);
    let cert_block = CertifiedBlock::new([2; 96], block);
    let result = resources
        .arbiter
        .handle_coi_message(CoIMessages::CertifiedBlock(cert_block.clone()))
        .await;
    assert!(result.is_ok());
    let sync_rx_data = resources.block_rx.try_recv();
    assert!(sync_rx_data.is_ok());
}
