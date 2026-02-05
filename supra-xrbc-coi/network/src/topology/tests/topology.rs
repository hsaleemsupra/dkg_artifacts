use crate::topology::config::NetworkConfig;
use crate::topology::peer_info::{PeerInfo, Role};
use crate::topology::tests::TopologyGenerator;
use crate::topology::{ChainTopology, PeerFilterPredicate};
use crypto::traits::NodeIdentityInterface;
use primitives::{Addresses, ClanIdentifier, PeerGlobalIndex, Protocol};
use std::collections::{HashMap, HashSet};

#[test]
#[should_panic]
fn check_topology_generator_with_invalid_config() {
    let config_json_string = r#"
    {
        "tribes": 1,
        "clans": 1,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 5
    }
    "#;
    let network_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();

    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    TopologyGenerator::new(role, peer_index, network_config);
}

#[test]
fn check_valid_topology_creation() {
    let network_config = NetworkConfig::small();

    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &network_config);
    let ct = ChainTopology::new(&network_config, peers, &node_identity.public_key());
    assert!(ct.is_ok(), "{:?}", ct);
}

#[test]
fn check_valid_topology_creation_multi_tribe_clan() {
    let config_json_string = r#"
    {
        "tribes": 3,
        "clans": 4,
        "clan_size": 5,
        "proposers_per_tribe": 2,
        "proposers_per_clan": 2
    }
    "#;
    let network_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();

    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &network_config);
    let ct = ChainTopology::new(&network_config, peers, &node_identity.public_key());
    assert!(ct.is_ok(), "{:?}", ct);
}

#[test]
fn check_valid_topology_creation_single_clan_max_broadcaster_nodes() {
    let config_json_string = r#"
    {
        "tribes": 1,
        "clans": 1,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 3
    }
    "#;
    let network_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();

    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &network_config);
    let ct = ChainTopology::new(&network_config, peers, &node_identity.public_key());
    assert!(ct.is_ok(), "{:?}", ct);
}

#[test]
fn check_valid_topology_creation_all_clan_nodes_broadcaster() {
    let config_json_string = r#"
    {
        "tribes": 1,
        "clans": 2,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 5
    }
    "#;
    let network_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();

    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &network_config);
    let ct = ChainTopology::new(&network_config, peers, &node_identity.public_key());
    assert!(ct.is_ok(), "{:?}", ct);
}

#[test]
fn check_topology_with_invalid_peers() {
    let peer_info = PeerInfo::new([0; 32]);
    let network_config = NetworkConfig::small();
    let ct = ChainTopology::new(
        &network_config,
        HashMap::from([([0; 32], peer_info)]),
        &[0; 32],
    );
    assert!(ct.is_err());
}

#[test]
fn check_topology_with_invalid_current_node() {
    let network_config = NetworkConfig::small();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (peers, _node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &network_config);
    let ct = ChainTopology::new(&network_config, peers, &[0; 32]);
    assert!(ct.is_err(), "{:?}", ct);
}

#[test]
fn check_topology_with_incomplete_peer_count() {
    let network_config = NetworkConfig::small();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (mut peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &network_config);
    let new_peer = PeerInfo::local([0; 32]);
    peers.insert([0; 32], new_peer);
    let ct = ChainTopology::new(&network_config, peers, &node_identity.public_key());
    assert!(ct.is_err(), "{:?}", ct);
}

#[test]
fn check_topology_with_incorrect_proposer_config() {
    let network_config = NetworkConfig::small();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (mut peers, node_identity) = TopologyGenerator::generate_random_topology_peers(
        role.clone(),
        peer_index,
        &network_config,
    );
    if let Some((_, peer)) = peers.iter_mut().find(|(_, peer)| !peer.is_proposer()) {
        peer.set_role(Role::Leader);
    }
    let ct = ChainTopology::new(&network_config, peers, &node_identity.public_key());
    assert!(ct.is_err(), "{:?}", ct);
}

#[test]
fn test_chain_topology_methods() {
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let role = Role::Leader;
    let config_json_string = r#"
    {
        "tribes": 1,
        "clans": 4,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let mut generator = TopologyGenerator::new(role.clone(), peer_index, nt_config.clone());
    generator.run();
    let (peers, current_node_origin) = (
        generator.get_network_peers(),
        generator.get_origin(&peer_index),
    );

    let chain_topology = ChainTopology::new(&nt_config, peers, &current_node_origin);
    assert!(chain_topology.is_ok(), "{:?}", chain_topology);
    let chain_topology = chain_topology.unwrap();

    // Check current peer info
    let peer_info = chain_topology.info_by_origin(&current_node_origin);
    assert!(peer_info.is_some());
    let peer_info = peer_info.unwrap();
    assert_eq!(peer_info, chain_topology.current_node());
    assert_eq!(peer_info.role(), &role);
    assert_eq!(peer_info.global_index(), peer_index);
    assert_eq!(chain_topology.get_position(), peer_index.position());
    assert_eq!(chain_topology.origin(), &current_node_origin);

    check_proposer_api(&chain_topology, &generator);
    check_peer_info_api(&chain_topology, &generator);
    check_clan_network_size_api(
        &chain_topology,
        nt_config.clan_size(),
        nt_config.tribes(),
        nt_config.total_nodes(),
    );

    check_address_retrieval_api(&chain_topology, &generator, Protocol::XRBC);
}

fn check_proposer_api(chain_topology: &ChainTopology, generator: &TopologyGenerator) {
    // Check is proposer API
    assert!(chain_topology.is_proposer(chain_topology.origin()));
    assert!(!chain_topology.is_proposer(&generator.get_origin(&PeerGlobalIndex::new(0, 2, 0))));
}

fn check_peer_info_api(chain_topology: &ChainTopology, generator: &TopologyGenerator) {
    // Check is peer_by_position API
    assert!(chain_topology.peer_by_position(1).is_some());
    assert!(chain_topology
        .peer_by_position(generator.config.clan_size())
        .is_none());

    // Check info by origin  API
    assert!(chain_topology
        .info_by_origin(&generator.get_origin(&PeerGlobalIndex::new(0, 3, 3)))
        .is_some());
    assert!(chain_topology.info_by_origin(&[1; 32]).is_none());

    // Check node info by predicate
    let origin1 = generator.get_origin(&PeerGlobalIndex::new(0, 1, 3));
    let origin2 = generator.get_origin(&PeerGlobalIndex::new(0, 2, 3));
    let nodes = chain_topology.get_nodes(PeerFilterPredicate::NotWithOrigin(&[origin1, origin2]));
    // excluding 2 origins from predicate and current node
    assert_eq!(nodes.len(), chain_topology.get_chain_size() - 3);
    let result = nodes
        .iter()
        .all(|p| p.id() != &origin1 && p.id() != &origin2 && p.id() != chain_topology.origin());
    assert!(result);

    let clan_identifier = chain_topology
        .info_by_origin(&origin1)
        .unwrap()
        .clan_identifier();
    let nodes = chain_topology.get_nodes(PeerFilterPredicate::NotInClan(clan_identifier));
    // excluding the clan peers and current node
    assert_eq!(
        nodes.len(),
        chain_topology.get_chain_size() - chain_topology.get_committee_size() - 1
    );

    let nodes = chain_topology.get_nodes(PeerFilterPredicate::Pass);
    // All except current node
    assert_eq!(nodes.len(), chain_topology.get_chain_size() - 1);
}

fn check_clan_network_size_api(
    chain_topology: &ChainTopology,
    expected_clan_size: usize,
    expected_tribes: usize,
    expected_network_size: usize,
) {
    // Check info by origin  API
    assert_eq!(chain_topology.get_committee_size(), expected_clan_size);
    assert_eq!(chain_topology.get_chain_size(), expected_network_size);
    assert_eq!(chain_topology.get_tribes_len(), expected_tribes);
    assert_eq!(
        chain_topology.get_tribe_size(),
        expected_network_size / (expected_tribes * expected_clan_size)
    );
}

fn check_address_retrieval_api(
    chain_topology: &ChainTopology,
    generator: &TopologyGenerator,
    protocol: Protocol,
) {
    let check_addresses = |addresses: Addresses, exclude_list: &[usize]| {
        assert_eq!(
            addresses.len(),
            chain_topology.get_committee_size() - exclude_list.len()
        );
        for i in 0..chain_topology.get_committee_size() {
            if exclude_list.contains(&i) {
                continue;
            }
            let peer_address = chain_topology
                .peer_by_position(i)
                .unwrap()
                .get_address(protocol)
                .unwrap();
            assert!(addresses.contains(&peer_address));
        }
    };
    let peer_addresses = chain_topology.get_peer_addresses(protocol, PeerFilterPredicate::Pass);
    check_addresses(peer_addresses, &[chain_topology.get_position()]);

    let peer_addresses =
        chain_topology.get_peer_addresses(protocol, PeerFilterPredicate::NotAtPosition(&[2, 4]));
    check_addresses(peer_addresses, &[chain_topology.get_position(), 2, 4]);

    // Check address by origin
    let origin = generator.get_origin(&PeerGlobalIndex::new(0, 2, 2));
    let peer_info = chain_topology.info_by_origin(&origin);
    let address = chain_topology.get_address_by_origin(protocol, &origin);
    assert!(address.is_some());
    assert_eq!(
        address,
        peer_info.and_then(|info| info.get_address(protocol))
    );

    assert!(chain_topology
        .get_address_by_origin(protocol, &[2; 32])
        .is_none());

    // Check address by position
    let position = 3;
    let peer_info = chain_topology.peer_by_position(position);
    let address = chain_topology.get_address_by_position(protocol, position);
    assert!(address.is_some());
    assert_eq!(
        address,
        peer_info.and_then(|info| info.get_address(protocol))
    );

    assert!(chain_topology
        .get_address_by_position(protocol, 5)
        .is_none());

    // Check node info by predicate
    let origin1 = generator.get_origin(&PeerGlobalIndex::new(0, 1, 3));
    let origin2 = generator.get_origin(&PeerGlobalIndex::new(0, 2, 3));
    let nodes = chain_topology.get_nodes_addresses(
        protocol,
        PeerFilterPredicate::NotWithOrigin(&[origin1, origin2]),
    );
    // excluding 2 origins from predicate and current node
    assert_eq!(nodes.len(), chain_topology.get_chain_size() - 3);

    let clan_identifier = chain_topology
        .info_by_origin(&origin1)
        .unwrap()
        .clan_identifier();
    let nodes = chain_topology
        .get_nodes_addresses(protocol, PeerFilterPredicate::NotInClan(clan_identifier));
    // excluding the clan peers and current node
    assert_eq!(
        nodes.len(),
        chain_topology.get_chain_size() - chain_topology.get_committee_size() - 1
    );

    let nodes = chain_topology.get_nodes_addresses(protocol, PeerFilterPredicate::Pass);
    // All except current node
    assert_eq!(nodes.len(), chain_topology.get_chain_size() - 1);
}

#[test]
fn test_global_index_calculation() {
    let config_json_string = r#"
    {
        "tribes": 2,
        "clans": 2,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &nt_config);
    let ct = ChainTopology::new(&nt_config, peers, &node_identity.public_key()).unwrap();

    assert_eq!(
        ct.calculate_global_index(0),
        Some(PeerGlobalIndex::new(0, 0, 0))
    );
    assert_eq!(
        ct.calculate_global_index(4),
        Some(PeerGlobalIndex::new(0, 0, 4))
    );
    assert_eq!(
        ct.calculate_global_index(5),
        Some(PeerGlobalIndex::new(0, 1, 0))
    );
    assert_eq!(
        ct.calculate_global_index(19),
        Some(PeerGlobalIndex::new(1, 1, 4))
    );
    assert_eq!(ct.calculate_global_index(20), None);
    assert_eq!(ct.calculate_global_index(25), None);
}

#[test]
fn test_info_by_global_index() {
    let config_json_string = r#"
    {
        "tribes": 2,
        "clans": 2,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let mut generator = TopologyGenerator::new(role, peer_index, nt_config);
    generator.run();
    let (ct, _) = generator.topology_for_peer(peer_index);

    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let peer_origin = generator.get_origin(&peer_index);
    let info = ct.info_by_origin(&peer_origin);
    println!("{:?}", peer_origin);
    assert!(info.is_some());
    assert_eq!(
        ct.info_by_origin(&peer_origin),
        ct.info_by_global_index(peer_index)
    );

    let peer_index = PeerGlobalIndex::new(1, 0, 0);
    let peer_origin = generator.get_origin(&peer_index);
    println!("{:?}", peer_origin);
    let info = ct.info_by_origin(&peer_origin);
    assert!(info.is_some());
    assert_eq!(
        ct.info_by_origin(&peer_origin),
        ct.info_by_global_index(peer_index)
    );

    let peer_index = PeerGlobalIndex::new(1, 2, 0);
    assert!(ct.info_by_global_index(peer_index).is_none());
}

#[test]
fn test_info_relative_to_current_node() {
    let config_json_string = r#"
    {
        "tribes": 3,
        "clans": 7,
        "clan_size": 5,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &nt_config);
    let ct = ChainTopology::new(&nt_config, peers, &node_identity.public_key()).unwrap();

    let mut distribution = HashSet::<PeerGlobalIndex>::new();
    for commitment_index in nt_config.clan_size()..nt_config.total_nodes() {
        if commitment_index % nt_config.clan_size() != peer_index.position() {
            continue;
        }
        let nt_peer = ct
            .get_info_relative_to_current_node(commitment_index)
            .expect("Expected info by peer index");
        let nt_target_peer_index = nt_peer.global_index();
        assert_ne!(nt_target_peer_index, peer_index);
        assert_eq!(nt_target_peer_index.position(), peer_index.position());
        distribution.insert(nt_target_peer_index);
    }
    assert_eq!(
        distribution.len(),
        nt_config.total_nodes() / nt_config.clan_size() - 1
    );

    distribution.clear();
    for commitment_index in 0..nt_config.clan_size() {
        let nt_peer = ct
            .get_info_relative_to_current_node(commitment_index)
            .expect("Expected info by peer index");
        let nt_target_peer_index = nt_peer.global_index();
        assert_eq!(
            nt_target_peer_index.clan_identifier(),
            peer_index.clan_identifier()
        );
        distribution.insert(nt_target_peer_index);
    }
    assert_eq!(distribution.len(), nt_config.clan_size());

    // Invalid flattened-global-index
    assert!(ct.get_info_relative_to_current_node(105).is_none());
    assert!(ct.get_info_relative_to_current_node(106).is_none());
}

#[test]
fn test_address_relative_to_current_node() {
    let config_json_string = r#"
    {
        "tribes": 2,
        "clans": 3,
        "clan_size": 4,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &nt_config);
    let ct = ChainTopology::new(&nt_config, peers, &node_identity.public_key()).unwrap();

    for commitment_index in 0..nt_config.total_nodes() {
        let nt_peer = ct
            .get_node_address_relative_to_current_node(Protocol::XRBC, commitment_index)
            .expect("Expected info by peer index");
        let peer = ct
            .get_info_relative_to_current_node(commitment_index)
            .expect("Expected info by peer index");
        assert_eq!(nt_peer, peer.get_address(Protocol::XRBC).unwrap());
    }

    // Invalid flattened-global-index
    assert!(ct
        .get_node_address_relative_to_current_node(Protocol::XRBC, 24)
        .is_none());
    assert!(ct
        .get_node_address_relative_to_current_node(Protocol::XRBC, 25)
        .is_none());
}

#[test]
fn test_address_relative_to_origin() {
    let config_json_string = r#"
    {
        "tribes": 2,
        "clans": 3,
        "clan_size": 4,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(1, 1, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &nt_config);
    let ct = ChainTopology::new(&nt_config, peers, &node_identity.public_key()).unwrap();
    let origin_111 = *ct
        .info_by_global_index(PeerGlobalIndex::new(1, 1, 1))
        .unwrap()
        .id();

    let origin_113 = *ct
        .info_by_global_index(PeerGlobalIndex::new(1, 1, 3))
        .unwrap()
        .id();

    for commitment_index in 0..nt_config.total_nodes() {
        let peer_cn = ct
            .get_info_relative_to_current_node(commitment_index)
            .expect("Expected info by peer index");
        let peer_rel_origin_111 = ct
            .get_info_relative_to_origin(&origin_111, commitment_index)
            .expect("Expected info by peer index");
        let peer_rel_origin_113 = ct
            .get_info_relative_to_origin(&origin_113, commitment_index)
            .expect("Expected info by peer index");
        assert_eq!(peer_cn, peer_rel_origin_111);
        assert_eq!(peer_cn, peer_rel_origin_113);
    }

    // Invalid flattened-global-index
    assert!(ct.get_info_relative_to_origin(&origin_111, 24).is_none());
}

#[test]
fn test_flattened_index_api() {
    let config_json_string = r#"
    {
        "tribes": 2,
        "clans": 3,
        "clan_size": 4,
        "proposers_per_tribe": 1,
        "proposers_per_clan": 2
    }
    "#;
    let nt_config: NetworkConfig = serde_json::from_str(config_json_string).unwrap();
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(1, 1, 2);
    let (peers, node_identity) =
        TopologyGenerator::generate_random_topology_peers(role, peer_index, &nt_config);
    let ct = ChainTopology::new(&nt_config, peers.clone(), &node_identity.public_key()).unwrap();

    assert_eq!(ct.get_flattened_index(), (1 * 3 + 1) * 4 + 2);

    // None existing origin
    assert!(ct.get_origin_flattened_index(&[2; 32]).is_none());

    let (origin, peer_info) = peers.iter().next().unwrap();
    let result = ct.get_origin_flattened_index(origin);
    assert!(result.is_some());
    assert_eq!(result, peer_info.global_index().flatten(3, 4));

    let (_origin, peer_info) = peers.iter().next().unwrap();
    let result = ct.get_peer_flattened_index(&peer_info);
    assert_eq!(result, peer_info.global_index().flatten(3, 4).unwrap());
}

#[test]
fn check_peer_filter_predicate() {
    let mut peer_info = PeerInfo::local([4; 32]);
    peer_info.set_tribe(1);
    peer_info.set_clan(2);
    peer_info.set_position(3);

    let check_predicate =
        |predicate: PeerFilterPredicate, peer_info: &PeerInfo, expected_result: bool| {
            let result = predicate.apply(&peer_info);
            let result_for_origin =
                predicate.for_origin_with_index(peer_info.id(), peer_info.global_index());
            assert_eq!(result, expected_result);
            assert_eq!(result, result_for_origin);
        };

    check_predicate(
        PeerFilterPredicate::NotWithOrigin(&[[1; 32]]),
        &peer_info,
        true,
    );

    check_predicate(
        PeerFilterPredicate::NotWithOrigin(&[[4; 32], [1; 32]]),
        &peer_info,
        false,
    );

    check_predicate(
        PeerFilterPredicate::NotInClan(ClanIdentifier::new(1, 3)),
        &peer_info,
        true,
    );

    check_predicate(
        PeerFilterPredicate::NotInClan(ClanIdentifier::new(1, 2)),
        &peer_info,
        false,
    );

    check_predicate(
        PeerFilterPredicate::NotAtPosition(&[peer_info.position() + 1]),
        &peer_info,
        true,
    );

    check_predicate(
        PeerFilterPredicate::NotAtPosition(&[peer_info.position() + 1, peer_info.position()]),
        &peer_info,
        false,
    );

    check_predicate(PeerFilterPredicate::Pass, &peer_info, true);

    let peer_info = PeerInfo::new([5; 32]);
    check_predicate(PeerFilterPredicate::Pass, &peer_info, true);
}
