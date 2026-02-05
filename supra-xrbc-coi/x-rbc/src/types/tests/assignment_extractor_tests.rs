use crate::types::helpers::Visitor;
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCCommitteeMessage, RBCNetworkMessage, ShareData,
    ValueData, VoteData,
};
use crate::types::tests::{
    certificate_data, get_value_data, header_with_origin, partial_share, ready_data,
    value_data_with_header, value_data_with_header_idx, TestSupraCodec,
};
use primitives::types::{Header, HeaderIfc};

use crate::states::tests::ContextProvider;
use crate::tasks::codec::EncodeResultIfc;
use crate::tasks::config::{DisseminationRule, EchoTarget};
use crate::types::context::ResourcesApi;
use crate::types::helpers::assignment_extractor::AssignmentExtractor;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::QuorumCertificate;
use network::topology::config::NetworkConfig;
use network::topology::peer_info::Role;
use network::topology::tests::TopologyGenerator;
use network::topology::{ChainTopology, PeerFilterPredicate};
use primitives::{PeerGlobalIndex, Protocol};
use vec_commitment::committed_chunk::CommitmentMeta;

const NETWORK_CONFIG_JSON: &'static str = r#"
{
    "tribes": 1,
    "clans": 3,
    "clan_size": 5,
    "proposers_per_tribe": 1,
    "proposers_per_clan": 1
}
"#;

fn get_topology_for_leader_node_022() -> ChainTopology {
    let role = Role::Leader;
    let config: NetworkConfig =
        serde_json::from_str(NETWORK_CONFIG_JSON).expect("Valid NetworkConfig");
    let (topology, _) =
        TopologyGenerator::generate_random_topology(role, PeerGlobalIndex::new(0, 2, 2), &config);
    topology
}

#[test]
fn check_payload_data_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();
    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let payload_data = PayloadData::new(header.clone(), vec![10; 25]);
    let addresses = <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_payload(
        &assignment_extractor,
        &payload_data,
    )
    .unwrap();
    assert_eq!(addresses.len(), topology.get_committee_size() - 1);
    let current_node_address = topology.current_node().get_address(Protocol::XRBC).unwrap();
    assert!(!addresses.contains(&current_node_address));
    let expected_addresses = topology.get_peer_addresses(Protocol::XRBC, PeerFilterPredicate::Pass);
    assert_eq!(expected_addresses, addresses)
}

#[test]
fn check_value_data_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();
    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let value_data_0 = value_data_with_header::<TestSupraCodec>(header.clone());
    let addresses_0 = assignment_extractor.visit_value(&value_data_0).unwrap();
    assert_eq!(addresses_0.len(), 1);
    assert!(addresses_0.contains(
        &topology
            .peer_by_position(0)
            .and_then(|p| p.get_address(Protocol::XRBC))
            .unwrap()
    ));

    // for value data data index does not play role
    let value_data_2 = value_data_with_header_idx::<TestSupraCodec>(header.clone(), 2);
    let addresses_2 = assignment_extractor.visit_value(&value_data_2).unwrap();
    assert_eq!(addresses_2.len(), 1);
    assert!(addresses_2.contains(
        &topology
            .peer_by_position(2)
            .and_then(|p| p.get_address(Protocol::XRBC))
            .unwrap()
    ));

    // RBC Value message sender is the same
    let rbc_msg = RBCCommitteeMessage::Value(value_data_2);
    let rbc_msg_sender = assignment_extractor
        .visit_committee_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_sender, addresses_2);

    // Non index returns nothing
    let addresses = assignment_extractor.visit_value(
        &value_data_with_header_idx::<TestSupraCodec>(Header::default(), 10),
    );
    assert!(addresses.is_none());
}

#[test]
fn check_echo_data_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let e_value_data_0 =
        EchoValueData::new(value_data_with_header::<TestSupraCodec>(header.clone()));
    let addresses_0 = assignment_extractor
        .visit_echo_value(&e_value_data_0)
        .unwrap();
    assert_eq!(addresses_0.len(), topology.get_committee_size() - 1);
    assert!(!addresses_0.contains(&topology.current_node().get_address(Protocol::XRBC).unwrap()));

    // for echo value data data index does play role
    let header_0 = header_with_origin(*topology.peer_by_position(0).unwrap().id());
    let e_value_data_2 =
        EchoValueData::new(value_data_with_header_idx::<TestSupraCodec>(header_0, 2));
    let addresses_2 = assignment_extractor
        .visit_echo_value(&e_value_data_2)
        .unwrap();
    assert_eq!(addresses_2.len(), topology.get_committee_size() - 2);
    assert!(!addresses_2.contains(&topology.current_node().get_address(Protocol::XRBC).unwrap()));
    assert!(!addresses_2.contains(
        &topology
            .peer_by_position(0)
            .unwrap()
            .get_address(Protocol::XRBC)
            .unwrap()
    ));

    // RBC EchoValue message sender is the same
    let rbc_msg = RBCCommitteeMessage::EchoValue(e_value_data_2);
    let rbc_msg_sender = assignment_extractor
        .visit_committee_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_sender, addresses_2);

    // Non existing origin result to nothing
    let invalid_origin = EchoValueData::new(value_data_with_header_idx::<TestSupraCodec>(
        header_with_origin([2; 32]),
        5,
    ));
    let addresses = assignment_extractor.visit_echo_value(&invalid_origin);
    assert!(addresses.is_none());
}

#[test]
fn check_vote_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let expected_address = topology
        .peer_by_position(1)
        .unwrap()
        .get_address(Protocol::XRBC)
        .unwrap();
    let header = header_with_origin(*topology.peer_by_position(1).unwrap().id());
    let vote_0 = VoteData::new(header.clone(), partial_share(0));
    let addresses_0 = <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_vote(
        &assignment_extractor,
        &vote_0,
    )
    .unwrap();
    assert_eq!(addresses_0.len(), 1);
    assert_eq!(addresses_0[0], expected_address);

    // for echo value data data index does play role
    let vote_2 = VoteData::new(header, partial_share(2));
    let addresses_2 = <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_vote(
        &assignment_extractor,
        &vote_2,
    )
    .unwrap();
    assert_eq!(addresses_0, addresses_2);

    // RBC Vote message sender is the same
    let rbc_msg = RBCCommitteeMessage::<TestSupraCodec>::Vote(vote_2);
    let rbc_msg_addresses = assignment_extractor
        .visit_committee_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_addresses, addresses_2);

    // Non existing origin
    let invalid_index = VoteData::new(Header::default(), partial_share(5));
    let addresses = <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_vote(
        &assignment_extractor,
        &invalid_index,
    );
    assert!(addresses.is_none());
}

#[test]
fn check_certificate_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let certificate = certificate_data(header);
    let addresses = <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_certificate(
        &assignment_extractor,
        &certificate,
    )
    .unwrap();
    assert_eq!(addresses.len(), 4);
}

#[test]
fn check_ready_data_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let sender_info = topology.peer_by_position(3);
    let value_data = value_data_with_header_idx::<TestSupraCodec>(header, 1);
    let ready = ready_data(*sender_info.unwrap().id(), value_data);
    let assignee_address = assignment_extractor.visit_ready(&ready).unwrap();
    assert_eq!(assignee_address.len(), 1);
    assert_eq!(
        assignee_address[0],
        topology
            .peer_by_position(1)
            .unwrap()
            .get_address(Protocol::XRBC)
            .unwrap()
    );

    // RBC ReadyData message sender is the same
    let rbc_msg = RBCCommitteeMessage::Ready(ready);
    let rbc_msg_assignee = assignment_extractor
        .visit_committee_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_assignee, assignee_address);

    // Non existing ready message index
    let addresses = assignment_extractor.visit_ready(&ready_data::<TestSupraCodec>(
        [1; 32],
        value_data_with_header_idx(Header::default(), 6),
    ));
    assert!(addresses.is_none());
}

#[test]
fn check_echo_ready_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.peer_by_position(3).unwrap().id());
    let ready_sender = topology.peer_by_position(1);
    let e_ready_data_0 = EchoReadyData::new(ready_data(
        *ready_sender.unwrap().id(),
        value_data_with_header::<TestSupraCodec>(header.clone()),
    ));
    let addresses_0 = assignment_extractor
        .visit_echo_ready(&e_ready_data_0)
        .unwrap();
    // current node, broadcaster and sender
    assert_eq!(addresses_0.len(), topology.get_committee_size() - 3);

    // RBC EchoValue message
    let rbc_msg = RBCCommitteeMessage::EchoReady(e_ready_data_0);
    let rbc_msg_addresses = assignment_extractor
        .visit_committee_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_addresses, addresses_0);

    // Non origin & invalid sender
    let invalid_index = EchoReadyData::new(ready_data(
        [1; 32],
        value_data_with_header_idx::<TestSupraCodec>(Header::default(), 5),
    ));
    let addresses = assignment_extractor.visit_echo_ready(&invalid_index);
    assert!(addresses.is_none());
}

#[test]
fn check_share_data_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let addresses_info = topology.peer_by_position(0).unwrap();
    let value_data = value_data_with_header::<TestSupraCodec>(header.clone());
    // Even though network chunk commitment index can not be 0, as chunks in [0, clan_size -1] are committee-chunks
    // extractor will return valid result which will be a 0th peer for current node clan
    let commitment_meta = CommitmentMeta::new(0, vec![], [0; 32]);
    let share = ShareData::new(*addresses_info.id(), value_data, commitment_meta);
    let addresses = assignment_extractor.visit_share(&share).unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        addresses[0],
        addresses_info.get_address(Protocol::XRBC).unwrap()
    );

    let addresses_info = topology.get_info_relative_to_clan(2, 9).unwrap();
    assert_eq!(addresses_info.clan(), 0);
    assert_eq!(addresses_info.position(), 4);
    let value_data = value_data_with_header::<TestSupraCodec>(header);
    let commitment_meta = CommitmentMeta::new(9, vec![], [0; 32]);
    let share = ShareData::new(*addresses_info.id(), value_data, commitment_meta);
    let addresses = assignment_extractor.visit_share(&share).unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(
        addresses[0],
        addresses_info.get_address(Protocol::XRBC).unwrap()
    );

    // RBC ShareData message assignment is the same
    let rbc_msg = RBCNetworkMessage::Share(share);
    let rbc_msg_addresses = assignment_extractor
        .visit_network_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_addresses, addresses);

    // Non existing network chunk index
    let commitment_meta = CommitmentMeta::new(topology.get_chain_size(), vec![], [0; 32]);
    let share = ShareData::<TestSupraCodec>::new(
        *addresses_info.id(),
        value_data_with_header(Header::default()),
        commitment_meta,
    );
    let addresses = assignment_extractor.visit_share(&share);
    assert!(addresses.is_none());
}

#[test]
fn check_echo_share_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let broadcaster_info = topology.get_info_relative_to_current_node(11).unwrap();
    let header = header_with_origin(*broadcaster_info.id());
    let value_data = value_data_with_header::<TestSupraCodec>(header);
    let e_share = EchoShareData::new(*topology.origin(), value_data);
    let addresses = assignment_extractor.visit_echo_share(&e_share).unwrap();
    // all chain nodes, except broadcaster clan and current node
    assert_eq!(
        addresses.len(),
        topology.get_chain_size() - topology.get_committee_size() - 1
    );

    // RBC ShareData message sender is the same
    let rbc_msg = RBCNetworkMessage::EchoShare(e_share);
    let rbc_msg_addresses = assignment_extractor
        .visit_network_message(&rbc_msg)
        .unwrap();
    assert_eq!(rbc_msg_addresses, addresses);

    // Non existing origin of header returns nothing
    let invalid_sender = &EchoShareData::new([2; 32], get_value_data::<TestSupraCodec>());
    let addresses = assignment_extractor.visit_echo_share(&invalid_sender);
    assert!(addresses.is_none());
}

#[test]
#[should_panic]
fn check_composite_assignee() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    assignment_extractor.visit_composite(&[RBCCommitteeMessage::Value(value_data_with_header::<
        TestSupraCodec,
    >(Header::default()))]);
}

#[test]
fn check_assigned_chunk_by_index() {
    // Current node global index (0, 2, 2)
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    // all broadcasters from clan (0, 0) will result having the same chunk assigned to the current node.
    let broadcaster = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 0, 0))
        .unwrap();
    let result = assignment_extractor.assigned_chunk_index(broadcaster.id());
    let current_node_index = topology.get_flattened_index();
    // "tribes": 1,  "clans": 3,  "clan_size": 5,
    assert_eq!(current_node_index, (0 * 3 + 2) * 5 + 2);
    assert_eq!(current_node_index, result);

    let broadcaster = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 0, 2))
        .unwrap();
    let result = assignment_extractor.assigned_chunk_index(broadcaster.id());
    // "tribes": 1,  "clans": 3,  "clan_size": 5,
    assert_eq!(current_node_index, result);

    let broadcaster = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 0, 4))
        .unwrap();
    let result = assignment_extractor.assigned_chunk_index(broadcaster.id());
    assert_eq!(current_node_index, result);

    // broadcasters from clan (0, 1)
    let broadcaster = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 1, 3))
        .unwrap();
    let result = assignment_extractor.assigned_chunk_index(broadcaster.id());
    let expected_index = (topology.get_flattened_index() + 10) % topology.get_chain_size();
    // "tribes": 1,  "clans": 3,  "clan_size": 5,
    assert_eq!(expected_index, result);
}

#[test]
fn check_target_chunk_index() {
    // Current node global index (0, 2, 2)
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);
    let broadcaster = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 0, 0))
        .unwrap();

    // broadcaster is requester
    let requester_info = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 0, 0))
        .unwrap();
    let commitment_index =
        assignment_extractor.target_chunk_index(broadcaster.id(), requester_info.id());
    let flattened_index = assignment_extractor
        .assigned_target_index_by_commitment_index(broadcaster.id(), commitment_index);
    let peer_index = topology.get_peer_flattened_index(requester_info);
    assert_eq!(commitment_index, peer_index);
    assert_eq!(flattened_index, peer_index);

    let requester_info = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 0, 1))
        .unwrap();
    let commitment_index =
        assignment_extractor.target_chunk_index(broadcaster.id(), requester_info.id());
    let flattened_index = assignment_extractor
        .assigned_target_index_by_commitment_index(broadcaster.id(), commitment_index);
    let peer_index = topology.get_peer_flattened_index(requester_info);
    assert_eq!(commitment_index, peer_index);
    assert_eq!(flattened_index, peer_index);

    let requester_info = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 1, 0))
        .unwrap();
    let commitment_index =
        assignment_extractor.target_chunk_index(broadcaster.id(), requester_info.id());
    let flattened_index = assignment_extractor
        .assigned_target_index_by_commitment_index(broadcaster.id(), commitment_index);
    let peer_index = topology.get_peer_flattened_index(requester_info);
    assert_eq!(commitment_index, peer_index);
    assert_eq!(flattened_index, peer_index);

    let requester_info = topology
        .info_by_global_index(PeerGlobalIndex::new(0, 1, 1))
        .unwrap();
    let commitment_index =
        assignment_extractor.target_chunk_index(broadcaster.id(), requester_info.id());
    let flattened_index = assignment_extractor
        .assigned_target_index_by_commitment_index(broadcaster.id(), commitment_index);
    let peer_index = topology.get_peer_flattened_index(requester_info);
    assert_eq!(commitment_index, peer_index);
    assert_eq!(flattened_index, peer_index);
}

#[test]
#[should_panic]
fn panic_for_sync_req() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::default();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);
    let header = header_with_origin(*topology.origin());
    let sync = SyncRequest::new(header, QuorumCertificate::default());
    <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_sync_request(
        &assignment_extractor,
        &sync,
    );
}

#[tokio::test]
async fn check_assigned_for_pull_req() {
    let role = Role::Leader;
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, broadcaster_index);
    let broadcaster = resource_provider.get_resources(broadcaster_index);

    let commitment = [5; 32];
    let good_header = TestResources::generate_header(broadcaster.authenticator(), commitment);
    let good_committee = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    let good_network = resource_provider.get_resources(PeerGlobalIndex::new(0, 1, 1));
    let good_qc = resource_provider.generate_qc(
        broadcaster_index.clan_identifier(),
        good_header.commitment(),
    );

    // committee
    let sync = SyncRequest::new(good_header.clone(), good_qc.clone());
    let pull = PullRequest::new(good_committee.authenticator().origin(), sync);
    let dissemination_rule = DisseminationRule::default();
    let mut receiver = AssignmentExtractor::new(
        &good_committee.topology(),
        Protocol::XRBC,
        &dissemination_rule,
    );
    receiver.add_custom_filter(PeerFilterPredicate::NotWithFlattenedIndex(
        &[],
        good_committee.topology().get_tribe_size(),
        good_committee.topology().get_committee_size(),
    ));
    let result =
        <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_pull_request(&receiver, &pull);
    assert!(result.is_some());
    let address = result.unwrap();
    assert_eq!(address.len(), 4);

    // broadcaster
    let sync = SyncRequest::new(good_header.clone(), good_qc.clone());
    let pull = PullRequest::new(broadcaster.authenticator().origin(), sync);
    let dissemination_rule = DisseminationRule::default();

    let mut receiver =
        AssignmentExtractor::new(&broadcaster.topology(), Protocol::XRBC, &dissemination_rule);
    receiver.add_custom_filter(PeerFilterPredicate::NotWithFlattenedIndex(
        &[],
        broadcaster.topology().get_tribe_size(),
        broadcaster.topology().get_committee_size(),
    ));
    let result =
        <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_pull_request(&receiver, &pull);
    assert!(result.is_some());
    let address = result.unwrap();
    assert_eq!(address.len(), 4);

    // network
    let sync = SyncRequest::new(good_header.clone(), good_qc.clone());
    let pull = PullRequest::new(good_network.authenticator().origin(), sync);
    let dissemination_rule = DisseminationRule::default();

    let mut receiver = AssignmentExtractor::new(
        &good_network.topology(),
        Protocol::XRBC,
        &dissemination_rule,
    );
    receiver.add_custom_filter(PeerFilterPredicate::NotWithFlattenedIndex(
        &[],
        good_network.topology().get_tribe_size(),
        good_network.topology().get_committee_size(),
    ));
    let result =
        <AssignmentExtractor as Visitor<TestSupraCodec>>::visit_pull_request(&receiver, &pull);
    assert!(result.is_some());
    let address = result.unwrap();
    assert_eq!(address.len(), 14);
}

#[test]
fn test_position_order_rule() {
    let order = AssignmentExtractor::position_order_by_right_rule(4, 7);
    assert_eq!(vec![5, 6, 0, 1, 2, 3], order, "{:?}", order);
    let order = AssignmentExtractor::position_order_by_left_rule(4, 7);
    assert_eq!(vec![3, 2, 1, 0, 6, 5], order, "{:?}", order);
}

#[test]
fn test_echo_value_with_partial_dissemination_rule() {
    let topology = get_topology_for_leader_node_022();
    let dissemination_rule = DisseminationRule::Partial(EchoTarget::Right(3));
    let node_count = dissemination_rule.node_count().unwrap();

    let assignment_extractor =
        AssignmentExtractor::new(&topology, Protocol::XRBC, &dissemination_rule);

    let header = header_with_origin(*topology.origin());
    let e_value_data_0 =
        EchoValueData::new(value_data_with_header::<TestSupraCodec>(header.clone()));
    let addresses_0 = assignment_extractor
        .visit_echo_value(&e_value_data_0)
        .unwrap();
    assert_eq!(addresses_0.len(), node_count);
    assert!(!addresses_0.contains(&topology.current_node().get_address(Protocol::XRBC).unwrap()));
}
