use crate::types::helpers::sender_extractor::SenderExtractor;
use crate::types::helpers::Visitor;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCCommitteeMessage, RBCNetworkMessage, VoteData,
};
use crate::types::tests::{
    certificate_data, get_value_data, header_with_origin, partial_share, ready_data, share_data,
    value_data_with_header, value_data_with_header_idx, TestSupraCodec,
};
use primitives::types::Header;

use crate::types::messages::payload_data::PayloadData;
use network::topology::config::NetworkConfig;
use network::topology::peer_info::Role;
use network::topology::tests::TopologyGenerator;
use network::topology::ChainTopology;
use primitives::types::QuorumCertificate;
use primitives::{ClanIdentifier, PeerGlobalIndex};

const NETWORK_CONFIG_JSON: &'static str = r#"
{
    "tribes": 1,
    "clans": 3,
    "clan_size": 5,
    "proposers_per_tribe": 1,
    "proposers_per_clan": 1
}
"#;

fn get_topology_for_leader_node() -> ChainTopology {
    let role = Role::Leader;
    let _clan_identifier = ClanIdentifier::new(0, 0);
    let config: NetworkConfig =
        serde_json::from_str(NETWORK_CONFIG_JSON).expect("Valid NetworkConfig");
    let (topology, _) =
        TopologyGenerator::generate_random_topology(role, PeerGlobalIndex::new(0, 0, 0), &config);
    topology
}

#[test]
fn check_payload_data_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let payload_data = PayloadData::new(header.clone(), vec![10; 25]);
    let sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_payload(
        &sender_extractor,
        &payload_data,
    );
    assert!(sender.is_some());
    assert_eq!(sender.unwrap(), topology.current_node());

    let header = header_with_origin(*topology.peer_by_position(2).unwrap().id());
    let payload_data = PayloadData::new(header.clone(), vec![10; 25]);
    let sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_payload(
        &sender_extractor,
        &payload_data,
    );
    assert!(sender.is_some());
    assert_eq!(sender.unwrap(), topology.peer_by_position(2).unwrap());

    // Unknown origin no sender
    let header = header_with_origin([0; 32]);
    let payload_data = PayloadData::new(header.clone(), vec![10; 25]);
    let sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_payload(
        &sender_extractor,
        &payload_data,
    );
    assert!(sender.is_none());
}

#[test]
fn check_value_data_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let value_data_0 = value_data_with_header::<TestSupraCodec>(header.clone());
    let sender_0 = sender_extractor.visit_value(&value_data_0);
    assert!(sender_0.is_some());
    assert_eq!(sender_0.unwrap(), topology.current_node());

    // for value data data index does not play role
    let value_data_2 = value_data_with_header_idx::<TestSupraCodec>(header.clone(), 2);
    let sender_2 = sender_extractor.visit_value(&value_data_2);
    assert_eq!(sender_0, sender_2);

    // RBC Value message sender is the same
    let rbc_msg = RBCCommitteeMessage::Value(value_data_2);
    let rbc_msg_sender = sender_extractor.visit_committee_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_0);

    // Non existing origin of header returns nothing
    let sender = sender_extractor.visit_value(&get_value_data::<TestSupraCodec>());
    assert!(sender.is_none());
}

#[test]
fn check_echo_data_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let e_value_data_0 =
        EchoValueData::new(value_data_with_header::<TestSupraCodec>(header.clone()));
    let sender_0 = sender_extractor.visit_echo_value(&e_value_data_0);
    assert!(sender_0.is_some());
    assert_eq!(sender_0.unwrap(), topology.current_node());

    // for echo value data data index does play role
    let e_value_data_2 = EchoValueData::new(value_data_with_header_idx::<TestSupraCodec>(
        header.clone(),
        2,
    ));
    let sender_2 = sender_extractor.visit_echo_value(&e_value_data_2);
    assert_ne!(sender_0, sender_2);
    assert_eq!(sender_2, topology.peer_by_position(2));

    // RBC EchoValue message sender is the same
    let rbc_msg = RBCCommitteeMessage::EchoValue(e_value_data_2);
    let rbc_msg_sender = sender_extractor.visit_committee_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_2);

    // Non existing peer by index
    let invalid_index = EchoValueData::new(value_data_with_header_idx::<TestSupraCodec>(
        header.clone(),
        5,
    ));
    let sender = sender_extractor.visit_echo_value(&invalid_index);
    assert!(sender.is_none());
}

#[test]
fn check_vote_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let vote_0 = VoteData::new(header.clone(), partial_share(0));
    let sender_0 =
        <SenderExtractor as Visitor<TestSupraCodec>>::visit_vote(&sender_extractor, &vote_0);
    assert!(sender_0.is_some());
    assert_eq!(sender_0.unwrap(), topology.current_node());

    // for echo value data data index does play role
    let vote_2 = VoteData::new(header, partial_share(2));
    let sender_2 =
        <SenderExtractor as Visitor<TestSupraCodec>>::visit_vote(&sender_extractor, &vote_2);
    assert_ne!(sender_0, sender_2);
    assert_eq!(sender_2, topology.peer_by_position(2));

    // for vote header does not play role in sender deduction
    let other_vote_2 = VoteData::new(header_with_origin([2; 32]), partial_share(2));
    let sender =
        <SenderExtractor as Visitor<TestSupraCodec>>::visit_vote(&sender_extractor, &other_vote_2);
    assert_eq!(sender, sender_2);

    // RBC Vote message sender is the same
    let rbc_msg = RBCCommitteeMessage::<TestSupraCodec>::Vote(vote_2);
    let rbc_msg_sender = sender_extractor.visit_committee_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_2);

    // Non existing index
    let invalid_index = VoteData::new(Header::default(), partial_share(5));
    let sender =
        <SenderExtractor as Visitor<TestSupraCodec>>::visit_vote(&sender_extractor, &invalid_index);
    assert!(sender.is_none());
}

#[test]
fn check_certificate_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let certificate = certificate_data(header);
    let sender_0 = <SenderExtractor as Visitor<TestSupraCodec>>::visit_certificate(
        &sender_extractor,
        &certificate,
    );
    assert!(sender_0.is_some());
    assert_eq!(sender_0.unwrap(), topology.current_node());

    // for value data data index does not play role
    let header_2 = header_with_origin(*topology.peer_by_position(2).unwrap().id());
    let certificate_2 = certificate_data(header_2);
    let sender_2 = <SenderExtractor as Visitor<TestSupraCodec>>::visit_certificate(
        &sender_extractor,
        &certificate_2,
    );
    assert!(sender_2.is_some());
    assert_ne!(sender_0, sender_2);

    // RBC Certificate message sender is the same
    let rbc_msg = RBCCommitteeMessage::<TestSupraCodec>::Certificate(certificate_2);
    let rbc_msg_sender = sender_extractor.visit_committee_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_2);

    // Non existing origin of header returns nothing
    let sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_certificate(
        &sender_extractor,
        &certificate_data(Header::default()),
    );
    assert!(sender.is_none());
}

#[test]
fn check_ready_data_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let sender_info = topology.peer_by_position(1);
    let value_data = value_data_with_header::<TestSupraCodec>(header);
    let ready = ready_data(*sender_info.unwrap().id(), value_data);
    let sender = sender_extractor.visit_ready(&ready);
    assert!(sender.is_some());
    assert_eq!(sender, sender_info);

    // RBC ReadyData message sender is the same
    let rbc_msg = RBCCommitteeMessage::Ready(ready);
    let rbc_msg_sender = sender_extractor.visit_committee_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_info);

    // Non existing origin of header returns nothing
    let sender =
        sender_extractor.visit_ready(&ready_data::<TestSupraCodec>([1; 32], get_value_data()));
    assert!(sender.is_none());
}

#[test]
fn check_echo_ready_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let ready_sender = topology.peer_by_position(1);
    let e_ready_data_0 = EchoReadyData::new(ready_data(
        *ready_sender.unwrap().id(),
        value_data_with_header::<TestSupraCodec>(header.clone()),
    ));
    let sender_0 = sender_extractor.visit_echo_ready(&e_ready_data_0);
    assert!(sender_0.is_some());
    assert_eq!(sender_0.unwrap(), topology.current_node());

    // for echo value data data index does play role
    let e_ready_data_2 = EchoReadyData::new(ready_data(
        *ready_sender.unwrap().id(),
        value_data_with_header_idx::<TestSupraCodec>(header.clone(), 2),
    ));
    let sender_2 = sender_extractor.visit_echo_ready(&e_ready_data_2);
    assert_ne!(sender_0, sender_2);
    assert_eq!(sender_2, topology.peer_by_position(2));

    // RBC EchoValue message sender is the same
    let rbc_msg = RBCCommitteeMessage::EchoReady(e_ready_data_2);
    let rbc_msg_sender = sender_extractor.visit_committee_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_2);

    // Non existing peer by index
    let invalid_index = EchoReadyData::new(ready_data(
        *ready_sender.unwrap().id(),
        value_data_with_header_idx::<TestSupraCodec>(header.clone(), 5),
    ));
    let sender = sender_extractor.visit_echo_ready(&invalid_index);
    assert!(sender.is_none());
}

#[test]
fn check_share_data_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let sender_info = topology.peer_by_position(1);
    let value_data = value_data_with_header::<TestSupraCodec>(header);
    let share = share_data(*sender_info.unwrap().id(), value_data);
    let sender = sender_extractor.visit_share(&share);
    assert!(sender.is_some());
    assert_eq!(sender, sender_info);

    // RBC ShareData message sender is the same
    let rbc_msg = RBCNetworkMessage::Share(share);
    let rbc_msg_sender = sender_extractor.visit_network_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_info);

    // Non existing origin of header returns nothing
    let sender =
        sender_extractor.visit_share(&share_data::<TestSupraCodec>([1; 32], get_value_data()));
    assert!(sender.is_none());
}

#[test]
fn check_echo_share_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let header = header_with_origin(*topology.origin());
    let sender_info = topology.peer_by_position(1);
    let value_data = value_data_with_header::<TestSupraCodec>(header);
    let e_share = EchoShareData::new(*sender_info.unwrap().id(), value_data);
    let sender = sender_extractor.visit_echo_share(&e_share);
    assert!(sender.is_some());
    assert_eq!(sender, sender_info);

    // RBC ShareData message sender is the same
    let rbc_msg = RBCNetworkMessage::EchoShare(e_share);
    let rbc_msg_sender = sender_extractor.visit_network_message(&rbc_msg);
    assert_eq!(rbc_msg_sender, sender_info);

    // Non existing origin of header returns nothing
    let invalid_sender = &EchoShareData::new([2; 32], get_value_data::<TestSupraCodec>());
    let sender = sender_extractor.visit_echo_share(&invalid_sender);
    assert!(sender.is_none());
}

#[test]
fn check_composite_sender() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);

    let empty_composite: Vec<RBCCommitteeMessage<TestSupraCodec>> = vec![];
    let result = sender_extractor.visit_composite(&empty_composite);
    assert!(result.is_none());

    // Composite with the same senders
    let header = header_with_origin(*topology.origin());
    let value = value_data_with_header_idx::<TestSupraCodec>(header.clone(), 1);
    let e_value = EchoValueData::new(value_data_with_header::<TestSupraCodec>(header));
    let composite = vec![
        RBCCommitteeMessage::Value(value),
        RBCCommitteeMessage::EchoValue(e_value),
    ];
    let result = sender_extractor.visit_composite(&composite);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), topology.current_node());

    // Composite with the different senders
    let header = header_with_origin(*topology.origin());
    let header_2 = header_with_origin(*topology.peer_by_position(1).unwrap().id());
    let value = value_data_with_header_idx::<TestSupraCodec>(header_2, 1);
    let e_value = EchoValueData::new(value_data_with_header::<TestSupraCodec>(header));
    let composite = vec![
        RBCCommitteeMessage::Value(value),
        RBCCommitteeMessage::EchoValue(e_value),
    ];
    let result = sender_extractor.visit_composite(&composite);
    assert!(result.is_none());
}

#[test]
fn check_sync_request_senders() {
    let topology = get_topology_for_leader_node();
    let sender_extractor = SenderExtractor::new(&topology);
    let sync_data = SyncRequest::new(Header::default(), QuorumCertificate::default());
    let sync_sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_sync_request(
        &sender_extractor,
        &sync_data,
    );
    assert!(sync_sender.is_some());
    assert_eq!(sync_sender.unwrap(), topology.current_node());

    let invalid_pull_request = PullRequest::new([0; 32], sync_data.clone());
    let pull_sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_pull_request(
        &sender_extractor,
        &invalid_pull_request,
    );
    assert!(pull_sender.is_none());

    let pull_request = PullRequest::new(
        topology.peer_by_position(2).unwrap().id().clone(),
        sync_data.clone(),
    );
    let pull_sender = <SenderExtractor as Visitor<TestSupraCodec>>::visit_pull_request(
        &sender_extractor,
        &pull_request,
    );
    assert!(pull_sender.is_some());
}
