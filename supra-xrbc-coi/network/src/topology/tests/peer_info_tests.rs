use crate::topology::peer_info::{PeerInfo, Role};
use crypto::traits::NodeIdentityInterface;
use crypto::NodeIdentity;
use primitives::Protocol;

#[test]
fn check_peer_info_validity() {
    let identity = NodeIdentity::random();
    let valid_info = PeerInfo {
        id: identity.public_key(),
        address: "127.0.0.1".to_string(),
        ports: vec![1025, 1026],
        position: 0,
        clan: 0,
        tribe: 0,
        role: Role::Leader,
    };
    assert!(valid_info.validate().is_ok());
    let invalid_address = PeerInfo {
        address: "test.com".to_string(),
        ..valid_info.clone()
    };
    assert!(invalid_address.validate().is_err());
    let invalid_port = PeerInfo {
        ports: vec![125, 1026],
        ..valid_info.clone()
    };
    assert!(invalid_port.validate().is_err(), "{}", invalid_port);

    let invalid_port = PeerInfo {
        ports: vec![1026, 1026],
        ..valid_info.clone()
    };
    assert!(invalid_port.validate().is_err());

    let invalid_position = PeerInfo {
        position: usize::MAX,
        ..valid_info.clone()
    };
    assert!(invalid_position.validate().is_err());

    let invalid_clan = PeerInfo {
        clan: usize::MAX,
        ..valid_info.clone()
    };
    assert!(invalid_clan.validate().is_err());

    let invalid_tribe = PeerInfo {
        tribe: usize::MAX,
        ..valid_info
    };
    assert!(invalid_tribe.validate().is_err());

    let new_peer = PeerInfo::new([4; 32]);
    assert!(new_peer.validate().is_err())
}

#[test]
fn check_peer_info_set_get_interfaces() {
    let identity = NodeIdentity::random();
    let mut valid_info = PeerInfo {
        id: [0; 32],
        address: "".to_string(),
        ports: vec![1025, 2026],
        position: 0,
        clan: 0,
        tribe: 0,
        role: Role::Leader,
    };
    valid_info.set_id(identity.public_key());
    assert_eq!(valid_info.id(), &identity.public_key());

    valid_info.set_port(Protocol::XRBC, 1055);
    assert_eq!(valid_info.port(Protocol::XRBC), 1055);

    valid_info.set_port(Protocol::COI, 1056);
    assert_eq!(valid_info.port(Protocol::XRBC), 1055);
    assert_eq!(valid_info.port(Protocol::COI), 1056);

    valid_info.set_address("127.0.0.1".to_string());
    assert!(valid_info.get_address(Protocol::XRBC).is_some());
    let address = valid_info.get_address(Protocol::XRBC).unwrap();
    assert_eq!(address.ip().to_string(), "127.0.0.1".to_string());
    assert_eq!(address.port(), 1055);

    assert!(valid_info.get_address(Protocol::COI).is_some());
    let address = valid_info.get_address(Protocol::COI).unwrap();
    assert_eq!(address.ip().to_string(), "127.0.0.1".to_string());
    assert_eq!(address.port(), 1056);

    let address = valid_info.get_address(Protocol::XRBC).unwrap();
    assert_eq!(address.port(), 1055);

    valid_info.set_position(10);
    assert_eq!(valid_info.position(), 10);

    valid_info.set_clan(11);
    assert_eq!(valid_info.clan(), 11);

    valid_info.set_tribe(1);
    assert_eq!(valid_info.tribe(), 1);

    valid_info.set_role(Role::Basic);
    assert_eq!(valid_info.role(), &Role::Basic);
}

#[test]
fn check_peer_is_proposer() {
    let mut valid_info = PeerInfo {
        id: [0; 32],
        address: "".to_string(),
        ports: vec![1025, 2026],
        position: 0,
        clan: 0,
        tribe: 0,
        role: Role::Leader,
    };
    assert!(valid_info.is_proposer());

    valid_info.set_role(Role::Basic);
    assert!(!valid_info.is_proposer());
}

#[test]
fn check_from_same_clan() {
    let peer1 = PeerInfo {
        id: [1; 32],
        address: "".to_string(),
        ports: vec![1025, 2026],
        position: 1,
        clan: 2,
        tribe: 3,
        role: Role::Leader,
    };
    let peer2 = PeerInfo {
        id: [1; 32],
        address: "".to_string(),
        ports: vec![1025, 2026],
        position: 2,
        clan: 2,
        tribe: 3,
        role: Role::Leader,
    };

    assert!(peer1.is_from_same_clan(&peer2));

    let peer3 = PeerInfo {
        clan: 3,
        ..peer2.clone()
    };
    assert!(!peer1.is_from_same_clan(&peer3));

    let peer4 = PeerInfo { tribe: 2, ..peer2 };
    assert!(!peer1.is_from_same_clan(&peer4));
}

#[test]
fn check_indexes() {
    let peer = PeerInfo {
        id: [1; 32],
        address: "".to_string(),
        ports: vec![1025, 2026],
        position: 1,
        clan: 2,
        tribe: 3,
        role: Role::Leader,
    };
    let clan_identifier = peer.clan_identifier();
    assert_eq!(clan_identifier.tribe, 3);
    assert_eq!(clan_identifier.clan, 2);

    let global_index = peer.global_index();
    assert_eq!(clan_identifier, global_index.clan_identifier());
    assert_eq!(global_index.position(), 1);
}
