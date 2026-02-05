use crate::distributed_key::PartialShare;
use crate::dkg::config::DKGConfig;
use crate::dkg::generate_distributed_key_for_chain;
use crate::{Authenticator, NodeIdentity};
use primitives::PeerGlobalIndex;

pub mod unit_test_authenticator_module;
pub mod unit_test_generate_distributed_key_for_chain;
pub mod unit_test_node_identity;

pub fn give_test_authenticator(peer_index: PeerGlobalIndex) -> Authenticator {
    let node_identity = NodeIdentity::random();
    let dkg_config = DKGConfig::small_config();
    let data = generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index);
    assert!(data.is_some());
    let data = data.unwrap();
    let auth = Authenticator::new(node_identity, data.1, data.0);
    assert!(auth.threshold().eq(&dkg_config.threshold()));
    auth
}

fn get_initialized_test_auth_obj() -> (
    [u8; 32],
    [u8; 32],
    Vec<PartialShare>,
    Vec<PartialShare>,
    Vec<Authenticator>,
    Vec<PeerGlobalIndex>,
) {
    // message sample
    let message_0 = [0; 32];
    let message_1 = [1; 32];

    // peer_global_index
    let peer_index_0 = PeerGlobalIndex::new(0, 0, 0);
    let peer_index_1 = PeerGlobalIndex::new(0, 0, 1);
    let peer_index_2 = PeerGlobalIndex::new(0, 0, 2);
    let peer_index_3 = PeerGlobalIndex::new(0, 0, 3);
    let peer_index_4 = PeerGlobalIndex::new(0, 0, 4);

    // peer_index and authenticator
    let auth_0 = give_test_authenticator(peer_index_0);
    let auth_1 = give_test_authenticator(peer_index_1);
    let auth_2 = give_test_authenticator(peer_index_2);
    let auth_3 = give_test_authenticator(peer_index_3);
    let auth_4 = give_test_authenticator(peer_index_4);

    // partial signature of peer on message 0
    let partial_sig_0_0 = auth_0.partial_signature(&message_0);
    let partial_sig_0_1 = auth_1.partial_signature(&message_0);
    let partial_sig_0_2 = auth_2.partial_signature(&message_0);
    let partial_sig_0_3 = auth_3.partial_signature(&message_0);
    let partial_sig_0_4 = auth_4.partial_signature(&message_0);

    assert!(partial_sig_0_0.is_ok());
    assert!(partial_sig_0_1.is_ok());
    assert!(partial_sig_0_2.is_ok());
    assert!(partial_sig_0_3.is_ok());
    assert!(partial_sig_0_4.is_ok());

    let partial_sig_0_0 = partial_sig_0_0.unwrap();
    let partial_sig_0_1 = partial_sig_0_1.unwrap();
    let partial_sig_0_2 = partial_sig_0_2.unwrap();
    let partial_sig_0_3 = partial_sig_0_3.unwrap();
    let partial_sig_0_4 = partial_sig_0_4.unwrap();

    // partial signature of peer on message 1
    let partial_sig_1_0 = auth_0.partial_signature(&message_1).unwrap();
    let partial_sig_1_1 = auth_1.partial_signature(&message_1).unwrap();
    let partial_sig_1_2 = auth_2.partial_signature(&message_1).unwrap();
    let partial_sig_1_3 = auth_3.partial_signature(&message_1).unwrap();
    let partial_sig_1_4 = auth_4.partial_signature(&message_1).unwrap();

    // list of all partial share on message 0
    let all_share_0 = vec![
        partial_sig_0_0,
        partial_sig_0_1,
        partial_sig_0_2,
        partial_sig_0_3,
        partial_sig_0_4,
    ];

    // list of all partial share on message 1
    let all_share_1 = vec![
        partial_sig_1_0,
        partial_sig_1_1,
        partial_sig_1_2,
        partial_sig_1_3,
        partial_sig_1_4,
    ];

    // list of all auth obj
    let auth = vec![auth_0, auth_1, auth_2, auth_3, auth_4];

    // list of peer global index
    let peer_index = vec![
        peer_index_0,
        peer_index_1,
        peer_index_2,
        peer_index_3,
        peer_index_4,
    ];
    (
        message_0,
        message_1,
        all_share_0,
        all_share_1,
        auth,
        peer_index,
    )
}
