#[test]
fn test_new_authenticator_node_identity_interface() {
    use crate::tests::give_test_authenticator;
    use crate::Authenticator;
    use primitives::PeerGlobalIndex;

    let message_0 = "random message one";
    let message_1 = "random message two";
    let peer_index_0 = PeerGlobalIndex::new(0, 0, 0);
    let peer_index_1 = PeerGlobalIndex::new(0, 0, 1);

    let auth_0 = give_test_authenticator(peer_index_0);
    let auth_1 = give_test_authenticator(peer_index_1);
    assert!(auth_0.origin().eq(&auth_0.origin()));

    let sign_0 = auth_0.sign(message_0.as_bytes());
    assert!(sign_0.is_ok());
    let sign_0 = sign_0.unwrap();

    let sign_1 = auth_1.sign(message_1.as_bytes());
    let sign_1 = sign_1.unwrap();

    let verify = Authenticator::verify(&auth_0.origin(), &sign_0, message_1.as_bytes());
    assert!(verify.is_err());

    let verify = Authenticator::verify(&auth_0.origin(), &sign_1, message_0.as_bytes());
    assert!(verify.is_err());

    let verify = Authenticator::verify(&auth_1.origin(), &sign_0, message_0.as_bytes());
    assert!(verify.is_err());

    let verify = Authenticator::verify(&auth_1.origin(), &sign_1, message_1.as_bytes());
    assert!(verify.is_ok());
}

#[test]
fn test_new_authenticator_dkg_for_partial_signature_verification() {
    use crate::tests::get_initialized_test_auth_obj;

    let (message_0, message_1, all_share_0, _all_share_1, auth, _peer_index) =
        get_initialized_test_auth_obj();
    // PASS: auth_0 partial_sig_0_0 message_0
    let verify_partial = auth[0].verify_partial_signature(&all_share_0[0], &message_0);
    assert!(verify_partial.is_ok());

    // PASS: auth_0 partial_sig_0_1 message_0
    let verify_partial = auth[0].verify_partial_signature(&all_share_0[1], &message_0);
    assert!(verify_partial.is_ok());

    // PASS: auth_0 partial_sig_0_2 message_0
    let verify_partial = auth[0].verify_partial_signature(&all_share_0[2], &message_0);
    assert!(verify_partial.is_ok());

    // PASS: auth_3 partial_sig_0_0 message_0
    let verify_partial = auth[3].verify_partial_signature(&all_share_0[0], &message_0);
    assert!(verify_partial.is_ok());

    // FAIL: auth_0 partial_sig_0_0 message_1  :> partial signature on message 0 applied in message 1
    let verify_partial = auth[0].verify_partial_signature(&all_share_0[0], &message_1);
    assert!(verify_partial.is_err());
}

#[test]
fn test_new_authenticator_dkg_for_threshold_signature_generation() {
    use crate::tests::get_initialized_test_auth_obj;

    let (_message_0, _message_1, all_share_0, _all_share_1, auth, _peer_index) =
        get_initialized_test_auth_obj();

    // FAIL: auth_0        [all_share_0]  : Not enough share
    let threshold_sign = auth[0].threshold_signature(all_share_0[3..].to_vec());
    assert!(threshold_sign.is_err());

    // PASS: auth_0        [all_share_0, all_share_0]
    let threshold_sign = auth[0].threshold_signature(all_share_0[1..].to_vec());
    assert!(threshold_sign.is_ok());

    // PASS: auth_0        [all_share_0, all_share_0, all_share_0]
    let threshold_sign_0 = auth[0].threshold_signature(all_share_0[0..].to_vec());
    assert!(threshold_sign_0.is_ok());

    // PASS: auth_1        [all_share_0, all_share_0, all_share_0]
    let threshold_sign_1 = auth[1].threshold_signature(all_share_0[1..].to_vec());
    assert!(threshold_sign_1.is_ok());
}

#[test]
fn test_new_authenticator_dkg_for_threshold_signature_verification() {
    use crate::tests::get_initialized_test_auth_obj;

    let (message_0, message_1, all_share_0, all_share_1, auth, peer_index) =
        get_initialized_test_auth_obj();

    // PASS: auth_0        [all_share_0, all_share_0, all_share_0]
    let threshold_sign_0 = auth[0].threshold_signature(all_share_0[1..].to_vec());
    assert!(threshold_sign_0.is_ok());

    // PASS: auth_1        [all_share_0, all_share_0, all_share_0]
    let threshold_sign_1 = auth[1].threshold_signature(all_share_0[1..].to_vec());
    assert!(threshold_sign_1.is_ok());

    // duplicate share will fail
    let all_share_2 = vec![all_share_1[1].clone(), all_share_1[1].clone()];
    let threshold_sign_2 = auth[1].threshold_signature(all_share_2);
    assert!(threshold_sign_2.is_err());

    // partial sig for different message can be combined but is not usable to verify any message
    let all_share_3 = vec![
        all_share_0[2].clone(),
        all_share_1[2].clone(),
        all_share_1[3].clone(),
    ];
    let threshold_sign_3 = auth[1].threshold_signature(all_share_3);
    assert!(threshold_sign_3.is_ok());

    // threshold signature
    let threshold_sign_0 = threshold_sign_0.unwrap();
    let threshold_sign_1 = threshold_sign_1.unwrap();
    let threshold_sign_3 = threshold_sign_3.unwrap();

    // PASS: peer_index_0  auth_0  threshold_sign_0  message_0
    let verify = auth[0].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_0,
        &message_0,
    );
    assert!(verify.is_ok());

    // PASS: peer_index_0  auth_1  threshold_sign_0  message_0
    let verify = auth[1].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_0,
        &message_0,
    );
    assert!(verify.is_ok());

    // PASS: peer_index_1  auth_0  threshold_sign_0  message_0
    let verify = auth[0].verify_threshold_signature(
        &peer_index[1].clan_identifier(),
        &threshold_sign_0,
        &message_0,
    );
    assert!(verify.is_ok());

    // PASS: peer_index_0  auth_0  threshold_sign_1  message_0
    let verify = auth[0].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_1,
        &message_0,
    );
    assert!(verify.is_ok());

    // PASS: peer_index_0  auth_0  threshold_sign_0  message_1 :> InvalidThresholdSignature
    let verify = auth[0].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_0,
        &message_1,
    );
    assert!(verify.is_err());

    // threshold_sign_3 is not useful
    let verify = auth[1].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_3,
        &message_0,
    );
    assert!(verify.is_err());

    // threshold_sign_3 is not useful
    let verify = auth[1].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_3,
        &message_1,
    );
    assert!(verify.is_err());

    // threshold_sign_3 is not useful
    let verify = auth[0].verify_threshold_signature(
        &peer_index[0].clan_identifier(),
        &threshold_sign_3,
        &message_1,
    );
    assert!(verify.is_err());
}
