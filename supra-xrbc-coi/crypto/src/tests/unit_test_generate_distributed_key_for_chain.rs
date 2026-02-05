#[test]
fn test_generate_distributed_key_for_chain() {
    use crate::dkg::config::DKGConfig;
    use crate::dkg::generate_distributed_key_for_chain;
    use primitives::PeerGlobalIndex;

    let dkg_config = DKGConfig::small_config();

    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let data = generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index);
    assert!(data.is_some());

    let peer_index = PeerGlobalIndex::new(0, 0, 5);
    let data = generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index);
    assert!(data.is_none());

    let peer_index = PeerGlobalIndex::new(1, 0, 0);
    let data = generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index);
    assert!(data.is_none());

    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let data = generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index);
    assert!(data.is_none());
}

#[test]
fn test_distributed_key_pair_interface() {
    use crate::dkg::config::DKGConfig;
    use crate::dkg::generate_distributed_key_for_chain;
    use crate::traits::DistributedKeyPairInterface;
    use crate::PartialShare;
    use primitives::PeerGlobalIndex;

    let dkg_config = DKGConfig::small_config();

    let peer_index = PeerGlobalIndex::new(0, 0, 3);
    let (_, dkey_pair) =
        generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index).unwrap();

    assert_eq!(dkg_config.threshold(), dkey_pair.threshold());

    let message_hash = [5; 32];
    let partial_share = dkey_pair
        .partial_signature(&message_hash)
        .expect("Valid partial signature");
    assert_eq!(partial_share.index(), peer_index.position() as u32);

    assert!(dkey_pair
        .verify_partial_signature(&partial_share, &message_hash)
        .is_ok());

    assert!(dkey_pair
        .verify_partial_signature(&partial_share, &[4; 32])
        .is_err());

    let random_share = PartialShare::new(1, [7; 96]);
    assert!(dkey_pair
        .verify_partial_signature(&random_share, &message_hash)
        .is_err());
}

#[test]
fn test_distributed_key_threshold_signature() {
    use crate::distributed_key::DistributedKeyPairError;
    use crate::dkg::config::DKGConfig;
    use crate::dkg::generate_distributed_key_for_chain;
    use crate::traits::DistributedKeyPairInterface;
    use crate::{DistributedKeyPair, PartialShare};
    use primitives::PeerGlobalIndex;

    let dkg_config = DKGConfig::small_config();

    let peer_index_003 = PeerGlobalIndex::new(0, 0, 3);
    let (_, dkey_pair_003) =
        generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index_003).unwrap();

    let peer_index_002 = PeerGlobalIndex::new(0, 0, 2);
    let (_, dkey_pair_002) =
        generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index_002).unwrap();

    let peer_index_004 = PeerGlobalIndex::new(0, 0, 4);
    let (_, dkey_pair_004) =
        generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index_004).unwrap();

    assert_eq!(dkg_config.threshold(), dkey_pair_002.threshold());

    assert!(matches!(
        dkey_pair_002.threshold_signature(vec![]),
        Err(DistributedKeyPairError::NotEnoughShares)
    ));

    let message_hash = [5; 32];
    let partial_share_002 = dkey_pair_002
        .partial_signature(&message_hash)
        .expect("Valid partial signature");

    let partial_share_003 = dkey_pair_003
        .partial_signature(&message_hash)
        .expect("Valid partial signature");

    let partial_share_004 = dkey_pair_004
        .partial_signature(&message_hash)
        .expect("Valid partial signature");

    assert!(matches!(
        dkey_pair_002.threshold_signature(vec![partial_share_003.clone()]),
        Err(DistributedKeyPairError::NotEnoughShares)
    ));

    let random_share = PartialShare::new(1, [7; 96]);
    let random_share_2 = PartialShare::new(2, [3; 96]);
    let result = dkey_pair_002.threshold_signature(vec![
        partial_share_003.clone(),
        random_share,
        random_share_2,
    ]);
    assert!(
        matches!(result, Err(DistributedKeyPairError::FromBlsttcError(_))),
        "{:?}",
        result
    );

    let threshold_signature = dkey_pair_002
        .threshold_signature(vec![
            partial_share_002,
            partial_share_003,
            partial_share_004,
        ])
        .expect("Valid threshold signature");

    assert!(dkey_pair_003
        .verify_threshold_signature(&threshold_signature, &message_hash)
        .is_ok());

    assert!(dkey_pair_003
        .verify_threshold_signature(&threshold_signature, &[8; 32])
        .is_err());

    assert!(dkey_pair_003
        .verify_threshold_signature(&[6; 96], &message_hash)
        .is_err());

    assert!(DistributedKeyPair::verify_threshold_signature_for_key(
        &dkey_pair_004.public_key(),
        &threshold_signature,
        &message_hash
    )
    .is_ok());

    assert!(DistributedKeyPair::verify_threshold_signature_for_key(
        &dkey_pair_002.public_key(),
        &[7; 96],
        &message_hash
    )
    .is_err());
}
