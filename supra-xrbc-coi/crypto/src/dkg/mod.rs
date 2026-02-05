pub mod config;

use crate::dkg::config::DKGConfig;
use crate::DistributedKeyPair;
use blsttc::rand::rngs::StdRng;
use blsttc::rand::SeedableRng;
use blsttc::SecretKeySet;
use primitives::{ClanIdentifier, ClanOrigin, PeerGlobalIndex};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;

const MIN_THRESHOLD: usize = 2;

pub fn generate_distributed_key_for_chain(
    number_of_tribes: usize,
    number_of_clans_in_tribe: usize,
    dkg_config: &DKGConfig,
    peer_index: &PeerGlobalIndex,
) -> Option<(HashMap<ClanIdentifier, ClanOrigin>, DistributedKeyPair)> {
    if peer_index.position() >= dkg_config.participants() {
        return None;
    }

    if dkg_config.threshold() < MIN_THRESHOLD {
        return None;
    }

    let mut clan_identities: HashMap<ClanIdentifier, ClanOrigin> = HashMap::new();
    let mut peer_secret_key_set = None;

    for t in 0..number_of_tribes {
        for c in 0..number_of_clans_in_tribe {
            let secrete_key_set = generate_distributed_key_set(t, c, dkg_config);
            let public_key_set = secrete_key_set.public_keys();
            let clan_public_key = public_key_set.public_key();
            let clan_origin = clan_public_key.to_bytes() as ClanOrigin;
            let clan_identifier = ClanIdentifier { tribe: t, clan: c };
            if clan_identifier.eq(&peer_index.clan_identifier()) {
                peer_secret_key_set = Some(secrete_key_set.clone());
            }
            clan_identities.insert(clan_identifier, clan_origin);
        }
    }
    peer_secret_key_set.map(|peer_secret_key_set| {
        (
            clan_identities,
            get_distributed_key_pair(
                peer_secret_key_set,
                peer_index.position(),
                dkg_config.threshold(),
            ),
        )
    })
}

pub fn generate_distributed_key_set(
    tribe_id: usize,
    clan_id: usize,
    dkg_config: &DKGConfig,
) -> SecretKeySet {
    let seed = format!("{}-{}-{}", tribe_id, clan_id, dkg_config.threshold());
    let mut hasher = DefaultHasher::new();
    let str_bytes = seed.as_bytes();
    str_bytes.iter().for_each(|s| hasher.write_u8(*s));
    let det_num = hasher.finish();
    let mut rng = StdRng::seed_from_u64(det_num);
    SecretKeySet::random(dkg_config.threshold() - 1, &mut rng)
}

pub fn get_distributed_key_pair(
    secrete_key_set: SecretKeySet,
    node_position: usize,
    threshold: usize,
) -> DistributedKeyPair {
    let clan_public_set = secrete_key_set.public_keys();
    let secret_share = secrete_key_set.secret_key_share(node_position);
    DistributedKeyPair::new(
        threshold,
        node_position as u32,
        secret_share,
        clan_public_set,
    )
}

pub fn generate_distributed_key_pair(
    peer_index: PeerGlobalIndex,
    dkg_config: &DKGConfig,
) -> DistributedKeyPair {
    let set = generate_distributed_key_set(peer_index.tribe(), peer_index.clan(), dkg_config);
    get_distributed_key_pair(set, peer_index.position(), dkg_config.threshold())
}
