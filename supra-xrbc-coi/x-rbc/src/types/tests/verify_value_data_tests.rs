use crate::tasks::codec::{
    EncodeResult, EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec,
};
use crate::types::context::{Resources, ResourcesApi};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::{ValueData, VoteData};
use crate::types::tests::{header_with_origin, value_data_with_header_idx};
use crate::SupraDeliveryErasureRs8Schema;
use crypto::dkg::config::DKGConfig;
use crypto::dkg::{
    generate_distributed_key_for_chain, generate_distributed_key_pair,
    generate_distributed_key_set, get_distributed_key_pair,
};
use crypto::traits::DistributedKeyPairInterface;
use crypto::{Authenticator, PartialShare};
use erasure::codecs::rs8::Rs8Settings;
use erasure::utils::codec_trait::Setting;
use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;

use crate::tasks::config::DisseminationRule;
use crate::types::messages::chunk::ChunkData;
use metrics::TimeStampTrait;
use network::topology::config::NetworkConfig;
use network::topology::peer_info::Role;
use network::topology::tests::TopologyGenerator;
use primitives::{ClanIdentifier, ClanOrigin, Origin, PeerGlobalIndex, HASH32};
use rand::Rng;
use std::collections::{BTreeSet, HashMap};
use std::panic::Location;
use std::time::Duration;
use storage::config::StorageConfig;
use storage::rocksdb_store::RocksDBEngine;
use storage::EngineFactory;

const NETWORK_CONFIG_JSON: &'static str = r#"
{
    "tribes": 1,
    "clans": 3,
    "clan_size": 5,
    "proposers_per_tribe": 1,
    "proposers_per_clan": 1
}
"#;

const DKG_CONFIG_JSON: &'static str = r#"
{
    "threshold": 3,
    "participants": 5
}
"#;

pub(crate) const RANDOM_PAYLOAD_SIZE: usize = 10000;

pub(crate) fn rs8_codec() -> SupraDeliveryCodec<SupraDeliveryErasureRs8Schema> {
    SupraDeliveryCodec::new(Rs8Settings::new(3, 2), Some(Rs8Settings::new(7, 3)))
}

pub(crate) fn payload(seed: u8) -> Vec<u8> {
    vec![seed; RANDOM_PAYLOAD_SIZE]
}

pub(crate) struct TestResources {
    topology_generator: TopologyGenerator,
    clans: HashMap<ClanIdentifier, ClanOrigin>,
    dkg_config: DKGConfig,
    committee_settings: (usize, usize),
    network_settings: (usize, usize),
    db_path: Vec<String>,
}

impl Drop for TestResources {
    fn drop(&mut self) {
        self.db_path.iter().for_each(|path| {
            let db_path = "db/".to_string() + &path;
            let _ = std::fs::remove_dir_all(db_path);
        });
    }
}

impl TestResources {
    ///
    /// Creates topology and authenticator resources for the small configuration:
    ///
    /// Network: {
    ///     "tribes": 1,
    ///     "clans": 3,
    ///     "clan_size": 5,
    ///     "proposers_per_tribe": 1,
    ///     "proposers_per_clan": 1
    /// }
    ///
    /// DKG: {
    ///     "threshold": 3,
    ///     "participants": 5
    /// }
    ///
    ///
    pub(crate) fn new(role: Role, global_index: PeerGlobalIndex) -> Self {
        let config: NetworkConfig =
            serde_json::from_str(NETWORK_CONFIG_JSON).expect("Valid NetworkConfig");
        let dkg_config: DKGConfig = serde_json::from_str(DKG_CONFIG_JSON).expect("Valid DKGConfig");
        let (clans, _) = generate_distributed_key_for_chain(
            config.tribes(),
            config.clans(),
            &dkg_config,
            &global_index,
        )
        .expect("Valid Chain Distributed Keys");
        let mut resources = Self {
            committee_settings: (
                dkg_config.threshold(),
                dkg_config.participants() - dkg_config.threshold(),
            ),
            network_settings: (
                config.total_nodes() - config.clan_size() - dkg_config.threshold(),
                dkg_config.threshold(),
            ),
            topology_generator: TopologyGenerator::new(role, global_index, config),
            clans,
            dkg_config,
            db_path: vec![],
        };
        resources.topology_generator.run();
        resources
    }

    pub(crate) fn get_resources(&mut self, global_index: PeerGlobalIndex) -> Resources {
        self.get_resources_with_rule(global_index, DisseminationRule::default())
    }

    #[track_caller]
    pub(crate) fn get_resources_with_rule(
        &mut self,
        global_index: PeerGlobalIndex,
        rule: DisseminationRule,
    ) -> Resources {
        let (topology, identity) = self.topology_generator.topology_for_peer(global_index);
        let distributed_key = generate_distributed_key_pair(global_index, &self.dkg_config);
        let authenticator = Authenticator::new(identity, distributed_key, self.clans.clone());
        let mut rng = rand::thread_rng();
        let identifier: u32 = rng.gen();
        let caller = Location::caller();
        let db_path = format!(
            "{}{}-{}-{}",
            caller.file(),
            caller.line(),
            caller.column(),
            identifier
        );
        self.db_path.push(db_path.clone());
        let storage_config = StorageConfig::<RocksDBEngine>::new(db_path).unwrap();
        let storage_client = EngineFactory::get_client(&storage_config).unwrap();
        Resources::new(topology, authenticator, storage_client, rule)
    }

    pub(crate) fn get_broadcaster_resources(&mut self) -> Resources {
        let index = self.topology_generator.get_broadcaster_index();
        self.get_resources(index)
    }

    pub(crate) fn generate_qc(
        &self,
        clan_identifier: ClanIdentifier,
        msg: &HASH32,
    ) -> QuorumCertificate {
        let secrete_key = generate_distributed_key_set(
            clan_identifier.tribe,
            clan_identifier.clan,
            &self.dkg_config,
        );

        let dk = get_distributed_key_pair(secrete_key.clone(), 0, self.dkg_config.threshold());
        let mut shares = vec![dk.partial_signature(msg).expect("Valid share")];
        let mut participants = BTreeSet::from([0]);
        for i in 1..self.dkg_config.threshold() {
            let dk = get_distributed_key_pair(secrete_key.clone(), i, self.dkg_config.threshold());
            let share = dk.partial_signature(msg).expect("Valid partial share");
            participants.insert(share.index());
            shares.push(share);
        }
        QuorumCertificate::new(
            dk.threshold_signature(shares)
                .expect("Valid threshold signature"),
            participants,
        )
    }

    pub(crate) fn generate_votes(
        &self,
        clan_identifier: ClanIdentifier,
        header: &Header,
    ) -> Vec<VoteData> {
        self.generate_shares(clan_identifier, header)
            .into_iter()
            .map(|share| VoteData::new(header.clone(), share))
            .collect()
    }

    pub(crate) fn generate_shares(
        &self,
        clan_identifier: ClanIdentifier,
        header: &Header,
    ) -> Vec<PartialShare> {
        let secrete_key = generate_distributed_key_set(
            clan_identifier.tribe,
            clan_identifier.clan,
            &self.dkg_config,
        );

        let mut shares = vec![];
        for i in 0..self.dkg_config.participants() {
            let dk = get_distributed_key_pair(secrete_key.clone(), i, self.dkg_config.threshold());
            let share = dk
                .partial_signature(header.commitment())
                .expect("Valid partial share");
            shares.push(share);
        }
        shares
    }

    pub(crate) fn generate_header(auth: &Authenticator, msg: HASH32) -> Header {
        let id = auth.sign(&msg).expect("Valid signature");
        Header::new(id, auth.origin(), msg)
    }

    pub(crate) fn get_origin(&self, peer_index: &PeerGlobalIndex) -> Origin {
        self.topology_generator.get_origin(peer_index)
    }

    pub(crate) fn committee_settings(&self) -> (usize, usize) {
        self.committee_settings
    }

    pub(crate) fn network_settings(&self) -> (usize, usize) {
        self.network_settings
    }
}

pub(crate) fn encoded_chunks(
    seed: u8,
    auth: &Authenticator,
) -> EncodeResult<SupraDeliveryErasureRs8Schema> {
    rs8_codec()
        .encode(payload(seed), auth)
        .expect("Successful encode")
}

///
/// chunk_owner.id != value_data.origin
/// chunk_owner.IsFromSameClan(Res.GetPeerInfo(value_data.origin))
/// value_data.committed_chunk.chunk_index() == chunk_owner.position
/// Res.IsBroadcaster(value_data.origin)
/// Res.VerifySignature(value_data.commitment, value_data.id, value_data.origin) // header
/// value_data.committed_chunk.verifyProof(value_data.commitment)
///

#[tokio::test]
async fn verify_value_data_with_invalid_owner_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let value_data = ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[0].clone(),
    );

    // Resources for peer (0, 0, 0) and value data for node 0
    let verifier = VerifierVisitor::new(&resources);
    let result = verifier.visit_value(&value_data);
    assert!(result.is_err());

    // Resources for peer (0, 0, 1) and value data for node 0
    let resources = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    let verifier = VerifierVisitor::new(&resources);
    let result = verifier.visit_value(&value_data);
    assert!(result.is_err());

    // Resources for peer (0, 1, 0) and value data for node from clan (0, 0)
    let resources = resource_provider.get_resources(PeerGlobalIndex::new(0, 1, 0));
    let verifier = VerifierVisitor::new(&resources);
    let result = verifier.visit_value(&value_data);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_value_data_with_invalid_header() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let header = header_with_origin(*encoded_data.header().origin());
    let value_data = ValueData::new(header, encoded_data.committee_chunks()[1].clone());

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Resources for peer (0, 0, 1) and value data for node 1
    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_value(&value_data);
    assert!(result.is_err());

    // Valid chunk header but not from proposer
    let header = TestResources::generate_header(
        resources_001.authenticator(),
        *encoded_data.header().commitment(),
    );
    let value_data = ValueData::new(header, encoded_data.committee_chunks()[1].clone());

    let result = verifier.visit_value(&value_data);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_value_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        encoded_data.header().clone(),
        1,
    );

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Resources for peer (0, 0, 1) and value data for node 1 and invalid chunk data
    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_value(&value_data);
    assert!(result.is_err());

    let value_data = ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[1].clone(),
    );

    let result = verifier.visit_value(&value_data);
    assert!(result.is_ok());
}

#[test]
fn value_data_timestamp_works() {
    let test_struct =
        ValueData::<SupraDeliveryErasureRs8Schema>::new(Header::default(), ChunkData::default());
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
