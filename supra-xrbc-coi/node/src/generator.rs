use crate::cli::GeneratorArgs;
use crate::helpers::{dump, load};
use crypto::traits::NodeIdentityInterface;
use crypto::NodeIdentity;
use network::topology::config::NetworkConfig;
use network::topology::peer_info::{PeerInfo, Role, COI_DEFAULT_PORT, XRBC_DEFAULT_PORT};
use network::topology::tests::TopologyGenerator;
use primitives::{ClanIdentifier, FaultyNodeIdentifier, Origin, PeerGlobalIndex, Protocol};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const LOCAL_HOST_IP: &str = "127.0.0.1";

pub struct Generator {
    topology_generator: TopologyGenerator,
    destination: PathBuf,
    peers: HashMap<Origin, PeerInfo>,
    /// Percentage of faulty node present in experiment chain
    fault_percent: usize,
}

impl Generator {
    pub fn run(params: GeneratorArgs) {
        let generator = Generator::new(params);
        generator.dump();
    }

    pub fn new(params: GeneratorArgs) -> Self {
        let destination = params.destination.clone();
        let fault_percent = params.fault_percent;
        let (network_config, remote_ips) = Generator::load(params);
        let mut generator = Self {
            topology_generator: Generator::prepare_topology_generator(network_config),
            destination,
            peers: Default::default(),
            fault_percent,
        };
        generator.prepare_peers(remote_ips);
        generator
    }

    fn dump(&self) {
        self.prepare_output_dir();
        self.dump_generated_peers();
        self.dump_identities();
        self.dump_faulty_peer_list();
    }

    fn prepare_output_dir(&self) {
        fs::create_dir_all(self.destination.clone()).expect("Successful destination path creation");
    }

    fn load(params: GeneratorArgs) -> (NetworkConfig, Option<Vec<String>>) {
        let network_config: NetworkConfig =
            load::<NetworkConfig>(params.network_config_file).expect("Well-Formed network config");

        let remote_ips = params
            .remote_ips
            .map(|remote_ips| load::<Vec<String>>(remote_ips).expect("Well-Formed ip list"));

        let valid_ip_info = remote_ips
            .as_ref()
            .map(|ips| ips.len() == network_config.total_nodes())
            .unwrap_or(true);
        if !valid_ip_info {
            panic!("Provided ip addresses count does not correspond to total nodes count in chain");
        }
        (network_config, remote_ips)
    }

    fn prepare_topology_generator(network_config: NetworkConfig) -> TopologyGenerator {
        let peer_index = PeerGlobalIndex::new(0, 0, 0);
        let mut generator = TopologyGenerator::new(Role::Basic, peer_index, network_config);
        generator.run();
        // To validate that valid topology can be created from the generated peers
        let _ = generator.topology_for_peer(peer_index);
        generator
    }

    fn prepare_peers(&mut self, remote_ips: Option<Vec<String>>) {
        self.peers = self.topology_generator.get_network_peers();
        if let Some(ips) = remote_ips {
            self.update_peers_addresses(ips);
        }
    }

    fn dump_generated_peers(&self) {
        dump(
            &self.peers.values().collect::<Vec<_>>(),
            self.destination.join("peers.json"),
        )
        .expect("Successful dump of peer data");
    }

    fn update_peers_addresses(&mut self, remote_ips: Vec<String>) {
        let mut ips_iter = remote_ips.iter();
        self.peers.iter_mut().for_each(|(_, peer)| {
            peer.set_address(ips_iter.next().unwrap().clone());
            peer.set_port(Protocol::XRBC, XRBC_DEFAULT_PORT);
            peer.set_port(Protocol::COI, COI_DEFAULT_PORT);
        })
    }

    fn dump_faulty_peer_list(&self) {
        let mut faulty_nodes = vec![];
        let network_config = self.topology_generator.network_config();
        let tribe = network_config.tribes();
        let clan = network_config.clans();
        let clan_size = network_config.clan_size();

        let mut clan_identity: HashMap<ClanIdentifier, usize> = HashMap::new();

        let fault_node = (clan_size as f32 * (self.fault_percent as f32 / 100.00)).ceil() as usize;
        for t in 0..tribe {
            for c in 0..clan {
                clan_identity.insert(ClanIdentifier::new(t, c), fault_node);
            }
        }
        for (_, peer_info) in self.peers.iter() {
            if !peer_info.is_proposer() && !peer_info.is_block_proposer() {
                let clan_identifier = peer_info.clan_identifier();
                let fault_left = clan_identity.get_mut(&clan_identifier).unwrap();
                if fault_left > &mut 0 {
                    faulty_nodes.push(FaultyNodeIdentifier::new(
                        peer_info.tribe(),
                        peer_info.clan(),
                        peer_info.position(),
                    ));
                    *fault_left -= 1;
                }
            }
        }

        let file_path = self.destination.join(PathBuf::from("faulty_peers.json"));
        dump::<Vec<FaultyNodeIdentifier>>(&faulty_nodes, file_path)
            .expect("faulty node identity dump");
    }

    fn dump_identities(&self) {
        self.topology_generator
            .identities()
            .iter()
            .for_each(|(idx, identity)| {
                let peer_info = self.peers.get(&identity.public_key()).unwrap();
                let suffix = Generator::define_suffix(peer_info.ip());
                let file_name = format!(
                    "node_{}_{}_{}{}.json",
                    idx.tribe(),
                    idx.clan(),
                    idx.position(),
                    suffix
                );
                let file_path = self.destination.join(PathBuf::from(file_name));
                dump::<NodeIdentity>(identity, file_path).expect("Successful node identity dump");
            })
    }

    fn define_suffix(ip_address: &String) -> String {
        if ip_address.as_str() == LOCAL_HOST_IP {
            "".to_string()
        } else {
            format!("_{ip_address}")
        }
    }
}

#[test]
fn test_load_success() {
    // No remote ips are provided
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: None,
    };

    let (_, remote_ips) = Generator::load(args);
    assert!(remote_ips.is_none());

    // well-formed remote ips are provided
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: Some(PathBuf::from("src/resources/remote_ips_1.json")),
    };

    let (config, remote_ips) = Generator::load(args);
    assert!(remote_ips.is_some());
    assert_eq!(remote_ips.as_ref().unwrap().len(), config.total_nodes());
}

#[test]
#[should_panic]
fn test_load_panic_when_net_config_load_fails() {
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("no_file.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: Some(PathBuf::from("src/resources/remote_ips_1.json")),
    };

    let _ = Generator::load(args);
}

#[test]
#[should_panic]
fn test_load_panic_when_remote_ips_load_fails() {
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: Some(PathBuf::from("no_file.json")),
    };

    let _ = Generator::load(args);
}

#[test]
#[should_panic]
fn test_load_panic_when_remote_ips_is_not_well_formed() {
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: Some(PathBuf::from("src/resources/remote_ips_2.json")),
    };

    let _ = Generator::load(args);
}

#[test]
fn test_generator_instantiation() {
    // No remote ips are provided
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: None,
    };

    let generator = Generator::new(args);
    assert!(!generator.peers.is_empty());
    generator.peers.values().for_each(|peer| {
        assert_eq!(peer.ip().as_str(), LOCAL_HOST_IP);
        if peer.global_index() != PeerGlobalIndex::new(0, 0, 0) {
            assert_ne!(peer.port(Protocol::XRBC), XRBC_DEFAULT_PORT);
            assert_ne!(peer.port(Protocol::COI), COI_DEFAULT_PORT);
        }
    });

    // well-formed remote ips are provided
    let ips_path = PathBuf::from("src/resources/remote_ips_1.json");
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: PathBuf::from(""),
        fault_percent: 0,
        remote_ips: Some(ips_path.clone()),
    };

    let generator = Generator::new(args);
    assert!(!generator.peers.is_empty());
    let mut remote_ips: Vec<String> = load(ips_path).expect("Successful load");
    generator.peers.values().for_each(|peer| {
        assert!(remote_ips.contains(peer.ip()));
        remote_ips.retain_mut(|v| v != peer.ip());
        assert_eq!(peer.port(Protocol::XRBC), XRBC_DEFAULT_PORT);
        assert_eq!(peer.port(Protocol::COI), COI_DEFAULT_PORT);
    });
}
#[test]
fn test_dump() {
    // No remote ips are provided
    let dest = PathBuf::from("test_generated_data");
    let _ = fs::remove_dir_all(dest.clone());
    let args = GeneratorArgs {
        network_config_file: PathBuf::from("src/resources/network_config_1.json"),
        destination: dest.clone(),
        fault_percent: 0,
        remote_ips: None,
    };

    let generator = Generator::new(args);
    assert!(!generator.peers.is_empty());
    generator.dump();
    let mut has_peers_json = false;
    let mut count = 0;
    for item in fs::read_dir(dest.clone()).expect("Successful dir read") {
        let file = item.expect("Successful file extraction");
        if file.path().is_file() {
            count += 1;
        }
        if file
            .file_name()
            .into_string()
            .unwrap()
            .eq_ignore_ascii_case("peers.json")
        {
            has_peers_json = true;
        }
    }
    assert!(has_peers_json);
    // config for all peers + peers.json + faulty_peer list
    assert_eq!(count, generator.peers.len() + 1 + 1);

    let _ = fs::remove_dir_all(dest);
}
