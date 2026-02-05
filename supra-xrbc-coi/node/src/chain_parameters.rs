use crate::helpers::{dump, load};
use batch::PayloadGeneratorConfig;
use block::config::BlockProposerConfig;
use crypto::dkg::config::DKGConfig;
use erasure::codecs::rs16::Rs16Settings;
use erasure::utils::codec_trait::Setting;
use network::topology::config::NetworkConfig;
use primitives::error::CommonError;
use serde::{Deserialize, Serialize};
use std::io::Error;
use std::path::PathBuf;
use x_rbc::{SupraDeliveryConfig, SupraDeliveryErasureRs16Schema, SupraDeliveryErasureRs8Schema};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SupraDeliveryConfigParameters {
    Rs16(SupraDeliveryConfig<SupraDeliveryErasureRs16Schema>),
    Rs8(SupraDeliveryConfig<SupraDeliveryErasureRs8Schema>),
}

impl SupraDeliveryConfigParameters {
    fn validate(&self, committee_size: usize, network_size: usize) -> Result<(), CommonError> {
        let (delivery_committee, delivery_network) = match self {
            SupraDeliveryConfigParameters::Rs16(params) => {
                params.validate().map_err(CommonError::InvalidData)?;
                (params.committee_size(), params.network_size())
            }
            SupraDeliveryConfigParameters::Rs8(params) => {
                params.validate().map_err(CommonError::InvalidData)?;
                (params.committee_size(), params.network_size())
            }
        };
        if delivery_network != 0 {
            if delivery_network != network_size {
                return Err(CommonError::InvalidData(format!(
                    "Invalid delivery config: Expected network size: {:?}, Actual: {:?}",
                    network_size, delivery_network
                )));
            }
        } else if committee_size != network_size {
            // if number of clan is greater than one then network config must be present
            return Err(CommonError::InvalidData(
                "Invalid delivery config: Network Configuration Expected".to_string(),
            ));
        }
        if committee_size != delivery_committee {
            Err(CommonError::InvalidData(format!(
                "Invalid delivery config:\nExpected committee size: {}, Actual: {}",
                committee_size, delivery_committee
            )))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChainParameters {
    pub network_config: NetworkConfig,
    pub dkg_config: DKGConfig,
    pub batch_config: PayloadGeneratorConfig,
    pub block_config: BlockProposerConfig,
    pub delivery_config: SupraDeliveryConfigParameters,
}

impl Default for ChainParameters {
    fn default() -> Self {
        let committee_erasure_config = Rs16Settings::new(63, 62);
        let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
            committee_erasure_config,
            None,
            Default::default(),
            Default::default(),
            Default::default(),
        );
        Self {
            network_config: NetworkConfig::default(),
            dkg_config: DKGConfig::default(),
            batch_config: PayloadGeneratorConfig::default(),
            block_config: Default::default(),
            delivery_config: SupraDeliveryConfigParameters::Rs16(supra_delivery_config),
        }
    }
}

impl ChainParameters {
    pub fn network_config(&self) -> &NetworkConfig {
        &self.network_config
    }

    pub fn batch_config(&self) -> &PayloadGeneratorConfig {
        &self.batch_config
    }

    pub fn block_config(&self) -> &BlockProposerConfig {
        &self.block_config
    }

    pub fn delivery_config(&self) -> &SupraDeliveryConfigParameters {
        &self.delivery_config
    }

    pub fn dkg_config(&self) -> &DKGConfig {
        &self.dkg_config
    }
}

impl ChainParameters {
    pub fn dump_default_config() -> Result<(), Error> {
        let config_file_path = PathBuf::from("default_config.json");
        let config = ChainParameters::default();
        dump(&config, config_file_path)
    }

    pub fn load(config_file_path: PathBuf) -> Result<ChainParameters, Error> {
        let chain_params = load::<ChainParameters>(config_file_path)?;
        chain_params.validate().map_err(Error::from)
    }

    pub fn validate(self) -> Result<ChainParameters, CommonError> {
        self.network_config
            .validate()
            .map_err(CommonError::InvalidData)?;
        self.dkg_config
            .validate()
            .map_err(CommonError::InvalidData)?;
        self.batch_config
            .validate()
            .map_err(CommonError::InvalidData)?;

        self.block_config()
            .validate()
            .map_err(CommonError::InvalidData)?;

        self.delivery_config.validate(
            self.network_config.clan_size(),
            self.network_config.total_nodes(),
        )?;
        Ok(self)
    }

    #[cfg(test)]
    pub fn invalid_config() -> Self {
        ChainParameters {
            network_config: NetworkConfig::invalid_config(),
            ..ChainParameters::default()
        }
    }
}

#[test]
fn check_supra_delivery_parameters() {
    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(63, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    let params = SupraDeliveryConfigParameters::Rs16(supra_delivery_config);
    assert!(params.validate(125, 250).is_ok());
    assert!(params.validate(125, 300).is_err());

    use erasure::codecs::rs8::Rs8Settings;

    let committee_erasure_config = Rs8Settings::new(9, 4);
    let network_erasure_config = Rs8Settings::new(18, 8);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs8Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    let params = SupraDeliveryConfigParameters::Rs8(supra_delivery_config);
    assert!(params.validate(13, 39).is_ok());
    assert!(params.validate(12, 39).is_err());

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        None,
        Default::default(),
        Default::default(),
        Default::default(),
    );
    let params = SupraDeliveryConfigParameters::Rs16(supra_delivery_config);
    assert!(params.validate(125, 125).is_ok());

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(0, 0);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    let params = SupraDeliveryConfigParameters::Rs16(supra_delivery_config);
    assert!(params.validate(125, 125).is_err());
}

#[test]
fn check_config_validity() {
    let invalid_network_config = ChainParameters {
        network_config: NetworkConfig::invalid_config(),
        ..ChainParameters::default()
    };
    assert!(invalid_network_config.validate().is_err());

    let invalid_dkg_config = ChainParameters {
        dkg_config: DKGConfig::invalid_config(),
        ..ChainParameters::default()
    };
    assert!(invalid_dkg_config.validate().is_err());

    let invalid_batch_config = ChainParameters {
        batch_config: PayloadGeneratorConfig::invalid_config(),
        ..ChainParameters::default()
    };
    assert!(invalid_batch_config.validate().is_err());

    let invalid_block_config = ChainParameters {
        block_config: BlockProposerConfig::new(0.0, 0),
        ..ChainParameters::default()
    };
    assert!(invalid_block_config.validate().is_err());
}

#[test]
fn check_config_load() {
    let valid_config = ChainParameters::load(PathBuf::from("src/resources/valid_config.json"));
    assert!(valid_config.is_ok(), "{:?}", valid_config);
    let invalid_config = ChainParameters::load(PathBuf::from("src/resources/invalid_config.json"));
    assert!(invalid_config.is_err(), "{:?}", invalid_config);

    let valid_config =
        ChainParameters::load(PathBuf::from("src/resources/valid_optional_network.json"));
    assert!(valid_config.is_ok(), "{:?}", valid_config);
    let invalid_config =
        ChainParameters::load(PathBuf::from("src/resources/invalid_optional_network.json"));
    assert!(invalid_config.is_err(), "{:?}", invalid_config);

    let with_dissemination_rule = ChainParameters::load(PathBuf::from(
        "src/resources/valid_config_with_partial_data_dissemination.json",
    ));
    assert!(
        with_dissemination_rule.is_ok(),
        "{:?}",
        with_dissemination_rule
    );

    let with_invalid_dissemination_rule = ChainParameters::load(PathBuf::from(
        "src/resources/invalid_config_with_partial_data_dissemination.json",
    ));
    assert!(
        with_invalid_dissemination_rule.is_err(),
        "{:?}",
        with_invalid_dissemination_rule
    );
}

#[test]
fn check_default_validity() {
    let default = ChainParameters::default().validate();
    assert!(default.is_ok(), "{:?}", default);
}
