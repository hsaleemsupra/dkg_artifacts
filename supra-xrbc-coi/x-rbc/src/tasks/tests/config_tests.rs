use crate::tasks::config::{
    DisseminationRule, EchoTarget, GarbageCollectorConfig, RBCTaskStateTimeConfig,
};
use crate::{SupraDeliveryConfig, SupraDeliveryErasureRs16Schema, SupraDeliveryErasureRs8Schema};
use erasure::codecs::rs16::Rs16Settings;
use erasure::codecs::rs8::Rs8Settings;
use erasure::utils::codec_trait::Setting;
use std::time::Duration;

#[test]
fn check_committee_network_size() {
    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(63, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert_eq!(125, supra_delivery_config.committee_size());
    assert_eq!(250, supra_delivery_config.network_size());

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(0, 0);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert_eq!(125, supra_delivery_config.committee_size());
    assert_eq!(125, supra_delivery_config.network_size());

    let committee_erasure_config = Rs8Settings::new(9, 4);
    let network_erasure_config = Rs8Settings::new(18, 8);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs8Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert_eq!(13, supra_delivery_config.committee_size());
    assert_eq!(39, supra_delivery_config.network_size());
}

#[test]
fn test_validity() {
    use erasure::codecs::rs16::Rs16Settings;
    use erasure::codecs::rs8::Rs8Settings;

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(63, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(supra_delivery_config.validate().is_ok());

    let committee_erasure_config = Rs8Settings::new(9, 4);
    let network_erasure_config = Rs8Settings::new(18, 8);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs8Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(supra_delivery_config.validate().is_ok());

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        None,
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(supra_delivery_config.validate().is_ok());

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(0, 0);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(supra_delivery_config.validate().is_err());

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(62, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(supra_delivery_config.validate().is_err());
}

#[test]
fn test_validity_of_task_time_paramerters() {
    use erasure::codecs::rs16::Rs16Settings;

    let committee_erasure_config = Rs16Settings::new(63, 62);
    let network_erasure_config = Rs16Settings::new(63, 62);
    let supra_delivery_config = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        Default::default(),
        Default::default(),
    );
    assert!(supra_delivery_config.validate().is_ok());

    let invalid_gc_config = GarbageCollectorConfig {
        task_stale_timeout: Duration::from_secs(0),
        garbage_collection_timeout: Duration::from_secs(1),
    };
    let invalid_gc_params = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        invalid_gc_config,
        Default::default(),
        Default::default(),
    );
    assert!(invalid_gc_params.validate().is_err());

    let invalid_gc_config = GarbageCollectorConfig {
        task_stale_timeout: Duration::from_secs(1),
        garbage_collection_timeout: Duration::from_secs(0),
    };
    let invalid_gc_params = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        invalid_gc_config,
        Default::default(),
        Default::default(),
    );
    assert!(invalid_gc_params.validate().is_err());

    let invalid_task_time_config = RBCTaskStateTimeConfig::new(Duration::from_secs(0));
    let invalid_gc_params = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        Default::default(),
        invalid_task_time_config,
        Default::default(),
    );
    assert!(invalid_gc_params.validate().is_err());

    let task_time_config = RBCTaskStateTimeConfig::new(Duration::from_secs(8));
    let gc_config = GarbageCollectorConfig {
        task_stale_timeout: Duration::from_secs(3),
        garbage_collection_timeout: Duration::from_secs(10),
    };
    let invalid_time_params = SupraDeliveryConfig::<SupraDeliveryErasureRs16Schema>::new(
        committee_erasure_config,
        Some(network_erasure_config),
        gc_config,
        task_time_config,
        Default::default(),
    );
    assert!(invalid_time_params.validate().is_err());
}

#[test]
fn test_node_count() {
    let rule = DisseminationRule::Partial(EchoTarget::Right(4));
    assert_eq!(rule.node_count(), Some(4));

    let rule = DisseminationRule::Partial(EchoTarget::Left(4));
    assert_eq!(rule.node_count(), Some(4));

    let rule = DisseminationRule::Full;
    assert_eq!(rule.node_count(), None);

    let rule = DisseminationRule::Partial(EchoTarget::All);
    assert_eq!(rule.node_count(), None);
}
