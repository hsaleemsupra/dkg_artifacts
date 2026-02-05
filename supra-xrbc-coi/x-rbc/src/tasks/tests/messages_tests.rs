use crate::tasks::messages::RBCMessage;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{EchoShareData, RBCCommitteeMessage, RBCNetworkMessage};
use crate::types::tests::{share_data, value_data_with_header};
use crate::SupraDeliveryErasureRs8Schema;
use metrics::TimeStampTrait;
use primitives::types::Header;
use primitives::types::QuorumCertificate;
use std::time::Duration;

#[test]
fn test_message_flags() {
    let message = RBCMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
        Header::default(),
        QuorumCertificate::default(),
    ));
    assert!(message.is_sync_message());
    assert!(message.is_committee_message());

    let message = RBCMessage::<SupraDeliveryErasureRs8Schema>::Pull(PullRequest::new(
        [5; 32],
        SyncRequest::new(Header::default(), QuorumCertificate::default()),
    ));
    assert!(message.is_sync_message());
    assert!(message.is_committee_message());

    let message = RBCMessage::<SupraDeliveryErasureRs8Schema>::Share(share_data::<
        SupraDeliveryErasureRs8Schema,
    >(
        [2; 32],
        value_data_with_header::<SupraDeliveryErasureRs8Schema>(Header::default()),
    ));
    assert!(!message.is_sync_message());
    assert!(!message.is_committee_message());

    let message = RBCMessage::<SupraDeliveryErasureRs8Schema>::EchoShare(EchoShareData::new(
        [2; 32],
        value_data_with_header::<SupraDeliveryErasureRs8Schema>(Header::default()),
    ));
    assert!(!message.is_sync_message());
    assert!(!message.is_committee_message());
}

#[test]
#[should_panic]
fn test_no_sync_from_committee_message() {
    let message = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
        Header::default(),
        QuorumCertificate::default(),
    ));
    let _ = RBCMessage::<SupraDeliveryErasureRs8Schema>::from(message);
}

#[test]
#[should_panic]
fn test_no_sync_from_network_message() {
    let message = RBCNetworkMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
        Header::default(),
        QuorumCertificate::default(),
    ));
    let _ = RBCMessage::<SupraDeliveryErasureRs8Schema>::from(message);
}

#[test]
fn rbc_message_timestamp_works() {
    let test_struct = RBCMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
        Header::default(),
        QuorumCertificate::default(),
    ));

    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
