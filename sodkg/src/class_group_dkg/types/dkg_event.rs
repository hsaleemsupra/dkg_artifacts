use crate::class_group_dkg::types::signatures::BlsMultiSignature;
use crate::sosmr_types::DkgCommittee;
use crate::BlsPartialSignature;
use crypto::dealing::{DealingCommitmentwithCiphers, EncryptedDealingWithProof};
use cs_deliver::types::deliver_event::CSDeliverEventData;
use deliver::types::deliver_event::DeliverEventData;
use nidkg_helper::cgdkg::dkg_meta::{
    AggregateEncryptedShare, DKGMeta, DKGMetaWithAggregateSignature, DKGMetaWithSignature,
    DKGMetaZis, DealingMetaWithSignature,
};
use nidkg_helper::cgdkg::{CGIndividualDealing, DealingSignature};
use nidkg_helper::BlsPublicKey;
use socrypto::{Hash, Identity};
use soruntime::state::Event;
use std::any::Any;
use std::fmt;

#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum DkgEventType {
    InitDkg,
    ReceivedDealingSign,
    ReceivedDealingEvent,
    ReceivedEncryptedDealingEvent,
    ReceivedVoteOnDealingMeta,
    ReceivedDKGMeta,
    ReceivedVoteOnDKGMeta,
    ReceivedDKGMetaQC,
    ReceivedDeliverEvent,
    ReceivedCSDeliverEvent,
    ReceivedAggregateEncryptedShareEvent,
    SignatureCollectionTimerExpired,
    End,
    ReceivedPublicShare,
    ReceivedPartialSignOnThresholdPublicKey,
    ThresholdSignature,
    DkGReload,
    Load,
    DkGUpdate,
    None,
    EncryptedDealingProcessed,
    DKGMetaProcessed,
}

impl fmt::Display for DkgEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = match self {
            DkgEventType::InitDkg => "InitDkg",
            DkgEventType::ReceivedDealingSign => "ReceivedDealingSign",
            DkgEventType::ReceivedDealingEvent => "ReceivedDealingEvent",
            DkgEventType::ReceivedEncryptedDealingEvent => "ReceivedEncryptedDealingEvent",
            DkgEventType::ReceivedVoteOnDealingMeta => "ReceivedVoteOnDealingMeta",
            DkgEventType::ReceivedDKGMeta => "ReceivedDKGMeta",
            DkgEventType::ReceivedVoteOnDKGMeta => "ReceivedVoteOnDKGMeta",
            DkgEventType::ReceivedDKGMetaQC => "ReceivedDKGMetaQC",
            DkgEventType::ReceivedPublicShare => "ReceivedPublicShare",
            DkgEventType::ReceivedPartialSignOnThresholdPublicKey => {
                "ReceivedPartialSignOnThresholdPublicKey"
            }
            DkgEventType::ThresholdSignature => "ThresholdSignature",
            DkgEventType::DkGReload => "DkGReload",
            DkgEventType::Load => "Load",
            DkgEventType::DkGUpdate => "DkGUpdate",
            DkgEventType::None => "None",
            DkgEventType::ReceivedDeliverEvent => "ReceivedDeliverEvent",
            DkgEventType::ReceivedCSDeliverEvent => "ReceivedCSDeliverEvent",
            DkgEventType::ReceivedAggregateEncryptedShareEvent => {
                "ReceivedAggregateEncryptedShareEvent"
            }
            DkgEventType::SignatureCollectionTimerExpired => "SignatureCollectionTimerExpired",
            DkgEventType::End => "End",
            DkgEventType::EncryptedDealingProcessed => "EncryptedDealingProcessed",
            DkgEventType::DKGMetaProcessed => "DKGMetaProcessed",
        };
        write!(f, "{}", val)
    }
}

#[derive(Debug, Clone)]
pub enum DkgEventData {
    ReceiveDealingSig(Identity, DealingSignature),
    ReceiveDealing(Identity, CGIndividualDealing),
    ReceiveEncryptedDealing(Identity, EncryptedDealingWithProof),
    ReceiveVoteOnDealingMeta(Identity, DealingMetaWithSignature),
    ReceiveDKGMeta(Identity, DKGMeta),
    ReceiveVoteOnDKGMeta(Identity, DKGMetaWithSignature),
    ReceiveDKGMetaQC(DKGMetaWithAggregateSignature),
    ReceivePublicShare(Identity, BlsPublicKey),
    ReceivePartialSignOnThresholdPublicKey(Identity, BlsPartialSignature),
    /// Multi signature on threshold-key being generated.
    ThresholdSignature(BlsPublicKey, Box<BlsMultiSignature>),
    Committee(DkgCommittee),
    DkGReload(Identity, BlsPublicKey),
    None,
    ReceiveDeliverEvent(DeliverEventData),
    ReceiveCSDeliverEvent(CSDeliverEventData),
    ReceiveAggregateEncryptedShareEvent(Identity, AggregateEncryptedShare),
    SignatureCollectionTimerExpired,
    End,
    EncryptedDealingProcessed(Hash, DealingCommitmentwithCiphers, DealingMetaWithSignature),
    DKGMetaProcessed(Identity, Hash, DKGMetaZis, DKGMetaWithSignature),
}

impl From<&DkgEventData> for DkgEventType {
    fn from(value: &DkgEventData) -> Self {
        match value {
            DkgEventData::ReceiveDealingSig(_, _) => DkgEventType::ReceivedDealingSign,
            DkgEventData::ReceiveDealing(_, _) => DkgEventType::ReceivedDealingEvent,
            DkgEventData::ReceiveEncryptedDealing(_, _) => {
                DkgEventType::ReceivedEncryptedDealingEvent
            }
            DkgEventData::ReceiveVoteOnDealingMeta(_, _) => DkgEventType::ReceivedVoteOnDealingMeta,
            DkgEventData::ReceiveDKGMeta(_, _) => DkgEventType::ReceivedDKGMeta,
            DkgEventData::ReceiveVoteOnDKGMeta(_, _) => DkgEventType::ReceivedVoteOnDKGMeta,
            DkgEventData::ReceiveDKGMetaQC(_) => DkgEventType::ReceivedDKGMetaQC,
            DkgEventData::ReceivePublicShare(_, _) => DkgEventType::ReceivedPublicShare,
            DkgEventData::ReceivePartialSignOnThresholdPublicKey(_, _) => {
                DkgEventType::ReceivedPartialSignOnThresholdPublicKey
            }
            DkgEventData::ThresholdSignature(_, _) => DkgEventType::ThresholdSignature,
            DkgEventData::Committee(_) => DkgEventType::Load,
            DkgEventData::DkGReload(_, _) => DkgEventType::DkGReload,
            DkgEventData::None => DkgEventType::None,
            DkgEventData::ReceiveDeliverEvent(_) => DkgEventType::ReceivedDeliverEvent,
            DkgEventData::ReceiveCSDeliverEvent(_) => DkgEventType::ReceivedCSDeliverEvent,
            DkgEventData::ReceiveAggregateEncryptedShareEvent(_, _) => {
                DkgEventType::ReceivedAggregateEncryptedShareEvent
            }
            DkgEventData::SignatureCollectionTimerExpired => {
                DkgEventType::SignatureCollectionTimerExpired
            }
            DkgEventData::End => DkgEventType::End,
            DkgEventData::EncryptedDealingProcessed(_, _, _) => {
                DkgEventType::EncryptedDealingProcessed
            }
            DkgEventData::DKGMetaProcessed(_, _, _, _) => DkgEventType::DKGMetaProcessed,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DkgEvent {
    pub event_type: DkgEventType,
    pub data: DkgEventData,
}

impl DkgEvent {
    pub fn new_init_dkg() -> DkgEvent {
        DkgEvent {
            event_type: DkgEventType::InitDkg,
            data: DkgEventData::None,
        }
    }
    pub fn new_update_dkg(data: DkgCommittee) -> DkgEvent {
        DkgEvent {
            event_type: DkgEventType::DkGUpdate,
            data: DkgEventData::Committee(data),
        }
    }

    pub fn new_end_dkg_event() -> DkgEvent {
        DkgEvent {
            event_type: DkgEventType::End,
            data: DkgEventData::End,
        }
    }

    pub fn is_end_dkg_event(&self) -> bool {
        self.event_type == DkgEventType::End
    }

    pub fn priority(&self) -> u8 {
        match self.event_type {
            DkgEventType::ReceivedDealingSign => 1,
            DkgEventType::ReceivedDealingEvent => 1,
            DkgEventType::ReceivedEncryptedDealingEvent => 1,

            DkgEventType::ReceivedVoteOnDealingMeta => 2,
            DkgEventType::ReceivedDKGMeta => 2,
            DkgEventType::ReceivedVoteOnDKGMeta => 2,

            DkgEventType::ReceivedDKGMetaQC => 3,
            DkgEventType::ReceivedDeliverEvent => 3,
            DkgEventType::ReceivedCSDeliverEvent => 3,
            DkgEventType::ReceivedAggregateEncryptedShareEvent => 3,

            DkgEventType::SignatureCollectionTimerExpired => 4,
            DkgEventType::End => 4,

            _ => 0, // Default priority
        }
    }
}

impl Event for DkgEvent {
    type Data = DkgEventData;
    type EventType = DkgEventType;

    fn data(&self) -> &Self::Data {
        &self.data
    }

    fn event_type(&self) -> Self::EventType {
        self.event_type
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
