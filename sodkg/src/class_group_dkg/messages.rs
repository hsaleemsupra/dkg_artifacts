//! DKG protocol message posted via P2P channel

use crypto::dealing::EncryptedDealingWithProof;
use crate::class_group_dkg::types::dkg_event::DkgEventData;
use crate::class_group_dkg::types::signatures::BlsPartialSignature;
use enum_kinds::EnumKind;
use log::trace;
use cs_deliver::messages::CSDeliverProtocolMessage;
use cs_deliver::types::deliver_event::CSDeliverEventData;
use nidkg_helper::cgdkg::{DealingSignature, CGIndividualDealing};
use nidkg_helper::serde_utils::{read_vector, write_vector};
use nidkg_helper::{BlsPublicKey};
use socrypto::Identity;
use deliver::messages::DeliverProtocolMessage;
use deliver::types::deliver_event::DeliverEventData;
use nidkg_helper::cgdkg::dkg_meta::{DKGMeta, DKGMetaWithSignature, DealingMetaWithSignature, AggregateEncryptedShare, DKGMetaWithAggregateSignature};
use crate::errors::DkgError;

/// Public Key information of the party to be shared with other parties in committee.
#[derive(Debug, Clone)]
pub struct PublicKeyShare {
    pub key: BlsPublicKey,
}

impl PublicKeyShare {
    /// Defines raw representation of the [PublicKeyShare]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = Vec::new();
        write_vector(&mut final_bytes, self.key.to_vec());
        final_bytes
    }
}

impl TryFrom<&[u8]> for PublicKeyShare {
    type Error = DkgError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(value);
        let key_raw = read_vector(&mut cursor).map_err(DkgError::NiDkgError)?;
        let key = BlsPublicKey::try_from(key_raw.as_slice()).map_err(DkgError::NiDkgError)?;
        Ok(Self { key })
    }
}

/// DKG protocol messages used for communication between 2 counterparts of the protocol during different
/// stages.
#[derive(Debug, Clone, EnumKind)]
#[enum_kind(DKGProtocolMessageKind)]
pub enum DKGProtocolMessage {
    // Data Messages
    Dealing(CGIndividualDealing),
    EncryptedDealing(EncryptedDealingWithProof),
    DealingSignature(DealingSignature),
    VoteOnDealingMeta(DealingMetaWithSignature),
    DKGMeta(DKGMeta),
    VoteOnDKGMeta(DKGMetaWithSignature),
    PublicKeyShare(Box<PublicKeyShare>),
    PartialSignatureOnThresholdKey(BlsPartialSignature),
    // Sync Messages
    Reloaded(Box<BlsPublicKey>),
    // Deliver Protocol Messages
    DeliverMessage(DeliverProtocolMessage),
    // CS Deliver Protocol Messages
    CSDeliverMessage(CSDeliverProtocolMessage),
    AggregatedEncryptedShare(AggregateEncryptedShare),
    //todo: to remove
    DKGMetaWithAggregateSignature(DKGMetaWithAggregateSignature)
}

impl DKGProtocolMessageKind {
    const fn index(self) -> u8 {
        match self {
            DKGProtocolMessageKind::Dealing => 0,
            DKGProtocolMessageKind::EncryptedDealing => 1,
            DKGProtocolMessageKind::DealingSignature => 2,
            DKGProtocolMessageKind::VoteOnDealingMeta => 3,
            DKGProtocolMessageKind::DKGMeta => 4,
            DKGProtocolMessageKind::VoteOnDKGMeta => 5,
            DKGProtocolMessageKind::PublicKeyShare => 6,
            DKGProtocolMessageKind::PartialSignatureOnThresholdKey => 7,
            DKGProtocolMessageKind::Reloaded => 8,
            DKGProtocolMessageKind::DeliverMessage => 9,
            DKGProtocolMessageKind::CSDeliverMessage => 10,
            DKGProtocolMessageKind::AggregatedEncryptedShare => 11,
            DKGProtocolMessageKind::DKGMetaWithAggregateSignature => 12,
        }
    }
}

impl TryFrom<u8> for DKGProtocolMessageKind {
    type Error = DkgError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DKGProtocolMessageKind::Dealing),
            1 => Ok(DKGProtocolMessageKind::EncryptedDealing),
            2 => Ok(DKGProtocolMessageKind::DealingSignature),
            3 => Ok(DKGProtocolMessageKind::VoteOnDealingMeta),
            4 => Ok(DKGProtocolMessageKind::DKGMeta),
            5 => Ok(DKGProtocolMessageKind::VoteOnDKGMeta),
            6 => Ok(DKGProtocolMessageKind::PublicKeyShare),
            7 => Ok(DKGProtocolMessageKind::PartialSignatureOnThresholdKey),
            8 => Ok(DKGProtocolMessageKind::Reloaded),
            9 => Ok(DKGProtocolMessageKind::DeliverMessage),
            10 => Ok(DKGProtocolMessageKind::CSDeliverMessage),
            11 => Ok(DKGProtocolMessageKind::AggregatedEncryptedShare),
            12 => Ok(DKGProtocolMessageKind::DKGMetaWithAggregateSignature),
            _ => Err(DkgError::GeneralError(
                "Invalid dkg message kind raw representation".to_string(),
            )),
        }
    }
}

impl DKGProtocolMessage {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_vec = Vec::new();
        let kind = DKGProtocolMessageKind::from(self).index();
        final_vec.push(kind);
        let mut payload_raw = match self {
            DKGProtocolMessage::Dealing(data) => data.to_vec(),
            DKGProtocolMessage::EncryptedDealing(data) => data.to_vec(),
            DKGProtocolMessage::DealingSignature(data) => data.to_vec(),
            DKGProtocolMessage::VoteOnDealingMeta(data) => data.to_vec(),
            DKGProtocolMessage::DKGMeta(data) => data.to_vec(),
            DKGProtocolMessage::VoteOnDKGMeta(data) => data.to_vec(),
            DKGProtocolMessage::PublicKeyShare(data) => data.to_vec(),
            DKGProtocolMessage::PartialSignatureOnThresholdKey(data) => data.0.to_vec(),
            DKGProtocolMessage::Reloaded(data) => data.to_vec(),
            DKGProtocolMessage::DeliverMessage(data) => data.to_vec(),
            DKGProtocolMessage::CSDeliverMessage(data) => data.to_vec(),
            DKGProtocolMessage::AggregatedEncryptedShare(data) => data.to_vec(),
            DKGProtocolMessage::DKGMetaWithAggregateSignature(data) => data.to_vec(),
        };
        final_vec.append(&mut payload_raw);
        final_vec
    }
}

impl TryFrom<&[u8]> for DKGProtocolMessage {
    type Error = DkgError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let kind = DKGProtocolMessageKind::try_from(value[0])?;
        trace!("DKG Message kind: {kind:?}");
        let data_raw = &value[1..];
        match kind {
            DKGProtocolMessageKind::Dealing => CGIndividualDealing::try_from(data_raw)
                .map(DKGProtocolMessage::Dealing)
                .map_err(DkgError::NiDkgError),
            DKGProtocolMessageKind::EncryptedDealing => EncryptedDealingWithProof::try_from(data_raw)
                .map(DKGProtocolMessage::EncryptedDealing)
                .map_err(DkgError::NiDkgError),
            DKGProtocolMessageKind::DealingSignature => DealingSignature::try_from(data_raw)
                .map(DKGProtocolMessage::DealingSignature)
                .map_err(DkgError::NiDkgError),
            DKGProtocolMessageKind::VoteOnDealingMeta => DealingMetaWithSignature::try_from(data_raw)
                .map(DKGProtocolMessage::VoteOnDealingMeta)
                .map_err(DkgError::NiDkgError),
            DKGProtocolMessageKind::DKGMeta => DKGMeta::try_from(data_raw)
                .map(DKGProtocolMessage::DKGMeta)
                .map_err(DkgError::NiDkgError),
            DKGProtocolMessageKind::VoteOnDKGMeta => DKGMetaWithSignature::try_from(data_raw)
                .map(DKGProtocolMessage::VoteOnDKGMeta)
                .map_err(DkgError::NiDkgError),
            DKGProtocolMessageKind::PublicKeyShare => PublicKeyShare::try_from(data_raw)
                .map(|d| DKGProtocolMessage::PublicKeyShare(Box::new(d))),
            DKGProtocolMessageKind::PartialSignatureOnThresholdKey => BlsPartialSignature::try_from(data_raw)
                .map_err(|e| DkgError::GeneralError(e.to_string()))
                .map(|d| DKGProtocolMessage::PartialSignatureOnThresholdKey(d)),
            DKGProtocolMessageKind::Reloaded => BlsPublicKey::try_from(data_raw)
                .map_err(DkgError::NiDkgError)
                .map(|k| DKGProtocolMessage::Reloaded(Box::new(k))),
            DKGProtocolMessageKind::DeliverMessage => DeliverProtocolMessage::try_from(data_raw)
                .map_err(DkgError::DeliverError)
                .map(|k| DKGProtocolMessage::DeliverMessage(k)),
            DKGProtocolMessageKind::CSDeliverMessage => CSDeliverProtocolMessage::try_from(data_raw)
                .map_err(DkgError::CSDeliverError)
                .map(|k| DKGProtocolMessage::CSDeliverMessage(k)),
            DKGProtocolMessageKind::AggregatedEncryptedShare => AggregateEncryptedShare::try_from(data_raw)
                .map_err(|e| DkgError::GeneralError(e.to_string()))
                .map(|d| DKGProtocolMessage::AggregatedEncryptedShare(d)),
            DKGProtocolMessageKind::DKGMetaWithAggregateSignature => DKGMetaWithAggregateSignature::try_from(data_raw)
                .map_err(|e| DkgError::GeneralError(e.to_string()))
                .map(|d| DKGProtocolMessage::DKGMetaWithAggregateSignature(d)),

        }
    }
}

impl From<(Identity, DKGProtocolMessage)> for DkgEventData {
    fn from(value: (Identity, DKGProtocolMessage)) -> Self {
        let (sender, message) = value;
        match message {
            DKGProtocolMessage::Dealing(data) => DkgEventData::ReceiveDealing(sender, data),
            DKGProtocolMessage::EncryptedDealing(data) => DkgEventData::ReceiveEncryptedDealing(sender, data),
            DKGProtocolMessage::DealingSignature(data) => {
                DkgEventData::ReceiveDealingSig(sender, data)
            }
            DKGProtocolMessage::VoteOnDealingMeta(data) => {
                DkgEventData::ReceiveVoteOnDealingMeta(sender, data)
            }
            DKGProtocolMessage::DKGMeta(data) => {
                DkgEventData::ReceiveDKGMeta(sender, data)
            }
            DKGProtocolMessage::VoteOnDKGMeta(data) => {
                DkgEventData::ReceiveVoteOnDKGMeta(sender, data)
            }
            DKGProtocolMessage::PublicKeyShare(data) => {
                DkgEventData::ReceivePublicShare(sender, data.key)
            }
            DKGProtocolMessage::PartialSignatureOnThresholdKey(data) => {
                DkgEventData::ReceivePartialSignOnThresholdPublicKey(sender, data)
            }
            DKGProtocolMessage::Reloaded(data) => DkgEventData::DkGReload(sender, *data),
            DKGProtocolMessage::DeliverMessage(data) => DkgEventData::ReceiveDeliverEvent(DeliverEventData::from((sender, data))),
            DKGProtocolMessage::CSDeliverMessage(data) => DkgEventData::ReceiveCSDeliverEvent(CSDeliverEventData::from((sender, data))),
            DKGProtocolMessage::AggregatedEncryptedShare(data) => {
                DkgEventData::ReceiveAggregateEncryptedShareEvent(sender, data)
            }
            DKGProtocolMessage::DKGMetaWithAggregateSignature(data) => {
                DkgEventData::ReceiveDKGMetaQC(data)
            }
        }
    }
}
