use crate::sosmr_types::SignedSmrTransaction;
//use crate::class_group_dkg::types::dkg_event::{DkgEvent, DkgEventData, DkgEventType};
//use crate::class_group_dkg::types::signatures::BlsPartialSignature;
//use crate::class_group_dkg::types::signatures::BlsMultiSignature;
use crate::errors::DkgError;
use log::debug;
//use nidkg_helper::BlsSignature;
//use nidkg_helper::BLS_PUBLIC_KEY_LEN;
//use nidkg_helper::BLS_SIGNATURE_LEN;
//use nidkg_helper::{BlsPublicKey};
use crate::sosmr_types::{
    AccountAddress,
    DkgTransactionPayload,
    SequenceNumber,
    SmrDkgCommitteeType,
    SmrTransactionHeader,
    //TTransactionHeaderProperties,
    //TTransactionPayload,
    UnsignedSmrTransaction,
};
use crate::sosmr_types::{DkgData, SmrTimestamp, SmrTransactionHeaderBuilder};
use crate::sosmr_types::{TTransactionHeaderProperties, TTransactionPayload};
use crate::{DkgEvent, DkgEventData, DkgEventType};
use nidkg_helper::cgdkg::dkg_meta::DKGMetaWithAggregateSignature;
use socrypto::{Identity, SecretKey};

const DKG_TXN_GAS_UNIT_PRICE: u64 = 2;
const DKG_TXN_MAX_GAS_AMOUNT: u64 = 2;

/// TODO: these hard coded values are temporary. they need to be specified at runtime based on DKG-run and account's transactions sequence number
const DKG_META_QC_SEQ: SequenceNumber = 0;
//const DKG_THRESHOLD_PUBLIC_KEY_SEQ: SequenceNumber = 1;

/// Fixed to 10 minutes for now.
const DKG_TXN_EXPIRATION_TIME_IN_SECS: u64 = 10 * 60;
pub(crate) fn create_dkg_transaction_header(
    address: AccountAddress,
    sequence_number: SequenceNumber,
) -> SmrTransactionHeader {
    SmrTransactionHeaderBuilder::new()
        .with_sender(address)
        .with_sequence_number(sequence_number)
        // TODO: pass as argument derived from epoch-duration: 1/2, 1/4 of epoch duration
        .with_expiration_timestamp(SmrTimestamp::seconds_from_now(
            DKG_TXN_EXPIRATION_TIME_IN_SECS,
        ))
        .with_chain_id(0)
        .with_gas_price(DKG_TXN_GAS_UNIT_PRICE)
        .with_max_gas_amount(DKG_TXN_MAX_GAS_AMOUNT)
        .build()
        .expect("Regression in constructing DKG TXN Header")
}

// In aptos, transaction sender is the sender account address, in our case it is public-key of the sender.
// As long as sender public-key can be rotated but not the account-address.
// In supra-node context identity is also something that is static for the node throughout its existence in scope of the chain,
// Which matches to the AccountAddress in APTOS.
// we might rethink of SmrTransaction.sender type
// for now let's assume that AccoundAddress/Identity and Public key are mutually interchangeable.
// But this needs to handled properly when DKG is run throughout epoch changes, and any rotation of the key happened for the node.
pub(crate) fn create_dkg_transaction(
    secret_key: &SecretKey,
    dkg_type: SmrDkgCommitteeType,
    dkg_data: DkgData,
    sequence_number: SequenceNumber,
) -> Result<SignedSmrTransaction, DkgError> {
    let pk = secret_key.gen_vk();
    let pk_bytes = pk.to_bytes();
    // TODO: currently identity and account address for DKG transactions are constructed from signer public key.
    //   Both should be provided by application layer to DKG to be passed here as arguments.
    let identity = Identity::new(pk_bytes);
    let address = AccountAddress::supra_address(pk_bytes);
    let dkg_txn_payload = DkgTransactionPayload::new(dkg_type, identity, dkg_data);
    // TODO: pass the sequence number and address as arguments
    let header = create_dkg_transaction_header(address, sequence_number);
    let unsigned_txn = UnsignedSmrTransaction::new(header, dkg_txn_payload.into());
    Ok(unsigned_txn.into_signed_transaction(secret_key))
}

pub fn create_dkg_meta_qc_tx(
    secret_key: &SecretKey,
    dkg_type: SmrDkgCommitteeType,
    dkg_meta_qc: Vec<u8>,
) -> Result<SignedSmrTransaction, DkgError> {
    let dkg_data = DkgData::dkg_meta_qc(dkg_meta_qc);
    create_dkg_transaction(secret_key, dkg_type, dkg_data, DKG_META_QC_SEQ)
}

/*pub fn create_thresholdsign_tx(
    secret_key: &SecretKey,
    dkg_type: SmrDkgCommitteeType,
    threshold_pubkey: &BlsPublicKey,
    node_partial_sign: Option<&BlsPartialSignature>,
    signature: BlsMultiSignature,
) -> Result<SignedSmrTransaction, DkgError> {
    let mut payload = vec![];
    payload.extend(threshold_pubkey.to_vec());
    payload.extend(signature.0.to_vec());
    debug!(
        "create_thresholdsign_tx node_partial_sign.is_some():{:?}",
        node_partial_sign.is_some()
    );
    match node_partial_sign {
        Some(pls) => {
            payload.push(1);
            payload.extend(pls.0.to_vec());
        }
        None => payload.push(0),
    }

    let dkg_data = DkgData::threshold_public_key(payload);
    create_dkg_transaction(secret_key, dkg_type, dkg_data, DKG_THRESHOLD_PUBLIC_KEY_SEQ)
}*/

/*pub fn extract_thresholdsign_tx_payload(
    payload: &[u8],
) -> Result<
    (
        BlsPublicKey,
        Option<BlsPartialSignature>,
        BlsMultiSignature,
    ),
    DkgError,
> {
    let bls_pubkey = BlsPublicKey::try_from(&payload[..BLS_PUBLIC_KEY_LEN])?;
    let mut start = BLS_PUBLIC_KEY_LEN;
    let threshold_sign = BlsSignature::try_from(&payload[start..start + BLS_SIGNATURE_LEN])?;
    start += BLS_SIGNATURE_LEN;
    let node_partial_sign = if payload[start] == 1 {
        start += 1;
        let bls = BlsSignature::try_from(&payload[start..start + BLS_SIGNATURE_LEN])?;
        Some(BlsPartialSignature(bls))
    } else {
        None
    };
    Ok((
        bls_pubkey,
        node_partial_sign,
        BlsMultiSignature(threshold_sign),
    ))
}*/

pub fn convert_received_smrtx_to_event(
    tx: &SignedSmrTransaction,
    _round: u64,
) -> Result<DkgEvent, DkgError> {
    if tx.is_dkg() {
        let dkg_transaction_payload = tx
            .payload()
            .dkg_transaction_payload()
            .expect("Identified as DKG transaction");
        debug!(
            "convert_received_smrtx_to_event tx sender:{} dkg type:{:?}",
            tx.sender(),
            dkg_transaction_payload.committee()
        );
        // In aptos transaction sender is the sender account address, in our case it is public-key of the sender.
        // As long as sender public-key can be rotated but not the account-address.
        // In supra-node context identity is also something that is static for the node throughout its existence in scope of the chain,
        // Which matches to the AccountAddress in APTOS.
        // we might rethink of SmrTransaction.sender type
        // for now let's assume that AccountAddress/Identity and Public key are mutually interchangeable.
        // But this needs to handled properly when DKG is run throughout epoch changes, and any rotation of the key happened for the node.
        convert_payload_to_event(dkg_transaction_payload)
    } else {
        Err(DkgError::TransactionConversionError(
            "convert_smrtx_to_event not a dkg tx".to_string(),
        ))
    }
}
pub fn convert_payload_to_event(
    dkg_transaction_payload: &DkgTransactionPayload,
) -> Result<DkgEvent, DkgError> {
    match dkg_transaction_payload.data() {
        DkgData::DKGMetaQC(payload) => Ok(DkgEvent {
            event_type: DkgEventType::ReceivedDKGMetaQC,
            data: DkgEventData::ReceiveDKGMetaQC(DKGMetaWithAggregateSignature::try_from(
                payload.as_slice(),
            )?),
        }),

        /*DkgData::ThresholdSignatureOnThresholdPublicKey(payload) => {
            let (bls_pubkey, node_partial_sign, threshold_sign) =
                extract_thresholdsign_tx_payload(payload.as_ref())?;
            Ok(DkgEvent {
                event_type: DkgEventType::ThresholdSignature,
                data: DkgEventData::ThresholdSignature(
                    bls_pubkey,
                    Box::new(node_partial_sign),
                    Box::new(threshold_sign),
                ),
            })
        }*/
        DkgData::NoType => Err(DkgError::TransactionConversionError(format!(
            "convert_smrtx_to_event bad tx subtype:{:?}",
            dkg_transaction_payload.data_type()
        ))),
    }
}
