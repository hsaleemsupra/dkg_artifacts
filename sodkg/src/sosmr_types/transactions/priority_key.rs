use crate::sosmr_types::{
    AccountAddress, GasPrice, SequenceNumber, SmrTimestamp, TTransactionHeaderProperties,
};
use std::cmp::Ordering;

/// Defines a key based on which transaction priority is defined.
/// The greater the key the higher the transaction priority.
///
/// The transaction priority key is ordered based on the following properties in fall-back manner:
///   - transaction rank/gas-unit-price (higher the rank higher the priority)
///   - transaction expiration time (sooner the expiration time higher the priority)
///   - transaction sender (greater the sender address the higher the priority)
///   - transaction sequence number (lower the sequence number the higher the priority)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TransactionPriorityKey {
    /// Transaction gas-unit-price.
    gas_price_unit: GasPrice,
    /// Transaction sequence number for account.
    sequence_number: SequenceNumber,
    /// Transaction expiration time specified by user.
    expiration_timestamp: SmrTimestamp,
    /// Transaction sender account address.
    sender: AccountAddress,
}

impl PartialOrd<Self> for TransactionPriorityKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionPriorityKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher gas price gives to the transaction higher priority
        let gas_price_order = self.gas_price_unit.cmp(&other.gas_price_unit);
        if gas_price_order != Ordering::Equal {
            return gas_price_order;
        }
        // The sooner the transaction expiration time the higher the transaction priority
        let timestamp_order = self.expiration_timestamp.cmp(&other.expiration_timestamp);
        if timestamp_order != Ordering::Equal {
            return timestamp_order.reverse();
        }
        // The greater the transaction sender address the higher the transaction priority
        let sender_order = self.sender.cmp(&other.sender);
        if sender_order != Ordering::Equal {
            return sender_order;
        }
        // The lower the transaction sequence number the higher the priority for the same sender
        self.sequence_number.cmp(&other.sequence_number).reverse()
    }
}

impl<T> From<&T> for TransactionPriorityKey
where
    T: TTransactionHeaderProperties,
{
    fn from(value: &T) -> Self {
        Self {
            gas_price_unit: value.gas_unit_price(),
            sequence_number: value.sequence_number(),
            expiration_timestamp: value.expiration_timestamp(),
            sender: value.sender(),
        }
    }
}
