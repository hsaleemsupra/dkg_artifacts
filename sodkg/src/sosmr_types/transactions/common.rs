//! Defines common types used in scope of smr-transaction

/// Type of the sequence number of the transaction of the sender account.
pub type SequenceNumber = u64;

/// Type of the gas unit price of the transaction.
/// E.g. Gas unit price is 2 SupraCoin.
pub type GasPrice = u64;

/// Type of the gas amount in gas units.
/// E.g. 5 gas units has been spent on the transaction execution.
/// E.g. transaction execution fee is 5 * GasPrice.
pub type GasAmount = u64;
