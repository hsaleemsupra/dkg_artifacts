use crate::sosmr_types::transactions::common::{GasAmount, GasPrice, SequenceNumber};
use crate::sosmr_types::{AccountAddress, ChainId, SmrTimestamp};
use serde::{Deserialize, Serialize};
use socrypto::Digest;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use utoipa::ToSchema;

/// A Supra transaction header. Contains properties common to all types of Supra transactions.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, ToSchema)]
pub struct SmrTransactionHeader {
    /// The unique identifier for the instance of the Supra chain that this transaction should
    /// be executed upon.
    #[schema(value_type = u8, format = "uint8")]
    chain_id: ChainId,
    /// The time at which this transaction should be discarded if it has not been executed.
    expiration_timestamp: SmrTimestamp,
    /// The standardized representation of the sender's account address in the target VM.
    sender: AccountAddress,
    /// The sequence number of the sender's account in the target VM.
    #[schema(value_type = u64, format = "uint64")]
    sequence_number: SequenceNumber,
    /// The amount of Supra that the sender is willing to pay per unit of gas.
    #[schema(value_type = u64, format = "uint64")]
    gas_unit_price: GasPrice,
    /// The maximum amount of gas that the sender is willing to spend.
    #[schema(value_type = u64, format = "uint64")]
    max_gas_amount: GasAmount,
}

/// Trait to access [SmrTransactionHeader] property owned by object.
pub trait TTransactionHeader {
    fn header(&self) -> &SmrTransactionHeader;
}

/// Defines generic API to access transaction header properties for owners of [SmrTransactionHeader]
pub trait TTransactionHeaderProperties {
    fn sender(&self) -> AccountAddress;

    fn sequence_number(&self) -> SequenceNumber;

    fn gas_unit_price(&self) -> GasPrice;

    fn max_gas_amount(&self) -> GasAmount;

    fn expiration_timestamp(&self) -> SmrTimestamp;

    fn chain_id(&self) -> ChainId;

    fn is_expired(&self) -> bool;
}

impl<T: TTransactionHeader> TTransactionHeaderProperties for T {
    fn sender(&self) -> AccountAddress {
        self.header().sender
    }

    fn sequence_number(&self) -> SequenceNumber {
        self.header().sequence_number
    }

    fn gas_unit_price(&self) -> GasPrice {
        self.header().gas_unit_price
    }

    fn max_gas_amount(&self) -> GasAmount {
        self.header().max_gas_amount
    }

    fn expiration_timestamp(&self) -> SmrTimestamp {
        self.header().expiration_timestamp
    }

    fn chain_id(&self) -> ChainId {
        self.header().chain_id
    }

    fn is_expired(&self) -> bool {
        self.header().expiration_timestamp.is_past()
    }
}

impl TTransactionHeader for SmrTransactionHeader {
    fn header(&self) -> &SmrTransactionHeader {
        self
    }
}

impl SmrTransactionHeader {
    /// Creates a new [SmrTransactionHeader] from the given properties.
    pub fn new(
        sender: AccountAddress,
        sequence_number: SequenceNumber,
        gas_unit_price: GasPrice,
        max_gas_amount: GasAmount,
        expiration_timestamp: SmrTimestamp,
        chain_id: ChainId,
    ) -> Self {
        Self {
            sender,
            sequence_number,
            gas_unit_price,
            max_gas_amount,
            expiration_timestamp,
            chain_id,
        }
    }

    /// Generates random transaction header. Mainly for testing proposes.
    pub fn random() -> Self {
        Self {
            sender: AccountAddress::random_supra(),
            sequence_number: 0,
            gas_unit_price: 1,
            max_gas_amount: 1,
            expiration_timestamp: SmrTimestamp::seconds_from_now(60),
            chain_id: 0,
        }
    }
}

impl Digest for SmrTransactionHeader {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(self.sender.as_ref());
        hasher.update(self.sequence_number.to_le_bytes());
        hasher.update(self.gas_unit_price.to_le_bytes());
        hasher.update(self.max_gas_amount.to_le_bytes());
        hasher.update(self.expiration_timestamp.to_le_bytes());
        hasher.update(self.chain_id.to_le_bytes());
    }
}

impl Display for SmrTransactionHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("sender", &self.sender)
            .field("seq", &self.sequence_number)
            .field("gas_price", &self.gas_unit_price)
            .field("max_gas_amount", &self.max_gas_amount)
            .field(
                "expires_at",
                &self.expiration_timestamp.utc_date_time_string(),
            )
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl Debug for SmrTransactionHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

// impl Verifier<SmrTransactionHeader> for &Committee {
//     /// Ensures that the [SmrTransactionHeader] has:
//     ///   1. The same [ChainId] as this [Committee].
//     ///   2. An expiration timestamp that is in the future.
//     fn verify(&self, h: &SmrTransactionHeader) -> Result<(), SmrError> {
//         if h.chain_id() != self.chain_id() {
//             return Err(SmrError::InvalidChainId(
//                 type_name::<SmrTransactionHeader>().to_string(),
//                 h.chain_id(),
//                 type_name::<Self>().to_string(),
//                 self.chain_id(),
//             ));
//         }
//
//         if h.is_expired() {
//             return Err(SmrError::ExpiredTransaction);
//         }
//
//         Ok(())
//     }
// }

/// [SmrTransactionHeader] builder interface
#[derive(Clone, Debug)]
pub struct SmrTransactionHeaderBuilder {
    sender: Option<AccountAddress>,
    sequence_number: Option<SequenceNumber>,
    gas_unit_price: Option<GasPrice>,
    max_gas_amount: Option<GasAmount>,
    expiration_timestamp: Option<SmrTimestamp>,
    chain_id: Option<ChainId>,
}

impl SmrTransactionHeaderBuilder {
    pub fn new() -> Self {
        Self {
            sender: None,
            sequence_number: None,
            gas_unit_price: None,
            max_gas_amount: None,
            expiration_timestamp: None,
            chain_id: None,
        }
    }

    pub fn with_sender(self, sender: AccountAddress) -> Self {
        Self {
            sender: Some(sender),
            ..self
        }
    }
    pub fn with_sequence_number(self, seq: SequenceNumber) -> Self {
        Self {
            sequence_number: Some(seq),
            ..self
        }
    }
    pub fn with_gas_price(self, price: u64) -> Self {
        Self {
            gas_unit_price: Some(price),
            ..self
        }
    }

    pub fn with_max_gas_amount(self, max_gas_amount: u64) -> Self {
        Self {
            max_gas_amount: Some(max_gas_amount),
            ..self
        }
    }
    pub fn with_expiration_timestamp(self, timestamp: SmrTimestamp) -> Self {
        Self {
            expiration_timestamp: Some(timestamp),
            ..self
        }
    }

    pub fn with_chain_id(self, chain_id: ChainId) -> Self {
        Self {
            chain_id: Some(chain_id),
            ..self
        }
    }

    pub fn build(self) -> Result<SmrTransactionHeader, SmrTransactionHeaderBuilderError> {
        let error_msg = if self.sender.is_none() {
            "Sender"
        } else if self.sequence_number.is_none() {
            "SequenceNumber"
        } else if self.gas_unit_price.is_none() {
            "GasUnitPrice"
        } else if self.max_gas_amount.is_none() {
            "MaxGasAmount"
        } else if self.expiration_timestamp.is_none() {
            "ExpirationTimestamp"
        } else if self.expiration_timestamp.as_ref().unwrap().is_past() {
            return invalid_value("Transaction has already expired.");
        } else if self.chain_id.is_none() {
            "ChainId"
        } else {
            ""
        };
        if !error_msg.is_empty() {
            return missing_field(error_msg);
        }
        Ok(SmrTransactionHeader {
            sender: self.sender.unwrap(),
            sequence_number: self.sequence_number.unwrap(),
            gas_unit_price: self.gas_unit_price.unwrap(),
            max_gas_amount: self.max_gas_amount.unwrap(),
            expiration_timestamp: self.expiration_timestamp.unwrap(),
            chain_id: self.chain_id.unwrap(),
        })
    }
}

impl Default for SmrTransactionHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Borrows only most permanent information such as sender, gas-price and amount and chain-id
impl From<&SmrTransactionHeader> for SmrTransactionHeaderBuilder {
    fn from(value: &SmrTransactionHeader) -> Self {
        Self {
            sender: Some(value.sender),
            sequence_number: None,
            gas_unit_price: Some(value.gas_unit_price),
            max_gas_amount: Some(value.max_gas_amount),
            expiration_timestamp: None,
            chain_id: Some(value.chain_id),
        }
    }
}

#[derive(Error, Debug)]
pub enum SmrTransactionHeaderBuilderError {
    #[error("Invalid transaction header value: {0}.")]
    InvalidValue(String),
    #[error("Missing SmrTransactionHeader required field: {0}.")]
    MissingField(String),
}

fn invalid_value(msg: &str) -> Result<SmrTransactionHeader, SmrTransactionHeaderBuilderError> {
    Err(SmrTransactionHeaderBuilderError::InvalidValue(
        msg.to_string(),
    ))
}

fn missing_field(msg: &str) -> Result<SmrTransactionHeader, SmrTransactionHeaderBuilderError> {
    Err(SmrTransactionHeaderBuilderError::MissingField(
        msg.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use crate::sosmr_types::transactions::header::SmrTransactionHeaderBuilder;
    use crate::sosmr_types::{
        AccountAddress, SmrTimestamp, SmrTransactionHeader, TTransactionHeaderProperties,
    };

    #[test]
    fn check_smr_transaction_header_build() {
        let builder = SmrTransactionHeaderBuilder::new();
        let builder = builder.with_sender(AccountAddress::random_supra());
        assert!(builder.clone().build().is_err());

        let builder = builder.with_sequence_number(5);
        assert!(builder.clone().build().is_err());

        let builder = builder.with_gas_price(10);
        assert!(builder.clone().build().is_err());

        let builder = builder.with_max_gas_amount(12);
        assert!(builder.clone().build().is_err());

        let builder = builder.with_expiration_timestamp(SmrTimestamp::seconds_from_now(60));
        assert!(builder.clone().build().is_err());

        let builder = builder.with_chain_id(1);
        assert!(builder.clone().build().is_ok());

        let testnet_valid_max_gas_amount = builder.clone().with_max_gas_amount(0);
        assert!(testnet_valid_max_gas_amount.build().is_ok());

        // Ensure that the builder will not construct a header with a timestamp that has expired.
        let expired_timestamp = builder
            .clone()
            .with_expiration_timestamp(SmrTimestamp::new_from(456789));
        assert!(expired_timestamp.build().is_err());
    }

    #[test]
    fn check_header_timestamp_expiry() {
        // Ensure that we can construct a header with a timestamp in the past.
        let expired_timestamp = SmrTimestamp::new_from(456789);
        let sender = AccountAddress::random_supra();
        let sequence_number = 7;
        let gas_unit_price = 10;
        let max_gas_amount = 200;
        let chain_id = 5;
        let header = SmrTransactionHeader::new(
            sender,
            sequence_number,
            gas_unit_price,
            max_gas_amount,
            expired_timestamp,
            chain_id,
        );
        // And that it correctly reports itself as having expired.
        assert!(header.is_expired());
    }
}
