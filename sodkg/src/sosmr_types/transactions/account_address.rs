//! Defines account address of the transaction sender

use hex::FromHexError;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use soserde::HexHumanReadableSerdeWithPrefix;
use std::array::TryFromSliceError;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct ConstSizeAddress<const N: usize>(
    #[serde(with = "HexHumanReadableSerdeWithPrefix")] [u8; N],
);

impl<const N: usize> ConstSizeAddress<N> {
    pub const LENGTH: usize = N;

    /// Provides random account address.
    pub fn random() -> Self {
        let mut inner = [0; N];
        thread_rng().fill_bytes(&mut inner);
        Self(inner)
    }

    /// Converts to inner representation of bytes.
    pub fn into_bytes(self) -> [u8; N] {
        self.0
    }

    /// Tries to construct [ConstSizeAddress] from bytes.
    pub fn from_bytes<T: AsRef<[u8]> + ?Sized>(slice: &T) -> Result<Self, AccountAddressError> {
        <[u8; N]>::try_from(slice.as_ref())
            .map_err(AccountAddressError::FromSlice)
            .map(Self)
    }
}

impl<const N: usize> From<ConstSizeAddress<N>> for String {
    fn from(value: ConstSizeAddress<N>) -> Self {
        String::from(&value)
    }
}

impl<const N: usize> From<&ConstSizeAddress<N>> for String {
    fn from(value: &ConstSizeAddress<N>) -> Self {
        hex::encode(value)
    }
}

impl<const N: usize> FromStr for ConstSizeAddress<N> {
    type Err = AccountAddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Strip the leading '0x' if the string is in human-readable format.
        let hex = if let Some(formatted_hex) = value.strip_prefix("0x") {
            formatted_hex
        } else {
            value
        };
        let digest = hex::decode(hex)?;
        ConstSizeAddress::<N>::from_bytes(&digest)
    }
}

impl<const N: usize> TryFrom<String> for ConstSizeAddress<N> {
    type Error = AccountAddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(value.as_str())
    }
}

impl<const N: usize> Deref for ConstSizeAddress<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for ConstSizeAddress<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Supra chain account address length in bytes
pub const SUPRA_ACCOUNT_SIZE: usize = 32;
/// Move transaction  account address length in bytes
pub const MOVE_ACCOUNT_SIZE: usize = 32;
/// EVM transaction  account address length in bytes
pub const EVM_ACCOUNT_SIZE: usize = 20;

/// Generic representation of the account-addresses supported by the supra-chain.
#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Clone, Copy, Deserialize, Serialize, ToSchema)]
pub enum AccountAddress {
    /// Supra 32 byte account address
    #[schema(value_type = String)]
    Supra(ConstSizeAddress<SUPRA_ACCOUNT_SIZE>),
    /// Move 32 byte account address
    #[schema(value_type = String)]
    Move(ConstSizeAddress<MOVE_ACCOUNT_SIZE>),
    /// Evm 20 byte account address
    #[schema(value_type = String)]
    Evm(ConstSizeAddress<EVM_ACCOUNT_SIZE>),
}

impl AccountAddress {
    /// Provides random supra chain account address .
    pub fn random_supra() -> Self {
        Self::Supra(ConstSizeAddress::<SUPRA_ACCOUNT_SIZE>::random())
    }

    /// Provides random MOVE account address in scope of supra chain.
    pub fn random_move() -> Self {
        Self::Move(ConstSizeAddress::<MOVE_ACCOUNT_SIZE>::random())
    }

    /// Provides random EVM account address in scope of supra chain.
    pub fn random_evm() -> Self {
        Self::Evm(ConstSizeAddress::<EVM_ACCOUNT_SIZE>::random())
    }

    pub const fn length(&self) -> usize {
        match self {
            AccountAddress::Supra(_) => SUPRA_ACCOUNT_SIZE,
            AccountAddress::Move(_) => MOVE_ACCOUNT_SIZE,
            AccountAddress::Evm(_) => EVM_ACCOUNT_SIZE,
        }
    }

    pub fn is_move(&self) -> bool {
        matches!(self, Self::Move(_))
    }
    pub fn is_supra(&self) -> bool {
        matches!(self, Self::Supra(_))
    }
    pub fn is_evm(&self) -> bool {
        matches!(self, Self::Evm(_))
    }

    pub fn supra_address(value: [u8; SUPRA_ACCOUNT_SIZE]) -> Self {
        AccountAddress::Supra(ConstSizeAddress::<SUPRA_ACCOUNT_SIZE>(value))
    }

    pub fn move_address(value: [u8; MOVE_ACCOUNT_SIZE]) -> Self {
        AccountAddress::Move(ConstSizeAddress::<MOVE_ACCOUNT_SIZE>(value))
    }

    pub fn evm_address(value: [u8; EVM_ACCOUNT_SIZE]) -> Self {
        AccountAddress::Evm(ConstSizeAddress::<EVM_ACCOUNT_SIZE>(value))
    }
}

impl AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] {
        match self {
            AccountAddress::Supra(inner) => inner.as_ref(),
            AccountAddress::Move(inner) => inner.as_ref(),
            AccountAddress::Evm(inner) => inner.as_ref(),
        }
    }
}

impl Debug for AccountAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            AccountAddress::Supra(inner) => format!("Supra({})", String::from(inner)),
            AccountAddress::Move(inner) => format!("Move({})", String::from(inner)),
            AccountAddress::Evm(inner) => format!("Evm({})", String::from(inner)),
        };
        write!(f, "AccountAddress::{}", value)
    }
}

impl Display for AccountAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Error, Debug)]
pub enum AccountAddressError {
    /// Hex decoder error
    #[error("HexDecode: {0}")]
    HexDecode(#[from] FromHexError),

    /// Invalid slice error.
    #[error("FromSlice: {0}")]
    FromSlice(#[from] TryFromSliceError),
}

#[cfg(test)]
mod tests {
    use crate::sosmr_types::transactions::account_address::{
        AccountAddressError, ConstSizeAddress, EVM_ACCOUNT_SIZE, MOVE_ACCOUNT_SIZE,
        SUPRA_ACCOUNT_SIZE,
    };
    use crate::sosmr_types::{AccountAddress, SmrDeserialize, SmrSerialize};
    use std::str::FromStr;

    #[test]
    fn check_const_size_address_json_serde() {
        type Address14 = ConstSizeAddress<14>;
        let test_address = Address14::random();
        let address_string: String = String::from(&test_address);
        let address_string_with_prefix = format!("0x{}", address_string);
        let address_hex = hex::encode(test_address);
        let address_json = serde_json::to_string(&test_address).unwrap();
        let address_string_from_json: String = serde_json::from_str(&address_json).unwrap();
        assert_eq!(address_string, address_hex);
        assert_eq!(address_string_with_prefix, address_string_from_json);
    }

    #[test]
    fn check_const_size_address_bytes_serde() {
        type Address14 = ConstSizeAddress<14>;
        let test_address = Address14::random();
        let bcs_bytes = test_address.to_bytes();
        let address_from_bcs_bytes = Address14::try_from_bytes(&bcs_bytes)
            .expect("Deserialization of bcs bytes should succeed.");
        assert_eq!(address_from_bcs_bytes.0, test_address.0);
    }

    #[test]
    fn check_account_address_conversions() {
        type Address14 = ConstSizeAddress<14>;
        let acc1 = Address14::random();

        assert_eq!(acc1.into_bytes().len(), Address14::LENGTH);
        let acc1_str: String = acc1.into();
        let _acc1_from_str: Address14 = Address14::try_from(acc1_str)
            .expect("Successful account address construction from string");

        let short_acc_inner = [0u8; 13];
        let short_acc_str = hex::encode(short_acc_inner);
        let short_acc_res = Address14::from_bytes(&short_acc_inner);
        assert!(matches!(
            short_acc_res,
            Err(AccountAddressError::FromSlice(_))
        ));

        let short_acc_res = Address14::try_from(short_acc_str);
        assert!(matches!(
            short_acc_res,
            Err(AccountAddressError::FromSlice(_))
        ));

        let long_acc_inner = [0u8; 36];
        let long_acc_str = hex::encode(long_acc_inner);
        let long_acc_res = Address14::from_bytes(&long_acc_inner);
        assert!(matches!(
            long_acc_res,
            Err(AccountAddressError::FromSlice(_))
        ));
        let long_acc_res = Address14::try_from(long_acc_str);
        assert!(matches!(
            long_acc_res,
            Err(AccountAddressError::FromSlice(_))
        ));

        let random_str = "askd3askjasdkjf";
        let random_acc_res = Address14::from_str(random_str);
        assert!(matches!(
            random_acc_res,
            Err(AccountAddressError::HexDecode(_))
        ));
    }

    #[test]
    fn account_address_api_checks() {
        let check =
            |supra_acc: AccountAddress, move_acc: AccountAddress, evm_acc: AccountAddress| {
                assert!(supra_acc.is_supra());
                assert!(move_acc.is_move());
                assert!(evm_acc.is_evm());
                assert_eq!(supra_acc.length(), SUPRA_ACCOUNT_SIZE);
                assert_eq!(move_acc.length(), MOVE_ACCOUNT_SIZE);
                assert_eq!(evm_acc.length(), EVM_ACCOUNT_SIZE);
            };

        let supra_acc = AccountAddress::random_supra();
        let move_acc = AccountAddress::random_move();
        let evm_acc = AccountAddress::random_evm();
        check(supra_acc, move_acc, evm_acc);

        let supra_acc = AccountAddress::supra_address([5; SUPRA_ACCOUNT_SIZE]);
        let move_acc = AccountAddress::move_address([4; MOVE_ACCOUNT_SIZE]);
        let evm_acc = AccountAddress::evm_address([3; EVM_ACCOUNT_SIZE]);
        check(supra_acc, move_acc, evm_acc);
    }
}
