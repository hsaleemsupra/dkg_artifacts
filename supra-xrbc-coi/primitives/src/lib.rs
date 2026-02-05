pub mod crypto;
pub mod error;
pub mod placeholders;
pub mod serde;
pub mod types;

use std::fmt::Debug;
pub use types::clan_identifier::ClanIdentifier;
pub use types::peer_global_index::PeerGlobalIndex;

use crate::error::CommonError;
use ::serde::{Deserialize, Serialize};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub trait Stringify: AsRef<[u8]> {
    fn hex_display(&self) -> String {
        hex::encode(self)[..7].to_string()
    }
}

// Primitive types
pub type Payload = Vec<u8>;
pub type HASH32 = [u8; 32];
pub type HASH48 = [u8; 48];
pub type HASH64 = [u8; 64];
pub type HASH96 = [u8; 96];

impl Stringify for HASH32 {}

impl Stringify for HASH48 {}

impl Stringify for HASH64 {}

impl Stringify for HASH96 {}

pub type Address = SocketAddr;
pub type Addresses = Vec<Address>;

/// Public Key of the node
pub type Origin = HASH32;

/// Public Key of the clan
pub type ClanOrigin = HASH48;

/// Data  Identifier
pub type ID = HASH64;

///
/// Unbound receiver channel
///
pub type RxChannel<T> = UnboundedReceiver<T>;
///
/// Unbound sender channel
///
pub type TxChannel<T> = UnboundedSender<T>;

///
/// Single Shot channel used to send one-time notifications
///
pub type NotificationSender<T> = tokio::sync::oneshot::Sender<T>;

///
/// Single Shot channel used to receive one-time notifications
///
pub type NotificationReceiver<T> = tokio::sync::oneshot::Receiver<T>;

pub const MIN_PORT: u16 = 1024;
/// Checks whether input port is in acceptable range
pub fn is_valid_port(port_number: &u16) -> bool {
    *port_number >= MIN_PORT
}

///
/// Protocol
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum Protocol {
    XRBC = 0,
    COI = 1,
}

impl Protocol {
    pub fn index(&self) -> usize {
        *self as usize
    }
}

#[derive(Serialize, Deserialize)]
pub struct FaultyNodeIdentifier {
    pub tribe: usize,
    pub clan: usize,
    pub position: usize,
}

impl FaultyNodeIdentifier {
    pub fn new(tribe: usize, clan: usize, position: usize) -> Self {
        Self {
            tribe,
            clan,
            position,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{is_valid_port, Protocol};

    #[test]
    fn check_is_valid_port() {
        assert!(!is_valid_port(&1023));
        assert!(is_valid_port(&1024));
        assert!(is_valid_port(&65347));
    }

    #[test]
    fn check_protocol_index() {
        assert_eq!(Protocol::XRBC.index(), 0);
        assert_eq!(Protocol::COI.index(), 1);
    }
}

pub trait Subscriber<T: Debug>: Send + Sync + Clone {
    fn send(&self, msg: T) -> Result<(), CommonError>;
}
