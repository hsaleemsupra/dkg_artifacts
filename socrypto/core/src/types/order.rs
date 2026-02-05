//! Defines order of the party in the set

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Represents identity order in scope of public-parameter set
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Copy, Default)]
pub struct Order(pub(crate) u16);

impl Order {
    /// Returns inner value as usize to be used as random access index.
    pub fn index(&self) -> usize {
        self.0 as usize
    }
}

impl Display for Order {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for Order {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl AsRef<u16> for Order {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl From<usize> for Order {
    fn from(value: usize) -> Self {
        Order(value as u16)
    }
}

impl From<Order> for usize {
    fn from(value: Order) -> Self {
        value.0 as usize
    }
}
