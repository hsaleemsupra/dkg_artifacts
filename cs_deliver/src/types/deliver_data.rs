use std::cmp::Ordering;
use ed25519_dalek::{
    VerifyingKey as PublicKey,
};

/// Encloses properties describing Deliver process state of the committee member for the local node
#[derive(Clone)]
pub(crate) struct CSDeliverData {
    /// Index/position of the node in scope of the committee. Nodes are ordered based on their identity.
    pub(crate) node_number: u32,
    /// Public Key for signature verification
    pub(crate) public_key: PublicKey,
}

impl CSDeliverData {
    pub(crate) fn new(node_number: u32, public_key: PublicKey) -> CSDeliverData {
        CSDeliverData {
            public_key,
            node_number,
        }
    }
}

impl PartialEq for CSDeliverData {
    fn eq(&self, other: &Self) -> bool {
        self.node_number == other.node_number
    }
}

impl PartialOrd for CSDeliverData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.node_number.cmp(&other.node_number))
    }
}

impl Ord for CSDeliverData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.node_number.cmp(&other.node_number)
    }
}

impl Eq for CSDeliverData {}
