use std::cmp::Ordering;

/// Encloses properties describing Deliver process state of the committee member for the local node
#[derive(Clone)]
pub(crate) struct DeliverData {
    /// Index/position of the node in scope of the committee. Nodes are ordered based on their identity.
    pub(crate) node_number: u32,
}

impl DeliverData {
    pub(crate) fn new(node_number: u32) -> DeliverData {
        DeliverData {
            node_number,
        }
    }
}

impl PartialEq for DeliverData {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl PartialOrd for DeliverData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.identity.cmp(&other.identity))
    }
}

impl Ord for DeliverData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity.cmp(&other.identity)
    }
}

impl Eq for DeliverData {}
