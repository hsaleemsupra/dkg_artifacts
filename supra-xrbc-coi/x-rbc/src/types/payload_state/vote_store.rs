use crypto::PartialShare;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};

pub(crate) struct VoteStore {
    inner: VoteState,
}

enum VoteState {
    Collecting(HashMap<u32, PartialShare>),
    Collected(HashSet<u32>),
}

impl Display for VoteStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl Display for VoteState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            VoteState::Collecting(data) => {
                for (k, v) in data {
                    writeln!(f, "{} > {}", k, v)?
                }
                writeln!(f)
            }
            VoteState::Collected(data) => {
                writeln!(f, "{:?}", data)
            }
        }
    }
}

impl Debug for VoteStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Default for VoteStore {
    fn default() -> Self {
        let collection = HashMap::new();
        Self {
            inner: VoteState::Collecting(collection),
        }
    }
}

impl VoteStore {
    fn inner(&self) -> &VoteState {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut VoteState {
        &mut self.inner
    }

    pub(crate) fn add_vote(&mut self, vote: PartialShare) {
        match self.inner_mut() {
            VoteState::Collecting(collection) => {
                collection.insert(vote.index(), vote);
            }
            VoteState::Collected(collection) => {
                collection.insert(vote.index());
            }
        };
    }

    pub(crate) fn has_vote(&self, index: &u32) -> bool {
        match self.inner() {
            VoteState::Collecting(collection) => collection.contains_key(index),
            VoteState::Collected(collection) => collection.contains(index),
        }
    }

    pub(crate) fn collect(&mut self) -> Option<Vec<PartialShare>> {
        match self.inner_mut() {
            VoteState::Collecting(collection) => {
                let mut aux_map = HashMap::new();
                std::mem::swap(&mut aux_map, collection);
                let set = HashSet::<u32>::from_iter(aux_map.clone().into_keys());
                self.inner = VoteState::Collected(set);
                Some(Vec::from_iter(aux_map.into_values()))
            }
            VoteState::Collected(_) => None,
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self.inner() {
            VoteState::Collecting(collection) => collection.len(),
            VoteState::Collected(collection) => collection.len(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        match self.inner() {
            VoteState::Collecting(collection) => collection.is_empty(),
            VoteState::Collected(collection) => collection.is_empty(),
        }
    }

    pub(crate) fn is_collected(&self) -> bool {
        match self.inner() {
            VoteState::Collecting(_) => false,
            VoteState::Collected(_) => true,
        }
    }

    pub(crate) fn get_vote(&self, idx: u32) -> Option<PartialShare> {
        match &self.inner {
            VoteState::Collecting(data) => data.get(&idx).cloned(),
            VoteState::Collected(_) => None,
        }
    }
}
