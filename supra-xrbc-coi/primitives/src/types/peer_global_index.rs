use crate::ClanIdentifier;
use std::fmt::{Display, Formatter};

///
/// Describes peer's 3D position in the chain
///     - tribe index
///     - clan index in the tribe
///     - position in the clan
///
#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq)]
pub struct PeerGlobalIndex {
    clan_identifier: ClanIdentifier,
    position: usize,
}

impl Display for PeerGlobalIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PeerGlobalIndex ({}, {}, {})",
            self.clan_identifier.tribe, self.clan_identifier.clan, self.position
        )
    }
}

impl PeerGlobalIndex {
    pub fn new(tribe: usize, clan: usize, position: usize) -> Self {
        Self {
            clan_identifier: ClanIdentifier::new(tribe, clan),
            position,
        }
    }

    pub fn in_clan_at_position(clan_identifier: ClanIdentifier, position: usize) -> Self {
        Self {
            clan_identifier,
            position,
        }
    }

    pub fn tribe(&self) -> usize {
        self.clan_identifier.tribe
    }

    pub fn clan(&self) -> usize {
        self.clan_identifier.clan
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn clan_identifier(&self) -> ClanIdentifier {
        self.clan_identifier
    }

    ///
    /// Returns flattened index in single node-axis system assuming PeerGlobalIndex represents node's
    /// 3D cartesian coordinate in (Tribe, Clan, Node) system
    ///
    pub fn flatten(&self, clans_in_tribe: usize, clan_size: usize) -> Option<usize> {
        (clans_in_tribe > self.clan() && clan_size > self.position).then(|| {
            self.clan_identifier.flatten(clans_in_tribe).unwrap() * clan_size + self.position
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClanIdentifier, PeerGlobalIndex};

    #[test]
    fn check_peer_global_index() {
        let global_index = PeerGlobalIndex::new(1, 2, 3);
        assert_eq!(global_index.tribe(), 1);
        assert_eq!(global_index.clan(), 2);
        assert_eq!(global_index.position(), 3);
        assert_eq!(global_index.clan_identifier(), ClanIdentifier::new(1, 2));
    }

    #[test]
    fn check_global_index_flatten() {
        let global_index = PeerGlobalIndex::new(3, 5, 6);

        // wrong # of clan in tribes
        assert!(global_index.flatten(3, 7).is_none());

        // wrong clan size in tribes
        assert!(global_index.flatten(6, 3).is_none());

        let result = global_index.flatten(6, 7);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), (3 * 6 + 5) * 7 + 6);
    }
}
