use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Hash, Clone, Eq, Copy)]
pub struct ClanIdentifier {
    pub tribe: usize,
    pub clan: usize,
}

impl ClanIdentifier {
    pub fn new(tribe_id: usize, clan_id: usize) -> Self {
        Self {
            tribe: tribe_id,
            clan: clan_id,
        }
    }

    ///
    /// Returns clan index in single clan-axis system assuming ClanIdentifier represents clan
    /// cartesian coordinate in (Tribe, Clan) system
    ///
    pub fn flatten(&self, clans_in_tribe: usize) -> Option<usize> {
        (clans_in_tribe > self.clan).then_some(self.tribe * clans_in_tribe + self.clan)
    }
}

impl Display for ClanIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "({}, {})", self.tribe, self.clan)
    }
}

#[cfg(test)]
mod tests {
    use crate::ClanIdentifier;

    #[test]
    fn check_clan_identifier_flatten() {
        let clan_identifier = ClanIdentifier::new(3, 5);

        // wrong # of clan in tribes
        assert!(clan_identifier.flatten(3).is_none());

        // wrong # of clan in tribes
        assert!(clan_identifier.flatten(5).is_none());

        let result = clan_identifier.flatten(6);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 3 * 6 + 5);
    }
}
