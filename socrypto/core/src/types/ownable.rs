/// Generic API to generate and proof that the provider of the public info/data also owns
/// the private half of the info/data.
pub trait Ownable {
    /// Type representing public information associated with ownable object.
    type PublicType: Clone + Eq + PartialEq + std::hash::Hash;
    /// Type representing proof of possession.
    type PopType;
    /// Error type reported by API
    type Error;

    /// Generates proof owning private part corresponding to the input public-data.
    fn generate_proof_of_possession(&self, pk: &Self::PublicType) -> Self::PopType;
    /// Verifies proof of possession w.r.t. input public-data.
    fn verify_possession(pk: &Self::PublicType, pop: &Self::PopType) -> Result<(), Self::Error>;
}
