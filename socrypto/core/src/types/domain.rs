/// Trait for unique domain id of signature schema instances
pub trait UniqueDomain {
    /// Get unique domain associated with instance of signature schema
    fn domain<'a>() -> &'a str;
}

// CRYPTO_TODO: maybe implement this in a way that actually guarantees uniqueness
