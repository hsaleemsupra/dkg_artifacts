use erasure::utils::errors::FECError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("Not enough chunk to proceed")]
    NotMerkleRoot,
    #[error("Not enough chunk to proceed")]
    EmptyMerkleTree,
    #[error("{0}")]
    FECError(#[from] FECError),
    #[error("{0}")]
    MerkleProofError(String),
}
