use crate::errors::CommitmentError;
use erasure::utils::codec_trait::Chunk;
use primitives::crypto::Hashers;
use primitives::HASH32;
use rs_merkle::{Hasher, MerkleProof, MerkleTree};
use std::marker::PhantomData;
use std::slice::Iter;

#[derive(Clone)]
pub struct Keccak256algorithm;

impl Hasher for Keccak256algorithm {
    type Hash = HASH32;

    fn hash(data: &[u8]) -> Self::Hash {
        Hashers::keccak256(data)
    }
}

pub struct MerkleUtil<HASHER: Hasher, CHUNK: Chunk> {
    root: HASHER::Hash,
    tree: MerkleTree<HASHER>,
    t_marker: PhantomData<CHUNK>,
}

impl<HASHER: Hasher, CHUNK: Chunk> MerkleUtil<HASHER, CHUNK> {
    pub fn create_tree(leaves_data: Iter<CHUNK>) -> Result<Self, CommitmentError> {
        let merkle_leaves_count = leaves_data.len();
        let mut leaves = Vec::with_capacity(merkle_leaves_count);
        leaves_data
            .into_iter()
            .for_each(|chunk| leaves.push(HASHER::hash(chunk.byte_chunk_ref())));
        let tree = MerkleTree::<HASHER>::from_leaves(leaves.as_slice());
        let root = tree.root().ok_or(CommitmentError::NotMerkleRoot)?;
        Ok(Self {
            root,
            tree,
            t_marker: Default::default(),
        })
    }

    pub fn generate_prove(&self, indexes: &[usize]) -> Vec<u8> {
        self.tree.proof(indexes).to_bytes()
    }

    pub fn leaves_count(&self) -> Result<usize, CommitmentError> {
        Ok(self
            .tree
            .leaves()
            .ok_or(CommitmentError::EmptyMerkleTree)?
            .len())
    }

    pub fn root(&self) -> HASHER::Hash {
        self.root
    }

    fn get_proof_from_bytes(
        &self,
        prove_bytes: Vec<u8>,
    ) -> Result<MerkleProof<HASHER>, CommitmentError> {
        MerkleProof::<HASHER>::try_from(prove_bytes)
            .map_err(|e| CommitmentError::MerkleProofError(e.to_string()))
    }

    pub fn verify_proof(
        &self,
        prove_bytes: Vec<u8>,
        leaf_indices: &[usize],
        leaf_items: &[CHUNK],
    ) -> Result<bool, CommitmentError> {
        let total_leaves_count = self.leaves_count()?;
        let proof = self.get_proof_from_bytes(prove_bytes).unwrap();
        let leaf_hashes = leaf_items
            .iter()
            .map(|x| HASHER::hash(x.byte_chunk_ref().as_slice()))
            .collect::<Vec<<HASHER as Hasher>::Hash>>();
        Ok(proof.verify(
            self.root,
            leaf_indices,
            leaf_hashes.as_slice(),
            total_leaves_count,
        ))
    }
}
