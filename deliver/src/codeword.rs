use erasure::codecs::rs8::Rs8Chunk;
use primitives::serde::{bincode_deserialize, bincode_serializer};
use vec_commitment::committed_chunk::CommittedChunk;
use socrypto::{Hash, HASH_LENGTH};
use crate::errors::DeliverError;
use crate::serde::{read_vector, write_vector};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Codeword {
    pub chunk_with_merkle_proof: CommittedChunk<Rs8Chunk>,
    pub merkle_root: Hash
}

impl Codeword {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        let raw_committed_chunk =
            bincode_serializer(&self.chunk_with_merkle_proof).expect("codeword serialization error!");
        write_vector(&mut final_bytes, raw_committed_chunk.to_vec());
        write_vector(&mut final_bytes, self.merkle_root.to_vec());
        final_bytes
    }
}

impl TryFrom<&[u8]> for Codeword {
    type Error = DeliverError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(value);
        let commited_chunk_bytes = read_vector(&mut cursor)?;
        let root_bytes = read_vector(&mut cursor)?;
        let mut merkle_root_arr = [0u8; HASH_LENGTH];
        merkle_root_arr.copy_from_slice(&root_bytes);
        let deserialized_chunk: CommittedChunk<Rs8Chunk> =
            bincode_deserialize(commited_chunk_bytes.as_ref()).map_err(|_| DeliverError::DeserializationError("CommitedChunk bytes are not valid".into()))?;

        Ok(Self {
            chunk_with_merkle_proof: deserialized_chunk,
            merkle_root: Hash::from(merkle_root_arr),
        })
    }
}

impl Ord for Codeword {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare by merkle_root
        match self.merkle_root.cmp(&other.merkle_root) {
            Ordering::Equal => {
                // If merkle_root is equal, compare chunk_with_merkle_proof
                self.chunk_with_merkle_proof.get_commitment_index().cmp(&other.chunk_with_merkle_proof.get_commitment_index())
            }
            ordering => ordering,
        }
    }
}

// You also need PartialOrd, which can be derived or manually implemented to match Ord:
impl PartialOrd for Codeword {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}