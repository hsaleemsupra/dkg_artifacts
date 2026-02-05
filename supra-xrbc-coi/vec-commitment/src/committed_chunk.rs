use crate::errors::CommitmentError;
use crate::merkle_util::{Keccak256algorithm, MerkleUtil};
use erasure::utils::codec_trait::Chunk;
use primitives::HASH32;
use rs_merkle::{Hasher, MerkleProof};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

///
/// Meta information of the commitment in the commitment vector
///
#[derive(Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct CommitmentMeta {
    /// Index of the chunk in the commitment vector
    index: usize,
    /// Commitment proof for the data in commitment vector
    proof: Vec<u8>,
    /// Hash of the committed data
    hash: HASH32,
}

impl Debug for CommitmentMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Display for CommitmentMeta {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommitmentMeta ({})", self.index)
    }
}

impl CommitmentMeta {
    pub fn new(index: usize, proof: Vec<u8>, hash: HASH32) -> Self {
        Self { index, proof, hash }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn proof(&self) -> &Vec<u8> {
        &self.proof
    }

    fn hash(&self) -> &HASH32 {
        &self.hash
    }

    pub fn verify(&self, merkle_root: HASH32, leave_count: usize) -> Result<bool, CommitmentError> {
        if self.proof.is_empty() {
            return Err(CommitmentError::MerkleProofError("Empty proof".to_string()));
        }
        let proof = MerkleProof::<Keccak256algorithm>::try_from(self.proof.clone())
            .map_err(|e| CommitmentError::MerkleProofError(e.to_string()))?;
        Ok(proof.verify(merkle_root, &[self.index()], &[*self.hash()], leave_count))
    }

    pub fn split(self) -> (usize, Vec<u8>) {
        (self.index, self.proof)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedChunk<CHUNK: Chunk> {
    index: usize,
    proof: Vec<u8>,
    #[serde(deserialize_with = "CHUNK::deserialize_wrapper")]
    chunk: CHUNK,
}

impl<CHUNK: Chunk + Default> CommittedChunk<CHUNK> {
    pub fn new(index: usize, proof: Vec<u8>, chunk: CHUNK) -> Self {
        Self {
            index,
            proof,
            chunk,
        }
    }

    pub fn get_hash(&self) -> HASH32 {
        Keccak256algorithm::hash(self.chunk.byte_chunk_ref())
    }

    pub fn get_meta(&self) -> CommitmentMeta {
        CommitmentMeta::new(self.index, self.proof.clone(), self.get_hash())
    }

    pub fn get_commitment_index(&self) -> usize {
        self.index
    }

    pub fn get_chunk_index(&self) -> usize {
        self.chunk.get_chunk_index()
    }

    pub fn take_chunk(&mut self) -> CHUNK {
        std::mem::take(&mut self.chunk)
    }

    pub fn commit_chunk_list(batch: Vec<CHUNK>) -> Result<(HASH32, Vec<Self>), CommitmentError> {
        let merkle_tree = MerkleUtil::<Keccak256algorithm, CHUNK>::create_tree(batch.iter())?;

        let merkle_root = merkle_tree.root();

        Ok((
            merkle_root,
            batch
                .into_iter()
                .enumerate()
                .map(|(index, chunk)| {
                    let proof = merkle_tree.generate_prove(&[index]);
                    Self {
                        proof,
                        index,
                        chunk,
                    }
                })
                .collect::<Vec<Self>>(),
        ))
    }

    pub fn split(self) -> (usize, Vec<u8>, CHUNK) {
        (self.index, self.proof, self.chunk)
    }

    pub fn verify(
        &self,
        merkle_root: HASH32,
        merkle_leaves_count: usize,
    ) -> Result<bool, CommitmentError> {
        if self.proof.is_empty() {
            return Err(CommitmentError::MerkleProofError("Empty proof".to_string()));
        }
        let proof = MerkleProof::<Keccak256algorithm>::try_from(self.proof.clone())
            .map_err(|e| CommitmentError::MerkleProofError(e.to_string()))?;
        Ok(proof.verify(
            merkle_root,
            &[self.get_commitment_index()],
            &[self.get_hash()],
            merkle_leaves_count,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::committed_chunk::{CommitmentMeta, CommittedChunk};
    use crate::txn_generator::GeneratorType;
    use erasure::codecs::rs16::{Rs16Chunk, Rs16Codec, Rs16Settings};
    use erasure::codecs::rs8::Rs8Chunk;
    use erasure::utils::codec_trait::{Chunk, Codec, Setting};
    use primitives::serde::{bincode_deserialize, bincode_serializer};
    use rand::prelude::SliceRandom;

    #[test]
    fn test_committed_chunk_ifc() {
        let rs8_chunk = Rs8Chunk::new(2, vec![5; 64], 256);
        let mut committed_chunk = CommittedChunk::<Rs8Chunk>::new(10, vec![], rs8_chunk.clone());
        assert_eq!(committed_chunk.get_chunk_index(), 2);
        assert_eq!(committed_chunk.get_commitment_index(), 10);

        let chunk = committed_chunk.take_chunk();
        assert!(!chunk.byte_chunk_ref().is_empty());
        assert_eq!(chunk, rs8_chunk);
        assert_eq!(committed_chunk.get_chunk_index(), 0);

        let chunk = committed_chunk.take_chunk();
        assert!(chunk.byte_chunk_ref().is_empty());

        let committed_chunk = CommittedChunk::<Rs8Chunk>::new(10, vec![], rs8_chunk.clone());
        let hash = committed_chunk.get_hash();
        let meta = committed_chunk.get_meta();
        assert_eq!(&hash, meta.hash());
        assert_eq!(committed_chunk.get_commitment_index(), meta.index());
        assert_eq!(&committed_chunk.proof, meta.proof());

        let (index, proof) = meta.split();
        assert_eq!(committed_chunk.get_commitment_index(), index);
        assert_eq!(committed_chunk.proof, proof);
    }

    #[test]
    fn test_get_root_and_index_work() {
        let b1 = GeneratorType::Gibberish.spawn_the_generator(100, 5);
        let original_data = bincode::serialize(&b1).unwrap();

        let n = 10;
        let k = 5;

        let chunks = Rs16Codec::encode(Rs16Settings::new(n, k), original_data.clone())
            .expect("Successfully encoded chunks");
        assert_eq!(chunks.len(), n + k);

        let (root, mut committed_chunks) =
            CommittedChunk::commit_chunk_list(chunks).expect("Successfully committed chunk");
        assert_eq!(committed_chunks.len(), n + k);

        // packet loss in transfer medium
        let mut rng = rand::thread_rng();
        committed_chunks.shuffle(&mut rng);
        committed_chunks.truncate(n);

        // receiver side
        let mut decoder = Rs16Codec::default();
        let mut flag = false;
        for r in committed_chunks.iter_mut() {
            if r.verify(root, n + k).unwrap() {
                decoder
                    .feed(r.take_chunk())
                    .expect("Successful consumption of chunk");
                let result = decoder.decode(Rs16Settings::new(n, k));
                if result.is_ok() {
                    assert_eq!(original_data, result.unwrap());
                    flag = true;
                    break;
                }
            }
        }
        assert!(flag);
    }

    #[test]
    fn test_serde() {
        let b1 = GeneratorType::Gibberish.spawn_the_generator(100, 5);
        let original_data = bincode::serialize(&b1).unwrap();

        let n = 10;
        let k = 5;

        let result = Rs16Codec::encode(Rs16Settings::new(n, k), original_data);
        assert!(result.is_ok());

        let (root, received_packets) = CommittedChunk::commit_chunk_list(result.unwrap()).unwrap();

        let raw_committed_chunk =
            bincode_serializer(&received_packets[0]).expect("Successful serialization");
        let de_serialized_chunk: CommittedChunk<Rs16Chunk> =
            bincode_deserialize(raw_committed_chunk.as_ref()).expect("Successful deserialize");
        assert_eq!(de_serialized_chunk.index, received_packets[0].index);
        assert_eq!(de_serialized_chunk.proof, received_packets[0].proof);
        let verify_result = de_serialized_chunk.verify(root, 15);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    #[test]
    fn test_commitment_proof() {
        let b1 = GeneratorType::Gibberish.spawn_the_generator(100, 5);
        let original_data = bincode::serialize(&b1).unwrap();

        let n = 10;
        let k = 5;

        let result = Rs16Codec::encode(Rs16Settings::new(n, k), original_data);
        assert!(result.is_ok());

        let (root, received_packets) = CommittedChunk::commit_chunk_list(result.unwrap()).unwrap();

        let first = received_packets.get(0).unwrap();

        let meta = first.get_meta();

        let mut invalid_meta = meta.clone();
        invalid_meta.hash = [0; 32];

        // valid hash
        let res = meta.verify(root, n + k);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res);

        // valid hash
        let res = invalid_meta.verify(root, n + k);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(!res);

        // empty proof
        let empty_proof = CommitmentMeta::new(1, vec![], [5; 32]);
        assert!(empty_proof.verify([1; 32], 5).is_err());
    }
}
