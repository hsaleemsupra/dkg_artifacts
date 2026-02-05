use erasure::codecs::rs8::Rs8Chunk;
use primitives::serde::{bincode_deserialize, bincode_serializer};
use vec_commitment::committed_chunk::CommittedChunk;
use socrypto::{Hash, Identity, HASH_LENGTH};
use crate::errors::CSDeliverError;
use crate::serde::{read_vector, write_vector};
use tiny_keccak::{Hasher, Keccak};
use std::hash::{Hash as StdHash, Hasher as StdHashHasher};
use ed25519_dalek::{
    Signature
};

#[derive(Debug, Clone)]
pub struct Codeword {
    pub sender: Identity,
    pub chunk_with_merkle_proof: CommittedChunk<Rs8Chunk>,
    pub merkle_root: Hash
}

impl Codeword {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_vector(&mut final_bytes, <Identity as AsRef<[u8]>>::as_ref(&self.sender).to_vec());
        let raw_committed_chunk =
            bincode_serializer(&self.chunk_with_merkle_proof).expect("codeword serialization error!");
        write_vector(&mut final_bytes, raw_committed_chunk.to_vec());
        write_vector(&mut final_bytes, self.merkle_root.to_vec());
        final_bytes
    }

    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        let raw_committed_chunk =
            bincode_serializer(&self.chunk_with_merkle_proof).expect("codeword serialization error!");
        hasher.update(raw_committed_chunk.iter().as_slice());
        hasher.update(self.merkle_root.as_slice());
        hasher.finalize(&mut output);
        Hash(output)
    }
}

impl TryFrom<&[u8]> for Codeword {
    type Error = CSDeliverError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(value);
        let identity_bytes = read_vector(&mut cursor)?;
        let commited_chunk_bytes = read_vector(&mut cursor)?;
        let root_bytes = read_vector(&mut cursor)?;

        let identity = Identity::new(identity_bytes);
        let mut merkle_root_arr = [0u8; HASH_LENGTH];
        merkle_root_arr.copy_from_slice(&root_bytes);
        let deserialized_chunk: CommittedChunk<Rs8Chunk> =
            bincode_deserialize(commited_chunk_bytes.as_ref()).map_err(|_| CSDeliverError::DeserializationError("CommitedChunk bytes are not valid".into()))?;

        Ok(Self {
            sender: identity,
            chunk_with_merkle_proof: deserialized_chunk,
            merkle_root: Hash::from(merkle_root_arr),
        })
    }
}

impl Eq for Codeword {}

impl PartialEq<Self> for Codeword {
    fn eq(&self, other: &Self) -> bool {
        self.chunk_with_merkle_proof == other.chunk_with_merkle_proof
            && self.merkle_root == other.merkle_root
    }
}

#[derive(Debug, Clone)]
pub struct CodewordWithSignature {
    pub codeword: Codeword,
    pub signature: Signature,
}

impl CodewordWithSignature {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_vector(&mut final_bytes, self.codeword.to_vec());
        write_vector(&mut final_bytes, self.signature.to_bytes().to_vec());
        final_bytes
    }
}

impl TryFrom<&[u8]> for CodewordWithSignature {
    type Error = CSDeliverError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(value);
        let codeword_bytes = read_vector(&mut cursor)?;
        let signature_bytes = read_vector(&mut cursor)?;

        let codeword = Codeword::try_from(codeword_bytes.as_slice())
            .map_err(|_| CSDeliverError::DeserializationError("Codeword bytes are not valid".into()))?;
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| CSDeliverError::DeserializationError("Signature bytes are not valid".into()))?;

        Ok(Self {
            codeword,
            signature,
        })
    }
}

impl Eq for CodewordWithSignature {}

impl PartialEq<Self> for CodewordWithSignature {
    fn eq(&self, other: &Self) -> bool {
        self.codeword == other.codeword
    }
}

/*impl Ord for Codeword {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.signature.cmp(&other.signature) {
            Ordering::Equal => {
                match self.chunk_with_merkle_proof.cmp(&other.chunk_with_merkle_proof) {
                    Ordering::Equal => {self.chunk_with_merkle_proof.get_commitment_index().cmp(&other.chunk_with_merkle_proof.get_commitment_index())}
                    ordering => ordering,
                }
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
}*/


impl StdHash for CodewordWithSignature {
    fn hash<H: StdHashHasher>(&self, state: &mut H) {
        // 1) Call your cryptographic hash function, which produces a 32-byte output
        let cryptohash = self.codeword.hash(); // returns `Hash([u8; 32])`

        // 2) Feed those 32 bytes into the standard library's Hasher
        state.write(cryptohash.as_ref());
    }
}