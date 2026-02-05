use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use erasure::codecs::rs8::{Rs8Codec, Rs8Settings};
use erasure::utils::codec_trait::{Codec, Setting};
use vec_commitment::committed_chunk::CommittedChunk;
use socrypto::{Hash, Identity};
use crate::codeword::Codeword;
use crate::errors::DeliverError;

pub struct DeliverNode<State> {
    /// Identity of the node in scope of which deliver process has been initiated
    pub(crate) node: Identity,
    /// Number of participants in committee
    /// We use the total number of shards for the erasure coding scheme as num_of_nodes
    pub(crate) num_of_nodes: u32,
    /// Number of byzantine nodes in the committee
    /// The erasure coding scheme splits the data in f+1 shards
    pub(crate) f_byzantine: u32,
    /// Node public keys ordered by their identity.
    pub(crate) committee: BTreeMap<Identity, u32>,
    /// Indicates valid codewords received by a node for each accumulation value (merkle root hash)
    /// indexed by chunk index
    pub(crate) code_words: BTreeMap<Hash,BTreeSet<Codeword>>,
    /// Indicates the reconstructed msg after a node has received enough valid codewords
    /// for the message, indexed by accumulation value (merkle root hash)
    pub reconstructed_data: BTreeMap<Hash,Vec<u8>>,
    pub(crate) state: PhantomData<State>,
}

impl<State> DeliverNode<State> {
    pub(crate) fn identity(&self) -> Identity {
        self.node
    }

    pub(crate) fn generate_data_codewords(&self, data_to_broadcast: &Vec<u8>) -> Result<Vec<Codeword>, DeliverError> {

        let chunks = Rs8Codec::encode(
            Rs8Settings::new(
                (self.f_byzantine+1) as usize,
                (self.num_of_nodes - (self.f_byzantine+1)) as usize),
            data_to_broadcast.clone())
            .map_err(|e| DeliverError::GeneralError(format!("Failed to erasure encode data: {}", e.to_string())))?;

        let (root, committed_chunks) =
            CommittedChunk::commit_chunk_list(chunks)
                .map_err(|e|
                    DeliverError::GeneralError(format!("Failed to create proofs for erasure coded data: {}", e.to_string())))?;

        let mut codeword_msgs = Vec::new();
        committed_chunks.iter().for_each(|commited_chunk| {
            codeword_msgs.push(
                    Codeword{
                        merkle_root: Hash(root.clone()),
                        chunk_with_merkle_proof: commited_chunk.clone()
                    }
                );
        });

        Ok(codeword_msgs)
    }

    pub(crate) fn consume_codeword(&mut self, codeword: Codeword)
        -> Result<bool, DeliverError> {

        // if we received a codeword with this root hash first time
        if !self.code_words.contains_key(&codeword.merkle_root){
            self.code_words.insert(codeword.merkle_root.clone(), BTreeSet::new());
        }

        // if we have already stored this codeword we donot need to do anything
        let msg_codewords = self.code_words.get_mut(&codeword.merkle_root).unwrap();
        if msg_codewords.contains(&codeword){
            return Ok(false);
        }

        // otherwise we can store the codeword if it passes verification
        let res = codeword.chunk_with_merkle_proof
            .verify(codeword.merkle_root.0, self.num_of_nodes as usize)
            .map_err(|e| DeliverError::GeneralError(format!("Failed to verify codeword: {}", e.to_string())))?;

        if res{
            msg_codewords.insert(codeword.clone());
            Ok(true)
        }
        else{
            Err(DeliverError::ChunkVerificationError(codeword.merkle_root))
        }
    }

    pub(crate) fn try_reconstruct_data(&mut self, merkle_root: Hash) -> Result<bool, DeliverError> {

        // if we have already reconstructed data for this merkle_root, we donot need to do anything
        if self.reconstructed_data.contains_key(&merkle_root){
            return Ok(false);
        }

        // if we do not have received any codewords for this merkle_root
        if !self.code_words.contains_key(&merkle_root)
        {
            return Ok(false);
        }

        let msg_codewords = self.code_words.get_mut(&merkle_root).unwrap();

        // if we have received f+1 valid codewords, we can decode the data
        if msg_codewords.len() >= (self.f_byzantine+1) as usize{

            let mut decoder = Rs8Codec::default();
            for commited_chunk in msg_codewords.iter() {

                // Does not return an error
                decoder.feed(commited_chunk.clone().chunk_with_merkle_proof.take_chunk()).unwrap();
            }

            let result = decoder.decode(Rs8Settings::new((self.f_byzantine+1) as usize,
                                                         (self.num_of_nodes - (self.f_byzantine+1)) as usize));
            if result.is_ok() {
                let data = result.unwrap();
                self.reconstructed_data.insert(merkle_root, data.to_vec());
                return Ok(true);
            }
            else{
                return Err(DeliverError::GeneralError(format!("Failed to decode data: {:?}", result.err())));
            }
        }

        Ok(false)
    }

    pub(crate) fn get_node_identity_by_index(&self, index: u32) -> Option<Identity> {
        for (pub_key, deliver_data) in self.committee.iter() {
            if *deliver_data == index {
                return Some(*pub_key);
            }
        }
        None
    }
}