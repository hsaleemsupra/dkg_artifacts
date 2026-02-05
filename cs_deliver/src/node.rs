use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;
use erasure::codecs::rs8::{Rs8Codec, Rs8Settings};
use erasure::utils::codec_trait::{Codec, Setting};
use vec_commitment::committed_chunk::CommittedChunk;
use socrypto::{Hash, Identity};
use crate::codeword::{Codeword, CodewordWithSignature};
use crate::errors::CSDeliverError;
use crate::types::deliver_data::CSDeliverData;
use ed25519_dalek::{Signer, SigningKey as SecretKey, Verifier, VerifyingKey as PublicKey};

pub struct CSDeliverNode<State> {
    /// Identity of the node in scope of which deliver process has been initiated
    pub(crate) node: Identity,
    /// Number of participants in committee
    /// We use the total number of shards for the erasure coding scheme as num_of_nodes
    pub(crate) num_of_nodes: u32,
    /// The erasure coding scheme splits the data in 2*f_byzantine+1 shards
    pub(crate) f_byzantine: u32,
    /// The node waits to receive fc_byzantine+1 identical shards before forwarding one
    pub(crate) fc_byzantine: u32,
    /// Secret Key for signing codewords
    pub(crate) signing_key: SecretKey,
    /// Node public keys ordered by their identity.
    pub(crate) committee: BTreeMap<Identity, CSDeliverData>,
    /// Indicates valid codewords received by a node for self chunk index
    /// Each codeword is sent by multiple senders
    pub(crate) code_words: BTreeMap<u32, CodewordWithSignature>,
    /// codewords that have been verified and can be used to reconstruct the original data
    /// once |finalized_code_words| == 2*f_byzantine+1
    pub(crate) verified_code_words: BTreeMap<usize, CodewordWithSignature>,
    /// Indicates the reconstructed msg after a node has received enough valid codewords
    /// for the message
    pub(crate) reconstructed_data: Vec<u8>,
    pub(crate) state: PhantomData<State>,
}

impl<State> CSDeliverNode<State> {
    pub(crate) fn identity(&self) -> Identity {
        self.node
    }

    pub(crate) fn generate_data_codewords(&self, data_to_broadcast: &Vec<u8>) -> Result<Vec<CodewordWithSignature>, CSDeliverError> {

        let chunks = Rs8Codec::encode(
            Rs8Settings::new(
                (2*self.f_byzantine + 1) as usize,
                (self.num_of_nodes - (2*self.f_byzantine + 1)) as usize),
            data_to_broadcast.clone())
            .map_err(|e| CSDeliverError::GeneralError(format!("Failed to erasure encode data: {}", e.to_string())))?;

        let (root, committed_chunks) =
            CommittedChunk::commit_chunk_list(chunks)
                .map_err(|e|
                    CSDeliverError::GeneralError(format!("Failed to create proofs for erasure coded data: {}", e.to_string())))?;

        let mut codeword_msgs = Vec::new();
        committed_chunks.iter().for_each(|commited_chunk| {
            let codeword = Codeword {
                sender: self.node,
                merkle_root: Hash(root.clone()),
                chunk_with_merkle_proof: commited_chunk.clone()
            };

            let codeword_hash = codeword.hash();
            let codeword_signature = self.signing_key.sign(&codeword_hash.0);
            codeword_msgs.push( CodewordWithSignature{
                codeword,
                signature: codeword_signature,
            });
        });

        Ok(codeword_msgs)
    }

    pub(crate) fn consume_codeword(&mut self, codeword_with_sig: CodewordWithSignature)
                                   -> Result<Option<CodewordWithSignature>, CSDeliverError> {

        if let Some(sender_index) = self.get_node_index_by_identity(codeword_with_sig.codeword.sender) {
            let chunk_index = codeword_with_sig.codeword.chunk_with_merkle_proof.get_chunk_index();

            //verify the signature on the codeword is correct
            let vk = self.get_node_verification_key_by_identity(codeword_with_sig.codeword.sender).unwrap();
            let data_hash = codeword_with_sig.codeword.hash();
            if vk.verify(&data_hash.0, &codeword_with_sig.signature).is_err(){
                return Err(CSDeliverError::ChunkVerificationError(codeword_with_sig.codeword.sender));
            }

            // Verify the chunk
            let chunk_is_verified = codeword_with_sig.codeword.chunk_with_merkle_proof
                .verify(codeword_with_sig.codeword.merkle_root.0, self.num_of_nodes as usize)
                .map_err(|e| CSDeliverError::GeneralError(format!("Failed to verify codeword: {}", e.to_string())))?;

            if chunk_is_verified{

                if !self.verified_code_words.contains_key(&chunk_index){
                    self.verified_code_words.insert(chunk_index, codeword_with_sig.clone());
                }

                if chunk_index == self.get_node_index_by_identity(self.node).unwrap() as usize {
                    // if received this chunk before from the sender
                    if self.code_words.contains_key(&sender_index){
                        return Ok(None);
                    }

                    self.code_words.insert(sender_index, codeword_with_sig.clone());

                    // check if we have received self.threshold_c identical codewords for this chunk index
                    if let Some(mut codeword_with_signature) = self.have_threshold_identical_codewords(self.fc_byzantine+1){

                        let codeword_hash = codeword_with_signature.codeword.hash();
                        let codeword_signature = self.signing_key.sign(&codeword_hash.0);
                        codeword_with_signature.signature = codeword_signature;
                        codeword_with_signature.codeword.sender = self.node;

                        return Ok(Some(codeword_with_signature));
                    }
                    else{
                        return Ok(None);
                    }
                }
                Ok(None)
            }
            else{
                Err(CSDeliverError::ChunkVerificationError(codeword_with_sig.codeword.sender))
            }
        }
        else{
            Err(CSDeliverError::GeneralError(format!("Unknown codeword sender: {:?}", codeword_with_sig.codeword.sender)))
        }
    }

    pub(crate) fn try_reconstruct_data(&mut self) -> Result<bool, CSDeliverError> {

        // if data is already reconstructed previously or we donot have enough codewords
        // we donot need to do anything
        if !self.reconstructed_data.is_empty() ||
            self.verified_code_words.len() < (2*self.f_byzantine + 1) as usize {
            return Ok(false);
        }

        // Otherwise we can try to reconstruct the data from codewords
        let msg_codewords = self.verified_code_words.values().cloned().collect::<Vec<_>>();

        let mut decoder = Rs8Codec::default();
        for commited_chunk in msg_codewords.iter() {

            // Does not return an error
            decoder.feed(commited_chunk.clone().codeword.chunk_with_merkle_proof.take_chunk()).unwrap();
        }

        let result = decoder.decode(Rs8Settings::new((2*self.f_byzantine + 1) as usize,
                                                     (self.num_of_nodes - (2*self.f_byzantine + 1)) as usize));
        if result.is_ok() {
            let data = result.unwrap();
            self.reconstructed_data = data.to_vec();
            Ok(true)
        }
        else{
            Err(CSDeliverError::GeneralError(format!("Failed to decode data: {:?}", result.err())))
        }
    }

    fn have_threshold_identical_codewords(&self, threshold: u32) -> Option<CodewordWithSignature> {

            if threshold == 0
                || self.code_words.len() < threshold as usize {
                return None;
            }

            // We'll collect frequencies of each Codeword using a HashMap.
            let mut freq: HashMap<&CodewordWithSignature, usize> = HashMap::new();

            for codeword in self.code_words.values() {
                // Increase the count for this codeword.
                let count = freq.entry(codeword).or_insert(0);
                *count += 1;

                // If it hits threshold, we're done.
                if *count == threshold as usize {
                    return Some(codeword.clone());
                }
            }
        None
    }

    pub(crate) fn get_node_identity_by_index(&self, index: u32) -> Option<Identity> {
        for (pub_key, deliver_data) in self.committee.iter() {
            if deliver_data.node_number == index {
                return Some(*pub_key);
            }
        }
        None
    }

    pub(crate) fn get_node_index_by_identity(&self, identity: Identity) -> Option<u32> {
        for (pub_key, deliver_data) in self.committee.iter() {
            if *pub_key == identity {
                return Some(deliver_data.node_number);
            }
        }
        None
    }

    pub(crate) fn get_node_verification_key_by_identity(&self, identity: Identity) -> Option<PublicKey> {
        for (pub_key, deliver_data) in self.committee.iter() {
            if *pub_key == identity {
                return Some(deliver_data.public_key);
            }
        }
        None
    }
}