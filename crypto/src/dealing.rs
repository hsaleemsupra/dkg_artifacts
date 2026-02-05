use std::collections::{BTreeMap};
use bicycl::{CiphertextBox, MpzBox, PublicKeyBox, QFIBox};
use blsttc::group::ff::Field;
use blsttc::group::Group;
use crate::errors::DkgError;
use crate::serde_utils::{read_u32, read_vector, read_vector_of_vectors, read_vector_of_vectors_u32, write_u32, write_vector, write_vector_of_vector, write_vector_of_vector_u32};
use crate::bls12381::nidkg_serde::{convert_fr_to_bytes, convert_g1_proj_to_bytes, convert_vec_cipher_to_bytes, convert_vec_g1_proj_to_bytes};
use crate::bls12381::nidkg_zk_share::{ZkProofSharing as ZkProofSharing12381};
use crate::bls12381::public_evals::{PublicEvals as PublicEvals12381};
use crate::bls12381::utils::get_cl as get_cl_12381;
use crate::bls12381::cg_encryption::CiphersWithSharingProof as CiphersWithSharingProof12381;
use blsttc::{Fr, G1Projective};
use tiny_keccak::{Hasher, Keccak};
use ed25519_dalek::{VerifyingKey as PublicKey, Signature, Verifier};
use lazy_static::lazy_static;
use rand::Rng;
use crate::bls12381::polynomial::{Polynomial as Polynomial12381};
use crate::bls12381::rng::RAND_ChaCha20;
use crate::public_key::CGPublicKey;
use std::hash::{Hash as StdHash, Hasher as StdHasher};

lazy_static! {
    pub static ref GEN_BLS12381: G1Projective = G1Projective::generator();
}

pub type Hash = [u8; 32];

#[derive(Clone, Debug)]
pub struct DkgConfig {
    /// number of nodes
    pub n: u32,
    /// threshold
    pub t: u32,
}

pub struct DealerSecret{
    pub polynomial_12381: Polynomial12381,
}

impl DealerSecret {
    pub fn new(config: &DkgConfig) -> Self {
        // to keep with the convention we construct a t coefficient polynomial so >=t dealings are required for reconstruction
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let rng = &mut RAND_ChaCha20::new(seed);
        DealerSecret{
            polynomial_12381: Polynomial12381::random(config.t as usize, rng),
        }
    }
    pub fn into_combined_dealing(&self, config: &DkgConfig, dealer_id: u32, instance_id: u32) -> CGCombinedDealing {
        let mut evals_12381: Vec<Fr> = Vec::new();
        let mut index_big = Fr::zero();
        let mut index = 0;
        while index <= config.n {
            evals_12381.push(self.polynomial_12381.evaluate_at(&index_big));
            index_big += Fr::one();
            index += 1;
        }
        let commitment_12381 = PublicEvals12381::from_evals(&evals_12381, &G1Projective::generator());

        CGCombinedDealing {
            evals_12381: evals_12381[1..].to_vec(),
            dealing_commitment: DealingCommitment{
                dealer_id,
                instance_id,
                bls12381_commitment: commitment_12381,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct DealingMeta{
    pub dealer_id: u32,
    pub instance_id: u32,
    pub accumulation_value: Hash,
    pub commitment_sk_12381: G1Projective,
}

impl DealingMeta {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_u32(&mut final_bytes, self.dealer_id);
        write_u32(&mut final_bytes, self.instance_id);
        write_vector(&mut final_bytes, self.accumulation_value.to_vec());
        write_vector(&mut final_bytes, convert_g1_proj_to_bytes(&self.commitment_sk_12381));
        final_bytes
    }
}

impl TryFrom<&[u8]> for DealingMeta {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        // dealer-meta
        let dealer_id = read_u32(&mut cursor)?;
        let instance_id = read_u32(&mut cursor)?;

        let accumulation_value = read_vector(&mut cursor)?;
        let commitment_sk_12381 = read_vector(&mut cursor)?;

        Ok(Self {
            dealer_id,
            instance_id,
            accumulation_value: Hash::try_from(accumulation_value).map_err(
                |_|{
                    DkgError::DeserializationError("Deserialization of accumulation value failed".to_string())
                })?,
            commitment_sk_12381: G1Projective::from_compressed(&commitment_sk_12381.try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"),
        })
    }
}

// 1. Implement PartialEq and Eq
impl PartialEq for DealingMeta {
    fn eq(&self, other: &Self) -> bool {
        self.dealer_id == other.dealer_id
            && self.instance_id == other.instance_id
            && self.accumulation_value == other.accumulation_value
            && self.commitment_sk_12381.eq(&other.commitment_sk_12381)
    }
}

impl Eq for DealingMeta {}

impl StdHash for DealingMeta {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let dealing_bytes = self.to_vec();
        state.write(&dealing_bytes);
    }
}

#[derive(Clone, Debug)]
pub struct CGIndividualDealing {
    pub dealer_id: u32,
    pub instance_id: u32,
    pub cg12381_share: Fr,
    pub cg12381_share_commitment: G1Projective,
}

impl CGIndividualDealing {

    pub fn new(dealer_id: u32, instance_id: u32, cg12381_share: Fr) -> Self {

        CGIndividualDealing{
            dealer_id,
            instance_id,
            cg12381_share,
            cg12381_share_commitment: G1Projective::generator() * cg12381_share,
        }
    }

    pub fn new_dealing_without_commitment(dealer_id: u32, instance_id: u32, cg12381_share: Fr) -> Self {
        CGIndividualDealing{
            dealer_id,
            instance_id,
            cg12381_share,
            cg12381_share_commitment: G1Projective::identity(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        let secret_bls12381_bytes = convert_fr_to_bytes(&self.cg12381_share);

        // dealer-meta
        write_u32(
            &mut final_bytes,
            self.dealer_id,
        );
        write_u32(
            &mut final_bytes,
            self.instance_id,
        );

        // bls12381 dealing bytes
        write_vector(&mut final_bytes, secret_bls12381_bytes);

        final_bytes
    }

    pub fn hash(&self) -> Hash {
        DealingCommitmentRef::from(self).hash()
    }
}

impl TryFrom<&[u8]> for CGIndividualDealing {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let dealer_id = read_u32(&mut cursor)?;
        let instance_id = read_u32(&mut cursor)?;
        let bls12381_scalar_bytes = read_vector(&mut cursor)?;

        Ok(CGIndividualDealing::new(
            dealer_id,
            instance_id,
            Fr::from_bytes_be(&bls12381_scalar_bytes.try_into().expect("failed to convert Vec<u8> to [u8;32]")).expect("failed Fr::from_bytes_be"),
        ))
    }
}

#[derive(Clone)]
pub struct ShareCommitment {
    pub dealer_id: u32,
    pub instance_id: u32,
    pub g_12381: G1Projective,
    pub commitment_12381: G1Projective,
}

impl ShareCommitment {
    pub fn hash(&self) -> Hash {
        DealingCommitmentRef::from(self).hash()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_u32(&mut final_bytes, self.dealer_id);
        write_u32(&mut final_bytes, self.instance_id);
        write_vector(&mut final_bytes, convert_g1_proj_to_bytes(&self.g_12381));
        write_vector(&mut final_bytes, convert_g1_proj_to_bytes(&self.commitment_12381));
        final_bytes
    }
}

impl From<CGIndividualDealing> for ShareCommitment {
    fn from(value: CGIndividualDealing) -> ShareCommitment {
        Self {
            dealer_id: value.dealer_id,
            instance_id: value.instance_id,
            g_12381: GEN_BLS12381.clone(),
            commitment_12381: value.cg12381_share_commitment.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DealingCommitment{
    pub dealer_id: u32,
    pub instance_id: u32,
    pub bls12381_commitment: PublicEvals12381,
}

impl DealingCommitment {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];

        hasher.update(convert_g1_proj_to_bytes(&self.bls12381_commitment.g).as_slice());
        let public_evals_12381 = self.bls12381_commitment.evals.as_slice();
        for i in 0..public_evals_12381.len(){
            hasher.update(convert_g1_proj_to_bytes(&public_evals_12381[i]).as_slice());
        }

        hasher.update(self.dealer_id.to_le_bytes().as_slice());
        hasher.update(self.instance_id.to_le_bytes().as_slice());
        hasher.finalize(&mut output);
        output
    }
}

#[derive(Clone, Debug)]
pub struct DealingCommitmentwithCiphers{
    pub bls12381_commitment: PublicEvals12381,
    pub ciphers_12381: BTreeMap<u32, CiphertextBox>,
}

impl DealingCommitmentwithCiphers{
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        let public_evals_12381: (Vec<u8>, Vec<Vec<u8>>) = (
            convert_g1_proj_to_bytes(&self.bls12381_commitment.g),
            convert_vec_g1_proj_to_bytes(
                &self
                    .bls12381_commitment
                    .evals,
            ),
        );

        let cipher_indices: Vec<Vec<u8>> = self.ciphers_12381
            .iter()
            .map(|(index, _)| index.to_le_bytes().to_vec())
            .collect();
        let cipher_vec_12381 = convert_vec_cipher_to_bytes(&self.ciphers_12381.values().cloned().collect::<Vec<_>>());

        write_vector(&mut final_bytes, public_evals_12381.0);
        write_vector_of_vector(&mut final_bytes, public_evals_12381.1);
        write_vector_of_vector(&mut final_bytes, cipher_indices);
        write_vector_of_vector(&mut final_bytes, cipher_vec_12381);

        final_bytes
    }
}

impl TryFrom<&[u8]> for DealingCommitmentwithCiphers {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let cl_12381 = get_cl_12381();
        let mut cursor = std::io::Cursor::new(bytes);

        let public_evals_12381 = (
            read_vector(&mut cursor)?,
            read_vector_of_vectors(&mut cursor)?,
        );

        // ciphers
        let ciphers_12381_indices = read_vector_of_vectors(&mut cursor)?;
        let ciphers_12381_bytes = read_vector_of_vectors(&mut cursor)?;

        if ciphers_12381_indices.len() != ciphers_12381_bytes.len() {
            return Err(Self::Error::DeserializationError("Failed to deserialize cipher map".to_string()));
        }

        let ciphers_12381: Vec<CiphertextBox> = ciphers_12381_bytes
            .iter()
            .map(|x| unsafe {
                CiphertextBox::from_bytes(x, &cl_12381)
                    .ok_or(DkgError::DeserializationError("Ciphertext12381 Deserialization Failed".to_string()))
            })
            .collect::<Result<_, DkgError>>()?;

        let mut cipher_map = BTreeMap::new();
        for i in 0..ciphers_12381_indices.len() {

            let ciphers_12381_index_array: [u8; 4] = ciphers_12381_indices[i].clone()
                .try_into()
                .map_err(|_| Self::Error::DeserializationError("Cipher index array must have exactly 4 elements".to_string()))?;
            let cipher_index = u32::from_le_bytes(ciphers_12381_index_array);

            cipher_map.insert(cipher_index, ciphers_12381[i].clone());
        }

        Ok(Self {
            bls12381_commitment: PublicEvals12381 {
                g: G1Projective::from_compressed(&public_evals_12381.0.try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed") ,
                evals: public_evals_12381
                    .1
                    .iter()
                    // TODO_BLSTTC: is there a way to avoid a clone here?
                    .map(|x| G1Projective::from_compressed(&x.clone().try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"))
                    .collect(),
            },
            ciphers_12381: cipher_map,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AggregatedDealingCommitmentwithCiphers{
    pub bls12381_commitment: PublicEvals12381,
    pub ciphers_12381: BTreeMap<u32, (Vec<u32>, CiphertextBox)>,
}

impl AggregatedDealingCommitmentwithCiphers{
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        let public_evals_12381: (Vec<u8>, Vec<Vec<u8>>) = (
            convert_g1_proj_to_bytes(&self.bls12381_commitment.g),
            convert_vec_g1_proj_to_bytes(
                &self
                    .bls12381_commitment
                    .evals,
            ),
        );

        let cipher_indices: Vec<Vec<u8>> = self.ciphers_12381
            .iter()
            .map(|(index, _)| index.to_le_bytes().to_vec())
            .collect();

        let dealers_for_each_cipher_12381: Vec<_> = self.ciphers_12381.iter()
            .map(|(_, (dealers, _))| dealers.clone()).collect();

        let ciphers_12381: Vec<_> = self.ciphers_12381.iter()
            .map(|(_, (_, agg_cipher))| agg_cipher.clone()).collect();

        let cipher_vec_12381 = convert_vec_cipher_to_bytes(&ciphers_12381);

        write_vector(&mut final_bytes, public_evals_12381.0);
        write_vector_of_vector(&mut final_bytes, public_evals_12381.1);
        write_vector_of_vector(&mut final_bytes, cipher_indices);
        write_vector_of_vector_u32(&mut final_bytes, dealers_for_each_cipher_12381);
        write_vector_of_vector(&mut final_bytes, cipher_vec_12381);

        final_bytes
    }
}

impl TryFrom<&[u8]> for AggregatedDealingCommitmentwithCiphers {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let cl_12381 = get_cl_12381();
        let mut cursor = std::io::Cursor::new(bytes);

        let public_evals_12381 = (
            read_vector(&mut cursor)?,
            read_vector_of_vectors(&mut cursor)?,
        );

        // ciphers
        let ciphers_12381_indices = read_vector_of_vectors(&mut cursor)?;
        let dealers_for_each_cipher_12381 = read_vector_of_vectors_u32(&mut cursor)?;
        let ciphers_12381_bytes = read_vector_of_vectors(&mut cursor)?;

        if ciphers_12381_indices.len() != ciphers_12381_bytes.len() ||
            ciphers_12381_indices.len() != dealers_for_each_cipher_12381.len() {
            return Err(Self::Error::DeserializationError("Failed to deserialize cipher map".to_string()));
        }

        let ciphers_12381: Vec<CiphertextBox> = ciphers_12381_bytes
            .iter()
            .map(|x| unsafe {
                CiphertextBox::from_bytes(x, &cl_12381)
                    .ok_or(DkgError::DeserializationError("Ciphertext12381 Deserialization Failed".to_string()))
            })
            .collect::<Result<_, DkgError>>()?;

        let mut cipher_map = BTreeMap::new();
        for i in 0..ciphers_12381_indices.len() {

            let ciphers_12381_index_array: [u8; 4] = ciphers_12381_indices[i].clone()
                .try_into()
                .map_err(|_| Self::Error::DeserializationError("Cipher index array must have exactly 4 elements".to_string()))?;
            let cipher_index = u32::from_le_bytes(ciphers_12381_index_array);

            cipher_map.insert(cipher_index, (dealers_for_each_cipher_12381[i].clone(), ciphers_12381[i].clone()));
        }

        Ok(Self {
            bls12381_commitment: PublicEvals12381 {
                g: G1Projective::from_compressed(&public_evals_12381.0.try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"),
                evals: public_evals_12381
                    .1
                    .iter()
                    .map(|x| G1Projective::from_compressed_unchecked(&x.clone().try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"))
                    .collect(),
            },
            ciphers_12381: cipher_map,
        })
    }
}

#[derive(Clone)]
pub struct CGCombinedDealing {
    pub evals_12381: Vec<Fr>,
    pub dealing_commitment: DealingCommitment
}

impl CGCombinedDealing {
    pub fn get_individual_dealings_without_commitment(&self) -> Vec<CGIndividualDealing> {

        let mut dealings: Vec<CGIndividualDealing> = Vec::new();
        for ss_12381 in self.evals_12381.iter() {
            let dealing: CGIndividualDealing = CGIndividualDealing::new_dealing_without_commitment(
                self.dealing_commitment.dealer_id,
                self.dealing_commitment.instance_id,
                ss_12381.clone(),
            );
            dealings.push(dealing);
        }
        dealings
    }
}

#[derive(Clone, Debug)]
pub struct CiphersWithSharingProof{
    pub ciphers_with_sharing_proof_12381: CiphersWithSharingProof12381,
}

struct DealingCommitmentRef<'a> {
    dealer_id: &'a u32,
    instance_id: &'a u32,
    bls12381_g: &'a G1Projective,
    bls12381_commitment: &'a G1Projective,
}

impl<'a> DealingCommitmentRef<'a> {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(convert_g1_proj_to_bytes(&self.bls12381_g).as_slice());
        hasher.update(convert_g1_proj_to_bytes(&self.bls12381_commitment).as_slice());
        hasher.update(self.dealer_id.to_le_bytes().as_slice());
        hasher.update(self.instance_id.to_le_bytes().as_slice());
        hasher.finalize(&mut output);
        output
    }
}

impl<'a> From<&'a CGIndividualDealing> for DealingCommitmentRef<'a> {
    fn from(value: &'a CGIndividualDealing) -> DealingCommitmentRef<'a> {
        Self {
            dealer_id: &value.dealer_id,
            instance_id: &value.instance_id,
            bls12381_g: &GEN_BLS12381,
            bls12381_commitment: &value.cg12381_share_commitment,
        }
    }
}

impl<'a> From<&'a ShareCommitment> for DealingCommitmentRef<'a> {
    fn from(value: &'a ShareCommitment) -> DealingCommitmentRef<'a> {
        Self {
            dealer_id: &value.dealer_id,
            instance_id: &value.instance_id,
            bls12381_g: &value.g_12381,
            bls12381_commitment: &value.commitment_12381,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncryptedDealingWithProof {
    pub dealing_commitment: DealingCommitment,
    pub signatures: BTreeMap<u32, Signature>,
    pub ciphers_with_sharing_proof: Option<CiphersWithSharingProof>,
}

impl EncryptedDealingWithProof {
    pub fn new(combined_dealing: &CGCombinedDealing,
               signatures: &BTreeMap<u32, Signature>,
               committee_nodes_encryption_keys: &BTreeMap<u32, PublicKeyBox>,
               threshold: u32)
               -> Result<Self, DkgError> {

        let n = combined_dealing.evals_12381.len() as u32;
        let t = threshold;

        //dealer generates encrypted shares and proof of sharing for nodes that did not send back signatures
        let mut shares_to_encrypt_with_proof_12381 = BTreeMap::new();
        let mut node_pks_for_shares_to_encrypt_with_proof_12381 = BTreeMap::new();

        for i in 0..n {
            if !signatures.contains_key(&i) {
                shares_to_encrypt_with_proof_12381.insert(i, combined_dealing.evals_12381[i as usize]);
                node_pks_for_shares_to_encrypt_with_proof_12381.insert(i, committee_nodes_encryption_keys.get(&i)
                    .ok_or(DkgError::EncryptedDealingGenerationError("Encryption Key missing".to_string()))?.clone());
            }
        }

        let mut ciphers_with_sharing_proof = None;
        // Only need to generate sharing proof if we have not received signatures from all nodes
        if signatures.len() != n as usize{

            let ciphers_with_sharing_proof_12381 =
                CiphersWithSharingProof12381::new(shares_to_encrypt_with_proof_12381,
                                                  node_pks_for_shares_to_encrypt_with_proof_12381,
                                                  combined_dealing.dealing_commitment.bls12381_commitment.evals[1..].to_vec(),
                                                  DkgConfig { n, t})
                    .map_err(|e| DkgError::EncryptedDealingGenerationError(e.to_string()))?;

            ciphers_with_sharing_proof =  Some(CiphersWithSharingProof{
                ciphers_with_sharing_proof_12381,
            });
        }

        Ok(EncryptedDealingWithProof{
            dealing_commitment: DealingCommitment {
                dealer_id: combined_dealing.dealing_commitment.dealer_id,
                instance_id: combined_dealing.dealing_commitment.instance_id,
                bls12381_commitment: combined_dealing.dealing_commitment.bls12381_commitment.clone(),
            },
            ciphers_with_sharing_proof,
            signatures: signatures.clone(),
        })
    }

    //todo: add low degree test
    pub fn verify(&self, committee_nodes_verification_keys: &BTreeMap<u32, CGPublicKey>, threshold: u32) -> bool{

        let n = committee_nodes_verification_keys.keys().len() as u32;

        //verify for each node i, either they signed the dealing or a ciphertext is available
        let signatures_present = self.signatures.len();

        // the dealer must send atleast threshold valid signatures
        if signatures_present < threshold as usize {
            return false;
        }

        let mut ciphers_present_12381 = 0;

        if let Some(ciphers_with_sharing_proof) = self.ciphers_with_sharing_proof.as_ref() {
            ciphers_present_12381 = ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.ciphers.len();
        }

        if (signatures_present + ciphers_present_12381) != n as usize {
            return false;
        }

        //verify the commitment using low degree test
        let commitment_verified_flag = self.dealing_commitment.bls12381_commitment.perform_low_degree_test(DkgConfig{
            n,
            t: threshold,
        });

        if !commitment_verified_flag{
            return false;
        }

        //verify the signatures are valid
        let vks_for_nodes_that_signed: Vec<PublicKey> = committee_nodes_verification_keys.iter()
            .filter(|(node_id, _)| self.signatures.contains_key(node_id))
            .map(|(_, vk)| vk.verification_key.clone())
            .collect();

        let share_comm_and_sigs_for_nodes_that_signed: Vec<(ShareCommitment, Signature)> = committee_nodes_verification_keys.iter()
            .filter(|(node_id, _)| self.signatures.contains_key(node_id))
            .map(|(node_id, _)| (
                ShareCommitment{
                    dealer_id: self.dealing_commitment.dealer_id,
                    instance_id: self.dealing_commitment.instance_id,
                    g_12381: self.dealing_commitment.bls12381_commitment.g.clone(),
                    commitment_12381: self.dealing_commitment.bls12381_commitment.evals[((*node_id)+1) as usize].clone(),
                },
                self.signatures[node_id].clone())
            )
            .collect();

        //verify all signatures on node share commitments
        for i in 0..vks_for_nodes_that_signed.len(){
            let (share_commitment, sig) = share_comm_and_sigs_for_nodes_that_signed[i].clone();
            let share_comm_bytes = share_commitment.to_vec();
            if vks_for_nodes_that_signed[i].verify(&share_comm_bytes, &sig).is_err(){
                return false;
            }
        }

        //verify proof of sharing is correct
        if let Some(ciphers_with_sharing_proof) = self.ciphers_with_sharing_proof.as_ref(){
            let pks_for_nodes_with_encrypted_shares_12381: BTreeMap<u32, PublicKeyBox> = committee_nodes_verification_keys.iter()
                .filter(|(node_id, _)| !self.signatures.contains_key(node_id))
                .map(|(node_id , pk)| (*node_id, pk.encryption_key_bls12381.key.clone()))
                .collect();

            //verify that the proof of sharing for encrypted shares
            return ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381
                .verify(pks_for_nodes_with_encrypted_shares_12381,
                        self.dealing_commitment.bls12381_commitment.evals[1..].to_vec(),
                        DkgConfig
                        {
                            n,
                            t: threshold,
                        });
        }
        true
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        let signers: Vec<Vec<u8>> = self.signatures
            .iter()
            .map(|(node_index, _)| node_index.to_le_bytes().to_vec())
            .collect();

        let signatures: Vec<Vec<u8>> = self.signatures
            .iter()
            .map(|(_, sig)| sig.to_bytes().to_vec())
            .collect();

        //BLS12381 curve
        let public_evals_12381: (Vec<u8>, Vec<Vec<u8>>) = (
            convert_g1_proj_to_bytes(&self.dealing_commitment.bls12381_commitment.g),
            convert_vec_g1_proj_to_bytes(
                &self
                    .dealing_commitment
                    .bls12381_commitment
                    .evals,
            ),
        );

        // dealer-meta
        write_u32(
            &mut final_bytes,
            self.dealing_commitment.dealer_id,
        );
        write_u32(
            &mut final_bytes,
            self.dealing_commitment.instance_id,
        );

        //signature bytes
        write_vector_of_vector(&mut final_bytes, signers);
        write_vector_of_vector(&mut final_bytes, signatures);
        // bls12381 dealing bytes
        // commitment
        write_vector(&mut final_bytes, public_evals_12381.0);
        write_vector_of_vector(&mut final_bytes, public_evals_12381.1);

        // zk proof of correct sharing
        if let Some(ciphers_with_sharing_proof) = self.ciphers_with_sharing_proof.as_ref() {

            //flag indicating presence of sharing proof
            write_u32(
                &mut final_bytes,
                1,
            );

            let cipher_vec_with_proof_12381 = convert_vec_cipher_to_bytes(&ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.ciphers);
            let zkproof_sharing_ff_12381 = unsafe{ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.zk_sharing_proof.ff.to_bytes()};
            let zkproof_sharing_aa_12381 = convert_g1_proj_to_bytes(&ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.zk_sharing_proof.aa);
            let zkproof_sharing_yy_12381 = unsafe{ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.zk_sharing_proof.yy.to_bytes()};
            let zkproof_sharing_zr_12381 = unsafe{ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.zk_sharing_proof.z_r.to_bytes()};
            let zkproof_sharing_zalpha_12381 = convert_fr_to_bytes(&ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.zk_sharing_proof.z_alpha);
            let zkproof_sharing_randomizer_12381 = unsafe{ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381.randomizer.to_bytes()};

            write_vector_of_vector(&mut final_bytes, cipher_vec_with_proof_12381);
            write_vector(&mut final_bytes, zkproof_sharing_ff_12381);
            write_vector(&mut final_bytes, zkproof_sharing_aa_12381);
            write_vector(&mut final_bytes, zkproof_sharing_yy_12381);
            write_vector(&mut final_bytes, zkproof_sharing_zr_12381);
            write_vector(&mut final_bytes, zkproof_sharing_zalpha_12381);
            write_vector(&mut final_bytes, zkproof_sharing_randomizer_12381);
        }
        else {
            //flag indicating absence of sharing proof
            write_u32(
                &mut final_bytes,
                0,
            );
        }

        final_bytes
    }

}

impl TryFrom<&[u8]> for EncryptedDealingWithProof {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let cl_12381 = get_cl_12381();
        let mut cursor = std::io::Cursor::new(bytes);
        // dealer-meta
        let dealer_id = read_u32(&mut cursor)?;
        let instance_id = read_u32(&mut cursor)?;
        //signatures
        let signers_bytes = read_vector_of_vectors(&mut cursor)?;
        let signatures_bytes = read_vector_of_vectors(&mut cursor)?;
        if signers_bytes.len() != signatures_bytes.len() {
            return Err(Self::Error::DeserializationError("Failed to deserialize signatures map".to_string()));
        }

        let mut signatures = BTreeMap::new();
        for i in 0..signers_bytes.len() {

            let signer_byte_array: [u8; 4] = signers_bytes[i].clone()
                .try_into()
                .map_err(|_| Self::Error::DeserializationError("Signer id array must have exactly 4 elements".to_string()))?;

            let signer = u32::from_le_bytes(signer_byte_array);
            let signature = Signature::try_from(signatures_bytes[i].clone().as_slice())
                .map_err(|_| Self::Error::DeserializationError("Failed to deserialize signature".to_string()))?;
            signatures.insert(signer, signature);

        }

        // curve bls12381
        // commitment
        let public_evals_12381 = (
            read_vector(&mut cursor)?,
            read_vector_of_vectors(&mut cursor)?,
        );

        let mut ciphers_with_sharing_proof = None;
        let proof_available = read_u32(&mut cursor)?;
        if proof_available == 1{

            let ciphers_12381_with_proof_bytes = read_vector_of_vectors(&mut cursor)?;
            // zk proof of correct sharing
            let zkproof_ff_12381 = read_vector(&mut cursor)?;
            let zkproof_aa_12381 = read_vector(&mut cursor)?;
            let zkproof_yy_12381 = read_vector(&mut cursor)?;
            let zkproof_zr_12381 = read_vector(&mut cursor)?;
            let zkproof_zalpha_12381 = read_vector(&mut cursor)?;
            let zkproof_randomizer_12381 = read_vector(&mut cursor)?;

            let ciphers_with_proof_12381: Vec<CiphertextBox> = ciphers_12381_with_proof_bytes
                .iter()
                .map(|x| unsafe {
                    CiphertextBox::from_bytes(x, &cl_12381)
                        .ok_or(DkgError::DeserializationError("Ciphertext12381 Deserialization Failed".to_string()))
                })
                .collect::<Result<_, DkgError>>()?;

            ciphers_with_sharing_proof = Some(CiphersWithSharingProof {
                ciphers_with_sharing_proof_12381: CiphersWithSharingProof12381 {
                    ciphers: ciphers_with_proof_12381,
                    zk_sharing_proof: ZkProofSharing12381 {
                        ff: unsafe{ QFIBox::from_bytes(&zkproof_ff_12381, &cl_12381)
                            .ok_or(DkgError::DeserializationError("Sharing Proof Deserialization Failed".to_string()))? },
                        aa: G1Projective::from_compressed(&zkproof_aa_12381.try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"),
                        yy: unsafe{QFIBox::from_bytes(&zkproof_yy_12381, &cl_12381)
                            .ok_or(DkgError::DeserializationError("Sharing Proof Deserialization Failed".to_string()))?},
                        z_r: unsafe{MpzBox::from_bytes(&zkproof_zr_12381)
                            .ok_or(DkgError::DeserializationError("Sharing Proof Deserialization Failed".to_string()))?},
                        z_alpha: Fr::from_bytes_be(&zkproof_zalpha_12381.try_into().expect("failed to convert Vec<u8> to [u8; 32]")).expect("failed Fr::from_bytes_be"),
                    },
                    randomizer: unsafe{QFIBox::from_bytes(&zkproof_randomizer_12381, &cl_12381)
                        .ok_or(DkgError::DeserializationError("Sharing Proof Deserialization Failed".to_string()))?},
                },
            });
        }

        Ok(EncryptedDealingWithProof {
            signatures,
            dealing_commitment: DealingCommitment {
                dealer_id,
                instance_id,
                bls12381_commitment: PublicEvals12381 {
                    g: G1Projective::from_compressed(&public_evals_12381.0.try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"),
                    evals: public_evals_12381
                        .1
                        .iter()
                        .map(|x| G1Projective::from_compressed(&x.clone().try_into().expect("failed to convert Vec<u8> to [u8; 48]")).expect("failed G1Projective::from_compressed"))
                        .collect(),
                },
            },
            ciphers_with_sharing_proof
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use crate::secret_key::CGSecretKey;
    use super::*;

    pub fn test_setup(num_nodes: u32, threshold: u32) -> (u32, u32, DkgConfig, HashMap<u32, (CGSecretKey, CGPublicKey)>) {

        let dealer_id = 1;
        let instance_id = 2;
        let config = DkgConfig{
            n: num_nodes,
            t: threshold,
        };

        let mut node_keys = HashMap::new();
        for i in 0..num_nodes {
            let node_cg_key = CGSecretKey::generate();
            let node_cg_pub_key = CGPublicKey::try_from(&node_cg_key).unwrap();
            node_keys.insert(i, (node_cg_key, node_cg_pub_key.clone()));
        }
        (dealer_id, instance_id, config, node_keys)
    }

    #[test]
    pub fn test_dkg_dealings_should_verify() {

        let (dealer_id, instance_id, config, node_keys) =
            test_setup(150, 100);

        let dealer_secret = DealerSecret::new(&config);
        let combined_dealing = dealer_secret.into_combined_dealing(&config, dealer_id, instance_id);
        let individual_dealing = combined_dealing.get_individual_dealings_without_commitment();

        let mut sigs = BTreeMap::new();

        for i in 0..config.t{

            let mut dealing: CGIndividualDealing = individual_dealing[i as usize].clone();
            dealing = CGIndividualDealing::try_from(dealing.to_vec().as_slice()).unwrap();
            let (cg_priv_key, _cg_pub_key) = node_keys.get(&i).unwrap();
            let dealing_sig = cg_priv_key.sign_commitment(&dealing);
            sigs.insert(i, dealing_sig.signature);
        }

        let node_pks: BTreeMap<u32, CGPublicKey> = node_keys.iter()
            .map( | (index, (_, pub_key)) | {
                (*index, pub_key.clone())})
            .collect();

        let encryption_keys = node_keys.iter()
            .map( | (index, (_priv_key, pub_key)) | {
                (*index, pub_key.encryption_key_bls12381.key.clone())})
            .collect();

        let mut encrypted_dealing = EncryptedDealingWithProof::new(&combined_dealing, &sigs, &encryption_keys, config.t).unwrap();
        encrypted_dealing = EncryptedDealingWithProof::try_from(encrypted_dealing.to_vec().as_slice()).unwrap();
        assert!(encrypted_dealing.verify(&node_pks, config.t));
    }

    #[test]
    pub fn test_dkg_dealings_should_verify_all_sigs_available() {

        let (dealer_id, instance_id, config, node_keys) =
            test_setup(11, 6);

        let dealer_secret = DealerSecret::new(&config);
        let combined_dealing = dealer_secret.into_combined_dealing(&config, dealer_id, instance_id);
        let individual_dealing = combined_dealing.get_individual_dealings_without_commitment();

        let mut sigs = BTreeMap::new();

        for i in 0..config.n{

            let mut dealing: CGIndividualDealing = individual_dealing[i as usize].clone();
            dealing = CGIndividualDealing::try_from(dealing.to_vec().as_slice()).unwrap();
            let (cg_priv_key, _cg_pub_key) = node_keys.get(&i).unwrap();
            let dealing_sig = cg_priv_key.sign_commitment(&dealing);
            sigs.insert(i, dealing_sig.signature);
        }

        let node_pks: BTreeMap<u32, CGPublicKey> = node_keys.iter()
            .map( | (index, (_, pub_key)) | {
                (*index, pub_key.clone())})
            .collect();

        let encryption_keys = node_keys.iter()
            .map( | (index, (_priv_key, pub_key)) | {
                (*index, pub_key.encryption_key_bls12381.key.clone())})
            .collect();

        let mut encrypted_dealing = EncryptedDealingWithProof::new(&combined_dealing, &sigs, &encryption_keys, config.t).unwrap();
        encrypted_dealing = EncryptedDealingWithProof::try_from(encrypted_dealing.to_vec().as_slice()).unwrap();
        assert!(encrypted_dealing.verify(&node_pks, config.t));
    }

}