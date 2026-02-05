use std::collections::{BTreeMap, HashMap};
use bicycl::CiphertextBox;
use blsttc::group::Group;
use blsttc::G1Projective;
use crypto::dealing::{DealingMeta, Hash};
use blst::min_pk::{AggregatePublicKey, AggregateSignature as AggregateSignatureBLS, PublicKey as PublicKeyBlst, Signature as SignatureBLS};
use crypto::errors::DkgError;
use crypto::public_key::verify_signature;
use crypto::serde_utils::{read_vector, read_vector_of_vectors, read_vector_u32, write_vector_u32};
use crate::serde_utils::{read_u32, write_u32, write_vector, write_vector_of_vector};
use crate::utils::{compute_accumulation_value, convert_cipher_to_bytes, convert_g1_proj_to_bytes, convert_vec_g1_proj_to_bytes};
use crate::BlsPublicKey;
use crypto::bls12381::utils::get_cl as get_cl_12381;
use crypto::bls12381::public_evals::PublicEvals as PublicEvals12381;
use std::hash::{Hash as StdHash, Hasher as StdHasher};

#[derive(Debug, Clone)]
pub struct DealingMetaWithSignature {
    pub(crate) dealing_meta: DealingMeta,
    pub(crate) signature: SignatureBLS,
}

impl DealingMetaWithSignature {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_vector(&mut final_bytes, self.dealing_meta.to_vec());
        write_vector(&mut final_bytes, self.signature.to_bytes().to_vec());
        final_bytes
    }
}

impl TryFrom<&[u8]> for DealingMetaWithSignature {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(bytes);
        let dealing_meta_bytes = read_vector(&mut cursor)?;
        let signature_bytes = read_vector(&mut cursor)?;

        Ok(Self{
            dealing_meta: DealingMeta::try_from(dealing_meta_bytes.as_slice())?,
            signature: SignatureBLS::from_bytes(signature_bytes.as_slice())
                .map_err(|_| Self::Error::DeserializationError("Signature BLS must not be valid".to_string()))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DKGMeta {
    pub(crate) public_key_12381: G1Projective,
    pub(crate) dealing_meta_qcs: HashMap<DealingMeta, (Vec<u32>,AggregateSignatureBLS)>
}

impl DKGMeta {
    pub fn new(dealing_meta_qcs: HashMap<DealingMeta, (Vec<u32>,AggregateSignatureBLS)>)
        -> Self {

        let mut public_key_12381 = G1Projective::identity();

        dealing_meta_qcs.iter().for_each(|(dealing_meta, _)| {
            public_key_12381 += dealing_meta.commitment_sk_12381;
        });

        Self{
            public_key_12381,
            dealing_meta_qcs,
        }
    }

    pub fn verify_meta_dkg(&self, threshold: u32, epoch: u64, node_vks: &BTreeMap<u32, PublicKeyBlst>) -> bool {

        // verify the dkg meta has threshold size
        if self.dealing_meta_qcs.len() != threshold as usize {
            return false;
        }

        // basic validation for epoch
        for (dealing_meta, _) in self.dealing_meta_qcs.iter(){
            if dealing_meta.instance_id != epoch as u32{
                return false;
            }
        }

        // verify all QC sigs
        let qc_verification_result = self.dealing_meta_qcs.iter()
            .all(|(dealing_meta,(node_indices, agg_sig))| {

                if node_indices.len() != threshold as usize {
                    return false;
                }

                let mut vks = Vec::new();
                for i in node_indices{
                    let node_vk = node_vks.get(i);
                    if let Some(vk) = node_vk {
                        vks.push(vk);
                    }
                    else {
                        return false;
                    }
                }

                let mut verification_success_flag = false;
                let agg_pk = AggregatePublicKey::aggregate(vks.as_slice(), false);
                if let Ok(agg_pk) = agg_pk {
                    let sig = agg_sig.to_signature();
                    let pk = agg_pk.to_public_key();
                    let verification_result = verify_signature(&pk, &dealing_meta.to_vec(), &sig);
                    verification_success_flag = verification_result;
                }
                verification_success_flag
        });

        if !qc_verification_result{
            return false;
        }

        // verify the aggregate key g^x is computed correctly from the commitments
        let dkg_meta_agg_key = DKGMeta::new(self.dealing_meta_qcs.clone());
        if dkg_meta_agg_key.public_key_12381 != self.public_key_12381 {
            return false;
        }

        true
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_vector(&mut final_bytes, convert_g1_proj_to_bytes(&self.public_key_12381));

        write_u32(&mut final_bytes, self.dealing_meta_qcs.len() as u32);

        self.dealing_meta_qcs.iter().for_each(|(dealing_meta, (node_indices, agg_sig))| {
            let dealing_meta_bytes = dealing_meta.to_vec();
            let node_indices_bytes: Vec<Vec<u8>> = node_indices
                .iter()
                .map(|node_index| node_index.to_le_bytes().to_vec())
                .collect();
            let agg_sig_bytes = agg_sig.to_signature().to_bytes().to_vec();

            write_vector(&mut final_bytes, dealing_meta_bytes);
            write_vector_of_vector(&mut final_bytes, node_indices_bytes);
            write_vector(&mut final_bytes, agg_sig_bytes);
        });

        final_bytes
    }
}

impl TryFrom<&[u8]> for DKGMeta {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(bytes);

        let public_key_12381_bytes = read_vector(&mut cursor)?;

        let dealing_meta_qcs_len = read_u32(&mut cursor)?;

        let mut dealing_meta_qcs= HashMap::<DealingMeta, (Vec<u32>,AggregateSignatureBLS)>::new();
        for _i in 0..dealing_meta_qcs_len {
            let dealing_meta_bytes = read_vector(&mut cursor)?;
            let node_indices_bytes = read_vector_of_vectors(&mut cursor)?;
            let agg_sig_bytes = read_vector(&mut cursor)?;

            let dealing_meta = DealingMeta::try_from(dealing_meta_bytes.as_slice())?;
            let mut node_indices: Vec<u32> = Vec::new();
            for i in 0..node_indices_bytes.len() {

                let node_id_byte_array: [u8; 4] = node_indices_bytes[i].clone()
                    .try_into()
                    .map_err(|_| Self::Error::DeserializationError("Node id array must have exactly 4 elements".to_string()))?;

                let node_id = u32::from_le_bytes(node_id_byte_array);
                node_indices.push(node_id);
            }

            let sig = SignatureBLS::from_bytes(agg_sig_bytes.as_slice()).map_err(|_| Self::Error::DeserializationError("Signature BLS must not be valid".to_string()))?;
            let agg_sig = AggregateSignatureBLS::from_signature(&sig);

            dealing_meta_qcs.insert(dealing_meta, (node_indices, agg_sig));
        }

        Ok(Self{
            public_key_12381: BlsPublicKey::try_from(public_key_12381_bytes.as_slice()).expect("failed to convert bytes to BlsPublicKey").bls12381,
            dealing_meta_qcs,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DKGMetaCompressed {
    pub instance_id: u32,
    pub public_key_12381: G1Projective,
    pub accumulation_value: Hash,
}

impl DKGMetaCompressed{
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_u32(&mut final_bytes, self.instance_id);
        write_vector(&mut final_bytes, convert_g1_proj_to_bytes(&self.public_key_12381));
        write_vector(&mut final_bytes, self.accumulation_value.to_vec());
        final_bytes
    }
}

impl TryFrom<&[u8]> for DKGMetaCompressed {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(bytes);

        let instance_id = read_u32(&mut cursor)?;
        let public_key_12381_bytes = read_vector(&mut cursor)?;
        let accumulation_value = read_vector(&mut cursor)?;

        Ok(Self{
            instance_id,
            public_key_12381: BlsPublicKey::try_from(public_key_12381_bytes.as_slice()).expect("failed to convert bytes to BlsPublicKey").bls12381,
            accumulation_value: Hash::try_from(accumulation_value).map_err(
                |_|{
                    DkgError::DeserializationError("Deserialization of accumulation value failed".to_string())
                })?,
        })
    }
}

/// Requires (DkgMeta, n, t) where n is the number of total shard and t is the number of data shards used when
/// creating the accumulation value
impl TryFrom<(&DKGMeta, u32, u32)> for DKGMetaCompressed {
    type Error = DkgError;

    fn try_from(dkg_meta_and_dkg_params: (&DKGMeta, u32, u32)) -> Result<Self, Self::Error> {

        let dkg_meta_zis = DKGMetaZis::try_from(dkg_meta_and_dkg_params.0)?;
        let accumulation_zs = compute_accumulation_value(&dkg_meta_zis.to_vec(),
                                                         dkg_meta_and_dkg_params.1 as usize,
                                                         dkg_meta_and_dkg_params.2 as usize)
            .map_err(|x|{
                DkgError::GeneralError(format!("Failed to compute accumulation value: {}",x))
            })?;

        let mut instance_id = 0;

        if let Some((dealing_meta, _)) = dkg_meta_and_dkg_params.0.dealing_meta_qcs.iter().next() {
            instance_id = dealing_meta.instance_id;
        }

        Ok(Self{
            instance_id,
            public_key_12381: dkg_meta_and_dkg_params.0.public_key_12381.clone(),
            accumulation_value: accumulation_zs.0,
        })
    }
}

impl PartialEq for DKGMetaCompressed {
    fn eq(&self, other: &Self) -> bool {
            self.instance_id == other.instance_id
            && self.accumulation_value == other.accumulation_value
            && self.public_key_12381 == other.public_key_12381
    }
}

impl Eq for DKGMetaCompressed {}

#[derive(Debug, Clone)]
pub struct DKGMetaWithSignature {
    pub(crate) dkg_meta: DKGMetaCompressed,
    pub(crate) signature: SignatureBLS,
}

impl DKGMetaWithSignature{
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_vector(&mut final_bytes, self.dkg_meta.to_vec());
        write_vector(&mut final_bytes, self.signature.to_bytes().to_vec());
        final_bytes

    }
}

impl TryFrom<&[u8]> for DKGMetaWithSignature {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(bytes);
        let dkg_meta_bytes  = read_vector(&mut cursor)?;
        let signature_bytes = read_vector(&mut cursor)?;

        Ok(Self{
            dkg_meta: DKGMetaCompressed::try_from(dkg_meta_bytes.as_slice())?,
            signature: SignatureBLS::from_bytes(signature_bytes.as_slice())
                .map_err(|_| Self::Error::DeserializationError("Signature BLS must not be valid".to_string()))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DKGMetaWithAggregateSignature {
    pub family_node_index: u32,
    pub dkg_meta: DKGMetaCompressed,
    pub signers: Vec<u32>,
    pub signature: AggregateSignatureBLS,
}

impl DKGMetaWithAggregateSignature{
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        write_u32(&mut final_bytes, self.family_node_index);
        write_vector(&mut final_bytes, self.dkg_meta.to_vec());

        let node_indices_bytes: Vec<Vec<u8>> = self.signers
            .iter()
            .map(|node_index| node_index.to_le_bytes().to_vec())
            .collect();
        write_vector_of_vector(&mut final_bytes, node_indices_bytes);

        write_vector(&mut final_bytes, self.signature.to_signature().to_bytes().to_vec());
        final_bytes
    }
}

impl TryFrom<&[u8]> for DKGMetaWithAggregateSignature {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {

        let mut cursor = std::io::Cursor::new(bytes);
        let family_node_index = read_u32(&mut cursor)?;
        let dkg_meta_bytes  = read_vector(&mut cursor)?;

        let node_indices_bytes = read_vector_of_vectors(&mut cursor)?;
        let mut node_indices: Vec<u32> = Vec::new();
        for i in 0..node_indices_bytes.len() {

            let node_id_byte_array: [u8; 4] = node_indices_bytes[i].clone()
                .try_into()
                .map_err(|_| Self::Error::DeserializationError("Node id array must have exactly 4 elements".to_string()))?;

            let node_id = u32::from_le_bytes(node_id_byte_array);
            node_indices.push(node_id);
        }

        let signature_bytes = read_vector(&mut cursor)?;
        let signature = SignatureBLS::from_bytes(signature_bytes.as_slice())
            .map_err(|_| Self::Error::DeserializationError("Signature BLS must not be valid".to_string()))?;

        Ok(Self{
            family_node_index,
            dkg_meta: DKGMetaCompressed::try_from(dkg_meta_bytes.as_slice())?,
            signers: node_indices,
            signature: AggregateSignatureBLS::from_signature(&signature),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DKGMetaZis {
    pub(crate) zis: BTreeMap<u32, Hash>,
}

impl DKGMetaZis{
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        let zis_indices_bytes: Vec<Vec<u8>> = self.zis
            .iter()
            .map(|(index, _)| index.to_le_bytes().to_vec())
            .collect();

        let mut zis_bytes = Vec::new();
        let zi_values: Vec<_> = self.zis.values().cloned().collect();

        for zi in &zi_values{
            zis_bytes.push(zi.to_vec());
        }

        write_vector_of_vector(&mut final_bytes, zis_indices_bytes);
        write_vector_of_vector(&mut final_bytes, zis_bytes);
        final_bytes
    }
}

impl TryFrom<&[u8]> for DKGMetaZis {

    type Error = DkgError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);

        let zis_indices_bytes = read_vector_of_vectors(&mut cursor)?;
        let zis_bytes = read_vector_of_vectors(&mut cursor)?;
        if zis_indices_bytes.len() != zis_bytes.len() {
            return Err(Self::Error::DeserializationError("Failed to deserialize DKGMetaZis".to_string()));
        }

        let mut zis_map = BTreeMap::new();
        for i in 0..zis_indices_bytes.len() {

            let zi_index_byte_array: [u8; 4] = zis_indices_bytes[i].clone()
                .try_into()
                .map_err(|_| Self::Error::DeserializationError("Zi index array must have exactly 4 elements".to_string()))?;

            let zi_index = u32::from_le_bytes(zi_index_byte_array);
            let zi = Hash::try_from(zis_bytes[i].clone()).map_err(
                |_|{
                    DkgError::DeserializationError("Deserialization of accumulation value failed".to_string())
                })?;
            zis_map.insert(zi_index, zi);
        }

        Ok(Self{ zis: zis_map })
    }
}

impl TryFrom<&DKGMeta> for DKGMetaZis {
    type Error = DkgError;

    fn try_from(dkg_meta: &DKGMeta) -> Result<Self, Self::Error> {
        let mut zis: BTreeMap<u32, Hash> = BTreeMap::new();
        dkg_meta.dealing_meta_qcs.iter().for_each(|(dealing_meta, _)| {
            zis.insert(dealing_meta.dealer_id, dealing_meta.accumulation_value);
        });

        Ok(Self{
            zis
        })
    }
}

#[derive(Debug, Clone)]
pub struct AggregateEncryptedShare {
    pub cipher_12381: CiphertextBox,
    pub dealer_ids: Vec<u32>,
}

impl AggregateEncryptedShare {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        let cipher_12381 = convert_cipher_to_bytes(&self.cipher_12381);
        write_vector(&mut final_bytes, cipher_12381);
        write_vector_u32(&mut final_bytes, self.dealer_ids.clone());
        final_bytes
    }
}

impl TryFrom<&[u8]> for AggregateEncryptedShare {
    type Error = DkgError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let cl_12381 = get_cl_12381();

        let mut cursor = std::io::Cursor::new(bytes);
        let cipher_12381 = read_vector(&mut cursor)?;

        let cipher_12381 = unsafe { CiphertextBox::from_bytes(&cipher_12381, &cl_12381) }
            .ok_or(DkgError::DeserializationError("Ciphertext12381 Deserialization Failed".to_string()))?;

        let dealer_ids = read_vector_u32(&mut cursor)?;

        Ok(Self{
            cipher_12381,
            dealer_ids
        })
    }
}

/*impl TryFrom<(&AggregatedDealingCommitmentwithCiphers, usize)> for AggregateEncryptedShare {
    type Error = DkgError;
    fn try_from(dealing_comm_with_cipher: (&AggregatedDealingCommitmentwithCiphers, usize)) -> Result<Self, Self::Error>{

        let (dealers, cipher) = dealing_comm_with_cipher.0.ciphers_12381.get(&dealing_comm_with_cipher.1)
            .ok_or(DkgError::DeserializationError("Ciphertext not found".to_string()))?;

        Ok(Self{ cipher_12381: cipher.clone(), dealer_ids: dealers.clone() })
    }
}*/

impl PartialEq for AggregateEncryptedShare {
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl Eq for AggregateEncryptedShare {}

impl StdHash for AggregateEncryptedShare {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let enc_share_bytes = self.to_vec();
        state.write(&enc_share_bytes);
    }
}

#[derive(Debug, Clone)]
pub struct AggregateCommitment {
    pub bls12381_commitment: PublicEvals12381,
    pub dealer_ids: Vec<u32>,
}

impl AggregateCommitment{
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

        write_vector(&mut final_bytes, public_evals_12381.0);
        write_vector_of_vector(&mut final_bytes, public_evals_12381.1);
        write_vector_u32(&mut final_bytes, self.dealer_ids.clone());
        final_bytes
    }
}

impl TryFrom<&[u8]> for AggregateCommitment{
    type Error = DkgError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);

        let public_evals_12381 = (
            read_vector(&mut cursor)?,
            read_vector_of_vectors(&mut cursor)?,
        );

        let dealer_ids = read_vector_u32(&mut cursor)?;

        Ok(Self{
            bls12381_commitment: PublicEvals12381 {
                g: BlsPublicKey::try_from(public_evals_12381.0.as_slice()).expect("failed to convert bytes to BlsPublicKey").bls12381,
                evals: public_evals_12381
                    .1
                    .iter()
                    .map(|x| BlsPublicKey::try_from(x.as_slice()).expect("failed to convert bytes to BlsPublicKey").bls12381)
                    .collect(),
            },
            dealer_ids
        })
    }
}

/*impl TryFrom<&DealingCommitmentwithCiphers> for AggregateCommitment {
    type Error = DkgError;
    fn try_from(dealing_comm_with_cipher: &DealingCommitmentwithCiphers) -> Result<Self, Self::Error>{
        Ok(Self{
            bls12381_commitment: dealing_comm_with_cipher.bls12381_commitment.clone(),
        })
    }
}*/