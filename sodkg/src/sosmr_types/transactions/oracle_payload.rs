use crate::sosmr_types::{Round, SmrError, SmrSerialize, Verifier};
use log::error;
use nidkg_helper::{BlsPublicKey, BlsSignature};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Keccak256};
use socrypto::{digest, Digest, Hash, PublicKey};
use soserde::impl_size_in_bytes;
use std::fmt::{Debug, Display, Formatter};
use web3::ethabi::{Token, Uint};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleTransactionPayload {
    committee_index: u64,
    cluster_data: SignedCoherentCluster,
}

impl_size_in_bytes!(OracleTransactionPayload);

impl OracleTransactionPayload {
    pub fn new(committee_index: u64, cluster_data: SignedCoherentCluster) -> Self {
        Self {
            committee_index,
            cluster_data,
        }
    }

    pub fn cluster_data(&self) -> &SignedCoherentCluster {
        &self.cluster_data
    }

    pub fn committee_index(&self) -> u64 {
        self.committee_index
    }
}

impl Digest for OracleTransactionPayload {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(self.committee_index.to_le_bytes());
        self.cluster_data.feed_to(hasher);
    }
}

impl Display for OracleTransactionPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignedCoherentCluster {
    pub cc: CoherentCluster,
    #[serde(
        serialize_with = "serialize_bls_signature",
        deserialize_with = "deserialize_bls_signature"
    )]
    pub qc: BlsSignature,
    pub round: Round,
    pub origin: Origin,
}

impl Verifier<SignedCoherentCluster> for &BlsPublicKey {
    fn verify(&self, scc: &SignedCoherentCluster) -> Result<(), SmrError> {
        self.verify_chain(scc.cc.to_bytes().as_slice(), &scc.qc)
            .then_some(())
            .ok_or_else(|| SmrError::InvalidSignature("CoherentCluster".to_string()))
    }
}

impl SignedCoherentCluster {
    pub fn new(
        cc: CoherentCluster,
        qc: BlsSignature,
        round: Round,
        origin: Origin,
    ) -> SignedCoherentCluster {
        SignedCoherentCluster {
            cc,
            qc,
            round,
            origin,
        }
    }

    pub fn get_qc(&self) -> BlsSignature {
        self.qc.clone()
    }

    pub fn get_cc(&self) -> &CoherentCluster {
        &self.cc
    }

    pub fn get_round(&self) -> Round {
        self.round
    }

    pub fn get_origin(&self) -> Origin {
        self.origin
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn into_tokens(&self) -> Vec<Token> {
        let cc = Token::Tuple(self.cc.into_tokens());
        let qc = Token::Bytes(self.qc.to_vec());
        let round = Token::Uint(Uint::from(self.round));
        let origin = Token::Tuple(self.origin.into_token());

        let arr: Vec<Token> = [cc, qc, round, origin].to_vec();
        let tuple = Token::Tuple(arr);
        vec![tuple]
    }

    pub fn encode_eth_abi(&self) -> Vec<u8> {
        let tokens = self.into_tokens();
        web3::ethabi::encode(&tokens)
    }

    pub fn encode_bcs(&self) -> Result<Vec<u8>, SmrError> {
        let cc: clusterbcs::ContractSignedCC = self.clone().into();
        cc.encode_bcs()
    }
}

impl Digest for SignedCoherentCluster {
    fn feed_to<THasher: Sha3Digest>(&self, hasher: &mut THasher) {
        let mut bcs_hasher = Keccak256::new();
        let bcs_bytes = self.encode_bcs().unwrap_or_else(|err| {
            error!("Error during ContractSignedCC BCS encoding: {err}");
            vec![]
        });
        bcs_hasher.update(&bcs_bytes);
        let bcs_hash = <[u8; 32]>::from(bcs_hasher.finalize());

        //create token and hash tokens
        let mut token_hasher = Keccak256::new();
        let abi_encoded_tx = self.encode_eth_abi();
        token_hasher.update(abi_encoded_tx);
        let token_hash = <[u8; 32]>::from(token_hasher.finalize());

        //hash(token, bincode)
        hasher.update(token_hash);
        hasher.update(bcs_hash);
        // TODO (areg): clarify whether the above logic is still applicable of this old-inherited code or can be dropped
        // //hash(token, bincode, sender, protocol, subtype)
        // let mut hasher = Keccak256::new();
        // hasher.update(token_hash);
        // hasher.update(bcs_hash);
        // hasher.update(sender.digest());
        // hasher.update(protocol.to_bytes());
        // hasher.update([sub_type]);
        // socrypto::Hash(<[u8; 32]>::from(hasher.finalize()))
        //
        // // Frenode for Eth
        // // from bincode oracle struct of data
        // // create struct to tokens
        // // hask token
        //
        // // create  bincode hash + tokens hash
        //
        // // send the Tx + Token + bincode hash + Token
        //
        // // On SC
        // // From token construct data.
        // // Hash token
        // // reconstruct Tx Hash from Hash token +  bincode hash  + sender + protocol
    }
}

impl Debug for SignedCoherentCluster {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let sig = hex::encode(self.qc.to_vec());
        f.debug_struct("SignedCoherentCluster")
            .field("cc", &self.cc)
            .field("qc", &sig)
            .field("round", &self.round)
            .field("origin", &self.origin)
            .finish()
    }
}

impl Display for SignedCoherentCluster {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CoherentCluster {
    pub data_hash: Hash,
    pub pair: Vec<u32>,
    pub prices: Vec<u128>,
    pub timestamp: Vec<u128>,
    pub decimals: Vec<u16>,
}

impl Debug for CoherentCluster {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let data_hash = hex::encode(self.data_hash.0);
        f.debug_struct("CoherentCluster")
            .field("data_hash", &data_hash)
            .field("pair", &self.pair)
            .field("prices", &self.prices)
            .field("timestamp", &self.timestamp)
            .field("decimals", &self.decimals)
            .finish()
    }
}

impl Display for CoherentCluster {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl CoherentCluster {
    pub fn new(
        data_hash: Hash,
        pair: Vec<u32>,
        prices: Vec<u128>,
        timestamp: Vec<u128>,
        decimals: Vec<u16>,
    ) -> CoherentCluster {
        CoherentCluster {
            data_hash,
            pair,
            prices,
            timestamp,
            decimals,
        }
    }

    pub fn get_hash(&self) -> Hash {
        digest(self.to_bytes())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn into_tokens(&self) -> Vec<Token> {
        let data_hash = Token::FixedBytes(self.data_hash.to_vec());

        let mut pair_tokens = vec![];
        for i in 0..self.pair.len() {
            pair_tokens.push(Token::Uint(Uint::from(self.pair[i])))
        }

        let mut price_tokens = vec![];
        for i in 0..self.prices.len() {
            price_tokens.push(Token::Uint(Uint::from(self.prices[i])))
        }

        let mut timestamp_tokens = vec![];
        for i in 0..self.timestamp.len() {
            timestamp_tokens.push(Token::Uint(Uint::from(self.timestamp[i])))
        }

        let mut decimals_tokens = vec![];
        for i in 0..self.decimals.len() {
            decimals_tokens.push(Token::Uint(Uint::from(self.decimals[i])))
        }

        let arr: Vec<Token> = [
            data_hash,
            Token::Array(pair_tokens),
            Token::Array(price_tokens),
            Token::Array(timestamp_tokens),
            Token::Array(decimals_tokens),
        ]
        .to_vec();
        // let tuple = Token::Tuple(arr);
        // vec![tuple]
        arr
    }
}

#[derive(Clone, Serialize, Copy, Deserialize, PartialEq, Eq)]
pub struct Origin {
    pub id: PublicKey,
    pub member_index: u64,
    pub committee_index: u64,
}

impl Debug for Origin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Origin")
            .field("id", &self.id)
            .field("member_index", &self.member_index)
            .field("committee_index", &self.committee_index)
            .finish()
    }
}

impl Origin {
    #[allow(clippy::wrong_self_convention)]
    pub fn into_token(&self) -> Vec<Token> {
        let id = Token::FixedBytes(self.id.to_bytes().to_vec());
        let member_index = Token::Uint(Uint::from(self.member_index));
        let committee_index = Token::Uint(Uint::from(self.committee_index));
        let arr: Vec<Token> = [id, member_index, committee_index].to_vec();
        // let tuple = Token::Tuple(arr);
        // vec![tuple]
        arr
    }
}

///
/// Deserializer logic for `BlsSignature` fiend in `BlsSignature`
///
pub fn deserialize_bls_signature<'de, D>(d: D) -> Result<BlsSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let b: &[u8] = serde::Deserialize::deserialize(d)?;
    let e = BlsSignature::try_from(b).map_err(|_e| D::Error::custom("Unable to deserialize"))?;
    Ok(e)
}

///
/// Serializer logic for `BlsSignature` fiend in `BlsSignature`
///
pub fn serialize_bls_signature<S>(x: &BlsSignature, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = s.serialize_bytes(&x.to_vec())?;
    Ok(bytes)
}

pub(crate) mod clusterbcs {
    use crate::sosmr_types::transactions::oracle_payload::deserialize_bls_signature;
    use crate::sosmr_types::transactions::oracle_payload::serialize_bls_signature;
    use crate::sosmr_types::Round;
    use crate::sosmr_types::SmrError;
    use nidkg_helper::BlsSignature;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct ContractCoherentCluster {
        pub data_hash: Vec<u8>,
        pub pair: Vec<u32>,
        pub prices: Vec<u128>,
        pub timestamp: Vec<u128>,
        pub decimals: Vec<u16>,
    }

    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
    pub struct ContractOrigin {
        pub id: Vec<u8>,
        pub member_index: u64,
        pub committee_index: u64,
    }

    #[derive(Serialize, Deserialize, Clone, Debug)]
    pub struct ContractSignedCC {
        pub cc: ContractCoherentCluster,
        #[serde(
            serialize_with = "serialize_bls_signature",
            deserialize_with = "deserialize_bls_signature"
        )]
        pub qc: BlsSignature,
        pub round: Round,
        pub origin: ContractOrigin,
    }

    impl ContractSignedCC {
        pub fn encode_bcs(&self) -> Result<Vec<u8>, SmrError> {
            bcs::to_bytes(self).map_err(|err| {
                SmrError::GeneralError(format!("ContractSignedCC BCS serialize error:{}", err))
            })
        }
    }

    impl From<super::SignedCoherentCluster> for ContractSignedCC {
        fn from(data: super::SignedCoherentCluster) -> Self {
            let cc = ContractCoherentCluster {
                data_hash: data.cc.data_hash.to_vec(),
                pair: data.cc.pair,
                prices: data.cc.prices,
                timestamp: data.cc.timestamp,
                decimals: data.cc.decimals,
            };
            let origin = ContractOrigin {
                id: data.origin.id.to_bytes().to_vec(),
                member_index: data.origin.member_index,
                committee_index: data.origin.committee_index,
            };
            ContractSignedCC {
                cc,
                origin,
                qc: data.qc,
                round: data.round,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::sosmr_types::transactions::oracle_payload::Origin;
    use crate::sosmr_types::transactions::oracle_payload::{
        CoherentCluster, SignedCoherentCluster,
    };
    use crate::sosmr_types::Round;
    use nidkg_helper::BlsPrivateKey;

    use socrypto::{digest, SecretKey};

    pub(crate) fn generate_signed_coherent_cluster() -> SignedCoherentCluster {
        let secret_key = SecretKey::new();
        let fix_pub_key = secret_key.gen_vk();

        let hash = digest(b"hello");
        let cc = CoherentCluster::new(
            hash,
            vec![1, 2, 3],
            vec![100, 200, 300],
            vec![1234567890123, 1234567890123, 1234567890123],
            vec![18, 18, 18],
        );

        let bls_priv = BlsPrivateKey::random();
        let bls_sig = bls_priv.sign(b"dummy");

        let round: Round = 1234560;
        let origin = Origin {
            id: fix_pub_key,
            committee_index: 0,
            member_index: 0,
        };
        SignedCoherentCluster::new(cc, bls_sig, round, origin)
    }
    #[test]
    fn test_bcs_ser() {
        let a = generate_signed_coherent_cluster();
        let a_bcs = a.encode_bcs();
        assert!(a_bcs.is_ok());
    }
}
