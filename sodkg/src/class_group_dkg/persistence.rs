use nidkg_helper::cgdkg::CGPublicKey;
use nidkg_helper::BlsPrivateKey;
use nidkg_helper::BlsPublicKey;
use serde::{Deserialize, Serialize};
use socrypto::Identity;
use crate::sosmr_types::DkgCommittee;
use crate::sosmr_types::DkgCommitteeNode;

pub const DKG_DATA_KEY: &str = "DKG";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgBlsPublicKey {
    key: String, //encoded pubkey.
}

impl From<&BlsPublicKey> for DkgBlsPublicKey {
    fn from(public_key: &BlsPublicKey) -> Self {
        DkgBlsPublicKey {
            key: hex::encode(public_key.to_vec()), //encoded pubkey.
        }
    }
}

impl From<&DkgBlsPublicKey> for BlsPublicKey {
    fn from(dkg_key: &DkgBlsPublicKey) -> Self {
        BlsPublicKey::try_from(&hex::decode(&dkg_key.key).unwrap()[..]).unwrap()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgBlsPrivateKey {
    key: String, //encoded private-key.
}

impl From<&BlsPrivateKey> for DkgBlsPrivateKey {
    fn from(priv_key: &BlsPrivateKey) -> Self {
        DkgBlsPrivateKey {
            key: hex::encode(priv_key.to_vec()), //encoded pubkey.
        }
    }
}

impl From<&DkgBlsPrivateKey> for BlsPrivateKey {
    fn from(dkg_key: &DkgBlsPrivateKey) -> Self {
        BlsPrivateKey::try_from(&hex::decode(&dkg_key.key).unwrap()[..]).unwrap()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgCGPubKey {
    key: String, //encoded pubkey.
}

impl From<&CGPublicKey> for DkgCGPubKey {
    fn from(pub_key: &CGPublicKey) -> Self {
        DkgCGPubKey {
            key: hex::encode(pub_key.to_vec()), //encoded pubkey.
        }
    }
}

impl From<&DkgCGPubKey> for CGPublicKey {
    fn from(dkg_key: &DkgCGPubKey) -> Self {
        CGPublicKey::try_from(&hex::decode(&dkg_key.key).unwrap()[..]).unwrap()
    }
}

/// State of the DKG protocol participant
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgNode {
    /// Identity of the participant in the network
    pub identity: Identity,
    /// Index of the participant in the DKG committee
    pub node_number: u32,
    /// Class Group public key of the participant
    pub cg_pubkey: DkgCGPubKey,
    /// ThresholdSigning key share corresponding to the node if any was registered.
    pub public_share: Option<DkgBlsPublicKey>,
}

/// Represents Distributed-Key (ThresholdSiging key) state when it has been successfully generated.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgData {
    /// Current DKG protocol participant private key share
    pub bls_privkey: DkgBlsPrivateKey,
    /// ThresholdSigning Public Key
    pub threshold_pubkey: DkgBlsPublicKey,
    /// State of each participant when ThresholdSigning key has been successfully generated
    pub dkg_committee: Vec<DkgNode>,
}

impl From<&DkgNode> for DkgCommitteeNode {
    fn from(node: &DkgNode) -> Self {
        DkgCommitteeNode {
            identity: node.identity,
            node_number: node.node_number,
            public_share: node.public_share.as_ref().map(BlsPublicKey::from),
        }
    }
}

impl From<&DkgData> for DkgCommittee {
    fn from(node: &DkgData) -> Self {
        DkgCommittee {
            private_key_share: Some(BlsPrivateKey::from(&node.bls_privkey)),
            threshold_public_key: BlsPublicKey::from(&node.threshold_pubkey),
            committee: node
                .dkg_committee
                .iter()
                .map(DkgCommitteeNode::from)
                .collect(),
        }
    }
}
