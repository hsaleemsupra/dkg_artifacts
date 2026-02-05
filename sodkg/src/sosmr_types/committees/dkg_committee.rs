use crate::sosmr_types::SmrDeserialize;
use crate::sosmr_types::SmrError;
use nidkg_helper::BlsPrivateKey;
use nidkg_helper::BlsPublicKey;
use serde::{Deserialize, Serialize};
use socrypto::Identity;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DkgCommitteeNode {
    pub identity: Identity,
    pub node_number: u32,
    pub public_share: Option<BlsPublicKey>,
}

impl TryFrom<Vec<u8>> for DkgCommitteeNode {
    type Error = SmrError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        DkgCommitteeNode::try_from(&vec[..])
    }
}

impl TryFrom<&[u8]> for DkgCommitteeNode {
    type Error = SmrError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes).map_err(Self::Error::from)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DkgCommittee {
    pub private_key_share: Option<BlsPrivateKey>,
    pub threshold_public_key: BlsPublicKey,
    pub committee: Vec<DkgCommitteeNode>,
}

impl DkgCommittee {
    pub fn get_private_key_share(&self) -> Result<&BlsPrivateKey, SmrError> {
        self.private_key_share
            .as_ref()
            .ok_or_else(|| SmrError::BlsPrivateKeyShareMissing)
    }

    pub fn get_member(&self, id: &Identity) -> Option<&DkgCommitteeNode> {
        self.committee.iter().find(|n| n.identity == *id)
    }
}

impl TryFrom<Vec<u8>> for DkgCommittee {
    type Error = SmrError;

    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        DkgCommittee::try_from(&vec[..])
    }
}

impl TryFrom<&[u8]> for DkgCommittee {
    type Error = SmrError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes).map_err(Self::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::sosmr_types::SmrSerialize;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use socrypto::{Digest, SecretKey};

    #[test]
    fn test_smr_dkg_committee_node_serialization() {
        let (node, node2) = get_nodes();

        let bytes = node.to_bytes();
        let new_node = DkgCommitteeNode::try_from(&bytes[..]).unwrap();
        let new_bytes = new_node.to_bytes();
        assert_eq!(bytes, new_bytes);

        let bytes = node2.to_bytes();
        let new_node = DkgCommitteeNode::try_from(&bytes[..]).unwrap();
        let new_bytes = new_node.to_bytes();
        assert_eq!(bytes, new_bytes);
    }

    #[test]
    fn test_smr_dkg_committee_serialization() {
        let (node, node2) = get_nodes();

        let private_share = BlsPrivateKey::random();
        let public_share = private_share.public_key();

        //empty
        let mut committee = DkgCommittee {
            private_key_share: Some(private_share),
            threshold_public_key: public_share,
            committee: vec![],
        };
        asset_committee(&committee);

        committee.committee.push(node.clone());
        asset_committee(&committee);
        committee.committee.clear();
        committee.committee.push(node2.clone());
        asset_committee(&committee);
        committee.committee.push(node.clone());
        asset_committee(&committee);
    }

    fn get_nodes() -> (DkgCommitteeNode, DkgCommitteeNode) {
        let secret_key1 = SecretKey::new();
        let pubkey1 = secret_key1.gen_vk();

        let node = DkgCommitteeNode {
            identity: Identity::new(pubkey1.digest()),
            node_number: 12,
            public_share: None,
        };

        let secret_key2 = SecretKey::new();
        let pubkey2 = secret_key2.gen_vk();
        let private_key = BlsPrivateKey::random();
        let public_share = private_key.public_key();

        let node2 = DkgCommitteeNode {
            identity: Identity::new(pubkey2.digest()),
            node_number: 234543334,
            public_share: Some(public_share),
        };
        (node, node2)
    }

    fn asset_committee(committee: &DkgCommittee) {
        let bytes = committee.to_bytes();
        let new_committee = DkgCommittee::try_from(&bytes[..]).unwrap();
        let new_bytes = new_committee.to_bytes();
        assert_eq!(bytes, new_bytes);
    }
}
