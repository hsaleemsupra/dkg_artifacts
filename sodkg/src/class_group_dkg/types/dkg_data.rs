use nidkg_helper::cgdkg::{CGPublicKey, NodeType};
use nidkg_helper::{BlsPublicKey};
use socrypto::Identity;
use std::cmp::Ordering;

#[derive(Clone)]
pub(crate) struct DkgNodeIdentify {
    // Identity of the participant in the DKG
    pub(crate) id: Identity,
    // Whether node belongs to DKG dealer clan or is a family node
    pub(crate) node_type: NodeType,
    // Class Group public key of the participant
    pub(crate) cg_pubkey: CGPublicKey,
}

pub(crate) type PublicPartialKey = BlsPublicKey;

/// Encloses properties describing DKG process state of the committee member for the local node
#[derive(Clone)]
pub(crate) struct DKGData {
    /// Identity of the committee member
    pub(crate) identity: DkgNodeIdentify,
    /// Index/position of the node in scope of the committee. Nodes are ordered based on their identity.
    pub(crate) node_number: u32,
    /// Indicates availability of the group public key share of the node
    pub(crate) public_share: Option<PublicPartialKey>,
    /// Indicates partial signature availability by threshold signing key share of the node on the group public key
    //pub(crate) public_partial_sign: Option<BlsPartialSignature>,
    /// Indicates availability of the group public key share of the node which is cached but not verified
    pub(crate) cached_public_share: Option<PublicPartialKey>,
    /*/// Indicates partial signature availability by threshold signing key share of the node on the group public key
    /// which is cached but not verified
   pub(crate) cached_public_partial_sign: Option<BlsPartialSignature>,*/
}

impl DKGData {
    pub(crate) fn new(node_number: u32, identity: DkgNodeIdentify) -> DKGData {
        DKGData {
            identity,
            node_number,
            public_share: None,
            //public_partial_sign: None,
            cached_public_share: None,
            //cached_public_partial_sign: None,
        }
    }
}

impl PartialEq for DKGData {
    fn eq(&self, other: &Self) -> bool {
        self.identity.id == other.identity.id
    }
}

impl PartialOrd for DKGData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.identity.id.cmp(&other.identity.id))
    }
}

impl Ord for DKGData {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity.id.cmp(&other.identity.id)
    }
}

impl Eq for DKGData {}
