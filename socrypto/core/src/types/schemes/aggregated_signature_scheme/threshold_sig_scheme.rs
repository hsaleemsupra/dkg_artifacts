use super::{AggregateSignatureScheme, TPublicParameters};
use crate::types::impls::helpers::serde::pretty_encode_base64;
use crate::types::serde::TCryptoSerde;
use crate::types::{CryptoError, CryptoResult, Identity, Order};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

/// Generic representation of threshold signature scheme
pub trait ThresholdSignatureScheme: AggregateSignatureScheme {
    /// secret keys from nidkg
    type DkgSecretKeys;
    /// public parameters from nidkg
    type DkgPublicParameters;
    /// public transcript output by nidkg
    /// note this may be
    type DkgTranscript;

    /// Initialize signing key and public parameters from DKG transcript, DKG secret keys, and DKG public parameters
    fn init_as_signer(
        sk_dkg: &Self::DkgSecretKeys,
        pp_dkg: &Self::DkgPublicParameters,
        transcript: &Self::DkgTranscript,
    ) -> (
        <Self as AggregateSignatureScheme>::SigningKeyType,
        <Self as AggregateSignatureScheme>::PublicParametersType,
    );

    /// Initialize public parameters for signature scheme from DKG public parameters and public transcript
    fn init_as_verifier(
        pp_dkg: &Self::DkgPublicParameters,
        transcript: Self::DkgTranscript,
    ) -> <Self as AggregateSignatureScheme>::PublicParametersType;

    /// TEMPORARY ONLY keygen using trusted setup
    /// eventually will be replaced with keygen generic (distributed or trusted)
    fn trusted_dkg(
        thresh: Order,
        num_parties: Order,
    ) -> (
        Vec<<Self as AggregateSignatureScheme>::SigningKeyType>,
        <Self as AggregateSignatureScheme>::PublicParametersType,
    );
}

/// Wrapper struct representing a public parameters for a multi-party signer of threshold signature
#[derive(Clone)]
pub struct GenericPublicParameters<VK, PK> {
    pub(crate) order_map: Arc<HashMap<Arc<Identity>, Order>>,
    pub(crate) keys: Arc<Vec<VK>>,
    pub(crate) identities: Arc<Vec<Arc<Identity>>>,

    pub(crate) pk: Arc<PK>,
    pub(crate) threshold: Order,
}

impl<VK, PK: TCryptoSerde> Debug for GenericPublicParameters<VK, PK> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", pretty_encode_base64(&self.pk.to_raw()))
    }
}

impl<VK, PK> GenericPublicParameters<VK, PK> {
    /// Initializes new GenericPublicParameters from identity map, public key, and threshold
    pub fn new<I: IntoIterator<Item = (Identity, VK)>>(
        id_map: I,
        public_key: PK,
        threshold: Order,
    ) -> CryptoResult<Self> {
        let ordered_map = id_map.into_iter().collect::<BTreeMap<Identity, VK>>();
        if threshold.0 as usize > ordered_map.len() {
            return Err(CryptoError::InvalidThresholdValue {
                upper_bound: ordered_map.len().into(),
                threshold,
            });
        }
        let (keys, (order_map, identities)): (Vec<_>, (HashMap<_, _>, Vec<_>)) = ordered_map
            .into_iter()
            .enumerate()
            .map(|(idx, (id, vk))| (vk, idx, Arc::new(id)))
            .map(|(vk, idx, id)| (vk, ((id.clone(), idx.into()), id)))
            .unzip();
        Ok(Self {
            keys: Arc::new(keys),
            order_map: Arc::new(order_map),
            identities: Arc::new(identities),
            pk: Arc::new(public_key),
            threshold,
        })
    }
}

impl<VK, PK> TPublicParameters<VK, PK> for GenericPublicParameters<VK, PK> {
    fn public_key(&self) -> &PK {
        &self.pk
    }
    fn verification_key(&self, identity: &Identity) -> Option<&VK> {
        self.order_map
            .get(identity)
            .and_then(|order| self.verification_key_by_order(order))
    }
    fn verification_key_by_order(&self, order: &Order) -> Option<&VK> {
        self.keys.get(order.index())
    }
    fn threshold(&self) -> usize {
        self.threshold.index()
    }
    fn identity_order(&self, identity: &Identity) -> Option<&Order> {
        self.order_map.get(identity)
    }
    fn identity_by_order(&self, order: &Order) -> Option<&Identity> {
        self.identities.get(order.index()).map(|a| a.as_ref())
    }
    fn identities(&self) -> Vec<&Identity> {
        self.identities.iter().map(|id| id.as_ref()).collect()
    }
}
