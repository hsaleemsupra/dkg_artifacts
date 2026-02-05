use super::AggregateSignatureScheme;

//use crate::types::sampleable::Sampleable;

use super::TPublicParameters;
use crate::types::serde::TRawRepresentation;
use crate::types::{CryptoError, CryptoResult, Identity, Order};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

/// Generic representation of multisignature
pub trait MultiSignatureScheme: AggregateSignatureScheme {
    /// Generate new random secret key.
    fn new_sk() -> <Self as AggregateSignatureScheme>::SigningKeyType;

    /// Generate new verification key `vk` from secret key `sk`.
    fn vk_from_sk(
        sk: &<Self as AggregateSignatureScheme>::SigningKeyType,
    ) -> <Self as AggregateSignatureScheme>::VerificationKeyType;

    /// Get order of parties who signed `sig`.
    fn get_signers(sig: &<Self as AggregateSignatureScheme>::AggregatedSignatureType)
        -> Vec<Order>;
}

/// Wrapper struct representing a public parameters for a multi-party signer  multi-signature scheme
#[derive(Clone)]
pub struct GenericPublicParameters<VK> {
    pub(crate) order_map: Arc<HashMap<Arc<Identity>, Order>>,
    pub(crate) keys: Arc<Vec<VK>>,
    pub(crate) identities: Arc<Vec<Arc<Identity>>>,

    pub(crate) threshold: Order,
}

impl<VK> Debug for GenericPublicParameters<VK> {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!("Implementation is pending and will be covered in separate PR")
    }
}

impl<VK> GenericPublicParameters<VK> {
    /// Initializes new GenericPublicParameters from identity map, public key, and threshold
    pub fn new<I: IntoIterator<Item = (Identity, VK)>>(
        id_map: I,
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
            threshold,
        })
    }
}

impl<VK> TPublicParameters<VK, GenericPublicParameters<VK>> for GenericPublicParameters<VK> {
    fn public_key(&self) -> &GenericPublicParameters<VK> {
        self
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

/// Wrapper struct representing a multi-signature for a multi-party signer multi-signature scheme
#[derive(Clone)]
pub struct GenericMultiSignature<S: Clone> {
    pub(crate) _sig: S,
    pub(crate) signers: Vec<Order>,
}

impl<T: TRawRepresentation + Clone> TRawRepresentation for GenericMultiSignature<T> {
    type Raw = Vec<u8>;

    fn create() -> Self::Raw {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn deserialize<'de, D: serde::Deserializer<'de>>(
        _deserializer: D,
    ) -> Result<Self::Raw, D::Error> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn serialize<S: serde::Serializer>(
        _raw: &Self::Raw,
        _serializer: S,
    ) -> Result<S::Ok, S::Error> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn to_raw(&self) -> Self::Raw {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn from(_data: &[u8]) -> CryptoResult<Self::Raw> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn from_raw(_src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        todo!("Implementation is pending and will be covered in separate PR")
    }
}

impl<T: TRawRepresentation> TRawRepresentation for GenericPublicParameters<T> {
    type Raw = Vec<u8>;

    fn create() -> Self::Raw {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn deserialize<'de, D: serde::Deserializer<'de>>(
        _deserializer: D,
    ) -> Result<Self::Raw, D::Error> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn serialize<S: serde::Serializer>(
        _raw: &Self::Raw,
        _serializer: S,
    ) -> Result<S::Ok, S::Error> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn to_raw(&self) -> Self::Raw {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn from(_data: &[u8]) -> CryptoResult<Self::Raw> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
    fn from_raw(_src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        todo!("Implementation is pending and will be covered in separate PR")
    }
}
