use super::{SignatureScheme, SignatureWrapper, VerificationKeyWrapperSig};
use crate::types::identity::Identity;
use crate::types::order::Order;
use crate::types::{CryptoError, CryptoResult};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

/// Wrapper struct representing a public parameters for a single signer signature scheme.
/// (hashmap from identity to verification key)
#[derive(Clone)]
pub struct PublicParametersWrapperSig<T: SignatureScheme> {
    pub(crate) order_map: Arc<HashMap<Arc<Identity>, Order>>,
    pub(crate) keys: Arc<Vec<T::VerificationKeyType>>,
    pub(crate) identities: Arc<Vec<Arc<Identity>>>,
}

impl<T: SignatureScheme> Debug for PublicParametersWrapperSig<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.order_map.keys().collect::<Vec<_>>())
    }
}

impl<T: SignatureScheme> PublicParametersWrapperSig<T> {
    /// Initialize self from mapping of identities to verification keys.
    pub fn new(id_map: HashMap<Identity, VerificationKeyWrapperSig<T>>) -> Self {
        let sorted = id_map
            .into_iter()
            .collect::<BTreeMap<Identity, VerificationKeyWrapperSig<T>>>();
        let ((keys, identities), inner): ((Vec<_>, Vec<_>), HashMap<_, _>) = sorted
            .into_iter()
            .enumerate()
            .map(|(idx, (key, value))| ((Arc::new(key), idx), value))
            .map(|((key, idx), value)| ((value.inner, key.clone()), (key, idx.into())))
            .unzip();
        Self {
            order_map: Arc::new(inner),
            keys: Arc::new(keys),
            identities: Arc::new(identities),
        }
    }

    /// Get an iterator over the identities in the public parameters.
    pub fn identities(&self) -> impl Iterator<Item = &Identity> + '_ {
        self.order_map.keys().map(|id| id.as_ref())
    }

    /// Verify signature `sig` was signed with verification key corresponding to `id`.
    pub fn verify_signature<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        id: &Identity,
        sig: &SignatureWrapper<T>,
    ) -> CryptoResult<()> {
        match self.order_map.get(id) {
            Some(order) => {
                T::verify_signature(msg, &self.keys[Into::<usize>::into(*order)], &sig.inner)
            }
            None => Err(CryptoError::UnknownPkError(*id)),
        }
    }

    /// Verify signature `sig` was signed with verification key corresponding to identity of the specified `order`.
    pub fn verify_signature_by_order<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        order: Order,
        sig: &SignatureWrapper<T>,
    ) -> CryptoResult<()> {
        let idx: usize = order.into();
        match self.keys.get(idx) {
            Some(vk) => T::verify_signature(msg, vk, &sig.inner),
            None => Err(CryptoError::UnknownPkOrderError(order)),
        }
    }

    /// Get the verification key associated with identity `id` if present.
    pub fn get_vk(&self, id: &Identity) -> Option<VerificationKeyWrapperSig<T>> {
        self.order_map
            .get(id)
            .map(|idx| &self.keys[usize::from(*idx)])
            .cloned()
            .map(VerificationKeyWrapperSig::new)
    }

    /// Returns order of the identity in the parameter set if any exists.
    pub fn order(&self, id: &Identity) -> Option<Order> {
        self.order_map.get(id).copied()
    }

    /// Returns identity corresponding to the order if any exists.
    pub fn identity_by_order(&self, order: Order) -> Option<&Identity> {
        let idx: usize = order.into();
        self.identities.get(idx).map(|d| d.as_ref())
    }

    /// Checks whether current set contains the input identity
    pub fn contains(&self, id: &Identity) -> bool {
        self.order_map.contains_key(id)
    }

    #[allow(missing_docs)]
    pub fn len(&self) -> usize {
        self.order_map.len()
    }

    #[allow(missing_docs)]
    pub fn is_empty(&self) -> bool {
        self.order_map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::api::instances::ecdsa_sig_ed25519::SigningKeyEd25519Sig;
    use crate::api::types::single_sig_types::PublicParametersWrapperSig;
    use crate::types::{CryptoError, Digest, Identity};
    use std::collections::HashMap;

    #[test]
    fn check_verify_signature() {
        let sk1 = SigningKeyEd25519Sig::new();
        let sk2 = SigningKeyEd25519Sig::new();
        let sk3 = SigningKeyEd25519Sig::new();
        let vk1 = sk1.gen_vk();
        let vk2 = sk2.gen_vk();
        let vk3 = sk3.gen_vk();
        let id_vk1 = Identity::new(vk1.digest());
        let id_vk2 = Identity::new(vk2.digest());
        let id_vk3 = Identity::new(vk3.digest());

        let pub_params =
            PublicParametersWrapperSig::new(HashMap::from([(id_vk1, vk1), (id_vk2, vk2)]));

        let msg = b"test_message";
        let sig1 = sk1.sign_no_vk(msg);
        let sig2 = sk2.sign_no_vk(msg);

        assert!(pub_params.verify_signature(msg, &id_vk1, &sig1).is_ok());
        assert!(pub_params.verify_signature(msg, &id_vk2, &sig2).is_ok());

        assert!(matches!(
            pub_params.verify_signature(msg, &id_vk2, &sig1),
            Err(CryptoError::DalekError(_))
        ));

        assert!(matches!(
            pub_params.verify_signature(msg, &id_vk1, &sig2),
            Err(CryptoError::DalekError(_))
        ));

        assert!(matches!(
            pub_params.verify_signature(msg, &id_vk3, &sig1),
            Err(CryptoError::UnknownPkError(_))
        ));
    }

    #[test]
    fn check_verification_key_api() {
        let sk1 = SigningKeyEd25519Sig::new();
        let sk2 = SigningKeyEd25519Sig::new();
        let sk3 = SigningKeyEd25519Sig::new();
        let vk1 = sk1.gen_vk();
        let vk2 = sk2.gen_vk();
        let vk3 = sk3.gen_vk();
        let id_vk1 = Identity::new(vk1.digest());
        let id_vk2 = Identity::new(vk2.digest());
        let id_vk3 = Identity::new(vk3.digest());

        let pub_params =
            PublicParametersWrapperSig::new(HashMap::from([(id_vk1, vk1), (id_vk2, vk2)]));

        assert_eq!(pub_params.get_vk(&id_vk1).as_ref(), Some(&vk1));
        assert_eq!(pub_params.get_vk(&id_vk2).as_ref(), Some(&vk2));
        assert!(pub_params.get_vk(&id_vk3).is_none());

        assert!(pub_params.contains(&id_vk1));
        assert!(pub_params.contains(&id_vk2));
        assert!(!pub_params.contains(&id_vk3));
    }
}
