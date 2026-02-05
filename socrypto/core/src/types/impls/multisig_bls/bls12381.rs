use super::{
    AggregateSignatureScheme, GenericMultiSignature, GenericPublicParameters, MultiSignatureScheme,
};
use crate::types::domain::UniqueDomain;
use crate::types::impls::helpers::bls12381::ecp_wrapper::EcpWrapper;
use crate::types::impls::helpers::secret_handler::SecretWrapper;
use crate::types::{CryptoResult, Identity, Order};
use miracl_core_bls12381::bls12381::ecp::ECP;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use crate::types::impls::helpers::bls12381::big_as_sk::BigSk;

pub(crate) type SigningKey = SecretWrapper<BigSk>;
pub(crate) type VerificationKey = EcpWrapper;
pub(crate) type AggregatedSignature = GenericMultiSignature<ECP>;
pub(crate) type PublicParameters = GenericPublicParameters<VerificationKey>;
pub(crate) type PartialSignature = ECP;

/// BLS Multisignature schema implemented on BLS 12381 elliptic curve
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct BlsMultisigBls12381<T: UniqueDomain>(PhantomData<T>);

impl<DST: UniqueDomain> AggregateSignatureScheme for BlsMultisigBls12381<DST> {
    type SigningKeyType = SigningKey;
    type VerificationKeyType = VerificationKey;
    type PartialSignatureType = PartialSignature;
    type AggregatedSignatureType = AggregatedSignature;
    type PublicParametersType = PublicParameters;
    type PublicKeyType = PublicParameters;

    fn sign<T: AsRef<[u8]>>(
        _msg: &T,
        _sk: &Self::SigningKeyType,
        _vk: &Self::VerificationKeyType,
    ) -> Self::PartialSignatureType {
        todo!("Implementation is pending and will be covered in separate PR")
    }

    fn sign_no_vk<T: AsRef<[u8]>>(
        _msg: &T,
        _sk: &Self::SigningKeyType,
    ) -> Self::PartialSignatureType {
        todo!("Implementation is pending and will be covered in separate PR")
    }

    fn verify_partial_signature<T: AsRef<[u8]>>(
        _msg: &T,
        _psig: &Self::PartialSignatureType,
        _vk: &Self::VerificationKeyType,
    ) -> CryptoResult<()> {
        todo!()
    }

    fn aggregate_partial_signatures<
        T: AsRef<[u8]>,
        PS: AsRef<Self::PartialSignatureType>,
        I: IntoIterator<Item = (Identity, PS)>,
    >(
        _msg: &T,
        _psigs: I,
        _pp: &Self::PublicParametersType,
    ) -> CryptoResult<Self::AggregatedSignatureType> {
        todo!("Implementation is pending and will be covered in separate PR")
    }

    fn verify_aggregated_signature<T: AsRef<[u8]>>(
        _msg: &T,
        _sig: &Self::AggregatedSignatureType,
        _pk: &Self::PublicKeyType,
    ) -> CryptoResult<()> {
        todo!("Implementation is pending and will be covered in separate PR")
    }
}

impl<DST: UniqueDomain> MultiSignatureScheme for BlsMultisigBls12381<DST> {
    fn new_sk() -> <Self as AggregateSignatureScheme>::SigningKeyType {
        todo!("Implementation is pending and will be covered in separate PR")
    }

    fn vk_from_sk(
        _sk: &<Self as AggregateSignatureScheme>::SigningKeyType,
    ) -> <Self as AggregateSignatureScheme>::VerificationKeyType {
        todo!("Implementation is pending and will be covered in separate PR")
    }

    fn get_signers(
        sig: &<Self as AggregateSignatureScheme>::AggregatedSignatureType,
    ) -> Vec<Order> {
        sig.signers.clone()
    }
}
