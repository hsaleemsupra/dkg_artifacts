mod aggregate_signature;
mod partial_signature;
mod pop;
mod public_key;
mod public_parameters;
mod signing_key;
mod verification_key;

pub use aggregate_signature::AggregatedSignatureWrapper;
pub use partial_signature::PartialSignatureWrapper;
pub use pop::PopWrapperAggSig;
pub use public_key::PublicKeyWrapperAggSig;
pub use public_parameters::PublicParametersWrapperAggSig;
pub use signing_key::SigningKeyWrapperAggSig;
pub use verification_key::VerificationKeyWrapperAggSig;

use crate::types::schemes::aggregated_signature_scheme::{
    AggregateSignatureScheme, MultiSignatureScheme, TPublicParameters, ThresholdSignatureScheme,
};

use super::Order;

pub(crate) fn trusted_dkg<TSS: ThresholdSignatureScheme>(
    thresh: Order,
    num_nodes: Order,
) -> (
    Vec<SigningKeyWrapperAggSig<TSS>>,
    PublicParametersWrapperAggSig<TSS>,
) {
    let (sks_inner, pp_inner) = TSS::trusted_dkg(thresh, num_nodes);
    let sks = sks_inner
        .into_iter()
        .map(|sk| SigningKeyWrapperAggSig::<TSS>(sk))
        .collect();
    let pp = PublicParametersWrapperAggSig::<TSS> { inner: pp_inner };
    (sks, pp)
}
