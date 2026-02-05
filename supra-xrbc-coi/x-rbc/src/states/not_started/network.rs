use crate::states::not_started::NotStarted;
use crate::states::WaitingForShare;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::network::{NetworkFSMContext, NetworkFSMContextSchema};
use crate::types::context::FSMContextOwner;
use sfsm::{State, TransitGuard, Transition};

/// ------------------------------------------------------------------------------------------------
/// NotStartedNetworkFSM<C: SupraDeliveryErasureCodecSchema>
/// ------------------------------------------------------------------------------------------------
///
/// Initial state for the state machine handling network messages
/// State machine does not stay in this state and it does not have any functional meaning except
/// being the traditional initial state
/// The state machine will directly transit to the next state: WFS
///
pub(crate) type NotStartedNetworkFSM<C> = NotStarted<NetworkFSMContext<C>>;

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for NotStartedNetworkFSM<C> {
    type Schema = NetworkFSMContextSchema<C>;
    fn context(&self) -> &NetworkFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut NetworkFSMContext<C> {
        &mut self.context
    }
}

///
/// State & Transition definitions for non-committee-state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> State for NotStartedNetworkFSM<C> {}

/// ------------------------------------------------------------------------------------------------
/// NotStartedNetworkFSM -> WaitingForShare
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForShare<C>> for NotStartedNetworkFSM<C> {
    fn into(self) -> WaitingForShare<C> {
        WaitingForShare::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForShare<C>>
    for NotStartedNetworkFSM<C>
{
    ///
    /// Transition to WFS state right after NotStarted state
    ///
    fn guard(&self) -> TransitGuard {
        TransitGuard::Transit
    }
}
