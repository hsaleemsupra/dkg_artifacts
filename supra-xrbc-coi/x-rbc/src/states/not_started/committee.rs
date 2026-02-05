use crate::states::handlers::{CommitteeChunkBroadcaster, NetworkShareBroadcaster};
use crate::states::not_started::NotStarted;
use crate::states::{WaitingForData, WaitingForVote};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::FSMContextOwner;

use crate::types::payload_state::PayloadFlags;
use sfsm::{State, TransitGuard, Transition};

///
/// Initial state for the state machine handling committee messages
///
/// State machine does not stay in this state and it transitions to the next state depending
/// on deliverable state
/// Committee Message delivery initiated:
///     - either when a new payload is produced by current node which should be delivered
///         - in this case state machine is already started with payload data available and
///           it will directly transition to WFV state, before broadcasting data to committee
///           (see State::execute() implementation)
///     - or when a deliverable message is received from committee peer
///         - in this case no payload details yet available and it will transition to WFD state
///
///
pub(crate) type NotStartedCommitteeFSM<C> = NotStarted<CommitteeFSMContext<C>>;

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for NotStartedCommitteeFSM<C> {
    type Schema = CommitteeFSMContextSchema<C>;
    fn context(&self) -> &CommitteeFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut CommitteeFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for NotStartedCommitteeFSM<C> {
    fn name<'a>() -> &'a str {
        "NotStartedCommitteeFSM"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for NotStartedCommitteeFSM<C> {
    ///
    /// If the task started upon new payload arrival, it is expected that state context already
    /// have all chunks and reconstructed payload
    ///
    /// - If payload in reconstructed and data is owned by current node
    ///     - Initiate broadcast of all committee chunks to peers
    ///     - Initiate echo-value for owned chunk to all peers in committee
    ///     - Initiate network chunk broadcast to the rest of the network
    /// - Otherwise do nothing
    ///
    /// According to protocol design state-machine does not stay in NotStarted state, it directly
    /// goes either to WFD(in case of non-broadcaster) or WFV(in case of broadcaster) state
    ///
    fn execute(&mut self) {
        if !self.payload_state().is_reconstructed() {
            return;
        }
        self.broadcast_committee_data();
        self.broadcast_network_shares();
    }
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkShareBroadcaster<C> for NotStartedCommitteeFSM<C> {}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeChunkBroadcaster<C>
    for NotStartedCommitteeFSM<C>
{
}

/// Transition Interface definition from NotStarted for CommitteeStateMachine

/// ------------------------------------------------------------------------------------------------
/// NotStartedCommitteeFSM -> WaitingForData
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForData<C>> for NotStartedCommitteeFSM<C> {
    fn into(self) -> WaitingForData<C> {
        WaitingForData::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForData<C>>
    for NotStartedCommitteeFSM<C>
{
    ///
    /// Transition to WFD state right after NotStarted state in case no reconstructed payload
    ///
    fn guard(&self) -> TransitGuard {
        (!self.payload_state().has_payload_data()).into()
    }
}

/// ------------------------------------------------------------------------------------------------
/// NotStartedCommitteeFSM -> WaitingForVote
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForVote<C>> for NotStartedCommitteeFSM<C> {
    fn into(self) -> WaitingForVote<C> {
        WaitingForVote::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForVote<C>>
    for NotStartedCommitteeFSM<C>
{
    ///
    /// Transition to WFV state right after NotStarted state in case reconstructed payload is available
    /// True for the deliverables produced by current node
    ///
    fn guard(&self) -> TransitGuard {
        self.payload_state().has_payload_data().into()
    }
}
