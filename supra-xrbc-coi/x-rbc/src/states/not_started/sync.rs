use crate::states::handlers::{
    PullRequestBroadcaster, PullRequestBroadcasterCommittee, PullRequestBroadcasterNetwork,
};
use crate::states::not_started::NotStarted;
use crate::states::{SyncReady, WaitingForSyncData};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::sync::{SyncFSMContext, SyncFSMContextSchema};
use crate::types::context::FSMContextOwner;
use crate::types::messages::requests::SyncRequest;
use crate::types::payload_state::sync::PayloadType;
use crate::types::payload_state::PayloadFlags;
use primitives::types::HeaderIfc;
use sfsm::{State, TransitGuard, Transition};

///
/// Initial state for the state machine handling payload synchronization
///
/// State machine does not stay in this state and it transitions to the next state depending
/// on deliverable sync state
/// Sync of the delivery initiated when a sync request is received
///     - either from internal Synchronizer component for a missing deliverable in the store
///     - or from other node in the chain
///         - despite the fact that current node has or doesn't have requested deliverable a sync task will be started
///
pub(crate) type NotStartedSyncFSM<C> = NotStarted<SyncFSMContext<C>>;

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for NotStartedSyncFSM<C> {
    type Schema = SyncFSMContextSchema<C>;
    fn context(&self) -> &SyncFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut SyncFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for NotStartedSyncFSM<C> {
    fn name<'a>() -> &'a str {
        "NotStartedSyncFSM"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for NotStartedSyncFSM<C> {
    ///
    /// If the task started based on  payload availability, it is expected that state context already
    /// has required data to reply to the external pull/sync requests.
    /// Otherwise it indicates that sync-task is started to pull/sync data from the chain
    ///
    /// - If no data is available
    ///     - Initiate broadcast of pull request to peers based on the payload type (Committee or Network)
    /// - Otherwise do nothing
    ///
    /// According to protocol design state-machine does not stay in NotStarted state, it directly
    /// goes either to WFSD or Ready state
    ///
    fn execute(&mut self) {
        if self.payload_state().is_reconstructed() {
            return;
        }
        let sync_request = SyncRequest::new(
            self.payload_state().get_header(),
            self.payload_state().get_qc(),
        );
        match self.payload_state().payload_type() {
            PayloadType::Committee => PullRequestBroadcasterCommittee(self.context_mut())
                .broadcast_pull_request(sync_request),
            PayloadType::Network => PullRequestBroadcasterNetwork(self.context_mut())
                .broadcast_pull_request(sync_request),
        };
    }
}

/// Transition Interface definition from NotStarted for SyncStateMachine

/// ------------------------------------------------------------------------------------------------
/// NotStartedSyncFSM -> WaitingForSyncData
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForSyncData<C>> for NotStartedSyncFSM<C> {
    fn into(self) -> WaitingForSyncData<C> {
        WaitingForSyncData::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForSyncData<C>>
    for NotStartedSyncFSM<C>
{
    ///
    /// Transition to WFSD state right after NotStarted state in case no payload data is available
    ///
    fn guard(&self) -> TransitGuard {
        (!self.payload_state().is_reconstructed()).into()
    }
}

/// ------------------------------------------------------------------------------------------------
/// NotStartedSyncFSM -> SyncReady
///
impl<C: SupraDeliveryErasureCodecSchema> Into<SyncReady<C>> for NotStartedSyncFSM<C> {
    fn into(self) -> SyncReady<C> {
        SyncReady::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<SyncReady<C>> for NotStartedSyncFSM<C> {
    ///
    /// Transition to SyncReady state right after NotStarted state in case payload data to respond
    /// to sync-requests are available
    /// True for the deliverables available in the current node store
    ///
    fn guard(&self) -> TransitGuard {
        self.payload_state().is_reconstructed().into()
    }
}
