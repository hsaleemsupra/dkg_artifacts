use crate::states::done::{Done, DoneCommitteeFSM};
use crate::states::handlers::{
    CommitteeChunkBroadcaster, CommitteeMessageHandler, CommitteeMessageReceiver, FSMErrorHandler,
    InputVerifier, TimeoutMessageHandler,
};
use crate::states::waiting_for_certificate::WaitingForCertificate;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
use crate::tasks::LoggingName;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::assignment_extractor::AssignmentExtractor;

use crate::types::helpers::Visitor;
use crate::types::messages::available::Available;
use crate::types::messages::certificate_data::QuorumCertificateData;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    CommitteeFSMResponseMessage, EchoReadyData, EchoValueData, RBCCommitteeMessage, ReadyData,
    ResponseTypeIfc, ValueData, VoteData,
};
use crate::types::payload_state::committee::{CommitteePayloadFlags, CommitteePayloadTag};
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use log::info;
use metrics::{
    impl_timestamp, nanoseconds_since_unix_epoch, report, MetricValue, TimeStampTrait, Timestamp,
};
use primitives::types::HeaderIfc;
use primitives::types::QuorumCertificate;
use sfsm::{ReceiveMessage, ReturnMessage, State, TransitGuard, Transition};

///
/// Committee message handler FSM state entered in case of message data was reconstructed
/// but no quorum certificate or integrity certificate is available
///
/// Based on the current node and message relationship state execution flow differs.
/// The possible relationship between current node and actual deliverable message is:
///     - node is the proposer/broadcaster of the data
///     - node is a committee member with data-proposer
///
/// According to the protocol:
///     - broadcaster does not vote for data
///     - broadcaster collects votes from committee peers and creates quorum certificate when enough
///       are available
///     - broadcaster should not expect any data except vote messages in this state,
///     - non-broadcaster only votes for the data
///     - non-broadcaster should not expect any vote message
///     - unexpected messages should be ignored and message senders should be blacklisted/reported
///     - duplicate message should be simply ignored
///     - all input message should be verified based on verification rules before being processed
///
/// Note: As an optimization for non-broadcasters transition to WFC state can be enabled after voting
///
pub(crate) struct WaitingForVote<C: SupraDeliveryErasureCodecSchema> {
    context: CommitteeFSMContext<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    WaitingForVote<Schema: SupraDeliveryErasureCodecSchema>
);

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for WaitingForVote<C> {
    type Schema = CommitteeFSMContextSchema<C>;
    fn context(&self) -> &CommitteeFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut CommitteeFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for WaitingForVote<C> {
    fn name<'a>() -> &'a str {
        "WaitingForVote"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> WaitingForVote<C> {
    pub(crate) fn new(context: CommitteeFSMContext<C>) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn has_quorum_reached(&self) -> bool {
        self.authenticator().threshold() == self.payload_state().votes_len()
    }

    pub(crate) fn sign(&self) -> VoteData {
        let auth = self.authenticator();
        let header = self.payload_state().header();
        let vote = auth.partial_signature(header.commitment()).unwrap();
        VoteData::new(header.clone(), vote)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for WaitingForVote<C>
where
    Self: FSMErrorHandler<RBCCommitteeMessage<C>, CommitteeFSMContextSchema<C>>,
{
    ///
    /// (Non-broadcaster node) Upon entry a vote is created and sent to data broadcaster.
    ///
    fn entry(&mut self) {
        if !self.payload_state().has_payload_data() {
            panic!("Internal implementation error, entered WFV state without payload data")
        }
        // If current node is data broadcaster, do nothing
        if self.is_data_broadcaster() {
            return;
        }
        // Sign
        let vote_data = self.sign();
        // Store the vote to re-send if required later
        self.payload_state_mut().add_vote(vote_data.vote().clone());

        // Broadcast
        let addresses = <AssignmentExtractor as Visitor<C>>::visit_vote(
            &self.assignment_extractor(),
            &vote_data,
        )
        .unwrap();
        let msg = (RBCCommitteeMessage::from(vote_data), addresses);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    ///
    /// Tries to create quorum certificate based on the so far collected votes.
    ///
    /// - If quorum reached the certificate is create and Available message is sent as feedback to
    /// delivery manager
    /// - Upon any error Feedback::InternalError is sent to delivery manager
    ///
    fn execute(&mut self) {
        if !self.has_quorum_reached() {
            return;
        }
        let votes = self.payload_state_mut().take_votes();
        let participants = votes.iter().map(|vote| vote.index()).collect();
        let maybe_qc = self
            .authenticator()
            .threshold_signature(votes)
            .map(|cert| QuorumCertificate::new(cert, participants));
        if let Ok(qc) = maybe_qc {
            report(
                &[
                    &CommitteePayloadTag::QCCreation,
                    self.payload_state().header(),
                    &CommitteePayloadTag::TagName,
                ],
                MetricValue::AsSeconds(self.elapsed_time()),
            );
            let qc_bytes = bincode::serialize(&qc).unwrap();
            let qc_signature = self.authenticator().sign(&qc_bytes).unwrap();
            self.payload_state_mut().set_certificate(qc.clone());
            self.broadcast_quorum_certificate_data(qc_signature, qc.clone());
            let header = self.payload_state().get_header();
            let available = Available::new(header, qc_signature, qc);
            let feedback = FeedbackMessage::Available(available);
            info!("{}: {}", Self::name(), feedback);
            self.response_mut().add_feedback(feedback);
        } else {
            self.register_internal_error(format!(
                "Failed to generate threshold signature: {:?}",
                self.payload_state().header()
            ));
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeChunkBroadcaster<C> for WaitingForVote<C> {}

/// Transition Interface definition from WaitingForData for CommitteeStateMachine

/// ------------------------------------------------------------------------------------------------
/// WaitingForVote -> WaitingForCertificate
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForCertificate<C>> for WaitingForVote<C> {
    fn into(self) -> WaitingForCertificate<C> {
        WaitingForCertificate::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForCertificate<C>>
    for WaitingForVote<C>
{
    ///
    /// Transition to WFC state is possible if
    ///     - no-error has been registered
    ///     - data is reconstructed
    ///     - quorum certificate is available or current node is not a deliverable owner(broadcaster)o
    ///
    /// Thus, only broadcaster of the deliverable stays in WFV state, the rest of the peers transition
    /// directly to WFC state.
    ///
    fn guard(&self) -> TransitGuard {
        (!self.payload_state().failed()
            && self.payload_state().has_payload_data()
            && (self.payload_state().is_certified() || !self.is_data_broadcaster()))
        .into()
    }
}

/// ------------------------------------------------------------------------------------------------
/// WaitingForVote -> DoneCommitteeFSM
///
impl<C: SupraDeliveryErasureCodecSchema> Into<DoneCommitteeFSM<C>> for WaitingForVote<C> {
    fn into(self) -> DoneCommitteeFSM<C> {
        Done::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<DoneCommitteeFSM<C>> for WaitingForVote<C> {
    ///
    /// Transition to Done state if any error is registered
    ///
    fn guard(&self) -> TransitGuard {
        self.payload_state().failed().into()
    }
}

/// Message handling and Response Query interfaces for WaitingForData state of CommitteeStateMachine

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<CommitteeFSMResponseMessage<C>>
    for WaitingForVote<C>
{
    fn return_message(&mut self) -> Option<CommitteeFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<RBCCommitteeMessage<C>>
    for WaitingForVote<C>
{
    fn receive_message(&mut self, message: RBCCommitteeMessage<C>) {
        self.handle_message(message)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<TimeoutMessage> for WaitingForVote<C>
where
    Self: CommitteeChunkBroadcaster<C>,
{
    fn receive_message(&mut self, message: TimeoutMessage) {
        if self.is_data_broadcaster() {
            self.handle_timeout(message)
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> TimeoutMessageHandler for WaitingForVote<C>
where
    Self: LoggingName,
{
    fn handle_retry(&mut self) {
        info!(
            "{} <= Timeout (Retry): {}",
            Self::name(),
            self.payload_state().header()
        );
        self.broadcast_committee_data();
    }
}

/// Implement Verifier  for messages
impl<C: SupraDeliveryErasureCodecSchema> InputVerifier<C, RBCCommitteeMessage<C>>
    for WaitingForVote<C>
{
}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeMessageReceiver<C> for WaitingForVote<C> {}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeMessageHandler for WaitingForVote<C>
where
    Self: FSMErrorHandler<RBCCommitteeMessage<C>, CommitteeFSMContextSchema<C>>,
{
    type Value = ValueData<C>;
    type EchoValue = EchoValueData<C>;
    type Ready = ReadyData<C>;
    type EchoReady = EchoReadyData<C>;

    ///
    /// Only Broadcaster stays in WFV state, Non-Broadcasters moved directly to WFC state
    /// Value messages are not expected in this state.
    ///
    fn handle_value(&mut self, msg: Self::Value) {
        self.register_internal_error(format!(
            "Unexpected value message in WFV state. Transition or Message verification error: {:?}",
            msg
        ));
    }

    ///
    /// Only Broadcaster stays in WFV state, Non-Broadcasters moved directly to WFC state
    /// EchoValue messages are not expected in this state.
    ///
    fn handle_echo_value(&mut self, msg: Self::EchoValue) {
        self.register_internal_error(format!(
            "Unexpected value message in WFV state. Transition or Message verification error: {:?}",
            msg
        ));
    }

    ///
    /// Stores input vote and sender as peer having all chunks
    ///
    fn handle_vote(&mut self, msg: VoteData) {
        let (_, vote) = msg.split();
        self.payload_state_mut().add_vote(vote);
    }

    ///
    /// Only Broadcaster stays in WFV state, Non-Broadcasters moved directly to WFC state
    /// Ready messages are not expected in this state.
    ///
    fn handle_ready(&mut self, msg: Self::Ready) {
        self.register_internal_error(format!(
            "Unexpected value message in WFV state. Transition or Message verification error: {:?}",
            msg
        ));
    }

    ///
    /// Only Broadcaster stays in WFV state, Non-Broadcasters moved directly to WFC state
    /// EchoReady messages are not expected in this state.
    ///
    fn handle_echo_ready(&mut self, msg: Self::EchoReady) {
        self.register_internal_error(format!(
            "Unexpected value message in WFV state. Transition or Message verification error: {:?}",
            msg
        ));
    }

    ///
    /// Certificate can not be generated without QC, QC is based on committee votes.
    /// So while broadcaster is in WFV state, no certificate can be expected for the message,
    /// as QC is not generated yet. Hence Internal error should be reported.
    ///
    /// Non-broadcaster peers do not stay in WFV state, after voting they transition directly to
    /// WFC state and no message is consumed in this state
    ///
    fn handle_certificate(&mut self, msg: QuorumCertificateData) {
        self.register_internal_error(format!(
            "WFV state, QC for deliverable is not ready yet, no Certificate should have been produced: {:?}",
            msg
        ));
    }

    fn handle_pull_request(&mut self, msg: PullRequest) {
        self.register_internal_error(format!(
            "WFV state, QC for deliverable is not ready yet, no PullRequest is excepted: {:?}",
            msg
        ));
    }

    fn handle_sync_request(&mut self, msg: SyncRequest) {
        self.register_internal_error(format!(
            "WFV state, QC for deliverable is not ready yet, no SyncRequest is excepted: {:?}",
            msg
        ));
    }

    fn handle_payload(&mut self, msg: PayloadData) {
        self.register_internal_error(format!(
            "Unexpected payload message in WFV state. Transition or Message verification error: {:?}",
            msg
        ));
    }
}
