use crate::states::handlers::{FSMErrorHandler, InputVerifier};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::committee::CommitteeFSMContextSchema;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::verifier_visitor::VerificationResult;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoValueData, RBCCommitteeMessage, ReadyData, ValueData, VoteData,
};
use crate::types::payload_state::committee::CommitteePayloadState;
use crate::QuorumCertificateData;
use log::info;
use primitives::types::HeaderIfc;

///
/// Common interface to handle RBC committee messages in any states of CommitteeStateMachine.
///
pub(crate) trait CommitteeMessageHandler {
    type Value;
    type EchoValue;
    type Ready;
    type EchoReady;

    fn handle_value(&mut self, msg: Self::Value);
    fn handle_echo_value(&mut self, msg: Self::EchoValue);
    fn handle_vote(&mut self, msg: VoteData);
    fn handle_ready(&mut self, msg: Self::Ready);
    fn handle_echo_ready(&mut self, msg: Self::EchoReady);
    fn handle_certificate(&mut self, msg: QuorumCertificateData);
    fn handle_pull_request(&mut self, msg: PullRequest);
    fn handle_sync_request(&mut self, msg: SyncRequest);
    fn handle_payload(&mut self, msg: PayloadData);
}

///
/// Common interface to receive RBC committee messages in any states of CommitteeStateMachine.
///
/// Before each message is handled and state is updated it is verified
/// Verification includes:
///     - checking duplicates
///     - verifying message according to the defined rules (See VerifierVisitor for verification rules)
///
/// Duplicate messages are ignored as well as failed messages but error message is registered as
/// feedback to delivery manager in case of verification failure.
/// If verification fails, the input message is never processed and the state-machine is not stopped
/// (i.e. it doesn't transition to DONE state.
///
pub(crate) trait CommitteeMessageReceiver<C: SupraDeliveryErasureCodecSchema>
where
    Self: InputVerifier<C, RBCCommitteeMessage<C>>
        + CommitteeMessageHandler<
            Value = ValueData<C>,
            EchoValue = EchoValueData<C>,
            Ready = ReadyData<C>,
            EchoReady = EchoReadyData<C>,
        > + FSMContextOwner<Schema = CommitteeFSMContextSchema<C>>
        + FSMErrorHandler<RBCCommitteeMessage<C>, CommitteeFSMContextSchema<C>>
        + LoggingName,
{
    fn handle_message(&mut self, message: RBCCommitteeMessage<C>) {
        match self.verify_message(&message) {
            VerificationResult::Failed => {
                self.register_error(message);
            }
            VerificationResult::Ignore => {
                info!("Ignoring message: {}", message);
            }
            VerificationResult::Success => self.process(message),
        }
    }

    fn verify_message(&self, message: &RBCCommitteeMessage<C>) -> VerificationResult {
        self.verify_message_wrt_delivery_state(message)
            .and_then(|| {
                if self.is_duplicate(message) {
                    VerificationResult::Ignore
                } else {
                    self.verify(message)
                }
            })
    }

    ///
    /// Checks whether the input message is expected by the task at all
    /// Currently Task handling
    ///     - broadcast can only receive vote from peers
    ///     - committee-delivery can receive any committee-message except vote
    ///
    fn verify_message_wrt_delivery_state(
        &self,
        message: &RBCCommitteeMessage<C>,
    ) -> VerificationResult {
        match message {
            RBCCommitteeMessage::Vote(_) => {
                VerificationResult::from(message.origin().eq(self.topology().origin()))
            }
            _ => VerificationResult::from(message.origin().ne(self.topology().origin())),
        }
    }

    ///
    /// Checks the input message being duplicate info
    /// Value message is not checked for duplication as it is always re-broadcast
    /// despite the fact whether it was already consumed by this node or not
    ///
    fn is_duplicate(&self, message: &RBCCommitteeMessage<C>) -> bool {
        let index = message.data_index().unwrap_or(usize::MAX);
        let payload_state: &CommitteePayloadState<C> = self.payload_state();
        match message {
            RBCCommitteeMessage::Vote(_) => payload_state.has_vote(index as u32),
            RBCCommitteeMessage::Value(_)
            | RBCCommitteeMessage::Payload(_)
            | RBCCommitteeMessage::Certificate(_)
            | RBCCommitteeMessage::Pull(_)
            | RBCCommitteeMessage::Sync(_) => false,
            _ => payload_state.has_chunk(index),
        }
    }

    fn process(&mut self, message: RBCCommitteeMessage<C>) {
        info!("{} <= {}", Self::name(), message);
        match message {
            RBCCommitteeMessage::Value(data) => self.handle_value(data),
            RBCCommitteeMessage::EchoValue(data) => self.handle_echo_value(data),
            RBCCommitteeMessage::Vote(data) => self.handle_vote(data),
            RBCCommitteeMessage::Certificate(data) => self.handle_certificate(data),
            RBCCommitteeMessage::Ready(data) => self.handle_ready(data),
            RBCCommitteeMessage::EchoReady(data) => self.handle_echo_ready(data),
            RBCCommitteeMessage::Composite(data) => {
                data.into_iter().for_each(|msg| self.process(msg))
            }
            RBCCommitteeMessage::Pull(data) => self.handle_pull_request(data),
            RBCCommitteeMessage::Sync(data) => self.handle_sync_request(data),
            RBCCommitteeMessage::Payload(data) => self.handle_payload(data),
        };
    }
}
