use crate::states::handlers::{FSMErrorHandler, InputVerifier};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::sync::SyncFSMContextSchema;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::verifier_visitor::VerificationResult;
use crate::types::messages::requests::PullRequest;
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCSyncMessage, ReadyData, ShareData,
};
use crate::types::payload_state::sync::{PayloadType, SyncPayloadState};
use log::info;
use primitives::types::HeaderIfc;

///
/// Common interface to handle RBC sync messages in any states of SyncStateMachine.
///
pub(crate) trait SyncMessageHandler {
    type EchoValue;
    type Ready;
    type EchoReady;
    type Share;
    type EchoShare;
    type Pull;

    fn handle_echo_value(&mut self, msg: Self::EchoValue);
    fn handle_ready(&mut self, msg: Self::Ready);
    fn handle_echo_ready(&mut self, msg: Self::EchoReady);
    fn handle_share(&mut self, msg: Self::Share);
    fn handle_echo_share(&mut self, msg: Self::EchoShare);
    fn handle_pull_request(&mut self, msg: Self::Pull);
}

///
/// Common interface to receive RBC sync messages in any states of SyncStateMachine.
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
pub(crate) trait SyncMessageReceiver<C: SupraDeliveryErasureCodecSchema>
where
    Self: InputVerifier<C, RBCSyncMessage<C>>
        + SyncMessageHandler<
            EchoValue = EchoValueData<C>,
            Ready = ReadyData<C>,
            EchoReady = EchoReadyData<C>,
            Share = ShareData<C>,
            EchoShare = EchoShareData<C>,
            Pull = PullRequest,
        > + FSMContextOwner<Schema = SyncFSMContextSchema<C>>
        + FSMErrorHandler<RBCSyncMessage<C>, SyncFSMContextSchema<C>>
        + LoggingName,
{
    fn handle_message(&mut self, message: RBCSyncMessage<C>) {
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

    fn verify_message(&self, message: &RBCSyncMessage<C>) -> VerificationResult {
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
    /// Checks whether the input message is expected with respect to the payload type which is being synced
    ///
    fn verify_message_wrt_delivery_state(&self, message: &RBCSyncMessage<C>) -> VerificationResult {
        match message {
            RBCSyncMessage::EchoValue(_)
            | RBCSyncMessage::Ready(_)
            | RBCSyncMessage::EchoReady(_) => VerificationResult::from(
                self.payload_state().payload_type() == PayloadType::Committee,
            ),
            RBCSyncMessage::Share(_) | RBCSyncMessage::EchoShare(_) => VerificationResult::from(
                self.payload_state().payload_type() == PayloadType::Network,
            ),
            RBCSyncMessage::Pull(request) => match self.payload_state().payload_type() {
                // Broadcaster clan node can expect pull request from both clan and network peers
                PayloadType::Committee => VerificationResult::Success,
                // No Pull request is expected from data broadcaster clan if current node is network-peer wrt broadcaster node
                PayloadType::Network => VerificationResult::from(
                    !self
                        .topology()
                        .are_clan_peers(request.sender(), self.payload_state().origin())
                        .unwrap_or(true),
                ),
            },
        }
    }

    fn is_duplicate(&self, message: &RBCSyncMessage<C>) -> bool {
        let index = message.data_index().unwrap_or(usize::MAX);
        let payload_state: &SyncPayloadState<C> = self.payload_state();
        match message {
            RBCSyncMessage::EchoValue(_)
            | RBCSyncMessage::Ready(_)
            | RBCSyncMessage::EchoReady(_)
            | RBCSyncMessage::EchoShare(_) => payload_state.has_chunk(index),
            RBCSyncMessage::Share(_) => payload_state.has_piece(index),
            RBCSyncMessage::Pull(_) => false,
        }
    }

    fn process(&mut self, message: RBCSyncMessage<C>) {
        info!("{} <= {}", Self::name(), message);
        match message {
            RBCSyncMessage::EchoValue(data) => self.handle_echo_value(data),
            RBCSyncMessage::Ready(data) => self.handle_ready(data),
            RBCSyncMessage::EchoReady(data) => self.handle_echo_ready(data),
            RBCSyncMessage::Pull(data) => self.handle_pull_request(data),
            RBCSyncMessage::Share(data) => self.handle_share(data),
            RBCSyncMessage::EchoShare(data) => self.handle_echo_share(data),
        };
    }
}
