use crate::states::handlers::{FSMErrorHandler, InputVerifier};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::network::NetworkFSMContextSchema;
use crate::types::context::FSMContextOwner;
use crate::types::helpers::verifier_visitor::VerificationResult;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{EchoShareData, RBCNetworkMessage, ShareData};
use log::info;

///
/// Common interface to handle RBC network messages in any states of NetworkMessageStateMachine.
///
pub(crate) trait NetworkMessageHandler {
    type Share;
    type EchoShare;

    fn handle_share(&mut self, msg: Self::Share);
    fn handle_echo_share(&mut self, msg: Self::EchoShare);
    fn handle_pull_request(&mut self, msg: PullRequest);
    fn handle_sync_request(&mut self, msg: SyncRequest);
}

///
/// Common interface to receive RBC network messages in any states of NetworkMessageStateMachine.
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
pub(crate) trait NetworkMessageReceiver<C: SupraDeliveryErasureCodecSchema>
where
    Self: InputVerifier<C, RBCNetworkMessage<C>>
        + NetworkMessageHandler<Share = ShareData<C>, EchoShare = EchoShareData<C>>
        + FSMContextOwner<Schema = NetworkFSMContextSchema<C>>
        + FSMErrorHandler<RBCNetworkMessage<C>, NetworkFSMContextSchema<C>>
        + LoggingName,
{
    fn handle_message(&mut self, message: RBCNetworkMessage<C>) {
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

    fn verify_message(&self, message: &RBCNetworkMessage<C>) -> VerificationResult {
        if self.is_duplicate(message) {
            VerificationResult::Ignore
        } else {
            self.verify(message)
        }
    }

    fn is_duplicate(&self, message: &RBCNetworkMessage<C>) -> bool {
        let index = message.data_index().unwrap_or(usize::MAX);
        match message {
            // TODO: optimize skip pieces which are part of the share that is reconstructed
            RBCNetworkMessage::Share(_) => self.payload_state().has_piece(index),
            RBCNetworkMessage::EchoShare(_) => self.payload_state().has_chunk(index),
            RBCNetworkMessage::Pull(_) | RBCNetworkMessage::Sync(_) => false,
        }
    }

    fn process(&mut self, message: RBCNetworkMessage<C>) {
        info!("{} <= {}", Self::name(), message);
        match message {
            RBCNetworkMessage::Share(data) => self.handle_share(data),
            RBCNetworkMessage::EchoShare(data) => self.handle_echo_share(data),
            RBCNetworkMessage::Pull(data) => self.handle_pull_request(data),
            RBCNetworkMessage::Sync(data) => self.handle_sync_request(data),
        };
    }
}
