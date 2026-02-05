use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
use crate::types::context::{FSMContextOwner, FSMContextSchema, ResourcesApi};
use crate::types::helpers::sender_extractor::SenderExtractor;
use crate::types::helpers::verifier_visitor::{VerificationResult, VerifierVisitor};
use crate::types::helpers::VisitorAcceptor;
use crate::types::messages::ResponseTypeIfc;
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use primitives::types::HeaderIfc;
use sfsm::ReceiveMessage;
use std::fmt::Display;

mod assemblers;
mod broadcast;
mod committee;
mod network;
mod sync;

pub(crate) use self::assemblers::{
    GenericAssembler, NetworkChunkAssembler, PayloadAssembler, ReconstructedDataAssembler,
};
pub(crate) use self::broadcast::{
    CommitteeChunkBroadcaster, NetworkShareBroadcaster, PullRequestBroadcaster,
    PullRequestBroadcasterCommittee, PullRequestBroadcasterNetwork,
};
pub(crate) use self::committee::{CommitteeMessageHandler, CommitteeMessageReceiver};
pub(crate) use self::network::{NetworkMessageHandler, NetworkMessageReceiver};
pub(crate) use self::sync::{SyncMessageHandler, SyncMessageReceiver};

///
/// Common interface to define/apply input message verification rules
///
/// By default it verifies all messages utilizing VerifierVisitor verification rules implementation
///
pub(crate) trait InputVerifier<C: SupraDeliveryErasureCodecSchema, M: VisitorAcceptor<C>>
where
    Self: FSMContextOwner,
{
    fn verify(&self, message: &M) -> VerificationResult {
        let verifier = VerifierVisitor::new(self.resources());
        message.accept(&verifier)
    }
}

///
/// Common interface to handle Timeout messages
///
pub(crate) trait TimeoutMessageHandler {
    fn handle_timeout(&mut self, message: TimeoutMessage) {
        match message {
            TimeoutMessage::Retry => self.handle_retry(),
        }
    }
    fn handle_retry(&mut self);
}

///
/// Common interface definition of handling errors in scope of FSM
///
pub(crate) trait FSMErrorHandler<InputMessageType, ContextSchema>
where
    ContextSchema: FSMContextSchema,
    ContextSchema::ResponseType: ResponseTypeIfc<FeedbackType = FeedbackMessage>,
    InputMessageType: HeaderIfc + Display + VisitorAcceptor<ContextSchema::CodecSchema>,
    Self: FSMContextOwner<Schema = ContextSchema>,
{
    ///
    /// Sends error feedback with message id and message sender info
    /// Payload state is not set to error state
    ///
    fn register_error(&mut self, message: InputMessageType) {
        let sender_extractor = SenderExtractor::new(self.topology());
        let sender_data = message.accept(&sender_extractor);
        let feedback = sender_data.map_or_else(
            || {
                FeedbackMessage::internal_error(
                    message.get_meta(),
                    format!("Verification failed: {}", message),
                )
            },
            |sender| FeedbackMessage::err_msg(message.get_meta(), *sender.id()),
        );

        self.response_mut().add_feedback(feedback);
    }

    ///
    /// Registers internal error and sets error state
    ///
    fn register_internal_error(&mut self, error_msg: String) {
        let meta = self.payload_state().header().get_meta();
        let error = FeedbackMessage::internal_error(meta, error_msg);
        self.register_error_feedback(error);
    }

    ///
    /// Updates payload state to error state and sets feedback as response
    ///
    fn register_error_feedback(&mut self, error: FeedbackMessage) {
        self.payload_state_mut().set_error();
        self.response_mut().add_feedback(error);
    }
}

///
/// Specialization of the FSMErrorHandler interface for the types that satisfy the trait bounds
///
impl<T, InputMessageType, ContextSchema> FSMErrorHandler<InputMessageType, ContextSchema> for T
where
    ContextSchema: FSMContextSchema,
    ContextSchema::ResponseType: ResponseTypeIfc<FeedbackType = FeedbackMessage>,
    InputMessageType: HeaderIfc + Display + VisitorAcceptor<ContextSchema::CodecSchema>,
    T: FSMContextOwner<Schema = ContextSchema> + ReceiveMessage<InputMessageType>,
{
}
