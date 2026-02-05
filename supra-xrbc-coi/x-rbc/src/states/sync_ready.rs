use crate::states::handlers::{
    InputVerifier, SyncMessageHandler, SyncMessageReceiver, TimeoutMessageHandler,
};
use crate::states::DoneSyncFSM;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
use crate::tasks::LoggingName;
use crate::types::context::sync::{SyncFSMContext, SyncFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::message_factory::{MessageFactoryTrait, MessageFrom};
use crate::types::messages::requests::PullRequest;
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCSyncMessage, ReadyData, ResponseTypeIfc,
    ShareData, SyncFSMResponseMessage, ValueData,
};
use crate::types::payload_state::sync::PayloadType;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::HeaderIfc;
use primitives::{Address, Origin, Protocol};
use sfsm::{ReceiveMessage, ReturnMessage, State, TransitGuard, Transition};

pub(crate) struct SyncReady<C: SupraDeliveryErasureCodecSchema> {
    context: SyncFSMContext<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    SyncReady<Schema: SupraDeliveryErasureCodecSchema>
);

impl<C: SupraDeliveryErasureCodecSchema> SyncReady<C> {
    pub(crate) fn new(context: SyncFSMContext<C>) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    ///
    /// Sends current node owned chunk to requester
    ///
    fn send_owned_chunk(&mut self, target: Address) {
        let owned_chunk = self.payload_state().get_owned_chunk().unwrap();
        let value_data = ValueData::new(self.payload_state().get_header(), owned_chunk);

        let data = {
            let message_factory = self.message_factory();
            match self.payload_state().payload_type() {
                PayloadType::Committee => {
                    let ready_data = message_factory.message_from(value_data);
                    RBCSyncMessage::EchoReady(message_factory.message_from(ready_data))
                }
                PayloadType::Network => {
                    RBCSyncMessage::EchoShare(message_factory.message_from(value_data))
                }
            }
        };
        self.response_mut().add_message((data, vec![target]));
    }

    ///
    /// Sends requester assigned chunk
    /// Precondition: should be called only for committee-payload, will panic otherwise
    /// If the requester is from the current clan, then committee-chunk corresponding to requester is sent
    /// If the requester is from the network, then corresponding network chunk piece is sent
    ///
    fn send_requester_chunk(&mut self, requester: &Origin, requester_address: Address) {
        let is_from_clan = self.topology().is_clan_member(requester).unwrap();
        let target_chunk_commitment_index = self
            .assignment_extractor()
            .target_chunk_index(self.payload_state().origin(), requester);
        let header = self.payload_state().get_header();
        let message = {
            let message_factory = self.message_factory();
            if is_from_clan {
                let chunk =
                    self.payload_state().committee_chunks()[target_chunk_commitment_index].clone();
                let value_data = ValueData::new(header, chunk);
                RBCSyncMessage::Ready(message_factory.message_from(value_data))
            } else {
                let chunk_index =
                    target_chunk_commitment_index - self.topology().get_committee_size();
                let piece_index = self.topology().get_position();
                let nt_chunk = &self.payload_state().network_chunk_pieces()[chunk_index];
                let value_data = ValueData::new(header, nt_chunk.pieces()[piece_index].clone());
                let share = message_factory.message_from((value_data, nt_chunk.get_meta()));
                RBCSyncMessage::Share(share)
            }
        };
        self.response_mut()
            .add_message((message, vec![requester_address]));
    }
}

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for SyncReady<C> {
    type Schema = SyncFSMContextSchema<C>;
    fn context(&self) -> &SyncFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut SyncFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for SyncReady<C> {
    fn name<'a>() -> &'a str {
        "SyncReady"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for SyncReady<C> {}

/// Transition Interface definition from WaitingForSyncData for SyncStateMachine

/// ------------------------------------------------------------------------------------------------
/// SyncReady -> Done
///
impl<C: SupraDeliveryErasureCodecSchema> Into<DoneSyncFSM<C>> for SyncReady<C> {
    fn into(self) -> DoneSyncFSM<C> {
        DoneSyncFSM::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<DoneSyncFSM<C>> for SyncReady<C> {
    fn guard(&self) -> TransitGuard {
        self.payload_state().should_finalize().into()
    }
}

/// Message handling and Response Query interfaces for SyncReady state of SyncStateMachine

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<SyncFSMResponseMessage<C>> for SyncReady<C> {
    fn return_message(&mut self) -> Option<SyncFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<RBCSyncMessage<C>> for SyncReady<C> {
    fn receive_message(&mut self, message: RBCSyncMessage<C>) {
        self.handle_message(message)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<TimeoutMessage> for SyncReady<C> {
    fn receive_message(&mut self, message: TimeoutMessage) {
        self.handle_timeout(message)
    }
}
impl<C: SupraDeliveryErasureCodecSchema> InputVerifier<C, RBCSyncMessage<C>> for SyncReady<C> {}

impl<C: SupraDeliveryErasureCodecSchema> SyncMessageReceiver<C> for SyncReady<C> {}

impl<C: SupraDeliveryErasureCodecSchema> SyncMessageHandler for SyncReady<C> {
    type EchoValue = EchoValueData<C>;
    type Ready = ReadyData<C>;
    type EchoReady = EchoReadyData<C>;
    type Share = ShareData<C>;
    type EchoShare = EchoShareData<C>;
    type Pull = PullRequest;

    fn handle_echo_value(&mut self, _msg: Self::EchoValue) {}

    fn handle_ready(&mut self, _msg: Self::Ready) {}

    fn handle_echo_ready(&mut self, _msg: Self::EchoReady) {}

    fn handle_share(&mut self, _msg: Self::Share) {}

    fn handle_echo_share(&mut self, _msg: Self::EchoShare) {}

    fn handle_pull_request(&mut self, msg: Self::Pull) {
        let (_, requester) = msg.split();
        let address = self
            .topology()
            .get_address_by_origin(Protocol::XRBC, &requester)
            .unwrap();
        let is_clan_member = self.topology().is_clan_member(&requester).unwrap();
        match self.payload_state().payload_type() {
            PayloadType::Committee => {
                if is_clan_member {
                    self.send_owned_chunk(address);
                }
                self.send_requester_chunk(&requester, address);
            }
            PayloadType::Network => self.send_owned_chunk(address),
        };
    }
}

impl<C: SupraDeliveryErasureCodecSchema> TimeoutMessageHandler for SyncReady<C> {
    fn handle_retry(&mut self) {
        self.payload_state_mut().set_finalize();
    }
}
