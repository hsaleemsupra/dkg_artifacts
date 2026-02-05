use primitives::Addresses;
pub(crate) mod available;
pub(crate) mod certificate_data;
pub(crate) mod chunk;
pub(crate) mod committee;
pub mod feedback;
pub(crate) mod network;
pub(crate) mod payload_data;
pub(crate) mod ready_data;
pub(crate) mod requests;
pub(crate) mod share_data;
pub(crate) mod sync;
pub(crate) mod value_data;
pub(crate) mod vote_data;

pub(crate) use self::network::NetworkFSMResponseMessage;
pub(crate) use self::network::RBCNetworkMessage;
pub use available::Available;
pub use certificate_data::QuorumCertificateData;
pub(crate) use committee::CommitteeFSMResponseMessage;
pub(crate) use committee::RBCCommitteeMessage;
pub use feedback::FeedbackMessage;
pub use primitives::types::QuorumCertificate;
pub(crate) use ready_data::EchoReadyData;
pub(crate) use ready_data::ReadyData;
pub(crate) use share_data::EchoShareData;
pub(crate) use share_data::ShareData;
pub(crate) use sync::RBCSyncMessage;
pub(crate) use sync::SyncFSMResponseMessage;
pub(crate) use value_data::EchoValueData;
pub(crate) use value_data::ValueData;
pub(crate) use vote_data::VoteData;

// Input data/message processing result
#[derive(Debug)]
pub struct OutputMessages<Message> {
    // Output message candidates to be sent to peers
    data: Vec<(Message, Addresses)>,
}

impl<Message> Default for OutputMessages<Message> {
    fn default() -> Self {
        Self { data: vec![] }
    }
}

impl<Messages> OutputMessages<Messages> {
    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn take(&mut self) -> Vec<(Messages, Addresses)> {
        std::mem::take(&mut self.data)
    }

    pub(crate) fn add(&mut self, message: (Messages, Addresses)) {
        self.data.push(message)
    }

    pub(crate) fn data(&self) -> &Vec<(Messages, Addresses)> {
        &self.data
    }
}

pub(crate) trait ResponseTypeIfc {
    type MessageType;
    type FeedbackType;
    type AuxMessageType;

    fn add_message_data<T>(&mut self, message: (T, Addresses))
    where
        T: Into<Self::MessageType>,
    {
        self.add_message((message.0.into(), message.1))
    }

    fn add_aux_message_data<T>(&mut self, message: (T, Addresses))
    where
        T: Into<Self::AuxMessageType>,
    {
        self.add_aux_message((message.0.into(), message.1))
    }

    fn add_message(&mut self, message: (Self::MessageType, Addresses));
    fn add_aux_message(&mut self, message: (Self::AuxMessageType, Addresses));
    fn add_feedback(&mut self, message: Self::FeedbackType);

    fn messages(&self) -> &OutputMessages<Self::MessageType>;
    fn aux_messages(&self) -> &OutputMessages<Self::AuxMessageType>;
    fn feedback(&self) -> &Vec<FeedbackMessage>;

    fn take_messages(&mut self) -> OutputMessages<Self::MessageType>;
    fn take_aux_messages(&mut self) -> OutputMessages<Self::AuxMessageType>;
    fn take_feedback(&mut self) -> Vec<FeedbackMessage>;
}
