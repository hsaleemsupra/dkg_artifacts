use crate::fsm::committee_state_machine::CommitteeFSMSchema;
use crate::fsm::network_message_state_machine::NetworkMessageFSMSchema;
use crate::fsm::sync_state_machine::SyncFSMSchema;
use crate::fsm::FSMSchema;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::errors::RBCError;
use crate::tasks::messages::RBCMessage;
use log::info;
use primitives::TxChannel;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use tokio::time::{Duration, Instant};

///
/// Generic RBC task client used to pass input message to associated task.
/// It has 2 generic parameters:
///     - Schema of FSMSchema type based on which actual message type that consumed by the task/engine is deduced
///     - SourceType which is input message type received from the network
/// Requirement is SourceType can be mapped to the input messaged consumed by the task engine
///
/// RBC Protocol transfer 3 type of messages
///     - Committee Messages - messages exchanged only between peers in the broadcaster clan to
///       deliver message to the clan
///     - Network Messages - messages exchanged broadcaster clan to network peers, and network peers
///       (except broadcaster-clan peers)
///     - Sync Messages - messages exchanged between all peers to synchronize deliverable
///
/// RBC Client converts rbc-protocol message to the input message the task supposed to consume and
/// sends it to the task
///
pub(crate) struct RBCTaskClient<Schema: FSMSchema, SourceType>
where
    SourceType: TryInto<Schema::InputMessageType>,
{
    pub(crate) tx: TxChannel<Schema::InputMessageType>,
    _phantom_: PhantomData<Schema>,
    _source_phantom_: PhantomData<SourceType>,
}

impl<Schema: FSMSchema, SourceType> RBCTaskClient<Schema, SourceType>
where
    SourceType: TryInto<Schema::InputMessageType>,
{
    pub(crate) fn new(tx: TxChannel<Schema::InputMessageType>) -> Self {
        Self {
            tx,
            _phantom_: Default::default(),
            _source_phantom_: Default::default(),
        }
    }
}

impl<Schema: FSMSchema, SourceType> RBCTaskClient<Schema, SourceType>
where
    SourceType: TryInto<Schema::InputMessageType>,
{
    fn send(&self, data: SourceType) -> Result<(), RBCError> {
        let msg = data.try_into().map_err(|_e| RBCError::ConversionError)?;
        if self.tx.is_closed() {
            info!("Task channel is closed dropping the message: {:?}", msg);
            return Ok(());
        }
        self.tx
            .send(msg)
            .map_err(|e| RBCError::SendError(format!("To Task: {:?}", e)))
    }
}

///
/// Defines type of the RBC task clients
///
pub(crate) enum RBCTaskClientType<CS: SupraDeliveryErasureCodecSchema> {
    /// Client associated with the task handling committee-messages
    Committee(RBCTaskClient<CommitteeFSMSchema<CS>, RBCMessage<CS>>),
    /// Client associated with the task handling network-messages
    Network(RBCTaskClient<NetworkMessageFSMSchema<CS>, RBCMessage<CS>>),
    /// Client associated with the task synchronizing  the deliverable
    Sync(RBCTaskClient<SyncFSMSchema<CS>, RBCMessage<CS>>),
}

impl<C: SupraDeliveryErasureCodecSchema> RBCTaskClientType<C> {
    pub(crate) fn send(&self, msg: RBCMessage<C>) -> Result<(), RBCError> {
        match self {
            RBCTaskClientType::Committee(client) => client.send(msg),
            RBCTaskClientType::Network(client) => client.send(msg),
            RBCTaskClientType::Sync(client) => client.send(msg),
        }
    }

    pub(crate) fn is_sync(&self) -> bool {
        match self {
            RBCTaskClientType::Committee(_) | RBCTaskClientType::Network(_) => false,
            RBCTaskClientType::Sync(_) => true,
        }
    }
    pub(crate) fn is_committee(&self) -> bool {
        match self {
            RBCTaskClientType::Sync(_) | RBCTaskClientType::Network(_) => false,
            RBCTaskClientType::Committee(_) => true,
        }
    }
    pub(crate) fn is_network(&self) -> bool {
        match self {
            RBCTaskClientType::Sync(_) | RBCTaskClientType::Committee(_) => false,
            RBCTaskClientType::Network(_) => true,
        }
    }
}

///
/// Provides interface to create RBC Client and return it wrapped in the corresponding type
///
pub(crate) trait RBCClientProvider<Schema: FSMSchema, ClientType> {
    fn new(tx: TxChannel<Schema::InputMessageType>) -> ClientType;
}

///
/// Provides RBC Client for the RBC tasks handling committee-messages
///
pub(crate) struct CommitteeRBCClientProvider<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}
impl<C: SupraDeliveryErasureCodecSchema>
    RBCClientProvider<CommitteeFSMSchema<C>, RBCTaskClientType<C>>
    for CommitteeRBCClientProvider<C>
{
    fn new(
        tx: TxChannel<<CommitteeFSMSchema<C> as FSMSchema>::InputMessageType>,
    ) -> RBCTaskClientType<<CommitteeFSMSchema<C> as FSMSchema>::CodecSchema> {
        let client = RBCTaskClient::<CommitteeFSMSchema<C>, RBCMessage<C>>::new(tx);
        RBCTaskClientType::Committee(client)
    }
}

///
/// Provides RBC Client for the RBC tasks handling network-messages
///
pub(crate) struct NetworkRBCClientProvider<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}
impl<C: SupraDeliveryErasureCodecSchema>
    RBCClientProvider<NetworkMessageFSMSchema<C>, RBCTaskClientType<C>>
    for NetworkRBCClientProvider<C>
{
    fn new(
        tx: TxChannel<<NetworkMessageFSMSchema<C> as FSMSchema>::InputMessageType>,
    ) -> RBCTaskClientType<<NetworkMessageFSMSchema<C> as FSMSchema>::CodecSchema> {
        let client = RBCTaskClient::<NetworkMessageFSMSchema<C>, RBCMessage<C>>::new(tx);
        RBCTaskClientType::Network(client)
    }
}

///
/// Provides RBC Client for the RBC tasks synchronizing deliverable
///
pub(crate) struct SyncRBCClientProvider<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}
impl<C: SupraDeliveryErasureCodecSchema> RBCClientProvider<SyncFSMSchema<C>, RBCTaskClientType<C>>
    for SyncRBCClientProvider<C>
{
    fn new(
        tx: TxChannel<<SyncFSMSchema<C> as FSMSchema>::InputMessageType>,
    ) -> RBCTaskClientType<<SyncFSMSchema<C> as FSMSchema>::CodecSchema> {
        let client = RBCTaskClient::<SyncFSMSchema<C>, RBCMessage<C>>::new(tx);
        RBCTaskClientType::Sync(client)
    }
}

pub(crate) enum RBCTaskState<CS: SupraDeliveryErasureCodecSchema> {
    InProgress(RBCTaskClientType<CS>, Instant),
    Done(Instant, usize),
}

impl<CS: SupraDeliveryErasureCodecSchema> Debug for RBCTaskState<CS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RBCTaskState::InProgress(..) => writeln!(f, "InProgress"),
            RBCTaskState::Done(..) => writeln!(f, "Done"),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> RBCTaskState<C> {
    pub(crate) fn send(&self, msg: RBCMessage<C>) -> Result<(), RBCError> {
        match self {
            RBCTaskState::InProgress(client, ..) => client.send(msg),
            _ => {
                info!("Task is done. Input message is ignored: {}", msg);
                Ok(())
            }
        }
    }

    pub(crate) fn refresh(&mut self) {
        let instant = match self {
            RBCTaskState::InProgress(_, instant) => instant,
            RBCTaskState::Done(instant, _) => instant,
        };
        *instant = Instant::now();
    }

    pub(crate) fn elapsed(&self) -> Duration {
        let instant = match self {
            RBCTaskState::InProgress(_, instant) => instant,
            RBCTaskState::Done(instant, _) => instant,
        };
        instant.elapsed()
    }

    pub fn is_stale(&self, time_out_duration: Duration) -> bool {
        self.elapsed() > time_out_duration
    }

    pub fn is_done(&self) -> bool {
        match self {
            RBCTaskState::InProgress(..) => false,
            RBCTaskState::Done(..) => true,
        }
    }

    pub fn is_inprogress(&self) -> bool {
        !self.is_done()
    }

    pub fn is_sync(&self) -> bool {
        match self {
            RBCTaskState::InProgress(client, _) => client.is_sync(),
            RBCTaskState::Done(_, _) => false,
        }
    }

    pub fn increment_gc_round(&mut self) {
        match self {
            RBCTaskState::InProgress(_, _) => {}
            RBCTaskState::Done(_, round) => {
                *round += 1;
            }
        }
    }

    pub fn gc_round(&self) -> usize {
        match self {
            RBCTaskState::InProgress(_, _) => 0,
            RBCTaskState::Done(_, round) => *round,
        }
    }

    ///
    /// Returns underlying client if any still in progress
    ///
    pub(crate) fn client(&self) -> Option<&RBCTaskClientType<C>> {
        match self {
            RBCTaskState::InProgress(task, _) => Some(task),
            RBCTaskState::Done(..) => None,
        }
    }
}
