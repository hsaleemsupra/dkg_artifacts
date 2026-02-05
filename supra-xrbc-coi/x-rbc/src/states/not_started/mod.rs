pub(crate) mod committee;
pub(crate) mod network;
mod sync;

pub(crate) use crate::states::not_started::network::NotStartedNetworkFSM;
pub(crate) use committee::NotStartedCommitteeFSM;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
pub(crate) use sync::NotStartedSyncFSM;

///
/// Initial state of the state machines for both Committee and Network messages
///
pub(crate) struct NotStarted<T> {
    context: T,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, NotStarted<T>);

impl<T> NotStarted<T> {
    pub(crate) fn new(context: T) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }
}
