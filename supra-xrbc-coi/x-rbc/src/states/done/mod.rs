pub(crate) mod committee;
pub(crate) mod network;
pub(crate) mod sync;

pub(crate) use crate::states::done::network::DoneNetworkFSM;
pub(crate) use committee::DoneCommitteeFSM;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
pub(crate) use sync::DoneSyncFSM;

pub(crate) struct Done<T> {
    context: T,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, Done<T>);

impl<T> Done<T> {
    pub(crate) fn new(context: T) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }
}
