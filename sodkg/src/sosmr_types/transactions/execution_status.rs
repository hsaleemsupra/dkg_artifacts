use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;
use utoipa::ToSchema;

/// The execution summary status for a Supra transaction.
#[derive(
    Serialize, Deserialize, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, ToSchema,
)]
#[repr(u8)]
pub enum TxExecutionStatus {
    /// Execution succeeded.
    Success = 1,
    /// The transaction is valid but its execution failed due to running out of gas or a similar
    /// runtime failure.
    Fail,
    /// The transaction is invalid, e.g. due to having an invalid signature.
    Invalid,
    /// The transaction was executed after being ordered by the consensus, but it returned an error
    /// code that indicates that it may succeed in a future execution (e.g. sequence number too high).
    PendingAfterExecution,
    /// Transaction is accepted by RPC, pending for execution.
    Pending = 255,
}

impl Default for TxExecutionStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl Display for TxExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
