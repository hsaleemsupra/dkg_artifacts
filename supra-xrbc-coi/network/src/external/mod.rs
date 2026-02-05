mod error;
pub(crate) mod receiver;
pub(crate) mod reliable_sender;
pub(crate) mod simple_sender;

#[cfg(test)]
#[path = "tests/common.rs"]
pub mod common;
