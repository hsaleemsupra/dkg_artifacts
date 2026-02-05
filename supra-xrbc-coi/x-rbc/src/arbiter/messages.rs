use crate::types::messages::available::Available;
use block::{Block, CertifiedBlock};
use serde::{Deserialize, Serialize};

///
/// Messages of the Chain of Integrity protocol
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoIMessages {
    /// Message describing delivery availability to be certified for integrity
    Available(Available),
    CertifiedBlock(CertifiedBlock),
    Block(Block),
}

impl From<Available> for CoIMessages {
    fn from(value: Available) -> Self {
        CoIMessages::Available(value)
    }
}

impl From<Block> for CoIMessages {
    fn from(value: Block) -> Self {
        CoIMessages::Block(value)
    }
}

impl From<CertifiedBlock> for CoIMessages {
    fn from(value: CertifiedBlock) -> Self {
        CoIMessages::CertifiedBlock(value)
    }
}
