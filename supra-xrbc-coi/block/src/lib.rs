pub mod config;
pub mod proposer;

use primitives::types::{Header, HeaderIfc, QuorumCertificate};
use primitives::{Stringify, HASH32, HASH96};
use serde_big_array::BigArray;
use std::fmt::{Debug, Display, Formatter};

use serde::{Deserialize, Serialize};

///
/// Represents single entry of the block
///
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockEntry {
    header: Header,
    qc: QuorumCertificate,
}

impl BlockEntry {
    pub fn new(header: Header, qc: QuorumCertificate) -> Self {
        Self { header, qc }
    }

    pub fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    pub fn get_qc(&self) -> QuorumCertificate {
        self.qc.clone()
    }

    pub fn split(self) -> (Header, QuorumCertificate) {
        (self.header, self.qc)
    }
}

impl HeaderIfc for BlockEntry {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl Display for BlockEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.header, self.qc.data().hex_display())
    }
}

impl Debug for BlockEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

///
/// Interface to get block common properties
///
pub trait BlockIfc {
    fn entries(&self) -> &Vec<BlockEntry>;
    fn id(&self) -> &HASH32;
    fn previous_id(&self) -> &HASH32;
}

///
/// Represents block structure
///
#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    previous: HASH32,
    id: HASH32,
    entries: Vec<BlockEntry>,
}

impl BlockIfc for Block {
    fn entries(&self) -> &Vec<BlockEntry> {
        &self.entries
    }

    fn id(&self) -> &HASH32 {
        &self.id
    }

    fn previous_id(&self) -> &HASH32 {
        &self.previous
    }
}

impl Block {
    pub fn new(id: HASH32, previous: HASH32) -> Self {
        Self {
            previous,
            id,
            entries: vec![],
        }
    }

    pub fn add_entry(&mut self, entry: BlockEntry) {
        self.entries.push(entry);
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block({}, {}, {}, {:?})",
            self.id.hex_display(),
            self.previous.hex_display(),
            self.entries().len(),
            self.entries()
        )
    }
}

impl Debug for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

///
/// Represents certified block
///
#[derive(Serialize, Deserialize, Clone)]
pub struct CertifiedBlock {
    block: Block,
    #[serde(with = "BigArray")]
    certificate: HASH96,
}

impl CertifiedBlock {
    pub fn new(certificate: HASH96, block: Block) -> Self {
        Self { block, certificate }
    }
}

impl BlockIfc for CertifiedBlock {
    fn entries(&self) -> &Vec<BlockEntry> {
        self.block.entries()
    }

    fn id(&self) -> &HASH32 {
        self.block.id()
    }

    fn previous_id(&self) -> &HASH32 {
        self.block.previous_id()
    }
}

impl Display for CertifiedBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CertifiedBlock({}, {})",
            self.certificate.hex_display(),
            self.block
        )
    }
}

impl Debug for CertifiedBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
