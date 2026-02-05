use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::sender_extractor::SenderIfc;
use crate::types::messages::chunk::ChunkData;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::Origin;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

///
/// Part of the Committee deliverable to be sent to assignee peer by broadcaster/leader
///
#[derive(Serialize, Deserialize)]
pub struct ValueData<C: SupraDeliveryErasureCodecSchema> {
    header: Header,
    chunk: ChunkData<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, ValueData<C: SupraDeliveryErasureCodecSchema>);

impl<C: SupraDeliveryErasureCodecSchema> Display for ValueData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Value ({}, {})",
            self.get_commitment_index(),
            self.header()
        )
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for ValueData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ValueData<C> {
    pub(crate) fn new(header: Header, chunk: ChunkData<C>) -> Self {
        Self {
            header,
            chunk,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn get_chunk_index(&self) -> usize {
        self.chunk.data().get_chunk_index()
    }

    pub(crate) fn get_commitment_index(&self) -> usize {
        self.chunk.data().get_commitment_index()
    }

    pub(crate) fn get_chunk(&self) -> ChunkData<C> {
        self.chunk.clone()
    }

    pub(crate) fn chunk_data(&self) -> &ChunkData<C> {
        &self.chunk
    }

    pub(crate) fn split(self) -> (Header, ChunkData<C>) {
        (self.header, self.chunk)
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            header: self.header.clone(),
            chunk: self.chunk.clone(),
            timestamp: self.timestamp,
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for ValueData<C> {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl<C: SupraDeliveryErasureCodecSchema> SenderIfc for ValueData<C> {
    fn sender(&self) -> &Origin {
        self.header.origin()
    }
}

///
/// Data sent by a committee member owning the underlying deliverable part to the rest of
/// the peers in committee
///
#[derive(Serialize, Deserialize)]
pub struct EchoValueData<C: SupraDeliveryErasureCodecSchema> {
    data: ValueData<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, EchoValueData<C: SupraDeliveryErasureCodecSchema>);

impl<C: SupraDeliveryErasureCodecSchema> Display for EchoValueData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "EchoValue ({})", self.data)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for EchoValueData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> EchoValueData<C> {
    pub(crate) fn new(data: ValueData<C>) -> Self {
        Self {
            data,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn get_chunk_index(&self) -> usize {
        self.data.get_chunk_index()
    }

    pub(crate) fn value(&self) -> &ValueData<C> {
        &self.data
    }

    pub(crate) fn split(self) -> ValueData<C> {
        self.data
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for EchoValueData<C> {
    fn header(&self) -> &Header {
        self.data.header()
    }
}
