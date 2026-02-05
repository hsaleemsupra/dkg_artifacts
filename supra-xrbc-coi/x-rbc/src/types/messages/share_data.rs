use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::sender_extractor::SenderIfc;
use crate::types::messages::ValueData;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::{Origin, Stringify};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

use vec_commitment::committed_chunk::CommitmentMeta;

///
/// Part of the committee deliverable to be sent to assignee network peer by any committee member
/// Assignee network peer is not a part of committee/clan
///
#[derive(Serialize, Deserialize)]
pub struct ShareData<C: SupraDeliveryErasureCodecSchema> {
    /// Sender origin
    sender: Origin,
    /// Piece of network chunk of the deliverable for the network peer
    data: ValueData<C>,
    /// Commitment meta information of the network chunk to which the included piece is part of
    network_chunk_meta: CommitmentMeta,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, ShareData<C: SupraDeliveryErasureCodecSchema>);

impl<C: SupraDeliveryErasureCodecSchema> Display for ShareData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Share ({}, {}, {})",
            self.data,
            self.network_chunk_meta,
            self.sender.hex_display()
        )
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for ShareData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ShareData<C> {
    pub(crate) fn new(sender: Origin, data: ValueData<C>, meta: CommitmentMeta) -> Self {
        Self {
            sender,
            data,
            network_chunk_meta: meta,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub fn value(&self) -> &ValueData<C> {
        &self.data
    }

    pub fn split(self) -> (Origin, ValueData<C>, CommitmentMeta) {
        (self.sender, self.data, self.network_chunk_meta)
    }

    pub fn network_chunk_meta(&self) -> &CommitmentMeta {
        &self.network_chunk_meta
    }

    pub fn get_piece_index(&self) -> usize {
        self.data.get_chunk_index()
    }

    pub fn get_network_chunk_index(&self) -> usize {
        self.network_chunk_meta.index()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for ShareData<C> {
    fn header(&self) -> &Header {
        self.data.header()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> SenderIfc for ShareData<C> {
    fn sender(&self) -> &Origin {
        &self.sender
    }
}

///
/// Part of the committee deliverable echoed by the network peer to the rest of the network.
/// The message is not echoed to the peers from the committee/clan of the deliverable
///
#[derive(Serialize, Deserialize)]
pub struct EchoShareData<C: SupraDeliveryErasureCodecSchema> {
    /// Sender origin
    sender: Origin,
    /// Reconstructed Network Chunk by sender
    data: ValueData<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, EchoShareData<C: SupraDeliveryErasureCodecSchema>);

impl<C: SupraDeliveryErasureCodecSchema> Display for EchoShareData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EchoShare ({}, {})",
            self.data,
            self.sender.hex_display()
        )
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for EchoShareData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> EchoShareData<C> {
    pub fn new(sender: Origin, data: ValueData<C>) -> Self {
        Self {
            sender,
            data,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub fn value(&self) -> &ValueData<C> {
        &self.data
    }

    pub fn split(self) -> (Origin, ValueData<C>) {
        (self.sender, self.data)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for EchoShareData<C> {
    fn header(&self) -> &Header {
        self.data.header()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> SenderIfc for EchoShareData<C> {
    fn sender(&self) -> &Origin {
        &self.sender
    }
}
