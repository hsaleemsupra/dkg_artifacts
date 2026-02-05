use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::sender_extractor::SenderIfc;
use crate::types::messages::ValueData;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::{Origin, Stringify};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

///
/// Data sent by a committee member to the current peer which was not registered to have either own
/// chunk or complete data
///
#[derive(Serialize, Deserialize)]
pub struct ReadyData<C: SupraDeliveryErasureCodecSchema> {
    /// Message Sender, peer from the current node clan
    sender: Origin,
    /// Portion of Data corresponding the current peer
    data: ValueData<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, ReadyData<C: SupraDeliveryErasureCodecSchema>);

impl<C: SupraDeliveryErasureCodecSchema> Display for ReadyData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ready ({}, {})", self.data, self.sender.hex_display())
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for ReadyData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReadyData<C> {
    pub fn new(sender: Origin, data: ValueData<C>) -> Self {
        Self {
            sender,
            data,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    ///
    /// Returns underlying base value-data representing part of the main deliverable
    ///
    pub(crate) fn value(&self) -> &ValueData<C> {
        &self.data
    }

    pub(crate) fn split(self) -> (Origin, ValueData<C>) {
        (self.sender, self.data)
    }

    ///
    /// Duplicates data.
    ///
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            sender: self.sender,
            data: self.data.duplicate(),
            timestamp: self.timestamp,
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for ReadyData<C> {
    fn header(&self) -> &Header {
        self.data.header()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> SenderIfc for ReadyData<C> {
    fn sender(&self) -> &Origin {
        &self.sender
    }
}

///
/// Data sent by a committee member owning the underlying deliverable part to the peers in the committee
///
#[derive(Serialize, Deserialize)]
pub struct EchoReadyData<C: SupraDeliveryErasureCodecSchema> {
    data: ReadyData<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(timestamp, EchoReadyData<C: SupraDeliveryErasureCodecSchema>);

impl<C: SupraDeliveryErasureCodecSchema> Display for EchoReadyData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "EchoReady ({})", self.data)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for EchoReadyData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> EchoReadyData<C> {
    pub(crate) fn new(data: ReadyData<C>) -> Self {
        Self {
            data,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    ///
    /// Returns underlying base value-data representing part of the main deliverable
    ///
    pub(crate) fn value(&self) -> &ValueData<C> {
        self.data.value()
    }

    ///
    /// Returns underlying base value-data representing part of the main deliverable
    ///
    pub(crate) fn ready_data(&self) -> &ReadyData<C> {
        &self.data
    }

    pub(crate) fn split(self) -> ReadyData<C> {
        self.data
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for EchoReadyData<C> {
    fn header(&self) -> &Header {
        self.data.header()
    }
}
