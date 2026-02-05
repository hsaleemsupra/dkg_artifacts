use crate::arbiter::messages::CoIMessages;
use async_trait::async_trait;
use bytes::Bytes;
use futures::SinkExt;
use log::error;
use network::{MessageHandler, Writer};
use primitives::serde::{bincode_deserialize, bincode_serializer};
use primitives::TxChannel;
use std::error::Error;

#[derive(Clone)]
pub struct ArbiterClient {
    tx: TxChannel<CoIMessages>,
}

impl ArbiterClient {
    pub(crate) fn new(tx: TxChannel<CoIMessages>) -> Self {
        Self { tx }
    }

    pub fn consume<T: Into<CoIMessages>>(&self, msg: T) {
        let _ = self
            .tx
            .send(msg.into())
            .map_err(|e| error!("Failed to send available message: {:?}", e));
    }
}

#[async_trait]
impl MessageHandler for ArbiterClient {
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        // Reply with an ACK.
        let ack_message = bincode_serializer(&"Ack").map_err(Box::new)?;
        let _ = writer.send(ack_message).await;

        // Deserialize and parse the message.
        let result = bincode_deserialize(&message).map_err(Box::new)?;
        let _ = self.tx.send(result).map_err(|e| error!("{:?}", e));
        Ok(())
    }
}
