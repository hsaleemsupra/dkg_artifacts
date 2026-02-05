use bytes::Bytes;
use primitives::error::CommonError;
use primitives::serde::bincode_serializer;
use primitives::{Address, Addresses, TxChannel};
use serde::Serialize;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

pub enum Action {
    Unicast(Address, Bytes),
    Broadcast(Addresses, Bytes),
    Cancel(Address),
}

impl Debug for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Unicast(a, _) => writeln!(f, "Unicast: {}", a),
            Action::Broadcast(a, _) => writeln!(f, "Broadcast: {:?}", a),
            Action::Cancel(a) => writeln!(f, "Cancel: {}", a),
        }
    }
}

pub trait NetworkServiceSchema: Clone + Send + Sync {
    type TargetType: Serialize;
}

#[derive(Clone)]
pub struct NetworkServiceIFC<ServiceSchema: NetworkServiceSchema> {
    tx: TxChannel<Action>,
    _phantom_: PhantomData<ServiceSchema>,
}

impl<ServiceSchema: NetworkServiceSchema> NetworkServiceIFC<ServiceSchema> {
    pub fn new(tx: TxChannel<Action>) -> Self {
        NetworkServiceIFC::<ServiceSchema> {
            tx,
            _phantom_: Default::default(),
        }
    }

    pub async fn send<T: Into<ServiceSchema::TargetType>>(
        &self,
        address: Address,
        data: T,
    ) -> Result<(), CommonError> {
        let network_data: ServiceSchema::TargetType = data.into();
        let bytes = bincode_serializer(&network_data)?;
        self.tx
            .send(Action::Unicast(address, bytes))
            .map_err(|_| CommonError::UnboundSendError(address.to_string()))
    }

    pub async fn broadcast<T: Into<ServiceSchema::TargetType>>(
        &self,
        addresses: Addresses,
        data: T,
    ) -> Result<(), CommonError> {
        let network_data: ServiceSchema::TargetType = data.into();
        let bytes = bincode_serializer(&network_data)?;
        self.tx
            .send(Action::Broadcast(addresses, bytes))
            .map_err(|e| CommonError::UnboundSendError(format!("Failed to broadcast to : {:?}", e)))
    }
}
