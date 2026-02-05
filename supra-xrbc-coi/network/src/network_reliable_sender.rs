use crate::client::{Action, NetworkServiceIFC, NetworkServiceSchema};
use crate::{CancelHandler, ReliableSender};
use primitives::{Address, RxChannel};
use std::collections::HashMap;
use tokio::sync::mpsc::unbounded_channel;

pub struct NetworkReliableSender {
    sender: ReliableSender,
    rx: RxChannel<Action>,
    cancel_handlers: HashMap<Address, Vec<CancelHandler>>,
}

impl NetworkReliableSender {
    pub fn new<ServiceSchema: NetworkServiceSchema>() -> NetworkServiceIFC<ServiceSchema> {
        let (tx, rx) = unbounded_channel::<Action>();
        let service = NetworkReliableSender {
            sender: Default::default(),
            rx,
            cancel_handlers: Default::default(),
        };
        tokio::spawn(NetworkReliableSender::run(service));
        NetworkServiceIFC::<ServiceSchema>::new(tx)
    }

    async fn run(mut service: NetworkReliableSender) {
        loop {
            let data = service.rx.recv().await;
            if let Some(action) = data {
                match action {
                    Action::Unicast(address, payload) => {
                        let handler = service.sender.send(address, payload).await;
                        if let Some(cancel_handler) = service.cancel_handlers.get_mut(&address) {
                            cancel_handler.push(handler);
                        } else {
                            service.cancel_handlers.insert(address, vec![handler]);
                        }
                    }
                    Action::Broadcast(addresses, payload) => {
                        let mut handlers =
                            service.sender.broadcast(addresses.clone(), payload).await;
                        addresses.into_iter().for_each(|address| {
                            let handle = handlers.pop().expect(
                                "Number of cancel handler are equal to # of broadcast addresses",
                            );
                            if let Some(cancel_handler) = service.cancel_handlers.get_mut(&address)
                            {
                                cancel_handler.push(handle);
                            } else {
                                service.cancel_handlers.insert(address, vec![handle]);
                            }
                        });
                    }
                    Action::Cancel(address) => {
                        service.cancel_handlers.remove(&address);
                    }
                }
            }
        }
    }
}
