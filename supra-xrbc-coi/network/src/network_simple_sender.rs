use crate::client::{Action, NetworkServiceIFC, NetworkServiceSchema};
use crate::SimpleSender;
use primitives::RxChannel;
use tokio::sync::mpsc::unbounded_channel;

pub struct NetworkSimpleSender {
    sender: SimpleSender,
    rx: RxChannel<Action>,
}

impl NetworkSimpleSender {
    pub fn new<ServiceSchema: NetworkServiceSchema>() -> NetworkServiceIFC<ServiceSchema> {
        let (tx, rx) = unbounded_channel::<Action>();
        let service = NetworkSimpleSender {
            sender: Default::default(),
            rx,
        };
        tokio::spawn(NetworkSimpleSender::run(service));
        NetworkServiceIFC::<ServiceSchema>::new(tx)
    }

    async fn run(mut service: NetworkSimpleSender) {
        loop {
            let data = service.rx.recv().await;
            if let Some(action) = data {
                match action {
                    Action::Unicast(address, payload) => {
                        service.sender.send(address, payload).await;
                    }
                    Action::Broadcast(addresses, payload) => {
                        service.sender.broadcast(addresses.clone(), payload).await;
                    }
                    Action::Cancel(_address) => {}
                }
            }
        }
    }
}
