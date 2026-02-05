use crate::{RxChannel, TxChannel};
use log::info;
use std::fmt::Display;
use std::marker::PhantomData;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;

pub struct Consumer<D: Display + Send + 'static> {
    rx: RxChannel<D>,
    name: String,
    _phantom: PhantomData<D>,
}

impl<D: Display + Send + 'static> Consumer<D> {
    pub fn spawn(name: &str) -> (TxChannel<D>, JoinHandle<()>) {
        let (tx, rx) = unbounded_channel::<D>();
        let consumer = Consumer {
            rx,
            name: name.to_string(),
            _phantom: Default::default(),
        };
        let handle = tokio::spawn(Consumer::<D>::run(consumer));
        (tx, handle)
    }

    async fn run(mut consumer: Consumer<D>) {
        loop {
            let message = consumer.rx.recv().await;
            if let Some(feedback) = message {
                info!("{} Consumer: {}", consumer.name, feedback);
            }
        }
    }
}
