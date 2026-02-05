use crate::state::Subscriber;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("General err:{0}")]
    GeneralError(String),
    #[error("Error during event send:{0}")]
    EventError(String),
    #[error("Error during task execution:{0}")]
    ActionError(String),
}

pub struct EventNotifyError<
    EventData: std::marker::Send,
    ET: std::marker::Send,
    Tx: std::marker::Send = (),
> {
    pub subscriber: Box<dyn Subscriber<EventData, ET, Tx>>,
    pub error: RuntimeError,
    et: PhantomData<ET>,
    eventdata: PhantomData<EventData>,
    tx: PhantomData<Tx>,
}

impl<EventData: std::marker::Send, ET: std::marker::Send, Tx: std::marker::Send>
    EventNotifyError<EventData, ET, Tx>
{
    pub fn new(subscriber: Box<dyn Subscriber<EventData, ET, Tx>>, error: RuntimeError) -> Self {
        EventNotifyError {
            subscriber,
            error,
            et: PhantomData,
            eventdata: PhantomData,
            tx: PhantomData,
        }
    }
}
