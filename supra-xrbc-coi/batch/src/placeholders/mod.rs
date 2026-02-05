use primitives::placeholders::consumer::Consumer;
use x_rbc::FeedbackMessage;

pub mod config;
pub mod payload_provider;

pub type PayloadConsumer = Consumer<FeedbackMessage>;
