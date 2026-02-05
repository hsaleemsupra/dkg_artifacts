use itertools::Itertools;
use metrics_logger::{MetricsBuilder, TagEntry};
use std::fmt::{Display, Formatter};
use std::time::Duration;

pub mod influx_collector;
#[cfg(test)]
mod tests;

pub use metrics_logger::duration_since_unix_epoch;
pub use metrics_logger::nanoseconds_since_unix_epoch;
pub use metrics_logger::Timestamp;

pub trait MetricTag: Display {
    fn key(&self) -> String {
        "name".to_string()
    }

    fn val(&self) -> String {
        self.to_string()
    }

    fn as_tag(&self) -> TagEntry {
        (self.key(), self.val())
    }
}

#[derive(Clone)]
pub enum MetricValue {
    AsBytes(usize),
    AsSeconds(Duration),
    AsNanoSeconds(Duration),
}

impl Into<metrics_logger::MetricValue> for MetricValue {
    fn into(self) -> metrics_logger::MetricValue {
        match self {
            MetricValue::AsBytes(v) => metrics_logger::MetricValue::Usize(v),
            MetricValue::AsSeconds(v) => metrics_logger::MetricValue::Float32(v.as_secs_f32()),
            MetricValue::AsNanoSeconds(v) => metrics_logger::MetricValue::UInt128(v.as_nanos()),
        }
    }
}

pub enum SystemThroughput {
    BatchArrival,
    BatchStoring,
    ReconstructedSize,
}

impl Display for SystemThroughput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SystemThroughput::BatchArrival => write!(f, "system-data-arrival-time"),
            SystemThroughput::BatchStoring => write!(f, "system-data-store-time"),
            SystemThroughput::ReconstructedSize => write!(f, "system-reconstructed-size"),
        }
    }
}

impl MetricTag for SystemThroughput {}

impl Display for MetricValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricValue::AsBytes(num) => write!(f, "{} b", num),
            MetricValue::AsSeconds(duration) => write!(f, "{} s", duration.as_secs_f32()),
            MetricValue::AsNanoSeconds(duration) => write!(f, "{} n", duration.as_nanos()),
        }
    }
}

pub fn report(tags: &[&dyn MetricTag], value: MetricValue) {
    if tags.is_empty() {
        panic!("not enough tags")
    }
    // log metric
    let (key, tags) = tags.split_first().unwrap();
    log::info!(target: "(METRIC)", "{} - {} - [{}]", key, value, tags.iter().join(", "));

    // influx metric
    let _ = MetricsBuilder::new()
        .with_key(key.val().as_str())
        // Tags keys should be properly handled
        .with_tags(tags.iter().map(|t| t.as_tag()).collect())
        .with_value(value.into())
        .build()
        .map(metrics_logger::record);
}

pub trait TimeStampTrait {
    fn created_time(&self) -> Timestamp;

    fn elapsed_time(&self) -> Duration;
}

///
/// # Usage
/// impl_timestamp!(time_stamp, ValueData<C: SupraDeliveryErasureCodecSchema>);
/// where time_stamp is a property of struct ValueData of type `Timestamp` or `u128`
///
#[macro_export]
macro_rules! impl_timestamp {
    (
        $prop:ident,
        $struct_name: ident
        $(<
            $T:ident$(:$N:ident)?
        >)?
    ) => {
        impl
        $(<
            $T$(:$N)?
        >)?
        $crate::TimeStampTrait for $struct_name
        $(<
            $T
        >)?
        {
             ///
             /// Returns the created time since unix epoch in nano second
             ///
            fn created_time(&self) -> Timestamp {
                self.$prop
            }

             ///
             /// Elapsed time should always be greater than zero
             ///
            fn elapsed_time(&self) -> std::time::Duration {
                std::time::Duration::from_nanos($crate::nanoseconds_since_unix_epoch() as u64)
                    .saturating_sub(std::time::Duration::from_nanos(self.$prop as u64))
             }
        }
    };
}
