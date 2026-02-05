use crate::{Metric, MetricValue, MetricsBuilder};

#[derive(Debug)]
pub enum MetricError {
    MetricError(Metric, Option<String>),
    MetricKeyError(Metric),
    MetricValueTypeError(MetricValue),
    MetricBuilderEmptyKey(MetricsBuilder),
    MetricBuilderEmptyValue(MetricsBuilder),
    MetricRegistryAlreadySet,
    MetricUnsupportedOp(MetricValue),
    BackendConfigError(String),
    BackendError(String),
}
