use crate::types::MetricValue;
use crate::{MetricError, TagEntry, Tags};

#[derive(Debug)]
pub struct Metric {
    tags: Tags,
    value: MetricValue,
    key: String,
}

impl Metric {
    pub fn merge(&self, update: Metric) -> Result<Self, MetricError> {
        if self.key.ne(&update.key) {
            return Err(MetricError::MetricKeyError(update));
        }
        let mut tags = self.tags.clone();
        tags.extend(update.tags);
        Ok(Metric {
            tags,
            value: update.value,
            key: update.key,
        })
    }

    ///
    /// Updates metric value only with the new input value having the same index
    /// Returns error if metric values have different indexes
    ///
    pub fn update(&mut self, value: MetricValue) -> Result<(), MetricError> {
        self.value = self.value.update(value)?;
        Ok(())
    }

    pub fn inc(&mut self, value: MetricValue) -> Result<(), MetricError> {
        self.value.inc(value)
    }

    pub fn get_key(&self) -> String {
        self.key.clone()
    }

    pub fn key(&self) -> &String {
        &self.key
    }

    pub fn tags(&self) -> &Tags {
        &self.tags
    }

    pub fn value(&self) -> &MetricValue {
        &self.value
    }
    pub fn value_mut(&mut self) -> &mut MetricValue {
        &mut self.value
    }
}

#[derive(Debug)]
pub struct MetricsBuilder {
    tags: Tags,
    value: Option<MetricValue>,
    key: Option<String>,
}

impl MetricsBuilder {
    pub fn new() -> Self {
        Self {
            tags: Default::default(),
            value: None,
            key: None,
        }
    }

    pub fn build(self) -> Result<Metric, MetricError> {
        if self.key.is_none() || self.key.as_ref().unwrap().is_empty() {
            return Err(MetricError::MetricBuilderEmptyKey(self));
        } else if self.value.is_none() {
            return Err(MetricError::MetricBuilderEmptyValue(self));
        }
        Ok(Metric {
            tags: self.tags,
            value: self.value.unwrap(),
            key: self.key.unwrap(),
        })
    }

    ///
    /// Key of the metric which should be any none-empty string
    /// In case of empty string build will fail with error
    ///
    pub fn with_key(mut self, key: &str) -> Self {
        self.key = (!key.is_empty()).then(|| key.to_string());
        self
    }

    pub fn with_tag(mut self, tag: TagEntry) -> Self {
        self.tags.insert(tag.0, tag.1);
        self
    }

    pub fn with_tags(mut self, tags: Vec<TagEntry>) -> Self {
        self.tags.extend(tags);
        self
    }

    pub fn with_value(mut self, value: MetricValue) -> Self {
        self.value = Some(value);
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{MetricValue, MetricsBuilder};

    #[test]
    fn build_metric_valid() {
        let builder = MetricsBuilder::new();
        let metric = builder
            .with_tag(("name".to_string(), "metric_time".to_string()))
            .with_key("value")
            .with_value(MetricValue::UInt128(0))
            .build();
        assert!(metric.is_ok());
    }

    #[test]
    fn build_metric_with_no_tags() {
        let builder = MetricsBuilder::new();
        let metric = builder
            .with_key("value")
            .with_value(MetricValue::UInt128(0))
            .build();
        assert!(metric.is_ok());
    }

    #[test]
    fn build_metric_with_no_key() {
        let metric = MetricsBuilder::new()
            .with_tag(("name".to_string(), "metric_time".to_string()))
            .with_value(MetricValue::UInt128(0))
            .build();
        assert!(metric.is_err());
        let metric = MetricsBuilder::new()
            .with_tag(("name".to_string(), "metric_time".to_string()))
            .with_key("")
            .with_value(MetricValue::UInt128(0))
            .build();
        assert!(metric.is_err());
        let metric = MetricsBuilder::new()
            .with_tag(("name".to_string(), "metric_time".to_string()))
            .with_key("value")
            .with_key("")
            .with_value(MetricValue::UInt128(0))
            .build();
        assert!(metric.is_err());
    }

    #[test]
    fn build_metric_with_no_value() {
        let builder = MetricsBuilder::new();
        let metric = builder
            .with_tag(("name".to_string(), "metric_time".to_string()))
            .with_key("value")
            .build();
        assert!(metric.is_err());
    }
}
