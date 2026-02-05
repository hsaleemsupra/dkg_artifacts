use crate::error::StorageError;
use crate::{Engine, StorageResult};
use std::marker::PhantomData;

pub struct StorageConfig<DB: Engine> {
    collection: String,
    s_marker: PhantomData<DB>,
}

impl<DB: Engine> StorageConfig<DB> {
    pub fn new(collection: String) -> StorageResult<Self> {
        let conf = Self {
            collection,
            s_marker: Default::default(),
        };
        conf.validate()
    }

    pub fn collection(&self) -> &str {
        self.collection.as_str()
    }

    fn validate(self) -> StorageResult<Self> {
        if self.collection.is_empty() {
            Err(StorageError::ConfigEmptyValue(
                "DBConfig.collection".to_string(),
            ))
        } else {
            Ok(self)
        }
    }
}
