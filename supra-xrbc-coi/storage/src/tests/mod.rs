use crate::config::StorageConfig;
use crate::rocksdb_store::RocksDBEngine;

mod unit_test_rocksdb_ifc;

fn get_test_db(name: &str) -> StorageConfig<RocksDBEngine> {
    StorageConfig::new(name.to_string()).unwrap()
}
