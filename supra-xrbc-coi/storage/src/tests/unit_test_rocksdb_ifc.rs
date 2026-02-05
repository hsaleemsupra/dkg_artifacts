use crate::tests::get_test_db;
use crate::{EngineFactory, StorageReadIfc, StorageWriteIfc};
use futures::future::try_join_all;
use futures::stream::FuturesUnordered;
use std::time::Duration;

#[tokio::test]
async fn check_storage_client() {
    let db_config = get_test_db("client");
    let _ = std::fs::remove_dir_all("db/".to_string() + db_config.collection());

    let db_client = EngineFactory::get_client(&db_config).unwrap();

    let db_client_1 = db_client.clone();
    let db_client_2 = db_client.clone();
    let db_client_3 = db_client.clone();

    let future_1 = db_client_1.subscribe([1; 32]);
    let future_2 = db_client_2.subscribe([2; 32]);
    let future_3 = db_client_3.subscribe([3; 32]);

    let waiting = FuturesUnordered::new();
    waiting.push(future_1);
    waiting.push(future_2);
    waiting.push(future_3);

    let res = db_client.has_key([1; 32]).await;
    assert!(!res);
    db_client.write([1; 32], vec![]);
    let res = db_client.has_key([1; 32]).await;
    assert!(res);
    let res = db_client.read([1; 32]).await;
    assert!(res.is_some());
    db_client.write([1; 32], vec![]);
    db_client.write([2; 32], vec![]);
    db_client.write([3; 32], vec![]);

    tokio::select! {
        res = try_join_all(waiting) => {
            println!("{res:?}");
        }
    }

    let _ = std::fs::remove_dir_all("db/".to_string() + db_config.collection());
}

#[tokio::test]
async fn check_storage_client_blocking_ifc() {
    let db_config = get_test_db("test_client_blocking");
    let _ = std::fs::remove_dir_all("db/".to_string() + db_config.collection());

    let db_client = EngineFactory::get_client(&db_config).unwrap();

    let dup_client = db_client.clone();
    let handler = tokio::task::spawn_blocking(move || {
        let res = dup_client.has_key_blocking([1; 32]);
        assert!(!res);
        let res = dup_client.read_blocking([1; 32]);
        assert!(res.is_none());
    });
    let result = tokio::time::timeout(Duration::from_secs(2), handler).await;
    assert!(result.is_ok());
    assert!(result.as_ref().unwrap().is_ok(), "{:?}", result);

    db_client.write([1; 32], vec![]);

    let handler = tokio::task::spawn_blocking(move || {
        let res = db_client.has_key_blocking([1; 32]);
        assert!(res);
        let res = db_client.read_blocking([1; 32]);
        assert!(res.is_some());
    });

    let result = tokio::time::timeout(Duration::from_secs(2), handler).await;
    assert!(result.is_ok());
    assert!(result.as_ref().unwrap().is_ok(), "{:?}", result);

    let _ = std::fs::remove_dir_all("db/".to_string() + db_config.collection());
}
