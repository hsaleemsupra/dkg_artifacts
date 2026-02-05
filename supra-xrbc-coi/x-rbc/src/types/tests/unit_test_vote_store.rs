use crate::types::payload_state::vote_store::VoteStore;
use crypto::PartialShare;

#[test]
fn test_vote_store() {
    let mut vote_store = VoteStore::default();
    assert!(vote_store.is_empty());
    assert!(!vote_store.is_collected());

    vote_store.add_vote(PartialShare::new(1, [0; 96]));
    assert!(vote_store.len().eq(&1));
    assert!(vote_store.has_vote(&1));
    assert!(vote_store.get_vote(1).is_some());

    let res = vote_store.collect();
    assert!(res.is_some());
    let partial_share = res.unwrap();
    assert!(partial_share.len().eq(&1));

    assert!(vote_store.is_collected());
    assert!(vote_store.len().eq(&1));

    vote_store.add_vote(PartialShare::new(1, [0; 96]));
    assert!(vote_store.len().eq(&1));
    assert!(vote_store.has_vote(&1));
    assert!(vote_store.get_vote(1).is_none());

    vote_store.add_vote(PartialShare::new(2, [0; 96]));
    assert!(vote_store.len().eq(&2));
    assert!(vote_store.has_vote(&2));
    assert!(vote_store.get_vote(2).is_none());

    let take = vote_store.collect();
    assert!(take.is_none());
    assert!(!vote_store.is_empty());
    assert!(vote_store.has_vote(&1));
    assert!(vote_store.has_vote(&2));
}
