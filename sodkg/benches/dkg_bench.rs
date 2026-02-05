use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use nidkg_helper::cgdkg::{CGPublicKey, CGSecretKey, NodeType};
use socrypto::Identity;
use sodkg::class_group_dkg::config::DkgConfig;
use sodkg::class_group_dkg::messages::DKGProtocolMessage;
use sodkg::class_group_dkg::state::init_states;
use sodkg::class_group_dkg::states::done::Done;
use sodkg::class_group_dkg::transaction::convert_received_smrtx_to_event;
use sodkg::class_group_dkg::types::dkg_event::{DkgEvent, DkgEventData, DkgEventType};
use sodkg::sosmr_types::SignedSmrTransaction;
use sodkg::sosmr_types::SmrDkgCommitteeType;
use sodkg::DkgNode;
use soruntime::state::Action;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::unbounded_channel;

fn pick_node_type(
    idx: usize,
    total_dealer_clan_nodes: usize,
    total_family_nodes: usize,
) -> NodeType {
    if idx < total_dealer_clan_nodes {
        NodeType::DealerClanNode
    } else if idx < total_dealer_clan_nodes + total_family_nodes {
        NodeType::FamilyNode
    } else {
        NodeType::NormalTribeNode
    }
}

fn wrap_data_as_dkg_event(sender_id: Identity, raw_data: &[u8]) -> DkgEvent {
    let dkg_msg =
        DKGProtocolMessage::try_from(raw_data).expect("Failed to parse DKGProtocolMessage");

    let event_data = DkgEventData::from((sender_id, dkg_msg));
    let event_type = DkgEventType::from(&event_data);
    DkgEvent {
        event_type,
        data: event_data,
    }
}

async fn run_dkg_benchmark(total_nodes: usize, total_nodes_clan: usize, total_nodes_family: usize) {
    let f_clan: usize = (total_nodes_clan - 1) / 2;
    let f_tribe: usize = (total_nodes - 1) / 3;

    let threshold_clan: usize = f_clan + 1;
    let threshold: usize = 2 * f_tribe + 1;

    let dkg_config = DkgConfig {
        threshold: threshold as u32,
        threshold_clan: threshold_clan as u32,
        total_nodes: total_nodes as u32,
        total_nodes_clan: total_nodes_clan as u32,
        dealing_sig_collection_timeout_ms: 100,
    };

    let mut node_cg_keys = HashMap::new();
    let mut node_identity_to_index = HashMap::new();
    let mut node_index_to_identity = HashMap::new();
    let mut committee_pub_keys = BTreeMap::new();

    for i in 0..total_nodes {
        let node_type = pick_node_type(i, total_nodes_clan, total_nodes_family);
        let node_cg_key = CGSecretKey::generate();
        let node_cg_pub_key = CGPublicKey::try_from(&node_cg_key).unwrap();

        let identity = Identity::new(node_cg_pub_key.verification_key.to_bytes());
        node_cg_keys.insert(i, (node_cg_key, node_cg_pub_key.clone()));
        committee_pub_keys.insert(identity, (node_type, node_cg_pub_key));
        node_identity_to_index.insert(identity, i);
        node_index_to_identity.insert(i, identity);
    }

    let committee_node_set: Vec<(Identity, NodeType, CGPublicKey)> = committee_pub_keys
        .into_iter()
        .map(|(identity, (node_type, public_key))| (identity, node_type, public_key))
        .collect();

    let mut node_processors = HashMap::new();
    for i in 0..total_nodes {
        let node_id = node_index_to_identity.get(&i).unwrap();
        let node_processor = init_states(
            *node_id,
            node_cg_keys.get(&i).unwrap().0.clone(),
            SmrDkgCommitteeType::Smr,
            dkg_config.clone(),
            0,
            committee_node_set.clone(),
        );
        node_processors.insert(i, node_processor);
    }

    let init_dkg_event = DkgEvent::new_init_dkg();
    let mut actions_queue: VecDeque<(
        usize,
        Action<DkgEventData, DkgEventType, SignedSmrTransaction>,
    )> = VecDeque::new();

    let (async_tx, mut async_rx) = unbounded_channel::<(
        usize,
        Action<DkgEventData, DkgEventType, SignedSmrTransaction>,
    )>();

    for i in 0..total_nodes {
        let processor = node_processors.get_mut(&i).unwrap();
        let returned_actions = processor.process_event(Box::new(init_dkg_event.clone()));
        for a in returned_actions {
            actions_queue.push_back((i, a));
        }
    }

    loop {
        if let Some((sender_idx, action)) = actions_queue.pop_front() {
            match action {
                Action::SendMessage(raw_data) => {
                    let sender_identity = *node_index_to_identity.get(&sender_idx).unwrap();
                    let event = wrap_data_as_dkg_event(sender_identity, &raw_data);
                    for (target_idx, processor) in node_processors.iter_mut() {
                        let new_actions = processor.process_event(Box::new(event.clone()));
                        for a in new_actions {
                            actions_queue.push_back((*target_idx, a));
                        }
                    }
                }
                Action::SendMessageTo(target_id, raw_data) => {
                    if let Some(&target_idx) = node_identity_to_index.get(&target_id) {
                        let sender_identity = *node_index_to_identity.get(&sender_idx).unwrap();
                        let event = wrap_data_as_dkg_event(sender_identity, &raw_data);
                        let processor = node_processors.get_mut(&target_idx).unwrap();
                        let new_actions = processor.process_event(Box::new(event));
                        for a in new_actions {
                            actions_queue.push_back((target_idx, a));
                        }
                    }
                }
                Action::SendMessageToPeers(target_ids, raw_data) => {
                    let sender_identity = *node_index_to_identity.get(&sender_idx).unwrap();
                    let event = wrap_data_as_dkg_event(sender_identity, &raw_data);
                    for target_id_ref in &target_ids {
                        if let Some(&target_idx) = node_identity_to_index.get(target_id_ref) {
                            let processor = node_processors.get_mut(&target_idx).unwrap();
                            let new_actions = processor.process_event(Box::new(event.clone()));
                            for a in new_actions {
                                actions_queue.push_back((target_idx, a));
                            }
                        }
                    }
                }
                Action::SendSMRTx(txn) => {
                    let event = convert_received_smrtx_to_event(&txn, 0).unwrap();
                    for (target_idx, processor) in node_processors.iter_mut() {
                        let new_actions = processor.process_event(Box::new(event.clone()));
                        for a in new_actions {
                            actions_queue.push_back((*target_idx, a));
                        }
                    }
                }
                Action::ExecAsync(pinned_future) => {
                    let async_tx_clone = async_tx.clone();
                    tokio::spawn(async move {
                        let event_box = pinned_future.await;
                        let _ = async_tx_clone.send((sender_idx, Action::SendEventOut(event_box)));
                    });
                }
                Action::SendEventOut(event_box) => {
                    let processor = node_processors.get_mut(&sender_idx).unwrap();
                    let new_actions = processor.process_event(event_box);
                    for a in new_actions {
                        actions_queue.push_back((sender_idx, a));
                    }
                }
                _ => {}
            }
        } else if let Ok((sender_idx, action)) = async_rx.try_recv() {
            actions_queue.push_back((sender_idx, action));
        } else {
            let all_done = (0..total_nodes).all(|idx| {
                if let Some(subscriber) = node_processors[&idx].get_subscriber(6) {
                    subscriber.as_any().is::<DkgNode<Done>>()
                } else {
                    false
                }
            });
            if all_done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

fn bench_dkg(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("DKG Process");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1200));
    group.warm_up_time(Duration::from_secs(10));

    let cases = [(64, 42, 14), (96, 64, 16), (128, 80, 17)];

    for (tribe, clan, family) in cases {
        group.bench_function(
            BenchmarkId::new("DKG Flow", format!("T{}_C{}_F{}", tribe, clan, family)),
            |b| {
                b.to_async(&rt)
                    .iter(|| run_dkg_benchmark(tribe, clan, family));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_dkg);
criterion_main!(benches);
