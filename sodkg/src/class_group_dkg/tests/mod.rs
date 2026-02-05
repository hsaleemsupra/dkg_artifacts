use crate::class_group_dkg::config::DkgConfig;
use crate::class_group_dkg::messages::DKGProtocolMessage;
use crate::class_group_dkg::state::init_states;
use crate::class_group_dkg::states::done::Done;
use crate::class_group_dkg::transaction::convert_received_smrtx_to_event;
use crate::class_group_dkg::types::dkg_event::{DkgEvent, DkgEventData, DkgEventType};
use crate::sosmr_types::SignedSmrTransaction;
use crate::sosmr_types::SmrDkgCommitteeType;
use crate::DkgNode;
use log::{debug, trace};
use nidkg_helper::cgdkg::{CGPublicKey, CGSecretKey, NodeType};
use socrypto::Identity;
use soruntime::state::Action;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::env;
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;

// A small utility to create some "fake" node type assignments for demonstration:
// For example, we’ll assign the first nodes as DealerClanNode, second as FamilyNode,
// rest as NormalTribeNode
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

/// Converts the raw message bytes into a `DkgEvent`.
/// This is a placeholder function that you’ll adapt to your actual `DKGProtocolMessage` & RBC flow.
fn wrap_data_as_dkg_event(sender_id: Identity, raw_data: &[u8]) -> DkgEvent {
    //println!("Node:{} generated DkgEvent with sender id: {:?}", sender_id, raw_data);
    //println!("Node:{} generated DkgEvent with sender id", sender_id);

    let dkg_msg =
        DKGProtocolMessage::try_from(raw_data).expect("Failed to parse DKGProtocolMessage");

    let event_data = DkgEventData::from((sender_id, dkg_msg));
    let event_type = DkgEventType::from(&event_data);
    DkgEvent {
        event_type,
        data: event_data,
    }
}

#[tokio::test]
async fn check_dkg_state_flow() {
    env::set_var("RUST_LOG", "error");
    let _ = env_logger::try_init();

    let total_nodes = 16;
    let total_nodes_clan = 7;
    let total_nodes_family = 5;

    let f_clan: usize = ((total_nodes_clan - 1) / 2) as usize;
    let f_tribe: usize = ((total_nodes - 1) / 3) as usize;

    let threshold_clan: usize = f_clan + 1;
    let threshold: usize = 2 * f_tribe + 1;

    let dkg_config = DkgConfig {
        threshold: threshold as u32,
        threshold_clan: threshold_clan as u32,
        total_nodes: total_nodes as u32,
        total_nodes_clan: total_nodes_clan as u32,
        dealing_sig_collection_timeout_ms: 1,
    };

    let mut node_cg_keys = HashMap::new();
    let mut node_identity_to_index = HashMap::new();
    let mut node_index_to_identity = HashMap::new();
    let mut committee_pub_keys = BTreeMap::new();

    // Generating keys
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
    // to maintain the same order as internal created btreemap first and then created the vec from it.
    let committee_node_set: Vec<(Identity, NodeType, CGPublicKey)> = committee_pub_keys
        .into_iter()
        .map(|(identity, (node_type, public_key))| (identity, node_type, public_key))
        .collect();

    // Generating individual dkg-node processor
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

    // We'll use a global queue to manage actions -> events
    // (sender, Action)
    let mut actions_queue: VecDeque<(
        usize,
        Action<DkgEventData, DkgEventType, SignedSmrTransaction>,
    )> = VecDeque::new();

    let (async_tx, mut async_rx) = unbounded_channel::<(
        usize,
        Action<DkgEventData, DkgEventType, SignedSmrTransaction>,
    )>();

    // Step 1: Fire InitDkg at all nodes
    for i in 0..total_nodes {
        let processor = node_processors.get_mut(&i).unwrap();
        let returned_actions = processor.process_event(Box::new(init_dkg_event.clone()));
        // collect these actions
        for a in returned_actions {
            actions_queue.push_back((i, a));
        }
    }

    loop {
        // 1) If we still have any actions in the queue, process the front:
        if let Some((sender_idx, action)) = actions_queue.pop_front() {
            match action {
                Action::SendMessage(raw_data) => {
                    // Broadcast to all other nodes
                    for (target_idx, processor) in node_processors.iter_mut() {
                        //if *target_idx == sender_idx {
                        //  continue;
                        // }
                        let sender_identity = node_index_to_identity.get(&sender_idx).unwrap();
                        let event = wrap_data_as_dkg_event(*sender_identity, &raw_data);
                        let new_actions = processor.process_event(Box::new(event));
                        for a in new_actions {
                            actions_queue.push_back((*target_idx, a));
                        }
                    }
                }

                Action::SendMessageTo(target_id, raw_data) => {
                    let target_idx = *node_identity_to_index
                        .get(&target_id)
                        .expect("Unknown target identity");
                    let processor = node_processors.get_mut(&target_idx).unwrap();
                    let sender_identity = node_index_to_identity.get(&sender_idx).unwrap();
                    let event = wrap_data_as_dkg_event(*sender_identity, &raw_data);
                    let new_actions = processor.process_event(Box::new(event));
                    for a in new_actions {
                        actions_queue.push_back((target_idx, a));
                    }
                }

                Action::SendMessageToPeers(target_ids, raw_data) => {
                    for target_idx in &target_ids {
                        let target_id = *node_identity_to_index
                            .get(&target_idx)
                            .expect("Unknown target identity");
                        let sender_identity = node_index_to_identity.get(&sender_idx).unwrap();
                        let event = wrap_data_as_dkg_event(*sender_identity, &raw_data);
                        let processor = node_processors.get_mut(&target_id).unwrap();
                        let new_actions = processor.process_event(Box::new(event));
                        for a in new_actions {
                            actions_queue.push_back((target_id, a));
                        }
                    }
                }

                Action::SendSMRTx(txn) => {
                    trace!("Node:{} generated SMR Tx: {:?}", sender_idx, txn);
                    for (target_idx, processor) in node_processors.iter_mut() {
                        let event = convert_received_smrtx_to_event(&txn, 0).unwrap();
                        let new_actions = processor.process_event(Box::new(event));
                        for a in new_actions {
                            actions_queue.push_back((*target_idx, a));
                        }
                    }
                }

                // We do NOT ".await" the future here. Instead, we spawn it so the loop can continue.
                Action::ExecAsync(pinned_future) => {
                    let async_tx_clone = async_tx.clone();
                    tokio::spawn(async move {
                        // Wait for the future (timer or otherwise) to complete
                        let event_box = pinned_future.await;
                        // Then enqueue its result as a "ProcessEvent" action for the same sender
                        // so we continue the protocol in the main loop.
                        let _ = async_tx_clone.send((sender_idx, Action::SendEventOut(event_box)));
                    });
                }

                // This is how the future’s returned Event re-enters the system
                // So that the node sees "TimerExpired" at the right time
                Action::SendEventOut(event_box) => {
                    let processor = node_processors.get_mut(&sender_idx).unwrap();
                    let new_actions = processor.process_event(event_box);
                    for a in new_actions {
                        actions_queue.push_back((sender_idx, a));
                    }
                }

                _ => panic!("Not a valid action"),
            }
        } else if let Ok((sender_idx, action)) = async_rx.try_recv() {
            // 2) If there's nothing in actions_queue, see if we have something from the async channel
            // i.e. a completed timer or background future
            actions_queue.push_back((sender_idx, action));
        } else {
            // 3) If both the local queue is empty AND async_rx has nothing,
            // we check if we're done. If yes, break; otherwise, keep waiting or break.
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

            // Otherwise, to avoid busy-looping, you can do a small yield or sleep:
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Step 3: Post-processing checks
    // We expect each node to be in Done state eventually if DKG completes.
    // Also, each node's threshold_pubkey should be set.
    for (idx, processor) in node_processors.iter() {
        // We can read the final subscriber (e.g., Done state has get_id() = 6).
        // If it’s in the done state, it should have a threshold_pubkey or relevant data in place.

        let maybe_sub = processor.get_subscriber(6); // 6 => Done
        assert!(maybe_sub.is_some(), "Node {} not in Done state?", idx);

        if let Some(subscriber) = maybe_sub {
            let done_node = subscriber.as_any().downcast_ref::<DkgNode<Done>>().unwrap();
            // Check if threshold_pubkey is set, or whatever conditions you want.
            assert!(
                done_node.committee_publickey.is_some(),
                "Node {} has no threshold_pubkey in done state",
                idx
            );
            debug!("Node {} is Done with threshold_pubkey set.", idx);
        }
    }

    println!("All nodes reached Done state with valid threshold_pubkey. Test passed!");
}
