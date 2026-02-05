use std::env;
use std::collections::{HashMap};
use env_logger;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use soruntime::state::{Action};
use socrypto::{Identity};
use crate::messages::CSDeliverProtocolMessage;
use crate::node::CSDeliverNode;
use crate::state::init_state;
use crate::states::wait_for_msgs::WaitForMsgs;
use crate::types::deliver_event::{CSDeliverEvent, CSDeliverEventData, CSDeliverEventType};
use ed25519_dalek::{
    SigningKey as SecretKey,
};
use rand::rngs::OsRng;

// Helper function to map Identity -> node index
fn identity_to_index(identities: &[Identity], id: &Identity) -> Option<usize> {
    identities.iter().position(|x| x == id)
}

// Helper to convert CSDeliverProtocolMessage into CSDeliverEvent (for receiving nodes)
fn create_deliver_event_from_message(msg: CSDeliverProtocolMessage) -> CSDeliverEvent {
    match msg {
        CSDeliverProtocolMessage::Codeword(codeword) => CSDeliverEvent {
            event_type: CSDeliverEventType::ReceivedCodeword,
            data: CSDeliverEventData::ReceiveCodeword(codeword),
        },
        CSDeliverProtocolMessage::Echo(codeword) => CSDeliverEvent {
            event_type: CSDeliverEventType::ReceivedEcho,
            data: CSDeliverEventData::ReceiveEcho(codeword),
        },
    }
}

// Simulate delivering actions (messages) from one node to others
fn deliver_actions(
    nodes_processors: &mut HashMap<usize, soruntime::state::EventProcessor<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType>>,
    identities: &[Identity],
    sender_index: usize,
    actions: &[Action<CSDeliverEventData, CSDeliverEventType>]
) {
    for action in actions {
        match action {
            Action::SendMessage(data) => {
                let msg = CSDeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                // We'll collect follow-up actions from all targets first
                let mut all_follow_up_actions = Vec::new();
                let keys: Vec<usize> = nodes_processors.keys().copied().collect();

                for i in keys {
                    if i == sender_index {
                        continue;
                    }
                    let event = create_deliver_event_from_message(msg.clone());
                    let follow_up_actions = {
                        let node_processor = nodes_processors.get_mut(&i).unwrap();
                        node_processor.process_event(Box::new(event))
                    };

                    // Collect follow-up actions
                    if !follow_up_actions.is_empty() {
                        all_follow_up_actions.push((i, follow_up_actions));
                    }
                }

                // Now process all collected follow-up actions
                for (target_idx, f_actions) in all_follow_up_actions {
                    deliver_actions(nodes_processors, identities, target_idx, &f_actions);
                }
            },
            Action::SendMessageTo(target_id, data) => {
                // Direct message to a specific node
                let msg = CSDeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                let target_idx = identity_to_index(identities, target_id).expect("Target not found");
                let event = create_deliver_event_from_message(msg);
                let node_processor = nodes_processors.get_mut(&target_idx).unwrap();
                let follow_up_actions = node_processor.process_event(Box::new(event));

                // If follow-up actions occur, recursively handle them as well
                // to simulate full message passing.
                if !follow_up_actions.is_empty() {
                    deliver_actions(nodes_processors, identities, target_idx, &follow_up_actions);
                }
            },
            _ => {}
        }
    }
}

#[test]
fn check_deliver_state_flow() {

    // Initialize environment
    env::set_var("RUST_LOG", "TRACE");
    let _ = env_logger::try_init();

    // Deliver configuration
    let f_byzantine = 1; // number of byzantine nodes
    let threshold_t = 2*f_byzantine + 1;  // tribe threshold

    let n_t = 3*f_byzantine + 1;  // total nodes in tribe
    let n_c = 2*f_byzantine + 1;  // total nodes in clan
    let threshold_c = f_byzantine + 1;  // clan threshold
    // Let's say the first node (index 0) is the broadcaster with some data
    let data_to_broadcast = b"Test Deliver data".to_vec();
    assert!(n_t > 3*f_byzantine, "Deliver requires n > 3f for safety usually");

    // Generate node identities
    let mut nodes_identities = Vec::new();
    let mut sks = Vec::new();
    for i in 0..n_t {
        // In a real scenario, generate keys or unique identities
        let rng_dalek = &mut OsRng;
        let sk = SecretKey::generate(rng_dalek);
        sks.push(sk.clone());
        let pk = sk.verifying_key();
        nodes_identities.push((Identity::new([i as u8; 32]), pk));
    }
    nodes_identities.sort_unstable_by(|(a_pk, _a_vk), (b_pk, _b_vk)| a_pk.cmp(b_pk));

    // Initialize event processors (one per node)
    let mut nodes_processors = HashMap::new();
    for i in 0..n_t {
        let node_processor = init_state(
            nodes_identities[i].0.clone(),
            n_t as u32,
            threshold_t as u32,
            threshold_c as u32,
            sks[i].clone(),
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Step 1: Initialize all nodes
    let mut queued_actions = Vec::new();
    for i in 0..n_t {
        let data = if i < n_c { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = CSDeliverEvent {
            event_type: CSDeliverEventType::ReceivedNewDataToBroadcast,
            data: CSDeliverEventData::ReceiveNewDataToBroadcast(data),
        };
        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        // Store these actions temporarily; do not deliver them yet
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    let identities = nodes_identities.iter().map(|x| x.0.clone()).collect::<Vec<Identity>>();

    // Step 2: Deliver the queued actions now that everyone is in WaitForMsgs
    for (sender_index, action) in queued_actions {
        deliver_actions(&mut nodes_processors, &identities, sender_index, &[action]);
    }

    // At this point, after init, the broadcaster should have sent codewords,
    // other nodes should respond with Echo,
    // The `deliver_actions` calls recursively handle the message passing simulation.

    // After all message passing is done (the test might need loops or extra checks
    // to ensure stability), we expect that all nodes have reconstructed the data.
    // To check that, we can retrieve the CSDeliverNode state subscriber from the event processor.

    for (i, node_processor) in nodes_processors.iter() {
        // The Deliver node after initialization and after moving to the "wait_for_msgs" state
        // has get_id() = 0. Thus, we try to get subscriber with id=1.
        // If your CSDeliverNode after completion has a different state id, adjust accordingly.

        if let Some(sub) = node_processor.get_subscriber(0) {
            // Downcast to CSDeliverNode<WaitForMsgs>
            if let Some(deliver_node) = sub.as_any().downcast_ref::<CSDeliverNode<WaitForMsgs>>() {

                // If needed, verify reconstructed data
                // Check that at least one message was reconstructed
                assert!(!deliver_node.reconstructed_data.is_empty(), "Node {} has no reconstructed data", i);

                // Verify the reconstructed data matches the broadcasted message
                // We know the broadcaster was node 0. Let's get some reconstructed entry:
                let reconstructed_msg = deliver_node.reconstructed_data.clone();
                assert_eq!(data_to_broadcast, reconstructed_msg, "Node {} reconstructed wrong data", i);
            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }

    println!("All nodes completed Deliver successfully and reconstructed the message.");
}

#[test]
fn check_deliver_with_byzantine_nodes() {
    env::set_var("RUST_LOG", "TRACE");
    let _ = env_logger::try_init();
    // Deliver configuration
    let f_byzantine = 2; // number of byzantine nodes
    let threshold_t = 2*f_byzantine + 1;  // tribe threshold

    // Let's say node 1 and node 2 are byzantine
    let byzantine_nodes = vec![1, 2];

    let n_t = 3*f_byzantine + 1;  // total nodes in tribe
    let n_c = 2*f_byzantine + 1;  // total nodes in clan
    let threshold_c = f_byzantine + 1;  // clan threshold
    // Let's say the first node (index 0) is the broadcaster with some data
    let data_to_broadcast = b"Test Deliver data".to_vec();
    assert!(n_t > 3*f_byzantine, "Deliver requires n > 3f for safety usually");

    // Generate node identities
    let mut nodes_identities = Vec::new();
    let mut sks = Vec::new();
    for i in 0..n_t {
        // In a real scenario, generate keys or unique identities
        let rng_dalek = &mut OsRng;
        let sk = SecretKey::generate(rng_dalek);
        sks.push(sk.clone());
        let pk = sk.verifying_key();
        nodes_identities.push((Identity::new([i as u8; 32]), pk));
    }
    nodes_identities.sort_unstable_by(|(a_pk, _a_vk), (b_pk, _b_vk)| a_pk.cmp(b_pk));

    // Initialize event processors (one per node)
    let mut nodes_processors = HashMap::new();
    for i in 0..n_t {
        let node_processor = init_state(
            nodes_identities[i].0.clone(),
            n_t as u32,
            threshold_t as u32,
            threshold_c as u32,
            sks[i].clone(),
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Step 1: Initialize all nodes
    let mut queued_actions = Vec::new();
    for i in 0..n_t {
        let data = if i < n_c { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = CSDeliverEvent {
            event_type: CSDeliverEventType::ReceivedNewDataToBroadcast,
            data: CSDeliverEventData::ReceiveNewDataToBroadcast(data),
        };
        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        // Store these actions temporarily; do not deliver them yet
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // Byzantine wrapper for deliver_actions
    fn deliver_actions_with_byzantine(
        nodes_processors: &mut HashMap<usize, soruntime::state::EventProcessor<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType>>,
        identities: &[Identity],
        sender_index: usize,
        actions: &[Action<CSDeliverEventData, CSDeliverEventType>],
        byzantine_nodes: &[usize]
    ) {
        for action in actions {
            match action {
                Action::SendMessage(data) => {
                    let mut all_follow_up_actions = Vec::new();
                    let msg = CSDeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                    let keys: Vec<usize> = nodes_processors.keys().copied().collect();

                    for i in keys {
                        if i == sender_index {
                            continue;
                        }

                        // Simulate byzantine behavior: drop messages to/from byzantine nodes
                        if byzantine_nodes.contains(&i) || byzantine_nodes.contains(&sender_index) {
                            // drop the message or alter it, simulate doing nothing
                            continue;
                        }

                        let event = create_deliver_event_from_message(msg.clone());
                        let follow_up_actions = {
                            let node_processor = nodes_processors.get_mut(&i).unwrap();
                            node_processor.process_event(Box::new(event))
                        };

                        if !follow_up_actions.is_empty() {
                            all_follow_up_actions.push((i, follow_up_actions));
                        }
                    }

                    for (target_idx, f_actions) in all_follow_up_actions {
                        deliver_actions_with_byzantine(nodes_processors, identities, target_idx, &f_actions, byzantine_nodes);
                    }
                },
                Action::SendMessageTo(target_id, data) => {
                    let msg = CSDeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                    let target_idx = identity_to_index(identities, target_id).expect("Target not found");

                    if byzantine_nodes.contains(&target_idx) || byzantine_nodes.contains(&sender_index) {
                        // drop/ignore this message
                        continue;
                    }

                    let event = create_deliver_event_from_message(msg);
                    let follow_up_actions = {
                        let node_processor = nodes_processors.get_mut(&target_idx).unwrap();
                        node_processor.process_event(Box::new(event))
                    };

                    if !follow_up_actions.is_empty() {
                        deliver_actions_with_byzantine(nodes_processors, identities, target_idx, &follow_up_actions, byzantine_nodes);
                    }
                },
                _ => {}
            }
        }
    }

    let identities = nodes_identities.iter().map(|x| x.0.clone()).collect::<Vec<Identity>>();

    // Deliver initial actions with byzantine behavior
    for (sender_index, action) in queued_actions {
        deliver_actions_with_byzantine(&mut nodes_processors, &identities, sender_index, &[action], &byzantine_nodes);
    }

    // Check if honest nodes complete Deliver (depending on Deliver definition, it might still complete)
    for (i, node_processor) in nodes_processors.iter() {
        // Byzantine nodes might not have reconstructed the data, but honest nodes should
        if byzantine_nodes.contains(&i) {
            continue; // We don't care if byzantine completed or not
        }

        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<CSDeliverNode<WaitForMsgs>>() {
                // The Deliver might tolerate f byzantine faults and still reconstruct.
                // Check if done is true or if partial completion is expected.
                assert!(!deliver_node.reconstructed_data.is_empty(), "Honest node {} has no reconstructed data", i);
            }
        }
    }
}

#[test]
fn check_deliver_all_broadcasting_large_committee_out_of_order() {

    // Instead of using deliver_actions directly, we will simulate out-of-order
    // message delivery by managing a global queue of actions.

    fn handle_action(
        node_processors: &mut HashMap<usize, soruntime::state::EventProcessor<CSDeliverEventData, CSDeliverEvent, CSDeliverEventType>>,
        identities: &[Identity],
        sender_index: usize,
        action: Action<CSDeliverEventData, CSDeliverEventType>,
        new_actions_queue: &mut Vec<(usize, Action<CSDeliverEventData, CSDeliverEventType>)>,
    ) {
        match action {
            Action::SendMessage(data) => {
                let msg = CSDeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                let keys: Vec<usize> = node_processors.keys().copied().collect();
                for i in keys {
                    if i == sender_index {
                        continue;
                    }
                    let event = create_deliver_event_from_message(msg.clone());
                    let follow_up_actions = node_processors.get_mut(&i).unwrap().process_event(Box::new(event));
                    for fa in follow_up_actions {
                        new_actions_queue.push((i, fa));
                    }
                }
            },
            Action::SendMessageTo(target_id, data) => {
                let msg = CSDeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                let target_idx = identity_to_index(identities, &target_id).expect("Target not found");
                let event = create_deliver_event_from_message(msg);
                let follow_up_actions = node_processors.get_mut(&target_idx).unwrap().process_event(Box::new(event));
                for fa in follow_up_actions {
                    new_actions_queue.push((target_idx, fa));
                }
            },
            _ => {
                // For Deliver typically just SendMessage and SendMessageTo are crucial.
            }
        }
    }

    // Initialize environment
    //env::set_var("RUST_LOG", "TRACE");
    //let _ = env_logger::try_init();

    // Deliver configuration
    let f_byzantine = 50; // number of byzantine nodes
    let threshold_t = 2*f_byzantine + 1;  // tribe threshold

    let n_t = 3*f_byzantine + 1;  // total nodes in tribe
    let n_c = 2*f_byzantine + 1;  // total nodes in clan
    let threshold_c = f_byzantine + 1;  // clan threshold
    // Let's say the first node (index 0) is the broadcaster with some data
    let data_to_broadcast = b"Test Deliver data".to_vec();
    assert!(n_t > 3*f_byzantine, "Deliver requires n > 3f for safety usually");

    // Generate node identities
    let mut nodes_identities = Vec::new();
    let mut sks = Vec::new();
    for i in 0..n_t {
        // In a real scenario, generate keys or unique identities
        let rng_dalek = &mut OsRng;
        let sk = SecretKey::generate(rng_dalek);
        sks.push(sk.clone());
        let pk = sk.verifying_key();
        nodes_identities.push((Identity::new([i as u8; 32]), pk));
    }
    nodes_identities.sort_unstable_by(|(a_pk, _a_vk), (b_pk, _b_vk)| a_pk.cmp(b_pk));

    // Initialize event processors (one per node)
    let mut nodes_processors = HashMap::new();
    for i in 0..n_t {
        let node_processor = init_state(
            nodes_identities[i].0.clone(),
            n_t as u32,
            threshold_t as u32,
            threshold_c as u32,
            sks[i].clone(),
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }
    // Step 1: Initialize all nodes (send InitDeliver)
    let mut global_action_queue = Vec::new();
    for i in 0..n_t {
        let data = if i < n_c { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = CSDeliverEvent {
            event_type: CSDeliverEventType::ReceivedNewDataToBroadcast,
            data: CSDeliverEventData::ReceiveNewDataToBroadcast(data),
        };
        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        // Store these actions temporarily; do not deliver them yet
        for a in actions {
            global_action_queue.push((i, a));
        }
    }

    let identities = nodes_identities.iter().map(|x| x.0.clone()).collect::<Vec<Identity>>();

    // Step 2: Out-of-order delivery simulation
    // We will repeatedly shuffle global_action_queue and process actions in random order.
    // Each processed action may generate follow-up actions appended to a temporary queue,
    // which we then incorporate into global_action_queue and shuffle again.

    let mut rng = thread_rng();
    let mut iterations = 0;
    // We stop when no more actions are generated (stable state) or after a large iteration count
    // to prevent infinite loops if something goes wrong.
    while !global_action_queue.is_empty() && iterations < 10_000 {
        iterations += 1;

        // Shuffle the actions
        global_action_queue.shuffle(&mut rng);

        let mut new_actions_queue = Vec::new();
        // Process each action in random order
        for (sender_idx, action) in global_action_queue.drain(..) {
            handle_action(&mut nodes_processors, &identities, sender_idx, action, &mut new_actions_queue);
        }

        // Move newly generated actions into global_action_queue for next iteration
        global_action_queue.extend(new_actions_queue);
    }

    // After no more actions are generated or we hit iteration limit, check if Deliver completed
    // We expect Deliver to complete successfully if assumptions hold and protocol is correct.

    for (i, node_processor) in nodes_processors.iter() {
        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<CSDeliverNode<WaitForMsgs>>() {

                // If needed, verify reconstructed data
                // Check that at least one message was reconstructed
                assert!(!deliver_node.reconstructed_data.is_empty(), "Node {} has no reconstructed data", i);

                // Verify the reconstructed data matches the broadcasted message
                // We know the broadcaster was node 0. Let's get some reconstructed entry:
                let reconstructed_msg = deliver_node.reconstructed_data.clone();
                assert_eq!(data_to_broadcast, reconstructed_msg, "Node {} reconstructed wrong data", i);

            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }

    println!("All nodes completed Deliver successfully, even with out-of-order delivery.");
}