use std::env;
use std::collections::{HashMap};
use env_logger;
use erasure::codecs::rs8::Rs8Chunk;
use erasure::utils::codec_trait::Chunk;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use crate::messages::DeliverProtocolMessage;
use crate::types::deliver_event::{DeliverEventData, DeliverEventType, DeliverEvent};
use crate::node::DeliverNode;
use soruntime::state::{Action};
use socrypto::Identity;
use crate::state::init_state;
use crate::states::wait_for_msgs::WaitForMsgs;

// Helper function to map Identity -> node index
fn identity_to_index(identities: &[Identity], id: &Identity) -> Option<usize> {
    identities.iter().position(|x| x == id)
}

// Helper to convert DeliverProtocolMessage into DeliverEvent (for receiving nodes)
fn create_deliver_event_from_message(msg: DeliverProtocolMessage) -> DeliverEvent {
    match msg {
        DeliverProtocolMessage::Codeword(codeword) => DeliverEvent {
            event_type: DeliverEventType::ReceivedCodeword,
            data: DeliverEventData::ReceiveCodeword(codeword),
        },
        DeliverProtocolMessage::Echo(codeword) => DeliverEvent {
            event_type: DeliverEventType::ReceivedEcho,
            data: DeliverEventData::ReceiveEcho(codeword),
        },
    }
}

// Simulate delivering actions (messages) from one node to others
fn deliver_actions(
    nodes_processors: &mut HashMap<usize, soruntime::state::EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType>>,
    identities: &[Identity],
    sender_index: usize,
    actions: &[Action<DeliverEventData, DeliverEventType>]
) {
    for action in actions {
        match action {
            Action::SendMessage(data) => {
                let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
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
                let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
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
    let n = 4;  // total nodes
    let f = 1;  // number of byzantine nodes
    // Let's say the first node (index 0) is the broadcaster with some data
    let data_to_broadcast = b"Test Deliver data".to_vec();
    assert!(n > 3*f, "Deliver requires n > 3f for safety usually");

    // Generate node identities
    let mut nodes_identities = Vec::new();
    for i in 0..n {
        // In a real scenario, generate keys or unique identities
        nodes_identities.push(Identity::new([i as u8; 32]));
    }
    nodes_identities.sort_unstable();

    // Initialize event processors (one per node)
    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Step 1: Initialize all nodes
    let mut queued_actions = Vec::new();
    for i in 0..n {
        let data = if i == 0 { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };
        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        // Store these actions temporarily; do not deliver them yet
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // Step 2: Deliver the queued actions now that everyone is in WaitForMsgs
    for (sender_index, action) in queued_actions {
        deliver_actions(&mut nodes_processors, &nodes_identities, sender_index, &[action]);
    }

    // At this point, after init, the broadcaster should have sent codewords,
    // other nodes should respond with Echo,
    // The `deliver_actions` calls recursively handle the message passing simulation.

    // After all message passing is done (the test might need loops or extra checks
    // to ensure stability), we expect that all nodes have reconstructed the data.
    // To check that, we can retrieve the DeliverNode state subscriber from the event processor.

    for (i, node_processor) in nodes_processors.iter() {
        // The Deliver node after initialization and after moving to the "wait_for_msgs" state
        // has get_id() = 0. Thus, we try to get subscriber with id=1.
        // If your DeliverNode after completion has a different state id, adjust accordingly.

        if let Some(sub) = node_processor.get_subscriber(0) {
            // Downcast to DeliverNode<WaitForMsgs>
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {

                // If needed, verify reconstructed data
                // Check that at least one message was reconstructed
                assert!(!deliver_node.reconstructed_data.is_empty(), "Node {} has no reconstructed data", i);

                // Verify the reconstructed data matches the broadcasted message
                // We know the broadcaster was node 0. Let's get some reconstructed entry:
                let reconstructed_msg = deliver_node.reconstructed_data.values().next().unwrap();
                assert_eq!(&data_to_broadcast, reconstructed_msg, "Node {} reconstructed wrong data", i);
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
fn check_deliver_multiple_broadcasters() {
    // Setup
    env::set_var("RUST_LOG", "TRACE");
    let _ = env_logger::try_init();

    let n = 4;
    let f = 1;
    assert!(n > 3 * f);

    let mut nodes_identities = (0..n).map(|i| Identity::new([i as u8; 32])).collect::<Vec<_>>();
    nodes_identities.sort_unstable();

    let data_broadcaster_0 = b"Data from node0".to_vec();
    let data_broadcaster_1 = b"Data from node1".to_vec();

    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Init all
    let mut queued_actions = Vec::new();
    for i in 0..n {
        let data = if i == 0 {
            data_broadcaster_0.clone()
        } else if i == 1 {
            data_broadcaster_1.clone()
        } else {
            vec![]
        };

        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };

        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // Deliver all initial actions
    for (sender_index, action) in queued_actions {
        deliver_actions(&mut nodes_processors, &nodes_identities, sender_index, &[action]);
    }

    // Check completion
    for (i, node_processor) in nodes_processors.iter() {
        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {

                // Verify data
                let mut reconstructed_messages = deliver_node
                    .reconstructed_data
                    .values()
                    .map(|msg| msg.clone())
                    .collect::<Vec<_>>();

                reconstructed_messages.sort();
                let mut expected_msgs = vec![data_broadcaster_0.clone(), data_broadcaster_1.clone()];
                expected_msgs.sort();

                assert_eq!(reconstructed_messages, expected_msgs, "Node {} reconstructed wrong data set", i);
            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }
}

#[test]
fn check_deliver_all_nodes_broadcasting() {

    env::set_var("RUST_LOG", "TRACE");
    let _ = env_logger::try_init();

    let n = 4;   // total nodes
    let f = 1;   // number of byzantine nodes (0 in this test if desired, but let's keep f=1 for Deliver parameters)
    assert!(n > 3*f, "Deliver requires n > 3f for safety usually");

    // Generate node identities
    let mut nodes_identities = Vec::new();
    for i in 0..n {
        // Generate unique identities for each node
        nodes_identities.push(Identity::new([i as u8; 32]));
    }
    nodes_identities.sort_unstable();

    // Assign each node different data to broadcast
    let node_data: Vec<Vec<u8>> = (0..n).map(|i| format!("Data from node {}", i).into_bytes()).collect();

    // Initialize event processors (one per node)
    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Step 1: Initialize all nodes and send InitDeliver
    let mut queued_actions = Vec::new();
    for i in 0..n {
        let data = node_data[i].clone();
        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };

        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // Step 2: Deliver the queued actions now that everyone is in WaitForMsgs
    for (sender_index, action) in queued_actions {
        deliver_actions(&mut nodes_processors, &nodes_identities, sender_index, &[action]);
    }

    // After all initial actions are delivered and the Deliver protocol messages circulate,
    // eventually each node should have reconstructed data from all n nodes.

    for (i, node_processor) in nodes_processors.iter() {
        // The Deliver node after moving to the "wait_for_msgs" state has get_id() = 0.
        if let Some(sub) = node_processor.get_subscriber(0) {
            // Downcast to DeliverNode<WaitForMsgs>
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {

                // Check that we have reconstructed all n messages
                assert_eq!(deliver_node.reconstructed_data.len(), n, "Node {} did not reconstruct all data", i);

                // Verify each reconstructed message matches what was broadcast
                let mut reconstructed_msgs: Vec<Vec<u8>> = deliver_node.reconstructed_data.values().map(|msg| msg.clone()).collect();
                reconstructed_msgs.sort();
                let mut expected_msgs = node_data.clone();
                expected_msgs.sort();

                assert_eq!(reconstructed_msgs, expected_msgs, "Node {} reconstructed wrong set of data", i);
            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }

    println!("All nodes completed Deliver successfully and reconstructed all {} messages.", n);
}

#[test]
fn check_deliver_with_byzantine_nodes() {
    env::set_var("RUST_LOG", "TRACE");
    let _ = env_logger::try_init();
    let n = 7;
    let f = 2;
    assert!(n > 3 * f);

    let mut nodes_identities = (0..n).map(|i| Identity::new([i as u8; 32])).collect::<Vec<_>>();
    nodes_identities.sort_unstable();

    // Let's say node 5 and node 6 are byzantine
    let byzantine_nodes = vec![5, 6];

    let data_to_broadcast = b"Data from node0".to_vec();

    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Initialize all nodes
    let mut queued_actions = Vec::new();
    for i in 0..n {
        let data = if i == 0 { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };
        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // Byzantine wrapper for deliver_actions
    fn deliver_actions_with_byzantine(
        nodes_processors: &mut HashMap<usize, soruntime::state::EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType>>,
        identities: &[Identity],
        sender_index: usize,
        actions: &[Action<DeliverEventData, DeliverEventType>],
        byzantine_nodes: &[usize]
    ) {
        for action in actions {
            match action {
                Action::SendMessage(data) => {
                    let mut all_follow_up_actions = Vec::new();
                    let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
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
                    let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
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

    // Deliver initial actions with byzantine behavior
    for (sender_index, action) in queued_actions {
        deliver_actions_with_byzantine(&mut nodes_processors, &nodes_identities, sender_index, &[action], &byzantine_nodes);
    }

    // Check if honest nodes complete Deliver (depending on Deliver definition, it might still complete)
    for (i, node_processor) in nodes_processors.iter() {
        // Byzantine nodes might not have reconstructed the data, but honest nodes should
        if byzantine_nodes.contains(&i) {
            continue; // We don't care if byzantine completed or not
        }

        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {
                // The Deliver might tolerate f byzantine faults and still reconstruct.
                // Check if done is true or if partial completion is expected.
                assert!(!deliver_node.reconstructed_data.is_empty(), "Honest node {} has no reconstructed data", i);
            }
        }
    }
}

#[test]
fn check_deliver_large_committee() {
    let _ = env_logger::try_init();
    let n = 200;
    let f = 50;
    assert!(n > 3 * f);

    let mut nodes_identities = (0..n).map(|i| Identity::new([i as u8; 32])).collect::<Vec<_>>();
    nodes_identities.sort_unstable();

    let data_to_broadcast = b"Large committee Deliver data".to_vec();

    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Init all
    let mut queued_actions = Vec::new();
    for i in 0..n {
        let data = if i == 0 { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };

        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // Deliver all initial actions
    for (sender_index, action) in queued_actions {
        deliver_actions(&mut nodes_processors, &nodes_identities, sender_index, &[action]);
    }

    // Check completion
    for (i, node_processor) in nodes_processors.iter() {
        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {
                assert!(!deliver_node.reconstructed_data.is_empty(), "Node {} has no reconstructed data", i);
                let reconstructed_msg = deliver_node.reconstructed_data.values().next().unwrap();
                assert_eq!(&data_to_broadcast, reconstructed_msg, "Node {} reconstructed wrong data", i);
            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }
}

#[test]
fn check_deliver_with_byzantine_garbage_messages() {
    let _ = env_logger::try_init();
    let n = 7;
    let f = 2;
    assert!(n > 3 * f);

    let mut nodes_identities = (0..n)
        .map(|i| Identity::new([i as u8; 32]))
        .collect::<Vec<_>>();
    nodes_identities.sort_unstable();

    // Node 5 and 6 are byzantine
    let byzantine_nodes = vec![5, 6];

    let data_to_broadcast = b"Data from node0".to_vec();

    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Initialize all nodes
    let mut queued_actions = Vec::new();
    for i in 0..n {
        let data = if i == 0 { data_to_broadcast.clone() } else { vec![] };
        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };

        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        for a in actions {
            queued_actions.push((i, a));
        }
    }

    // A helper function to generate garbage Deliver messages of all types
    // For Codeword and Echo (which contain codewords), we provide invalid chunk data or merkle root.
    // For Ready, we provide an invalid hash.
    fn generate_garbage_message() -> DeliverProtocolMessage {
        use crate::codeword::Codeword;
        use vec_commitment::committed_chunk::CommittedChunk;
        use socrypto::Hash;

        // Create a garbage codeword with invalid proof:
        let invalid_root = Hash([0xFF; 32]); // invalid merkle root
        let invalid_chunk = vec![0xFF; 10];  // invalid arbitrary data
        let chunk_with_proof = CommittedChunk::new(0, vec![], Rs8Chunk::new(0,invalid_chunk.clone(),invalid_chunk.len())); // Empty proof

        let garbage_codeword = Codeword {
            merkle_root: invalid_root,
            chunk_with_merkle_proof: chunk_with_proof,
        };

        // Randomly choose a message type to return as garbage
        let rand_type = rand::random::<u8>() % 2;
        match rand_type {
            0 => DeliverProtocolMessage::Codeword(garbage_codeword.clone()),
            _ => DeliverProtocolMessage::Echo(garbage_codeword.clone()),
        }
    }

    // Byzantine message delivery:
    // Honest nodes send correct messages as is.
    // Byzantine nodes always send garbage messages instead of the original.
    fn deliver_actions_with_garbage(
        nodes_processors: &mut HashMap<usize, soruntime::state::EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType>>,
        identities: &[Identity],
        sender_index: usize,
        actions: &[Action<DeliverEventData, DeliverEventType>],
        byzantine_nodes: &[usize],
    ) {
        for action in actions {
            match action {
                Action::SendMessage(data) => {
                    let mut all_follow_up_actions = Vec::new();
                    let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                    let keys: Vec<usize> = nodes_processors.keys().copied().collect();

                    for i in keys {
                        if i == sender_index {
                            continue;
                        }
                        let actual_msg = if byzantine_nodes.contains(&sender_index) {
                            // Sender is byzantine, send garbage
                            generate_garbage_message()
                        } else {
                            // Honest sender sends the correct message
                            msg.clone()
                        };

                        let event = create_deliver_event_from_message(actual_msg);
                        let follow_up_actions = {
                            let node_processor = nodes_processors.get_mut(&i).unwrap();
                            node_processor.process_event(Box::new(event))
                        };

                        if !follow_up_actions.is_empty() {
                            all_follow_up_actions.push((i, follow_up_actions));
                        }
                    }

                    for (target_idx, f_actions) in all_follow_up_actions {
                        deliver_actions_with_garbage(nodes_processors, identities, target_idx, &f_actions, byzantine_nodes);
                    }
                },
                Action::SendMessageTo(target_id, data) => {
                    let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
                    let target_idx = identity_to_index(identities, target_id).expect("Target not found");

                    let actual_msg = if byzantine_nodes.contains(&sender_index) {
                        // Sender is byzantine, send garbage
                        generate_garbage_message()
                    } else {
                        msg
                    };

                    let event = create_deliver_event_from_message(actual_msg);
                    let follow_up_actions = {
                        let node_processor = nodes_processors.get_mut(&target_idx).unwrap();
                        node_processor.process_event(Box::new(event))
                    };

                    if !follow_up_actions.is_empty() {
                        deliver_actions_with_garbage(nodes_processors, identities, target_idx, &follow_up_actions, byzantine_nodes);
                    }
                },
                _ => {}
            }
        }
    }

    // Deliver initial actions with byzantine garbage messaging
    for (sender_index, action) in queued_actions {
        deliver_actions_with_garbage(&mut nodes_processors, &nodes_identities, sender_index, &[action], &byzantine_nodes);
    }

    // Check that honest nodes complete Deliver
    // With f=2 byzantine nodes, Deliver should still succeed for honest nodes.
    for (i, node_processor) in nodes_processors.iter() {
        if byzantine_nodes.contains(&i) {
            // Don't care if byzantine nodes complete or not
            continue;
        }

        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {
                assert!(!deliver_node.reconstructed_data.is_empty(), "Honest node {} has no reconstructed data", i);
                let reconstructed_msg = deliver_node.reconstructed_data.values().next().unwrap();
                assert_eq!(&data_to_broadcast, reconstructed_msg, "Honest node {} got wrong data", i);
            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }

    println!("All honest nodes completed Deliver successfully despite byzantine nodes sending garbage messages.");
}

#[test]
fn check_deliver_all_broadcasting_large_committee_out_of_order() {

    // Instead of using deliver_actions directly, we will simulate out-of-order
    // message delivery by managing a global queue of actions.

    fn process_and_queue_event(
        node_processors: &mut HashMap<usize, soruntime::state::EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType>>,
        sender_idx: usize,
        event: DeliverEvent,
        action_queue: &mut Vec<(usize, Action<DeliverEventData, DeliverEventType>)>,
    ) {
        let actions = node_processors.get_mut(&sender_idx).unwrap().process_event(Box::new(event));
        for a in actions {
            action_queue.push((sender_idx, a));
        }
    }

    fn handle_action(
        node_processors: &mut HashMap<usize, soruntime::state::EventProcessor<DeliverEventData, DeliverEvent, DeliverEventType>>,
        identities: &[Identity],
        sender_index: usize,
        action: Action<DeliverEventData, DeliverEventType>,
        new_actions_queue: &mut Vec<(usize, Action<DeliverEventData, DeliverEventType>)>,
    ) {
        match action {
            Action::SendMessage(data) => {
                let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
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
                let msg = DeliverProtocolMessage::try_from(data.as_slice()).expect("valid Deliver msg");
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
    let n = 200;  // large committee
    let f = 50;   // number of byzantine nodes (just for Deliver thresholding, can be zero if you like)
    assert!(n > 3*f, "Deliver requires n > 3f for safety");

    // Generate node identities
    let mut nodes_identities = Vec::new();
    for i in 0..n {
        nodes_identities.push(Identity::new([i as u8; 32]));
    }
    nodes_identities.sort_unstable();

    // Assign each node different data to broadcast
    let node_data: Vec<Vec<u8>> = (0..n).map(|i| format!("Data from node {}", i).into_bytes()).collect();

    // Initialize event processors (one per node)
    let mut nodes_processors = HashMap::new();
    for i in 0..n {
        let node_processor = init_state(
            nodes_identities[i],
            n as u32,
            f as u32,
            nodes_identities.clone(),
        );
        nodes_processors.insert(i, node_processor);
    }

    // Step 1: Initialize all nodes (send InitDeliver)
    let mut global_action_queue = Vec::new();
    for i in 0..n {
        let data = node_data[i].clone();
        let new_data_event = DeliverEvent {
            event_type: DeliverEventType::ReceivedNewDataToBroadcast,
            data: DeliverEventData::ReceiveNewDataToBroadcast(data),
        };

        let actions = nodes_processors.get_mut(&i).unwrap().process_event(Box::new(new_data_event));
        for a in actions {
            global_action_queue.push((i, a));
        }
    }

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
            handle_action(&mut nodes_processors, &nodes_identities, sender_idx, action, &mut new_actions_queue);
        }

        // Move newly generated actions into global_action_queue for next iteration
        global_action_queue.extend(new_actions_queue);
    }

    // After no more actions are generated or we hit iteration limit, check if Deliver completed
    // We expect Deliver to complete successfully if assumptions hold and protocol is correct.

    for (i, node_processor) in nodes_processors.iter() {
        if let Some(sub) = node_processor.get_subscriber(0) {
            if let Some(deliver_node) = sub.as_any().downcast_ref::<DeliverNode<WaitForMsgs>>() {
                assert_eq!(deliver_node.reconstructed_data.len(), n, "Node {} did not reconstruct all data", i);

                let mut reconstructed_msgs: Vec<Vec<u8>> = deliver_node.reconstructed_data.values().map(|msg| msg.clone()).collect();
                reconstructed_msgs.sort();
                let mut expected_msgs = node_data.clone();
                expected_msgs.sort();

                assert_eq!(reconstructed_msgs, expected_msgs, "Node {} reconstructed wrong set of data", i);
            } else {
                panic!("Cannot downcast subscriber for node {}", i);
            }
        } else {
            panic!("No subscriber with id=0 found for node {}", i);
        }
    }

    println!("All nodes completed Deliver successfully and reconstructed all {} messages, even with out-of-order delivery.", n);
}
