//! STI-OS Basic Cycle Example
//!
//! Demonstrates the L1 -> L2 pipeline:
//! 1. Create a ControlPlaneConfig and ControlPlaneCollector
//! 2. Build a TemporalGraph
//! 3. Ingest signals manually (mock NormalizedSignal)
//! 4. Check concordant_pairs for hypothesis candidates
//!
//! This example does NOT require a live RPC endpoint;
//! all signals are constructed in-memory.

use std::collections::HashMap;

use alloy_primitives::{Address, B256};
use chrono::Utc;

use sti_os::collectors::control_plane::{
    ControlPlaneCollector, ControlPlaneConfig,
};
use sti_os::graph::{DependencyType, EntityType, TemporalGraph};
use sti_os::types::{
    selectors, Classification, DataQuality, ForgeryLevel,
    Hypothesis, NormalizedSignal, SignalType,
};

/// Build a mock NormalizedSignal for demonstration.
fn mock_signal(
    id: &str,
    selector: [u8; 4],
    block: u64,
    entity: Address,
    source_tx: B256,
    fields: HashMap<String, serde_json::Value>,
) -> NormalizedSignal {
    NormalizedSignal {
        id: id.to_string(),
        signal_type: SignalType::ControlPlane,
        source_tx,
        block_number: block,
        timestamp: Utc::now(),
        chain_id: 1,
        entity,
        event_selector: selector,
        raw_data: vec![],
        normalized_fields: fields,
        forgery_cost: ForgeryLevel::High,
        quality: DataQuality::Clean,
    }
}

#[tokio::main]
async fn main() {
    // ----------------------------------------------------------------
    // Step 1: Create ControlPlaneConfig and ControlPlaneCollector
    // ----------------------------------------------------------------
    let config = ControlPlaneConfig {
        rpc_url: "http://localhost:8545".to_string(),
        chain_id: 1,
        watch_addresses: vec![],
        rpc_timeout_secs: 5,
    };
    let _collector = ControlPlaneCollector::new(config);
    println!("[1] ControlPlaneCollector created (RPC not called in this demo)");

    // ----------------------------------------------------------------
    // Step 2: Create a TemporalGraph
    // ----------------------------------------------------------------
    let mut graph = TemporalGraph::new();
    println!("[2] TemporalGraph created (entities={}, edges={})",
        graph.entity_count(), graph.edge_count());

    // ----------------------------------------------------------------
    // Step 3: Ingest mock signals
    // ----------------------------------------------------------------
    let contract = Address::from([0x01; 20]);
    let new_owner = "0x0000000000000000000000000000000000000002";

    // Signal A: OwnershipTransferred on contract
    let mut fields_a = HashMap::new();
    fields_a.insert("event".to_string(), serde_json::json!("OwnershipTransferred"));
    fields_a.insert("newOwner".to_string(), serde_json::json!(new_owner));

    let signal_a = mock_signal(
        "sig-001",
        selectors::OWNERSHIP_TRANSFERRED,
        100,
        contract,
        B256::ZERO,
        fields_a,
    );
    graph.ingest_control_plane_signal(&signal_a);
    println!("[3a] Ingested OwnershipTransferred -> entities={}, edges={}",
        graph.entity_count(), graph.edge_count());

    // Signal B: Another OwnershipTransferred on the same contract
    //           from a different tx (strengthens the Owns edge).
    let mut fields_b = HashMap::new();
    fields_b.insert("event".to_string(), serde_json::json!("OwnershipTransferred"));
    fields_b.insert("newOwner".to_string(), serde_json::json!(new_owner));

    let signal_b = mock_signal(
        "sig-002",
        selectors::OWNERSHIP_TRANSFERRED,
        110,
        contract,
        B256::from([1u8; 32]),
        fields_b,
    );
    graph.ingest_control_plane_signal(&signal_b);
    println!("[3b] Ingested second OwnershipTransferred -> entities={}, edges={}",
        graph.entity_count(), graph.edge_count());

    // ----------------------------------------------------------------
    // Step 4: Check concordant_pairs
    // ----------------------------------------------------------------
    let pairs = graph.concordant_pairs();
    println!("[4] Concordant pairs (evidence >= 2): {}", pairs.len());
    for pair in &pairs {
        println!("    {} -> {} | type={:?} | evidence={} | weight={:.3}",
            pair.from_address, pair.to_address,
            pair.dep_type, pair.evidence_count, pair.weight);
    }

    // ----------------------------------------------------------------
    // Bonus: Manual graph operations
    // ----------------------------------------------------------------
    let deployer = Address::from([0xAA; 20]);
    let vault = Address::from([0xBB; 20]);

    let deployer_idx = graph.ensure_entity(deployer, 1, EntityType::Deployer, 50);
    let vault_idx = graph.ensure_entity(vault, 1, EntityType::Vault, 60);
    graph.add_dependency(
        deployer_idx,
        vault_idx,
        DependencyType::Funds,
        "manual-evidence-1".to_string(),
        70,
    );
    graph.add_dependency(
        deployer_idx,
        vault_idx,
        DependencyType::Funds,
        "manual-evidence-2".to_string(),
        80,
    );

    let all_pairs = graph.concordant_pairs();
    println!("[5] Total concordant pairs after manual edges: {}", all_pairs.len());

    // ----------------------------------------------------------------
    // Bonus: Confidence calculation
    // ----------------------------------------------------------------
    let now = Utc::now();
    let refs: Vec<&NormalizedSignal> = vec![&signal_a, &signal_b];
    let confidence = Hypothesis::calculate_confidence(&refs, 1.0, now);
    let classification = Classification::from_confidence(confidence);
    println!("[6] Confidence from 2 signals: {:.4} -> {:?}", confidence, classification);

    println!("\nDone. STI-OS basic cycle complete.");
}
