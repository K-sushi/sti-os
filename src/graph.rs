//! Temporal Dependency Graph — L2 core data structure.
//!
//! petgraph::DiGraph<Entity, Dependency> with temporal windowing.
//! Nodes = on-chain entities, Edges = dependency relationships with timestamps.
//! Intelligence comes from ORDER, not just connections.

use alloy_primitives::Address;
use chrono::{DateTime, Utc};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::NormalizedSignal;

// ============================================================================
// Node: Entity
// ============================================================================

/// Type of on-chain entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    EOA,
    Contract,
    Proxy,
    Multisig,
    Deployer,
    Implementation,
    Vault,
    BridgeEndpoint,
    GovernanceActor,
    Relayer,
}

/// An entity in the temporal graph (node).
/// Includes chain_id for cross-chain entity separation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub address: Address,
    pub chain_id: u64,
    pub entity_type: EntityType,
    pub first_seen_block: u64,
    pub last_seen_block: u64,
    pub signal_count: usize,
}

// ============================================================================
// Edge: Dependency
// ============================================================================

/// Type of dependency relationship between entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DependencyType {
    Owns,
    Upgrades,
    Funds,
    Signs,
    Delegates,
    BridgesTo,
    ClaimsFrom,
    AlwaysPrecedes,
    CoOccursWith,
    SimulatesBefore,
    ConsistentlyReactsTo,
}

/// A dependency edge with temporal context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub dep_type: DependencyType,
    pub evidence_signal_ids: Vec<String>,
    pub temporal_window: (u64, u64), // (first_block, last_block)
    pub weight: f64,
    pub last_updated: DateTime<Utc>,
}

// ============================================================================
// Temporal Graph
// ============================================================================

/// The temporal dependency graph.
///
/// Key design decisions:
/// - temporal, not static: edges carry time windows
/// - pruning: decayed edges are removed
/// - concordance: multiple independent signals on same edge = stronger
pub struct TemporalGraph {
    graph: DiGraph<Entity, Dependency>,
    /// (chain_id, address) → node index lookup (cross-chain aware)
    address_index: HashMap<(u64, Address), NodeIndex>,
}

impl TemporalGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            address_index: HashMap::new(),
        }
    }

    /// Number of entities (nodes).
    pub fn entity_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of dependencies (edges).
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get or create an entity node (chain_id-aware).
    pub fn ensure_entity(
        &mut self,
        address: Address,
        chain_id: u64,
        entity_type: EntityType,
        block_number: u64,
    ) -> NodeIndex {
        let key = (chain_id, address);
        if let Some(&idx) = self.address_index.get(&key) {
            // Update last_seen
            if let Some(entity) = self.graph.node_weight_mut(idx) {
                if block_number > entity.last_seen_block {
                    entity.last_seen_block = block_number;
                }
                entity.signal_count += 1;
            }
            idx
        } else {
            let entity = Entity {
                address,
                chain_id,
                entity_type,
                first_seen_block: block_number,
                last_seen_block: block_number,
                signal_count: 1,
            };
            let idx = self.graph.add_node(entity);
            self.address_index.insert(key, idx);
            idx
        }
    }

    /// Add or strengthen a dependency edge.
    /// If edge already exists between (from, to) with same dep_type,
    /// strengthen it (add evidence, extend window, increase weight).
    pub fn add_dependency(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        dep_type: DependencyType,
        signal_id: String,
        block_number: u64,
    ) {
        // Check if edge already exists
        let existing = self.graph.edges_connecting(from, to)
            .find(|e| e.weight().dep_type == dep_type);

        if let Some(edge_ref) = existing {
            let edge_idx = edge_ref.id();
            if let Some(dep) = self.graph.edge_weight_mut(edge_idx) {
                dep.evidence_signal_ids.push(signal_id);
                dep.temporal_window.1 = dep.temporal_window.1.max(block_number);
                dep.temporal_window.0 = dep.temporal_window.0.min(block_number);
                // More evidence = higher weight (concordance)
                dep.weight = (dep.evidence_signal_ids.len() as f64 / 3.0).min(1.0);
                dep.last_updated = Utc::now();
            }
        } else {
            let dep = Dependency {
                dep_type,
                evidence_signal_ids: vec![signal_id],
                temporal_window: (block_number, block_number),
                weight: 1.0 / 3.0, // single evidence = 0.33 concordance
                last_updated: Utc::now(),
            };
            self.graph.add_edge(from, to, dep);
        }
    }

    /// Ingest a control-plane signal into the graph.
    /// Creates entities and edges based on the signal's normalized fields.
    /// Handles RoleRevoked (edge removal) and AdminChanged (data parsing).
    pub fn ingest_control_plane_signal(&mut self, signal: &NormalizedSignal) {
        let contract_addr = signal.entity;
        let block = signal.block_number;
        let chain_id = signal.chain_id;

        match signal.event_selector {
            crate::types::selectors::OWNERSHIP_TRANSFERRED => {
                let contract_node = self.ensure_entity(contract_addr, chain_id, EntityType::Contract, block);

                if let Some(new_owner_hex) = signal.normalized_fields.get("newOwner")
                    .and_then(|v| v.as_str())
                {
                    if let Some(new_owner) = parse_address_from_field(new_owner_hex) {
                        let owner_node = self.ensure_entity(new_owner, chain_id, EntityType::EOA, block);
                        self.add_dependency(
                            owner_node,
                            contract_node,
                            DependencyType::Owns,
                            signal.id.clone(),
                            block,
                        );
                    }
                }
            }
            crate::types::selectors::UPGRADED => {
                let proxy_node = self.ensure_entity(contract_addr, chain_id, EntityType::Proxy, block);

                if let Some(impl_hex) = signal.normalized_fields.get("implementation")
                    .and_then(|v| v.as_str())
                {
                    if let Some(impl_addr) = parse_address_from_field(impl_hex) {
                        let impl_node = self.ensure_entity(impl_addr, chain_id, EntityType::Implementation, block);
                        self.add_dependency(
                            proxy_node,
                            impl_node,
                            DependencyType::Upgrades,
                            signal.id.clone(),
                            block,
                        );
                    }
                }
            }
            crate::types::selectors::ROLE_GRANTED => {
                let contract_node = self.ensure_entity(contract_addr, chain_id, EntityType::Contract, block);

                if let Some(account_hex) = signal.normalized_fields.get("account")
                    .and_then(|v| v.as_str())
                {
                    if let Some(account_addr) = parse_address_from_field(account_hex) {
                        let account_node = self.ensure_entity(account_addr, chain_id, EntityType::EOA, block);
                        self.add_dependency(
                            contract_node,
                            account_node,
                            DependencyType::Delegates,
                            signal.id.clone(),
                            block,
                        );
                    }
                }
            }
            crate::types::selectors::ROLE_REVOKED => {
                // RoleRevoked removes/weakens the Delegates edge
                if let Some(account_hex) = signal.normalized_fields.get("account")
                    .and_then(|v| v.as_str())
                {
                    if let Some(account_addr) = parse_address_from_field(account_hex) {
                        let contract_key = (chain_id, contract_addr);
                        let account_key = (chain_id, account_addr);
                        if let (Some(&from_idx), Some(&to_idx)) = (
                            self.address_index.get(&contract_key),
                            self.address_index.get(&account_key),
                        ) {
                            self.remove_dependency(from_idx, to_idx, DependencyType::Delegates);
                        }
                    }
                }
            }
            crate::types::selectors::ADMIN_CHANGED => {
                // Parse previousAdmin/newAdmin from data field
                if let Some(new_admin_hex) = signal.normalized_fields.get("newAdmin")
                    .and_then(|v| v.as_str())
                {
                    if let Some(new_admin) = parse_address_from_field(new_admin_hex) {
                        let contract_node = self.ensure_entity(contract_addr, chain_id, EntityType::Proxy, block);
                        let admin_node = self.ensure_entity(new_admin, chain_id, EntityType::EOA, block);
                        self.add_dependency(
                            admin_node,
                            contract_node,
                            DependencyType::Owns,
                            signal.id.clone(),
                            block,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    /// Remove a dependency edge between two nodes of a given type.
    /// Used when RoleRevoked invalidates a Delegates edge.
    pub fn remove_dependency(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        dep_type: DependencyType,
    ) -> bool {
        let edge = self.graph.edges_connecting(from, to)
            .find(|e| e.weight().dep_type == dep_type)
            .map(|e| e.id());

        if let Some(edge_idx) = edge {
            self.graph.remove_edge(edge_idx);
            true
        } else {
            false
        }
    }

    /// Prune edges whose weight has decayed below threshold.
    /// Returns number of edges removed.
    pub fn prune_decayed(&mut self, min_weight: f64) -> usize {
        let mut to_remove = Vec::new();

        for edge in self.graph.edge_indices() {
            if let Some(dep) = self.graph.edge_weight(edge) {
                if dep.weight < min_weight {
                    to_remove.push(edge);
                }
            }
        }

        let count = to_remove.len();
        // Remove in reverse order to avoid index invalidation
        to_remove.sort_unstable();
        for edge in to_remove.into_iter().rev() {
            self.graph.remove_edge(edge);
        }
        count
    }

    /// Find entity pairs with ≥2 evidence signals.
    /// These are hypothesis candidates (concordance threshold met).
    ///
    /// NOTE: Graph-level concordance counts evidence_signal_ids.
    /// Full independence check (source_tx × event_selector) is done
    /// in Hypothesis::count_independent when forming hypotheses.
    pub fn concordant_pairs(&self) -> Vec<ConcordantPair> {
        let mut pairs = Vec::new();

        for edge in self.graph.edge_indices() {
            if let Some(dep) = self.graph.edge_weight(edge) {
                if dep.evidence_signal_ids.len() >= 2 {
                    let Some((from, to)) = self.graph.edge_endpoints(edge) else {
                        continue;
                    };
                    let from_entity = &self.graph[from];
                    let to_entity = &self.graph[to];

                    pairs.push(ConcordantPair {
                        from_address: from_entity.address,
                        to_address: to_entity.address,
                        dep_type: dep.dep_type,
                        evidence_count: dep.evidence_signal_ids.len(),
                        temporal_window: dep.temporal_window,
                        weight: dep.weight,
                    });
                }
            }
        }

        pairs
    }

    /// Get entity by chain_id and address (cross-chain aware).
    pub fn get_entity(&self, chain_id: u64, address: &Address) -> Option<&Entity> {
        self.address_index.get(&(chain_id, *address))
            .and_then(|&idx| self.graph.node_weight(idx))
    }
}

impl Default for TemporalGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// A pair of entities with concordant evidence.
#[derive(Debug, Clone)]
pub struct ConcordantPair {
    pub from_address: Address,
    pub to_address: Address,
    pub dep_type: DependencyType,
    pub evidence_count: usize,
    pub temporal_window: (u64, u64),
    pub weight: f64,
}

fn parse_address_from_field(hex_str: &str) -> Option<Address> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = ::hex::decode(hex_str).ok()?;
    if bytes.len() < 20 {
        return None;
    }
    // Take last 20 bytes (handles 32-byte topics)
    let start = bytes.len() - 20;
    Some(Address::from_slice(&bytes[start..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_signal(id: &str, selector: [u8; 4], block: u64, fields: HashMap<String, serde_json::Value>) -> NormalizedSignal {
        NormalizedSignal {
            id: id.to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: alloy_primitives::B256::ZERO,
            block_number: block,
            timestamp: Utc::now(),
            chain_id: 1,
            entity: Address::from([0x01; 20]),
            event_selector: selector,
            raw_data: vec![],
            normalized_fields: fields,
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        }
    }

    #[test]
    fn test_entity_creation() {
        let mut graph = TemporalGraph::new();
        let addr = Address::from([0x01; 20]);

        let idx = graph.ensure_entity(addr, 1, EntityType::Contract, 100);
        assert_eq!(graph.entity_count(), 1);

        // Same (chain_id, address) → same node, updated
        let idx2 = graph.ensure_entity(addr, 1, EntityType::Contract, 200);
        assert_eq!(idx, idx2);
        assert_eq!(graph.entity_count(), 1);
        assert_eq!(graph.get_entity(1, &addr).unwrap().last_seen_block, 200);

        // Same address on different chain → different node
        let idx3 = graph.ensure_entity(addr, 10, EntityType::Contract, 100);
        assert_ne!(idx, idx3);
        assert_eq!(graph.entity_count(), 2);
    }

    #[test]
    fn test_dependency_strengthening() {
        let mut graph = TemporalGraph::new();
        let a = graph.ensure_entity(Address::from([0x01; 20]), 1, EntityType::EOA, 100);
        let b = graph.ensure_entity(Address::from([0x02; 20]), 1, EntityType::Contract, 100);

        graph.add_dependency(a, b, DependencyType::Owns, "s1".to_string(), 100);
        assert_eq!(graph.edge_count(), 1);

        // Same dep_type → strengthen, not duplicate
        graph.add_dependency(a, b, DependencyType::Owns, "s2".to_string(), 110);
        assert_eq!(graph.edge_count(), 1);

        let pairs = graph.concordant_pairs();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].evidence_count, 2);
    }

    #[test]
    fn test_concordant_pairs_threshold() {
        let mut graph = TemporalGraph::new();
        let a = graph.ensure_entity(Address::from([0x01; 20]), 1, EntityType::EOA, 100);
        let b = graph.ensure_entity(Address::from([0x02; 20]), 1, EntityType::Contract, 100);

        // Single evidence → not concordant
        graph.add_dependency(a, b, DependencyType::Owns, "s1".to_string(), 100);
        assert_eq!(graph.concordant_pairs().len(), 0);

        // Two evidence → concordant
        graph.add_dependency(a, b, DependencyType::Owns, "s2".to_string(), 110);
        assert_eq!(graph.concordant_pairs().len(), 1);
    }

    #[test]
    fn test_ingest_ownership_transferred() {
        let mut graph = TemporalGraph::new();
        let mut fields = HashMap::new();
        fields.insert("event".to_string(), serde_json::json!("OwnershipTransferred"));
        fields.insert("newOwner".to_string(), serde_json::json!("0x0000000000000000000000000000000000000002"));

        let signal = make_signal("s1", selectors::OWNERSHIP_TRANSFERRED, 100, fields);
        graph.ingest_control_plane_signal(&signal);

        assert_eq!(graph.entity_count(), 2); // contract + new owner
        assert_eq!(graph.edge_count(), 1);   // Owns edge
    }

    #[test]
    fn test_prune_decayed() {
        let mut graph = TemporalGraph::new();
        let a = graph.ensure_entity(Address::from([0x01; 20]), 1, EntityType::EOA, 100);
        let b = graph.ensure_entity(Address::from([0x02; 20]), 1, EntityType::Contract, 100);

        graph.add_dependency(a, b, DependencyType::Owns, "s1".to_string(), 100);
        // Single evidence = weight 0.33

        let removed = graph.prune_decayed(0.5);
        assert_eq!(removed, 1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_role_revoked_removes_edge() {
        // RoleRevoked should remove the Delegates edge
        let mut graph = TemporalGraph::new();

        // First: RoleGranted creates a Delegates edge
        let mut grant_fields = HashMap::new();
        grant_fields.insert("event".to_string(), serde_json::json!("RoleGranted"));
        grant_fields.insert("role".to_string(), serde_json::json!("0x00"));
        grant_fields.insert("account".to_string(), serde_json::json!("0x0000000000000000000000000000000000000002"));
        let grant = make_signal("s1", selectors::ROLE_GRANTED, 100, grant_fields);
        graph.ingest_control_plane_signal(&grant);

        assert_eq!(graph.entity_count(), 2);
        assert_eq!(graph.edge_count(), 1); // Delegates edge exists

        // Then: RoleRevoked removes it
        let mut revoke_fields = HashMap::new();
        revoke_fields.insert("event".to_string(), serde_json::json!("RoleRevoked"));
        revoke_fields.insert("role".to_string(), serde_json::json!("0x00"));
        revoke_fields.insert("account".to_string(), serde_json::json!("0x0000000000000000000000000000000000000002"));
        let revoke = make_signal("s2", selectors::ROLE_REVOKED, 200, revoke_fields);
        graph.ingest_control_plane_signal(&revoke);

        assert_eq!(graph.edge_count(), 0); // Delegates edge removed
    }

    #[test]
    fn test_admin_changed_creates_owns_edge() {
        // AdminChanged should create an Owns edge
        let mut graph = TemporalGraph::new();
        let mut fields = HashMap::new();
        fields.insert("event".to_string(), serde_json::json!("AdminChanged"));
        fields.insert("newAdmin".to_string(), serde_json::json!("0x0000000000000000000000000000000000000003"));

        let signal = make_signal("s1", selectors::ADMIN_CHANGED, 100, fields);
        graph.ingest_control_plane_signal(&signal);

        assert_eq!(graph.entity_count(), 2); // proxy + new admin
        assert_eq!(graph.edge_count(), 1);   // Owns edge
    }

    #[test]
    fn test_cross_chain_entity_separation() {
        // Same address on different chains should be separate entities
        let mut graph = TemporalGraph::new();
        let addr = Address::from([0x01; 20]);

        let _idx_eth = graph.ensure_entity(addr, 1, EntityType::Contract, 100);
        let _idx_arb = graph.ensure_entity(addr, 42161, EntityType::Contract, 100);

        assert_eq!(graph.entity_count(), 2);
        assert_eq!(graph.get_entity(1, &addr).unwrap().chain_id, 1);
        assert_eq!(graph.get_entity(42161, &addr).unwrap().chain_id, 42161);
    }
}
