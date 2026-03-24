//! STI-OS Core Types
//!
//! NormalizedSignal, Hypothesis, ReplayResult — the 3 core data structures
//! flowing through L1→L2→L3→L4 pipeline.

use alloy_primitives::{Address, B256, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Layer 1: Signal Types
// ============================================================================

/// 6 signal types — behavioral signals, not content.
/// Priority: content < cadence, prices < transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalType {
    /// Owner/admin permission changes: proxy admin, multisig signer, threshold, upgrade impl
    ControlPlane,
    /// Changes in regular operation patterns: nonce burst, maintenance rhythm, deploy cadence
    OperationalCadence,
    /// Irreversible contract state changes: pool migration, vault rotation, param update
    StateTransition,
    /// Synchronized multi-address behavior: same gas source, timing cluster, co-occurrence
    Coordination,
    /// Stress indicators: gas spike, revert rate, pool imbalance, oracle deviation
    Stress,
    /// Pre-production rehearsal: small-amount test tx, fork deploy, dust capability probe
    ExperimentRehearsal,
}

impl SignalType {
    /// Decay half-life in seconds per signal type.
    /// Stress decays fast (3d), control-plane persists (30d).
    pub fn half_life_secs(&self) -> u64 {
        match self {
            Self::ControlPlane => 30 * 86400,       // 30 days
            Self::OperationalCadence => 14 * 86400,  // 14 days
            Self::StateTransition => 7 * 86400,      // 7 days
            Self::Coordination => 7 * 86400,         // 7 days
            Self::Stress => 3 * 86400,               // 3 days
            Self::ExperimentRehearsal => 14 * 86400,  // 14 days
        }
    }
}

/// Forgery cost — how expensive it is to fake this signal.
/// LOW = cheap to create (dust tx). HIGH = requires admin key / governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForgeryLevel {
    Low,
    Medium,
    High,
}

impl ForgeryLevel {
    /// Weight for confidence calculation.
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.3,
            Self::Medium => 0.6,
            Self::High => 0.9,
        }
    }
}

/// Data quality flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataQuality {
    Clean,
    Degraded,
    Partial,
}

/// Normalized signal — L1 output, L2 input.
/// Extends a normalized on-chain event with signal_type, forgery_cost, decay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedSignal {
    pub id: String,
    pub signal_type: SignalType,
    pub source_tx: B256,
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
    pub chain_id: u64,
    pub entity: Address,
    pub event_selector: [u8; 4],
    pub raw_data: Vec<u8>,
    pub normalized_fields: HashMap<String, serde_json::Value>,
    pub forgery_cost: ForgeryLevel,
    pub quality: DataQuality,
}

impl NormalizedSignal {
    /// Decay weight at a given time.
    /// weight(t) = 0.5^(age_secs / half_life)
    pub fn weight_at(&self, now: DateTime<Utc>) -> f64 {
        let age_secs = (now - self.timestamp).num_seconds().max(0) as f64;
        let half_life = self.signal_type.half_life_secs() as f64;
        0.5_f64.powf(age_secs / half_life)
    }
}

// ============================================================================
// Layer 2: Hypothesis
// ============================================================================

/// Classification level based on confidence score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    /// confidence >= 0.7, requires REVM replay confirmation
    Confirmed,
    /// confidence >= 0.5
    Probable,
    /// confidence >= 0.3
    Possible,
    /// confidence < 0.3, not publishable
    Speculative,
}

impl Classification {
    pub fn from_confidence(c: f64) -> Self {
        if c >= 0.7 {
            Self::Confirmed
        } else if c >= 0.5 {
            Self::Probable
        } else if c >= 0.3 {
            Self::Possible
        } else {
            Self::Speculative
        }
    }
}

/// A reference to a supporting signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRef {
    pub signal_id: String,
    pub signal_type: SignalType,
    pub source_tx: B256,
    pub block_number: u64,
    pub relevance: String,
}

/// Replay specification — what to simulate to verify/falsify a hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySpec {
    pub target_contract: Address,
    pub function_selector: [u8; 4],
    pub calldata: Vec<u8>,
    pub msg_value: U256,
    pub state_overrides: Vec<SlotOverride>,
    pub expected_success: bool,
    pub expected_return_match: Option<Vec<u8>>,
}

/// A single storage slot override with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotOverride {
    pub address: Address,
    pub slot: U256,
    pub value: U256,
    pub justification: String,
}

/// Hypothesis — L2 output, L3 input.
/// Formed from ≥2 independent signals. Each hypothesis is falsifiable via replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub claim: String,
    pub evidence: Vec<SignalRef>,
    pub temporal_window: (u64, u64), // (start_block, end_block)
    pub replay_spec: ReplaySpec,
    pub kill_criteria: Vec<String>,
    pub confidence: f64,
    pub classification: Classification,
    pub created_at: DateTime<Utc>,
}

impl Hypothesis {
    /// Count effective independent signals with entity diversity discount.
    ///
    /// Independent = unique (source_tx, event_selector) pair.
    /// Entity discount: if N independent signals come from the same entity,
    /// they contribute sqrt(N) instead of N (Sybil resistance).
    ///
    /// Examples:
    /// - 3 signals from 3 entities → 3.0 (full credit)
    /// - 3 signals from 1 entity → sqrt(3) ≈ 1.73 (discounted)
    /// - 4 signals from 2 entities (2 each) → 2*sqrt(2) ≈ 2.83
    pub fn count_independent(signals: &[&NormalizedSignal]) -> f64 {
        use std::collections::{HashSet, HashMap};
        let mut seen = HashSet::new();
        let mut entity_counts: HashMap<Address, usize> = HashMap::new();

        for s in signals {
            if seen.insert((s.source_tx, s.event_selector)) {
                *entity_counts.entry(s.entity).or_insert(0) += 1;
            }
        }

        // Entity diversity discount: sqrt(N) for N signals from same entity
        entity_counts.values()
            .map(|&n| (n as f64).sqrt())
            .sum()
    }

    /// Calculate confidence from evidence signals.
    ///
    /// confidence = cost × irreversibility × concordance × persistence
    ///
    /// Each factor is in [0.0, 1.0]:
    /// - cost: avg forgery weight (Low=0.3, Med=0.6, High=0.9)
    /// - irreversibility: manually assessed (0.0=reversible, 1.0=permanent)
    /// - concordance: min(1.0, independent_signal_count / 3)
    ///   NOTE: counts INDEPENDENT signals (unique source_tx × event_selector)
    /// - persistence: avg decay weight at evaluation time
    ///
    /// Mathematical properties:
    /// - Range: [0.0, 0.9] (cost caps at 0.9 for HIGH forgery)
    /// - 2 diverse HIGH signals, fresh, irreversible: 0.9 × 1.0 × 0.67 × 1.0 = 0.6 (PROBABLE)
    /// - 3 diverse HIGH signals, fresh, irreversible: 0.9 × 1.0 × 1.0 × 1.0 = 0.9 (CONFIRMED)
    /// - 3 same-entity HIGH signals: 0.9 × 1.0 × (√3/3) × 1.0 ≈ 0.52 (PROBABLE, not CONFIRMED)
    /// - CONFIRMED (≥0.7) requires ≥3 independent signals from diverse entities
    pub fn calculate_confidence(
        signals: &[&NormalizedSignal],
        irreversibility: f64,
        now: DateTime<Utc>,
    ) -> f64 {
        if signals.is_empty() {
            return 0.0;
        }

        let irreversibility = irreversibility.clamp(0.0, 1.0);

        // cost: average forgery weight of ALL signals (duplicates included for weighting)
        let cost = signals.iter()
            .map(|s| s.forgery_cost.weight())
            .sum::<f64>() / signals.len() as f64;

        // concordance: based on INDEPENDENT signal count, not total count
        let independent_count = Self::count_independent(signals);
        let concordance = (independent_count / 3.0).min(1.0);

        // persistence: average decay weight at evaluation time
        let persistence = signals.iter()
            .map(|s| s.weight_at(now))
            .sum::<f64>() / signals.len() as f64;

        cost * irreversibility * concordance * persistence
    }
}

// ============================================================================
// Layer 3: Replay Result
// ============================================================================

/// Verdict from REVM replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Confirmed,
    Refuted,
    Inconclusive,
}

/// A storage diff entry from replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDiff {
    pub address: Address,
    pub slot: U256,
    pub before: U256,
    pub after: U256,
}

/// An emitted log from replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmittedLog {
    pub address: Address,
    pub topic0: B256,
    pub data: Vec<u8>,
}

/// Replay result — L3 output, L4 input.
/// Contains the proof (or disproof) of a capability hypothesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub hypothesis_id: String,
    pub block_context: u64,
    pub valid_until: u64,
    pub chain_id: u64,
    pub overrides_applied: Vec<SlotOverride>,
    pub success: bool,
    pub return_data: Vec<u8>,
    pub revert_reason: Option<String>,
    pub gas_used: u64,
    pub gas_anomaly: bool,
    pub state_changes: Vec<StorageDiff>,
    pub logs: Vec<EmittedLog>,
    pub verdict: Verdict,
    pub verdict_evidence: String,
    pub capability_proven: Option<String>,
    pub executed_at: DateTime<Utc>,
}

impl ReplayResult {
    /// Check if this result has expired (block_context + 100 blocks).
    pub fn is_expired(&self, current_block: u64) -> bool {
        current_block > self.valid_until
    }
}

// ============================================================================
// Well-known Event Selectors
// ============================================================================

/// Well-known event selectors for control-plane signals.
pub mod selectors {
    /// OwnershipTransferred(address,address)
    pub const OWNERSHIP_TRANSFERRED: [u8; 4] = [0x8b, 0xe0, 0x07, 0x9c];
    /// Upgraded(address)
    pub const UPGRADED: [u8; 4] = [0xbc, 0x7c, 0xd7, 0x5a];
    /// RoleGranted(bytes32,address,address)
    pub const ROLE_GRANTED: [u8; 4] = [0x2f, 0x87, 0x88, 0x11];
    /// RoleRevoked(bytes32,address,address)
    pub const ROLE_REVOKED: [u8; 4] = [0xf6, 0x39, 0x1f, 0x5c];
    /// AdminChanged(address,address)
    pub const ADMIN_CHANGED: [u8; 4] = [0x7e, 0x64, 0x4d, 0x79];
    /// Paused(address) — OpenZeppelin Pausable
    pub const PAUSED: [u8; 4] = [0x62, 0xe7, 0x8c, 0xea];
    /// Unpaused(address) — OpenZeppelin Pausable
    pub const UNPAUSED: [u8; 4] = [0x5d, 0xb9, 0xee, 0x0a];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_type_half_life() {
        assert_eq!(SignalType::ControlPlane.half_life_secs(), 30 * 86400);
        assert_eq!(SignalType::Stress.half_life_secs(), 3 * 86400);
    }

    #[test]
    fn test_forgery_weight() {
        assert!((ForgeryLevel::Low.weight() - 0.3).abs() < f64::EPSILON);
        assert!((ForgeryLevel::High.weight() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_classification_from_confidence() {
        assert_eq!(Classification::from_confidence(0.8), Classification::Confirmed);
        assert_eq!(Classification::from_confidence(0.6), Classification::Probable);
        assert_eq!(Classification::from_confidence(0.4), Classification::Possible);
        assert_eq!(Classification::from_confidence(0.2), Classification::Speculative);
    }

    #[test]
    fn test_signal_decay_weight() {
        let signal = NormalizedSignal {
            id: "test".to_string(),
            signal_type: SignalType::Stress,
            source_tx: B256::ZERO,
            block_number: 100,
            timestamp: Utc::now() - chrono::Duration::days(3),
            chain_id: 1,
            entity: Address::ZERO,
            event_selector: [0; 4],
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::Low,
            quality: DataQuality::Clean,
        };

        let weight = signal.weight_at(Utc::now());
        // Stress half-life = 3 days, age = 3 days → weight ≈ 0.5
        assert!((weight - 0.5).abs() < 0.05, "weight={}", weight);
    }

    #[test]
    fn test_confidence_2_independent_high_signals_diverse_entities() {
        let now = Utc::now();
        // Two signals from DIFFERENT entities → full concordance credit
        let s1 = NormalizedSignal {
            id: "s1".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO,
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::from([0x01; 20]), // Entity A
            event_selector: selectors::OWNERSHIP_TRANSFERRED,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };
        let s2 = NormalizedSignal {
            id: "s2".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::from([1u8; 32]),
            block_number: 101,
            timestamp: now,
            chain_id: 1,
            entity: Address::from([0x02; 20]), // Entity B (different!)
            event_selector: selectors::UPGRADED,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        let signals: Vec<&NormalizedSignal> = vec![&s1, &s2];
        let conf = Hypothesis::calculate_confidence(&signals, 1.0, now);

        // Diverse entities: count = sqrt(1)+sqrt(1) = 2.0
        // cost=0.9, irreversibility=1.0, concordance=2/3≈0.667, persistence=1.0
        let expected = 0.9 * 1.0 * (2.0 / 3.0) * 1.0;
        assert!((conf - expected).abs() < 1e-10, "conf={} expected={}", conf, expected);
        assert_eq!(Classification::from_confidence(conf), Classification::Probable);
    }

    #[test]
    fn test_confidence_2_signals_same_entity_discounted() {
        // Same entity gets sqrt discount (Sybil resistance)
        let now = Utc::now();
        let s1 = NormalizedSignal {
            id: "s1".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO,
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO, // Same entity
            event_selector: selectors::OWNERSHIP_TRANSFERRED,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };
        let s2 = NormalizedSignal {
            id: "s2".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::from([1u8; 32]),
            block_number: 101,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO, // Same entity!
            event_selector: selectors::UPGRADED,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        let signals: Vec<&NormalizedSignal> = vec![&s1, &s2];
        let conf = Hypothesis::calculate_confidence(&signals, 1.0, now);

        // Same entity: count = sqrt(2) ≈ 1.414
        // concordance = sqrt(2)/3 ≈ 0.471
        // conf = 0.9 * 0.471 ≈ 0.424 → Possible (NOT Probable)
        let expected = 0.9 * 1.0 * (2.0_f64.sqrt() / 3.0) * 1.0;
        assert!((conf - expected).abs() < 1e-10, "conf={} expected={}", conf, expected);
        assert_eq!(Classification::from_confidence(conf), Classification::Possible);
    }

    #[test]
    fn test_confidence_3_independent_diverse_reaches_confirmed() {
        let now = Utc::now();
        // 3 signals from 3 DIFFERENT entities → full concordance
        let make = |id: &str, tx: [u8; 32], sel: [u8; 4], entity_byte: u8| NormalizedSignal {
            id: id.to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::from(tx),
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::from([entity_byte; 20]),
            event_selector: sel,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        let s1 = make("s1", [0u8; 32], selectors::OWNERSHIP_TRANSFERRED, 0x01);
        let s2 = make("s2", [1u8; 32], selectors::UPGRADED, 0x02);
        let s3 = make("s3", [2u8; 32], selectors::ROLE_GRANTED, 0x03);

        let signals: Vec<&NormalizedSignal> = vec![&s1, &s2, &s3];
        let conf = Hypothesis::calculate_confidence(&signals, 1.0, now);

        // 3 diverse entities: count = 3.0, concordance = 1.0
        // cost=0.9, irreversibility=1.0, persistence=1.0
        // expected = 0.9
        let expected = 0.9;
        assert!((conf - expected).abs() < 1e-10, "conf={}", conf);
        assert_eq!(Classification::from_confidence(conf), Classification::Confirmed);
    }

    #[test]
    fn test_confidence_3_same_entity_not_confirmed() {
        // Sybil resistance: 3 signals from 1 entity should NOT reach Confirmed
        let now = Utc::now();
        let make = |id: &str, tx: [u8; 32], sel: [u8; 4]| NormalizedSignal {
            id: id.to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::from(tx),
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO, // ALL same entity
            event_selector: sel,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        let s1 = make("s1", [0u8; 32], selectors::OWNERSHIP_TRANSFERRED);
        let s2 = make("s2", [1u8; 32], selectors::UPGRADED);
        let s3 = make("s3", [2u8; 32], selectors::ROLE_GRANTED);

        let signals: Vec<&NormalizedSignal> = vec![&s1, &s2, &s3];
        let conf = Hypothesis::calculate_confidence(&signals, 1.0, now);

        // Same entity: count = sqrt(3) ≈ 1.732
        // concordance = sqrt(3)/3 ≈ 0.577
        // conf = 0.9 * 0.577 ≈ 0.520 → Probable, NOT Confirmed
        let expected = 0.9 * (3.0_f64.sqrt() / 3.0);
        assert!((conf - expected).abs() < 1e-10, "conf={}", conf);
        assert_eq!(Classification::from_confidence(conf), Classification::Probable);
    }

    #[test]
    fn test_concordance_rejects_duplicate_tx() {
        // Same source_tx + same event_selector = NOT independent
        let now = Utc::now();
        let s1 = NormalizedSignal {
            id: "s1".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO, // SAME tx
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO,
            event_selector: selectors::OWNERSHIP_TRANSFERRED, // SAME event
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };
        let s2 = NormalizedSignal {
            id: "s2".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO, // SAME tx
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO,
            event_selector: selectors::OWNERSHIP_TRANSFERRED, // SAME event
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        // 2 signals but only 1 independent (same tx+selector+entity)
        let count = Hypothesis::count_independent(&[&s1, &s2]);
        assert!((count - 1.0).abs() < 1e-10, "count={}", count);

        let conf = Hypothesis::calculate_confidence(&[&s1, &s2], 1.0, now);
        // concordance = 1/3 = 0.333, NOT 2/3
        // conf = 0.9 × 1.0 × 0.333 × 1.0 = 0.3 (exactly at Possible boundary)
        let expected = 0.9 * 1.0 * (1.0 / 3.0) * 1.0;
        assert!((conf - expected).abs() < 1e-10, "conf={} expected={}", conf, expected);
        assert_eq!(Classification::from_confidence(conf), Classification::Possible);
    }

    #[test]
    fn test_same_tx_different_event_is_independent() {
        // Same tx emitting different events = independent (tx triggered multiple changes)
        let now = Utc::now();
        let s1 = NormalizedSignal {
            id: "s1".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO,
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO,
            event_selector: selectors::OWNERSHIP_TRANSFERRED,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };
        let s2 = NormalizedSignal {
            id: "s2".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO, // same tx
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO,
            event_selector: selectors::UPGRADED, // different event
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        // Same tx, different events, same entity → 2 independent but sqrt(2) effective
        let count = Hypothesis::count_independent(&[&s1, &s2]);
        assert!((count - 2.0_f64.sqrt()).abs() < 1e-10, "count={}", count);
    }

    #[test]
    fn test_confidence_empty_signals() {
        let now = Utc::now();
        let conf = Hypothesis::calculate_confidence(&[], 1.0, now);
        assert_eq!(conf, 0.0);
    }

    #[test]
    fn test_confidence_irreversibility_clamped() {
        let now = Utc::now();
        let s = NormalizedSignal {
            id: "s1".to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx: B256::ZERO,
            block_number: 100,
            timestamp: now,
            chain_id: 1,
            entity: Address::ZERO,
            event_selector: selectors::OWNERSHIP_TRANSFERRED,
            raw_data: vec![],
            normalized_fields: HashMap::new(),
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        };

        // irreversibility > 1.0 should be clamped to 1.0
        let conf_over = Hypothesis::calculate_confidence(&[&s], 1.5, now);
        let conf_one = Hypothesis::calculate_confidence(&[&s], 1.0, now);
        assert!((conf_over - conf_one).abs() < 1e-10);

        // irreversibility < 0.0 should be clamped to 0.0
        let conf_neg = Hypothesis::calculate_confidence(&[&s], -0.5, now);
        assert_eq!(conf_neg, 0.0);
    }

    #[test]
    fn test_confidence_range_always_0_to_1() {
        // Property: for any valid inputs, 0.0 ≤ confidence ≤ 1.0
        let now = Utc::now();
        let forgery_levels = [ForgeryLevel::Low, ForgeryLevel::Medium, ForgeryLevel::High];
        let signal_types = [
            SignalType::ControlPlane,
            SignalType::Stress,
            SignalType::ExperimentRehearsal,
        ];

        for &ft in &forgery_levels {
            for &st in &signal_types {
                for age_days in [0, 1, 7, 30, 365] {
                    let s = NormalizedSignal {
                        id: "test".to_string(),
                        signal_type: st,
                        source_tx: B256::ZERO,
                        block_number: 100,
                        timestamp: now - chrono::Duration::days(age_days),
                        chain_id: 1,
                        entity: Address::ZERO,
                        event_selector: [0; 4],
                        raw_data: vec![],
                        normalized_fields: HashMap::new(),
                        forgery_cost: ft,
                        quality: DataQuality::Clean,
                    };

                    for irrev in [0.0, 0.5, 1.0] {
                        let conf = Hypothesis::calculate_confidence(&[&s], irrev, now);
                        assert!(
                            conf >= 0.0 && conf <= 1.0,
                            "conf={} out of range for ft={:?} st={:?} age={}d irrev={}",
                            conf, ft, st, age_days, irrev
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_decay_monotonically_decreasing() {
        // Property: weight_at(t1) >= weight_at(t2) for t1 < t2
        let now = Utc::now();
        for st in [SignalType::Stress, SignalType::ControlPlane] {
            let s = NormalizedSignal {
                id: "test".to_string(),
                signal_type: st,
                source_tx: B256::ZERO,
                block_number: 100,
                timestamp: now - chrono::Duration::days(1),
                chain_id: 1,
                entity: Address::ZERO,
                event_selector: [0; 4],
                raw_data: vec![],
                normalized_fields: HashMap::new(),
                forgery_cost: ForgeryLevel::High,
                quality: DataQuality::Clean,
            };

            let w1 = s.weight_at(now);
            let w2 = s.weight_at(now + chrono::Duration::days(1));
            let w3 = s.weight_at(now + chrono::Duration::days(7));
            let w4 = s.weight_at(now + chrono::Duration::days(30));

            assert!(w1 >= w2, "w1={} < w2={}", w1, w2);
            assert!(w2 >= w3, "w2={} < w3={}", w2, w3);
            assert!(w3 >= w4, "w3={} < w4={}", w3, w4);
        }
    }

    #[test]
    fn test_decay_exact_half_life_values() {
        // At exactly 1 half-life: weight = 0.5
        // At exactly 2 half-lives: weight = 0.25
        // At exactly 0 half-lives: weight = 1.0
        for st in [
            SignalType::ControlPlane,
            SignalType::Stress,
            SignalType::OperationalCadence,
        ] {
            let hl_secs = st.half_life_secs();
            let now = Utc::now();

            let s = NormalizedSignal {
                id: "test".to_string(),
                signal_type: st,
                source_tx: B256::ZERO,
                block_number: 100,
                timestamp: now,
                chain_id: 1,
                entity: Address::ZERO,
                event_selector: [0; 4],
                raw_data: vec![],
                normalized_fields: HashMap::new(),
                forgery_cost: ForgeryLevel::High,
                quality: DataQuality::Clean,
            };

            // At creation: weight = 1.0
            let w0 = s.weight_at(now);
            assert!((w0 - 1.0).abs() < 1e-10, "st={:?} w0={}", st, w0);

            // At 1 half-life: weight = 0.5
            let w1 = s.weight_at(now + chrono::Duration::seconds(hl_secs as i64));
            assert!((w1 - 0.5).abs() < 1e-10, "st={:?} w1={}", st, w1);

            // At 2 half-lives: weight = 0.25
            let w2 = s.weight_at(now + chrono::Duration::seconds(2 * hl_secs as i64));
            assert!((w2 - 0.25).abs() < 1e-10, "st={:?} w2={}", st, w2);
        }
    }

    #[test]
    fn test_confidence_monotonic_in_each_factor() {
        let now = Utc::now();

        let make_signal = |forgery: ForgeryLevel, age_days: i64, tx: [u8; 32], sel: [u8; 4]| {
            NormalizedSignal {
                id: uuid::Uuid::new_v4().to_string(),
                signal_type: SignalType::ControlPlane,
                source_tx: B256::from(tx),
                block_number: 100,
                timestamp: now - chrono::Duration::days(age_days),
                chain_id: 1,
                entity: Address::ZERO,
                event_selector: sel,
                raw_data: vec![],
                normalized_fields: HashMap::new(),
                forgery_cost: forgery,
                quality: DataQuality::Clean,
            }
        };

        // Monotonic in forgery cost: Low < Medium < High
        let s_low = make_signal(ForgeryLevel::Low, 0, [0; 32], [0; 4]);
        let s_med = make_signal(ForgeryLevel::Medium, 0, [0; 32], [0; 4]);
        let s_high = make_signal(ForgeryLevel::High, 0, [0; 32], [0; 4]);

        let c_low = Hypothesis::calculate_confidence(&[&s_low], 1.0, now);
        let c_med = Hypothesis::calculate_confidence(&[&s_med], 1.0, now);
        let c_high = Hypothesis::calculate_confidence(&[&s_high], 1.0, now);
        assert!(c_low < c_med, "Low({}) >= Med({})", c_low, c_med);
        assert!(c_med < c_high, "Med({}) >= High({})", c_med, c_high);

        // Monotonic in irreversibility
        let s = make_signal(ForgeryLevel::High, 0, [0; 32], [0; 4]);
        let c_rev = Hypothesis::calculate_confidence(&[&s], 0.3, now);
        let c_irr = Hypothesis::calculate_confidence(&[&s], 0.9, now);
        assert!(c_rev < c_irr, "rev({}) >= irr({})", c_rev, c_irr);

        // Monotonic in concordance (more independent signals from diverse entities → higher)
        let make_diverse = |forgery: ForgeryLevel, age_days: i64, tx: [u8; 32], sel: [u8; 4], entity_byte: u8| {
            NormalizedSignal {
                id: uuid::Uuid::new_v4().to_string(),
                signal_type: SignalType::ControlPlane,
                source_tx: B256::from(tx),
                block_number: 100,
                timestamp: now - chrono::Duration::days(age_days),
                chain_id: 1,
                entity: Address::from([entity_byte; 20]),
                event_selector: sel,
                raw_data: vec![],
                normalized_fields: HashMap::new(),
                forgery_cost: forgery,
                quality: DataQuality::Clean,
            }
        };
        let s1 = make_diverse(ForgeryLevel::High, 0, [0; 32], selectors::OWNERSHIP_TRANSFERRED, 0x01);
        let s2 = make_diverse(ForgeryLevel::High, 0, [1; 32], selectors::UPGRADED, 0x02);
        let s3 = make_diverse(ForgeryLevel::High, 0, [2; 32], selectors::ROLE_GRANTED, 0x03);

        let c_1 = Hypothesis::calculate_confidence(&[&s1], 1.0, now);
        let c_2 = Hypothesis::calculate_confidence(&[&s1, &s2], 1.0, now);
        let c_3 = Hypothesis::calculate_confidence(&[&s1, &s2, &s3], 1.0, now);
        assert!(c_1 < c_2, "1sig({}) >= 2sig({})", c_1, c_2);
        assert!(c_2 < c_3, "2sig({}) >= 3sig({})", c_2, c_3);

        // Monotonic in persistence (fresher signals → higher)
        let s_fresh = make_signal(ForgeryLevel::High, 0, [0; 32], [0; 4]);
        let s_old = make_signal(ForgeryLevel::High, 15, [0; 32], [0; 4]);
        let c_fresh = Hypothesis::calculate_confidence(&[&s_fresh], 1.0, now);
        let c_old = Hypothesis::calculate_confidence(&[&s_old], 1.0, now);
        assert!(c_old < c_fresh, "old({}) >= fresh({})", c_old, c_fresh);
    }

    #[test]
    fn test_classification_boundary_values() {
        // Exact boundaries
        assert_eq!(Classification::from_confidence(0.7), Classification::Confirmed);
        assert_eq!(Classification::from_confidence(0.5), Classification::Probable);
        assert_eq!(Classification::from_confidence(0.3), Classification::Possible);

        // Just below boundaries
        assert_eq!(Classification::from_confidence(0.6999), Classification::Probable);
        assert_eq!(Classification::from_confidence(0.4999), Classification::Possible);
        assert_eq!(Classification::from_confidence(0.2999), Classification::Speculative);

        // Edge cases
        assert_eq!(Classification::from_confidence(0.0), Classification::Speculative);
        assert_eq!(Classification::from_confidence(1.0), Classification::Confirmed);
        assert_eq!(Classification::from_confidence(f64::NAN.max(0.0)), Classification::Speculative);
    }

    #[test]
    fn test_replay_result_expiry() {
        let result = ReplayResult {
            hypothesis_id: "H-1".to_string(),
            block_context: 1000,
            valid_until: 1100,
            chain_id: 1,
            overrides_applied: vec![],
            success: true,
            return_data: vec![],
            revert_reason: None,
            gas_used: 21000,
            gas_anomaly: false,
            state_changes: vec![],
            logs: vec![],
            verdict: Verdict::Confirmed,
            verdict_evidence: "simulation succeeded".to_string(),
            capability_proven: Some("Entity can upgrade".to_string()),
            executed_at: Utc::now(),
        };

        assert!(!result.is_expired(1050));
        assert!(result.is_expired(1101));
    }
}
