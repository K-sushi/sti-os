//! STI-OS: State-Transition Intelligence OS
//!
//! Onchain Indications & Warnings Engine.
//!
//! Not a dashboard. Not a price predictor. Not an analytics tool.
//! An intelligence system that proves what CAPABILITIES became available
//! through on-chain state transitions.
//!
//! # Architecture (4 Layers)
//!
//! ```text
//! L1  Hard-Trigger Collection     → NormalizedSignal
//! L2  Temporal Dependency Graph   → Hypothesis
//! L3  Capability Replay (REVM)    → ReplayResult
//! L4  Defensive Action Queue      → Intelligence Product
//! ```
//!
//! # Priority Stack
//!
//! - Capability > Immediacy > Incentive
//! - Content < Cadence
//! - Prices < Transitions
//! - Charts < Hypotheses
//! - Anomaly < Campaign
//!
//! # 6 Signal Types
//!
//! 1. control-plane (30d decay, HIGH forgery cost)
//! 2. operational-cadence (14d decay, MEDIUM forgery cost)
//! 3. state-transition (7d decay, HIGH forgery cost)
//! 4. coordination (7d decay, MEDIUM forgery cost)
//! 5. stress (3d decay, LOW forgery cost)
//! 6. experiment-rehearsal (14d decay, LOW forgery cost)
//!
//! # Confidence Formula
//!
//! `confidence = cost × irreversibility × concordance × persistence`

pub mod types;
pub mod collector;
pub mod collectors;
pub mod graph;
pub mod replay;

// Re-exports for convenience
pub use collector::SignalCollector;
pub use collectors::control_plane::{ControlPlaneCollector, ControlPlaneConfig};
pub use graph::TemporalGraph;
pub use replay::{CapabilityReplayer, RpcCapabilityReplayer};
pub use types::{
    Classification, DataQuality, ForgeryLevel, Hypothesis, NormalizedSignal,
    ReplayResult, ReplaySpec, SignalRef, SignalType, SlotOverride, Verdict,
};
