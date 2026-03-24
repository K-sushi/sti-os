# STI-OS: State-Transition Intelligence OS

**Prove what became possible, not predict what will happen.**

A Rust framework for on-chain intelligence that detects, correlates, and verifies state transitions across EVM chains. STI-OS treats blockchain events not as price signals but as **capability transitions** — proving that an entity gained a new ability (upgraded a proxy, received admin role, funded a new wallet) rather than forecasting what will happen next.

## Core Concept

Traditional on-chain monitoring asks "what happened?" STI-OS asks **"what became possible?"**

When an admin key transfers ownership, that's not just an event — it's a state transition that enables a new set of actions. STI-OS captures these transitions, correlates them across entities and time, and verifies whether the resulting capabilities were actually exercised.

## Confidence Formula

Every hypothesis in STI-OS carries a confidence score:

```
confidence = cost * irreversibility * concordance * persistence
```

| Factor | Meaning | Range |
|--------|---------|-------|
| **cost** | How expensive it is to forge this signal (in ETH) | 0.0 - 1.0 |
| **irreversibility** | Can this action be undone? | 0.0 - 1.0 |
| **concordance** | How many independent signals agree? (min 2) | 0.0 - 1.0 |
| **persistence** | Has the signal survived decay? | 0.0 - 1.0 |

## Signal Types

STI-OS classifies on-chain events into 6 signal types, each with different decay rates and forgery costs:

| Type | Description | Decay Half-Life | Forgery Cost |
|------|-------------|-----------------|--------------|
| `ControlPlane` | Owner/admin permission changes | 30 days | HIGH |
| `OperationalCadence` | Changes in regular operation patterns | 14 days | MEDIUM |
| `StateTransition` | Irreversible contract state changes | 7 days | HIGH |
| `Coordination` | Synchronized multi-address behavior | 7 days | MEDIUM |
| `Stress` | Gas spikes, revert increases, pool imbalances | 3 days | LOW |
| `ExperimentRehearsal` | Small-amount test txs, fork deploys | 14 days | LOW |

## Architecture

```
L1: SignalCollector    — collect and normalize on-chain events
L2: DependencyGraph    — build temporal entity-relationship graph (petgraph)
L3: CapabilityReplayer — verify hypotheses via REVM state replay
L4: ProductWriter      — generate intelligence products (IIR, SITREP, Assessment)
```

## Quick Start

```rust
use sti_os::graph::{TemporalGraph, EntityType};
use sti_os::collectors::control_plane::{ControlPlaneCollector, ControlPlaneConfig};
use sti_os::collector::SignalCollector;

// Create a control-plane signal collector
let config = ControlPlaneConfig {
    rpc_url: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY".into(),
    chain_id: 1,
    watch_addresses: vec![],  // empty = watch all
    rpc_timeout_secs: 10,
};
let collector = ControlPlaneCollector::new(config);

// Collect signals from a block range
let signals = collector.collect_range(from_block, to_block).await?;

// Build a temporal dependency graph
let mut graph = TemporalGraph::new();
for signal in &signals {
    graph.ingest_control_plane_signal(signal);
}

// Check for entities with concordant signals (2+ independent sources)
let pairs = graph.concordant_pairs();
```

## Hypothesis Lifecycle

```
Proposed → Active → Replayed → Confirmed / Refuted / Inconclusive
                                    ↓
                              Kill Criteria:
                              - 3 cycles with no correlated signals → expire
                              - Replay unconfirmed → demote confidence
                              - FP rate > 50% → redesign signal definition
```

## Intelligence Products

| Product | Purpose | When to Use |
|---------|---------|-------------|
| **IIR** (Intelligence Information Report) | Single hypothesis capability proof | One entity, one hypothesis |
| **SITREP** (Situation Report) | Periodic status summary | Regular monitoring cadence |
| **Assessment** | Deep analysis of specific hypothesis | Complex multi-signal investigation |

## Current State

This is v0.1 with:
- 6 signal types with full type system and decay model
- Temporal dependency graph engine (petgraph-based)
- CapabilityReplayer trait (designed for REVM integration)
- 1 collector implementation (ControlPlane: ownership, upgrades, roles)
- Full test suite (`cargo test`)

Planned collectors: OperationalCadence, Coordination, Stress.

## Related Projects

- [revm](https://github.com/bluealloy/revm) — Rust EVM used for capability replay
- [alloy](https://github.com/alloy-rs/alloy) — Rust Ethereum toolkit
- [Foundry](https://github.com/foundry-rs/foundry) — Ethereum development toolkit

## License

Apache-2.0
