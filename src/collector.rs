//! SignalCollector trait — L1 collection interface.
//!
//! Extends the watcher pattern with signal-type awareness,
//! forgery cost estimation, and chain-specific collection.

use async_trait::async_trait;
use anyhow::Result;

use crate::types::{NormalizedSignal, SignalType};

/// Signal collector trait — the L1 entry point.
///
/// Each collector watches for a specific set of signal types
/// and produces NormalizedSignal outputs.
///
/// Design: requirement-driven, not source-driven.
/// "What do we need to know?" → "Which signals answer that?"
#[async_trait]
pub trait SignalCollector: Send + Sync {
    /// Which signal types this collector handles.
    fn signal_types(&self) -> &[SignalType];

    /// Which event selectors to filter for (topic0 first 4 bytes).
    fn event_selectors(&self) -> &[[u8; 4]];

    /// Target chain ID.
    fn chain_id(&self) -> u64;

    /// Collect signals from a specific block.
    /// Returns normalized signals found in this block.
    async fn collect_block(&self, block_number: u64) -> Result<Vec<NormalizedSignal>>;

    /// Collect signals from a block range (inclusive).
    /// Default: iterate block by block. Collectors may optimize with batch eth_getLogs.
    async fn collect_range(&self, from_block: u64, to_block: u64) -> Result<Vec<NormalizedSignal>> {
        let mut signals = Vec::new();
        for block in from_block..=to_block {
            let mut block_signals = self.collect_block(block).await?;
            signals.append(&mut block_signals);
        }
        Ok(signals)
    }
}
