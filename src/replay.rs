//! Capability Replay — L3 verification.
//!
//! Prove/disprove capability hypotheses via EVM state replay.
//! The "capability prover" — proving what IS POSSIBLE, not predicting what WILL happen.
//!
//! Protocol: snapshot → override → simulate → evaluate → restore
//!
//! This module defines the replay types and protocol as a trait,
//! allowing implementation against different REVM backends.

use alloy_primitives::Address;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use tracing::warn;

use crate::types::{Hypothesis, ReplayResult, Verdict};

/// Capability replayer trait — interface to REVM backend.
///
/// Implementors wrap a REVM-based simulator to provide
/// hypothesis verification.
#[async_trait]
pub trait CapabilityReplayer: Send + Sync {
    /// Verify a hypothesis by replaying its spec against chain state.
    ///
    /// Protocol:
    /// 1. Fork chain state at target block
    /// 2. Apply state overrides from hypothesis.replay_spec
    /// 3. Execute target function
    /// 4. Compare result against expected outcome
    /// 5. Return ReplayResult with verdict
    async fn verify(&self, hypothesis: &Hypothesis) -> Result<ReplayResult>;

    /// Get current block number for freshness check.
    async fn current_block(&self) -> Result<u64>;

    /// Check if a block context is still fresh (within 100 blocks).
    async fn is_fresh(&self, block_context: u64) -> Result<bool> {
        let current = self.current_block().await?;
        Ok(current.saturating_sub(block_context) < 100)
    }
}

/// RPC-based capability replayer using JSON-RPC eth_call with state overrides.
///
/// ⚠ OPSEC WARNING: This replayer sends state_overrides and target contracts
/// to an external RPC provider, leaking investigation hypotheses.
/// Use LocalCapabilityReplayer (REVM-based) for sensitive operations.
/// RPC calls may leak investigation context.
pub struct RpcCapabilityReplayer {
    rpc_url: String,
    chain_id: u64,
    http_client: reqwest::Client,
    /// Caller address for msg.sender context
    from_address: Option<Address>,
    /// Typical gas for common operations (for anomaly detection)
    #[allow(dead_code)]
    typical_gas: u64,
}

impl RpcCapabilityReplayer {
    pub fn new(rpc_url: String, chain_id: u64) -> Self {
        warn!(
            "[OPSEC] RpcCapabilityReplayer sends hypothesis details to external RPC. \
             Use LocalCapabilityReplayer for sensitive operations."
        );

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            rpc_url,
            chain_id,
            http_client,
            from_address: None,
            typical_gas: 100_000,
        }
    }

    /// Set the caller address for msg.sender context.
    pub fn with_from(mut self, from: Address) -> Self {
        self.from_address = Some(from);
        self
    }

    /// Build eth_call params with state overrides.
    fn build_eth_call(
        &self,
        hypothesis: &Hypothesis,
        _block_hex: &str,
    ) -> (serde_json::Value, serde_json::Value) {
        let spec = &hypothesis.replay_spec;

        // Transaction object
        let mut calldata = spec.function_selector.to_vec();
        calldata.extend_from_slice(&spec.calldata);

        let mut tx = serde_json::json!({
            "to": format!("0x{}", hex::encode(spec.target_contract.as_slice())),
            "data": format!("0x{}", hex::encode(&calldata)),
            "gas": "0x1c9c380", // 30M gas limit
            "value": format!("0x{:x}", spec.msg_value),
        });

        // Include `from` for msg.sender-dependent calls
        if let Some(from) = &self.from_address {
            tx["from"] = serde_json::json!(format!("0x{}", hex::encode(from.as_slice())));
        }

        // State overrides (eth_call format)
        let mut overrides = serde_json::Map::new();
        for slot_override in &spec.state_overrides {
            let addr_key = format!("0x{}", hex::encode(slot_override.address.as_slice()));
            let entry = overrides.entry(addr_key).or_insert_with(|| {
                serde_json::json!({"stateDiff": {}})
            });

            if let Some(state_diff) = entry.get_mut("stateDiff") {
                let slot_key = format!("0x{:064x}", slot_override.slot);
                let value_hex = format!("0x{:064x}", slot_override.value);
                state_diff[slot_key] = serde_json::json!(value_hex);
            }
        }

        let state_override = serde_json::Value::Object(overrides);
        (tx, state_override)
    }
}

#[async_trait]
impl CapabilityReplayer for RpcCapabilityReplayer {
    async fn verify(&self, hypothesis: &Hypothesis) -> Result<ReplayResult> {
        let _block_hex = format!("0x{:x}", hypothesis.replay_spec.state_overrides
            .first()
            .map(|_| hypothesis.temporal_window.1)
            .unwrap_or(0));

        // Check freshness
        let current = self.current_block().await?;
        let block_context = hypothesis.temporal_window.1;
        let is_stale = current.saturating_sub(block_context) >= 100;

        let effective_block = if is_stale {
            tracing::warn!(
                "[Replay] Block {} is stale (current={}), using latest",
                block_context, current
            );
            current
        } else {
            block_context
        };

        let block_param = format!("0x{:x}", effective_block);
        let (tx, state_override) = self.build_eth_call(hypothesis, &block_param);

        // eth_call with state overrides
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [tx, block_param, state_override],
            "id": 1
        });

        let resp = self.http_client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        warn!(
            "[OPSEC] Sent eth_call with {} state overrides to external RPC for hypothesis {}",
            hypothesis.replay_spec.state_overrides.len(),
            hypothesis.id
        );

        let (success, return_data, revert_reason) = if let Some(result) = body.get("result") {
            let hex_str = result.as_str().unwrap_or("0x");
            let data = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
                .unwrap_or_default();
            (true, data, None)
        } else if let Some(error) = body.get("error") {
            let msg = error.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            // Try to extract revert data for better diagnostics
            let revert_data = error.get("data")
                .and_then(|d| d.as_str())
                .map(|d| format!("{} (data: {})", msg, d))
                .unwrap_or(msg);
            (false, vec![], Some(revert_data))
        } else {
            (false, vec![], Some("unexpected response".to_string()))
        };

        // Evaluate verdict
        let spec = &hypothesis.replay_spec;
        let verdict = if success == spec.expected_success {
            if let Some(ref expected_return) = spec.expected_return_match {
                if return_data.starts_with(expected_return) {
                    Verdict::Confirmed
                } else {
                    Verdict::Inconclusive
                }
            } else {
                Verdict::Confirmed
            }
        } else {
            Verdict::Refuted
        };

        let verdict_evidence = match verdict {
            Verdict::Confirmed => format!(
                "Simulation {} as expected",
                if success { "succeeded" } else { "reverted" }
            ),
            Verdict::Refuted => format!(
                "Expected success={}, got success={}. {}",
                spec.expected_success,
                success,
                revert_reason.as_deref().unwrap_or("")
            ),
            Verdict::Inconclusive => "Success but unexpected return data".to_string(),
        };

        let capability_proven = if verdict == Verdict::Confirmed {
            Some(hypothesis.claim.clone())
        } else {
            None
        };

        Ok(ReplayResult {
            hypothesis_id: hypothesis.id.clone(),
            block_context: effective_block,
            valid_until: effective_block + 100,
            chain_id: self.chain_id,
            overrides_applied: hypothesis.replay_spec.state_overrides.clone(),
            success,
            return_data,
            revert_reason,
            // eth_call via RPC doesn't return gas_used/state_changes/logs.
            // These fields are best-effort — LocalCapabilityReplayer (REVM) fills them properly.
            gas_used: 0,
            gas_anomaly: false,
            state_changes: vec![],
            logs: vec![],
            verdict,
            verdict_evidence,
            capability_proven,
            executed_at: Utc::now(),
        })
    }

    async fn current_block(&self) -> Result<u64> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        let resp = self.http_client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;
        let hex_str = body.get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("eth_blockNumber: missing result"))?;

        let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        u64::from_str_radix(hex, 16)
            .map_err(|e| anyhow::anyhow!("eth_blockNumber parse error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use crate::types::*;

    #[test]
    fn test_build_eth_call_params() {
        let replayer = RpcCapabilityReplayer::new(
            "http://localhost:8545".to_string(),
            1,
        );

        let hypothesis = Hypothesis {
            id: "H-1".to_string(),
            claim: "Test".to_string(),
            evidence: vec![],
            temporal_window: (100, 200),
            replay_spec: ReplaySpec {
                target_contract: Address::from([0x01; 20]),
                function_selector: [0x12, 0x34, 0x56, 0x78],
                calldata: vec![0xAA, 0xBB],
                msg_value: U256::ZERO,
                state_overrides: vec![SlotOverride {
                    address: Address::from([0x02; 20]),
                    slot: U256::from(1),
                    value: U256::from(42),
                    justification: "test override".to_string(),
                }],
                expected_success: true,
                expected_return_match: None,
            },
            kill_criteria: vec!["test".to_string()],
            confidence: 0.5,
            classification: Classification::Probable,
            created_at: Utc::now(),
        };

        let (tx, overrides) = replayer.build_eth_call(&hypothesis, "0xc8");

        assert!(tx.get("to").is_some());
        assert!(tx.get("data").is_some());
        // Data should be selector + calldata
        let data = tx["data"].as_str().unwrap();
        assert!(data.starts_with("0x12345678")); // selector
        assert!(overrides.is_object());
    }
}
