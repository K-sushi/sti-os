//! Control-Plane Signal Collector
//!
//! Watches for owner/admin permission changes — the strongest behavioral signal.
//! These are HIGH forgery cost (require admin key or governance execution)
//! and have 30-day decay half-life.
//!
//! Target events:
//! - OwnershipTransferred(address indexed, address indexed)
//! - Upgraded(address indexed)
//! - RoleGranted(bytes32 indexed, address indexed, address indexed)
//! - RoleRevoked(bytes32 indexed, address indexed, address indexed)
//! - AdminChanged(address, address)

use alloy_primitives::{Address, B256};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::collector::SignalCollector;
use crate::types::{
    DataQuality, ForgeryLevel, NormalizedSignal, SignalType,
    selectors,
};

/// Full topic0 hashes for eth_getLogs filter.
/// These are keccak256 of the full event signature.
const TOPIC_OWNERSHIP_TRANSFERRED: &str =
    "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0";
const TOPIC_UPGRADED: &str =
    "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";
const TOPIC_ROLE_GRANTED: &str =
    "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d";
const TOPIC_ROLE_REVOKED: &str =
    "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b";
const TOPIC_ADMIN_CHANGED: &str =
    "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f";
/// Paused(address) — OpenZeppelin Pausable
const TOPIC_PAUSED: &str =
    "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258";
/// Unpaused(address) — OpenZeppelin Pausable
const TOPIC_UNPAUSED: &str =
    "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa";

/// Configuration for ControlPlaneCollector.
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// JSON-RPC URL
    pub rpc_url: String,
    /// Chain ID
    pub chain_id: u64,
    /// Optional: restrict to specific contract addresses.
    /// Empty = watch all contracts (broad but expensive).
    pub watch_addresses: Vec<Address>,
    /// HTTP client timeout in seconds
    pub rpc_timeout_secs: u64,
}

/// Collector for control-plane signals.
pub struct ControlPlaneCollector {
    config: ControlPlaneConfig,
    http_client: reqwest::Client,
}

impl ControlPlaneCollector {
    pub fn new(config: ControlPlaneConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.rpc_timeout_secs))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            config,
            http_client,
        }
    }

    /// Fetch block timestamp from RPC.
    async fn get_block_timestamp(&self, block_number: u64) -> Result<DateTime<Utc>> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{:x}", block_number), false],
            "id": 1
        });

        let resp = self.http_client
            .post(&self.config.rpc_url)
            .json(&payload)
            .send()
            .await
            .context("eth_getBlockByNumber failed")?;

        let body: serde_json::Value = resp.json().await
            .context("eth_getBlockByNumber parse failed")?;

        let timestamp_hex = body
            .get("result")
            .and_then(|r| r.get("timestamp"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing block timestamp"))?;

        let timestamp_secs = parse_hex_u64(timestamp_hex)
            .ok_or_else(|| anyhow::anyhow!("invalid block timestamp hex"))?;

        Ok(Utc.timestamp_opt(timestamp_secs as i64, 0)
            .single()
            .unwrap_or_else(Utc::now))
    }

    /// Check contract legitimacy via eth_getCode.
    /// Returns false if address has no code (EOA pretending to be contract).
    async fn has_code(&self, address: &Address) -> Result<bool> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [format!("0x{}", hex::encode(address.as_slice())), "latest"],
            "id": 1
        });

        let resp = self.http_client
            .post(&self.config.rpc_url)
            .json(&payload)
            .send()
            .await
            .context("eth_getCode failed")?;

        let body: serde_json::Value = resp.json().await
            .context("eth_getCode parse failed")?;

        let code = body.get("result")
            .and_then(|v| v.as_str())
            .unwrap_or("0x");

        // "0x" or empty = no code (EOA)
        Ok(code.len() > 2)
    }

    /// Build eth_getLogs filter params for a block range.
    fn build_filter(&self, from_block: u64, to_block: u64) -> serde_json::Value {
        let topics = vec![
            TOPIC_OWNERSHIP_TRANSFERRED,
            TOPIC_UPGRADED,
            TOPIC_ROLE_GRANTED,
            TOPIC_ROLE_REVOKED,
            TOPIC_ADMIN_CHANGED,
            TOPIC_PAUSED,
            TOPIC_UNPAUSED,
        ];

        let mut filter = json!({
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
            "topics": [topics],
        });

        if !self.config.watch_addresses.is_empty() {
            let addrs: Vec<String> = self.config.watch_addresses.iter()
                .map(|a| format!("0x{}", hex::encode(a.as_slice())))
                .collect();
            filter["address"] = json!(addrs);
        }

        filter
    }

    /// Execute eth_getLogs RPC call.
    async fn eth_get_logs(&self, filter: serde_json::Value) -> Result<Vec<serde_json::Value>> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [filter],
            "id": 1
        });

        let resp = self.http_client
            .post(&self.config.rpc_url)
            .json(&payload)
            .send()
            .await
            .context("eth_getLogs RPC request failed")?;

        let body: serde_json::Value = resp.json().await
            .context("eth_getLogs response parse failed")?;

        if let Some(error) = body.get("error") {
            anyhow::bail!("eth_getLogs RPC error: {}", error);
        }

        body.get("result")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("eth_getLogs: missing result array"))
    }

    /// Parse a single log entry into a NormalizedSignal.
    /// Accepts block_timestamp instead of using Utc::now().
    fn parse_log(&self, log: &serde_json::Value, block_timestamp: DateTime<Utc>) -> Option<NormalizedSignal> {
        let topics = log.get("topics")?.as_array()?;
        if topics.is_empty() {
            return None;
        }

        let topic0 = topics[0].as_str()?;
        let (signal_selector, event_name) = match topic0 {
            t if t == TOPIC_OWNERSHIP_TRANSFERRED => (selectors::OWNERSHIP_TRANSFERRED, "OwnershipTransferred"),
            t if t == TOPIC_UPGRADED => (selectors::UPGRADED, "Upgraded"),
            t if t == TOPIC_ROLE_GRANTED => (selectors::ROLE_GRANTED, "RoleGranted"),
            t if t == TOPIC_ROLE_REVOKED => (selectors::ROLE_REVOKED, "RoleRevoked"),
            t if t == TOPIC_ADMIN_CHANGED => (selectors::ADMIN_CHANGED, "AdminChanged"),
            t if t == TOPIC_PAUSED => (selectors::PAUSED, "Paused"),
            t if t == TOPIC_UNPAUSED => (selectors::UNPAUSED, "Unpaused"),
            _ => return None,
        };

        let address_hex = log.get("address")?.as_str()?;
        let entity = parse_address(address_hex)?;

        let tx_hash_hex = log.get("transactionHash")?.as_str()?;
        let source_tx = parse_b256(tx_hash_hex)?;

        let block_hex = log.get("blockNumber")?.as_str()?;
        let block_number = parse_hex_u64(block_hex)?;

        let raw_data_hex = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
        let raw_data = hex::decode(raw_data_hex.strip_prefix("0x").unwrap_or(raw_data_hex))
            .unwrap_or_default();

        // Build normalized fields from topics
        let mut normalized_fields = HashMap::new();
        normalized_fields.insert("event".to_string(), json!(event_name));
        normalized_fields.insert("contract".to_string(), json!(address_hex));

        // Decode topic-based fields per event type
        match event_name {
            "OwnershipTransferred" => {
                if let Some(prev) = topics.get(1).and_then(|t| t.as_str()) {
                    normalized_fields.insert("previousOwner".to_string(), json!(topic_to_address(prev)));
                }
                if let Some(new) = topics.get(2).and_then(|t| t.as_str()) {
                    normalized_fields.insert("newOwner".to_string(), json!(topic_to_address(new)));
                }
            }
            "Upgraded" => {
                if let Some(impl_addr) = topics.get(1).and_then(|t| t.as_str()) {
                    normalized_fields.insert("implementation".to_string(), json!(topic_to_address(impl_addr)));
                }
            }
            "RoleGranted" | "RoleRevoked" => {
                if let Some(role) = topics.get(1).and_then(|t| t.as_str()) {
                    normalized_fields.insert("role".to_string(), json!(role));
                }
                if let Some(account) = topics.get(2).and_then(|t| t.as_str()) {
                    normalized_fields.insert("account".to_string(), json!(topic_to_address(account)));
                }
                if let Some(sender) = topics.get(3).and_then(|t| t.as_str()) {
                    normalized_fields.insert("sender".to_string(), json!(topic_to_address(sender)));
                }
            }
            "AdminChanged" => {
                // AdminChanged(address previousAdmin, address newAdmin) - in data field
                if raw_data.len() >= 64 {
                    let prev_hex = format!("0x{}", hex::encode(&raw_data[12..32]));
                    let new_hex = format!("0x{}", hex::encode(&raw_data[44..64]));
                    normalized_fields.insert("previousAdmin".to_string(), json!(prev_hex));
                    normalized_fields.insert("newAdmin".to_string(), json!(new_hex));
                }
            }
            "Paused" => {
                // Paused(address account) - indexed
                if let Some(account) = topics.get(1).and_then(|t| t.as_str()) {
                    normalized_fields.insert("account".to_string(), json!(topic_to_address(account)));
                }
                normalized_fields.insert("paused".to_string(), json!(true));
            }
            "Unpaused" => {
                // Unpaused(address account) - indexed
                if let Some(account) = topics.get(1).and_then(|t| t.as_str()) {
                    normalized_fields.insert("account".to_string(), json!(topic_to_address(account)));
                }
                normalized_fields.insert("paused".to_string(), json!(false));
            }
            _ => {}
        }

        Some(NormalizedSignal {
            id: uuid::Uuid::new_v4().to_string(),
            signal_type: SignalType::ControlPlane,
            source_tx,
            block_number,
            timestamp: block_timestamp, // Use actual block timestamp
            chain_id: self.config.chain_id,
            entity,
            event_selector: signal_selector,
            raw_data,
            normalized_fields,
            forgery_cost: ForgeryLevel::High,
            quality: DataQuality::Clean,
        })
    }
}

#[async_trait]
impl SignalCollector for ControlPlaneCollector {
    fn signal_types(&self) -> &[SignalType] {
        &[SignalType::ControlPlane]
    }

    fn event_selectors(&self) -> &[[u8; 4]] {
        &[
            selectors::OWNERSHIP_TRANSFERRED,
            selectors::UPGRADED,
            selectors::ROLE_GRANTED,
            selectors::ROLE_REVOKED,
            selectors::ADMIN_CHANGED,
            selectors::PAUSED,
            selectors::UNPAUSED,
        ]
    }

    fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    async fn collect_block(&self, block_number: u64) -> Result<Vec<NormalizedSignal>> {
        self.collect_range(block_number, block_number).await
    }

    async fn collect_range(&self, from_block: u64, to_block: u64) -> Result<Vec<NormalizedSignal>> {
        let filter = self.build_filter(from_block, to_block);
        let logs = self.eth_get_logs(filter).await?;

        debug!(
            "[ControlPlane] blocks {}..{}: {} logs found",
            from_block, to_block, logs.len()
        );

        // Collect unique block numbers and fetch timestamps
        let mut block_timestamps: HashMap<u64, DateTime<Utc>> = HashMap::new();
        for log in &logs {
            if let Some(block_hex) = log.get("blockNumber").and_then(|v| v.as_str()) {
                if let Some(block_num) = parse_hex_u64(block_hex) {
                    if let std::collections::hash_map::Entry::Vacant(entry) = block_timestamps.entry(block_num) {
                        match self.get_block_timestamp(block_num).await {
                            Ok(ts) => { entry.insert(ts); }
                            Err(e) => {
                                warn!("[ControlPlane] Failed to get timestamp for block {}: {}", block_num, e);
                                entry.insert(Utc::now());
                            }
                        }
                    }
                }
            }
        }

        let mut signals = Vec::new();
        for log in &logs {
            let block_num = log.get("blockNumber")
                .and_then(|v| v.as_str())
                .and_then(parse_hex_u64)
                .unwrap_or(0);
            let timestamp = block_timestamps.get(&block_num).copied().unwrap_or_else(Utc::now);

            match self.parse_log(log, timestamp) {
                Some(mut s) => {
                    // Contract legitimacy filter — downgrade forgery cost for non-code addresses
                    match self.has_code(&s.entity).await {
                        Ok(false) => {
                            warn!(
                                "[ControlPlane] Entity {} has no code — downgrading forgery cost",
                                s.entity
                            );
                            s.forgery_cost = ForgeryLevel::Low;
                            s.quality = DataQuality::Degraded;
                        }
                        Err(e) => {
                            debug!("[ControlPlane] eth_getCode check failed: {}", e);
                            s.quality = DataQuality::Degraded;
                        }
                        Ok(true) => {} // has code, keep HIGH
                    }
                    signals.push(s);
                }
                None => {
                    warn!("[ControlPlane] Failed to parse log: {:?}", log);
                }
            }
        }

        Ok(signals)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_address(hex: &str) -> Option<Address> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    Some(Address::from_slice(&bytes))
}

fn parse_b256(hex: &str) -> Option<B256> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(B256::from_slice(&bytes))
}

fn parse_hex_u64(hex: &str) -> Option<u64> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    u64::from_str_radix(hex, 16).ok()
}

/// Extract address from a 32-byte topic (last 20 bytes).
fn topic_to_address(topic: &str) -> String {
    let topic = topic.strip_prefix("0x").unwrap_or(topic);
    if topic.len() >= 40 {
        format!("0x{}", &topic[topic.len() - 40..])
    } else {
        format!("0x{}", topic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address() {
        let addr = parse_address("0x0000000000000000000000000000000000000001");
        assert!(addr.is_some());
        assert_eq!(addr.unwrap(), Address::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn test_parse_hex_u64() {
        assert_eq!(parse_hex_u64("0xff"), Some(255));
        assert_eq!(parse_hex_u64("0x0"), Some(0));
        assert_eq!(parse_hex_u64("1a2b3c"), Some(0x1a2b3c));
    }

    #[test]
    fn test_topic_to_address() {
        let topic = "0x000000000000000000000000dead000000000000000000000000000000beef";
        let addr = topic_to_address(topic);
        assert_eq!(addr, "0x00dead000000000000000000000000000000beef");
    }

    #[test]
    fn test_build_filter_no_address() {
        let config = ControlPlaneConfig {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 1,
            watch_addresses: vec![],
            rpc_timeout_secs: 5,
        };
        let collector = ControlPlaneCollector::new(config);
        let filter = collector.build_filter(100, 200);

        assert_eq!(filter["fromBlock"], "0x64");
        assert_eq!(filter["toBlock"], "0xc8");
        assert!(filter.get("address").is_none());
    }

    #[test]
    fn test_build_filter_with_address() {
        let config = ControlPlaneConfig {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 1,
            watch_addresses: vec![Address::from([0xAA; 20])],
            rpc_timeout_secs: 5,
        };
        let collector = ControlPlaneCollector::new(config);
        let filter = collector.build_filter(100, 200);

        assert!(filter.get("address").is_some());
    }

    #[test]
    fn test_parse_log_ownership_transferred() {
        let config = ControlPlaneConfig {
            rpc_url: "http://localhost:8545".to_string(),
            chain_id: 1,
            watch_addresses: vec![],
            rpc_timeout_secs: 5,
        };
        let collector = ControlPlaneCollector::new(config);

        let log = json!({
            "address": "0x0000000000000000000000000000000000000001",
            "topics": [
                TOPIC_OWNERSHIP_TRANSFERRED,
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0x000000000000000000000000dead000000000000000000000000000000beef"
            ],
            "data": "0x",
            "blockNumber": "0x64",
            "transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000001"
        });

        let signal = collector.parse_log(&log, Utc::now()).unwrap();
        assert_eq!(signal.signal_type, SignalType::ControlPlane);
        assert_eq!(signal.block_number, 100);
        assert_eq!(signal.forgery_cost, ForgeryLevel::High);
        assert_eq!(signal.event_selector, selectors::OWNERSHIP_TRANSFERRED);
        assert_eq!(
            signal.normalized_fields.get("event").unwrap(),
            &json!("OwnershipTransferred")
        );
    }
}
