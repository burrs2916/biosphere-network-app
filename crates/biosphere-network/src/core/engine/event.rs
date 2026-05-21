use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use super::event_type::BiosEventType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiosEvent {
    pub event_type: BiosEventType,
    pub data: String,
    pub module: String,
    pub confidence: u8,
    pub visibility: u8,
    pub risk: u8,
    pub source_event_hash: Option<String>,
    pub hash: String,
    pub generated: u64,
    pub scan_id: String,
    #[serde(default)]
    pub source_event_type: Option<BiosEventType>,
    #[serde(default)]
    pub source_event_data: Option<String>,
    #[serde(default)]
    pub store_only: bool,
}

impl BiosEvent {
    pub fn new(
        event_type: BiosEventType,
        data: String,
        module: String,
        source_event: Option<&BiosEvent>,
        scan_id: String,
    ) -> Self {
        let generated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let source_event_hash = source_event.map(|e| e.hash.clone()).unwrap_or_else(|| "ROOT".to_string());
        let source_event_type = source_event.map(|e| e.event_type.clone());
        let source_event_data = source_event.map(|e| e.data.clone());

        let mut hasher = Sha256::new();
        hasher.update(event_type.as_str().as_bytes());
        hasher.update(data.to_lowercase().as_bytes());
        hasher.update(module.as_bytes());
        hasher.update(source_event_hash.as_bytes());
        if let Some(ref src_type) = source_event_type {
            hasher.update(src_type.as_str().as_bytes());
        }
        if let Some(ref src_data) = source_event_data {
            hasher.update(src_data.to_lowercase().as_bytes());
        }
        let hash = format!("{:x}", hasher.finalize());

        Self {
            event_type,
            data,
            module,
            confidence: 100,
            visibility: 100,
            risk: 0,
            source_event_hash: Some(source_event_hash),
            hash,
            generated,
            scan_id,
            source_event_type,
            source_event_data,
            store_only: false,
        }
    }

    pub fn root(scan_id: String, target_value: String) -> Self {
        Self {
            event_type: BiosEventType::Root,
            data: target_value,
            module: "BiosPhere".to_string(),
            confidence: 100,
            visibility: 100,
            risk: 0,
            source_event_hash: None,
            hash: "ROOT".to_string(),
            generated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            scan_id,
            source_event_type: None,
            source_event_data: None,
            store_only: false,
        }
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    pub fn with_visibility(mut self, visibility: u8) -> Self {
        self.visibility = visibility.min(100);
        self
    }

    pub fn with_risk(mut self, risk: u8) -> Self {
        self.risk = risk.min(100);
        self
    }

    pub fn with_store_only(mut self, store_only: bool) -> Self {
        self.store_only = store_only;
        self
    }

    pub fn is_root(&self) -> bool {
        self.event_type == BiosEventType::Root
    }

    pub fn is_entity(&self) -> bool {
        self.event_type.is_entity()
    }

    pub fn check_circular(&self, seen_hashes: &HashSet<String>) -> bool {
        if let Some(ref src_hash) = self.source_event_hash {
            seen_hashes.contains(src_hash)
                && seen_hashes.contains(&self.hash)
        } else {
            false
        }
    }

    pub fn should_suppress_notification(&self, event_chain: &std::collections::HashMap<String, BiosEventRef>) -> bool {
        if self.is_root() {
            return false;
        }

        let mut current_hash = self.source_event_hash.clone();
        let mut depth = 0;
        const MAX_CHAIN_DEPTH: usize = 100;

        while let Some(ref hash) = current_hash {
            if depth >= MAX_CHAIN_DEPTH {
                return true;
            }

            if let Some(parent) = event_chain.get(hash) {
                if let Some(ref parent_src_type) = parent.source_event_type {
                    if parent_src_type == &self.event_type {
                        if let Some(ref parent_src_data) = parent.source_event_data {
                            if parent_src_data.to_lowercase() == self.data.to_lowercase() {
                                return true;
                            }
                        }
                    }
                }
                current_hash = parent.source_event_hash.clone();
            } else {
                break;
            }
            depth += 1;
        }

        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiosEventRef {
    pub event_type: BiosEventType,
    pub data: String,
    pub module: String,
    pub hash: String,
    pub confidence: u8,
    pub visibility: u8,
    pub risk: u8,
    pub source_event_hash: Option<String>,
    pub source_event_type: Option<BiosEventType>,
    pub source_event_data: Option<String>,
    #[serde(default)]
    pub store_only: bool,
}

impl From<&BiosEvent> for BiosEventRef {
    fn from(event: &BiosEvent) -> Self {
        Self {
            event_type: event.event_type.clone(),
            data: event.data.clone(),
            module: event.module.clone(),
            hash: event.hash.clone(),
            confidence: event.confidence,
            visibility: event.visibility,
            risk: event.risk,
            source_event_hash: event.source_event_hash.clone(),
            source_event_type: event.source_event_type.clone(),
            source_event_data: event.source_event_data.clone(),
            store_only: event.store_only,
        }
    }
}
