use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::infrastructure::database::models::Target;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub id: Option<i64>,
    pub name: String,
    pub target_type: String,
    pub target_value: String,
    pub description: Option<String>,
    pub tags: Option<String>,
    pub location: Option<String>,
    pub organization: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_scanned_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub group_id: Option<i64>,
    pub status: String,
    pub risk_level: String,
    pub priority: String,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub auto_scan: bool,
    pub scan_interval: Option<i64>,
    pub next_scan_at: Option<DateTime<Utc>>,
    pub total_scans: i32,
    pub open_ports_count: i32,
    pub vulnerabilities_count: i32,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetListResult {
    pub targets: Vec<TargetInfo>,
    pub total: i32,
    pub page: i32,
    pub page_size: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetOperationResult {
    pub success: bool,
    pub message: String,
    pub target_id: Option<i64>,
}

impl TargetInfo {
    pub fn from_config(config: &super::TargetConfig) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            name: config.name.clone(),
            target_type: config.target_type.as_str().to_string(),
            target_value: config.target_value.clone(),
            description: config.description.clone(),
            tags: config.tags.as_ref().map(|tags| tags.join(",")),
            location: config.location.clone(),
            organization: config.organization.clone(),
            created_at: now,
            updated_at: now,
            last_scanned_at: None,
            is_active: true,
            group_id: None,
            status: "new".to_string(),
            risk_level: "none".to_string(),
            priority: config.priority.clone().unwrap_or_else(|| "normal".to_string()),
            owner: config.owner.clone(),
            contact: config.contact.clone(),
            auto_scan: config.auto_scan.unwrap_or(false),
            scan_interval: config.scan_interval,
            next_scan_at: None,
            total_scans: 0,
            open_ports_count: 0,
            vulnerabilities_count: 0,
            metadata: config.metadata.clone(),
        }
    }

    pub fn from_db_target(t: &Target) -> Self {
        Self {
            id: t.id,
            name: t.name.clone(),
            target_type: t.target_type.clone(),
            target_value: t.target_value.clone(),
            description: t.description.clone(),
            tags: t.tags.clone(),
            location: t.location.clone(),
            organization: t.organization.clone(),
            created_at: t.created_at,
            updated_at: t.updated_at,
            last_scanned_at: t.last_scanned_at,
            is_active: t.is_active,
            group_id: t.group_id,
            status: t.status.clone(),
            risk_level: t.risk_level.clone(),
            priority: t.priority.clone(),
            owner: t.owner.clone(),
            contact: t.contact.clone(),
            auto_scan: t.auto_scan,
            scan_interval: t.scan_interval,
            next_scan_at: t.next_scan_at,
            total_scans: t.total_scans,
            open_ports_count: t.open_ports_count,
            vulnerabilities_count: t.vulnerabilities_count,
            metadata: t.metadata.clone(),
        }
    }

    pub fn get_tags_list(&self) -> Vec<String> {
        self.tags
            .as_ref()
            .map(|tags| tags.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default()
    }
}

impl TargetListResult {
    pub fn new(targets: Vec<TargetInfo>, total: i32, page: i32, page_size: i32) -> Self {
        Self {
            targets,
            total,
            page,
            page_size,
        }
    }
}

impl TargetOperationResult {
    pub fn success(message: String, target_id: Option<i64>) -> Self {
        Self {
            success: true,
            message,
            target_id,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            message,
            target_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub target_id: i64,
    pub scan_type: String,
    pub open_ports_count: Option<i32>,
    pub vulnerabilities_count: Option<i32>,
    pub risk_level: Option<String>,
    pub status: Option<String>,
}
