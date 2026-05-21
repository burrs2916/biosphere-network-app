use crate::core::Result;
use crate::infrastructure::database::{Database, TargetGroup as DbTargetGroup};
use crate::tools::info_gathering::target_manager::{
    TargetConfig, TargetInfo, TargetListResult, TargetOperationResult, TargetManager, ScanRecord,
};
use std::sync::Arc;

pub struct TargetService {
    manager: Arc<TargetManager>,
    db: Arc<Database>,
}

impl TargetService {
    pub fn new(db: Database) -> Self {
        let db = Arc::new(db);
        let manager = Arc::new(TargetManager::new(db.clone()));
        Self { manager, db }
    }

    pub fn manager(&self) -> &TargetManager {
        &self.manager
    }

    pub fn create_target(&self, config: TargetConfig) -> Result<TargetOperationResult> {
        self.manager.create_target(config)
    }

    pub fn update_target(&self, id: i64, config: TargetConfig) -> Result<TargetOperationResult> {
        self.manager.update_target(id, config)
    }

    pub fn delete_target(&self, id: i64) -> Result<TargetOperationResult> {
        self.manager.delete_target(id)
    }

    pub fn get_targets(&self, page: i32, page_size: i32) -> Result<TargetListResult> {
        self.manager.get_targets(page, page_size)
    }

    pub fn get_targets_by_group(&self, group_id: i64, page: i32, page_size: i32) -> Result<TargetListResult> {
        let offset = (page - 1) * page_size;
        let targets = self.db.get_targets_by_group(group_id, page_size, offset)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?;
        let total = self.db.get_targets_count_by_group(group_id)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?;

        let target_infos: Vec<TargetInfo> = targets
            .iter()
            .map(|t| TargetInfo::from_db_target(t))
            .collect();

        Ok(TargetListResult::new(target_infos, total as i32, page, page_size))
    }

    pub fn search_targets(&self, query: &str, page: i32, page_size: i32) -> Result<TargetListResult> {
        self.manager.search_targets(query, page, page_size)
    }

    pub fn get_target_by_value(&self, target_value: &str) -> Result<Option<TargetInfo>> {
        self.manager.get_target_by_value(target_value)
    }

    pub fn get_target_by_id(&self, id: i64) -> Result<Option<TargetInfo>> {
        let target = self.db.get_target_by_id(id)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?;
        Ok(target.map(|t| TargetInfo::from_db_target(&t)))
    }

    pub fn get_targets_filtered(
        &self,
        target_type: Option<&str>,
        status: Option<&str>,
        risk_level: Option<&str>,
        priority: Option<&str>,
        tag: Option<&str>,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        page: i32,
        page_size: i32,
    ) -> Result<TargetListResult> {
        let offset = (page - 1) * page_size;

        let targets = self.db.get_targets_filtered(
            target_type, status, risk_level, priority, tag,
            sort_by, sort_order, page_size, offset,
        ).map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?;

        let total = self.db.get_targets_filtered_count(
            target_type, status, risk_level, priority, tag,
        ).map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?;

        let target_infos: Vec<TargetInfo> = targets.iter()
            .map(|t| TargetInfo::from_db_target(t))
            .collect();

        Ok(TargetListResult::new(target_infos, total as i32, page, page_size))
    }

    pub fn batch_update_target_group(&self, target_ids: &[i64], group_id: Option<i64>) -> Result<()> {
        self.db.batch_update_target_group(target_ids, group_id)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn batch_update_target_tags(&self, target_ids: &[i64], tags: &str, append: bool) -> Result<()> {
        self.db.batch_update_target_tags(target_ids, tags, append)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn get_scan_tasks_by_target(&self, target_value: &str, page: i32, page_size: i32) -> Result<Vec<crate::infrastructure::database::ScanTask>> {
        let offset = (page - 1) * page_size;
        self.db.get_scan_tasks_by_target(target_value, page_size, offset)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn get_target_statistics(&self) -> Result<serde_json::Value> {
        self.db.get_target_statistics()
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn get_target_groups(&self) -> Result<Vec<DbTargetGroup>> {
        self.db.get_target_groups(100, 0)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn create_target_group(&self, name: String, description: Option<String>, color: Option<String>, icon: Option<String>) -> Result<i64> {
        let group = DbTargetGroup {
            id: None,
            name,
            description,
            target_ids: None,
            tags: None,
            color: color.unwrap_or_else(|| "#3498db".to_string()),
            created_at: chrono::Utc::now(),
            updated_at: None,
            parent_id: None,
            icon,
            target_count: 0,
            active_count: 0,
            risk_count: 0,
            default_scan_config: None,
            auto_scan: false,
            scan_interval: None,
            owner: None,
            is_public: true,
            shared_with: None,
        };

        self.db.create_target_group(&group)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn update_target_group(&self, id: i64, name: String, description: Option<String>, color: Option<String>, icon: Option<String>) -> Result<()> {
        let group = DbTargetGroup {
            id: Some(id),
            name,
            description,
            target_ids: None,
            tags: None,
            color: color.unwrap_or_else(|| "#3498db".to_string()),
            created_at: chrono::Utc::now(),
            updated_at: Some(chrono::Utc::now()),
            parent_id: None,
            icon,
            target_count: 0,
            active_count: 0,
            risk_count: 0,
            default_scan_config: None,
            auto_scan: false,
            scan_interval: None,
            owner: None,
            is_public: true,
            shared_with: None,
        };

        self.db.update_target_group(&group)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn delete_target_group(&self, id: i64) -> Result<()> {
        self.db.delete_target_group(id)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))
    }

    pub fn record_scan(&self, record: ScanRecord) -> Result<TargetOperationResult> {
        let mut target = self.db.get_target_by_id(record.target_id)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?
            .ok_or_else(|| crate::core::ToolError::ExecutionError(
                format!("Target with id {} not found", record.target_id)
            ))?;

        target.last_scanned_at = Some(chrono::Utc::now());
        target.total_scans += 1;
        target.updated_at = chrono::Utc::now();

        if let Some(ports) = record.open_ports_count {
            target.open_ports_count = ports;
        }
        if let Some(vulns) = record.vulnerabilities_count {
            target.vulnerabilities_count = vulns;
        }
        if let Some(risk) = record.risk_level {
            target.risk_level = risk;
        }
        if let Some(status) = record.status {
            target.status = status;
        }

        self.db.update_target(&target)
            .map_err(|e| crate::core::ToolError::ExecutionError(e.to_string()))?;

        Ok(TargetOperationResult::success(
            format!("Scan '{}' recorded for target {}", record.scan_type, target.name),
            Some(record.target_id),
        ))
    }
}
