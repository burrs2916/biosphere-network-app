use super::{TargetConfig, TargetInfo, TargetListResult, TargetOperationResult};
use crate::core::Result;
use crate::infrastructure::database::{Database, Target as DbTarget};
use std::sync::Arc;

pub struct TargetManager {
    db: Arc<Database>,
}

impl TargetManager {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub fn create_target(&self, config: TargetConfig) -> Result<TargetOperationResult> {
        if let Err(e) = config.validate() {
            return Ok(TargetOperationResult::error(e));
        }

        let existing = self.db.get_target_by_value(&config.target_value)?;
        if existing.is_some() {
            return Ok(TargetOperationResult::error("Target with this value already exists".to_string()));
        }

        let target_info = TargetInfo::from_config(&config);
        let mut db_target = DbTarget::new(
            target_info.name,
            target_info.target_type,
            target_info.target_value,
        );
        db_target.description = target_info.description;
        db_target.tags = target_info.tags;
        db_target.location = target_info.location;
        db_target.organization = target_info.organization;
        db_target.owner = target_info.owner;
        db_target.contact = target_info.contact;
        db_target.priority = target_info.priority;
        db_target.auto_scan = target_info.auto_scan;
        db_target.scan_interval = target_info.scan_interval;
        db_target.metadata = target_info.metadata;

        let id = self.db.create_target(&db_target)?;

        Ok(TargetOperationResult::success(
            "Target created successfully".to_string(),
            Some(id),
        ))
    }

    pub fn update_target(&self, id: i64, config: TargetConfig) -> Result<TargetOperationResult> {
        if let Err(e) = config.validate() {
            return Ok(TargetOperationResult::error(e));
        }

        let existing = self.db.get_target_by_value(&config.target_value)?;
        if let Some(existing_target) = existing {
            if existing_target.id != Some(id) {
                return Ok(TargetOperationResult::error("Target with this value already exists".to_string()));
            }
        }

        let target_info = TargetInfo::from_config(&config);
        let mut db_target = DbTarget::new(
            target_info.name,
            target_info.target_type,
            target_info.target_value,
        );
        db_target.id = Some(id);
        db_target.description = target_info.description;
        db_target.tags = target_info.tags;
        db_target.location = target_info.location;
        db_target.organization = target_info.organization;
        db_target.owner = target_info.owner;
        db_target.contact = target_info.contact;
        db_target.priority = target_info.priority;
        db_target.auto_scan = target_info.auto_scan;
        db_target.scan_interval = target_info.scan_interval;
        db_target.metadata = target_info.metadata;

        self.db.update_target(&db_target)?;

        Ok(TargetOperationResult::success(
            "Target updated successfully".to_string(),
            Some(id),
        ))
    }

    pub fn delete_target(&self, id: i64) -> Result<TargetOperationResult> {
        self.db.delete_target(id)?;

        Ok(TargetOperationResult::success(
            "Target deleted successfully".to_string(),
            None,
        ))
    }

    pub fn get_targets(&self, page: i32, page_size: i32) -> Result<TargetListResult> {
        let offset = (page - 1) * page_size;
        let targets = self.db.get_targets(page_size, offset)?;

        let total = self.db.count_targets().unwrap_or(0);

        let target_infos: Vec<TargetInfo> = targets
            .iter()
            .map(TargetInfo::from_db_target)
            .collect();

        Ok(TargetListResult::new(target_infos, total, page, page_size))
    }

    pub fn get_target_by_value(&self, target_value: &str) -> Result<Option<TargetInfo>> {
        let target = self.db.get_target_by_value(target_value)?;

        Ok(target.as_ref().map(TargetInfo::from_db_target))
    }

    pub fn search_targets(&self, query: &str, page: i32, page_size: i32) -> Result<TargetListResult> {
        let all_targets = self.db.get_targets(1000, 0)?;

        let filtered: Vec<_> = all_targets
            .iter()
            .filter(|t| {
                t.name.to_lowercase().contains(&query.to_lowercase())
                    || t.target_value.to_lowercase().contains(&query.to_lowercase())
                    || t.description
                        .as_ref()
                        .map(|d| d.to_lowercase().contains(&query.to_lowercase()))
                        .unwrap_or(false)
            })
            .collect();

        let total = filtered.len() as i32;
        let offset = ((page - 1) * page_size) as usize;
        let end = (offset + page_size as usize).min(filtered.len());

        let page_targets = filtered[offset..end].to_vec();

        let target_infos: Vec<TargetInfo> = page_targets
            .iter()
            .map(|t| TargetInfo::from_db_target(t))
            .collect();

        Ok(TargetListResult::new(target_infos, total, page, page_size))
    }
}
