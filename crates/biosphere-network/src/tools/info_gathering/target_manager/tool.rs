use super::{TargetConfig, TargetManager};
use crate::core::{Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput, ToolError, Result, ProgressReporter};
use crate::infrastructure::database::models::TargetType;
use std::sync::Arc;

pub struct TargetManagerTool {
    info: ToolInfo,
    manager: Arc<TargetManager>,
}

impl TargetManagerTool {
    pub fn new(manager: Arc<TargetManager>) -> Self {
        Self {
            info: ToolInfo {
                id: "target_manager".to_string(),
                name: "Target Manager".to_string(),
                description: "Target management tool for organizing and managing network targets".to_string(),
                category: ToolCategory::InformationGathering,
                installed: true,
            },
            manager,
        }
    }
}

impl Tool for TargetManagerTool {
    fn info(&self) -> ToolInfo {
        self.info.clone()
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let action = args.get_option("action")
            .ok_or_else(|| ToolError::MissingArgument("action".to_string()))?;

        match action.as_str() {
            "create" => {
                let name = args.get_option("name")
                    .ok_or_else(|| ToolError::MissingArgument("name".to_string()))?
                    .to_string();
                
                let target_type_str = args.get_option("targetType")
                    .ok_or_else(|| ToolError::MissingArgument("targetType".to_string()))?;
                
                let target_type = TargetType::from_str(target_type_str)
                    .ok_or_else(|| ToolError::ParseError(format!("Invalid target type: {}", target_type_str)))?;
                
                let target_value = args.get_option("targetValue")
                    .ok_or_else(|| ToolError::MissingArgument("targetValue".to_string()))?
                    .to_string();
                
                let mut config = TargetConfig::new(name, target_type, target_value);
                
                if let Some(desc) = args.get_option("description") {
                    config = config.with_description(desc.to_string());
                }
                
                if let Some(tags) = args.get_option("tags") {
                    let tag_list: Vec<String> = tags.split(',').map(|s| s.trim().to_string()).collect();
                    config = config.with_tags(tag_list);
                }
                
                if let Some(loc) = args.get_option("location") {
                    config = config.with_location(loc.to_string());
                }
                
                if let Some(org) = args.get_option("organization") {
                    config = config.with_organization(org.to_string());
                }
                
                let result = self.manager.create_target(config)?;
                Ok(ToolOutput::success(serde_json::to_string(&result).unwrap_or_default()))
            }
            "update" => {
                let id = args.get_option("id")
                    .and_then(|i| i.parse::<i64>().ok())
                    .ok_or_else(|| ToolError::MissingArgument("id".to_string()))?;
                
                let name = args.get_option("name")
                    .ok_or_else(|| ToolError::MissingArgument("name".to_string()))?
                    .to_string();
                
                let target_type_str = args.get_option("targetType")
                    .ok_or_else(|| ToolError::MissingArgument("targetType".to_string()))?;
                
                let target_type = TargetType::from_str(target_type_str)
                    .ok_or_else(|| ToolError::ParseError(format!("Invalid target type: {}", target_type_str)))?;
                
                let target_value = args.get_option("targetValue")
                    .ok_or_else(|| ToolError::MissingArgument("targetValue".to_string()))?
                    .to_string();
                
                let mut config = TargetConfig::new(name, target_type, target_value);
                
                if let Some(desc) = args.get_option("description") {
                    config = config.with_description(desc.to_string());
                }
                
                if let Some(tags) = args.get_option("tags") {
                    let tag_list: Vec<String> = tags.split(',').map(|s| s.trim().to_string()).collect();
                    config = config.with_tags(tag_list);
                }
                
                if let Some(loc) = args.get_option("location") {
                    config = config.with_location(loc.to_string());
                }
                
                if let Some(org) = args.get_option("organization") {
                    config = config.with_organization(org.to_string());
                }
                
                let result = self.manager.update_target(id, config)?;
                Ok(ToolOutput::success(serde_json::to_string(&result).unwrap_or_default()))
            }
            "delete" => {
                let id = args.get_option("id")
                    .and_then(|i| i.parse::<i64>().ok())
                    .ok_or_else(|| ToolError::MissingArgument("id".to_string()))?;
                
                let result = self.manager.delete_target(id)?;
                Ok(ToolOutput::success(serde_json::to_string(&result).unwrap_or_default()))
            }
            "list" => {
                let page = args.get_option("page")
                    .and_then(|p| p.parse::<i32>().ok())
                    .unwrap_or(1);
                
                let page_size = args.get_option("pageSize")
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(20);
                
                let result = self.manager.get_targets(page, page_size)?;
                Ok(ToolOutput::success(serde_json::to_string(&result).unwrap_or_default()))
            }
            "search" => {
                let query = args.get_option("query")
                    .ok_or_else(|| ToolError::MissingArgument("query".to_string()))?;
                
                let page = args.get_option("page")
                    .and_then(|p| p.parse::<i32>().ok())
                    .unwrap_or(1);
                
                let page_size = args.get_option("pageSize")
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(20);
                
                let result = self.manager.search_targets(query, page, page_size)?;
                Ok(ToolOutput::success(serde_json::to_string(&result).unwrap_or_default()))
            }
            _ => Err(ToolError::ExecutionError(format!("Unknown action: {}", action))),
        }
    }
}
