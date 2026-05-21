use crate::core::{Tool, ToolInfo, ToolArgs, ToolOutput, ToolCategory, Result, ProgressReporter, ToolError};
use super::{WhoisConfig, WhoisResolver, WhoisResult};

pub struct WhoisTool;

impl WhoisTool {
    pub fn new() -> Self {
        Self
    }
}

impl Tool for WhoisTool {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            id: "whois".to_string(),
            name: "Whois Query".to_string(),
            description: "Query domain registration information from WHOIS database".to_string(),
            category: ToolCategory::InformationGathering,
            installed: true,
        }
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let domain = args.get_target()?;
        
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let config = WhoisConfig::new(domain.clone());
                WhoisResolver::query(config).await
            })
        });
        
        match result {
            Ok(whois_result) => {
                let json = serde_json::to_string(&whois_result)
                    .map_err(|e| ToolError::ExecutionError(e.to_string()))?;
                Ok(ToolOutput::success(json))
            }
            Err(e) => Ok(ToolOutput::error(e.to_string())),
        }
    }
}

pub async fn query_whois(domain: String, timeout_ms: Option<u64>) -> Result<WhoisResult> {
    let mut config = WhoisConfig::new(domain);
    if let Some(timeout) = timeout_ms {
        config = config.with_timeout(timeout);
    }
    
    WhoisResolver::query(config).await
        .map_err(|e| ToolError::ExecutionError(e.to_string()))
}
