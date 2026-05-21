use super::{DnsQueryConfig, DnsResolver, DnsQueryType};
use crate::core::{Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput, Result, ProgressReporter};

pub struct DnsQueryTool {
    info: ToolInfo,
}

impl DnsQueryTool {
    pub fn new() -> Self {
        Self {
            info: ToolInfo {
                id: "dns_query".to_string(),
                name: "DNS Query".to_string(),
                description: "DNS query tool for looking up DNS records".to_string(),
                category: ToolCategory::InformationGathering,
                installed: true,
            },
        }
    }
}

impl Tool for DnsQueryTool {
    fn info(&self) -> ToolInfo {
        self.info.clone()
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let target = args.get_target()?;
        
        let query_type = args.get_option("query_type")
            .and_then(|t| DnsQueryType::from_str(t))
            .unwrap_or(DnsQueryType::A);
        
        let dns_server = args.get_option("dns_server").map(|s| s.clone());
        let timeout = args.get_option("timeout")
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(5);

        let config = DnsQueryConfig::new(target.clone(), query_type)
            .with_dns_server(dns_server.unwrap_or_default())
            .with_timeout(timeout);

        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(DnsResolver::query(config))
        })?;

        let output = if result.is_success() {
            ToolOutput::success(result.to_json())
        } else {
            ToolOutput::error(result.error.unwrap_or_else(|| "Query failed".to_string()))
        };

        Ok(output)
    }
}

impl Default for DnsQueryTool {
    fn default() -> Self {
        Self::new()
    }
}
