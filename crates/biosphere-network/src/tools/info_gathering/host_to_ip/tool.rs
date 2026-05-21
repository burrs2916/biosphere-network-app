use super::{ResolveConfig, Resolver};
use crate::core::{ProgressReporter, Result, Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput};

pub struct HostToIp;

impl HostToIp {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HostToIp {
    fn default() -> Self {
        Self::new()
    }
}

impl Tool for HostToIp {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            id: "host_to_ip".to_string(),
            name: "Host to IP".to_string(),
            description: "Convert hostname to IP address".to_string(),
            category: ToolCategory::InformationGathering,
            installed: true,
        }
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let hostname = args.get_target()?.clone();
        let config = ResolveConfig::new(hostname);
        
        let result = Resolver::resolve(config)?;

        if result.is_empty() {
            return Ok(ToolOutput::error(format!(
                "No IP addresses found for host: {}",
                result.hostname
            )));
        }

        let output = result.to_string_list().join("\n");
        Ok(ToolOutput::success(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_info() {
        let tool = HostToIp::new();
        let info = tool.info();

        assert_eq!(info.id, "host_to_ip");
        assert_eq!(info.name, "Host to IP");
        assert_eq!(info.category, ToolCategory::InformationGathering);
        assert!(info.installed);
    }

    #[test]
    fn test_run_localhost() {
        let tool = HostToIp::new();
        let args = ToolArgs::new(Some("localhost".to_string()));
        let result = tool.run(args, None).unwrap();

        assert!(result.success);
        assert!(result.data.contains("127.0.0.1"));
    }

    #[test]
    fn test_run_example() {
        let tool = HostToIp::new();
        let args = ToolArgs::new(Some("example.com".to_string()));
        let result = tool.run(args, None).unwrap();

        assert!(result.success);
        assert!(!result.data.is_empty());
    }

    #[test]
    fn test_run_invalid() {
        let tool = HostToIp::new();
        let args = ToolArgs::new(Some("invalid.hostname.that.does.not.exist".to_string()));
        let result = tool.run(args, None);

        assert!(result.is_err());
    }
}
