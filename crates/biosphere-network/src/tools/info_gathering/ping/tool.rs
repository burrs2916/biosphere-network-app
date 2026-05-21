use super::{PingConfig, Pinger};
use crate::core::{Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput, Result, ProgressReporter};

pub struct PingTool {
    info: ToolInfo,
}

impl PingTool {
    pub fn new() -> Self {
        Self {
            info: ToolInfo {
                id: "ping".to_string(),
                name: "Ping".to_string(),
                description: "Ping tool for testing network connectivity".to_string(),
                category: ToolCategory::InformationGathering,
                installed: true,
            },
        }
    }
}

impl Tool for PingTool {
    fn info(&self) -> ToolInfo {
        self.info.clone()
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let target = args.get_target()?;
        
        let count = args.get_option("count")
            .and_then(|c| c.parse::<u32>().ok())
            .unwrap_or(4);
        
        let timeout = args.get_option("timeout")
            .and_then(|t| t.parse::<u64>().ok())
            .unwrap_or(2);
        
        let interval = args.get_option("interval")
            .and_then(|i| i.parse::<u64>().ok())
            .unwrap_or(1);
        
        let packet_size = args.get_option("packet_size")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(64);

        let config = PingConfig::new(target.clone())
            .with_count(count)
            .with_timeout(timeout)
            .with_interval(interval)
            .with_packet_size(packet_size);

        let result = Pinger::ping(config)?;

        let output = if result.is_success() {
            ToolOutput::success(serde_json::to_string(&result).unwrap_or_default())
        } else {
            ToolOutput::error(result.error_message.unwrap_or_else(|| "Ping failed".to_string()))
        };

        Ok(output)
    }
}

impl Default for PingTool {
    fn default() -> Self {
        Self::new()
    }
}
