use super::{PortScanConfig, PortScanResult, ScanMode, Scanner};
use crate::core::{ProgressReporter, Result, Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput};

pub struct PortScanner;

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PortScanner {
    pub fn new() -> Self {
        Self
    }
}

impl Tool for PortScanner {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            id: "port_scanner".to_string(),
            name: "Port Scanner".to_string(),
            description: "Fast asynchronous TCP port scanner with service detection and banner grabbing. Supports multiple targets (comma-separated) and domain name resolution.".to_string(),
            category: ToolCategory::InformationGathering,
            installed: true,
        }
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let target = args.get_target()?.clone();

        let start_port = args.get_option("start_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let end_port = args.get_option("end_port")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024);

        let timeout_ms = args.get_option("timeout_ms")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let scan_mode = args.get_option("scan_mode")
            .and_then(|s| match s.as_str() {
                "quick" => Some(ScanMode::Quick),
                "standard" => Some(ScanMode::Standard),
                "full" => Some(ScanMode::Full),
                "custom" => Some(ScanMode::Custom),
                _ => None,
            })
            .unwrap_or(ScanMode::Standard);

        let config = PortScanConfig {
            target: target.clone(),
            start_port,
            end_port,
            timeout_ms,
            concurrent_limit: 100,
            scan_mode,
        };

        let scanner = Scanner::new(config);
        
        let results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(scanner.scan())
        })?;

        let open_ports: Vec<&PortScanResult> = results.iter()
            .filter(|r| r.is_open())
            .collect();

        let targets: Vec<&str> = target.split(',').map(|s| s.trim()).collect();
        let is_multi_target = targets.len() > 1;
        
        let output = if open_ports.is_empty() {
            if is_multi_target {
                format!("No open ports found on {} targets", targets.len())
            } else {
                format!("No open ports found on {}", target)
            }
        } else {
            let mut output = if is_multi_target {
                format!("Open ports on {} targets:\n\n", targets.len())
            } else {
                format!("Open ports on {}:\n\n", target)
            };
            
            let mut current_target: Option<String> = None;
            
            for result in open_ports {
                if is_multi_target {
                    let target_display = result.get_target_display();
                    if current_target.as_ref() != Some(&target_display) {
                        output.push_str(&format!("[{}]\n", target_display));
                        current_target = Some(target_display);
                    }
                }
                
                output.push_str(&format!(
                    "Port {:5} - {:?}  {}\n",
                    result.port,
                    result.status,
                    result.get_service_display()
                ));
            }
            output
        };

        Ok(ToolOutput::success(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_info() {
        let scanner = PortScanner::new();
        let info = scanner.info();
        
        assert_eq!(info.id, "port_scanner");
        assert_eq!(info.name, "Port Scanner");
        assert_eq!(info.category, ToolCategory::InformationGathering);
    }
}
