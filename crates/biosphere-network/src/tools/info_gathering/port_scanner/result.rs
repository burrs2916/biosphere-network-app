use serde::{Deserialize, Serialize};
use super::service_detect::ServiceVersion;
use super::os_detect::OSDetection;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub target: Option<String>,
    pub resolved_ip: Option<String>,
    pub all_resolved_ips: Option<Vec<String>>,
    pub port: u16,
    pub status: PortStatus,
    pub service: Option<String>,
    pub version: Option<ServiceVersion>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub resolved_ip: String,
    pub all_resolved_ips: Vec<String>,
    pub os_detection: Option<OSDetection>,
    pub open_ports: Vec<PortScanResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
}

impl PortScanResult {
    pub fn is_open(&self) -> bool {
        self.status == PortStatus::Open
    }

    pub fn has_version(&self) -> bool {
        self.version.is_some()
    }

    pub fn get_target_display(&self) -> String {
        match (&self.target, &self.all_resolved_ips) {
            (Some(target), Some(ips)) if !ips.is_empty() => {
                if target.parse::<std::net::IpAddr>().is_ok() {
                    target.clone()
                } else {
                    let ipv4: Vec<String> = ips.iter()
                        .filter(|ip| ip.parse::<std::net::IpAddr>()
                            .map(|i| i.is_ipv4())
                            .unwrap_or(false))
                        .cloned()
                        .collect();
                    
                    let ipv6: Vec<String> = ips.iter()
                        .filter(|ip| ip.parse::<std::net::IpAddr>()
                            .map(|i| i.is_ipv6())
                            .unwrap_or(false))
                        .cloned()
                        .collect();
                    
                    let mut display_ips = Vec::new();
                    if !ipv4.is_empty() {
                        display_ips.push(ipv4.join(", "));
                    }
                    if !ipv6.is_empty() {
                        display_ips.push(ipv6.join(", "));
                    }
                    
                    if display_ips.is_empty() {
                        target.clone()
                    } else {
                        format!("{} ({})", target, display_ips.join(" | "))
                    }
                }
            }
            (Some(target), None) => target.clone(),
            (None, Some(ips)) if !ips.is_empty() => ips[0].clone(),
            _ => "unknown".to_string(),
        }
    }

    pub fn get_service_display(&self) -> String {
        if let Some(ref version) = self.version {
            if !version.version.is_empty() {
                format!("{} ({})", version.service, version.version)
            } else {
                version.service.clone()
            }
        } else if let Some(ref service) = self.service {
            service.clone()
        } else {
            "unknown".to_string()
        }
    }

    pub fn get_version_display(&self) -> String {
        if let Some(ref version) = self.version {
            if !version.version.is_empty() {
                version.version.clone()
            } else {
                "unknown".to_string()
            }
        } else {
            "unknown".to_string()
        }
    }
}
