use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    pub target: String,
    pub start_port: u16,
    pub end_port: u16,
    pub timeout_ms: u64,
    pub concurrent_limit: usize,
    pub scan_mode: ScanMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanMode {
    Quick,
    Standard,
    Full,
    Custom,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            start_port: 1,
            end_port: 1024,
            timeout_ms: 300,
            concurrent_limit: 500,
            scan_mode: ScanMode::Standard,
        }
    }
}

impl PortScanConfig {
    pub fn get_ports(&self) -> Vec<u16> {
        match self.scan_mode {
            ScanMode::Quick => vec![
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
            ],
            ScanMode::Standard => (1..=1024).collect(),
            ScanMode::Full => (1..=65535).collect(),
            ScanMode::Custom => (self.start_port..=self.end_port).collect(),
        }
    }

    pub fn parse_targets(&self) -> Vec<String> {
        let mut targets = Vec::new();
        
        for part in self.target.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            
            if Self::is_cidr(part) {
                if let Ok(cidr_targets) = Self::parse_cidr(part) {
                    targets.extend(cidr_targets);
                }
            } else {
                targets.push(part.to_string());
            }
        }
        
        targets
    }

    pub fn is_ip_address(s: &str) -> bool {
        s.parse::<IpAddr>().is_ok()
    }

    pub fn is_cidr(s: &str) -> bool {
        s.contains('/') && s.split('/').count() == 2
    }

    pub fn parse_cidr(cidr: &str) -> Result<Vec<String>, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format".to_string());
        }

        let ip_str = parts[0];
        let prefix_len: u8 = parts[1].parse().map_err(|_| "Invalid prefix length")?;

        let ip: IpAddr = ip_str.parse().map_err(|_| "Invalid IP address")?;

        match ip {
            IpAddr::V4(ipv4) => {
                let prefix_len = prefix_len.min(32);
                Self::parse_ipv4_cidr(ipv4, prefix_len)
            }
            IpAddr::V6(_) => {
                Err("IPv6 CIDR not supported yet".to_string())
            }
        }
    }

    fn parse_ipv4_cidr(ip: std::net::Ipv4Addr, prefix_len: u8) -> Result<Vec<String>, String> {
        if prefix_len > 32 {
            return Err("Prefix length must be <= 32".to_string());
        }

        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        
        let network = ip_u32 & mask;
        let broadcast = network | !mask;

        let mut hosts = Vec::new();
        
        if prefix_len >= 31 {
            for addr in network..=broadcast {
                hosts.push(Self::u32_to_ipv4_string(addr));
            }
        } else {
            for addr in (network + 1)..broadcast {
                hosts.push(Self::u32_to_ipv4_string(addr));
            }
        }

        if hosts.len() > 65536 {
            return Err(format!("CIDR range too large ({} hosts). Maximum 65536 hosts allowed.", hosts.len()));
        }

        Ok(hosts)
    }

    fn u32_to_ipv4_string(addr: u32) -> String {
        let bytes = addr.to_be_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_parsing() {
        let hosts = PortScanConfig::parse_cidr("192.168.1.0/30").unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "192.168.1.1");
        assert_eq!(hosts[1], "192.168.1.2");
    }

    #[test]
    fn test_cidr_parsing_single() {
        let hosts = PortScanConfig::parse_cidr("192.168.1.100/32").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "192.168.1.100");
    }

    #[test]
    fn test_parse_targets_with_cidr() {
        let config = PortScanConfig {
            target: "192.168.1.0/30,example.com".to_string(),
            ..Default::default()
        };
        
        let targets = config.parse_targets();
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&"192.168.1.1".to_string()));
        assert!(targets.contains(&"192.168.1.2".to_string()));
        assert!(targets.contains(&"example.com".to_string()));
    }
}
