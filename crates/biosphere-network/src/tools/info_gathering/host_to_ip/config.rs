use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveConfig {
    pub hostname: String,
    pub timeout_ms: Option<u64>,
    pub query_all_records: bool,
    pub include_reverse_dns: bool,
    pub include_cname: bool,
}

impl ResolveConfig {
    pub fn new(hostname: String) -> Self {
        Self {
            hostname,
            timeout_ms: None,
            query_all_records: true,
            include_reverse_dns: true,
            include_cname: true,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub ip: IpAddr,
    pub ip_version: String,
    pub reverse_dns: Option<String>,
    pub is_private: bool,
    pub asn: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResult {
    pub hostname: String,
    pub ip_addresses: Vec<IpAddr>,
    pub host_info: Vec<HostInfo>,
    pub dns_records: Vec<HostDnsRecord>,
    pub cname: Option<String>,
    pub is_cdn: bool,
    pub cdn_provider: Option<String>,
    pub security_findings: Vec<HostSecurityFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

impl ResolveResult {
    pub fn new(hostname: String, ip_addresses: Vec<IpAddr>) -> Self {
        Self {
            hostname,
            ip_addresses,
            host_info: Vec::new(),
            dns_records: Vec::new(),
            cname: None,
            is_cdn: false,
            cdn_provider: None,
            security_findings: Vec::new(),
            summary: String::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ip_addresses.is_empty()
    }

    pub fn count(&self) -> usize {
        self.ip_addresses.len()
    }

    pub fn to_string_list(&self) -> Vec<String> {
        self.ip_addresses.iter().map(|ip| ip.to_string()).collect()
    }
}
