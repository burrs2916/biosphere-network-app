pub mod port_scanner;
pub mod host_to_ip;
pub mod dns_query;
pub mod ping;
pub mod target_manager;
pub mod whois;

pub use port_scanner::{
    PortScanner, PortScanConfig, PortScanResult, PortStatus, ScanMode, Scanner, ServiceVersion, OSDetection,
    request_cancel, is_cancelled, reset_cancel,
};
pub use host_to_ip::{HostToIp, ResolveConfig, ResolveResult, Resolver, HostDnsRecord, HostInfo, HostSecurityFinding};
pub use dns_query::{DnsQueryTool, DnsQueryConfig, DnsQueryResult, DnsQueryType, DnsResolver};
pub use ping::{PingTool, PingConfig, PingResult, Pinger};
pub use target_manager::{TargetManagerTool, TargetManager, TargetConfig, TargetInfo, TargetListResult, TargetOperationResult, TargetType, TargetCategory, TargetGroup, TargetGroupWithTargets, TargetService};
pub use whois::{WhoisTool, WhoisConfig, WhoisResult, WhoisResolver, query_whois};

// 未来扩展的工具模块（预留）
// pub mod network_mapper;
// pub mod osint_scanner;
// pub mod subdomain_scanner;
