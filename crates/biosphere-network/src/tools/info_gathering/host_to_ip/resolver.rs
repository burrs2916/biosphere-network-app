use super::{ResolveConfig, ResolveResult, HostDnsRecord, HostInfo, HostSecurityFinding};
use crate::core::{ToolError, Result};
use std::net::ToSocketAddrs;

pub struct Resolver;

impl Resolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve(config: ResolveConfig) -> Result<ResolveResult> {
        let hostname = config.hostname.clone();
        
        let ip_addresses: Vec<std::net::IpAddr> = (hostname.as_str(), 0)
            .to_socket_addrs()
            .map_err(|e| ToolError::ExecutionError(format!("Failed to resolve hostname: {}", e)))?
            .map(|addr| addr.ip())
            .collect();

        let mut result = ResolveResult::new(hostname.clone(), ip_addresses.clone());

        if config.query_all_records {
            result.dns_records = Self::query_dns_records(&hostname);
        }

        if config.include_cname {
            result.cname = Self::query_cname(&hostname);
        }

        if config.include_reverse_dns {
            result.host_info = Self::build_host_info(&ip_addresses);
        }

        let (is_cdn, provider) = Self::detect_cdn(&hostname, &result.dns_records);
        result.is_cdn = is_cdn;
        result.cdn_provider = provider;

        result.security_findings = Self::analyze_security(&result);
        result.summary = Self::build_summary(&result);

        Ok(result)
    }

    fn query_dns_records(hostname: &str) -> Vec<HostDnsRecord> {
        let mut records = Vec::new();

        let a_records = (hostname, 0)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip().to_string()).collect::<Vec<_>>())
            .unwrap_or_default();

        for ip in a_records {
            records.push(HostDnsRecord {
                record_type: "A".to_string(),
                name: hostname.to_string(),
                value: ip,
                ttl: None,
            });
        }

        if let Ok(output) = std::process::Command::new("dig")
            .args(["+short", "MX", hostname])
            .output()
        {
            let mx_str = String::from_utf8_lossy(&output.stdout);
            for line in mx_str.lines().filter(|l| !l.is_empty()) {
                records.push(HostDnsRecord {
                    record_type: "MX".to_string(),
                    name: hostname.to_string(),
                    value: line.to_string(),
                    ttl: None,
                });
            }
        }

        if let Ok(output) = std::process::Command::new("dig")
            .args(["+short", "NS", hostname])
            .output()
        {
            let ns_str = String::from_utf8_lossy(&output.stdout);
            for line in ns_str.lines().filter(|l| !l.is_empty()) {
                records.push(HostDnsRecord {
                    record_type: "NS".to_string(),
                    name: hostname.to_string(),
                    value: line.to_string(),
                    ttl: None,
                });
            }
        }

        if let Ok(output) = std::process::Command::new("dig")
            .args(["+short", "TXT", hostname])
            .output()
        {
            let txt_str = String::from_utf8_lossy(&output.stdout);
            for line in txt_str.lines().filter(|l| !l.is_empty()) {
                records.push(HostDnsRecord {
                    record_type: "TXT".to_string(),
                    name: hostname.to_string(),
                    value: line.to_string(),
                    ttl: None,
                });
            }
        }

        if let Ok(output) = std::process::Command::new("dig")
            .args(["+short", "AAAA", hostname])
            .output()
        {
            let aaaa_str = String::from_utf8_lossy(&output.stdout);
            for line in aaaa_str.lines().filter(|l| !l.is_empty()) {
                records.push(HostDnsRecord {
                    record_type: "AAAA".to_string(),
                    name: hostname.to_string(),
                    value: line.to_string(),
                    ttl: None,
                });
            }
        }

        records
    }

    fn query_cname(hostname: &str) -> Option<String> {
        if let Ok(output) = std::process::Command::new("dig")
            .args(["+short", "CNAME", hostname])
            .output()
        {
            let cname_str = String::from_utf8_lossy(&output.stdout);
            let cname = cname_str.lines().next().unwrap_or("").trim().to_string();
            if !cname.is_empty() {
                return Some(cname);
            }
        }
        None
    }

    fn is_ip_private(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(v4) => v4.is_private(),
            std::net::IpAddr::V6(v6) => {
                let segs = v6.segments();
                segs[0] == 0xfc00 || segs[0] == 0xfd00
            }
        }
    }

    fn build_host_info(ip_addresses: &[std::net::IpAddr]) -> Vec<HostInfo> {
        ip_addresses.iter().map(|ip| {
            let ip_version = if ip.is_ipv4() { "IPv4".to_string() } else { "IPv6".to_string() };
            let is_private = Self::is_ip_private(ip);

            let reverse_dns = if let Ok(output) = std::process::Command::new("dig")
                .args(["+short", "-x", &ip.to_string()])
                .output()
            {
                let rdns = String::from_utf8_lossy(&output.stdout);
                let r = rdns.lines().next().unwrap_or("").trim().to_string();
                if r.is_empty() { None } else { Some(r.trim_end_matches('.').to_string()) }
            } else {
                None
            };

            HostInfo {
                ip: *ip,
                ip_version,
                reverse_dns,
                is_private,
                asn: None,
                country: None,
                org: None,
            }
        }).collect()
    }

    fn detect_cdn(hostname: &str, dns_records: &[HostDnsRecord]) -> (bool, Option<String>) {
        let cdn_indicators: [(&str, &str); 7] = [
            ("cloudflare", "CloudFlare"),
            ("akamai", "Akamai"),
            ("fastly", "Fastly"),
            ("cloudfront", "AWS CloudFront"),
            ("cdn", "Generic CDN"),
            ("edgekey", "Akamai"),
            ("cdn.cloudflare", "CloudFlare"),
        ];

        for record in dns_records {
            let val_lower = record.value.to_lowercase();
            for (indicator, provider) in &cdn_indicators {
                if val_lower.contains(indicator) {
                    return (true, Some(provider.to_string()));
                }
            }
        }

        if let Some(cname) = Self::query_cname(hostname) {
            let cname_lower = cname.to_lowercase();
            for (indicator, provider) in &cdn_indicators {
                if cname_lower.contains(indicator) {
                    return (true, Some(provider.to_string()));
                }
            }
        }

        (false, None)
    }

    fn analyze_security(result: &ResolveResult) -> Vec<HostSecurityFinding> {
        let mut findings = Vec::new();

        for info in &result.host_info {
            if info.is_private {
                findings.push(HostSecurityFinding {
                    severity: "medium".to_string(),
                    category: "私有IP".to_string(),
                    description: format!("主机 {} 解析到私有IP地址 {}", result.hostname, info.ip),
                    recommendation: "检查DNS配置是否正确，私有IP不应在公网DNS中暴露".to_string(),
                });
            }
        }

        if result.ip_addresses.len() > 4 {
            findings.push(HostSecurityFinding {
                severity: "low".to_string(),
                category: "多IP解析".to_string(),
                description: format!("主机 {} 解析到 {} 个IP地址，可能使用轮询DNS", result.hostname, result.ip_addresses.len()),
                recommendation: "多IP解析通常用于负载均衡，确认所有IP都是预期的".to_string(),
            });
        }

        let has_mx = result.dns_records.iter().any(|r| r.record_type == "MX");
        let has_spf = result.dns_records.iter().any(|r| r.record_type == "TXT" && r.value.contains("v=spf1"));
        if has_mx && !has_spf {
            findings.push(HostSecurityFinding {
                severity: "high".to_string(),
                category: "邮件安全".to_string(),
                description: format!("域名 {} 有MX记录但缺少SPF记录，可能遭受邮件伪造攻击", result.hostname),
                recommendation: "添加SPF TXT记录以防止邮件伪造".to_string(),
            });
        }

        let has_dmarc = result.dns_records.iter().any(|r| r.record_type == "TXT" && r.value.contains("v=DMARC"));
        if has_mx && !has_dmarc {
            findings.push(HostSecurityFinding {
                severity: "medium".to_string(),
                category: "邮件安全".to_string(),
                description: format!("域名 {} 有MX记录但缺少DMARC记录", result.hostname),
                recommendation: "添加DMARC TXT记录以增强邮件认证".to_string(),
            });
        }

        if result.is_cdn {
            findings.push(HostSecurityFinding {
                severity: "info".to_string(),
                category: "CDN检测".to_string(),
                description: format!("域名 {} 使用CDN服务 ({})", result.hostname, result.cdn_provider.as_deref().unwrap_or("未知")),
                recommendation: "使用CDN时注意源站IP保护，避免IP泄露".to_string(),
            });
        }

        findings
    }

    fn build_summary(result: &ResolveResult) -> String {
        let mut parts = Vec::new();

        parts.push(format!("主机 {} 解析到 {} 个IP地址", result.hostname, result.ip_addresses.len()));

        if !result.ip_addresses.is_empty() {
            let ips: Vec<String> = result.ip_addresses.iter().map(|ip: &std::net::IpAddr| ip.to_string()).collect();
            parts.push(format!("IP: {}", ips.join(", ")));
        }

        if let Some(ref cname) = result.cname {
            parts.push(format!("CNAME: {}", cname));
        }

        if result.is_cdn {
            parts.push(format!("CDN: {}", result.cdn_provider.as_deref().unwrap_or("检测到")));
        }

        let mut type_set = std::collections::HashSet::new();
        for r in &result.dns_records {
            type_set.insert(r.record_type.clone());
        }
        if !type_set.is_empty() {
            let types_str = type_set.into_iter().collect::<Vec<_>>().join(", ");
            parts.push(format!("DNS记录类型: {}", types_str));
        }

        if !result.security_findings.is_empty() {
            let high = result.security_findings.iter().filter(|f| f.severity == "high").count();
            let medium = result.security_findings.iter().filter(|f| f.severity == "medium").count();
            if high > 0 || medium > 0 {
                parts.push(format!("安全发现: {}个高危, {}个中危", high, medium));
            }
        }

        parts.join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_localhost() {
        let config = ResolveConfig::new("localhost".to_string());
        let result = Resolver::resolve(config).unwrap();
        
        assert!(!result.is_empty());
        assert!(result.to_string_list().contains(&"127.0.0.1".to_string()));
    }

    #[test]
    fn test_resolve_example() {
        let config = ResolveConfig::new("example.com".to_string());
        let result = Resolver::resolve(config).unwrap();
        
        assert!(!result.is_empty());
        assert!(result.count() > 0);
    }

    #[test]
    fn test_resolve_invalid() {
        let config = ResolveConfig::new("invalid.hostname.that.does.not.exist".to_string());
        let result = Resolver::resolve(config);
        
        assert!(result.is_err());
    }
}
