use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseIpConfig {
    pub ip: String,
    pub timeout: u64,
    pub include_dns_history: bool,
    pub include_subdomains: bool,
}

impl Default for ReverseIpConfig {
    fn default() -> Self {
        Self {
            ip: String::new(),
            timeout: 30,
            include_dns_history: true,
            include_subdomains: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseIpResult {
    pub success: bool,
    pub ip: String,
    pub domains: Vec<ReverseDomain>,
    pub dns_history: Vec<DnsHistoryEntry>,
    pub related_ips: Vec<RelatedIp>,
    pub security_findings: Vec<ReverseIpFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseDomain {
    pub domain: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub record_type: String,
    pub is_active: bool,
    pub is_subdomain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryEntry {
    pub domain: String,
    pub ip: String,
    pub record_type: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedIp {
    pub ip: String,
    pub relationship: String,
    pub domains: Vec<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseIpFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

pub struct ReverseIpTool;

impl ReverseIpTool {
    pub async fn lookup(config: &ReverseIpConfig) -> std::result::Result<ReverseIpResult, String> {
        if config.ip.is_empty() {
            return Err("IP address is required".to_string());
        }

        let ip = config.ip.trim().to_string();

        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("Invalid IP address: {}", ip));
        }

        let mut domains = Vec::new();
        let mut dns_history = Vec::new();
        
        let mut findings = Vec::new();

        let reverse_name = Self::reverse_dns_lookup(&ip);
        if let Some(name) = &reverse_name {
            domains.push(ReverseDomain {
                domain: name.clone(),
                first_seen: None,
                last_seen: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                record_type: "PTR".to_string(),
                is_active: true,
                is_subdomain: false,
            });
        }

        let virtual_hosts = Self::lookup_virtual_hosts(&ip).await;
        domains.extend(virtual_hosts);

        if config.include_subdomains {
            let subdomains = Self::discover_subdomains(&ip);
            domains.extend(subdomains);
        }

        if config.include_dns_history {
            dns_history = Self::get_dns_history(&ip);
        }

        let related_ips: Vec<RelatedIp> = Self::find_related_ips(&ip);

        Self::analyze_security(&ip, &domains, &related_ips, &mut findings);

        let active_count = domains.iter().filter(|d| d.is_active).count();
        let subdomain_count = domains.iter().filter(|d| d.is_subdomain).count();

        let summary = format!(
            "Reverse IP lookup completed | IP: {} | Domains: {} | Active: {} | Subdomains: {} | Related IPs: {}",
            ip, domains.len(), active_count, subdomain_count, related_ips.len()
        );

        Ok(ReverseIpResult {
            success: true,
            ip,
            domains,
            dns_history,
            related_ips,
            security_findings: findings,
            summary,
        })
    }

    fn reverse_dns_lookup(ip: &str) -> Option<String> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if let Ok(output) = std::process::Command::new("dig")
                .args(["-x", ip, "+short"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && trimmed.contains('.') {
                        return Some(trimmed.trim_end_matches('.').to_string());
                    }
                }
            }

            if let Ok(output) = std::process::Command::new("host")
                .arg(ip)
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(pos) = line.find("domain name pointer ") {
                        let domain = &line[pos + 20..];
                        let domain = domain.trim().trim_end_matches('.').trim_end_matches(';');
                        if !domain.is_empty() && domain.contains('.') {
                            return Some(domain.to_string());
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("nslookup")
                .arg(ip)
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(pos) = line.find("name = ") {
                        let domain = &line[pos + 7..];
                        let domain = domain.trim().trim_end_matches('.').trim_end_matches(';');
                        if !domain.is_empty() && domain.contains('.') {
                            return Some(domain.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    async fn lookup_virtual_hosts(ip: &str) -> Vec<ReverseDomain> {
        let mut domains = Vec::new();

        if let Ok(resp) = Self::http_get(&format!(
            "https://api.hackertarget.com/reverseiplookup/?q={}",
            ip
        ))
        .await
        {
            for line in resp.lines() {
                let domain = line.trim().to_string();
                if domain.is_empty() || !domain.contains('.') {
                    continue;
                }
                if domain.starts_with("error") || domain.starts_with("API") {
                    continue;
                }
                let is_subdomain = domain.matches('.').count() > 1;
                domains.push(ReverseDomain {
                    domain: domain.clone(),
                    first_seen: None,
                    last_seen: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                    record_type: "A".to_string(),
                    is_active: true,
                    is_subdomain,
                });
            }
        }

        if domains.is_empty() {
            if let Ok(resp) = Self::http_get(&format!(
                "https://rapiddns.io/sameip/{}#result",
                ip
            ))
            .await
            {
                for line in resp.lines() {
                    let domain = line.trim().to_string();
                    if domain.is_empty() || !domain.contains('.') || domain.contains(' ') {
                        continue;
                    }
                    if domain.starts_with("http") || domain.starts_with('<') || domain.starts_with('/') {
                        continue;
                    }
                    let is_subdomain = domain.matches('.').count() > 1;
                    domains.push(ReverseDomain {
                        domain: domain.clone(),
                        first_seen: None,
                        last_seen: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                        record_type: "A".to_string(),
                        is_active: true,
                        is_subdomain,
                    });
                }
            }
        }

        domains.truncate(100);
        domains
    }

    fn discover_subdomains(ip: &str) -> Vec<ReverseDomain> {
        let mut domains = Vec::new();

        let reverse_name = Self::reverse_dns_lookup(ip);
        if let Some(base_domain) = &reverse_name {
            let parts: Vec<&str> = base_domain.split('.').collect();
            let domain_root = if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                base_domain.clone()
            };

            let common_prefixes = [
                "www", "mail", "ftp", "api", "admin", "blog", "dev",
                "staging", "test", "cdn", "ns1", "ns2", "mx", "vpn",
                "portal", "app", "git", "ci", "jenkins", "db",
            ];

            for prefix in &common_prefixes {
                let subdomain = format!("{}.{}", prefix, domain_root);
                if let Ok(output) = std::process::Command::new("dig")
                    .args(["+short", &subdomain, "A"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let resolved_ip = line.trim();
                        if resolved_ip == ip {
                            domains.push(ReverseDomain {
                                domain: subdomain.clone(),
                                first_seen: None,
                                last_seen: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                                record_type: "A".to_string(),
                                is_active: true,
                                is_subdomain: true,
                            });
                            break;
                        }
                    }
                }
            }
        }

        domains.truncate(50);
        domains
    }

    fn get_dns_history(ip: &str) -> Vec<DnsHistoryEntry> {
        let mut history = Vec::new();

        if let Ok(output) = std::process::Command::new("dig")
            .args(["-x", ip, "+short"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let domain = line.trim().trim_end_matches('.').to_string();
                if !domain.is_empty() && domain.contains('.') {
                    history.push(DnsHistoryEntry {
                        domain: domain.clone(),
                        ip: ip.to_string(),
                        record_type: "A".to_string(),
                        first_seen: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                        last_seen: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                    });
                }
            }
        }

        if let Ok(output) = std::process::Command::new("dig")
            .args(["-x", ip, "ANY", "+short"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts.contains(&"PTR") {
                    let domain = parts.last().unwrap_or(&"").trim_end_matches('.').to_string();
                    if !domain.is_empty() && domain.contains('.')
                        && !history.iter().any(|h| h.domain == domain) {
                            history.push(DnsHistoryEntry {
                                domain: domain.clone(),
                                ip: ip.to_string(),
                                record_type: "PTR".to_string(),
                                first_seen: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                                last_seen: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                            });
                        }
                }
            }
        }

        history
    }

    fn find_related_ips(ip: &str) -> Vec<RelatedIp> {
        let mut related = Vec::new();
        let parts: Vec<&str> = ip.split('.').collect();

        if parts.len() != 4 {
            return related;
        }

        let base = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

        let nearby_offsets: [i32; 6] = [1, 2, 3, -1, -2, -3];
        for offset in &nearby_offsets {
            let last: i32 = parts[3].parse().unwrap_or(0);
            let candidate = last + offset;
            if candidate <= 0 || candidate > 254 {
                continue;
            }
            let candidate_ip = format!("{}.{}", base, candidate);
            if candidate_ip == ip {
                continue;
            }

            let mut domains_for_ip = Vec::new();
            let mut asn_info = None;
            let mut org_info = None;

            if let Ok(output) = std::process::Command::new("dig")
                .args(["-x", &candidate_ip, "+short"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let domain = line.trim().trim_end_matches('.').to_string();
                    if !domain.is_empty() && domain.contains('.') {
                        domains_for_ip.push(domain);
                    }
                }
            }

            if let Ok(output) = std::process::Command::new("whois")
                .arg(&candidate_ip)
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let lower = line.to_lowercase();
                    if lower.starts_with("origin:") || lower.starts_with("as:") {
                        let val = line.split(':').nth(1).map(|v| v.trim().to_string());
                        if let Some(asn) = val {
                            if !asn.is_empty() {
                                asn_info = Some(asn);
                            }
                        }
                    }
                    if lower.starts_with("org-name:") || lower.starts_with("organization:") || lower.starts_with("netname:") {
                        let val = line.split(':').nth(1).map(|v| v.trim().to_string());
                        if let Some(org) = val {
                            if !org.is_empty() && org_info.is_none() {
                                org_info = Some(org);
                            }
                        }
                    }
                }
            }

            let has_info = !domains_for_ip.is_empty() || asn_info.is_some() || org_info.is_some();
            if has_info {
                related.push(RelatedIp {
                    ip: candidate_ip,
                    relationship: "Same C-class".to_string(),
                    domains: domains_for_ip,
                    asn: asn_info,
                    org: org_info,
                });
            }
        }

        related.truncate(20);
        related
    }

    fn analyze_security(ip: &str, domains: &[ReverseDomain], related_ips: &[RelatedIp], findings: &mut Vec<ReverseIpFinding>) {
        if domains.len() > 10 {
            findings.push(ReverseIpFinding {
                severity: "medium".to_string(),
                category: "Virtual Host Overload".to_string(),
                description: format!("This IP address is associated with {} domains, which may indicate virtual hosting security risks", domains.len()),
                recommendation: "Review security configuration of all virtual hosts, ensure proper isolation".to_string(),
            });
        }

        let inactive_count = domains.iter().filter(|d| !d.is_active).count();
        if inactive_count > 3 {
            findings.push(ReverseIpFinding {
                severity: "low".to_string(),
                category: "Dormant Domains".to_string(),
                description: format!("{} inactive domains found pointing to this IP, potential subdomain takeover risk", inactive_count),
                recommendation: "Remove DNS records for inactive domains or repoint them to prevent takeover".to_string(),
            });
        }

        let subdomain_count = domains.iter().filter(|d| d.is_subdomain).count();
        if subdomain_count > 5 {
            findings.push(ReverseIpFinding {
                severity: "low".to_string(),
                category: "Subdomain Exposure".to_string(),
                description: format!("{} subdomains found on this IP, expanding the attack surface", subdomain_count),
                recommendation: "Minimize exposed subdomains, use wildcard certificates carefully".to_string(),
            });
        }

        let is_private = ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("172.17.")
            || ip.starts_with("172.18.")
            || ip.starts_with("172.19.")
            || ip.starts_with("172.2")
            || ip.starts_with("172.3")
            || ip.starts_with("127.");
        if is_private && !domains.is_empty() {
            findings.push(ReverseIpFinding {
                severity: "info".to_string(),
                category: "Private IP".to_string(),
                description: format!("IP {} is a private/internal address with {} associated domains", ip, domains.len()),
                recommendation: "Private IPs should not be publicly resolvable, check DNS configuration".to_string(),
            });
        }

        if related_ips.len() > 5 {
            findings.push(ReverseIpFinding {
                severity: "info".to_string(),
                category: "Dense Network".to_string(),
                description: format!("{} related IPs found in the same C-class segment, indicating a dense hosting environment", related_ips.len()),
                recommendation: "Assess the security posture of neighboring hosts".to_string(),
            });
        }

        findings.truncate(20);
    }

    async fn http_get(url: &str) -> std::result::Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client
            .get(url)
            .header("User-Agent", "BiosPherePro/1.0")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        resp.text().await.map_err(|e| e.to_string())
    }
}
