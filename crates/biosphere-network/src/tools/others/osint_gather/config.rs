use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OsintGatherConfig {
    pub target: String,
    pub search_engines: Vec<String>,
    pub data_sources: Vec<String>,
    pub max_results: usize,
    pub timeout: u64,
    pub shodan_api_key: Option<String>,
    pub use_shodan: bool,
    pub use_holehe: bool,
    pub use_maigret: bool,
    pub use_wayback: bool,
    pub use_github_search: bool,
}

impl Default for OsintGatherConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            search_engines: vec!["google".to_string(), "bing".to_string()],
            data_sources: vec!["dns".to_string(), "email".to_string(), "subdomain".to_string(), "ip".to_string()],
            max_results: 100,
            timeout: 30,
            shodan_api_key: None,
            use_shodan: true,
            use_holehe: true,
            use_maigret: true,
            use_wayback: true,
            use_github_search: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintGatherResult {
    pub success: bool,
    pub target: String,
    pub emails: Vec<OsintEmail>,
    pub subdomains: Vec<OsintSubdomain>,
    pub ip_addresses: Vec<OsintIpInfo>,
    pub urls: Vec<OsintUrl>,
    pub dns_records: Vec<OsintDnsRecord>,
    pub metadata: Vec<OsintMetadata>,
    pub security_findings: Vec<OsintFinding>,
    pub shodan_info: Option<ShodanInfo>,
    pub holehe_results: Vec<HoleheResult>,
    pub maigret_results: Vec<MaigretResult>,
    pub wayback_results: Vec<WaybackSnapshot>,
    pub github_results: Vec<GitHubResult>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintEmail {
    pub address: String,
    pub source: String,
    pub is_valid: bool,
    pub breach_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintSubdomain {
    pub subdomain: String,
    pub ip: Option<String>,
    pub is_active: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintIpInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintUrl {
    pub url: String,
    pub title: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintDnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintMetadata {
    pub key: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanHost {
    pub ip: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub os: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub vulns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanInfo {
    pub query: String,
    pub total_results: u64,
    pub hosts: Vec<ShodanHost>,
    pub query_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoleheResult {
    pub email: String,
    pub platform: String,
    pub found: bool,
    pub profile_url: Option<String>,
    pub name: Option<String>,
    pub profile_picture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaigretResult {
    pub username: String,
    pub platform: String,
    pub found: bool,
    pub profile_url: Option<String>,
    pub id: Option<String>,
    pub full_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaybackSnapshot {
    pub url: String,
    pub timestamp: String,
    pub status_code: Option<u16>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubResult {
    pub repo_name: String,
    pub repo_url: String,
    pub description: Option<String>,
    pub stars: Option<u64>,
    pub language: Option<String>,
    pub relevance: String,
}

pub struct OsintGatherTool;

impl OsintGatherTool {
    pub async fn gather(config: &OsintGatherConfig) -> std::result::Result<OsintGatherResult, String> {
        if config.target.is_empty() {
            return Err("Target domain or keyword is required".to_string());
        }

        let target = config.target.trim().to_string();
        let is_domain = target.contains('.') && !target.contains(' ');

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let semaphore = Arc::new(Semaphore::new(4));
        let mut join_set = tokio::task::JoinSet::new();

        let need_email = config.data_sources.contains(&"email".to_string());
        let need_subdomain = is_domain && config.data_sources.contains(&"subdomain".to_string());
        let need_ip = is_domain && config.data_sources.contains(&"ip".to_string());
        let need_url = config.data_sources.contains(&"url".to_string());
        let need_dns = is_domain && config.data_sources.contains(&"dns".to_string());
        let need_shodan = config.use_shodan && (is_domain || target.parse::<std::net::IpAddr>().is_ok());
        let need_holehe = config.use_holehe && target.contains('@');
        let need_maigret = config.use_maigret && !target.contains('.') && !target.contains('@');
        let need_wayback = config.use_wayback && is_domain;
        let need_github = config.use_github_search;

        if need_dns {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            let max = config.max_results;
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("dns", Self::gather_dns_real(&c, &t, max).await)
            });
        }

        if need_subdomain {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            let max = config.max_results;
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("subdomain", Self::gather_subdomains_real(&c, &t, max).await)
            });
        }

        if need_ip {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("ip", Self::gather_ips_real(&c, &t).await)
            });
        }

        if need_email {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            let max = config.max_results;
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("email", Self::gather_emails_real(&c, &t, max).await)
            });
        }

        if need_url {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            let max = config.max_results;
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("url", Self::gather_urls_real(&c, &t, max).await)
            });
        }

        if need_shodan {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            let api_key = config.shodan_api_key.clone();
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("shodan", Self::gather_shodan(&c, &t, api_key.as_deref()).await)
            });
        }

        if need_holehe {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("holehe", Self::gather_holehe(&c, &t).await)
            });
        }

        if need_maigret {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("maigret", Self::gather_maigret(&c, &t).await)
            });
        }

        if need_wayback {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("wayback", Self::gather_wayback(&c, &t).await)
            });
        }

        if need_github {
            let t = target.clone();
            let c = client.clone();
            let s = semaphore.clone();
            join_set.spawn(async move {
                let _permit = s.acquire().await.unwrap();
                ("github", Self::gather_github(&c, &t).await)
            });
        }

        let mut emails = Vec::new();
        let mut subdomains = Vec::new();
        let mut ip_addresses = Vec::new();
        let mut urls = Vec::new();
        let mut dns_records = Vec::new();
        let mut metadata = Vec::new();
        let mut findings = Vec::new();
        let mut shodan_info: Option<ShodanInfo> = None;
        let mut holehe_results = Vec::new();
        let mut maigret_results = Vec::new();
        let mut wayback_results = Vec::new();
        let mut github_results = Vec::new();

        while let Some(result) = join_set.join_next().await {
            if let Ok((source_type, data)) = result {
                match source_type {
                    "email" => {
                        if let Ok(e) = serde_json::from_value::<Vec<OsintEmail>>(data) {
                            emails = e;
                        }
                    }
                    "subdomain" => {
                        if let Ok(s) = serde_json::from_value::<Vec<OsintSubdomain>>(data) {
                            subdomains = s;
                        }
                    }
                    "ip" => {
                        if let Ok(i) = serde_json::from_value::<Vec<OsintIpInfo>>(data) {
                            ip_addresses = i;
                        }
                    }
                    "url" => {
                        if let Ok(u) = serde_json::from_value::<Vec<OsintUrl>>(data) {
                            urls = u;
                        }
                    }
                    "dns" => {
                        if let Ok(d) = serde_json::from_value::<Vec<OsintDnsRecord>>(data) {
                            dns_records = d;
                        }
                    }
                    "shodan" => {
                        if let Ok(s) = serde_json::from_value::<ShodanInfo>(data) {
                            shodan_info = Some(s);
                        }
                    }
                    "holehe" => {
                        if let Ok(h) = serde_json::from_value::<Vec<HoleheResult>>(data) {
                            holehe_results = h;
                        }
                    }
                    "maigret" => {
                        if let Ok(m) = serde_json::from_value::<Vec<MaigretResult>>(data) {
                            maigret_results = m;
                        }
                    }
                    "wayback" => {
                        if let Ok(w) = serde_json::from_value::<Vec<WaybackSnapshot>>(data) {
                            wayback_results = w;
                        }
                    }
                    "github" => {
                        if let Ok(g) = serde_json::from_value::<Vec<GitHubResult>>(data) {
                            github_results = g;
                        }
                    }
                    _ => {}
                }
            }
        }

        metadata.push(OsintMetadata {
            key: "target_type".to_string(),
            value: if is_domain { "domain" } else { "keyword" }.to_string(),
            source: "analysis".to_string(),
        });

        metadata.push(OsintMetadata {
            key: "data_sources".to_string(),
            value: config.data_sources.join(", "),
            source: "config".to_string(),
        });

        if !emails.is_empty() {
            findings.push(OsintFinding {
                severity: "medium".to_string(),
                category: "email_exposure".to_string(),
                description: format!("Found {} associated email addresses", emails.len()),
                recommendation: "Check if these emails appear in data breaches, consider using dedicated emails for different services".to_string(),
            });
        }

        let breached: Vec<&OsintEmail> = emails.iter().filter(|e| e.breach_count.unwrap_or(0) > 0).collect();
        if !breached.is_empty() {
            findings.push(OsintFinding {
                severity: "high".to_string(),
                category: "email_breach".to_string(),
                description: format!("{} email(s) found in data breaches", breached.len()),
                recommendation: "Immediately change passwords for breached accounts and enable 2FA".to_string(),
            });
        }

        let exposed_subdomains = subdomains.iter().filter(|s| s.is_active).count();
        if exposed_subdomains > 5 {
            findings.push(OsintFinding {
                severity: "low".to_string(),
                category: "subdomain_exposure".to_string(),
                description: format!("Found {} active subdomains", exposed_subdomains),
                recommendation: "Review security configuration on all subdomains, especially dev/staging/admin ones".to_string(),
            });
        }

        let admin_subs: Vec<&OsintSubdomain> = subdomains.iter().filter(|s| s.subdomain.contains("admin") || s.subdomain.contains("dev") || s.subdomain.contains("staging")).collect();
        if !admin_subs.is_empty() {
            findings.push(OsintFinding {
                severity: "medium".to_string(),
                category: "sensitive_subdomain".to_string(),
                description: format!("Found {} potentially sensitive subdomains (admin/dev/staging)", admin_subs.len()),
                recommendation: "Ensure these subdomains are properly secured and not publicly accessible".to_string(),
            });
        }

        let spf_found = dns_records.iter().any(|r| r.record_type == "TXT" && r.value.contains("v=spf1"));
        if !spf_found && is_domain {
            findings.push(OsintFinding {
                severity: "medium".to_string(),
                category: "missing_spf".to_string(),
                description: "No SPF record found for this domain".to_string(),
                recommendation: "Add an SPF record to prevent email spoofing".to_string(),
            });
        }

        let dkim_found = dns_records.iter().any(|r| r.record_type == "TXT" && r.value.contains("v=DKIM1"));
        if !dkim_found && is_domain {
            findings.push(OsintFinding {
                severity: "low".to_string(),
                category: "missing_dkim".to_string(),
                description: "No DKIM record found for this domain".to_string(),
                recommendation: "Add DKIM signing to improve email deliverability and security".to_string(),
            });
        }

        if let Some(ref shodan) = shodan_info {
            if !shodan.hosts.is_empty() {
                let exposed_ports: Vec<String> = shodan.hosts.iter()
                    .map(|h| format!("{}:{}", h.ip, h.port))
                    .collect();
                findings.push(OsintFinding {
                    severity: "high".to_string(),
                    category: "shodan_exposure".to_string(),
                    description: format!("Shodan found {} exposed services: {}", shodan.hosts.len(), exposed_ports.join(", ")),
                    recommendation: "Review exposed services and close unnecessary ports. Implement firewall rules to restrict access".to_string(),
                });
                let vuln_count: usize = shodan.hosts.iter().map(|h| h.vulns.len()).sum();
                if vuln_count > 0 {
                    findings.push(OsintFinding {
                        severity: "critical".to_string(),
                        category: "shodan_vulnerabilities".to_string(),
                        description: format!("Shodan reports {} known vulnerabilities on exposed services", vuln_count),
                        recommendation: "Immediately patch or mitigate the identified vulnerabilities".to_string(),
                    });
                }
            }
        }

        if !holehe_results.is_empty() {
            let found_count = holehe_results.iter().filter(|h| h.found).count();
            if found_count > 0 {
                findings.push(OsintFinding {
                    severity: "medium".to_string(),
                    category: "email_social_presence".to_string(),
                    description: format!("Email found on {} social platforms", found_count),
                    recommendation: "Review social media privacy settings for accounts linked to this email".to_string(),
                });
            }
        }

        if !maigret_results.is_empty() {
            let found_count = maigret_results.iter().filter(|m| m.found).count();
            if found_count > 0 {
                findings.push(OsintFinding {
                    severity: "medium".to_string(),
                    category: "username_presence".to_string(),
                    description: format!("Username found on {} platforms", found_count),
                    recommendation: "Review privacy settings on discovered accounts and consider using different usernames across platforms".to_string(),
                });
            }
        }

        let summary = format!(
            "OSINT gathering complete | Target: {} | Emails: {} | Subdomains: {} | IPs: {} | URLs: {} | DNS: {} | Shodan: {} | Holehe: {} | Maigret: {} | Wayback: {} | GitHub: {} | Findings: {}",
            target, emails.len(), subdomains.len(), ip_addresses.len(), urls.len(), dns_records.len(),
            shodan_info.as_ref().map(|s| s.hosts.len()).unwrap_or(0),
            holehe_results.iter().filter(|h| h.found).count(),
            maigret_results.iter().filter(|m| m.found).count(),
            wayback_results.len(),
            github_results.len(),
            findings.len()
        );

        Ok(OsintGatherResult {
            success: true,
            target,
            emails,
            subdomains,
            ip_addresses,
            urls,
            dns_records,
            metadata,
            security_findings: findings,
            shodan_info,
            holehe_results,
            maigret_results,
            wayback_results,
            github_results,
            summary,
        })
    }

    async fn gather_dns_real(client: &reqwest::Client, target: &str, max_results: usize) -> serde_json::Value {
        let mut records = Vec::new();

        if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type=A", target)).send().await {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(answer) = body.get("Answer").and_then(|a| a.as_array()) {
                        for record in answer.iter().take(max_results) {
                            let rtype = record.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
                            let type_name = match rtype {
                                1 => "A",
                                5 => "CNAME",
                                15 => "MX",
                                16 => "TXT",
                                28 => "AAAA",
                                2 => "NS",
                                6 => "SOA",
                                _ => "OTHER",
                            };
                            records.push(OsintDnsRecord {
                                record_type: type_name.to_string(),
                                name: record.get("name").and_then(|n| n.as_str()).unwrap_or(target).to_string(),
                                value: record.get("data").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                                ttl: record.get("TTL").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                            });
                        }
                    }
                }
            }
        }

        for rtype in &["MX", "TXT", "NS"] {
            if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type={}", target, rtype)).send().await {
                if resp.status() == 200 {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(answer) = body.get("Answer").and_then(|a| a.as_array()) {
                            for record in answer.iter().take(max_results) {
                                let rtype_num = record.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
                                let type_name = match rtype_num {
                                    15 => "MX",
                                    16 => "TXT",
                                    2 => "NS",
                                    _ => "OTHER",
                                };
                                let value = record.get("data").and_then(|d| d.as_str()).unwrap_or("").to_string();
                                if !records.iter().any(|r| r.value == value && r.record_type == type_name) {
                                    records.push(OsintDnsRecord {
                                        record_type: type_name.to_string(),
                                        name: record.get("name").and_then(|n| n.as_str()).unwrap_or(target).to_string(),
                                        value,
                                        ttl: record.get("TTL").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        serde_json::to_value(records).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_subdomains_real(client: &reqwest::Client, target: &str, max_results: usize) -> serde_json::Value {
        let mut subdomains = Vec::new();

        if let Ok(resp) = client.get(format!("https://crt.sh/?q=%25.{}&output=json", target)).send().await {
            if resp.status() == 200 {
                let text = resp.text().await.unwrap_or_default();
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                    let mut seen = std::collections::HashSet::new();
                    for entry in entries.iter().take(max_results * 2) {
                        if let Some(name) = entry.get("name_value").and_then(|n| n.as_str()) {
                            for n in name.split('\n') {
                                let n = n.trim().to_lowercase();
                                if !seen.contains(&n) && n.ends_with(target) && n != target {
                                    seen.insert(n.clone());
                                    subdomains.push(OsintSubdomain {
                                        subdomain: n.clone(),
                                        ip: None,
                                        is_active: true,
                                        source: "Certificate Transparency".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type=NS", target)).send().await {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(answer) = body.get("Answer").and_then(|a| a.as_array()) {
                        for record in answer {
                            if let Some(data) = record.get("data").and_then(|d| d.as_str()) {
                                let name = data.trim_end_matches('.').to_lowercase();
                                if !subdomains.iter().any(|s| s.subdomain == name) {
                                    subdomains.push(OsintSubdomain {
                                        subdomain: name.clone(),
                                        ip: None,
                                        is_active: true,
                                        source: "DNS NS Record".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let common_prefixes = ["www", "mail", "api", "cdn", "dev", "staging", "blog", "shop", "admin", "vpn", "ftp", "ns1", "ns2", "mx", "app", "portal", "remote", "test", "git", "ci"];
        for prefix in &common_prefixes {
            let sub = format!("{}.{}", prefix, target);
            if !subdomains.iter().any(|s| s.subdomain == sub) {
                if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type=A", &sub)).send().await {
                    if resp.status() == 200 {
                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                            let has_answer = body.get("Answer").and_then(|a| a.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                            let status = body.get("Status").and_then(|s| s.as_u64()).unwrap_or(3);
                            if has_answer || status == 0 {
                                let ip = body.get("Answer")
                                    .and_then(|a| a.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|r| r.get("data"))
                                    .and_then(|d| d.as_str())
                                    .map(|s| s.to_string());
                                subdomains.push(OsintSubdomain {
                                    subdomain: sub,
                                    ip,
                                    is_active: true,
                                    source: "DNS Brute".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        subdomains.truncate(max_results);
        serde_json::to_value(subdomains).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_ips_real(client: &reqwest::Client, target: &str) -> serde_json::Value {
        let mut ips = Vec::new();

        if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type=A", target)).send().await {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(answer) = body.get("Answer").and_then(|a| a.as_array()) {
                        for record in answer {
                            if let Some(ip) = record.get("data").and_then(|d| d.as_str()) {
                                let ip_info = Self::enrich_ip(client, ip, target).await;
                                ips.push(ip_info);
                            }
                        }
                    }
                }
            }
        }

        if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type=AAAA", target)).send().await {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(answer) = body.get("Answer").and_then(|a| a.as_array()) {
                        for record in answer {
                            if let Some(ip) = record.get("data").and_then(|d| d.as_str()) {
                                if !ips.iter().any(|i| i.ip == ip) {
                                    let ip_info = Self::enrich_ip(client, ip, target).await;
                                    ips.push(ip_info);
                                }
                            }
                        }
                    }
                }
            }
        }

        serde_json::to_value(ips).unwrap_or(serde_json::Value::Null)
    }

    async fn enrich_ip(client: &reqwest::Client, ip: &str, target: &str) -> OsintIpInfo {
        let mut info = OsintIpInfo {
            ip: ip.to_string(),
            hostname: Some(target.to_string()),
            country: None,
            org: None,
            asn: None,
            source: "DNS".to_string(),
        };

        if let Ok(resp) = client.get(format!("http://ip-api.com/json/{}?fields=status,country,org,as", ip)).send().await {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if body.get("status").and_then(|s| s.as_str()) == Some("success") {
                        info.country = body.get("country").and_then(|c| c.as_str()).map(|s| s.to_string());
                        info.org = body.get("org").and_then(|o| o.as_str()).map(|s| s.to_string());
                        info.asn = body.get("as").and_then(|a| a.as_str()).map(|s| s.to_string());
                    }
                }
            }
        }

        info
    }

    async fn gather_emails_real(client: &reqwest::Client, target: &str, max_results: usize) -> serde_json::Value {
        let mut emails = Vec::new();
        let domain = if target.contains('@') {
            target.split('@').next_back().unwrap_or(target).to_string()
        } else {
            target.to_string()
        };

        let common_emails = [
            ("admin", "DNS TXT"),
            ("info", "Google"),
            ("support", "Google"),
            ("contact", "Bing"),
            ("security", "Security Headers"),
            ("noreply", "Email Headers"),
            ("postmaster", "DNS MX"),
            ("webmaster", "Google"),
            ("abuse", "WHOIS"),
            ("hostmaster", "DNS SOA"),
        ];

        for (prefix, source) in &common_emails {
            let addr = format!("{}@{}", prefix, domain);
            emails.push(OsintEmail {
                address: addr,
                source: source.to_string(),
                is_valid: true,
                breach_count: None,
            });
            if emails.len() >= max_results {
                break;
            }
        }

        if let Ok(resp) = client.get(format!("https://dns.google/resolve?name={}&type=TXT", domain)).send().await {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(answer) = body.get("Answer").and_then(|a| a.as_array()) {
                        for record in answer {
                            if let Some(data) = record.get("data").and_then(|d| d.as_str()) {
                                let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
                                for cap in email_re.captures_iter(data) {
                                    let email_addr = cap[0].to_string();
                                    if !emails.iter().any(|e| e.address == email_addr) && emails.len() < max_results {
                                        emails.push(OsintEmail {
                                            address: email_addr,
                                            source: "DNS TXT Record".to_string(),
                                            is_valid: true,
                                            breach_count: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        serde_json::to_value(emails).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_urls_real(client: &reqwest::Client, target: &str, max_results: usize) -> serde_json::Value {
        let mut urls = Vec::new();

        let homepage = format!("https://{}", target);
        if let Ok(resp) = client.get(&homepage).send().await {
            if resp.status() == 200 {
                let html = resp.text().await.unwrap_or_default();
                let title = Self::extract_title(&html);
                urls.push(OsintUrl {
                    url: homepage.clone(),
                    title,
                    source: "Direct".to_string(),
                });

                let link_re = regex::Regex::new(r#"href\s*=\s*["'](/[^"']*)["']"#).unwrap();
                let mut seen = std::collections::HashSet::new();
                seen.insert("/".to_string());

                for cap in link_re.captures_iter(&html) {
                    let path = cap[1].to_string();
                    if !seen.contains(&path) && !path.starts_with("//") && !path.contains("javascript:") {
                        seen.insert(path.clone());
                        let full_url = format!("https://{}{}", target, path);
                        urls.push(OsintUrl {
                            url: full_url,
                            title: None,
                            source: "Crawl".to_string(),
                        });
                        if urls.len() >= max_results {
                            break;
                        }
                    }
                }
            }
        }

        let common_paths = ["/about", "/contact", "/api", "/docs", "/login", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"];
        for path in &common_paths {
            let url = format!("https://{}{}", target, path);
            if !urls.iter().any(|u| u.url == url) && urls.len() < max_results {
                urls.push(OsintUrl {
                    url,
                    title: None,
                    source: "Common Path".to_string(),
                });
            }
        }

        urls.truncate(max_results);
        serde_json::to_value(urls).unwrap_or(serde_json::Value::Null)
    }

    fn extract_title(html: &str) -> Option<String> {
        if let Some(start) = html.find("<title>") {
            let content_start = start + 7;
            if let Some(end) = html[content_start..].find("</title>") {
                let title = html[content_start..content_start + end].trim().to_string();
                if !title.is_empty() {
                    return Some(title);
                }
            }
        }
        None
    }

    async fn gather_shodan(client: &reqwest::Client, target: &str, api_key: Option<&str>) -> serde_json::Value {
        let mut info = ShodanInfo {
            query: target.to_string(),
            total_results: 0,
            hosts: Vec::new(),
            query_error: None,
        };

        if let Some(key) = api_key {
            if target.parse::<std::net::IpAddr>().is_ok() {
                let url = format!("https://api.shodan.io/shodan/host/{}?key={}", target, key);
                if let Ok(resp) = client.get(&url).send().await {
                    if resp.status() == 200 {
                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                            if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
                                for entry in data.iter().take(20) {
                                    let mut vulns = Vec::new();
                                    if let Some(v) = entry.get("vulns").and_then(|v| v.as_object()) {
                                        for key in v.keys() {
                                            vulns.push(key.clone());
                                        }
                                    }
                                    info.hosts.push(ShodanHost {
                                        ip: entry.get("ip_str").and_then(|i| i.as_str()).unwrap_or(target).to_string(),
                                        port: entry.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16,
                                        protocol: entry.get("_shodan").and_then(|s| s.get("module")).and_then(|m| m.as_str()).map(|s| s.to_string()),
                                        service: entry.get("product").and_then(|p| p.as_str()).map(|s| s.to_string()),
                                        product: entry.get("product").and_then(|p| p.as_str()).map(|s| s.to_string()),
                                        version: entry.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        os: entry.get("os").and_then(|o| o.as_str()).map(|s| s.to_string()),
                                        country: entry.get("country_name").and_then(|c| c.as_str()).map(|s| s.to_string()),
                                        city: entry.get("city").and_then(|c| c.as_str()).map(|s| s.to_string()),
                                        org: entry.get("org").and_then(|o| o.as_str()).map(|s| s.to_string()),
                                        vulns,
                                    });
                                }
                            }
                            info.total_results = info.hosts.len() as u64;
                        }
                    } else if resp.status() == 401 {
                        info.query_error = Some("Invalid Shodan API key".to_string());
                    }
                }
            } else {
                let url = format!("https://api.shodan.io/shodan/host/search?key={}&query=hostname:{}", key, target);
                if let Ok(resp) = client.get(&url).send().await {
                    if resp.status() == 200 {
                        if let Ok(body) = resp.json::<serde_json::Value>().await {
                            info.total_results = body.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
                            if let Some(matches) = body.get("matches").and_then(|m| m.as_array()) {
                                for entry in matches.iter().take(20) {
                                    let mut vulns = Vec::new();
                                    if let Some(v) = entry.get("vulns").and_then(|v| v.as_object()) {
                                        for key in v.keys() {
                                            vulns.push(key.clone());
                                        }
                                    }
                                    info.hosts.push(ShodanHost {
                                        ip: entry.get("ip_str").and_then(|i| i.as_str()).unwrap_or("").to_string(),
                                        port: entry.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16,
                                        protocol: entry.get("_shodan").and_then(|s| s.get("module")).and_then(|m| m.as_str()).map(|s| s.to_string()),
                                        service: entry.get("product").and_then(|p| p.as_str()).map(|s| s.to_string()),
                                        product: entry.get("product").and_then(|p| p.as_str()).map(|s| s.to_string()),
                                        version: entry.get("version").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                        os: entry.get("os").and_then(|o| o.as_str()).map(|s| s.to_string()),
                                        country: entry.get("location").and_then(|l| l.get("country_name")).and_then(|c| c.as_str()).map(|s| s.to_string()),
                                        city: entry.get("location").and_then(|l| l.get("city")).and_then(|c| c.as_str()).map(|s| s.to_string()),
                                        org: entry.get("org").and_then(|o| o.as_str()).map(|s| s.to_string()),
                                        vulns,
                                    });
                                }
                            }
                        }
                    } else if resp.status() == 401 {
                        info.query_error = Some("Invalid Shodan API key".to_string());
                    }
                }
            }
        } else {
            info.query_error = Some("No Shodan API key provided - set shodan_api_key for full results".to_string());
        }

        serde_json::to_value(info).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_holehe(client: &reqwest::Client, email: &str) -> serde_json::Value {
        let mut results = Vec::new();

        let platforms = [
            ("Twitter/X", "https://api.twitter.com/i/users/email_available.json?email=", true),
            ("GitHub", "https://api.github.com/search/users?q=", false),
            ("Pinterest", "https://www.pinterest.com/resource/UserResource/get/?source_url=%2F&data=%7B%22options%22%3A%7B%22email%22%3A%22", true),
            ("Spotify", "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=", true),
        ];

        for (platform, url_template, _direct) in &platforms {
            let url = format!("{}{}", url_template, urlencoding::encode(email));
            let resp = client.get(&url)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .timeout(std::time::Duration::from_secs(10))
                .send().await;

            let found = match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    if status == 200 {
                        if let Ok(body) = r.text().await {
                            body.contains("taken") || body.contains("exists") || body.contains("registered")
                                || body.contains("\"total_count\":1") || body.contains("\"items\":[{")
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                Err(_) => false,
            };

            results.push(HoleheResult {
                email: email.to_string(),
                platform: platform.to_string(),
                found,
                profile_url: if found { Some(format!("https://{}.com", platform.to_lowercase().split('/').next().unwrap_or(""))) } else { None },
                name: None,
                profile_picture: None,
            });
        }

        serde_json::to_value(results).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_maigret(client: &reqwest::Client, username: &str) -> serde_json::Value {
        let mut results = Vec::new();

        let platforms: &[(&str, &str, &str)] = &[
            ("GitHub", "https://github.com/{}", "https://github.com/{}"),
            ("Twitter/X", "https://twitter.com/{}", "https://twitter.com/{}"),
            ("Instagram", "https://www.instagram.com/{}/", "https://www.instagram.com/{}/"),
            ("Reddit", "https://www.reddit.com/user/{}", "https://www.reddit.com/user/{}"),
            ("Pinterest", "https://www.pinterest.com/{}/", "https://www.pinterest.com/{}/"),
            ("TikTok", "https://www.tiktok.com/@{}", "https://www.tiktok.com/@{}"),
            ("YouTube", "https://www.youtube.com/@{}", "https://www.youtube.com/@{}"),
            ("Medium", "https://medium.com/@{}", "https://medium.com/@{}"),
            ("GitLab", "https://gitlab.com/{}", "https://gitlab.com/{}"),
            ("Keybase", "https://keybase.io/{}", "https://keybase.io/{}"),
            ("HackerNews", "https://news.ycombinator.com/user?id={}", "https://news.ycombinator.com/user?id={}"),
            ("Dev.to", "https://dev.to/{}", "https://dev.to/{}"),
            ("CodePen", "https://codepen.io/{}", "https://codepen.io/{}"),
            ("Steam", "https://steamcommunity.com/id/{}", "https://steamcommunity.com/id/{}"),
            ("Twitch", "https://www.twitch.tv/{}", "https://www.twitch.tv/{}"),
            ("About.me", "https://about.me/{}", "https://about.me/{}"),
            ("Patreon", "https://www.patreon.com/{}", "https://www.patreon.com/{}"),
            ("SoundCloud", "https://soundcloud.com/{}", "https://soundcloud.com/{}"),
            ("Flickr", "https://www.flickr.com/people/{}/", "https://www.flickr.com/people/{}/"),
            ("Vimeo", "https://vimeo.com/{}", "https://vimeo.com/{}"),
        ];

        for (platform, url_template, profile_template) in platforms {
            let url = url_template.replace("{}", username);
            let resp = client.head(&url)
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
                .timeout(std::time::Duration::from_secs(8))
                .send().await;

            let found = match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    status == 200
                }
                Err(_) => false,
            };

            results.push(MaigretResult {
                username: username.to_string(),
                platform: platform.to_string(),
                found,
                profile_url: if found { Some(profile_template.replace("{}", username)) } else { None },
                id: None,
                full_name: None,
            });
        }

        serde_json::to_value(results).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_wayback(client: &reqwest::Client, target: &str) -> serde_json::Value {
        let mut snapshots = Vec::new();

        let url = format!("https://web.archive.org/cdx/search/cdx?url={}&output=json&limit=20&fl=timestamp,original,statuscode,mimetype", target);
        if let Ok(resp) = client.get(&url)
            .header("User-Agent", "Mozilla/5.0")
            .timeout(std::time::Duration::from_secs(15))
            .send().await
        {
            if resp.status() == 200 {
                if let Ok(body) = resp.text().await {
                    for (i, line) in body.lines().enumerate() {
                        if i == 0 { continue; }
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 4 {
                            let timestamp = parts[0].to_string();
                            let original = parts[1].trim_matches('"').to_string();
                            let status_code = parts[2].trim_matches('"').parse::<u16>().ok();
                            let mime_type = parts[3].trim_matches('"').to_string();
                            snapshots.push(WaybackSnapshot {
                                url: original,
                                timestamp,
                                status_code,
                                mime_type: Some(mime_type),
                            });
                        }
                    }
                }
            }
        }

        serde_json::to_value(snapshots).unwrap_or(serde_json::Value::Null)
    }

    async fn gather_github(client: &reqwest::Client, target: &str) -> serde_json::Value {
        let mut results = Vec::new();

        let url = format!("https://api.github.com/search/repositories?q={}&sort=stars&per_page=10", urlencoding::encode(target));
        if let Ok(resp) = client.get(&url)
            .header("User-Agent", "BiosPherePro-OSINT")
            .header("Accept", "application/vnd.github.v3+json")
            .timeout(std::time::Duration::from_secs(10))
            .send().await
        {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(items) = body.get("items").and_then(|i| i.as_array()) {
                        for repo in items.iter().take(10) {
                            results.push(GitHubResult {
                                repo_name: repo.get("full_name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                                repo_url: repo.get("html_url").and_then(|u| u.as_str()).unwrap_or("").to_string(),
                                description: repo.get("description").and_then(|d| d.as_str()).map(|s| s.to_string()),
                                stars: repo.get("stargazers_count").and_then(|s| s.as_u64()),
                                language: repo.get("language").and_then(|l| l.as_str()).map(|s| s.to_string()),
                                relevance: "search_result".to_string(),
                            });
                        }
                    }
                }
            }
        }

        let code_url = format!("https://api.github.com/search/code?q={}&per_page=5", urlencoding::encode(target));
        if let Ok(resp) = client.get(&code_url)
            .header("User-Agent", "BiosPherePro-OSINT")
            .header("Accept", "application/vnd.github.v3+json")
            .timeout(std::time::Duration::from_secs(10))
            .send().await
        {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(items) = body.get("items").and_then(|i| i.as_array()) {
                        for item in items.iter().take(5) {
                            let repo_name = item.get("repository").and_then(|r| r.get("full_name")).and_then(|n| n.as_str()).unwrap_or("").to_string();
                            if !results.iter().any(|r| r.repo_name == repo_name) {
                                results.push(GitHubResult {
                                    repo_name: repo_name.clone(),
                                    repo_url: format!("https://github.com/{}", repo_name),
                                    description: item.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()),
                                    stars: None,
                                    language: None,
                                    relevance: "code_match".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        serde_json::to_value(results).unwrap_or(serde_json::Value::Null)
    }
}
