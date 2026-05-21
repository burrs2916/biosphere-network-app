use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSearchConfig {
    pub query: String,
    pub search_engine: String,
    pub api_key: Option<String>,
    pub max_results: usize,
    pub search_type: String,
    pub timeout: u64,
}

impl Default for AssetSearchConfig {
    fn default() -> Self {
        Self {
            query: String::new(),
            search_engine: "shodan".to_string(),
            api_key: None,
            max_results: 50,
            search_type: "host".to_string(),
            timeout: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSearchResult {
    pub success: bool,
    pub query: String,
    pub engine: String,
    pub total_results: usize,
    pub assets: Vec<DiscoveredAsset>,
    pub statistics: SearchStatistics,
    pub security_findings: Vec<AssetSecurityFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub version: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>,
    pub last_seen: Option<String>,
    pub vulnerabilities: Vec<String>,
    pub banner: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchStatistics {
    pub total_hosts: usize,
    pub open_ports: std::collections::HashMap<String, usize>,
    pub top_services: Vec<(String, usize)>,
    pub top_countries: Vec<(String, usize)>,
    pub vulnerable_hosts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub affected_asset: String,
    pub recommendation: String,
}

pub struct AssetSearchTool;

impl AssetSearchTool {
    pub async fn search(config: &AssetSearchConfig) -> std::result::Result<AssetSearchResult, String> {
        if config.query.is_empty() {
            return Err("Search query is required".to_string());
        }

        let query = config.query.trim().to_string();
        let engine = config.search_engine.to_lowercase();

        let (assets, statistics, findings) = match engine.as_str() {
            "shodan" => Self::search_shodan(&query, config.max_results, config.api_key.as_deref()).await,
            "censys" => Self::search_censys(&query, config.max_results, config.api_key.as_deref()).await,
            "fofa" => Self::search_fofa(&query, config.max_results, config.api_key.as_deref()).await,
            "zoomeye" => Self::search_zoomeye(&query, config.max_results, config.api_key.as_deref()).await,
            _ => return Err(format!("Unsupported search engine: {}, supported: shodan, censys, fofa, zoomeye", engine)),
        };

        let total = assets.len();
        let high_findings = findings.iter().filter(|f| f.severity == "high").count();
        let medium_findings = findings.iter().filter(|f| f.severity == "medium").count();

        let summary = format!(
            "Asset search completed | Engine: {} | Query: {} | Found: {} assets | Security findings: {} (High: {}, Medium: {})",
            engine, query, total, findings.len(), high_findings, medium_findings
        );

        Ok(AssetSearchResult {
            success: true,
            query,
            engine,
            total_results: total,
            assets,
            statistics,
            security_findings: findings,
            summary,
        })
    }

    async fn search_shodan(query: &str, max_results: usize, api_key: Option<&str>) -> (Vec<DiscoveredAsset>, SearchStatistics, Vec<AssetSecurityFinding>) {
        let mut assets = Vec::new();
        let mut findings = Vec::new();

        if let Some(key) = api_key {
            if !key.is_empty() {
                let url = format!("https://api.shodan.io/shodan/host/search?key={}&query={}", key, urlencoding::encode(query));

                if let Ok(resp) = Self::http_get(&url).await {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                        if let Some(matches) = json.get("matches").and_then(|m| m.as_array()) {
                            for match_val in matches.iter().take(max_results) {
                                let ip = match_val.get("ip_str").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let port = match_val.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                let protocol = match_val.get("transport").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                                let service = match_val.get("_shodan").and_then(|v| v.get("module")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let version = match_val.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let hostname = match_val.get("hostnames").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).map(|s| s.to_string());
                                let os = match_val.get("os").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let country = match_val.get("location").and_then(|v| v.get("country_name")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                let city = match_val.get("location").and_then(|v| v.get("city")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                let org = match_val.get("org").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let banner = match_val.get("data").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let vulns = match_val.get("vulns").and_then(|v| v.as_array())
                                    .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                    .unwrap_or_default();

                                let mut tags = Vec::new();
                                if let Some(tag_list) = match_val.get("tags").and_then(|v| v.as_array()) {
                                    for tag in tag_list {
                                        if let Some(t) = tag.as_str() {
                                            tags.push(t.to_string());
                                        }
                                    }
                                }

                                assets.push(DiscoveredAsset {
                                    ip, port, protocol, service, version, hostname, os,
                                    country, city, org, last_seen: None, vulnerabilities: vulns,
                                    banner, tags,
                                });
                            }
                        }

                        findings = Self::analyze_assets_for_findings(&assets);
                        let statistics = Self::build_statistics(&assets);
                        return (assets, statistics, findings);
                    }
                }

                findings.push(AssetSecurityFinding {
                    severity: "medium".to_string(),
                    category: "API Error".to_string(),
                    description: "Shodan API request failed, please check API Key and network connection".to_string(),
                    affected_asset: query.to_string(),
                    recommendation: "Verify API Key is valid and check network connection".to_string(),
                });
            }
        }

        let is_ip = query.parse::<std::net::IpAddr>().is_ok();
        if is_ip {
            assets = Self::scan_ip_directly(query, &mut findings);
        } else {
            assets = Self::dns_lookup_assets(query, &mut findings);
        }

        findings.extend(Self::analyze_assets_for_findings(&assets));
        let statistics = Self::build_statistics(&assets);
        (assets, statistics, findings)
    }

    async fn search_censys(query: &str, max_results: usize, api_key: Option<&str>) -> (Vec<DiscoveredAsset>, SearchStatistics, Vec<AssetSecurityFinding>) {
        let mut assets = Vec::new();
        let mut findings = Vec::new();

        if let Some(key) = api_key {
            if !key.is_empty() {
                let url = format!("https://search.censys.io/api/v2/hosts/search?q={}&per_page={}", urlencoding::encode(query), max_results.min(100));

                if let Ok(resp) = Self::http_get_with_auth(&url, key).await {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                        if let Some(result) = json.get("result").and_then(|r| r.get("hits")).and_then(|h| h.as_array()) {
                            for hit in result.iter().take(max_results) {
                                let ip = hit.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let services = hit.get("services").and_then(|v| v.as_array());

                                if let Some(svc_list) = services {
                                    for svc in svc_list {
                                        let port = svc.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                        let service = svc.get("service_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                        let version = svc.get("software").and_then(|v| v.as_array()).and_then(|a| a.first())
                                            .and_then(|s| s.get("version")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let banner = svc.get("banner").and_then(|v| v.as_str()).map(|s| s.to_string());

                                        let country = hit.get("location").and_then(|l| l.get("country_code")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let city = hit.get("location").and_then(|l| l.get("city")).and_then(|v| v.as_str()).map(|s| s.to_string());

                                        assets.push(DiscoveredAsset {
                                            ip: ip.clone(), port, protocol: "tcp".to_string(), service, version,
                                            hostname: None, os: None, country, city, org: None,
                                            last_seen: None, vulnerabilities: vec![], banner, tags: vec![],
                                        });
                                    }
                                } else {
                                    assets.push(DiscoveredAsset {
                                        ip: ip.clone(), port: 0, protocol: "tcp".to_string(), service: String::new(),
                                        version: None, hostname: None, os: None, country: None, city: None, org: None,
                                        last_seen: None, vulnerabilities: vec![], banner: None, tags: vec![],
                                    });
                                }
                            }
                        }

                        findings = Self::analyze_assets_for_findings(&assets);
                        let statistics = Self::build_statistics(&assets);
                        return (assets, statistics, findings);
                    }
                }
            }
        }

        let is_ip = query.parse::<std::net::IpAddr>().is_ok();
        if is_ip {
            assets = Self::scan_ip_directly(query, &mut findings);
        } else {
            assets = Self::dns_lookup_assets(query, &mut findings);
        }

        findings.extend(Self::analyze_assets_for_findings(&assets));
        let statistics = Self::build_statistics(&assets);
        (assets, statistics, findings)
    }

    async fn search_fofa(query: &str, max_results: usize, api_key: Option<&str>) -> (Vec<DiscoveredAsset>, SearchStatistics, Vec<AssetSecurityFinding>) {
        let mut assets = Vec::new();
        let mut findings = Vec::new();

        if let Some(key) = api_key {
            if !key.is_empty() {
                let encoded_query = base64_encode(query);
                let url = format!("https://fofa.info/api/v1/search/all?email=&key={}&qbase64={}&size={}", key, encoded_query, max_results.min(100));

                if let Ok(resp) = Self::http_get(&url).await {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                        if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
                            for result in results.iter().take(max_results) {
                                if let Some(arr) = result.as_array() {
                                    let ip = arr.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let port_str = arr.get(1).and_then(|v| v.as_str()).unwrap_or("0");
                                    let port: u16 = port_str.parse().unwrap_or(0);
                                    let protocol = arr.get(2).and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                                    let service = arr.get(3).and_then(|v| v.as_str()).unwrap_or("").to_string();
                                    let banner = arr.get(5).and_then(|v| v.as_str()).map(|s| s.to_string());

                                    assets.push(DiscoveredAsset {
                                        ip, port, protocol, service, version: None,
                                        hostname: None, os: None, country: None, city: None, org: None,
                                        last_seen: None, vulnerabilities: vec![], banner, tags: vec![],
                                    });
                                }
                            }
                        }

                        findings = Self::analyze_assets_for_findings(&assets);
                        let statistics = Self::build_statistics(&assets);
                        return (assets, statistics, findings);
                    }
                }
            }
        }

        let is_ip = query.parse::<std::net::IpAddr>().is_ok();
        if is_ip {
            assets = Self::scan_ip_directly(query, &mut findings);
        } else {
            assets = Self::dns_lookup_assets(query, &mut findings);
        }

        findings.extend(Self::analyze_assets_for_findings(&assets));
        let statistics = Self::build_statistics(&assets);
        (assets, statistics, findings)
    }

    async fn search_zoomeye(query: &str, max_results: usize, api_key: Option<&str>) -> (Vec<DiscoveredAsset>, SearchStatistics, Vec<AssetSecurityFinding>) {
        let mut assets = Vec::new();
        let mut findings = Vec::new();

        if let Some(key) = api_key {
            if !key.is_empty() {
                let url = format!("https://api.zoomeye.org/host/search?query={}&facet=app,os&count={}", urlencoding::encode(query), max_results.min(20));

                if let Ok(resp) = Self::http_get_with_auth(&url, key).await {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                        if let Some(matches) = json.get("matches").and_then(|m| m.as_array()) {
                            for m in matches.iter().take(max_results) {
                                let ip = m.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let port = m.get("portinfo").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                                let service = m.get("app").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let banner = m.get("banner").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let os = m.get("os").and_then(|v| v.as_str()).map(|s| s.to_string());
                                let country = m.get("geoinfo").and_then(|g| g.get("country_names")).and_then(|v| v.as_str()).map(|s| s.to_string());
                                let city = m.get("geoinfo").and_then(|g| g.get("city")).and_then(|v| v.as_str()).map(|s| s.to_string());

                                assets.push(DiscoveredAsset {
                                    ip, port, protocol: "tcp".to_string(), service, version: None,
                                    hostname: None, os, country, city, org: None,
                                    last_seen: None, vulnerabilities: vec![], banner, tags: vec![],
                                });
                            }
                        }

                        findings = Self::analyze_assets_for_findings(&assets);
                        let statistics = Self::build_statistics(&assets);
                        return (assets, statistics, findings);
                    }
                }
            }
        }

        let is_ip = query.parse::<std::net::IpAddr>().is_ok();
        if is_ip {
            assets = Self::scan_ip_directly(query, &mut findings);
        } else {
            assets = Self::dns_lookup_assets(query, &mut findings);
        }

        findings.extend(Self::analyze_assets_for_findings(&assets));
        let statistics = Self::build_statistics(&assets);
        (assets, statistics, findings)
    }

    fn scan_ip_directly(query: &str, findings: &mut Vec<AssetSecurityFinding>) -> Vec<DiscoveredAsset> {
        let mut assets = Vec::new();
        let common_ports: [(u16, &str); 15] = [
            (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
            (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
            (443, "HTTPS"), (3306, "MySQL"), (3389, "RDP"),
            (5432, "PostgreSQL"), (6379, "Redis"), (8080, "HTTP-Proxy"),
            (27017, "MongoDB"),
        ];

        for (port, service) in &common_ports {
            if Self::tcp_connect(query, *port, 3) {
                let banner = Self::grab_banner(query, *port);
                let version = Self::detect_version_from_banner(&banner);
                let mut vulns = Vec::new();
                let mut tags = Vec::new();

                if *port == 6379 { vulns.push("Redis may allow unauthorized access".to_string()); tags.push("database".to_string()); }
                if *port == 27017 { vulns.push("MongoDB may allow unauthorized access".to_string()); tags.push("database".to_string()); }
                if *port == 3306 { tags.push("database".to_string()); }
                if *port == 23 { vulns.push("Telnet transmits in plaintext".to_string()); }
                if *port == 21 { vulns.push("FTP transmits in plaintext".to_string()); }

                assets.push(DiscoveredAsset {
                    ip: query.to_string(),
                    port: *port,
                    protocol: "tcp".to_string(),
                    service: service.to_string(),
                    version,
                    hostname: None,
                    os: None,
                    country: None,
                    city: None,
                    org: None,
                    last_seen: Some(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                    vulnerabilities: vulns,
                    banner: if banner.is_empty() { None } else { Some(banner) },
                    tags,
                });
            }
        }

        if !assets.is_empty() {
            let db_exposed = assets.iter().any(|a| a.port == 3306 || a.port == 6379 || a.port == 27017 || a.port == 5432);
            if db_exposed {
                findings.push(AssetSecurityFinding {
                    severity: "high".to_string(),
                    category: "Database Exposed".to_string(),
                    description: format!("Target {} has exposed database ports", query),
                    affected_asset: query.to_string(),
                    recommendation: "Bind database to internal interface, use firewall to restrict access".to_string(),
                });
            }
        }

        assets
    }

    fn dns_lookup_assets(domain: &str, findings: &mut Vec<AssetSecurityFinding>) -> Vec<DiscoveredAsset> {
        let mut assets = Vec::new();

        if let Ok(output) = std::process::Command::new("dig")
            .args(["+short", domain, "A"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let ip = line.trim().to_string();
                if ip.parse::<std::net::IpAddr>().is_ok() {
                    let sub_assets = Self::scan_ip_directly(&ip, findings);
                    assets.extend(sub_assets);
                    if assets.len() >= 50 { break; }
                }
            }
        }

        if assets.is_empty() {
            if let Ok(output) = std::process::Command::new("nslookup")
                .arg(domain)
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if let Some(addr_part) = line.strip_prefix("Address:") {
                        let ip = addr_part.trim().to_string();
                        if ip.parse::<std::net::IpAddr>().is_ok() {
                            let sub_assets = Self::scan_ip_directly(&ip, findings);
                            assets.extend(sub_assets);
                            if assets.len() >= 50 { break; }
                        }
                    }
                }
            }
        }

        if assets.is_empty() {
            findings.push(AssetSecurityFinding {
                severity: "info".to_string(),
                category: "DNS Resolution".to_string(),
                description: format!("Cannot resolve IP address for domain {}, and no API Key provided", domain),
                affected_asset: domain.to_string(),
                recommendation: "Provide a valid API Key for complete search results".to_string(),
            });
        }

        assets
    }

    fn tcp_connect(host: &str, port: u16, timeout_secs: u64) -> bool {
        use std::net::TcpStream;
        use std::time::Duration;

        let addr = format!("{}:{}", host, port);
        TcpStream::connect_timeout(&addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()), Duration::from_secs(timeout_secs)).is_ok()
    }

    fn grab_banner(host: &str, port: u16) -> String {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let addr = format!("{}:{}", host, port);
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()), Duration::from_secs(5)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

            if port == 80 || port == 8080 {
                let _ = stream.write_all(format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", host).as_bytes());
            }

            let mut buf = [0u8; 1024];
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        }
    }

    fn detect_version_from_banner(banner: &str) -> Option<String> {
        if banner.is_empty() { return None; }

        let patterns = ["Server:", "SSH-", "FTP", "SMTP", "HTTP/", "MySQL", "PostgreSQL", "Redis"];
        for line in banner.lines() {
            for pattern in &patterns {
                if line.contains(pattern) {
                    return Some(line.trim().to_string());
                }
            }
        }
        None
    }

    fn analyze_assets_for_findings(assets: &[DiscoveredAsset]) -> Vec<AssetSecurityFinding> {
        let mut findings = Vec::new();

        for asset in assets {
            if asset.port == 6379 && asset.service.contains("Redis") {
                findings.push(AssetSecurityFinding {
                    severity: "high".to_string(),
                    category: "Redis Unauthorized".to_string(),
                    description: format!("Redis service (6379) may allow unauthorized access: {}", asset.ip),
                    affected_asset: format!("{}:6379", asset.ip),
                    recommendation: "Enable Redis authentication, bind to internal interface".to_string(),
                });
            }
            if asset.port == 27017 {
                findings.push(AssetSecurityFinding {
                    severity: "high".to_string(),
                    category: "MongoDB Unauthorized".to_string(),
                    description: format!("MongoDB service (27017) may allow unauthorized access: {}", asset.ip),
                    affected_asset: format!("{}:27017", asset.ip),
                    recommendation: "Enable MongoDB authentication, restrict network access".to_string(),
                });
            }
            if asset.port == 23 {
                findings.push(AssetSecurityFinding {
                    severity: "high".to_string(),
                    category: "Telnet Exposed".to_string(),
                    description: format!("Telnet service (23) transmits in plaintext: {}", asset.ip),
                    affected_asset: format!("{}:23", asset.ip),
                    recommendation: "Disable Telnet, use SSH instead".to_string(),
                });
            }
            if asset.port == 21 {
                findings.push(AssetSecurityFinding {
                    severity: "medium".to_string(),
                    category: "FTP Plaintext".to_string(),
                    description: format!("FTP service (21) transmits data in plaintext: {}", asset.ip),
                    affected_asset: format!("{}:21", asset.ip),
                    recommendation: "Use SFTP or FTPS instead of FTP".to_string(),
                });
            }
            if asset.port == 3306 || asset.port == 5432 {
                findings.push(AssetSecurityFinding {
                    severity: "high".to_string(),
                    category: "Database Exposed".to_string(),
                    description: format!("Database service ({}) exposed on public network: {}", asset.port, asset.ip),
                    affected_asset: format!("{}:{}", asset.ip, asset.port),
                    recommendation: "Bind database to internal interface, use firewall to restrict access".to_string(),
                });
            }
            if !asset.vulnerabilities.is_empty() {
                for vuln in &asset.vulnerabilities {
                    findings.push(AssetSecurityFinding {
                        severity: "high".to_string(),
                        category: "Known Vulnerability".to_string(),
                        description: format!("{}: {}", asset.ip, vuln),
                        affected_asset: format!("{}:{}", asset.ip, asset.port),
                        recommendation: "Apply security patches promptly".to_string(),
                    });
                }
            }
        }

        findings.truncate(20);
        findings
    }

    fn build_statistics(assets: &[DiscoveredAsset]) -> SearchStatistics {
        let mut port_counts = std::collections::HashMap::new();
        let mut service_counts = std::collections::HashMap::new();
        let mut country_counts = std::collections::HashMap::new();
        let mut vulnerable = 0;

        for asset in assets {
            *port_counts.entry(asset.port.to_string()).or_insert(0usize) += 1;
            *service_counts.entry(asset.service.clone()).or_insert(0usize) += 1;
            if let Some(ref country) = asset.country {
                *country_counts.entry(country.clone()).or_insert(0usize) += 1;
            }
            if !asset.vulnerabilities.is_empty() {
                vulnerable += 1;
            }
        }

        let mut top_services: Vec<(String, usize)> = service_counts.into_iter().collect();
        top_services.sort_by(|a, b| b.1.cmp(&a.1));
        top_services.truncate(10);

        let mut top_countries: Vec<(String, usize)> = country_counts.into_iter().collect();
        top_countries.sort_by(|a, b| b.1.cmp(&a.1));
        top_countries.truncate(10);

        SearchStatistics {
            total_hosts: assets.len(),
            open_ports: port_counts,
            top_services,
            top_countries,
            vulnerable_hosts: vulnerable,
        }
    }

    async fn http_get(url: &str) -> std::result::Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client.get(url)
            .header("User-Agent", "BiosPherePro/1.0")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        resp.text().await.map_err(|e| e.to_string())
    }

    async fn http_get_with_auth(url: &str, api_key: &str) -> std::result::Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client.get(url)
            .header("User-Agent", "BiosPherePro/1.0")
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        resp.text().await.map_err(|e| e.to_string())
    }
}

fn base64_encode(input: &str) -> String {
    use std::fmt::Write;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let mut accum: u32 = 0;
        let mut bits = 0;
        for &byte in chunk {
            accum = (accum << 8) | byte as u32;
            bits += 8;
        }
        while bits >= 6 {
            bits -= 6;
            let idx = ((accum >> bits) & 0x3F) as usize;
            result.write_char(CHARSET[idx] as char).unwrap();
        }
        if bits > 0 {
            let idx = ((accum << (6 - bits)) & 0x3F) as usize;
            result.write_char(CHARSET[idx] as char).unwrap();
        }
    }

    while result.len() % 4 != 0 {
        result.push('=');
    }

    result
}
