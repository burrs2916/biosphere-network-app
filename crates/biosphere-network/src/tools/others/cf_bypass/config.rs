use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfBypassConfig {
    pub domain: String,
    pub timeout: u64,
    pub check_dns_history: bool,
    pub check_subdomains: bool,
    pub check_ssl_certs: bool,
    pub check_mail_headers: bool,
    pub check_censys: bool,
    pub check_securitytrails: bool,
    pub check_wayback: bool,
    pub check_crlf_injection: bool,
    pub censys_api_id: Option<String>,
    pub censys_api_secret: Option<String>,
    pub securitytrails_api_key: Option<String>,
}

impl Default for CfBypassConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            timeout: 30,
            check_dns_history: true,
            check_subdomains: true,
            check_ssl_certs: true,
            check_mail_headers: true,
            check_censys: true,
            check_securitytrails: true,
            check_wayback: true,
            check_crlf_injection: false,
            censys_api_id: None,
            censys_api_secret: None,
            securitytrails_api_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfBypassResult {
    pub success: bool,
    pub domain: String,
    pub is_behind_cf: bool,
    pub cf_ips: Vec<String>,
    pub origin_ips: Vec<OriginIp>,
    pub methods: Vec<BypassMethod>,
    pub dns_history: Vec<DnsHistoryRecord>,
    pub subdomain_ips: Vec<SubdomainRecord>,
    pub ssl_info: Option<SslCertificateInfo>,
    pub censys_results: Vec<CensysHost>,
    pub wayback_ips: Vec<OriginIp>,
    pub crlf_result: Option<CrlfInjectionResult>,
    pub security_findings: Vec<CfBypassFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysHost {
    pub ip: String,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
    pub country: Option<String>,
    pub last_updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlfInjectionResult {
    pub vulnerable: bool,
    pub tested_urls: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginIp {
    pub ip: String,
    pub source: String,
    pub confidence: String,
    pub is_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassMethod {
    pub method: String,
    pub description: String,
    pub result: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryRecord {
    pub domain: String,
    pub ip: String,
    pub record_type: String,
    pub first_seen: String,
    pub last_seen: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainRecord {
    pub subdomain: String,
    pub ip: String,
    pub is_cf_protected: bool,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertificateInfo {
    pub issuer: String,
    pub subject: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub san_domains: Vec<String>,
    pub possible_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfBypassFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

pub struct CfBypassTool;

impl CfBypassTool {
    pub async fn bypass(config: &CfBypassConfig) -> std::result::Result<CfBypassResult, String> {
        if config.domain.is_empty() {
            return Err("Domain is required".to_string());
        }

        let domain = config.domain.trim().to_string();
        let mut cf_ips = Vec::new();
        let mut origin_ips = Vec::new();
        let mut methods = Vec::new();
        let mut dns_history = Vec::new();
        let mut subdomain_ips = Vec::new();
        let mut ssl_info = None;
        let mut censys_results = Vec::new();
        let mut wayback_ips = Vec::new();
        let mut crlf_result = None;
        let mut findings = Vec::new();

        let is_behind_cf = Self::check_cloudflare(&domain, &mut cf_ips);

        methods.push(BypassMethod {
            method: "CloudFlare Detection".to_string(),
            description: "Check if the domain uses CloudFlare".to_string(),
            result: if is_behind_cf { format!("CloudFlare detected, IPs: {:?}", cf_ips) } else { "No CloudFlare detected".to_string() },
            success: is_behind_cf,
        });

        if config.check_dns_history {
            let (history, history_origins) = Self::check_dns_history_records(&domain).await;
            dns_history = history;
            origin_ips.extend(history_origins);

            methods.push(BypassMethod {
                method: "DNS History Lookup".to_string(),
                description: "Query historical DNS records to find pre-CloudFlare IPs".to_string(),
                result: if !dns_history.is_empty() { format!("Found {} historical records", dns_history.len()) } else { "No historical records found".to_string() },
                success: !dns_history.is_empty(),
            });
        }

        if config.check_subdomains {
            let (subdomains, sub_origins) = Self::check_subdomain_records(&domain);
            subdomain_ips = subdomains;
            origin_ips.extend(sub_origins);

            methods.push(BypassMethod {
                method: "Subdomain Enumeration".to_string(),
                description: "Find subdomains that may not be behind CloudFlare".to_string(),
                result: if !subdomain_ips.is_empty() { format!("Found {} subdomains", subdomain_ips.len()) } else { "No subdomains found".to_string() },
                success: !subdomain_ips.is_empty(),
            });
        }

        if config.check_ssl_certs {
            let (cert, cert_origins) = Self::check_ssl_certificate(&domain);
            ssl_info = cert;
            origin_ips.extend(cert_origins);

            methods.push(BypassMethod {
                method: "SSL Certificate Analysis".to_string(),
                description: "Analyze SSL certificate for exposed origin information".to_string(),
                result: if ssl_info.is_some() { "SSL certificate info found".to_string() } else { "No SSL certificate found".to_string() },
                success: ssl_info.is_some(),
            });
        }

        if config.check_mail_headers {
            let mail_origins = Self::check_mail_records(&domain);
            let mail_success = !mail_origins.is_empty();
            origin_ips.extend(mail_origins);

            methods.push(BypassMethod {
                method: "Mail Record Analysis".to_string(),
                description: "Check MX records and mail headers for exposed origin IPs".to_string(),
                result: if mail_success { format!("Found {} mail-related IPs", mail_success as usize) } else { "No mail records exposing origin".to_string() },
                success: mail_success,
            });
        }

        if config.check_censys {
            let (censys_hosts, censys_origins) = Self::check_censys(&domain, config.censys_api_id.as_deref(), config.censys_api_secret.as_deref()).await;
            censys_results = censys_hosts;
            origin_ips.extend(censys_origins);

            methods.push(BypassMethod {
                method: "Censys Search".to_string(),
                description: "Search Censys for hosts with matching SSL certificates or headers".to_string(),
                result: if !censys_results.is_empty() { format!("Found {} hosts on Censys", censys_results.len()) } else { "No Censys results found".to_string() },
                success: !censys_results.is_empty(),
            });
        }

        if config.check_securitytrails {
            let st_origins = Self::check_securitytrails(&domain, config.securitytrails_api_key.as_deref()).await;
            let st_success = !st_origins.is_empty();
            origin_ips.extend(st_origins);

            methods.push(BypassMethod {
                method: "SecurityTrails Lookup".to_string(),
                description: "Query SecurityTrails for historical DNS and associated IPs".to_string(),
                result: if st_success { "Found IPs via SecurityTrails".to_string() } else { "No SecurityTrails results".to_string() },
                success: st_success,
            });
        }

        if config.check_wayback {
            let wb_origins = Self::check_wayback_machine(&domain).await;
            wayback_ips = wb_origins.clone();
            origin_ips.extend(wb_origins);

            methods.push(BypassMethod {
                method: "Wayback Machine".to_string(),
                description: "Check Wayback Machine for historical snapshots that may reveal origin IPs".to_string(),
                result: if !wayback_ips.is_empty() { format!("Found {} IPs from Wayback", wayback_ips.len()) } else { "No Wayback results".to_string() },
                success: !wayback_ips.is_empty(),
            });
        }

        if config.check_crlf_injection {
            let crlf = Self::check_crlf_injection(&domain).await;
            let crlf_vuln = crlf.vulnerable;
            crlf_result = Some(crlf);

            methods.push(BypassMethod {
                method: "CRLF Injection".to_string(),
                description: "Test for CRLF injection that may bypass CloudFlare caching".to_string(),
                result: if crlf_vuln { "CRLF injection vulnerability detected!".to_string() } else { "No CRLF injection found".to_string() },
                success: crlf_vuln,
            });
        }

        if !origin_ips.is_empty() {
            findings.push(CfBypassFinding {
                severity: "high".to_string(),
                category: "Origin IP Leak".to_string(),
                description: format!("Found {} possible origin IP addresses", origin_ips.len()),
                recommendation: "Ensure all subdomains are proxied through CloudFlare, check if DNS history can be cleared".to_string(),
            });
        }

        if !subdomain_ips.is_empty() {
            let unprotected: Vec<&SubdomainRecord> = subdomain_ips.iter().filter(|s| !s.is_cf_protected).collect();
            if !unprotected.is_empty() {
                findings.push(CfBypassFinding {
                    severity: "medium".to_string(),
                    category: "Unprotected Subdomains".to_string(),
                    description: format!("Found {} subdomains not protected by CloudFlare", unprotected.len()),
                    recommendation: "Add all subdomains to CloudFlare and enable proxy".to_string(),
                });
            }
        }

        if is_behind_cf && origin_ips.is_empty() {
            findings.push(CfBypassFinding {
                severity: "info".to_string(),
                category: "CloudFlare Properly Configured".to_string(),
                description: "Domain is behind CloudFlare and no origin IPs were exposed".to_string(),
                recommendation: "Continue maintaining proper CloudFlare configuration".to_string(),
            });
        }

        let origin_count = origin_ips.len();
        let summary = format!(
            "CloudFlare Bypass analysis complete | Domain: {} | CF Protection: {} | Origin IPs Found: {} | Methods: {}",
            domain,
            if is_behind_cf { "Yes" } else { "No" },
            origin_count,
            methods.iter().filter(|m| m.success).count()
        );

        Ok(CfBypassResult {
            success: true,
            domain,
            is_behind_cf,
            cf_ips,
            origin_ips,
            methods,
            dns_history,
            subdomain_ips,
            ssl_info,
            censys_results,
            wayback_ips,
            crlf_result,
            security_findings: findings,
            summary,
        })
    }

    fn check_cloudflare(domain: &str, cf_ips: &mut Vec<String>) -> bool {
        let cf_ranges = [
            "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
            "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
            "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
            "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
            "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
            "172.67.", "173.245.", "1.0.0.", "1.1.1.",
        ];

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if let Ok(output) = std::process::Command::new("dig")
                .args(["+short", domain])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let ip = line.trim().to_string();
                    if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() {
                        cf_ips.push(ip);
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("nslookup")
                .arg(domain)
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if let Some(ip_part) = line.strip_prefix("Address:") {
                        let ip = ip_part.trim().to_string();
                        if ip.parse::<std::net::IpAddr>().is_ok() {
                            cf_ips.push(ip);
                        }
                    }
                }
            }
        }

        if cf_ips.is_empty() {
            return false;
        }

        cf_ips.iter().any(|ip| cf_ranges.iter().any(|range| ip.starts_with(range)))
    }

    async fn check_dns_history_records(domain: &str) -> (Vec<DnsHistoryRecord>, Vec<OriginIp>) {
        let mut history = Vec::new();
        let mut origins = Vec::new();

        if let Ok(resp) = Self::http_get(&format!(
            "https://api.hackertarget.com/dnshistory/?q={}",
            domain
        ))
        .await
        {
            for line in resp.lines() {
                let parts: Vec<&str> = line.splitn(4, ',').collect();
                if parts.len() >= 2 {
                    let hist_domain = parts[0].trim().to_string();
                    let hist_ip = parts[1].trim().to_string();

                    if hist_ip.is_empty() || !hist_ip.contains('.') {
                        continue;
                    }
                    if hist_ip.starts_with("error") || hist_ip.starts_with("API") {
                        continue;
                    }

                    let is_cf = [
                        "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                        "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                        "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                        "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
                        "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
                        "172.67.", "173.245.", "1.0.0.", "1.1.1.",
                    ].iter().any(|r| hist_ip.starts_with(r));

                    let first_seen = if parts.len() >= 3 { parts[2].trim().to_string() } else { "Unknown".to_string() };
                    let last_seen = if parts.len() >= 4 { parts[3].trim().to_string() } else { first_seen.clone() };

                    history.push(DnsHistoryRecord {
                        domain: hist_domain.clone(),
                        ip: hist_ip.clone(),
                        record_type: "A".to_string(),
                        first_seen: first_seen.clone(),
                        last_seen: last_seen.clone(),
                        provider: "HackerTarget".to_string(),
                    });

                    if !is_cf {
                        origins.push(OriginIp {
                            ip: hist_ip,
                            source: format!("DNS History ({})", hist_domain),
                            confidence: "high".to_string(),
                            is_verified: false,
                        });
                    }
                }
            }
        }

        if history.is_empty() {
            if let Ok(resp) = Self::http_get(&format!(
                "https://api.hackertarget.com/dnslookup/?q={}",
                domain
            ))
            .await
            {
                for line in resp.lines() {
                    let line = line.trim();
                    if line.starts_with("error") || line.starts_with("API") {
                        continue;
                    }
                    if let Some(_pos) = line.find(" A ") {
                        let parts: Vec<&str> = line.split(" A ").collect();
                        if parts.len() == 2 {
                            let hist_domain = parts[0].trim().to_string();
                            let hist_ip = parts[1].trim().to_string();
                            if hist_ip.parse::<std::net::IpAddr>().is_ok() {
                                let is_cf = [
                                    "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                                    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                                    "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                                    "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
                                    "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
                                    "172.67.", "173.245.", "1.0.0.", "1.1.1.",
                                ].iter().any(|r| hist_ip.starts_with(r));

                                if !is_cf {
                                    history.push(DnsHistoryRecord {
                                        domain: hist_domain.clone(),
                                        ip: hist_ip.clone(),
                                        record_type: "A".to_string(),
                                        first_seen: "Current".to_string(),
                                        last_seen: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                                        provider: "DNS Lookup".to_string(),
                                    });

                                    origins.push(OriginIp {
                                        ip: hist_ip,
                                        source: format!("DNS Lookup ({})", hist_domain),
                                        confidence: "medium".to_string(),
                                        is_verified: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        history.truncate(50);
        origins.truncate(20);
        (history, origins)
    }

    fn check_subdomain_records(domain: &str) -> (Vec<SubdomainRecord>, Vec<OriginIp>) {
        let mut subdomains = Vec::new();
        let mut origins = Vec::new();

        let common_subs = [
            "direct", "mail", "ftp", "admin", "staging", "dev",
            "test", "api", "blog", "shop", "portal", "vpn",
            "cdn", "ns1", "ns2", "mx", "webmail", "cpanel",
            "old", "backup", "db", "git", "ci", "jenkins",
            "app", "m", "mobile", "static", "media", "img",
        ];

        let cf_ranges = [
            "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
            "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
            "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
            "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
            "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
            "172.67.", "173.245.", "1.0.0.", "1.1.1.",
        ];

        for sub in &common_subs {
            let subdomain = format!("{}.{}", sub, domain);

            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                if let Ok(output) = std::process::Command::new("dig")
                    .args(["+short", &subdomain, "A"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let ip = line.trim().to_string();
                        if ip.is_empty() || ip.parse::<std::net::IpAddr>().is_err() {
                            continue;
                        }

                        let is_cf = cf_ranges.iter().any(|r| ip.starts_with(r));
                        let service = Self::guess_service(sub);

                        subdomains.push(SubdomainRecord {
                            subdomain: subdomain.clone(),
                            ip: ip.clone(),
                            is_cf_protected: is_cf,
                            service: service.clone(),
                        });

                        if !is_cf {
                            origins.push(OriginIp {
                                ip: ip.clone(),
                                source: format!("Subdomain {}", subdomain),
                                confidence: "high".to_string(),
                                is_verified: false,
                            });
                        }
                    }
                }
            }

            #[cfg(target_os = "windows")]
            {
                if let Ok(output) = std::process::Command::new("nslookup")
                    .arg(&subdomain)
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let line = line.trim();
                        if let Some(ip_part) = line.strip_prefix("Address:") {
                            let ip = ip_part.trim().to_string();
                            if ip.parse::<std::net::IpAddr>().is_ok() {
                                let is_cf = cf_ranges.iter().any(|r| ip.starts_with(r));
                                let service = Self::guess_service(sub);

                                subdomains.push(SubdomainRecord {
                                    subdomain: subdomain.clone(),
                                    ip: ip.clone(),
                                    is_cf_protected: is_cf,
                                    service: service.clone(),
                                });

                                if !is_cf {
                                    origins.push(OriginIp {
                                        ip: ip.clone(),
                                        source: format!("Subdomain {}", subdomain),
                                        confidence: "high".to_string(),
                                        is_verified: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        subdomains.truncate(50);
        origins.truncate(20);
        (subdomains, origins)
    }

    fn guess_service(sub: &str) -> Option<String> {
        match sub {
            "mail" | "mx" | "webmail" => Some("Mail Server".to_string()),
            "ftp" => Some("FTP Server".to_string()),
            "admin" | "cpanel" => Some("Admin Panel".to_string()),
            "staging" | "dev" | "test" => Some("Development".to_string()),
            "api" => Some("API Server".to_string()),
            "blog" => Some("Blog".to_string()),
            "cdn" | "static" | "media" | "img" => Some("CDN/Static".to_string()),
            "vpn" => Some("VPN".to_string()),
            "db" => Some("Database".to_string()),
            "git" | "ci" | "jenkins" => Some("CI/CD".to_string()),
            "direct" => Some("Direct Access".to_string()),
            "backup" => Some("Backup".to_string()),
            _ => None,
        }
    }

    fn check_ssl_certificate(domain: &str) -> (Option<SslCertificateInfo>, Vec<OriginIp>) {
        let mut origins = Vec::new();
        let mut issuer = String::new();
        let mut subject = String::new();
        let mut serial = String::new();
        let mut not_before = String::new();
        let mut not_after = String::new();
        let mut san_domains = Vec::new();
        let mut possible_origin = None;

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if let Ok(s_client_output) = std::process::Command::new("openssl")
                .args(["s_client", "-connect", &format!("{}:443", domain), "-servername", domain])
                .stderr(std::process::Stdio::null())
                .output()
            {
                let s_client_stdout = String::from_utf8_lossy(&s_client_output.stdout);
                if !s_client_stdout.is_empty() {
                    if let Ok(mut x509_child) = std::process::Command::new("openssl")
                        .args(["x509", "-noout", "-text"])
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                    {
                        if let Some(mut stdin) = x509_child.stdin.take() {
                            use std::io::Write;
                            let _ = stdin.write_all(s_client_stdout.as_bytes());
                        }
                        if let Ok(x509_output) = x509_child.wait_with_output() {
                            let x509_stdout = String::from_utf8_lossy(&x509_output.stdout);
                            Self::parse_ssl_output(&x509_stdout, &mut issuer, &mut subject, &mut serial, &mut not_before, &mut not_after, &mut san_domains);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(s_client_output) = std::process::Command::new("openssl")
                .args(["s_client", "-connect", &format!("{}:443", domain), "-servername", domain])
                .stderr(std::process::Stdio::null())
                .output()
            {
                let s_client_stdout = String::from_utf8_lossy(&s_client_output.stdout);
                if !s_client_stdout.is_empty() {
                    if let Ok(mut x509_child) = std::process::Command::new("openssl")
                        .args(["x509", "-noout", "-text"])
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                    {
                        if let Some(mut stdin) = x509_child.stdin.take() {
                            use std::io::Write;
                            let _ = stdin.write_all(s_client_stdout.as_bytes());
                        }
                        if let Ok(x509_output) = x509_child.wait_with_output() {
                            let x509_stdout = String::from_utf8_lossy(&x509_output.stdout);
                            Self::parse_ssl_output(&x509_stdout, &mut issuer, &mut subject, &mut serial, &mut not_before, &mut not_after, &mut san_domains);
                        }
                    }
                }
            }
        }

        if issuer.is_empty() {
            return (None, origins);
        }

        for san in &san_domains {
            let san_trimmed = san.trim_start_matches("*.").trim_start_matches(".");
            if san_trimmed != domain && !san_trimmed.contains('*') {
                if let Ok(output) = std::process::Command::new("dig")
                    .args(["+short", san_trimmed, "A"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let ip = line.trim().to_string();
                        if ip.parse::<std::net::IpAddr>().is_ok() {
                            let cf_ranges = [
                                "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                                "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                                "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                                "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
                                "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
                                "172.67.", "173.245.", "1.0.0.", "1.1.1.",
                            ];
                            let is_cf = cf_ranges.iter().any(|r| ip.starts_with(r));
                            if !is_cf && possible_origin.is_none() {
                                possible_origin = Some(ip.clone());
                                origins.push(OriginIp {
                                    ip,
                                    source: format!("SSL Certificate SAN ({})", san_trimmed),
                                    confidence: "medium".to_string(),
                                    is_verified: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        (Some(SslCertificateInfo {
            issuer,
            subject,
            serial,
            not_before,
            not_after,
            san_domains,
            possible_origin,
        }), origins)
    }

    fn parse_ssl_output(
        stdout: &str,
        issuer: &mut String,
        subject: &mut String,
        serial: &mut String,
        not_before: &mut String,
        not_after: &mut String,
        san_domains: &mut Vec<String>,
    ) {
        let mut in_san = false;
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("Issuer:") {
                *issuer = line.strip_prefix("Issuer:").unwrap_or("").trim().to_string();
            }
            if line.starts_with("Subject:") {
                *subject = line.strip_prefix("Subject:").unwrap_or("").trim().to_string();
            }
            if line.starts_with("Serial Number:") {
                *serial = line.strip_prefix("Serial Number:").unwrap_or("").trim().to_string();
            }
            if line.starts_with("Not Before:") {
                *not_before = line.strip_prefix("Not Before:").unwrap_or("").trim().to_string();
            }
            if line.starts_with("Not After:") {
                *not_after = line.strip_prefix("Not After:").unwrap_or("").trim().to_string();
            }
            if line.contains("Subject Alternative Name") {
                in_san = true;
                if let Some(pos) = line.find("DNS:") {
                    let rest = &line[pos..];
                    for entry in rest.split(',') {
                        let entry = entry.trim();
                        if let Some(dns) = entry.strip_prefix("DNS:") {
                            san_domains.push(dns.trim().to_string());
                        }
                    }
                }
                continue;
            }
            if in_san && line.starts_with("DNS:") {
                for entry in line.split(',') {
                    let entry = entry.trim();
                    if let Some(dns) = entry.strip_prefix("DNS:") {
                        san_domains.push(dns.trim().to_string());
                    }
                }
                in_san = false;
            }
        }
    }

    fn check_mail_records(domain: &str) -> Vec<OriginIp> {
        let mut origins = Vec::new();

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if let Ok(output) = std::process::Command::new("dig")
                .args(["+short", "MX", domain])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let mx_host = parts[1].trim_end_matches('.').to_string();
                        if mx_host.is_empty() || !mx_host.contains('.') {
                            continue;
                        }

                        if let Ok(ip_output) = std::process::Command::new("dig")
                            .args(["+short", &mx_host, "A"])
                            .output()
                        {
                            let ip_stdout = String::from_utf8_lossy(&ip_output.stdout);
                            for ip_line in ip_stdout.lines() {
                                let ip = ip_line.trim().to_string();
                                if ip.parse::<std::net::IpAddr>().is_ok() {
                                    let cf_ranges = [
                                        "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
                                        "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                                        "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
                                        "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
                                        "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
                                        "172.67.", "173.245.", "1.0.0.", "1.1.1.",
                                    ];
                                    let is_cf = cf_ranges.iter().any(|r| ip.starts_with(r));
                                    if !is_cf {
                                        origins.push(OriginIp {
                                            ip: ip.clone(),
                                            source: format!("MX Record ({})", mx_host),
                                            confidence: "medium".to_string(),
                                            is_verified: false,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("nslookup")
                .args(["-type=MX", domain])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.contains("mail exchanger") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(mx_host) = parts.last() {
                            let mx_host = mx_host.trim_end_matches('.').to_string();
                            if mx_host.contains('.') {
                                if let Ok(ip_output) = std::process::Command::new("nslookup")
                                    .arg(&mx_host)
                                    .output()
                                {
                                    let ip_stdout = String::from_utf8_lossy(&ip_output.stdout);
                                    for ip_line in ip_stdout.lines() {
                                        let ip_line = ip_line.trim();
                                        if let Some(ip_part) = ip_line.strip_prefix("Address:") {
                                            let ip = ip_part.trim().to_string();
                                            if ip.parse::<std::net::IpAddr>().is_ok() {
                                                origins.push(OriginIp {
                                                    ip: ip.clone(),
                                                    source: format!("MX Record ({})", mx_host),
                                                    confidence: "medium".to_string(),
                                                    is_verified: false,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        origins.truncate(10);
        origins
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

    async fn check_censys(domain: &str, api_id: Option<&str>, api_secret: Option<&str>) -> (Vec<CensysHost>, Vec<OriginIp>) {
        let mut hosts = Vec::new();
        let mut origins = Vec::new();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .danger_accept_invalid_certs(true)
            .build();

        let client = match client {
            Ok(c) => c,
            Err(_) => return (hosts, origins),
        };

        if let (Some(id), Some(secret)) = (api_id, api_secret) {
            let url = "https://search.censys.io/api/v2/hosts/search";
            let query = serde_json::json!({
                "q": format!("services.tls.certificates.leaf.data.names: {}", domain),
                "per_page": 10
            });

            if let Ok(resp) = client.post(url)
                .header("Accept", "application/json")
                .basic_auth(id, Some(secret))
                .json(&query)
                .send().await
            {
                if resp.status() == 200 {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(results) = body.get("result").and_then(|r| r.get("hits")).and_then(|h| h.as_array()) {
                            for hit in results.iter().take(10) {
                                let ip = hit.get("ip").and_then(|i| i.as_str()).unwrap_or("").to_string();
                                let mut ports = Vec::new();
                                let mut services = Vec::new();

                                if let Some(svc_arr) = hit.get("services").and_then(|s| s.as_array()) {
                                    for svc in svc_arr {
                                        if let Some(port) = svc.get("port").and_then(|p| p.as_u64()) {
                                            ports.push(port as u16);
                                        }
                                        if let Some(name) = svc.get("service_name").and_then(|n| n.as_str()) {
                                            services.push(name.to_string());
                                        }
                                    }
                                }

                                let country = hit.get("location").and_then(|l| l.get("country"))
                                    .and_then(|c| c.as_str()).map(|s| s.to_string());

                                if !ip.is_empty() {
                                    let is_cf = Self::is_cf_ip(&ip);
                                    if !is_cf {
                                        origins.push(OriginIp {
                                            ip: ip.clone(),
                                            source: "Censys Search".to_string(),
                                            confidence: "high".to_string(),
                                            is_verified: false,
                                        });
                                    }
                                    hosts.push(CensysHost {
                                        ip,
                                        ports,
                                        services,
                                        country,
                                        last_updated: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let url = format!("https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=5&q={}", urlencoding::encode(&format!("services.tls.certificates.leaf.data.names: {}", domain)));
            if let Ok(resp) = client.get(&url)
                .header("User-Agent", "Mozilla/5.0")
                .send().await
            {
                if resp.status() == 200 {
                    if let Ok(html) = resp.text().await {
                        if let Ok(re) = regex::Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
                            for cap in re.captures_iter(&html) {
                                let ip = cap[1].to_string();
                                if !Self::is_cf_ip(&ip) && !hosts.iter().any(|h| h.ip == ip) {
                                    hosts.push(CensysHost {
                                        ip: ip.clone(),
                                        ports: Vec::new(),
                                        services: Vec::new(),
                                        country: None,
                                        last_updated: None,
                                    });
                                    origins.push(OriginIp {
                                        ip,
                                        source: "Censys Web Search".to_string(),
                                        confidence: "low".to_string(),
                                        is_verified: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        hosts.truncate(10);
        origins.truncate(10);
        (hosts, origins)
    }

    async fn check_securitytrails(domain: &str, api_key: Option<&str>) -> Vec<OriginIp> {
        let mut origins = Vec::new();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build();

        let client = match client {
            Ok(c) => c,
            Err(_) => return origins,
        };

        if let Some(key) = api_key {
            let url = format!("https://api.securitytrails.com/v1/history/{}/dns/a", domain);
            if let Ok(resp) = client.get(&url)
                .header("APIKEY", key)
                .header("Accept", "application/json")
                .send().await
            {
                if resp.status() == 200 {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(records) = body.get("records").and_then(|r| r.as_array()) {
                            for record in records.iter().take(20) {
                                if let Some(values) = record.get("values").and_then(|v| v.as_array()) {
                                    for val in values {
                                        if let Some(ip) = val.get("ip").and_then(|i| i.as_str()) {
                                            if !Self::is_cf_ip(ip) && !origins.iter().any(|o| o.ip == ip) {
                                                origins.push(OriginIp {
                                                    ip: ip.to_string(),
                                                    source: "SecurityTrails".to_string(),
                                                    confidence: "high".to_string(),
                                                    is_verified: false,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let url = format!("https://api.securitytrails.com/v1/domain/{}", domain);
            if let Ok(resp) = client.get(&url)
                .header("Accept", "application/json")
                .send().await
            {
                if resp.status() == 200 {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(current_dns) = body.get("current_dns").and_then(|d| d.get("a")) {
                            if let Some(values) = current_dns.get("values").and_then(|v| v.as_array()) {
                                for val in values {
                                    if let Some(ip) = val.get("ip").and_then(|i| i.as_str()) {
                                        if !Self::is_cf_ip(ip) && !origins.iter().any(|o| o.ip == ip) {
                                            origins.push(OriginIp {
                                                ip: ip.to_string(),
                                                source: "SecurityTrails Current DNS".to_string(),
                                                confidence: "medium".to_string(),
                                                is_verified: false,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        origins.truncate(10);
        origins
    }

    async fn check_wayback_machine(domain: &str) -> Vec<OriginIp> {
        let mut origins = Vec::new();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build();

        let client = match client {
            Ok(c) => c,
            Err(_) => return origins,
        };

        let url = format!("https://web.archive.org/cdx/search/cdx?url={}&output=json&limit=10&fl=timestamp,original,statuscode", domain);
        if let Ok(resp) = client.get(&url)
            .header("User-Agent", "Mozilla/5.0")
            .send().await
        {
            if resp.status() == 200 {
                if let Ok(body) = resp.text().await {
                    for (i, line) in body.lines().enumerate() {
                        if i == 0 { continue; }
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 2 {
                            let original = parts[1].trim_matches('"');
                            if let Ok(parsed) = url::Url::parse(&format!("https://{}", original)) {
                                if let Some(host) = parsed.host_str() {
                                    if host != domain && !host.ends_with(&format!(".{}", domain)) {
                                        if let Ok(dig_output) = std::process::Command::new("dig")
                                            .args(["+short", host, "A"])
                                            .output()
                                        {
                                            let stdout = String::from_utf8_lossy(&dig_output.stdout);
                                            for ip_line in stdout.lines() {
                                                let ip = ip_line.trim().to_string();
                                                if ip.parse::<std::net::IpAddr>().is_ok() && !Self::is_cf_ip(&ip)
                                                    && !origins.iter().any(|o| o.ip == ip) {
                                                        origins.push(OriginIp {
                                                            ip,
                                                            source: format!("Wayback Machine ({})", host),
                                                            confidence: "low".to_string(),
                                                            is_verified: false,
                                                        });
                                                    }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        origins.truncate(10);
        origins
    }

    async fn check_crlf_injection(domain: &str) -> CrlfInjectionResult {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(3))
            .danger_accept_invalid_certs(true)
            .build();

        let client = match client {
            Ok(c) => c,
            Err(_) => return CrlfInjectionResult {
                vulnerable: false,
                tested_urls: Vec::new(),
                details: "Failed to create HTTP client".to_string(),
            },
        };

        let payloads = [
            "/%0d%0aX-Forwarded-For:%20127.0.0.1",
            "/%0d%0aX-Original-URL:%20/admin",
            "/%0d%0aLocation:%20http://evil.com",
            "/..%252f..%252f..%252f",
            "/..;/admin",
        ];

        let mut tested = Vec::new();
        let mut vulnerable = false;
        let mut details = String::new();

        for payload in &payloads {
            let url = format!("https://{}{}", domain, payload);
            tested.push(url.clone());

            if let Ok(resp) = client.get(&url)
                .header("User-Agent", "Mozilla/5.0")
                .send().await
            {
                let status = resp.status().as_u16();
                if status == 200 {
                    if let Ok(headers) = resp.text().await {
                        if headers.contains("X-Forwarded-For") || headers.contains("X-Original-URL") {
                            vulnerable = true;
                            details = format!("CRLF injection possible with payload: {}", payload);
                            break;
                        }
                    }
                }
            }
        }

        if details.is_empty() {
            details = if vulnerable { "CRLF injection detected".to_string() } else { "No CRLF injection vulnerability found".to_string() };
        }

        CrlfInjectionResult {
            vulnerable,
            tested_urls: tested,
            details,
        }
    }

    fn is_cf_ip(ip: &str) -> bool {
        let cf_ranges = [
            "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
            "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
            "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
            "141.101.", "108.162.", "190.93.", "188.114.", "197.234.",
            "198.41.", "162.158.", "172.64.", "172.65.", "172.66.",
            "172.67.", "173.245.", "1.0.0.", "1.1.1.",
        ];
        cf_ranges.iter().any(|r| ip.starts_with(r))
    }
}
