use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityCheckerConfig {
    pub check_ip_leak: bool,
    pub check_dns_leak: bool,
    pub check_webrtc_leak: bool,
    pub check_browser_fingerprint: bool,
    pub check_proxy: bool,
    pub check_tor: bool,
    pub check_vpn: bool,
    pub check_tor_control: bool,
    pub check_proxy_chain: bool,
    pub check_traffic_route: bool,
    pub generate_anonymization_plan: bool,
    pub proxy_host: Option<String>,
    pub proxy_port: Option<u16>,
    pub target_url: Option<String>,
    pub timeout: u64,
}

impl Default for AnonymityCheckerConfig {
    fn default() -> Self {
        Self {
            check_ip_leak: true,
            check_dns_leak: true,
            check_webrtc_leak: true,
            check_browser_fingerprint: true,
            check_proxy: true,
            check_tor: true,
            check_vpn: true,
            check_tor_control: true,
            check_proxy_chain: true,
            check_traffic_route: true,
            generate_anonymization_plan: true,
            proxy_host: None,
            proxy_port: None,
            target_url: None,
            timeout: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLeakInfo {
    pub real_ip: String,
    pub public_ip: String,
    pub is_leaking: bool,
    pub isp: String,
    pub country: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timezone: String,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub ip_type: String,
    pub asn: String,
    pub org: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLeakInfo {
    pub is_leaking: bool,
    pub dns_servers: Vec<String>,
    pub real_dns: Vec<String>,
    pub leak_count: usize,
    pub test_results: Vec<DnsLeakTest>,
    pub external_dns_queries: Vec<String>,
    pub dns_over_https: bool,
    pub dns_over_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLeakTest {
    pub test_server: String,
    pub resolved_by: String,
    pub is_leak: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRtcLeakInfo {
    pub is_leaking: bool,
    pub local_ips: Vec<String>,
    pub public_ips: Vec<String>,
    pub leak_type: String,
    pub stun_server_reachable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserFingerprint {
    pub user_agent: String,
    pub screen_resolution: String,
    pub platform: String,
    pub language: String,
    pub languages: Vec<String>,
    pub plugins_count: usize,
    pub canvas_hash: String,
    pub webgl_hash: String,
    pub audio_hash: String,
    pub font_count: usize,
    pub uniqueness_score: f64,
    pub timezone: String,
    pub do_not_track: bool,
    pub cookie_enabled: bool,
    pub hardware_concurrency: usize,
    pub device_memory: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInfo {
    pub is_detected: bool,
    pub detected: bool,
    pub proxy_type: String,
    pub proxy_headers: Vec<String>,
    pub anonymity_level: String,
    pub risk_level: String,
    pub proxy_ip: String,
    pub forwarding_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorInfo {
    pub is_tor_exit: bool,
    pub tor_detected: bool,
    pub exit_node: Option<String>,
    pub connection_secure: bool,
    pub relay_count: usize,
    pub exit_country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnInfo {
    pub vpn_detected: bool,
    pub vpn_provider: Option<String>,
    pub encryption_level: String,
    pub kill_switch: bool,
    pub dns_protected: bool,
    pub ip_shared: bool,
    pub hosting_provider: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityIssue {
    pub category: String,
    pub issue: String,
    pub description: String,
    pub severity: String,
    pub recommendation: String,
    pub confidence: f64,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorControlInfo {
    pub tor_installed: bool,
    pub tor_running: bool,
    pub tor_version: Option<String>,
    pub socks_port: u16,
    pub control_port: u16,
    pub control_port_accessible: bool,
    pub bridges_configured: bool,
    pub pluggable_transport: Option<String>,
    pub exit_node_country: Option<String>,
    pub circuit_count: usize,
    pub connection_status: String,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChainNode {
    pub host: String,
    pub port: u16,
    pub proxy_type: String,
    pub country: Option<String>,
    pub anonymity_level: String,
    pub latency_ms: Option<u64>,
    pub is_alive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChainInfo {
    pub current_chain: Vec<ProxyChainNode>,
    pub chain_length: usize,
    pub chain_working: bool,
    pub dns_through_chain: bool,
    pub webrtc_through_chain: bool,
    pub chain_leak_detected: bool,
    pub leak_details: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRouteHop {
    pub hop: usize,
    pub ip: String,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    pub latency_ms: Option<u64>,
    pub is_anonymous: bool,
    pub is_tor_relay: bool,
    pub is_vpn_node: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRouteInfo {
    pub route_traced: bool,
    pub hops: Vec<TrafficRouteHop>,
    pub total_hops: usize,
    pub anonymous_hops: usize,
    pub first_unanonymous_hop: Option<usize>,
    pub route_secure: bool,
    pub route_leak_detected: bool,
    pub leak_description: Option<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationStep {
    pub step_number: usize,
    pub category: String,
    pub action: String,
    pub description: String,
    pub priority: String,
    pub automated: bool,
    pub command: Option<String>,
    pub verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationPlan {
    pub current_anonymity_level: String,
    pub target_anonymity_level: String,
    pub steps: Vec<AnonymizationStep>,
    pub estimated_anonymity_improvement: f64,
    pub warnings: Vec<String>,
    pub tools_required: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityCheckerResult {
    pub success: bool,
    pub anonymity_score: f64,
    pub anonymity_level: String,
    pub ip_leak: IpLeakInfo,
    pub dns_leak: DnsLeakInfo,
    pub webrtc_leak: WebRtcLeakInfo,
    pub browser_fingerprint: BrowserFingerprint,
    pub proxy: ProxyInfo,
    pub tor: TorInfo,
    pub vpn: VpnInfo,
    pub tor_control: Option<TorControlInfo>,
    pub proxy_chain: Option<ProxyChainInfo>,
    pub traffic_route: Option<TrafficRouteInfo>,
    pub anonymization_plan: Option<AnonymizationPlan>,
    pub issues: Vec<AnonymityIssue>,
    pub summary: String,
}

pub struct AnonymityCheckerTool;

impl AnonymityCheckerTool {
    pub async fn check(config: &AnonymityCheckerConfig) -> std::result::Result<AnonymityCheckerResult, String> {
        let timeout = Duration::from_secs(config.timeout.max(5));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut issues = Vec::new();

        let ip_leak_info = if config.check_ip_leak {
            Self::check_ip_leak(&client, &mut issues).await
        } else {
            Self::default_ip_leak_info()
        };

        let dns_leak_info = if config.check_dns_leak {
            Self::check_dns_leak(&client, &mut issues).await
        } else {
            Self::default_dns_leak_info()
        };

        let webrtc_leak_info = if config.check_webrtc_leak {
            Self::check_webrtc_leak(&mut issues).await
        } else {
            Self::default_webrtc_leak_info()
        };

        let browser_fingerprint = if config.check_browser_fingerprint {
            Self::check_fingerprint(&client, &mut issues).await
        } else {
            Self::default_browser_fingerprint()
        };

        let proxy_info = if config.check_proxy {
            Self::check_proxy(&client, &config.proxy_host, &config.proxy_port, &mut issues).await
        } else {
            Self::default_proxy_info()
        };

        let tor_info = if config.check_tor {
            Self::check_tor(&client, &ip_leak_info, &mut issues).await
        } else {
            Self::default_tor_info()
        };

        let vpn_info = if config.check_vpn {
            Self::check_vpn(&ip_leak_info, &mut issues)
        } else {
            Self::default_vpn_info()
        };

        let tor_control_info = if config.check_tor_control {
            Some(Self::check_tor_control(&ip_leak_info, &tor_info, &mut issues).await)
        } else {
            None
        };

        let proxy_chain_info = if config.check_proxy_chain {
            Some(Self::check_proxy_chain(&client, &config.proxy_host, &config.proxy_port, &ip_leak_info, &dns_leak_info, &mut issues).await)
        } else {
            None
        };

        let traffic_route_info = if config.check_traffic_route {
            Some(Self::check_traffic_route(&ip_leak_info, &tor_info, &vpn_info, &mut issues))
        } else {
            None
        };

        let anonymization_plan = if config.generate_anonymization_plan {
            Some(Self::generate_anonymization_plan(&issues, &ip_leak_info, &tor_info, &vpn_info))
        } else {
            None
        };

        let anonymity_score = Self::calculate_anonymity_score(&issues);
        let anonymity_level = Self::score_to_level(anonymity_score);

        let summary = format!(
            "Anonymity Check: Score={:.0}%, Level={}, Issues={}, IP Leak={}, DNS Leak={}, WebRTC Leak={}, Tor={}, VPN={}",
            anonymity_score * 100.0, anonymity_level, issues.len(),
            ip_leak_info.is_leaking, dns_leak_info.is_leaking, webrtc_leak_info.is_leaking,
            tor_info.tor_detected, vpn_info.vpn_detected
        );

        Ok(AnonymityCheckerResult {
            success: true,
            anonymity_score,
            anonymity_level,
            ip_leak: ip_leak_info,
            dns_leak: dns_leak_info,
            webrtc_leak: webrtc_leak_info,
            browser_fingerprint,
            proxy: proxy_info,
            tor: tor_info,
            vpn: vpn_info,
            tor_control: tor_control_info,
            proxy_chain: proxy_chain_info,
            traffic_route: traffic_route_info,
            anonymization_plan,
            issues,
            summary,
        })
    }

    async fn check_ip_leak(client: &reqwest::Client, issues: &mut Vec<AnonymityIssue>) -> IpLeakInfo {
        let mut public_ip = String::new();
        let mut isp = String::new();
        let mut country = String::new();
        let mut city = String::new();
        let mut timezone = String::new();
        let mut latitude = 0.0;
        let mut longitude = 0.0;
        let mut ip_type = String::new();
        let mut asn = String::new();
        let mut org = String::new();
        let mut is_vpn = false;
        let mut is_proxy = false;
        let mut is_tor = false;

        match client.get("https://ipinfo.io/json").send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    public_ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    isp = json.get("org").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    org = isp.clone();
                    country = json.get("country").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    city = json.get("city").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    timezone = json.get("timezone").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    asn = json.get("asn").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    if let Some(loc) = json.get("loc").and_then(|v| v.as_str()) {
                        let parts: Vec<&str> = loc.split(',').collect();
                        if parts.len() == 2 {
                            latitude = parts[0].parse().unwrap_or(0.0);
                            longitude = parts[1].parse().unwrap_or(0.0);
                        }
                    }

                    if let Some(privacy) = json.get("privacy") {
                        is_vpn = privacy.get("vpn").and_then(|v| v.as_bool()).unwrap_or(false);
                        is_proxy = privacy.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false);
                        is_tor = privacy.get("tor").and_then(|v| v.as_bool()).unwrap_or(false);
                        ip_type = if is_vpn { "VPN".to_string() }
                            else if is_proxy { "Proxy".to_string() }
                            else if is_tor { "Tor".to_string() }
                            else { "Residential".to_string() };
                    } else {
                        ip_type = "Residential".to_string();
                    }
                }
            }
            Err(_) => {
                if let Ok(resp) = client.get("http://ip-api.com/json").send().await {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        public_ip = json.get("query").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        isp = json.get("isp").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        org = json.get("org").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        country = json.get("country").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        city = json.get("city").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        timezone = json.get("timezone").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        latitude = json.get("lat").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        longitude = json.get("lon").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        asn = json.get("as").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        ip_type = "Residential".to_string();
                    }
                } else {
                    issues.push(AnonymityIssue {
                        category: "IP Leak".to_string(),
                        issue: "IP info API unreachable".to_string(),
                        description: "Could not reach ipinfo.io or ip-api.com. Check your network connection.".to_string(),
                        severity: "medium".to_string(),
                        recommendation: "Check network connectivity and try again".to_string(),
                        confidence: 0.5,
                        mitre_id: "".to_string(),
                    });
                }
            }
        }

        let is_leaking = !public_ip.is_empty() && !is_vpn && !is_proxy && !is_tor;

        if is_leaking {
            issues.push(AnonymityIssue {
                category: "IP Leak".to_string(),
                issue: "Real IP address exposed".to_string(),
                description: format!("Your real IP {} is visible. No VPN, proxy, or Tor detected.", public_ip),
                severity: "high".to_string(),
                recommendation: "Use a VPN or proxy to hide your real IP address".to_string(),
                confidence: 0.9,
                mitre_id: "T1590".to_string(),
            });
        }

        if is_proxy {
            issues.push(AnonymityIssue {
                category: "IP Leak".to_string(),
                issue: "Proxy detected but may leak real IP".to_string(),
                description: "A proxy is detected, but transparent proxies may still reveal your real IP".to_string(),
                severity: "medium".to_string(),
                recommendation: "Use high-anonymity (elite) proxies or VPN instead".to_string(),
                confidence: 0.7,
                mitre_id: "T1090".to_string(),
            });
        }

        if is_tor {
            issues.push(AnonymityIssue {
                category: "IP Leak".to_string(),
                issue: "Tor exit node detected".to_string(),
                description: "Your traffic is routed through a Tor exit node, which can be identified by websites".to_string(),
                severity: "low".to_string(),
                recommendation: "Consider using Tor bridges for better anonymity".to_string(),
                confidence: 0.6,
                mitre_id: "T1090.003".to_string(),
            });
        }

        IpLeakInfo {
            real_ip: String::new(),
            public_ip,
            is_leaking,
            isp,
            country,
            city,
            latitude,
            longitude,
            timezone,
            is_vpn,
            is_proxy,
            is_tor,
            ip_type,
            asn,
            org,
        }
    }

    async fn check_dns_leak(client: &reqwest::Client, issues: &mut Vec<AnonymityIssue>) -> DnsLeakInfo {
        let mut dns_servers = Vec::new();
        let mut test_results = Vec::new();
        let mut dns_over_https = false;
        let mut dns_over_tls = false;

        let common_dns = [
            ("8.8.8.8", "Google DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("208.67.222.222", "OpenDNS"),
            ("9.9.9.9", "Quad9 DNS"),
        ];

        for (dns_ip, dns_name) in &common_dns {
            if Self::check_tcp_connectivity(dns_ip, 53, 3).await {
                dns_servers.push(format!("{} ({})", dns_ip, dns_name));
            }
        }

        if Self::check_tcp_connectivity("1.1.1.1", 443, 3).await {
            dns_over_https = true;
        }

        if Self::check_tcp_connectivity("1.1.1.1", 853, 3).await {
            dns_over_tls = true;
        }

        if let Ok(resp) = client.get("https://1.1.1.1/cdn-cgi/trace").send().await {
            if let Ok(text) = resp.text().await {
                for line in text.lines() {
                    if line.starts_with("gateway=") {
                        let gateway = line.trim_start_matches("gateway=");
                        if !gateway.is_empty() && gateway != "1.1.1.1" {
                            test_results.push(DnsLeakTest {
                                test_server: "1.1.1.1".to_string(),
                                resolved_by: gateway.to_string(),
                                is_leak: !gateway.starts_with("1.") && !gateway.starts_with("8.8."),
                            });
                        }
                    }
                }
            }
        } else if let Ok(resp) = client.get("https://cloudflare-dns.com/cdn-cgi/trace").send().await {
            if let Ok(text) = resp.text().await {
                for line in text.lines() {
                    if line.starts_with("gateway=") {
                        let gateway = line.trim_start_matches("gateway=");
                        if !gateway.is_empty() && gateway != "1.1.1.1" {
                            test_results.push(DnsLeakTest {
                                test_server: "cloudflare-dns.com".to_string(),
                                resolved_by: gateway.to_string(),
                                is_leak: !gateway.starts_with("1.") && !gateway.starts_with("8.8."),
                            });
                        }
                    }
                }
            }
        }

        if dns_servers.is_empty() {
            test_results.push(DnsLeakTest {
                test_server: "common-dns-check".to_string(),
                resolved_by: "No common DNS reachable".to_string(),
                is_leak: false,
            });
        }

        let leak_count = test_results.iter().filter(|t| t.is_leak).count();
        let is_leaking = leak_count > 0;
        let real_dns: Vec<String> = test_results.iter()
            .filter(|t| t.is_leak)
            .map(|t| t.resolved_by.clone())
            .collect();
        let external_dns_queries: Vec<String> = test_results.iter()
            .map(|t| format!("{} -> {}", t.test_server, t.resolved_by))
            .collect();

        if is_leaking {
            issues.push(AnonymityIssue {
                category: "DNS Leak".to_string(),
                issue: format!("{} DNS leak(s) detected", leak_count),
                description: "Your DNS queries may be leaking to your ISP's DNS servers instead of going through your VPN/proxy tunnel".to_string(),
                severity: "high".to_string(),
                recommendation: "Configure DNS-over-HTTPS or use your VPN's DNS servers".to_string(),
                confidence: 0.85,
                mitre_id: "T1590".to_string(),
            });
        }

        if !dns_over_https && !dns_over_tls {
            issues.push(AnonymityIssue {
                category: "DNS Leak".to_string(),
                issue: "DNS queries not encrypted".to_string(),
                description: "DNS queries are sent in plaintext and can be intercepted by your ISP or network administrator".to_string(),
                severity: "medium".to_string(),
                recommendation: "Enable DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) in your browser or OS".to_string(),
                confidence: 0.8,
                mitre_id: "T1040".to_string(),
            });
        }

        if dns_servers.is_empty() {
            issues.push(AnonymityIssue {
                category: "DNS Leak".to_string(),
                issue: "No common DNS servers reachable".to_string(),
                description: "Could not connect to any common DNS servers (Google, Cloudflare, OpenDNS, Quad9)".to_string(),
                severity: "low".to_string(),
                recommendation: "Check your network configuration and DNS settings".to_string(),
                confidence: 0.6,
                mitre_id: "".to_string(),
            });
        }

        DnsLeakInfo {
            is_leaking,
            dns_servers,
            real_dns,
            leak_count,
            test_results,
            external_dns_queries,
            dns_over_https,
            dns_over_tls,
        }
    }

    async fn check_webrtc_leak(issues: &mut Vec<AnonymityIssue>) -> WebRtcLeakInfo {
        let stun_reachable = Self::check_tcp_connectivity("stun.l.google.com", 19302, 5).await;

        let local_ips: Vec<String> = Vec::new();
        let public_ips: Vec<String> = Vec::new();

        let is_leaking = stun_reachable;
        let leak_type = if stun_reachable {
            "STUN/TURN reachable - potential IP leak via WebRTC".to_string()
        } else {
            "No WebRTC leak detected - STUN servers unreachable".to_string()
        };

        if is_leaking {
            issues.push(AnonymityIssue {
                category: "WebRTC Leak".to_string(),
                issue: "WebRTC may leak local IP address".to_string(),
                description: "WebRTC STUN servers are reachable, which could reveal your local or public IP address even when using VPN".to_string(),
                severity: "medium".to_string(),
                recommendation: "Disable WebRTC in browser or use a WebRTC blocking extension".to_string(),
                confidence: 0.75,
                mitre_id: "T1590".to_string(),
            });
        }

        WebRtcLeakInfo {
            is_leaking,
            local_ips,
            public_ips,
            leak_type,
            stun_server_reachable: stun_reachable,
        }
    }

    async fn check_fingerprint(client: &reqwest::Client, issues: &mut Vec<AnonymityIssue>) -> BrowserFingerprint {
        let mut user_agent = String::new();
        let mut platform = String::new();
        let mut language = String::new();
        let mut languages: Vec<String> = Vec::new();
        let timezone = String::new();
        let mut do_not_track = false;

        if let Ok(resp) = client.get("https://httpbin.org/headers").send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(headers) = json.get("headers") {
                    user_agent = headers.get("User-Agent")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if let Some(accept_lang) = headers.get("Accept-Language").and_then(|v| v.as_str()) {
                        language = accept_lang.split(',').next().unwrap_or("").trim().to_string();
                        languages = accept_lang.split(',')
                            .map(|l| {
                                let l = l.trim();
                                if let Some(idx) = l.find(';') { l[..idx].trim().to_string() } else { l.to_string() }
                            })
                            .collect();
                    }

                    if let Some(dnt) = headers.get("Dnt").and_then(|v| v.as_str()) {
                        do_not_track = dnt == "1";
                    }
                }
            }
        }

        if user_agent.contains("Windows") {
            platform = "Windows".to_string();
        } else if user_agent.contains("Mac OS X") {
            platform = "macOS".to_string();
        } else if user_agent.contains("Linux") {
            platform = "Linux".to_string();
        } else if user_agent.contains("Android") {
            platform = "Android".to_string();
        } else if user_agent.contains("iPhone") || user_agent.contains("iPad") {
            platform = "iOS".to_string();
        }

        let mut uniqueness_score: f64 = 0.3;
        if !user_agent.is_empty() { uniqueness_score += 0.15; }
        if !languages.is_empty() && languages.len() > 1 { uniqueness_score += 0.1; }
        if !platform.is_empty() { uniqueness_score += 0.1; }
        if do_not_track { uniqueness_score -= 0.05; }
        uniqueness_score = uniqueness_score.clamp(0.0, 1.0);

        issues.push(AnonymityIssue {
            category: "Browser Fingerprint".to_string(),
            issue: "Browser fingerprinting is possible".to_string(),
            description: "Websites can create a unique fingerprint based on your browser's characteristics (canvas, WebGL, fonts, etc.)".to_string(),
            severity: "medium".to_string(),
            recommendation: "Use anti-fingerprinting browser (Tor Browser) or install privacy extensions (Canvas Blocker)".to_string(),
            confidence: 0.7,
            mitre_id: "T1590".to_string(),
        });

        if !user_agent.is_empty() {
            issues.push(AnonymityIssue {
                category: "Browser Fingerprint".to_string(),
                issue: "User-Agent header exposed".to_string(),
                description: format!("Your User-Agent '{}' reveals browser and OS information", user_agent),
                severity: "low".to_string(),
                recommendation: "Use a User-Agent spoofer or privacy-focused browser".to_string(),
                confidence: 0.8,
                mitre_id: "T1590".to_string(),
            });
        }

        BrowserFingerprint {
            user_agent,
            screen_resolution: "N/A (requires client-side JS)".to_string(),
            platform,
            language,
            languages,
            plugins_count: 0,
            canvas_hash: "N/A (requires client-side JS)".to_string(),
            webgl_hash: "N/A (requires client-side JS)".to_string(),
            audio_hash: "N/A (requires client-side JS)".to_string(),
            font_count: 0,
            uniqueness_score,
            timezone,
            do_not_track,
            cookie_enabled: true,
            hardware_concurrency: 0,
            device_memory: None,
        }
    }

    async fn check_proxy(
        client: &reqwest::Client,
        proxy_host: &Option<String>,
        proxy_port: &Option<u16>,
        issues: &mut Vec<AnonymityIssue>,
    ) -> ProxyInfo {
        let mut is_detected = false;
        let mut detected = false;
        let mut proxy_type = String::new();
        let mut proxy_headers = Vec::new();
        let mut anonymity_level = String::new();
        let mut risk_level = String::new();
        let mut proxy_ip = String::new();
        let mut forwarding_detected = false;

        if let (Some(host), Some(port)) = (proxy_host, proxy_port) {
            is_detected = true;
            detected = true;
            proxy_ip = host.clone();

            if Self::check_tcp_connectivity(host, *port, 5).await {
                proxy_type = "HTTP".to_string();
                anonymity_level = "Unknown".to_string();
                risk_level = "medium".to_string();
                forwarding_detected = true;

                let test_headers = ["X-Forwarded-For", "Via", "X-Real-IP", "Forwarded", "Proxy-Connection"];
                for header in &test_headers {
                    proxy_headers.push(header.to_string());
                }

                issues.push(AnonymityIssue {
                    category: "Proxy Detection".to_string(),
                    issue: "Proxy headers may be forwarded".to_string(),
                    description: format!("Proxy at {}:{} may forward identifying headers (X-Forwarded-For, Via, etc.)", host, port),
                    severity: "medium".to_string(),
                    recommendation: "Use elite (high-anonymity) proxies that do not forward identifying headers".to_string(),
                    confidence: 0.7,
                    mitre_id: "T1090".to_string(),
                });
            } else {
                proxy_type = "Unreachable".to_string();
                anonymity_level = "Unknown".to_string();
                risk_level = "high".to_string();

                issues.push(AnonymityIssue {
                    category: "Proxy Detection".to_string(),
                    issue: "Proxy server unreachable".to_string(),
                    description: format!("Proxy at {}:{} is not responding", host, port),
                    severity: "high".to_string(),
                    recommendation: "Check proxy configuration and ensure the proxy server is running".to_string(),
                    confidence: 0.9,
                    mitre_id: "T1090".to_string(),
                });
            }
        } else {
            if let Ok(resp) = client.get("https://ipinfo.io/json").send().await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(privacy) = json.get("privacy") {
                        if privacy.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false) {
                            is_detected = true;
                            detected = true;
                            proxy_type = "Detected via API".to_string();
                            proxy_ip = json.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            anonymity_level = "Detected".to_string();
                            risk_level = "medium".to_string();
                            forwarding_detected = true;
                        }
                    }
                }
            }

            if let Ok(resp) = client.get("https://httpbin.org/headers").send().await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(headers) = json.get("headers") {
                        let leak_headers = ["X-Forwarded-For", "Via", "X-Real-IP", "Forwarded", "Proxy-Connection", "X-Proxy-Id"];
                        for header in &leak_headers {
                            if headers.get(header).is_some() {
                                proxy_headers.push(header.to_string());
                                if !is_detected {
                                    is_detected = true;
                                    detected = true;
                                    proxy_type = "Transparent".to_string();
                                    anonymity_level = "Low (Transparent)".to_string();
                                    risk_level = "high".to_string();
                                    forwarding_detected = true;
                                }
                            }
                        }
                    }
                }
            }

            if !is_detected {
                issues.push(AnonymityIssue {
                    category: "Proxy Detection".to_string(),
                    issue: "No proxy detected".to_string(),
                    description: "No proxy server is being used. Your direct connection can be traced".to_string(),
                    severity: "medium".to_string(),
                    recommendation: "Consider using a proxy or VPN for better anonymity".to_string(),
                    confidence: 0.6,
                    mitre_id: "T1090".to_string(),
                });
            }
        }

        ProxyInfo {
            is_detected,
            detected,
            proxy_type,
            proxy_headers,
            anonymity_level,
            risk_level,
            proxy_ip,
            forwarding_detected,
        }
    }

    async fn check_tor(client: &reqwest::Client, ip_info: &IpLeakInfo, issues: &mut Vec<AnonymityIssue>) -> TorInfo {
        let mut is_tor_exit = false;
        let mut tor_detected = false;
        let mut exit_node: Option<String> = None;
        let mut relay_count = 0;
        let mut exit_country: Option<String> = None;

        if ip_info.is_tor {
            is_tor_exit = true;
            tor_detected = true;
            exit_node = Some(ip_info.public_ip.clone());
            exit_country = Some(ip_info.country.clone());
        }

        if !ip_info.public_ip.is_empty() {
            let tor_check_url = format!(
                "https://check.torproject.org/torbulkexitlist?ip={}",
                ip_info.public_ip
            );
            if let Ok(resp) = client.get(&tor_check_url).send().await {
                if let Ok(text) = resp.text().await {
                    if text.trim() == ip_info.public_ip {
                        is_tor_exit = true;
                        tor_detected = true;
                        exit_node = Some(ip_info.public_ip.clone());
                        exit_country = Some(ip_info.country.clone());
                    }
                }
            } else if let Ok(resp) = client.get("https://check.torproject.org/api/ip").send().await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if json.get("IsTor").and_then(|v| v.as_bool()).unwrap_or(false) {
                        is_tor_exit = true;
                        tor_detected = true;
                        exit_node = Some(ip_info.public_ip.clone());
                        exit_country = Some(ip_info.country.clone());
                    }
                }
            }
        }

        let tor_relays = [
            ("tor1.digitale-gesellschaft.ch", 443),
            ("tor2.digitale-gesellschaft.ch", 443),
            ("bridges.torproject.org", 443),
        ];

        for (host, port) in &tor_relays {
            if Self::check_tcp_connectivity(host, *port, 3).await {
                relay_count += 1;
            }
        }

        if tor_detected {
            issues.push(AnonymityIssue {
                category: "Tor Detection".to_string(),
                issue: "Tor exit node detected".to_string(),
                description: "Your connection is through a Tor exit node. Some websites block Tor traffic".to_string(),
                severity: "low".to_string(),
                recommendation: "Use Tor bridges or pluggable transports if Tor is blocked".to_string(),
                confidence: 0.85,
                mitre_id: "T1090.003".to_string(),
            });
        } else {
            issues.push(AnonymityIssue {
                category: "Tor Detection".to_string(),
                issue: "Tor not detected".to_string(),
                description: "Tor is not being used. For maximum anonymity, consider using the Tor network".to_string(),
                severity: "info".to_string(),
                recommendation: "Install Tor Browser for anonymous browsing".to_string(),
                confidence: 0.5,
                mitre_id: "T1090.003".to_string(),
            });
        }

        TorInfo {
            is_tor_exit,
            tor_detected,
            exit_node,
            connection_secure: tor_detected,
            relay_count,
            exit_country,
        }
    }

    fn check_vpn(ip_info: &IpLeakInfo, issues: &mut Vec<AnonymityIssue>) -> VpnInfo {
        let mut vpn_detected = false;
        let mut vpn_provider: Option<String> = None;
        let encryption_level: String;
        let mut kill_switch = false;
        let mut dns_protected = false;
        let mut ip_shared = false;
        let mut hosting_provider = false;

        if ip_info.is_vpn {
            vpn_detected = true;

            let vpn_keywords = [
                ("nordvpn", "NordVPN"), ("expressvpn", "ExpressVPN"), ("surfshark", "Surfshark"),
                ("cyberghost", "CyberGhost"), ("private internet access", "PIA"),
                ("mullvad", "Mullvad VPN"), ("proton", "ProtonVPN"), ("windscribe", "Windscribe"),
                ("tunnelbear", "TunnelBear"), ("ipvanish", "IPVanish"), ("vyprvpn", "VyprVPN"),
                ("hidemyass", "HMA"), ("purevpn", "PureVPN"), ("hotspot shield", "Hotspot Shield"),
            ];
            let org_lower = ip_info.org.to_lowercase();
            let isp_lower = ip_info.isp.to_lowercase();
            let mut provider_found = false;
            for (keyword, name) in &vpn_keywords {
                if org_lower.contains(keyword) || isp_lower.contains(keyword) {
                    vpn_provider = Some(name.to_string());
                    provider_found = true;
                    break;
                }
            }
            if !provider_found {
                vpn_provider = Some("VPN Provider".to_string());
            }

            encryption_level = "Unknown (client-side check required)".to_string();

            if !ip_info.is_leaking {
                kill_switch = true;
                dns_protected = true;
            }

            issues.push(AnonymityIssue {
                category: "VPN Detection".to_string(),
                issue: "VPN detected".to_string(),
                description: "A VPN connection is active. Ensure the VPN has kill switch and DNS leak protection enabled".to_string(),
                severity: "info".to_string(),
                recommendation: "Verify VPN kill switch and DNS leak protection are enabled".to_string(),
                confidence: 0.8,
                mitre_id: "T1090".to_string(),
            });
        } else {
            encryption_level = "None".to_string();

            let hosting_keywords = ["hosting", "cloud", "server", "datacenter", "vps", "dedicated", "colocation", "digital", "amazon", "google", "microsoft", "azure", "aws"];
            let org_lower = ip_info.org.to_lowercase();
            let isp_lower = ip_info.isp.to_lowercase();

            for keyword in &hosting_keywords {
                if org_lower.contains(keyword) || isp_lower.contains(keyword) {
                    hosting_provider = true;
                    break;
                }
            }

            if hosting_provider {
                ip_shared = true;
                issues.push(AnonymityIssue {
                    category: "VPN Detection".to_string(),
                    issue: "Hosting/datacenter IP detected".to_string(),
                    description: format!("Your IP appears to be from a hosting provider ({}), which may indicate VPN or proxy usage", ip_info.org),
                    severity: "low".to_string(),
                    recommendation: "This is normal if using a VPN. If not, check for unauthorized proxy usage".to_string(),
                    confidence: 0.6,
                    mitre_id: "T1090".to_string(),
                });
            } else {
                issues.push(AnonymityIssue {
                    category: "VPN Detection".to_string(),
                    issue: "No VPN detected".to_string(),
                    description: "No VPN connection detected. Your traffic is not encrypted at the network level".to_string(),
                    severity: "medium".to_string(),
                    recommendation: "Use a reputable VPN service to encrypt your traffic and protect your privacy".to_string(),
                    confidence: 0.7,
                    mitre_id: "T1090".to_string(),
                });
            }
        }

        VpnInfo {
            vpn_detected,
            vpn_provider,
            encryption_level,
            kill_switch,
            dns_protected,
            ip_shared,
            hosting_provider,
        }
    }

    async fn check_tcp_connectivity(host: &str, port: u16, timeout_secs: u64) -> bool {
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", host, port);
        match addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(socket_addr) = addrs.next() {
                    let result = tokio::time::timeout(
                        Duration::from_secs(timeout_secs),
                        tokio::net::TcpStream::connect(socket_addr)
                    ).await;
                    result.is_ok()
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    fn calculate_anonymity_score(issues: &[AnonymityIssue]) -> f64 {
        if issues.is_empty() {
            return 1.0;
        }
        let penalty: f64 = issues.iter().map(|i| match i.severity.as_str() {
            "critical" => 0.25,
            "high" => 0.15,
            "medium" => 0.08,
            "low" => 0.03,
            "info" => 0.0,
            _ => 0.01,
        }).sum();
        (1.0 - penalty).clamp(0.0, 1.0)
    }

    fn score_to_level(score: f64) -> String {
        if score >= 0.9 { "excellent".to_string() }
        else if score >= 0.7 { "high".to_string() }
        else if score >= 0.5 { "medium".to_string() }
        else if score >= 0.3 { "low".to_string() }
        else { "critical".to_string() }
    }

    fn default_ip_leak_info() -> IpLeakInfo {
        IpLeakInfo {
            real_ip: String::new(), public_ip: String::new(), is_leaking: false,
            isp: String::new(), country: String::new(), city: String::new(),
            latitude: 0.0, longitude: 0.0, timezone: String::new(),
            is_vpn: false, is_proxy: false, is_tor: false,
            ip_type: String::new(), asn: String::new(), org: String::new(),
        }
    }

    fn default_dns_leak_info() -> DnsLeakInfo {
        DnsLeakInfo {
            is_leaking: false, dns_servers: vec![], real_dns: vec![],
            leak_count: 0, test_results: vec![], external_dns_queries: vec![],
            dns_over_https: false, dns_over_tls: false,
        }
    }

    fn default_webrtc_leak_info() -> WebRtcLeakInfo {
        WebRtcLeakInfo {
            is_leaking: false, local_ips: vec![], public_ips: vec![],
            leak_type: String::new(), stun_server_reachable: false,
        }
    }

    fn default_browser_fingerprint() -> BrowserFingerprint {
        BrowserFingerprint {
            user_agent: String::new(), screen_resolution: String::new(),
            platform: String::new(), language: String::new(), languages: vec![],
            plugins_count: 0, canvas_hash: String::new(), webgl_hash: String::new(),
            audio_hash: String::new(), font_count: 0, uniqueness_score: 0.0,
            timezone: String::new(), do_not_track: false, cookie_enabled: false,
            hardware_concurrency: 0, device_memory: None,
        }
    }

    fn default_proxy_info() -> ProxyInfo {
        ProxyInfo {
            is_detected: false, detected: false, proxy_type: String::new(),
            proxy_headers: vec![], anonymity_level: String::new(),
            risk_level: String::new(), proxy_ip: String::new(),
            forwarding_detected: false,
        }
    }

    fn default_tor_info() -> TorInfo {
        TorInfo {
            is_tor_exit: false, tor_detected: false, exit_node: None,
            connection_secure: false, relay_count: 0, exit_country: None,
        }
    }

    fn default_vpn_info() -> VpnInfo {
        VpnInfo {
            vpn_detected: false, vpn_provider: None, encryption_level: String::new(),
            kill_switch: false, dns_protected: false, ip_shared: false,
            hosting_provider: false,
        }
    }

    async fn check_tor_control(ip_info: &IpLeakInfo, tor_info: &TorInfo, issues: &mut Vec<AnonymityIssue>) -> TorControlInfo {
        let mut tor_installed = false;
        let mut tor_running = false;
        let mut tor_version: Option<String> = None;
        let socks_port: u16 = 9050;
        let control_port: u16 = 9051;
        let mut control_port_accessible = false;
        let mut bridges_configured = false;
        let mut pluggable_transport: Option<String> = None;
        let mut circuit_count = 0usize;
        let mut recommendations = Vec::new();

        if let Ok(output) = std::process::Command::new("tor").arg("--version").output() {
            if output.status.success() {
                tor_installed = true;
                let ver = String::from_utf8_lossy(&output.stdout);
                tor_version = ver.lines().next().map(|s| s.trim().to_string());
            }
        }

        if !tor_installed {
            if let Ok(output) = std::process::Command::new("which").arg("tor").output() {
                if output.status.success() {
                    tor_installed = true;
                }
            }
        }

        if !tor_installed {
            if let Ok(output) = std::process::Command::new("brew").args(["list", "tor"]).output() {
                if output.status.success() {
                    tor_installed = true;
                }
            }
        }

        if Self::check_tcp_connectivity("127.0.0.1", socks_port, 2).await {
            tor_running = true;
        }

        if Self::check_tcp_connectivity("127.0.0.1", control_port, 2).await {
            control_port_accessible = true;
        }

        if tor_info.tor_detected {
            tor_running = true;
        }

        if let Ok(home) = std::env::var("HOME") {
            let torrc_path = format!("{}/.tor/torrc", home);
            if let Ok(content) = std::fs::read_to_string(&torrc_path) {
                if content.contains("Bridge ") {
                    bridges_configured = true;
                }
                if content.contains("UseBridges 1") {
                    bridges_configured = true;
                }
                for transport in &["obfs4", "meek", "snowflake", "webtunnel"] {
                    if content.contains(&format!("ClientTransportPlugin {} ", transport)) {
                        pluggable_transport = Some(transport.to_string());
                    }
                }
            }

            let torrc_path2 = "/etc/tor/torrc";
            if let Ok(content) = std::fs::read_to_string(torrc_path2) {
                if content.contains("Bridge ") || content.contains("UseBridges 1") {
                    bridges_configured = true;
                }
                for transport in &["obfs4", "meek", "snowflake", "webtunnel"] {
                    if content.contains(&format!("ClientTransportPlugin {} ", transport)) {
                        pluggable_transport = Some(transport.to_string());
                    }
                }
            }
        }

        if tor_running && control_port_accessible {
            if let Ok(stream) = std::net::TcpStream::connect(format!("127.0.0.1:{}", control_port)) {
                use std::io::{Read, Write};
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = stream.write_all(b"AUTHENTICATE \"\"\r\nGETINFO circuit-status\r\nQUIT\r\n");
                let mut buf = [0u8; 8192];
                if let Ok(n) = stream.read(&mut buf) {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    circuit_count = resp.lines().filter(|l| l.starts_with("250+circuit-status=") || l.contains(" BUILT ")).count();
                }
            }
        }

        if !tor_installed {
            issues.push(AnonymityIssue {
                category: "Tor Control".to_string(),
                issue: "Tor not installed".to_string(),
                description: "Tor is not installed on this system. Tor provides strong anonymity by routing traffic through multiple encrypted relays".to_string(),
                severity: "medium".to_string(),
                recommendation: "Install Tor: apt install tor (Linux) or brew install tor (macOS)".to_string(),
                confidence: 0.95,
                mitre_id: "T1090.003".to_string(),
            });
            recommendations.push("Install Tor for anonymous browsing and communication".to_string());
        } else if !tor_running {
            issues.push(AnonymityIssue {
                category: "Tor Control".to_string(),
                issue: "Tor installed but not running".to_string(),
                description: "Tor is installed but the service is not active. Start Tor to enable anonymous routing".to_string(),
                severity: "medium".to_string(),
                recommendation: "Start Tor: sudo systemctl start tor (Linux) or brew services start tor (macOS)".to_string(),
                confidence: 0.9,
                mitre_id: "T1090.003".to_string(),
            });
            recommendations.push("Start the Tor service to enable anonymous routing".to_string());
        } else if !bridges_configured {
            issues.push(AnonymityIssue {
                category: "Tor Control".to_string(),
                issue: "Tor running without bridges".to_string(),
                description: "Tor is running but not using bridges. In censored regions, Tor connections may be blocked. Bridges help bypass censorship".to_string(),
                severity: "low".to_string(),
                recommendation: "Configure Tor bridges for censorship resistance: add 'UseBridges 1' and 'Bridge ...' to torrc".to_string(),
                confidence: 0.6,
                mitre_id: "T1090.003".to_string(),
            });
            recommendations.push("Consider configuring Tor bridges (obfs4/snowflake) for better censorship resistance".to_string());
        }

        if tor_running && !ip_info.is_tor {
            issues.push(AnonymityIssue {
                category: "Tor Control".to_string(),
                issue: "Tor running but traffic not routed through it".to_string(),
                description: "Tor service is running but your application traffic is not being routed through the Tor SOCKS proxy".to_string(),
                severity: "high".to_string(),
                recommendation: "Configure applications to use SOCKS5 proxy 127.0.0.1:9050, or use Tor Browser".to_string(),
                confidence: 0.85,
                mitre_id: "T1090.003".to_string(),
            });
            recommendations.push("Configure your applications to route through Tor SOCKS5 proxy at 127.0.0.1:9050".to_string());
        }

        if pluggable_transport.is_none() && bridges_configured {
            recommendations.push("Consider using pluggable transports (obfs4, snowflake) for better obfuscation".to_string());
        }

        let connection_status = if !tor_installed {
            "not_installed".to_string()
        } else if !tor_running {
            "stopped".to_string()
        } else if !ip_info.is_tor {
            "running_not_routed".to_string()
        } else {
            "active".to_string()
        };

        TorControlInfo {
            tor_installed,
            tor_running,
            tor_version,
            socks_port,
            control_port,
            control_port_accessible,
            bridges_configured,
            pluggable_transport,
            exit_node_country: tor_info.exit_country.clone(),
            circuit_count,
            connection_status,
            recommendations,
        }
    }

    async fn check_proxy_chain(
        client: &reqwest::Client,
        proxy_host: &Option<String>,
        proxy_port: &Option<u16>,
        ip_info: &IpLeakInfo,
        dns_info: &DnsLeakInfo,
        issues: &mut Vec<AnonymityIssue>,
    ) -> ProxyChainInfo {
        let mut current_chain = Vec::new();
        let mut chain_working = false;
        let mut dns_through_chain = false;
        let mut webrtc_through_chain = false;
        let mut chain_leak_detected = false;
        let mut leak_details = Vec::new();
        let mut recommendations = Vec::new();

        if let (Some(host), Some(port)) = (proxy_host, proxy_port) {
            let is_alive = Self::check_tcp_connectivity(host, *port, 5).await;
            let latency = if is_alive {
                let start = std::time::Instant::now();
                let _ = client.get("https://httpbin.org/ip").send().await;
                Some(start.elapsed().as_millis() as u64)
            } else {
                None
            };

            current_chain.push(ProxyChainNode {
                host: host.clone(),
                port: *port,
                proxy_type: "HTTP/SOCKS".to_string(),
                country: None,
                anonymity_level: if ip_info.is_leaking { "transparent".to_string() } else if ip_info.is_proxy { "anonymous".to_string() } else { "elite".to_string() },
                latency_ms: latency,
                is_alive,
            });

            chain_working = is_alive;
        }

        if ip_info.is_tor {
            current_chain.push(ProxyChainNode {
                host: "127.0.0.1".to_string(),
                port: 9050,
                proxy_type: "SOCKS5 (Tor)".to_string(),
                country: ip_info.country.clone().into(),
                anonymity_level: "high".to_string(),
                latency_ms: None,
                is_alive: true,
            });
            chain_working = true;
        }

        if ip_info.is_vpn {
            current_chain.push(ProxyChainNode {
                host: "VPN Gateway".to_string(),
                port: 0,
                proxy_type: "VPN".to_string(),
                country: None,
                anonymity_level: "high".to_string(),
                latency_ms: None,
                is_alive: true,
            });
            chain_working = true;
        }

        if !current_chain.is_empty() {
            dns_through_chain = !dns_info.is_leaking;
            webrtc_through_chain = !dns_info.is_leaking;

            if ip_info.is_leaking {
                chain_leak_detected = true;
                leak_details.push("Real IP is leaking despite proxy chain".to_string());
            }

            if dns_info.is_leaking {
                chain_leak_detected = true;
                leak_details.push("DNS queries are bypassing the proxy chain".to_string());
            }

            if !ip_info.is_leaking && !dns_info.is_leaking {
                chain_working = true;
            }
        }

        if current_chain.is_empty() {
            issues.push(AnonymityIssue {
                category: "Proxy Chain".to_string(),
                issue: "No proxy chain configured".to_string(),
                description: "No proxy, VPN, or Tor is being used. All traffic goes directly from your IP".to_string(),
                severity: "high".to_string(),
                recommendation: "Set up a proxy chain: VPN -> Tor -> SOCKS proxy for maximum anonymity".to_string(),
                confidence: 0.9,
                mitre_id: "T1090".to_string(),
            });
            recommendations.push("Set up a multi-layer proxy chain for better anonymity".to_string());
            recommendations.push("Recommended chain: VPN -> Tor -> SOCKS5 proxy".to_string());
        } else if chain_leak_detected {
            issues.push(AnonymityIssue {
                category: "Proxy Chain".to_string(),
                issue: "Proxy chain leak detected".to_string(),
                description: format!("Proxy chain is active but leaking: {}", leak_details.join("; ")),
                severity: "high".to_string(),
                recommendation: "Fix proxy chain leaks: ensure DNS and WebRTC traffic also goes through the chain".to_string(),
                confidence: 0.85,
                mitre_id: "T1090".to_string(),
            });
            recommendations.push("Fix DNS leak: configure DNS-over-HTTPS or use proxy's DNS resolution".to_string());
            recommendations.push("Fix WebRTC leak: disable WebRTC in browser or use WebRTC-blocking extension".to_string());
        } else if current_chain.len() == 1 {
            issues.push(AnonymityIssue {
                category: "Proxy Chain".to_string(),
                issue: "Single-layer proxy protection".to_string(),
                description: "Only one layer of proxy protection is active. A single point of failure could expose your identity".to_string(),
                severity: "medium".to_string(),
                recommendation: "Add additional layers: VPN + Tor, or proxy chain with multiple hops".to_string(),
                confidence: 0.7,
                mitre_id: "T1090".to_string(),
            });
            recommendations.push("Add a second anonymity layer for redundancy (e.g., VPN over Tor)".to_string());
        }

        if !dns_through_chain && !current_chain.is_empty() {
            recommendations.push("Route DNS queries through the proxy chain to prevent DNS leaks".to_string());
        }

        let chain_length = current_chain.len();
        ProxyChainInfo {
            current_chain,
            chain_length,
            chain_working,
            dns_through_chain,
            webrtc_through_chain,
            chain_leak_detected,
            leak_details,
            recommendations,
        }
    }

    fn check_traffic_route(
        ip_info: &IpLeakInfo,
        tor_info: &TorInfo,
        vpn_info: &VpnInfo,
        issues: &mut Vec<AnonymityIssue>,
    ) -> TrafficRouteInfo {
        let mut hops = Vec::new();
        let mut route_secure = true;
        let mut route_leak_detected = false;
        let mut leak_description: Option<String> = None;
        let mut recommendations = Vec::new();

        if vpn_info.vpn_detected {
            hops.push(TrafficRouteHop {
                hop: 1,
                ip: "Local Gateway".to_string(),
                hostname: None,
                country: None,
                org: None,
                latency_ms: None,
                is_anonymous: false,
                is_tor_relay: false,
                is_vpn_node: false,
            });
            hops.push(TrafficRouteHop {
                hop: 2,
                ip: ip_info.public_ip.clone(),
                hostname: None,
                country: ip_info.country.clone().into(),
                org: vpn_info.vpn_provider.clone(),
                latency_ms: None,
                is_anonymous: true,
                is_tor_relay: false,
                is_vpn_node: true,
            });
        }

        if tor_info.tor_detected {
            if hops.is_empty() {
                hops.push(TrafficRouteHop {
                    hop: 1,
                    ip: "Local -> Tor Entry".to_string(),
                    hostname: None,
                    country: None,
                    org: None,
                    latency_ms: None,
                    is_anonymous: false,
                    is_tor_relay: false,
                    is_vpn_node: false,
                });
            }
            hops.push(TrafficRouteHop {
                hop: hops.len() + 1,
                ip: "Tor Relay (encrypted)".to_string(),
                hostname: None,
                country: None,
                org: Some("Tor Network".to_string()),
                latency_ms: None,
                is_anonymous: true,
                is_tor_relay: true,
                is_vpn_node: false,
            });
            hops.push(TrafficRouteHop {
                hop: hops.len() + 1,
                ip: "Tor Relay (encrypted)".to_string(),
                hostname: None,
                country: None,
                org: Some("Tor Network".to_string()),
                latency_ms: None,
                is_anonymous: true,
                is_tor_relay: true,
                is_vpn_node: false,
            });
            hops.push(TrafficRouteHop {
                hop: hops.len() + 1,
                ip: ip_info.public_ip.clone(),
                hostname: None,
                country: tor_info.exit_country.clone(),
                org: Some("Tor Exit Node".to_string()),
                latency_ms: None,
                is_anonymous: true,
                is_tor_relay: true,
                is_vpn_node: false,
            });
        }

        if !vpn_info.vpn_detected && !tor_info.tor_detected {
            hops.push(TrafficRouteHop {
                hop: 1,
                ip: ip_info.public_ip.clone(),
                hostname: None,
                country: ip_info.country.clone().into(),
                org: ip_info.org.clone().into(),
                latency_ms: None,
                is_anonymous: false,
                is_tor_relay: false,
                is_vpn_node: false,
            });
            route_secure = false;
            route_leak_detected = true;
            leak_description = Some("Traffic goes directly from your IP without any anonymization layer".to_string());
        }

        if ip_info.is_leaking && (vpn_info.vpn_detected || tor_info.tor_detected) {
            route_leak_detected = true;
            leak_description = Some("Real IP is leaking despite VPN/Tor being active".to_string());
            route_secure = false;
        }

        let anonymous_hops = hops.iter().filter(|h| h.is_anonymous).count();
        let first_unanonymous = hops.iter().position(|h| !h.is_anonymous);
        let total_hops = hops.len();
        let route_traced = !hops.is_empty();

        if route_leak_detected {
            issues.push(AnonymityIssue {
                category: "Traffic Route".to_string(),
                issue: "Traffic route leak detected".to_string(),
                description: leak_description.clone().unwrap_or_default(),
                severity: "high".to_string(),
                recommendation: "Ensure all traffic is routed through VPN/Tor and check for IP/DNS leaks".to_string(),
                confidence: 0.85,
                mitre_id: "T1590".to_string(),
            });
        }

        if !route_secure {
            recommendations.push("Route all traffic through VPN or Tor to prevent direct IP exposure".to_string());
        }
        if vpn_info.vpn_detected && !vpn_info.kill_switch {
            recommendations.push("Enable VPN kill switch to prevent traffic leaks when VPN disconnects".to_string());
        }
        if tor_info.tor_detected && !ip_info.is_tor {
            recommendations.push("Verify Tor is properly configured as system proxy or use Tor Browser".to_string());
        }

        TrafficRouteInfo {
            route_traced,
            hops,
            total_hops,
            anonymous_hops,
            first_unanonymous_hop: first_unanonymous,
            route_secure,
            route_leak_detected,
            leak_description,
            recommendations,
        }
    }

    fn generate_anonymization_plan(
        issues: &[AnonymityIssue],
        ip_info: &IpLeakInfo,
        tor_info: &TorInfo,
        vpn_info: &VpnInfo,
    ) -> AnonymizationPlan {
        let current_level = if ip_info.is_leaking { "exposed".to_string() }
            else if vpn_info.vpn_detected && tor_info.tor_detected { "high".to_string() }
            else if vpn_info.vpn_detected || tor_info.tor_detected { "medium".to_string() }
            else { "low".to_string() };

        let target_level = "high".to_string();
        let mut steps = Vec::new();
        let mut step_num = 1;
        let mut warnings = Vec::new();
        let mut tools_required = Vec::new();

        if ip_info.is_leaking {
            steps.push(AnonymizationStep {
                step_number: step_num,
                category: "IP Protection".to_string(),
                action: "Hide real IP address".to_string(),
                description: "Your real IP is exposed. Install and activate a VPN or Tor to conceal it".to_string(),
                priority: "critical".to_string(),
                automated: false,
                command: Some("Install VPN client or Tor Browser".to_string()),
                verification: "Check that ipinfo.io does not show your real IP".to_string(),
            });
            step_num += 1;
            tools_required.push("VPN Client (NordVPN/ExpressVPN/Mullvad)".to_string());
            tools_required.push("Tor Browser".to_string());
        }

        if !vpn_info.vpn_detected && !tor_info.tor_detected {
            steps.push(AnonymizationStep {
                step_number: step_num,
                category: "Network Anonymization".to_string(),
                action: "Establish VPN connection".to_string(),
                description: "Connect to a reputable VPN service to encrypt all traffic and mask your IP".to_string(),
                priority: "critical".to_string(),
                automated: true,
                command: Some("vpn-client connect".to_string()),
                verification: "Verify VPN connection is active and IP has changed".to_string(),
            });
            step_num += 1;

            steps.push(AnonymizationStep {
                step_number: step_num,
                category: "Network Anonymization".to_string(),
                action: "Start Tor service".to_string(),
                description: "Start Tor for additional anonymity layer. Use VPN + Tor for maximum protection".to_string(),
                priority: "high".to_string(),
                automated: true,
                command: Some("sudo systemctl start tor".to_string()),
                verification: "Check Tor is running: curl --socks5 127.0.0.1:9050 https://check.torproject.org".to_string(),
            });
            step_num += 1;
            tools_required.push("VPN Service".to_string());
            tools_required.push("Tor".to_string());
        }

        if !vpn_info.kill_switch && vpn_info.vpn_detected {
            steps.push(AnonymizationStep {
                step_number: step_num,
                category: "VPN Hardening".to_string(),
                action: "Enable VPN kill switch".to_string(),
                description: "Kill switch prevents traffic from leaking if VPN disconnects unexpectedly".to_string(),
                priority: "high".to_string(),
                automated: true,
                command: Some("Enable kill switch in VPN client settings".to_string()),
                verification: "Disconnect VPN and verify internet is blocked".to_string(),
            });
            step_num += 1;
        }

        if !vpn_info.dns_protected && vpn_info.vpn_detected {
            steps.push(AnonymizationStep {
                step_number: step_num,
                category: "DNS Protection".to_string(),
                action: "Enable DNS leak protection".to_string(),
                description: "Configure VPN to handle DNS queries through the encrypted tunnel".to_string(),
                priority: "high".to_string(),
                automated: true,
                command: Some("Enable DNS leak protection in VPN settings".to_string()),
                verification: "Run DNS leak test at dnsleaktest.com".to_string(),
            });
            step_num += 1;
        }

        steps.push(AnonymizationStep {
            step_number: step_num,
            category: "Browser Hardening".to_string(),
            action: "Disable WebRTC".to_string(),
            description: "WebRTC can leak your real IP even through VPN. Disable it in browser settings".to_string(),
            priority: "high".to_string(),
            automated: false,
            command: Some("Install WebRTC blocking extension or disable WebRTC in browser flags".to_string()),
            verification: "Visit browserleaks.com/webrtc to verify WebRTC is disabled".to_string(),
        });
        step_num += 1;

        steps.push(AnonymizationStep {
            step_number: step_num,
            category: "Browser Hardening".to_string(),
            action: "Anti-fingerprinting configuration".to_string(),
            description: "Use Tor Browser or install anti-fingerprinting extensions to reduce browser uniqueness".to_string(),
            priority: "medium".to_string(),
            automated: false,
            command: Some("Install Canvas Blocker, Privacy Badger, uBlock Origin extensions".to_string()),
            verification: "Check fingerprint uniqueness at amiunique.org".to_string(),
        });
        step_num += 1;

        steps.push(AnonymizationStep {
            step_number: step_num,
            category: "DNS Encryption".to_string(),
            action: "Enable DNS-over-HTTPS (DoH)".to_string(),
            description: "Encrypt DNS queries to prevent ISP from seeing your browsing history".to_string(),
            priority: "medium".to_string(),
            automated: true,
            command: Some("Enable DoH in browser settings or configure system DNS to 1.1.1.1".to_string()),
            verification: "Verify DoH is active in browser security settings".to_string(),
        });
        step_num += 1;

        if tor_info.tor_detected {
            steps.push(AnonymizationStep {
                step_number: step_num,
                category: "Tor Hardening".to_string(),
                action: "Configure Tor bridges".to_string(),
                description: "Use obfs4 or snowflake bridges to disguise Tor traffic and bypass censorship".to_string(),
                priority: "medium".to_string(),
                automated: false,
                command: Some("Add 'UseBridges 1' and bridge lines to torrc".to_string()),
                verification: "Restart Tor and verify connection works with bridges enabled".to_string(),
            });
            step_num += 1;
            tools_required.push("obfs4proxy".to_string());
        }

        steps.push(AnonymizationStep {
            step_number: step_num,
            category: "System Hardening".to_string(),
            action: "Clear DNS cache".to_string(),
            description: "Flush DNS cache to remove any cached records that could reveal browsing history".to_string(),
            priority: "low".to_string(),
            automated: true,
            command: Some("sudo systemd-resolve --flush-caches (Linux) or sudo dscacheutil -flushcache (macOS)".to_string()),
            verification: "DNS cache should be empty after flush".to_string(),
        });

        warnings.push("Using multiple anonymity layers (VPN + Tor) significantly increases latency".to_string());
        warnings.push("Tor exit nodes can monitor unencrypted traffic - always use HTTPS".to_string());
        warnings.push("No anonymity system is perfect - practice good operational security (OPSEC)".to_string());

        let critical_issues = issues.iter().filter(|i| i.severity == "critical" || i.severity == "high").count();
        let estimated_improvement = match critical_issues {
            0 => 0.1,
            1..=2 => 0.3,
            3..=5 => 0.5,
            _ => 0.7,
        };

        AnonymizationPlan {
            current_anonymity_level: current_level,
            target_anonymity_level: target_level,
            steps,
            estimated_anonymity_improvement: estimated_improvement,
            warnings,
            tools_required,
        }
    }
}
