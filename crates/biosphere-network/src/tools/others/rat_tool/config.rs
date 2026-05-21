use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatToolConfig {
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub operation: String,
}

impl Default for RatToolConfig {
    fn default() -> Self {
        Self {
            target_host: String::new(),
            target_port: 4444,
            protocol: "tcp".to_string(),
            operation: "detect".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatConnection {
    pub remote_address: String,
    pub local_address: String,
    pub state: String,
    pub protocol: String,
    pub process_name: String,
    pub pid: u32,
    pub data_volume: u64,
    pub duration_secs: u64,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatCapability {
    pub name: String,
    pub category: String,
    pub risk_level: String,
    pub description: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatDetection {
    pub rat_family: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub c2_server: String,
    pub protocol: String,
    pub persistence_mechanism: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatSecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatToolResult {
    pub success: bool,
    pub target: String,
    pub connections: Vec<RatConnection>,
    pub capabilities: Vec<RatCapability>,
    pub detections: Vec<RatDetection>,
    pub security_findings: Vec<RatSecurityFinding>,
    pub summary: String,
}

struct RatSignature {
    port: u16,
    family: &'static str,
    persistence: &'static str,
    indicators: Vec<&'static str>,
}

pub struct RatTool;

impl RatTool {
    fn get_rat_signatures() -> Vec<RatSignature> {
        vec![
            RatSignature { port: 4444, family: "Metasploit Default", persistence: "registry_run_key/scheduled_task", indicators: vec!["Port 4444 is Metasploit default listener", "Default configuration unchanged"] },
            RatSignature { port: 5555, family: "Common RAT (5555)", persistence: "registry_run_key", indicators: vec!["Port 5555 is common RAT port", "Android ADB default port reuse"] },
            RatSignature { port: 1337, family: "Backdoor (1337)", persistence: "system_service", indicators: vec!["Port 1337 is common backdoor port", "Leet speak commonly used port"] },
            RatSignature { port: 31337, family: "Back Orifice", persistence: "registry_run_key/system_service", indicators: vec!["Port 31337 is Back Orifice default port", "Classic Windows backdoor"] },
            RatSignature { port: 6666, family: "Common RAT (6666)", persistence: "registry_run_key", indicators: vec!["Port 6666 is common RAT port"] },
            RatSignature { port: 6667, family: "IRC Backdoor", persistence: "registry_run_key/scheduled_task", indicators: vec!["Port 6667 is IRC default port", "IRC backdoor commonly uses this port"] },
            RatSignature { port: 9999, family: "Common RAT (9999)", persistence: "registry_run_key", indicators: vec!["Port 9999 is common RAT port"] },
            RatSignature { port: 12345, family: "NetBus", persistence: "registry_run_key", indicators: vec!["Port 12345 is NetBus default port", "Classic remote administration tool"] },
            RatSignature { port: 27374, family: "SubSeven", persistence: "registry_run_key/system_service", indicators: vec!["Port 27374 is SubSeven default port", "Classic Windows RAT"] },
            RatSignature { port: 54321, family: "Common Backdoor (54321)", persistence: "registry_run_key", indicators: vec!["Port 54321 is common backdoor port"] },
            RatSignature { port: 6660, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6660 is IRC C2 commonly used port"] },
            RatSignature { port: 6661, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6661 is IRC C2 commonly used port"] },
            RatSignature { port: 6662, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6662 is IRC C2 commonly used port"] },
            RatSignature { port: 6663, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6663 is IRC C2 commonly used port"] },
            RatSignature { port: 6664, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6664 is IRC C2 commonly used port"] },
            RatSignature { port: 6665, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6665 is IRC C2 commonly used port"] },
            RatSignature { port: 6668, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6668 is IRC C2 commonly used port"] },
            RatSignature { port: 6669, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 6669 is IRC C2 commonly used port"] },
            RatSignature { port: 7000, family: "IRC C2", persistence: "registry_run_key", indicators: vec!["Port 7000 is IRC C2 commonly used port"] },
            RatSignature { port: 1604, family: "DarkComet", persistence: "registry_run_key/hkcu_run", indicators: vec!["Port 1604 is DarkComet default port", "DarkComet RAT signature"] },
            RatSignature { port: 5300, family: "DarkComet (Alt)", persistence: "registry_run_key/hkcu_run", indicators: vec!["Port 5300 is DarkComet alternate port"] },
            RatSignature { port: 2589, family: "Poison Ivy", persistence: "registry_run_key", indicators: vec!["Port 2589 is Poison Ivy default port"] },
            RatSignature { port: 3460, family: "Poison Ivy (Alt)", persistence: "registry_run_key", indicators: vec!["Port 3460 is Poison Ivy alternate port"] },
            RatSignature { port: 443, family: "Cobalt Strike HTTPS", persistence: "scheduled_task/wmi_subscription", indicators: vec!["Port 443 used for Cobalt Strike HTTPS beacon", "Legitimate HTTPS traffic mimicry"] },
            RatSignature { port: 80, family: "Cobalt Strike HTTP", persistence: "scheduled_task/wmi_subscription", indicators: vec!["Port 80 used for Cobalt Strike HTTP beacon", "Legitimate HTTP traffic mimicry"] },
            RatSignature { port: 50050, family: "Cobalt Strike TeamServer", persistence: "n/a", indicators: vec!["Port 50050 is Cobalt Strike TeamServer default", "C2 infrastructure port"] },
            RatSignature { port: 9002, family: "Gh0st RAT", persistence: "registry_run_key/system_service", indicators: vec!["Port 9002 is Gh0st RAT commonly used port", "Chinese APT tool signature"] },
            RatSignature { port: 8080, family: "PlugX", persistence: "registry_run_key/wmi_subscription", indicators: vec!["Port 8080 used by PlugX RAT", "Often masquerades as legitimate HTTP proxy"] },
            RatSignature { port: 53, family: "DNS C2 Tunnel", persistence: "scheduled_task", indicators: vec!["Port 53 used for DNS-based C2 communication", "DNS tunneling for data exfiltration"] },
        ]
    }

    async fn scan_port(host: &str, port: u16, timeout_duration: Duration) -> bool {
        let addr = format!("{}:{}", host, port);
        match addr.parse::<SocketAddr>() {
            Ok(socket_addr) => {
                timeout(timeout_duration, TcpStream::connect(&socket_addr)).await.is_ok()
            }
            Err(_) => {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    let socket_addr = SocketAddr::new(ip, port);
                    timeout(timeout_duration, TcpStream::connect(&socket_addr)).await.is_ok()
                } else {
                    match tokio::net::lookup_host(&addr).await {
                        Ok(mut addrs) => {
                            if let Some(socket_addr) = addrs.next() {
                                timeout(timeout_duration, TcpStream::connect(&socket_addr)).await.is_ok()
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    }
                }
            }
        }
    }

    async fn grab_banner(host: &str, port: u16) -> Option<String> {
        let addr = format!("{}:{}", host, port);
        let socket_addr = match addr.parse::<SocketAddr>() {
            Ok(s) => s,
            Err(_) => {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    SocketAddr::new(ip, port)
                } else {
                    match tokio::net::lookup_host(&addr).await.ok()?.next() {
                        Some(s) => s,
                        None => return None,
                    }
                }
            }
        };

        if let Ok(Ok(mut stream)) = timeout(Duration::from_secs(5), TcpStream::connect(&socket_addr)).await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = stream.writable().await;
            let probe = match port {
                80 | 8080 | 8000 | 443 => b"GET / HTTP/1.1\r\nHost: target\r\n\r\n".to_vec(),
                21 | 22 | 25 | 110 | 143 => Vec::new(),
                _ => Vec::new(),
            };

            if !probe.is_empty() {
                let _ = stream.write_all(&probe).await;
            }

            let mut buf = [0u8; 1024];
            if let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                if n > 0 {
                    return Some(String::from_utf8_lossy(&buf[..n]).to_string());
                }
            }
        }
        None
    }

    fn get_active_connections() -> Vec<RatConnection> {
        let mut connections = Vec::new();

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("lsof")
                .args(["-i", "-n", "-P"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 9 {
                        let process_name = parts[0].to_string();
                        let pid = parts[1].parse::<u32>().unwrap_or(0);
                        let name_field = parts[8..].join(" ");
                        let protocol = if name_field.contains("TCP") { "TCP" } else { "UDP" }.to_string();

                        let (local_addr, remote_addr, state) = if name_field.contains("->") {
                            let mut addr_part = name_field.clone();
                            let conn_state = if addr_part.contains('(') {
                                let start = addr_part.rfind('(').unwrap_or(addr_part.len());
                                let end = addr_part.rfind(')').unwrap_or(addr_part.len());
                                if start < end {
                                    let s = addr_part[start+1..end].to_string();
                                    addr_part = addr_part[..start].trim_end().to_string();
                                    s
                                } else {
                                    "ESTABLISHED".to_string()
                                }
                            } else {
                                "ESTABLISHED".to_string()
                            };

                            if let Some(pos) = addr_part.find("->") {
                                let local = addr_part[..pos].trim().to_string();
                                let remote = addr_part[pos+2..].trim().to_string();
                                (local, remote, conn_state)
                            } else {
                                (addr_part.clone(), String::new(), conn_state)
                            }
                        } else {
                            let listen_state = if name_field.contains("(LISTEN)") {
                                "LISTEN".to_string()
                            } else {
                                "UNKNOWN".to_string()
                            };
                            let addr = name_field.split_whitespace().next().unwrap_or("").to_string();
                            (addr, String::new(), listen_state)
                        };

                        let is_suspicious = Self::is_connection_suspicious(&process_name, &local_addr, &remote_addr, &state);

                        connections.push(RatConnection {
                            remote_address: remote_addr,
                            local_address: local_addr,
                            state,
                            protocol,
                            process_name,
                            pid,
                            data_volume: 0,
                            duration_secs: 0,
                            is_suspicious,
                        });
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("ss")
                .args(["-tunap"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let process_re = regex::Regex::new(r#""([^"]+)".*?pid=(\d+)"#).unwrap();
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let protocol = parts[0].to_string();
                        let state = parts[1].to_string();
                        let local_addr = parts[4].to_string();
                        let remote_addr = parts[5].to_string();
                        let process_info = parts.get(6).unwrap_or(&"").to_string();

                        let (process_name, pid) = if process_info.contains('"') {
                            if let Some(caps) = process_re.captures(&process_info) {
                                (caps[1].to_string(), caps[2].parse::<u32>().unwrap_or(0))
                            } else {
                                (process_info.clone(), 0)
                            }
                        } else {
                            (process_info.clone(), 0)
                        };

                        let is_suspicious = Self::is_connection_suspicious(&process_name, &local_addr, &remote_addr, &state);

                        connections.push(RatConnection {
                            remote_address: remote_addr,
                            local_address: local_addr,
                            state,
                            protocol,
                            process_name,
                            pid,
                            data_volume: 0,
                            duration_secs: 0,
                            is_suspicious,
                        });
                    }
                }
            }
        }

        connections
    }

    fn is_connection_suspicious(process_name: &str, local_addr: &str, remote_addr: &str, state: &str) -> bool {
        let suspicious_processes = ["nc", "ncat", "socat", "nmap", "meterpreter", "reverse_shell", "suspicious"];
        let name_lower = process_name.to_lowercase();
        for sp in &suspicious_processes {
            if name_lower.contains(sp) {
                return true;
            }
        }

        if state == "ESTABLISHED" && !remote_addr.is_empty() {
            let rat_ports = [4444, 5555, 1337, 31337, 6666, 6667, 9999, 12345, 27374, 54321, 1604, 5300, 2589, 3460, 50050, 9002];
            for port in &rat_ports {
                if remote_addr.contains(&format!(":{}", port)) || local_addr.contains(&format!(":{}", port)) {
                    return true;
                }
            }
        }

        false
    }

    fn analyze_banner_for_rat(banner: &str, port: u16) -> Option<String> {
        let banner_lower = banner.to_lowercase();

        let rat_signatures = [
            ("metasploit", "Metasploit"),
            ("meterpreter", "Meterpreter"),
            ("back orifice", "Back Orifice"),
            ("netbus", "NetBus"),
            ("subseven", "SubSeven"),
            ("darkcomet", "DarkComet"),
            ("poison ivy", "Poison Ivy"),
            ("gh0st", "Gh0st RAT"),
            ("plugx", "PlugX"),
            ("cobalt strike", "Cobalt Strike"),
            ("beacon", "Cobalt Strike Beacon"),
            ("carbanak", "Carbanak"),
            ("miniduke", "MiniDuke"),
            ("cosmicduke", "CosmicDuke"),
            ("njrat", "njRAT"),
            ("remcos", "Remcos"),
            ("nanocore", "NanoCore"),
            ("spy-net", "Spy-Net"),
            ("blacknix", "BlackNix"),
            ("droidjack", "DroidJack"),
            ("androrat", "AndroRAT"),
            ("quasar", "Quasar RAT"),
            ("asyncrat", "AsyncRAT"),
        ];

        for (sig, family) in &rat_signatures {
            if banner_lower.contains(sig) {
                return Some(family.to_string());
            }
        }

        if port == 4444 && (banner_lower.contains("shell") || banner_lower.contains("meterpreter")) {
            return Some("Metasploit".to_string());
        }

        None
    }

    pub async fn analyze(config: &RatToolConfig) -> Result<RatToolResult, String> {
        if config.target_host.is_empty() {
            return Err("Target host address is required".to_string());
        }

        let mut connections = Vec::new();
        let mut capabilities = Vec::new();
        let mut detections = Vec::new();
        let mut security_findings = Vec::new();

        let target = format!("{}:{}", config.target_host, config.target_port);

        let rat_signatures = Self::get_rat_signatures();
        let scan_timeout = Duration::from_secs(3);

        let is_target_open = Self::scan_port(&config.target_host, config.target_port, scan_timeout).await;

        if is_target_open {
            let banner = Self::grab_banner(&config.target_host, config.target_port).await;
            let mut banner_family_matched = false;

            if let Some(ref banner_text) = banner {
                if let Some(family) = Self::analyze_banner_for_rat(banner_text, config.target_port) {
                    banner_family_matched = true;
                    detections.push(RatDetection {
                        rat_family: family,
                        confidence: 0.95,
                        indicators: vec![
                            format!("Port {} open with RAT banner match", config.target_port),
                            format!("Banner content: {}", banner_text.chars().take(100).collect::<String>()),
                        ],
                        c2_server: config.target_host.clone(),
                        protocol: config.protocol.clone(),
                        persistence_mechanism: "pending_further_analysis".to_string(),
                    });
                }
            }

            for sig in &rat_signatures {
                if sig.port == config.target_port {
                    if banner_family_matched {
                        continue;
                    }
                    let mut indicators = sig.indicators.iter().map(|s| s.to_string()).collect::<Vec<_>>();
                    if let Some(ref b) = banner {
                        indicators.push(format!("Banner: {}", b.chars().take(80).collect::<String>()));
                    }
                    detections.push(RatDetection {
                        rat_family: sig.family.to_string(),
                        confidence: if banner.is_some() { 0.90 } else { 0.70 },
                        indicators,
                        c2_server: config.target_host.clone(),
                        protocol: config.protocol.clone(),
                        persistence_mechanism: sig.persistence.to_string(),
                    });
                }
            }

            if detections.is_empty() {
                detections.push(RatDetection {
                    rat_family: "Unknown RAT".to_string(),
                    confidence: 0.40,
                    indicators: vec![
                        format!("Port {} open but no known RAT signature matched", config.target_port),
                        "Further traffic analysis recommended".to_string(),
                    ],
                    c2_server: config.target_host.clone(),
                    protocol: config.protocol.clone(),
                    persistence_mechanism: "pending_analysis".to_string(),
                });
            }

            connections.push(RatConnection {
                remote_address: format!("{}:{}", config.target_host, config.target_port),
                local_address: "0.0.0.0:0".to_string(),
                state: "ESTABLISHED".to_string(),
                protocol: config.protocol.clone(),
                process_name: "unknown".to_string(),
                pid: 0,
                data_volume: 0,
                duration_secs: 0,
                is_suspicious: true,
            });
        }

        let mut open_rat_ports = Vec::new();
        let should_scan_extra_ports = config.operation == "detect" || config.operation == "full";

        if should_scan_extra_ports {
            let mut extra_ports_to_scan: Vec<u16> = rat_signatures.iter().map(|s| s.port).collect();
            extra_ports_to_scan.sort();
            extra_ports_to_scan.dedup();
            extra_ports_to_scan.retain(|&p| p != config.target_port);

            let mut join_set = tokio::task::JoinSet::new();
            for port in extra_ports_to_scan {
                let host = config.target_host.clone();
                join_set.spawn(async move {
                    let is_open = Self::scan_port(&host, port, Duration::from_secs(2)).await;
                    (port, is_open)
                });
            }

            while let Some(result) = join_set.join_next().await {
                if let Ok((port, is_open)) = result {
                    if is_open {
                        open_rat_ports.push(port);
                    }
                }
            }

            for open_port in &open_rat_ports {
                let banner = Self::grab_banner(&config.target_host, *open_port).await;

                for sig in &rat_signatures {
                    if sig.port == *open_port {
                        let mut indicators = sig.indicators.iter().map(|s| s.to_string()).collect::<Vec<_>>();
                        if let Some(ref b) = banner {
                            indicators.push(format!("Banner: {}", b.chars().take(80).collect::<String>()));
                            if let Some(family) = Self::analyze_banner_for_rat(b, *open_port) {
                                indicators.push(format!("Banner matched RAT family: {}", family));
                            }
                        }
                        detections.push(RatDetection {
                            rat_family: sig.family.to_string(),
                            confidence: if banner.is_some() { 0.90 } else { 0.70 },
                            indicators,
                            c2_server: config.target_host.clone(),
                            protocol: "tcp".to_string(),
                            persistence_mechanism: sig.persistence.to_string(),
                        });
                    }
                }

                connections.push(RatConnection {
                    remote_address: format!("{}:{}", config.target_host, open_port),
                    local_address: "0.0.0.0:0".to_string(),
                    state: "ESTABLISHED".to_string(),
                    protocol: "tcp".to_string(),
                    process_name: "unknown".to_string(),
                    pid: 0,
                    data_volume: 0,
                    duration_secs: 0,
                    is_suspicious: true,
                });
            }
        }

        let local_connections = Self::get_active_connections();
        let suspicious_local = local_connections.into_iter().filter(|c| c.is_suspicious).collect::<Vec<_>>();
        connections.extend(suspicious_local);

        let should_analyze_capabilities = config.operation == "capabilities" || config.operation == "full";

        if !detections.is_empty() && should_analyze_capabilities {
            let rat_capability_map: Vec<(&str, &str, &str, &str, Vec<&str>)> = vec![
                ("keylogger", "info_collection", "high", "Records user keyboard input", vec!["keylog", "keyboard hook"]),
                ("screen_capture", "info_collection", "medium", "Periodically captures screen images", vec!["screenshot", "screen capture"]),
                ("file_manager", "remote_control", "high", "Remote file system browsing and manipulation", vec!["file manager", "remote fs"]),
                ("remote_shell", "remote_control", "critical", "Provides remote command execution capability", vec!["remote shell", "cmd exec"]),
                ("webcam_access", "privacy_violation", "critical", "Remote webcam access", vec!["webcam", "camera access"]),
                ("microphone_monitor", "privacy_violation", "critical", "Remote microphone listening", vec!["microphone", "audio capture"]),
                ("clipboard_monitor", "info_collection", "medium", "Monitors clipboard content", vec!["clipboard", "clipboard monitor"]),
                ("credential_theft", "credential_theft", "critical", "Extracts saved passwords", vec!["password dump", "credential theft"]),
                ("process_manipulation", "system_control", "high", "Start/stop/modify system processes", vec!["process list", "process kill"]),
                ("registry_editor", "system_control", "medium", "Remote Windows registry modification", vec!["registry edit", "reg key modify"]),
                ("download_execute", "payload_delivery", "critical", "Download and execute additional payloads", vec!["download exec", "dropper"]),
                ("lateral_movement", "network_propagation", "high", "Spread to other systems on the network", vec!["lateral move", "network spread"]),
            ];

            for (name, category, risk, desc, indicators) in &rat_capability_map {
                capabilities.push(RatCapability {
                    name: name.to_string(),
                    category: category.to_string(),
                    risk_level: risk.to_string(),
                    description: desc.to_string(),
                    indicators: indicators.iter().map(|s| s.to_string()).collect(),
                });
            }
        }

        if !detections.is_empty() {
            security_findings.push(RatSecurityFinding {
                severity: "critical".to_string(),
                category: "rat_detected".to_string(),
                description: format!("Detected {} RAT family signatures", detections.len()),
                recommendation: "Immediately isolate the infected host and perform full forensic analysis".to_string(),
                mitre_technique: Some("T1219".to_string()),
            });
        }

        if !open_rat_ports.is_empty() {
            security_findings.push(RatSecurityFinding {
                severity: "high".to_string(),
                category: "extra_rat_ports".to_string(),
                description: format!("Target host has {} additional known RAT ports open: {:?}", open_rat_ports.len(), open_rat_ports),
                recommendation: "Check services on these ports to confirm if they are legitimate".to_string(),
                mitre_technique: Some("T1571".to_string()),
            });
        }

        if is_target_open {
            security_findings.push(RatSecurityFinding {
                severity: "high".to_string(),
                category: "c2_communication".to_string(),
                description: format!("Target {}:{} exhibits suspicious C2 communication characteristics", config.target_host, config.target_port),
                recommendation: "Inspect network traffic and block C2 communication".to_string(),
                mitre_technique: Some("T1071".to_string()),
            });
        }

        let suspicious_count = connections.iter().filter(|c| c.is_suspicious).count();
        if suspicious_count > 0 {
            security_findings.push(RatSecurityFinding {
                severity: "medium".to_string(),
                category: "local_suspicious_connections".to_string(),
                description: format!("Found {} suspicious network connections on local system", suspicious_count),
                recommendation: "Check processes associated with suspicious connections, confirm if RAT is implanted".to_string(),
                mitre_technique: Some("T1071".to_string()),
            });
        }

        if !detections.is_empty() {
            let high_confidence: Vec<&RatDetection> = detections.iter().filter(|d| d.confidence >= 0.9).collect();
            if !high_confidence.is_empty() {
                security_findings.push(RatSecurityFinding {
                    severity: "critical".to_string(),
                    category: "high_confidence_detection".to_string(),
                    description: format!("{} RAT detection(s) with high confidence (>=90%)", high_confidence.len()),
                    recommendation: "Treat as confirmed infection - initiate incident response procedures immediately".to_string(),
                    mitre_technique: Some("T1219".to_string()),
                });
            }
        }

        if is_target_open && banner_is_suspicious(&detections) {
            security_findings.push(RatSecurityFinding {
                severity: "high".to_string(),
                category: "suspicious_banner".to_string(),
                description: "Service banner contains patterns consistent with known RAT tools".to_string(),
                recommendation: "Analyze the banner content in detail and compare with known RAT signatures".to_string(),
                mitre_technique: Some("T1200".to_string()),
            });
        }

        let summary = if !detections.is_empty() {
            let op_label = match config.operation.as_str() {
                "detect" => "Detection",
                "capabilities" => "Capability Analysis",
                "full" => "Full Audit",
                _ => "Analysis",
            };
            format!(
                "[{}] RAT activity detected | Families: {} | Suspicious connections: {} | Capabilities: {} | Findings: {}",
                op_label, detections.len(), connections.len(), capabilities.len(), security_findings.len()
            )
        } else if is_target_open {
            format!(
                "Target {}:{} port open but no known RAT signature matched, further analysis recommended",
                config.target_host, config.target_port
            )
        } else {
            format!(
                "Target {}:{} - No known RAT characteristics detected",
                config.target_host, config.target_port
            )
        };

        Ok(RatToolResult {
            success: true,
            target,
            connections,
            capabilities,
            detections,
            security_findings,
            summary,
        })
    }
}

fn banner_is_suspicious(detections: &[RatDetection]) -> bool {
    detections.iter().any(|d| d.indicators.iter().any(|ind| ind.starts_with("Banner:")))
}
