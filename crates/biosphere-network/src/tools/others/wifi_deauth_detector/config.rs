use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiDeauthConfig {
    pub interface: String,
    pub scan_duration: u64,
    pub channel: Option<u32>,
    pub detect_all_channels: bool,
    pub alert_threshold: u32,
    pub monitor_mode: bool,
    pub capture_packets: bool,
    pub max_packets: u32,
    pub timeout: u64,
}

impl Default for WifiDeauthConfig {
    fn default() -> Self {
        Self {
            interface: "en0".to_string(),
            scan_duration: 30,
            channel: None,
            detect_all_channels: true,
            alert_threshold: 5,
            monitor_mode: true,
            capture_packets: true,
            max_packets: 1000,
            timeout: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthPacket {
    pub timestamp: String,
    pub source_mac: String,
    pub destination_mac: String,
    pub bssid: String,
    pub channel: u32,
    pub signal_dbm: i32,
    pub packet_type: String,
    pub reason_code: u16,
    pub reason_description: String,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub channel: u32,
    pub signal_dbm: i32,
    pub encryption: String,
    pub is_suspicious: bool,
    pub deauth_count: u32,
    pub clients_affected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthAlert {
    pub severity: String,
    pub alert_type: String,
    pub description: String,
    pub source_mac: String,
    pub target_mac: String,
    pub bssid: String,
    pub channel: u32,
    pub packet_count: u32,
    pub recommendation: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAnalysis {
    pub channel: u32,
    pub total_packets: u32,
    pub deauth_packets: u32,
    pub deauth_ratio: f64,
    pub is_anomalous: bool,
    pub access_points: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiDeauthResult {
    pub success: bool,
    pub interface: String,
    pub scan_duration: u64,
    pub total_packets_captured: u32,
    pub deauth_packets_detected: u32,
    pub access_points: Vec<AccessPoint>,
    pub deauth_packets: Vec<DeauthPacket>,
    pub alerts: Vec<DeauthAlert>,
    pub channel_analysis: Vec<ChannelAnalysis>,
    pub attack_detected: bool,
    pub attack_type: String,
    pub security_findings: Vec<WifiDeauthFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiDeauthFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiInterface {
    pub name: String,
    pub interface_type: String,
    pub is_wireless: bool,
    pub is_up: bool,
}

pub struct WifiDeauthDetectorTool;

impl WifiDeauthDetectorTool {
    pub async fn detect(config: &WifiDeauthConfig) -> std::result::Result<WifiDeauthResult, String> {
        let interface = config.interface.trim().to_string();

        if interface.is_empty() {
            return Err("Network interface name cannot be empty".to_string());
        }

        let mut result = WifiDeauthResult {
            success: true,
            interface: interface.clone(),
            scan_duration: config.scan_duration,
            total_packets_captured: 0,
            deauth_packets_detected: 0,
            access_points: Vec::new(),
            deauth_packets: Vec::new(),
            alerts: Vec::new(),
            channel_analysis: Vec::new(),
            attack_detected: false,
            attack_type: String::new(),
            security_findings: Vec::new(),
            summary: String::new(),
        };

        let scan_output = Self::run_wifi_scan(&interface);
        let aps = Self::parse_access_points(&scan_output);
        result.access_points = aps;

        if config.capture_packets {
            let packet_output = Self::capture_deauth_packets(&interface, config.scan_duration, config.timeout);
            let packets = Self::parse_deauth_packets(&packet_output);
            result.total_packets_captured = packets.len() as u32;

            for pkt in &packets {
                if pkt.is_suspicious {
                    result.deauth_packets_detected += 1;
                }
            }
            result.deauth_packets = packets;
        } else {
            result.total_packets_captured = scan_output.lines().count() as u32;
        }

        Self::correlate_deauth_with_aps(&mut result);

        result.channel_analysis = Self::analyze_channels(&result.access_points, &result.deauth_packets);
        result.alerts = Self::generate_alerts(&result.deauth_packets, &result.access_points, config.alert_threshold);

        let evil_twin_alerts = Self::detect_evil_twins(&result.access_points);
        result.alerts.extend(evil_twin_alerts);

        result.attack_detected = !result.alerts.is_empty();
        if result.attack_detected {
            result.attack_type = Self::classify_attack(&result.alerts);
        }

        result.security_findings = Self::analyze_security(&result);
        result.summary = Self::build_summary(&result);

        Ok(result)
    }

    pub fn list_interfaces() -> Vec<WifiInterface> {
        let mut interfaces = Vec::new();

        if let Ok(output) = std::process::Command::new("networksetup")
            .args(["-listallhardwareports"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut lines = text.lines().peekable();
            while let Some(line) = lines.next() {
                if line.starts_with("Device:") {
                    let device = line.replace("Device:", "").trim().to_string();
                    let mut is_wireless = false;
                    let mut iface_type = "Ethernet".to_string();

                    if let Some(next) = lines.peek() {
                        if next.starts_with("Ethernet Address:") {
                            lines.next();
                        }
                    }

                    if device.starts_with("en") {
                        if let Ok(iw_output) = std::process::Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
                            .args(["-I", &device])
                            .output()
                        {
                            let iw_text = String::from_utf8_lossy(&iw_output.stdout);
                            is_wireless = !iw_text.contains("AirPort: Off") && !iw_text.trim().is_empty();
                            if is_wireless {
                                iface_type = "Wi-Fi".to_string();
                            }
                        }
                    }

                    let is_up = std::path::Path::new(&format!("/sys/class/net/{}/operstate", device)).exists()
                        || Self::check_interface_up(&device);

                    interfaces.push(WifiInterface {
                        name: device,
                        interface_type: iface_type,
                        is_wireless,
                        is_up,
                    });
                }
            }
        }

        if let Ok(output) = std::process::Command::new("ifconfig")
            .args(["-l"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for iface in text.split_whitespace() {
                if !interfaces.iter().any(|i| i.name == iface) {
                    let is_wireless = iface.starts_with("wlan") || iface.starts_with("wlp");
                    interfaces.push(WifiInterface {
                        name: iface.to_string(),
                        interface_type: if is_wireless { "Wi-Fi".to_string() } else { "Other".to_string() },
                        is_wireless,
                        is_up: Self::check_interface_up(iface),
                    });
                }
            }
        }

        if interfaces.is_empty() {
            interfaces.push(WifiInterface {
                name: "en0".to_string(),
                interface_type: "Wi-Fi".to_string(),
                is_wireless: true,
                is_up: true,
            });
        }

        interfaces
    }

    fn check_interface_up(iface: &str) -> bool {
        if let Ok(output) = std::process::Command::new("ifconfig")
            .arg(iface)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            return text.contains("status: active") || text.contains("inet ");
        }
        false
    }

    fn run_wifi_scan(interface: &str) -> String {
        let mut output = String::new();

        if let Ok(result) = std::process::Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .args(["-s"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            if !stdout.trim().is_empty() {
                output = stdout;
            }
        }

        if output.is_empty() {
            if let Ok(result) = std::process::Command::new("iwlist")
                .args([interface, "scan"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&result.stdout).to_string();
                if !stdout.trim().is_empty() {
                    output = stdout;
                }
            }
        }

        if output.is_empty() {
            if let Ok(result) = std::process::Command::new("nmcli")
                .args(["device", "wifi", "list", "--rescan", "yes"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&result.stdout).to_string();
                if !stdout.trim().is_empty() {
                    output = stdout;
                }
            }
        }

        output
    }

    fn parse_access_points(output: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();

        if output.contains("SSID") && output.contains("BSSID") {
            aps = Self::parse_airport_output(output);
        }

        if aps.is_empty() && output.contains("Cell") {
            aps = Self::parse_iwlist_output(output);
        }

        if aps.is_empty() && output.contains("IN-USE") {
            aps = Self::parse_nmcli_output(output);
        }

        if aps.is_empty() {
            aps = Self::parse_generic_output(output);
        }

        aps
    }

    fn parse_airport_output(output: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();
        let mac_re = regex_for_mac();
        for line in output.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() { continue; }

            let mut ssid = String::new();
            if let Some(mac_match) = mac_re.find(line) {
                let before_mac = line[..mac_match.start()].trim();
                ssid = if before_mac.is_empty() { "<Hidden>".to_string() } else { before_mac.to_string() };
            }

            let bssid_match = Self::extract_bssid(line);
            let channel = Self::extract_channel(line);
            let signal = Self::extract_signal(line);
            let encryption = Self::extract_encryption(line);

            if ssid.is_empty() && bssid_match.is_empty() { continue; }
            if ssid.is_empty() { ssid = "<Hidden>".to_string(); }

            aps.push(AccessPoint {
                ssid,
                bssid: bssid_match,
                channel,
                signal_dbm: signal,
                encryption,
                is_suspicious: false,
                deauth_count: 0,
                clients_affected: Vec::new(),
            });
        }
        aps
    }

    fn parse_iwlist_output(output: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();
        let mut current_ssid = String::new();
        let mut current_bssid = String::new();
        let mut current_channel: u32 = 0;
        let mut current_signal: i32 = -100;
        let mut current_encryption = "Unknown".to_string();

        for line in output.lines() {
            let line = line.trim();

            if line.starts_with("Cell") {
                if !current_ssid.is_empty() {
                    aps.push(AccessPoint {
                        ssid: current_ssid.clone(),
                        bssid: current_bssid.clone(),
                        channel: current_channel,
                        signal_dbm: current_signal,
                        encryption: current_encryption.clone(),
                        is_suspicious: false,
                        deauth_count: 0,
                        clients_affected: Vec::new(),
                    });
                }
                current_ssid = String::new();
                current_bssid = String::new();
                current_channel = 0;
                current_signal = -100;
                current_encryption = "Unknown".to_string();

                if let Some(addr) = line.split("Address:").nth(1) {
                    current_bssid = addr.trim().to_string();
                }
            }

            if line.starts_with("ESSID:") {
                current_ssid = line.replace("ESSID:", "").trim().trim_matches('"').to_string();
            }
            if line.contains("Channel:") {
                if let Some(ch) = line.split("Channel:").nth(1) {
                    current_channel = ch.trim().parse().unwrap_or(0);
                }
            }
            if line.contains("Frequency:") && line.contains("Channel ") {
                if let Some(ch_part) = line.split("Channel ").nth(1) {
                    current_channel = ch_part.trim().trim_end_matches(')').parse().unwrap_or(0);
                }
            }
            if line.contains("Signal level=") {
                if let Some(sig_part) = line.split("Signal level=").nth(1) {
                    let sig_str: String = sig_part.chars().take_while(|c| c.is_digit(10) || *c == '-').collect();
                    current_signal = sig_str.parse().unwrap_or(-100);
                }
            }
            if line.contains("Encryption key:") {
                if line.contains("off") {
                    current_encryption = "OPN".to_string();
                }
            }
            if line.contains("WPA3") {
                current_encryption = "WPA3".to_string();
            } else if line.contains("WPA2") {
                current_encryption = "WPA2".to_string();
            } else if line.contains("WPA") && current_encryption != "WPA2" && current_encryption != "WPA3" {
                current_encryption = "WPA".to_string();
            } else if line.contains("WEP") {
                current_encryption = "WEP".to_string();
            }
        }

        if !current_ssid.is_empty() {
            aps.push(AccessPoint {
                ssid: current_ssid,
                bssid: current_bssid,
                channel: current_channel,
                signal_dbm: current_signal,
                encryption: current_encryption,
                is_suspicious: false,
                deauth_count: 0,
                clients_affected: Vec::new(),
            });
        }

        aps
    }

    fn parse_nmcli_output(output: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();
        let mut header_indices: Vec<usize> = Vec::new();

        if let Some(header) = output.lines().next() {
            for (i, c) in header.char_indices() {
                if i == 0 || (c.is_uppercase() && i > 0 && !header.chars().nth(i-1).unwrap_or(' ').is_uppercase()) {
                    header_indices.push(i);
                }
            }
        }

        for line in output.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() { continue; }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let ssid = parts[0].to_string();
                let signal_str = parts.get(2).unwrap_or(&"0");
                let signal: i32 = signal_str.parse().unwrap_or(0);
                let signal_dbm = if signal > 0 { -100 + signal } else { signal };
                let channel: u32 = parts.get(3).unwrap_or(&"0").parse().unwrap_or(0);
                let encryption = parts.last().unwrap_or(&"Unknown").to_string();

                aps.push(AccessPoint {
                    ssid,
                    bssid: String::new(),
                    channel,
                    signal_dbm,
                    encryption,
                    is_suspicious: false,
                    deauth_count: 0,
                    clients_affected: Vec::new(),
                });
            }
        }

        aps
    }

    fn parse_generic_output(output: &str) -> Vec<AccessPoint> {
        let mut aps = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("SSID") || line.starts_with("BSSID") {
                continue;
            }

            let mac_pattern = regex_for_mac();
            if let Some(mac_match) = mac_pattern.find(line) {
                let bssid = mac_match.as_str().to_string();
                let before_mac = &line[..mac_match.start()];
                let ssid = before_mac.trim().to_string();
                let after_mac = &line[mac_match.end()..];

                let channel = Self::extract_channel(after_mac);
                let signal = Self::extract_signal(after_mac);
                let encryption = Self::extract_encryption(after_mac);

                aps.push(AccessPoint {
                    ssid: if ssid.is_empty() { "<Hidden>".to_string() } else { ssid },
                    bssid,
                    channel,
                    signal_dbm: signal,
                    encryption,
                    is_suspicious: false,
                    deauth_count: 0,
                    clients_affected: Vec::new(),
                });
            }
        }

        if aps.is_empty() && !output.trim().is_empty() {
            aps.push(AccessPoint {
                ssid: "Scan-Result".to_string(),
                bssid: "N/A".to_string(),
                channel: 0,
                signal_dbm: 0,
                encryption: "Unknown".to_string(),
                is_suspicious: false,
                deauth_count: 0,
                clients_affected: Vec::new(),
            });
        }

        aps
    }

    fn extract_bssid(line: &str) -> String {
        let mac_pattern = regex_for_mac();
        if let Some(m) = mac_pattern.find(line) {
            return m.as_str().to_string();
        }
        String::new()
    }

    fn extract_channel(text: &str) -> u32 {
        for part in text.split_whitespace() {
            if let Ok(ch) = part.parse::<u32>() {
                if ch >= 1 && ch <= 165 {
                    return ch;
                }
            }
        }
        0
    }

    fn extract_signal(text: &str) -> i32 {
        for part in text.split_whitespace() {
            if part.starts_with('-') {
                if let Ok(sig) = part.trim_end_matches(',').parse::<i32>() {
                    if sig >= -100 && sig <= 0 {
                        return sig;
                    }
                }
            }
        }
        -50
    }

    fn extract_encryption(text: &str) -> String {
        let upper = text.to_uppercase();
        if upper.contains("WPA3") { return "WPA3".to_string(); }
        if upper.contains("WPA2") { return "WPA2".to_string(); }
        if upper.contains("WPA") { return "WPA".to_string(); }
        if upper.contains("WEP") { return "WEP".to_string(); }
        if upper.contains("OPN") || upper.contains("OPEN") || upper.contains("--") { return "OPN".to_string(); }
        "Unknown".to_string()
    }

    fn capture_deauth_packets(interface: &str, duration: u64, timeout: u64) -> String {
        let mut output = String::new();
        let effective_timeout = std::cmp::min(duration, timeout);
        let max_packets = 500u32;

        if let Ok(result) = std::process::Command::new("tcpdump")
            .args([
                "-i", interface,
                "-c", &max_packets.to_string(),
                "-l",
                "-n",
                "-t",
                "-G", &effective_timeout.to_string(),
                "type mgt subtype deauth or type mgt subtype disassoc",
            ])
            .output()
        {
            let stdout = String::from_utf8_lossy(&result.stdout).to_string();
            if !stdout.trim().is_empty() {
                output = stdout;
            }
        }

        if output.is_empty() {
            if let Ok(result) = std::process::Command::new("tshark")
                .args([
                    "-i", interface,
                    "-a", &format!("duration:{}", effective_timeout.min(30)),
                    "-c", &max_packets.to_string(),
                    "-f", "subtype deauth or subtype disassoc",
                    "-T", "fields",
                    "-e", "wlan.sa",
                    "-e", "wlan.da",
                    "-e", "wlan.bssid",
                    "-e", "radiotap.dbm_antsignal",
                    "-e", "wlan_radio.channel",
                    "-e", "wlan.fixed.reason_code",
                ])
                .output()
            {
                let stdout = String::from_utf8_lossy(&result.stdout).to_string();
                if !stdout.trim().is_empty() {
                    output = stdout;
                }
            }
        }

        output
    }

    fn parse_deauth_packets(output: &str) -> Vec<DeauthPacket> {
        let mut packets = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let source_mac = parts[0].to_string();
                let destination_mac = if parts.len() > 1 { parts[1].to_string() } else { "ff:ff:ff:ff:ff:ff".to_string() };
                let bssid = if parts.len() > 2 { parts[2].to_string() } else { source_mac.clone() };

                let signal_dbm = parts.get(3)
                    .and_then(|s| s.parse::<i32>().ok())
                    .unwrap_or(-50);

                let channel = parts.get(4)
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);

                let reason_code = parts.get(5)
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(1);

                let is_suspicious = destination_mac == "ff:ff:ff:ff:ff:ff"
                    || destination_mac == "Broadcast"
                    || destination_mac.to_lowercase() == "ff:ff:ff:ff:ff:ff";

                packets.push(DeauthPacket {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source_mac,
                    destination_mac,
                    bssid,
                    channel,
                    signal_dbm,
                    packet_type: "Deauthentication".to_string(),
                    reason_code,
                    reason_description: Self::reason_code_description(reason_code),
                    is_suspicious,
                });
            }
        }

        packets
    }

    fn reason_code_description(code: u16) -> String {
        match code {
            0 => "Reserved".to_string(),
            1 => "Unspecified reason".to_string(),
            2 => "Previous authentication no longer valid".to_string(),
            3 => "Station is leaving or has left BSS".to_string(),
            4 => "Disassociated due to inactivity".to_string(),
            5 => "AP unable to handle all associated stations".to_string(),
            6 => "Class 2 frame received from nonauthenticated station".to_string(),
            7 => "Class 3 frame received from nonassociated station".to_string(),
            8 => "Station leaving BSS (disassociating)".to_string(),
            9 => "Station requesting reassociation not authenticated".to_string(),
            10 => "Disassociated because information in Power Capability element is unacceptable".to_string(),
            15 => "Association denied due to unspecified reason".to_string(),
            17 => "Association denied because AP is unable to handle additional associated stations".to_string(),
            18 => "Station requesting association is not authenticated".to_string(),
            23 => "Association denied due to rejected lifetime value".to_string(),
            30 => "Association denied - Power Capability element content is unacceptable".to_string(),
            31 => "Association denied - Supported Channels element content is unacceptable".to_string(),
            32 => "Association denied - Invalid information element".to_string(),
            37 => "Association denied - Requested service not supported".to_string(),
            _ => format!("Reason code {}", code),
        }
    }

    fn correlate_deauth_with_aps(result: &mut WifiDeauthResult) {
        let mut ap_deauth_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let mut ap_clients: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        for pkt in &result.deauth_packets {
            if pkt.is_suspicious {
                *ap_deauth_counts.entry(pkt.bssid.clone()).or_insert(0) += 1;
                let clients = ap_clients.entry(pkt.bssid.clone()).or_default();
                if !clients.contains(&pkt.destination_mac) {
                    clients.push(pkt.destination_mac.clone());
                }
            }
        }

        for ap in &mut result.access_points {
            if let Some(&count) = ap_deauth_counts.get(&ap.bssid) {
                ap.deauth_count = count;
                ap.is_suspicious = count > 3;
            }
            if let Some(clients) = ap_clients.get(&ap.bssid) {
                ap.clients_affected = clients.clone();
            }
        }
    }

    fn analyze_channels(aps: &[AccessPoint], packets: &[DeauthPacket]) -> Vec<ChannelAnalysis> {
        let mut channel_map: std::collections::HashMap<u32, ChannelAnalysis> = std::collections::HashMap::new();

        for ap in aps {
            let entry = channel_map.entry(ap.channel).or_insert_with(|| ChannelAnalysis {
                channel: ap.channel,
                total_packets: 0,
                deauth_packets: 0,
                deauth_ratio: 0.0,
                is_anomalous: false,
                access_points: Vec::new(),
            });
            if !entry.access_points.contains(&ap.ssid) {
                entry.access_points.push(ap.ssid.clone());
            }
        }

        for pkt in packets {
            let ch = if pkt.channel > 0 { pkt.channel } else {
                aps.iter().find(|ap| ap.bssid == pkt.bssid).map(|ap| ap.channel).unwrap_or(0)
            };
            let entry = channel_map.entry(ch).or_insert_with(|| ChannelAnalysis {
                channel: ch,
                total_packets: 0,
                deauth_packets: 0,
                deauth_ratio: 0.0,
                is_anomalous: false,
                access_points: Vec::new(),
            });
            entry.total_packets += 1;
            if pkt.is_suspicious {
                entry.deauth_packets += 1;
            }
        }

        for analysis in channel_map.values_mut() {
            if analysis.total_packets > 0 {
                analysis.deauth_ratio = analysis.deauth_packets as f64 / analysis.total_packets as f64;
            }
            analysis.is_anomalous = analysis.deauth_ratio > 0.3 || analysis.deauth_packets > 5;
        }

        let mut channels: Vec<ChannelAnalysis> = channel_map.into_values().collect();
        channels.sort_by_key(|c| c.channel);
        channels
    }

    fn generate_alerts(packets: &[DeauthPacket], aps: &[AccessPoint], threshold: u32) -> Vec<DeauthAlert> {
        let mut alerts = Vec::new();
        let mut mac_counts: std::collections::HashMap<String, Vec<&DeauthPacket>> = std::collections::HashMap::new();

        for pkt in packets {
            if pkt.is_suspicious {
                mac_counts.entry(pkt.source_mac.clone()).or_default().push(pkt);
            }
        }

        for (source_mac, pkts) in &mac_counts {
            if pkts.len() >= threshold as usize {
                let target_macs: Vec<String> = pkts.iter().map(|p| p.destination_mac.clone()).collect();
                let bssid = pkts[0].bssid.clone();
                let channel = pkts[0].channel;

                let severity = if pkts.len() >= threshold as usize * 3 {
                    "critical".to_string()
                } else if pkts.len() >= threshold as usize * 2 {
                    "high".to_string()
                } else {
                    "medium".to_string()
                };

                alerts.push(DeauthAlert {
                    severity,
                    alert_type: "Deauth Flood".to_string(),
                    description: format!("Detected {} Deauth frames from {}, targets: {}", pkts.len(), source_mac, target_macs.join(", ")),
                    source_mac: source_mac.clone(),
                    target_mac: target_macs.join(", "),
                    bssid,
                    channel,
                    packet_count: pkts.len() as u32,
                    recommendation: "Check if source MAC is legitimate; possible Deauth attack, consider switching channels or enabling 802.11w MFP".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        for ap in aps {
            if ap.deauth_count > threshold {
                alerts.push(DeauthAlert {
                    severity: "high".to_string(),
                    alert_type: "AP Under Attack".to_string(),
                    description: format!("AP '{}' ({}) under Deauth attack, {} clients affected", ap.ssid, ap.bssid, ap.clients_affected.len()),
                    source_mac: "Unknown".to_string(),
                    target_mac: ap.bssid.clone(),
                    bssid: ap.bssid.clone(),
                    channel: ap.channel,
                    packet_count: ap.deauth_count,
                    recommendation: "Enable 802.11w MFP; consider changing channels; check for unauthorized APs".to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        alerts.sort_by(|a, b| match a.severity.as_str() {
            "critical" => std::cmp::Ordering::Less,
            "high" => if b.severity == "critical" { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less },
            "medium" => if b.severity == "low" { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater },
            _ => std::cmp::Ordering::Greater,
        });

        alerts
    }

    fn detect_evil_twins(aps: &[AccessPoint]) -> Vec<DeauthAlert> {
        let mut alerts = Vec::new();
        let mut ssid_groups: std::collections::HashMap<String, Vec<&AccessPoint>> = std::collections::HashMap::new();

        for ap in aps {
            ssid_groups.entry(ap.ssid.clone()).or_default().push(ap);
        }

        for (ssid, group) in &ssid_groups {
            if group.len() > 1 {
                let bssids: Vec<String> = group.iter().map(|ap| ap.bssid.clone()).collect();
                let channels: Vec<u32> = group.iter().map(|ap| ap.channel).collect();
                let signals: Vec<i32> = group.iter().map(|ap| ap.signal_dbm).collect();

                let has_different_channels = channels.windows(2).any(|w| w[0] != w[1]);
                let has_similar_signals = signals.windows(2).all(|w| (w[0] - w[1]).abs() < 20);

                if has_different_channels || bssids.len() > 1 {
                    let is_likely_evil_twin = has_different_channels && has_similar_signals;

                    let severity = if is_likely_evil_twin { "high" } else { "medium" };

                    alerts.push(DeauthAlert {
                        severity: severity.to_string(),
                        alert_type: "Possible Evil Twin".to_string(),
                        description: format!(
                            "SSID '{}' found on {} different BSSIDs ({}) on channels {}",
                            ssid,
                            bssids.len(),
                            bssids.join(", "),
                            channels.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")
                        ),
                        source_mac: bssids.join(", "),
                        target_mac: String::new(),
                        bssid: bssids[0].clone(),
                        channel: channels[0],
                        packet_count: bssids.len() as u32,
                        recommendation: "Verify which AP is legitimate; Evil Twin attacks clone SSID to intercept traffic; check BSSID against known legitimate AP".to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        alerts
    }

    fn classify_attack(alerts: &[DeauthAlert]) -> String {
        if alerts.is_empty() {
            return "No attack".to_string();
        }

        let has_critical = alerts.iter().any(|a| a.severity == "critical");
        let has_flood = alerts.iter().any(|a| a.alert_type == "Deauth Flood");
        let has_evil_twin = alerts.iter().any(|a| a.alert_type == "Possible Evil Twin");

        if has_critical && has_flood && has_evil_twin {
            "Massive Deauth Flood + Evil Twin Attack".to_string()
        } else if has_critical && has_flood {
            "Massive Deauth Flood Attack".to_string()
        } else if has_flood && has_evil_twin {
            "Deauth Flood + Possible Evil Twin".to_string()
        } else if has_evil_twin {
            "Possible Evil Twin Attack".to_string()
        } else if has_flood {
            "Deauth Flood Attack".to_string()
        } else {
            "Suspected Deauth Attack".to_string()
        }
    }

    fn analyze_security(result: &WifiDeauthResult) -> Vec<WifiDeauthFinding> {
        let mut findings = Vec::new();

        if result.attack_detected {
            findings.push(WifiDeauthFinding {
                severity: "high".to_string(),
                category: "Deauth Attack".to_string(),
                description: format!("WiFi Deauth attack detected: {}, {} Deauth frames total", result.attack_type, result.deauth_packets_detected),
                recommendation: "Enable 802.11w Management Frame Protection (MFP); change WiFi channel; check for unauthorized devices nearby".to_string(),
            });
        }

        let evil_twin_count = result.alerts.iter().filter(|a| a.alert_type == "Possible Evil Twin").count();
        if evil_twin_count > 0 {
            findings.push(WifiDeauthFinding {
                severity: "high".to_string(),
                category: "Evil Twin".to_string(),
                description: format!("{} possible Evil Twin AP(s) detected", evil_twin_count),
                recommendation: "Verify AP legitimacy by checking BSSID against known good APs; Evil Twin attacks intercept traffic by cloning SSID".to_string(),
            });
        }

        let anomalous_channels = result.channel_analysis.iter().filter(|c| c.is_anomalous).count();
        if anomalous_channels > 0 {
            findings.push(WifiDeauthFinding {
                severity: "medium".to_string(),
                category: "Channel Anomaly".to_string(),
                description: format!("{} channel(s) with anomalous Deauth traffic", anomalous_channels),
                recommendation: "Check if APs on affected channels are under attack".to_string(),
            });
        }

        let open_networks = result.access_points.iter().filter(|ap| ap.encryption == "OPN" || ap.encryption == "Open").count();
        if open_networks > 0 {
            findings.push(WifiDeauthFinding {
                severity: "medium".to_string(),
                category: "Open Network".to_string(),
                description: format!("Found {} open (unencrypted) WiFi networks", open_networks),
                recommendation: "Open networks are more vulnerable to Deauth attacks; use WPA3 encryption".to_string(),
            });
        }

        let wep_networks = result.access_points.iter().filter(|ap| ap.encryption.contains("WEP")).count();
        if wep_networks > 0 {
            findings.push(WifiDeauthFinding {
                severity: "high".to_string(),
                category: "Weak Encryption".to_string(),
                description: format!("Found {} WEP-encrypted WiFi networks (insecure)", wep_networks),
                recommendation: "WEP encryption is broken; upgrade to WPA2 or WPA3 immediately".to_string(),
            });
        }

        let wpa_networks = result.access_points.iter().filter(|ap| ap.encryption == "WPA").count();
        if wpa_networks > 0 {
            findings.push(WifiDeauthFinding {
                severity: "low".to_string(),
                category: "Outdated Encryption".to_string(),
                description: format!("Found {} WPA(1)-encrypted WiFi networks (outdated)", wpa_networks),
                recommendation: "WPA1 is outdated; upgrade to WPA2 or WPA3 for better security".to_string(),
            });
        }

        findings
    }

    fn build_summary(result: &WifiDeauthResult) -> String {
        let mut parts = Vec::new();

        parts.push(format!("Interface: {}", result.interface));
        parts.push(format!("Scan: {}s", result.scan_duration));
        parts.push(format!("APs: {}", result.access_points.len()));
        parts.push(format!("Packets: {}", result.total_packets_captured));
        parts.push(format!("Deauth: {}", result.deauth_packets_detected));

        if result.attack_detected {
            parts.push(format!("Attack: {}", result.attack_type));
            parts.push(format!("Alerts: {}", result.alerts.len()));
        } else {
            parts.push("No Deauth attack detected".to_string());
        }

        parts.join(" | ")
    }
}

fn regex_for_mac() -> regex::Regex {
    regex::Regex::new(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})").unwrap()
}
