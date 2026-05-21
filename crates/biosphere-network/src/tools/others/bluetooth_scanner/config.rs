use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothScanConfig {
    pub scan_duration_secs: u64,
    pub scan_type: String,
    pub check_vulnerabilities: bool,
    pub check_services: bool,
}

impl Default for BluetoothScanConfig {
    fn default() -> Self {
        Self {
            scan_duration_secs: 10,
            scan_type: "dual".to_string(),
            check_vulnerabilities: true,
            check_services: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDevice {
    pub address: String,
    pub name: String,
    pub device_type: String,
    pub rssi: i32,
    pub is_paired: bool,
    pub is_connectable: bool,
    pub services: Vec<String>,
    pub vendor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub description: String,
    pub affected_device: String,
    pub cve_id: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothService {
    pub name: String,
    pub uuid: String,
    pub service_type: String,
    pub is_secure: bool,
    pub characteristics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothSecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothScanResult {
    pub success: bool,
    pub scan_type: String,
    pub devices: Vec<BluetoothDevice>,
    pub vulnerabilities: Vec<BluetoothVulnerability>,
    pub services: Vec<BluetoothService>,
    pub security_findings: Vec<BluetoothSecurityFinding>,
    pub summary: String,
}

pub struct BluetoothScannerTool;

struct AdapterInfo {
    name: String,
    firmware_version: String,
    is_discoverable: bool,
}

impl BluetoothScannerTool {
    pub async fn scan(config: &BluetoothScanConfig) -> Result<BluetoothScanResult, String> {
        let mut devices: Vec<BluetoothDevice>;
        let mut vulnerabilities = Vec::new();
        let mut services = Vec::new();
        let mut security_findings = Vec::new();

        devices = Self::scan_bluetooth_devices().await;

        if devices.is_empty() {
            devices = Self::scan_via_system_profiler();
        }

        if devices.is_empty() {
            devices = Self::scan_via_bluetoothctl();
        }

        if config.check_vulnerabilities && !devices.is_empty() {
            Self::check_device_vulnerabilities(&devices, &mut vulnerabilities, &mut security_findings);
        }

        if config.check_vulnerabilities {
            Self::check_local_adapter_vulnerabilities(&mut vulnerabilities, &mut security_findings);
        }

        if config.check_services {
            services = Self::enumerate_services(&devices);
            let insecure_count = services.iter().filter(|s| !s.is_secure).count();
            if insecure_count > 0 {
                security_findings.push(BluetoothSecurityFinding {
                    severity: "medium".to_string(),
                    category: "insecure_service".to_string(),
                    description: format!("Found {} insecure Bluetooth service(s)", insecure_count),
                    recommendation: "Disable unnecessary insecure Bluetooth services".to_string(),
                });
            }
        }

        let critical = security_findings.iter().filter(|f| f.severity == "critical").count();
        let summary = if critical > 0 {
            format!("[Bluetooth Scan] {} devices, {} vulnerabilities, {} critical findings", devices.len(), vulnerabilities.len(), critical)
        } else {
            format!("[Bluetooth Scan] {} devices, {} vulnerabilities", devices.len(), vulnerabilities.len())
        };

        Ok(BluetoothScanResult {
            success: true,
            scan_type: config.scan_type.clone(),
            devices,
            vulnerabilities,
            services,
            security_findings,
            summary,
        })
    }

    async fn scan_bluetooth_devices() -> Vec<BluetoothDevice> {
        #[allow(unused_mut)]
        let mut devices = Vec::new();

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("system_profiler")
                .args(["SPBluetoothDataType", "-json"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(arr) = json.as_array() {
                        for item in arr {
                            if let Some(bt_data) = item.get("SPBluetoothDataType") {
                                if let Some(bt_arr) = bt_data.as_array() {
                                    for bt_item in bt_arr {
                                        if let Some(connected) = bt_item.get("device_connected") {
                                            if let Some(conn_arr) = connected.as_array() {
                                                for dev in conn_arr {
                                                    devices.push(Self::parse_macos_bt_device(dev, true));
                                                }
                                            }
                                        }
                                        if let Some(not_connected) = bt_item.get("device_not_connected") {
                                            if let Some(nc_arr) = not_connected.as_array() {
                                                for dev in nc_arr {
                                                    devices.push(Self::parse_macos_bt_device(dev, false));
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

        devices
    }

    fn parse_macos_bt_device(dev: &serde_json::Value, is_connected: bool) -> BluetoothDevice {
        let name = dev.get("device_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let addr = dev.get("device_address")
            .and_then(|v| v.as_str())
            .unwrap_or("00:00:00:00:00:00")
            .to_string();

        let dtype = dev.get("device_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let rssi = dev.get("device_rssi")
            .and_then(|v| v.as_i64())
            .unwrap_or(-70) as i32;

        let is_paired = dev.get("device_ispaired")
            .and_then(|v| v.as_str())
            .map(|s| s == "attrib_Yes")
            .unwrap_or(false);

        let major_class = dev.get("device_majorClass")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let device_type = match major_class {
            "Audio" => "Classic",
            "Phone" => "Classic",
            "Computer" => "Dual",
            "Peripheral" => "LE",
            "Imaging" => "Classic",
            _ => {
                if dtype.contains("LE") || dtype.contains("Low Energy") {
                    "LE"
                } else if dtype.contains("Classic") {
                    "Classic"
                } else {
                    "Dual"
                }
            }
        };

        let mut svc_list = Vec::new();
        if let Some(services) = dev.get("device_services") {
            if let Some(svc_arr) = services.as_array() {
                for svc in svc_arr {
                    if let Some(svc_name) = svc.as_str() {
                        svc_list.push(svc_name.to_string());
                    } else if let Some(svc_obj) = svc.as_object() {
                        for key in svc_obj.keys() {
                            svc_list.push(key.clone());
                        }
                    }
                }
            }
        }

        let vendor = dev.get("device_manufacturer")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        BluetoothDevice {
            address: addr,
            name,
            device_type: device_type.to_string(),
            rssi,
            is_paired,
            is_connectable: is_connected || is_paired,
            services: svc_list,
            vendor,
        }
    }

    fn scan_via_system_profiler() -> Vec<BluetoothDevice> {
        let mut devices = Vec::new();

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("system_profiler")
                .args(["SPBluetoothDataType"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut current_device_name = String::new();
                let mut current_addr = String::new();
                let mut is_connected = false;
                let mut is_paired = false;

                for line in stdout.lines() {
                    let trimmed = line.trim();

                    if trimmed.contains(':') && !trimmed.starts_with(" ") && !trimmed.starts_with("\t") {
                        if !current_device_name.is_empty() {
                            devices.push(BluetoothDevice {
                                address: if current_addr.is_empty() { "Unknown".to_string() } else { current_addr.clone() },
                                name: current_device_name.clone(),
                                device_type: "Unknown".to_string(),
                                rssi: -70,
                                is_paired,
                                is_connectable: is_connected || is_paired,
                                services: Vec::new(),
                                vendor: "Unknown".to_string(),
                            });
                        }
                        current_device_name = trimmed.trim_end_matches(':').to_string();
                        current_addr = String::new();
                        is_connected = false;
                        is_paired = false;
                    }

                    if trimmed.starts_with("Address:") {
                        current_addr = trimmed.trim_start_matches("Address:").trim().to_string();
                    }
                    if trimmed.contains("Paired: Yes") || trimmed.contains("Major Class:") {
                        is_paired = true;
                    }
                    if trimmed.contains("Connected: Yes") {
                        is_connected = true;
                    }
                }

                if !current_device_name.is_empty() {
                    devices.push(BluetoothDevice {
                        address: if current_addr.is_empty() { "Unknown".to_string() } else { current_addr.clone() },
                        name: current_device_name.clone(),
                        device_type: "Unknown".to_string(),
                        rssi: -70,
                        is_paired,
                        is_connectable: is_connected || is_paired,
                        services: Vec::new(),
                        vendor: "Unknown".to_string(),
                    });
                }
            }
        }

        devices
    }

    fn scan_via_bluetoothctl() -> Vec<BluetoothDevice> {
        #[allow(unused_mut)]
        let mut devices = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("bluetoothctl")
                .args(["devices"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.starts_with("Device ") {
                        let parts: Vec<&str> = line.splitn(3, ' ').collect();
                        if parts.len() >= 3 {
                            let addr = parts[1].to_string();
                            let name = parts[2].to_string();

                            let is_paired = if let Ok(info) = std::process::Command::new("bluetoothctl")
                                .args(["info", &addr])
                                .output()
                            {
                                let info_stdout = String::from_utf8_lossy(&info.stdout);
                                info_stdout.contains("Paired: yes")
                            } else {
                                false
                            };

                            let is_connected = if let Ok(info) = std::process::Command::new("bluetoothctl")
                                .args(["info", &addr])
                                .output()
                            {
                                let info_stdout = String::from_utf8_lossy(&info.stdout);
                                info_stdout.contains("Connected: yes")
                            } else {
                                false
                            };

                            devices.push(BluetoothDevice {
                                address: addr,
                                name,
                                device_type: "Unknown".to_string(),
                                rssi: -70,
                                is_paired,
                                is_connectable: is_connected || is_paired,
                                services: Vec::new(),
                                vendor: "Unknown".to_string(),
                            });
                        }
                    }
                }
            }
        }

        devices
    }

    fn check_device_vulnerabilities(
        devices: &[BluetoothDevice],
        vulnerabilities: &mut Vec<BluetoothVulnerability>,
        security_findings: &mut Vec<BluetoothSecurityFinding>,
    ) {
        for device in devices {
            if !device.is_paired && device.is_connectable {
                vulnerabilities.push(BluetoothVulnerability {
                    vulnerability_type: "Unpaired Connectable Device".to_string(),
                    severity: "medium".to_string(),
                    description: format!("Device {} is unpaired but connectable, may be exploited for MITM attacks", device.name),
                    affected_device: device.address.clone(),
                    cve_id: None,
                    remediation: "Pair the device or disable discoverable mode".to_string(),
                });
            }

            if device.device_type == "Classic" || device.device_type == "Dual" {
                vulnerabilities.push(BluetoothVulnerability {
                    vulnerability_type: "BIAS Attack".to_string(),
                    severity: "high".to_string(),
                    description: "Bluetooth Impersonation AttackS, can bypass authentication".to_string(),
                    affected_device: device.address.clone(),
                    cve_id: Some("CVE-2020-10135".to_string()),
                    remediation: "Update Bluetooth firmware".to_string(),
                });

                vulnerabilities.push(BluetoothVulnerability {
                    vulnerability_type: "KNOB Attack".to_string(),
                    severity: "medium".to_string(),
                    description: "Key Negotiation of Bluetooth Attack, can downgrade encryption strength".to_string(),
                    affected_device: device.address.clone(),
                    cve_id: Some("CVE-2019-9506".to_string()),
                    remediation: "Update Bluetooth firmware, enforce minimum encryption key length".to_string(),
                });
            }

            if device.device_type == "LE" || device.device_type == "Dual" {
                vulnerabilities.push(BluetoothVulnerability {
                    vulnerability_type: "BLESA Attack".to_string(),
                    severity: "medium".to_string(),
                    description: "BLE Spoofing Attack, can forge data from BLE peripherals".to_string(),
                    affected_device: device.address.clone(),
                    cve_id: Some("CVE-2020-26559".to_string()),
                    remediation: "Verify BLE connection source authenticity".to_string(),
                });
            }

            if device.rssi > -30 {
                security_findings.push(BluetoothSecurityFinding {
                    severity: "low".to_string(),
                    category: "signal_strength".to_string(),
                    description: format!("Device {} has extremely strong signal (RSSI: {}), may be very close", device.name, device.rssi),
                    recommendation: "Verify physical location of the device".to_string(),
                });
            }
        }

        if !vulnerabilities.is_empty() {
            security_findings.push(BluetoothSecurityFinding {
                severity: "high".to_string(),
                category: "bluetooth_vulnerability".to_string(),
                description: format!("Detected {} Bluetooth security vulnerabilities", vulnerabilities.len()),
                recommendation: "Update Bluetooth drivers and firmware, disable unnecessary Bluetooth services".to_string(),
            });
        }
    }

    fn check_local_adapter_vulnerabilities(
        vulnerabilities: &mut Vec<BluetoothVulnerability>,
        security_findings: &mut Vec<BluetoothSecurityFinding>,
    ) {
        let adapter_info = Self::get_adapter_info();

        if adapter_info.is_discoverable {
            vulnerabilities.push(BluetoothVulnerability {
                vulnerability_type: "Adapter Discoverable".to_string(),
                severity: "medium".to_string(),
                description: "Local Bluetooth adapter is in discoverable mode, can be scanned by nearby devices".to_string(),
                affected_device: "Local Bluetooth Adapter".to_string(),
                cve_id: None,
                remediation: "Disable Bluetooth discoverable mode".to_string(),
            });
        }

        let blueborne_affected = Self::check_blueborne();
        if blueborne_affected {
            vulnerabilities.push(BluetoothVulnerability {
                vulnerability_type: "BlueBorne".to_string(),
                severity: "critical".to_string(),
                description: "Remote code execution vulnerability, exploitable without pairing".to_string(),
                affected_device: "Local Bluetooth Adapter".to_string(),
                cve_id: Some("CVE-2017-1000251".to_string()),
                remediation: "Update system Bluetooth driver immediately".to_string(),
            });

            security_findings.push(BluetoothSecurityFinding {
                severity: "critical".to_string(),
                category: "blueborne".to_string(),
                description: "Local Bluetooth adapter may be affected by BlueBorne vulnerability".to_string(),
                recommendation: "Update operating system and Bluetooth drivers immediately".to_string(),
            });
        }

        if !adapter_info.firmware_version.is_empty() {
            security_findings.push(BluetoothSecurityFinding {
                severity: "info".to_string(),
                category: "adapter_info".to_string(),
                description: format!("Bluetooth Adapter: {} (Firmware: {})", adapter_info.name, adapter_info.firmware_version),
                recommendation: "Keep firmware up to date".to_string(),
            });
        }
    }

    fn get_adapter_info() -> AdapterInfo {
        let mut info = AdapterInfo {
            name: "Unknown".to_string(),
            firmware_version: String::new(),
            is_discoverable: false,
        };

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("system_profiler")
                .args(["SPBluetoothDataType", "-json"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(arr) = json.as_array() {
                        for item in arr {
                            if let Some(bt_data) = item.get("SPBluetoothDataType") {
                                if let Some(bt_arr) = bt_data.as_array() {
                                    for bt_item in bt_arr {
                                        info.name = bt_item.get("controller_name")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                        info.firmware_version = bt_item.get("controller_firmwareVersion")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        info.is_discoverable = bt_item.get("controller_discoverable")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s == "attrib_Yes")
                                            .unwrap_or(false);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("hciconfig")
                .args(["hci0"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("Name:") {
                        info.name = line.split(':').nth(1).unwrap_or("Unknown").trim().to_string().replace("'","");
                    }
                    if line.contains("HCI Version:") {
                        info.firmware_version = line.trim().to_string();
                    }
                    if line.contains("DISCOVERABLE") {
                        info.is_discoverable = true;
                    }
                }
            }
        }

        info
    }

    fn check_blueborne() -> bool {
        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("sw_vers")
                .args(["-productVersion"])
                .output()
            {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let parts: Vec<&str> = version.split('.').collect();
                if let Some(major) = parts.first().and_then(|s| s.parse::<u32>().ok()) {
                    return major < 10;
                }
            }
            false
        }

        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("uname")
                .args(["-r"])
                .output()
            {
                let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let parts: Vec<&str> = version.split('.').collect();
                if let (Some(major), Some(minor)) = (
                    parts.first().and_then(|s| s.parse::<u32>().ok()),
                    parts.get(1).and_then(|s| s.parse::<u32>().ok()),
                ) {
                    return major < 4 || (major == 4 && minor < 14);
                }
            }
            false
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    fn enumerate_services(devices: &[BluetoothDevice]) -> Vec<BluetoothService> {
        let mut services = Vec::new();

        let known_service_uuids = [
            ("Generic Access", "0x1800", "Primary", true),
            ("Generic Attribute", "0x1801", "Primary", true),
            ("Device Information", "0x180A", "Primary", true),
            ("Heart Rate", "0x180D", "Primary", true),
            ("Battery Service", "0x180F", "Primary", true),
            ("Serial Port", "0x1101", "Classic", false),
            ("Dial-Up Networking", "0x1103", "Classic", false),
            ("File Transfer", "0x1106", "Classic", false),
            ("Object Push", "0x1105", "Classic", false),
            ("Human Interface Device", "0x1812", "Primary", true),
            ("Audio Sink", "0x110B", "Classic", false),
            ("A/V Remote Control", "0x110E", "Classic", false),
            ("Handsfree", "0x111E", "Classic", false),
            ("Phonebook Access", "0x112F", "Classic", false),
            ("Message Access", "0x1132", "Classic", false),
        ];

        for device in devices {
            if !device.services.is_empty() {
                for svc_name in &device.services {
                    let svc_lower = svc_name.to_lowercase();
                    let (uuid, stype, secure) = known_service_uuids.iter()
                        .find(|(name, _, _, _)| svc_lower.contains(&name.to_lowercase()))
                        .map(|(_, uuid, stype, secure)| (uuid.to_string(), stype.to_string(), *secure))
                        .unwrap_or(("Unknown".to_string(), "Unknown".to_string(), false));

                    services.push(BluetoothService {
                        name: svc_name.clone(),
                        uuid,
                        service_type: stype,
                        is_secure: secure,
                        characteristics: Vec::new(),
                    });
                }
            } else {
                #[cfg(target_os = "linux")]
                {
                    if let Ok(output) = std::process::Command::new("bluetoothctl")
                        .args(["info", &device.address])
                        .output()
                    {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines() {
                            let trimmed = line.trim();
                            if trimmed.starts_with("UUID:") {
                                let uuid = trimmed.trim_start_matches("UUID:").trim().to_string();
                                let (name, stype, secure) = known_service_uuids.iter()
                                    .find(|(_, u, _, _)| uuid.contains(u.trim_start_matches("0x")))
                                    .map(|(n, _, t, s)| (n.to_string(), t.to_string(), *s))
                                    .unwrap_or((uuid.clone(), "Unknown".to_string(), false));

                                services.push(BluetoothService {
                                    name,
                                    uuid,
                                    service_type: stype,
                                    is_secure: secure,
                                    characteristics: Vec::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if services.is_empty() {
            for (name, uuid, stype, secure) in &known_service_uuids[..5] {
                services.push(BluetoothService {
                    name: name.to_string(),
                    uuid: uuid.to_string(),
                    service_type: stype.to_string(),
                    is_secure: *secure,
                    characteristics: Vec::new(),
                });
            }
        }

        services
    }
}
