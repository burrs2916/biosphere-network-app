use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityConfig {
    pub app_path: String,
    pub platform: String,
    pub check_permissions: bool,
    pub check_api_security: bool,
    pub check_data_storage: bool,
    pub check_cryptography: bool,
    pub check_network: bool,
    pub check_code_quality: bool,
    pub check_tampering: bool,
    pub check_debugging: bool,
    pub check_privacy: bool,
    pub timeout: u64,
    pub use_frida: bool,
    pub use_objection: bool,
    pub dynamic_analysis: bool,
    pub frida_scripts: Vec<String>,
    pub device_id: Option<String>,
}

impl Default for MobileSecurityConfig {
    fn default() -> Self {
        Self {
            app_path: String::new(),
            platform: "android".to_string(),
            check_permissions: true,
            check_api_security: true,
            check_data_storage: true,
            check_cryptography: true,
            check_network: true,
            check_code_quality: true,
            check_tampering: true,
            check_debugging: true,
            check_privacy: true,
            timeout: 60,
            use_frida: false,
            use_objection: false,
            dynamic_analysis: false,
            frida_scripts: Vec::new(),
            device_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionInfo {
    pub name: String,
    pub risk_level: String,
    pub description: String,
    pub is_dangerous: bool,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityIssue {
    pub endpoint: String,
    pub method: String,
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStorageIssue {
    pub location: String,
    pub data_type: String,
    pub is_encrypted: bool,
    pub risk_level: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIssue {
    pub algorithm: String,
    pub usage: String,
    pub key_size: Option<u32>,
    pub issue: String,
    pub severity: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIssue {
    pub url: String,
    pub protocol: String,
    pub issue_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeQualityIssue {
    pub category: String,
    pub description: String,
    pub severity: String,
    pub file: String,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperingProtection {
    pub root_detection: bool,
    pub jailbreak_detection: bool,
    pub integrity_check: bool,
    pub anti_debug: bool,
    pub anti_tamper: bool,
    pub emulator_detection: bool,
    pub repackaging_detection: bool,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIssue {
    pub data_collected: String,
    pub purpose: String,
    pub is_necessary: bool,
    pub risk_level: String,
    pub regulation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FridaHookResult {
    pub method_name: String,
    pub class_name: String,
    pub return_value: Option<String>,
    pub arguments: Vec<String>,
    pub is_crypto_operation: bool,
    pub is_auth_bypass: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectionFinding {
    pub category: String,
    pub finding: String,
    pub severity: String,
    pub detail: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAnalysisResult {
    pub runtime_hooks: Vec<FridaHookResult>,
    pub ssl_pinning_bypass: bool,
    pub root_bypass: bool,
    pub keychain_dump: Vec<String>,
    pub objection_findings: Vec<ObjectionFinding>,
    pub method_trace: Vec<MethodTraceEntry>,
    pub memory_dumps: Vec<MemoryDumpInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodTraceEntry {
    pub method: String,
    pub class: String,
    pub duration_ms: u64,
    pub call_count: u32,
    pub thread_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpInfo {
    pub address: String,
    pub size: u64,
    pub content_preview: String,
    pub contains_sensitive_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityResult {
    pub success: bool,
    pub app_path: String,
    pub platform: String,
    pub app_name: String,
    pub package_name: String,
    pub version: String,
    pub min_sdk: String,
    pub target_sdk: String,
    pub permissions: Vec<PermissionInfo>,
    pub api_issues: Vec<ApiSecurityIssue>,
    pub storage_issues: Vec<DataStorageIssue>,
    pub crypto_issues: Vec<CryptoIssue>,
    pub network_issues: Vec<NetworkIssue>,
    pub code_issues: Vec<CodeQualityIssue>,
    pub tampering_protection: TamperingProtection,
    pub privacy_issues: Vec<PrivacyIssue>,
    pub dynamic_analysis: Option<DynamicAnalysisResult>,
    pub security_score: f64,
    pub total_issues: usize,
    pub critical_issues: usize,
    pub summary: String,
}

pub struct MobileSecurityTool;

impl MobileSecurityTool {
    pub async fn analyze(config: &MobileSecurityConfig) -> std::result::Result<MobileSecurityResult, String> {
        if config.app_path.is_empty() {
            return Err("App path is required".to_string());
        }

        let app_path = config.app_path.trim().to_string();
        if !Path::new(&app_path).exists() {
            return Err(format!("App file not found: {}", app_path));
        }

        let platform = Self::detect_platform(&app_path, &config.platform);

        let (app_name, package_name, version, min_sdk, target_sdk) = Self::extract_app_info(&app_path, &platform);

        let permissions = if config.check_permissions {
            Self::check_permissions(&app_path, &platform)
        } else {
            vec![]
        };

        let api_issues = if config.check_api_security {
            Self::check_api_security(&app_path, &platform)
        } else {
            vec![]
        };

        let storage_issues = if config.check_data_storage {
            Self::check_data_storage(&app_path, &platform)
        } else {
            vec![]
        };

        let crypto_issues = if config.check_cryptography {
            Self::check_cryptography(&app_path, &platform)
        } else {
            vec![]
        };

        let network_issues = if config.check_network {
            Self::check_network(&app_path, &platform)
        } else {
            vec![]
        };

        let code_issues = if config.check_code_quality {
            Self::check_code_quality(&app_path, &platform)
        } else {
            vec![]
        };

        let tampering_protection = if config.check_tampering || config.check_debugging {
            Self::check_tampering(&app_path, &platform)
        } else {
            TamperingProtection { root_detection: false, jailbreak_detection: false, integrity_check: false, anti_debug: false, anti_tamper: false, emulator_detection: false, repackaging_detection: false, score: 0.0 }
        };

        let privacy_issues = if config.check_privacy {
            Self::check_privacy(&app_path, &platform, &permissions)
        } else {
            vec![]
        };

        let total_issues = permissions.iter().filter(|p| p.is_dangerous).count()
            + api_issues.len() + storage_issues.len() + crypto_issues.len()
            + network_issues.len() + code_issues.len() + privacy_issues.len();

        let critical_issues = api_issues.iter().filter(|i| i.severity == "critical").count()
            + storage_issues.iter().filter(|i| i.risk_level == "critical").count()
            + crypto_issues.iter().filter(|i| i.severity == "critical").count();

        let security_score = Self::calculate_score(total_issues, critical_issues, &tampering_protection);

        let summary = format!(
            "Mobile security analysis complete: app={}, platform={}, score={:.0}%, total_issues={}, critical={}",
            app_path, platform, security_score * 100.0, total_issues, critical_issues
        );

        Ok(MobileSecurityResult {
            success: true,
            app_path,
            platform,
            app_name,
            package_name,
            version,
            min_sdk,
            target_sdk,
            permissions,
            api_issues,
            storage_issues,
            crypto_issues,
            network_issues,
            code_issues,
            tampering_protection,
            privacy_issues,
            dynamic_analysis: None,
            security_score,
            total_issues,
            critical_issues,
            summary,
        })
    }

    fn run_command(cmd: &str, args: &[&str]) -> std::result::Result<String, String> {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .map_err(|e| e.to_string())
    }

    fn detect_platform(path: &str, config_platform: &str) -> String {
        let lower = path.to_lowercase();
        if lower.ends_with(".apk") {
            "android".to_string()
        } else if lower.ends_with(".ipa") || lower.ends_with(".app") || lower.ends_with(".appx") {
            "ios".to_string()
        } else {
            config_platform.to_lowercase()
        }
    }

    fn extract_app_info(path: &str, platform: &str) -> (String, String, String, String, String) {
        let mut app_name = String::new();
        let mut package_name = String::new();
        let mut version = String::new();
        let mut min_sdk = String::new();
        let mut target_sdk = String::new();

        match platform {
            "android" => {
                if let Ok(output) = Self::run_command("aapt", &["dump", "badging", path]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.starts_with("package:") {
                            for part in line.split_whitespace() {
                                if part.starts_with("name=") {
                                    package_name = part.trim_start_matches("name='").trim_end_matches("'").to_string();
                                } else if part.starts_with("versionName=") {
                                    version = part.trim_start_matches("versionName='").trim_end_matches("'").to_string();
                                }
                            }
                        }
                        if line.starts_with("application:") {
                            for part in line.split_whitespace() {
                                if part.starts_with("label=") {
                                    app_name = part.trim_start_matches("label='").trim_end_matches("'").to_string();
                                }
                            }
                        }
                        if line.contains("sdkVersion:") {
                            min_sdk = line.split(':').next_back().unwrap_or("").trim().to_string();
                        }
                        if line.contains("targetSdkVersion:") {
                            target_sdk = line.split(':').next_back().unwrap_or("").trim().to_string();
                        }
                    }
                }

                if package_name.is_empty() {
                    if let Ok(output) = Self::run_command("aapt2", &["dump", "badging", path]) {
                        for line in output.lines() {
                            let line = line.trim();
                            if line.starts_with("package:") {
                                for part in line.split_whitespace() {
                                    if part.starts_with("name=") {
                                        package_name = part.trim_start_matches("name='").trim_end_matches("'").to_string();
                                    } else if part.starts_with("versionName=") {
                                        version = part.trim_start_matches("versionName='").trim_end_matches("'").to_string();
                                    }
                                }
                            }
                        }
                    }
                }

                if package_name.is_empty() {
                    if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_apk_tmp"]) {
                        let manifest_path = "/tmp/biosphere_apk_tmp/AndroidManifest.xml";
                        if Path::new(manifest_path).exists() {
                            if let Ok(content) = std::fs::read_to_string(manifest_path) {
                                for line in content.lines() {
                                    let line = line.trim();
                                    if line.contains("package=") {
                                        package_name = Self::extract_attr(line, "package");
                                    }
                                    if line.contains("android:versionName=") {
                                        version = Self::extract_attr(line, "android:versionName");
                                    }
                                    if line.contains("android:minSdkVersion=") {
                                        min_sdk = Self::extract_attr(line, "android:minSdkVersion");
                                    }
                                    if line.contains("android:targetSdkVersion=") {
                                        target_sdk = Self::extract_attr(line, "android:targetSdkVersion");
                                    }
                                }
                            }
                        }
                        let _ = std::fs::remove_dir_all("/tmp/biosphere_apk_tmp");
                    }
                }

                if app_name.is_empty() {
                    app_name = package_name.clone();
                }
            }
            "ios" => {
                if let Ok(output) = Self::run_command("unzip", &["-l", path]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.contains("Info.plist") {
                            let plist_path = line.split_whitespace().last().unwrap_or("");
                            if !plist_path.is_empty() {
                                if let Ok(plist_output) = Self::run_command("unzip", &["-p", path, plist_path]) {
                                    if let Ok(info) = Self::parse_plist(&plist_output) {
                                        app_name = info.get("CFBundleDisplayName")
                                            .or_else(|| info.get("CFBundleName"))
                                            .cloned()
                                            .unwrap_or_default();
                                        package_name = info.get("CFBundleIdentifier")
                                            .cloned()
                                            .unwrap_or_default();
                                        version = info.get("CFBundleShortVersionString")
                                            .cloned()
                                            .unwrap_or_default();
                                        min_sdk = info.get("MinimumOSVersion")
                                            .cloned()
                                            .unwrap_or_default();
                                    }
                                }
                            }
                            break;
                        }
                    }
                }

                if app_name.is_empty() {
                    let file_name = Path::new(path).file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown");
                    app_name = file_name.to_string();
                }
            }
            _ => {}
        }

        (app_name, package_name, version, min_sdk, target_sdk)
    }

    fn extract_attr(line: &str, attr: &str) -> String {
        let pattern = format!("{}=\"", attr);
        if let Some(start) = line.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end) = line[value_start..].find('"') {
                return line[value_start..value_start + end].to_string();
            }
        }
        String::new()
    }

    fn parse_plist(content: &str) -> std::result::Result<std::collections::HashMap<String, String>, String> {
        let mut map = std::collections::HashMap::new();
        let mut current_key = String::new();
        let mut is_key = false;
        let mut is_value = false;

        for line in content.lines() {
            let line = line.trim();
            if line == "<key>" || line.starts_with("<key>") {
                is_key = true;
                is_value = false;
                current_key = line.replace("<key>", "").replace("</key>", "").trim().to_string();
            } else if line == "<string>" || line.starts_with("<string>") {
                is_value = true;
                is_key = false;
                let value = line.replace("<string>", "").replace("</string>", "").trim().to_string();
                if !current_key.is_empty() && !value.is_empty() {
                    map.insert(current_key.clone(), value);
                }
                current_key.clear();
            } else if is_key && line.contains("</key>") {
                current_key = line.replace("</key>", "").trim().to_string();
            } else if is_value && line.contains("</string>") {
                let value = line.replace("</string>", "").trim().to_string();
                if !current_key.is_empty() && !value.is_empty() {
                    map.insert(current_key.clone(), value);
                }
                current_key.clear();
                is_value = false;
            }
        }

        Ok(map)
    }

    fn check_permissions(path: &str, platform: &str) -> Vec<PermissionInfo> {
        let mut permissions = Vec::new();

        match platform {
            "android" => {
                let dangerous_perms: std::collections::HashMap<&str, (&str, &str)> = [
                    ("READ_CONTACTS", ("Contacts", "high")),
                    ("WRITE_CONTACTS", ("Contacts", "high")),
                    ("READ_CALENDAR", ("Calendar", "high")),
                    ("WRITE_CALENDAR", ("Calendar", "high")),
                    ("CAMERA", ("Camera", "high")),
                    ("READ_PHONE_STATE", ("Device Info", "high")),
                    ("CALL_PHONE", ("Phone", "critical")),
                    ("READ_CALL_LOG", ("Call Log", "critical")),
                    ("WRITE_CALL_LOG", ("Call Log", "critical")),
                    ("ACCESS_FINE_LOCATION", ("Location", "high")),
                    ("ACCESS_COARSE_LOCATION", ("Location", "medium")),
                    ("RECORD_AUDIO", ("Microphone", "high")),
                    ("READ_EXTERNAL_STORAGE", ("Storage", "medium")),
                    ("WRITE_EXTERNAL_STORAGE", ("Storage", "medium")),
                    ("READ_SMS", ("SMS", "critical")),
                    ("SEND_SMS", ("SMS", "critical")),
                    ("RECEIVE_SMS", ("SMS", "critical")),
                    ("BODY_SENSORS", ("Sensors", "high")),
                    ("READ_PHONE_NUMBERS", ("Device Info", "high")),
                    ("ANSWER_PHONE_CALLS", ("Phone", "high")),
                    ("PROCESS_OUTGOING_CALLS", ("Phone", "high")),
                    ("ACCESS_BACKGROUND_LOCATION", ("Location", "critical")),
                ].iter().cloned().collect();

                if let Ok(output) = Self::run_command("aapt", &["dump", "permissions", path]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.starts_with("uses-permission:") {
                            let perm = line.replace("uses-permission:", "").trim().to_string();
                            let perm_name = perm.split('.').next_back().unwrap_or("").to_string();

                            let (category, risk, is_dangerous, description) = if let Some((cat, risk)) = dangerous_perms.get(perm_name.as_str()) {
                                (cat.to_string(), risk.to_string(), true, format!("Dangerous permission: {}", perm_name))
                            } else if perm_name == "INTERNET" {
                                ("Network".to_string(), "low".to_string(), false, "Full network access".to_string())
                            } else if perm_name == "ACCESS_NETWORK_STATE" || perm_name == "ACCESS_WIFI_STATE" {
                                ("Network".to_string(), "low".to_string(), false, "View network state".to_string())
                            } else if perm_name == "VIBRATE" || perm_name == "WAKE_LOCK" {
                                ("Device".to_string(), "low".to_string(), false, format!("Normal permission: {}", perm_name))
                            } else {
                                ("Other".to_string(), "info".to_string(), false, format!("Permission: {}", perm_name))
                            };

                            permissions.push(PermissionInfo {
                                name: perm,
                                risk_level: risk,
                                description,
                                is_dangerous,
                                category,
                            });
                        }
                    }
                }

                if permissions.is_empty() {
                    if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_perm_tmp"]) {
                        let manifest_path = "/tmp/biosphere_perm_tmp/AndroidManifest.xml";
                        if Path::new(manifest_path).exists() {
                            if let Ok(content) = std::fs::read_to_string(manifest_path) {
                                for line in content.lines() {
                                    if line.contains("uses-permission") && line.contains("android:name=") {
                                        let perm = Self::extract_attr(line, "android:name");
                                        if !perm.is_empty() {
                                            let perm_name = perm.split('.').next_back().unwrap_or("").to_string();
                                            let (category, risk, is_dangerous, description) = if let Some((cat, risk)) = dangerous_perms.get(perm_name.as_str()) {
                                                (cat.to_string(), risk.to_string(), true, format!("Dangerous permission: {}", perm_name))
                                            } else {
                                                ("Other".to_string(), "info".to_string(), false, format!("Permission: {}", perm_name))
                                            };

                                            permissions.push(PermissionInfo {
                                                name: perm,
                                                risk_level: risk,
                                                description,
                                                is_dangerous,
                                                category,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        let _ = std::fs::remove_dir_all("/tmp/biosphere_perm_tmp");
                    }
                }
            }
            "ios" => {
                if let Ok(output) = Self::run_command("unzip", &["-p", path, "Info.plist"]) {
                    if let Ok(info) = Self::parse_plist(&output) {
                        if let Some(_ents) = info.get("NSAppTransportSecurity") {
                            permissions.push(PermissionInfo {
                                name: "NSAppTransportSecurity".to_string(),
                                risk_level: "medium".to_string(),
                                description: "App Transport Security configuration".to_string(),
                                is_dangerous: false,
                                category: "Network Security".to_string(),
                            });
                        }
                    }
                }

                let ios_permissions = [
                    ("NSLocationWhenInUseUsageDescription", "Location (When In Use)", "high"),
                    ("NSLocationAlwaysAndWhenInUseUsageDescription", "Location (Always)", "critical"),
                    ("NSCameraUsageDescription", "Camera", "high"),
                    ("NSMicrophoneUsageDescription", "Microphone", "high"),
                    ("NSContactsUsageDescription", "Contacts", "high"),
                    ("NSPhotoLibraryUsageDescription", "Photo Library", "high"),
                    ("NSCalendarsUsageDescription", "Calendar", "medium"),
                    ("NSMotionUsageDescription", "Motion", "medium"),
                    ("NSHealthShareUsageDescription", "Health Data", "critical"),
                    ("NSHealthUpdateUsageDescription", "Health Data Write", "critical"),
                    ("NSBluetoothAlwaysUsageDescription", "Bluetooth", "medium"),
                    ("NSSpeechRecognitionUsageDescription", "Speech Recognition", "high"),
                    ("NSAppleMusicUsageDescription", "Apple Music", "low"),
                    ("NSFaceIDUsageDescription", "Face ID", "medium"),
                ];

                if let Ok(output) = Self::run_command("unzip", &["-p", path, "Info.plist"]) {
                    for (perm, desc, risk) in ios_permissions {
                        if output.contains(perm) {
                            permissions.push(PermissionInfo {
                                name: perm.to_string(),
                                risk_level: risk.to_string(),
                                description: desc.to_string(),
                                is_dangerous: risk != "low",
                                category: desc.to_string(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        permissions
    }

    fn check_api_security(path: &str, platform: &str) -> Vec<ApiSecurityIssue> {
        let mut issues = Vec::new();

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let mut http_urls = Vec::new();
            let mut api_endpoints = Vec::new();
            let mut has_api_key = false;
            let mut has_hardcoded_token = false;

            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("http://") && !line.contains("schemas.android.com") && !line.contains("www.w3.org") {
                    http_urls.push(line.to_string());
                }
                if line.contains("/api/") || line.contains("/v1/") || line.contains("/v2/") || line.contains("/rest/") {
                    api_endpoints.push(line.to_string());
                }
                if (line.contains("api_key") || line.contains("apikey") || line.contains("API_KEY"))
                    && line.contains("=") && line.len() > 20 {
                        has_api_key = true;
                    }
                if line.contains("Bearer ") && line.len() > 30 {
                    has_hardcoded_token = true;
                }
            }

            if !http_urls.is_empty() {
                let sample: Vec<&str> = http_urls.iter().take(3).map(|s| s.as_str()).collect();
                issues.push(ApiSecurityIssue {
                    endpoint: sample.join(", "),
                    method: "Various".to_string(),
                    issue_type: "Plaintext HTTP Communication".to_string(),
                    severity: "high".to_string(),
                    description: format!("Found {} HTTP plaintext URLs, data transmission insecure", http_urls.len()),
                    recommendation: "All API communication should use HTTPS".to_string(),
                });
            }

            if has_api_key {
                issues.push(ApiSecurityIssue {
                    endpoint: "App Code".to_string(),
                    method: "N/A".to_string(),
                    issue_type: "Hardcoded API Key".to_string(),
                    severity: "critical".to_string(),
                    description: "Hardcoded API key found in application code".to_string(),
                    recommendation: "Store API keys securely, use environment variables or key management services".to_string(),
                });
            }

            if has_hardcoded_token {
                issues.push(ApiSecurityIssue {
                    endpoint: "App Code".to_string(),
                    method: "N/A".to_string(),
                    issue_type: "Hardcoded Auth Token".to_string(),
                    severity: "critical".to_string(),
                    description: "Hardcoded authentication token found in application code".to_string(),
                    recommendation: "Use secure token storage mechanisms like iOS Keychain or Android Keystore".to_string(),
                });
            }
        }

        if platform == "android" {
            if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_api_tmp"]) {
                let smali_dir = "/tmp/biosphere_api_tmp/smali";
                if Path::new(smali_dir).exists() {
                    if let Ok(find_output) = Self::run_command("grep", &["-rl", "addJavascriptInterface", smali_dir]) {
                        if !find_output.trim().is_empty() {
                            issues.push(ApiSecurityIssue {
                                endpoint: "WebView".to_string(),
                                method: "JavaScript Interface".to_string(),
                                issue_type: "JavaScript Interface Exposed".to_string(),
                                severity: "high".to_string(),
                                description: "addJavascriptInterface call found, RCE risk when API version < 17".to_string(),
                                recommendation: "Ensure API version >= 17, limit exposed JavaScript interface methods".to_string(),
                            });
                        }
                    }

                    if let Ok(find_output) = Self::run_command("grep", &["-rl", "setAllowFileAccess", smali_dir]) {
                        if !find_output.trim().is_empty() {
                            issues.push(ApiSecurityIssue {
                                endpoint: "WebView".to_string(),
                                method: "File Access".to_string(),
                                issue_type: "WebView File Access".to_string(),
                                severity: "medium".to_string(),
                                description: "WebView allows file access, may leak local files".to_string(),
                                recommendation: "Disable WebView file access permission".to_string(),
                            });
                        }
                    }
                }
                let _ = std::fs::remove_dir_all("/tmp/biosphere_api_tmp");
            }
        }

        issues
    }

    fn check_data_storage(path: &str, platform: &str) -> Vec<DataStorageIssue> {
        let mut issues = Vec::new();

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let mut has_sp_creds = false;
            let mut has_sqlite_unencrypted = false;
            let mut has_log_sensitive = false;
            let mut has_plaintext_password = false;

            let sensitive_patterns = [
                ("password", "Password"),
                ("passwd", "Password"),
                ("secret", "Secret"),
                ("token", "Token"),
                ("credential", "Credential"),
                ("private_key", "Private Key"),
                ("api_key", "API Key"),
                ("access_token", "Access Token"),
                ("refresh_token", "Refresh Token"),
                ("auth_token", "Auth Token"),
                ("session_id", "Session ID"),
                ("credit_card", "Credit Card"),
                ("ssn", "SSN"),
            ];

            let mut found_sensitive = Vec::new();
            for line in output.lines() {
                let lower = line.to_lowercase();
                for (pattern, _desc) in &sensitive_patterns {
                    if lower.contains(pattern) && !found_sensitive.contains(&pattern.to_string()) {
                        found_sensitive.push(pattern.to_string());

                        if pattern.starts_with("password") || pattern.starts_with("passwd") {
                            has_plaintext_password = true;
                        }
                    }
                }

                if lower.contains("sharedpreferences") && (lower.contains("password") || lower.contains("token")) {
                    has_sp_creds = true;
                }
                if lower.contains("sqlite") && !lower.contains("sqlcipher") && !lower.contains("encrypted") {
                    has_sqlite_unencrypted = true;
                }
                if lower.contains("log.") && (lower.contains("password") || lower.contains("token") || lower.contains("key")) {
                    has_log_sensitive = true;
                }
            }

            if has_sp_creds {
                issues.push(DataStorageIssue {
                    location: "SharedPreferences".to_string(),
                    data_type: "Sensitive Credentials".to_string(),
                    is_encrypted: false,
                    risk_level: "critical".to_string(),
                    description: "Sensitive credentials stored in SharedPreferences".to_string(),
                });
            }

            if has_sqlite_unencrypted {
                issues.push(DataStorageIssue {
                    location: "SQLite Database".to_string(),
                    data_type: "App Data".to_string(),
                    is_encrypted: false,
                    risk_level: "high".to_string(),
                    description: "Using unencrypted SQLite database for data storage".to_string(),
                });
            }

            if has_log_sensitive {
                issues.push(DataStorageIssue {
                    location: "Log Output".to_string(),
                    data_type: "Sensitive Info".to_string(),
                    is_encrypted: false,
                    risk_level: "high".to_string(),
                    description: "Sensitive information output in logs".to_string(),
                });
            }

            if has_plaintext_password {
                issues.push(DataStorageIssue {
                    location: "App Code".to_string(),
                    data_type: "Password".to_string(),
                    is_encrypted: false,
                    risk_level: "critical".to_string(),
                    description: "Plaintext password storage or transmission found".to_string(),
                });
            }
        }

        if platform == "android" {
            if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_storage_tmp"]) {
                let shared_prefs = "/tmp/biosphere_storage_tmp/shared_prefs";
                if Path::new(shared_prefs).exists() {
                    if let Ok(entries) = std::fs::read_dir(shared_prefs) {
                        for entry in entries.flatten() {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                let lower = content.to_lowercase();
                                if lower.contains("password") || lower.contains("token") || lower.contains("secret") {
                                    issues.push(DataStorageIssue {
                                        location: format!("SharedPreferences/{}", entry.file_name().to_string_lossy()),
                                        data_type: "Sensitive Info".to_string(),
                                        is_encrypted: false,
                                        risk_level: "critical".to_string(),
                                        description: "Sensitive information stored in SharedPreferences".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
                let _ = std::fs::remove_dir_all("/tmp/biosphere_storage_tmp");
            }
        }

        if platform == "ios" {
            if let Ok(output) = Self::run_command("unzip", &["-p", path, "Info.plist"]) {
                if output.contains("NSFileProtectionNone") {
                    issues.push(DataStorageIssue {
                        location: "File Protection".to_string(),
                        data_type: "File Data".to_string(),
                        is_encrypted: false,
                        risk_level: "high".to_string(),
                        description: "Using NSFileProtectionNone, file data not encrypted".to_string(),
                    });
                }
            }
        }

        issues
    }

    fn check_cryptography(path: &str, platform: &str) -> Vec<CryptoIssue> {
        let mut issues = Vec::new();

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let crypto_patterns = [
                ("AES/ECB", "AES ECB Mode", "high", "Use AES/GCM/NoPadding instead of ECB mode"),
                ("DES/", "DES Encryption", "critical", "DES is insecure, use AES instead"),
                ("MD5", "MD5 Hash", "critical", "MD5 is broken, use SHA-256 or stronger"),
                ("SHA1", "SHA-1 Hash", "high", "SHA-1 is insecure, use SHA-256 or stronger"),
                ("RC4", "RC4 Encryption", "critical", "RC4 has multiple vulnerabilities, use AES instead"),
                ("RSA/ECB/PKCS1Padding", "RSA PKCS1 Padding", "high", "Use RSA/OAEP instead of PKCS1 padding"),
                ("Blowfish", "Blowfish Encryption", "medium", "Consider using AES instead of Blowfish"),
                ("PBKDF1", "PBKDF1 Key Derivation", "high", "Use PBKDF2 or Argon2 instead"),
                ("CBC/PKCS5Padding", "AES CBC Mode", "medium", "Consider using AES/GCM instead of CBC mode"),
            ];

            let mut found = std::collections::HashSet::new();
            for line in output.lines() {
                let line = line.trim();
                for (pattern, desc, severity, rec) in &crypto_patterns {
                    if line.contains(pattern) && !found.contains(*pattern) {
                        found.insert(*pattern);
                        issues.push(CryptoIssue {
                            algorithm: pattern.to_string(),
                            usage: desc.to_string(),
                            key_size: None,
                            issue: format!("Insecure encryption algorithm detected: {}", pattern),
                            severity: severity.to_string(),
                            recommendation: rec.to_string(),
                        });
                    }
                }
            }

            let mut found_hardcoded_keys = false;
            for line in output.lines() {
                let line = line.trim();
                if (line.len() == 16 || line.len() == 24 || line.len() == 32)
                    && line.chars().all(|c| c.is_ascii_hexdigit())
                    && !found_hardcoded_keys
                {
                    let context_lower = line.to_lowercase();
                    if context_lower.contains("key") || context_lower.contains("secret") || context_lower.contains("aes") {
                        found_hardcoded_keys = true;
                        issues.push(CryptoIssue {
                            algorithm: "Hardcoded Key".to_string(),
                            usage: "Encryption Key".to_string(),
                            key_size: Some((line.len() * 4) as u32),
                            issue: "Hardcoded encryption key found".to_string(),
                            severity: "critical".to_string(),
                            recommendation: "Use secure key storage like Android Keystore or iOS Keychain".to_string(),
                        });
                    }
                }
            }
        }

        if platform == "android" {
            if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_crypto_tmp"]) {
                let smali_dir = "/tmp/biosphere_crypto_tmp/smali";
                if Path::new(smali_dir).exists() {
                    if let Ok(find_output) = Self::run_command("grep", &["-rl", "javax/crypto/Cipher", smali_dir]) {
                        if !find_output.trim().is_empty() {
                            for file_path in find_output.lines().take(5) {
                                if let Ok(content) = std::fs::read_to_string(file_path.trim()) {
                                    if content.contains("AES/ECB")
                                        && !issues.iter().any(|i| i.algorithm == "AES/ECB") {
                                            issues.push(CryptoIssue {
                                                algorithm: "AES/ECB".to_string(),
                                                usage: "Data Encryption".to_string(),
                                                key_size: None,
                                                issue: "ECB mode is insecure".to_string(),
                                                severity: "high".to_string(),
                                                recommendation: "Use AES/GCM/NoPadding".to_string(),
                                            });
                                        }
                                }
                            }
                        }
                    }
                }
                let _ = std::fs::remove_dir_all("/tmp/biosphere_crypto_tmp");
            }
        }

        issues
    }

    fn check_network(path: &str, platform: &str) -> Vec<NetworkIssue> {
        let mut issues = Vec::new();

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let mut http_count = 0;
            let mut has_ssl_pinning = false;
            let mut has_trust_all_certs = false;

            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("http://") && !line.contains("schemas.android.com") && !line.contains("www.w3.org") && !line.contains("schemas.microsoft.com") {
                    http_count += 1;
                }
                if line.contains("TrustAllCertificates") || line.contains("TrustManager") || line.contains("ALLOW_ALL_HOSTNAME_VERIFIER") {
                    has_trust_all_certs = true;
                }
                if line.contains("CertificatePinner") || line.contains("SSLContext") || line.contains("SSLPinning") {
                    has_ssl_pinning = true;
                }
            }

            if http_count > 0 {
                issues.push(NetworkIssue {
                    url: format!("{} HTTP URLs", http_count),
                    protocol: "HTTP".to_string(),
                    issue_type: "Plaintext Communication".to_string(),
                    severity: "high".to_string(),
                    description: format!("Found {} HTTP plaintext communication URLs", http_count),
                });
            }

            if has_trust_all_certs {
                issues.push(NetworkIssue {
                    url: "SSL Verification".to_string(),
                    protocol: "HTTPS".to_string(),
                    issue_type: "SSL Certificate Verification Disabled".to_string(),
                    severity: "critical".to_string(),
                    description: "App disabled SSL certificate verification, vulnerable to MITM attacks".to_string(),
                });
            }

            if !has_ssl_pinning {
                issues.push(NetworkIssue {
                    url: "SSL Pinning".to_string(),
                    protocol: "HTTPS".to_string(),
                    issue_type: "No SSL Pinning".to_string(),
                    severity: "medium".to_string(),
                    description: "App does not implement SSL certificate pinning, may be vulnerable to MITM attacks".to_string(),
                });
            }
        }

        if platform == "android" {
            if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_net_tmp"]) {
                let manifest = "/tmp/biosphere_net_tmp/AndroidManifest.xml";
                if Path::new(manifest).exists() {
                    if let Ok(content) = std::fs::read_to_string(manifest) {
                        if content.contains("android:usesCleartextTraffic=\"true\"") {
                            issues.push(NetworkIssue {
                                url: "AndroidManifest.xml".to_string(),
                                protocol: "HTTP".to_string(),
                                issue_type: "Cleartext Traffic Allowed".to_string(),
                                severity: "high".to_string(),
                                description: "App configuration allows cleartext network traffic".to_string(),
                            });
                        }
                    }
                }

                let network_config = "/tmp/biosphere_net_tmp/res/xml/network_security_config.xml";
                if Path::new(network_config).exists() {
                    if let Ok(content) = std::fs::read_to_string(network_config) {
                        if content.contains("cleartextTrafficPermitted=\"true\"") {
                            issues.push(NetworkIssue {
                                url: "network_security_config.xml".to_string(),
                                protocol: "HTTP".to_string(),
                                issue_type: "Network Security Config Allows Cleartext".to_string(),
                                severity: "high".to_string(),
                                description: "Network security configuration allows cleartext traffic".to_string(),
                            });
                        }
                    }
                }
                let _ = std::fs::remove_dir_all("/tmp/biosphere_net_tmp");
            }
        }

        if platform == "ios" {
            if let Ok(output) = Self::run_command("unzip", &["-p", path, "Info.plist"]) {
                if output.contains("NSAllowsArbitraryLoads") && output.contains("true") {
                    issues.push(NetworkIssue {
                        url: "Info.plist".to_string(),
                        protocol: "HTTPS".to_string(),
                        issue_type: "ATS Exception".to_string(),
                        severity: "high".to_string(),
                        description: "App Transport Security configuration allows arbitrary HTTP connections".to_string(),
                    });
                }
            }
        }

        issues
    }

    fn check_code_quality(path: &str, platform: &str) -> Vec<CodeQualityIssue> {
        let mut issues = Vec::new();

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let mut has_debug_logging = false;
            let mut _has_stack_trace = false;
            let mut has_print_stack_trace = false;

            for line in output.lines() {
                let line = line.trim();
                if line.contains("Log.d(") || line.contains("Log.v(") || line.contains("Log.i(") || line.contains("NSLog(") {
                    has_debug_logging = true;
                }
                if line.contains("printStackTrace") || line.contains("StackTrace") {
                    has_print_stack_trace = true;
                }
                if line.contains("Exception") && line.contains("at ") && line.contains(".java:") {
                    _has_stack_trace = true;
                }
            }

            if has_debug_logging {
                issues.push(CodeQualityIssue {
                    category: "Log Leakage".to_string(),
                    description: "Debug logs may be output in production environment".to_string(),
                    severity: "medium".to_string(),
                    file: "Multiple Files".to_string(),
                    line: None,
                });
            }

            if has_print_stack_trace {
                issues.push(CodeQualityIssue {
                    category: "Exception Handling".to_string(),
                    description: "Using printStackTrace to output exception stack, may leak internal info".to_string(),
                    severity: "medium".to_string(),
                    file: "Multiple Files".to_string(),
                    line: None,
                });
            }
        }

        if platform == "android" {
            if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_code_tmp"]) {
                let manifest = "/tmp/biosphere_code_tmp/AndroidManifest.xml";
                if Path::new(manifest).exists() {
                    if let Ok(content) = std::fs::read_to_string(manifest) {
                        if content.contains("android:debuggable=\"true\"") {
                            issues.push(CodeQualityIssue {
                                category: "Debug Configuration".to_string(),
                                description: "App is marked as debuggable (debuggable=true)".to_string(),
                                severity: "critical".to_string(),
                                file: "AndroidManifest.xml".to_string(),
                                line: None,
                            });
                        }
                        if content.contains("android:allowBackup=\"true\"") {
                            issues.push(CodeQualityIssue {
                                category: "Data Backup".to_string(),
                                description: "App allows ADB backup, may leak application data".to_string(),
                                severity: "medium".to_string(),
                                file: "AndroidManifest.xml".to_string(),
                                line: None,
                            });
                        }
                        if content.contains("android:exported=\"true\"") {
                            let count = content.matches("android:exported=\"true\"").count();
                            if count > 3 {
                                issues.push(CodeQualityIssue {
                                    category: "Component Exposure".to_string(),
                                    description: format!("Found {} exported components, may expose functionality", count),
                                    severity: "medium".to_string(),
                                    file: "AndroidManifest.xml".to_string(),
                                    line: None,
                                });
                            }
                        }
                    }
                }
                let _ = std::fs::remove_dir_all("/tmp/biosphere_code_tmp");
            }
        }

        if platform == "ios" {
            if let Ok(output) = Self::run_command("unzip", &["-p", path, "Info.plist"]) {
                if output.contains("UIFileSharingEnabled") && output.contains("true") {
                    issues.push(CodeQualityIssue {
                        category: "File Sharing".to_string(),
                        description: "App has iTunes file sharing enabled".to_string(),
                        severity: "medium".to_string(),
                        file: "Info.plist".to_string(),
                        line: None,
                    });
                }
            }
        }

        issues
    }

    fn check_tampering(path: &str, platform: &str) -> TamperingProtection {
        let mut root_detection = false;
        let mut jailbreak_detection = false;
        let mut integrity_check = false;
        let mut anti_debug = false;
        let mut anti_tamper = false;
        let mut emulator_detection = false;
        let mut repackaging_detection = false;

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let content = output.to_lowercase();

            if content.contains("supersu") || content.contains("magisk") || content.contains("su binary")
                || content.contains("/system/app/superuser") || content.contains("isrooted")
                || content.contains("rootbeer") || content.contains("rootdetect")
            {
                root_detection = true;
            }

            if content.contains("cydia") || content.contains("substrate") || content.contains("/bin/bash")
                || content.contains("/usr/sbin/sshd") || content.contains("/etc/apt")
                || content.contains("jailbroken") || content.contains("jailbreak")
            {
                jailbreak_detection = true;
            }

            if content.contains("signature") && (content.contains("verify") || content.contains("check"))
                || content.contains("packagename") && content.contains("signature")
                || content.contains("getsignatures")
            {
                integrity_check = true;
            }

            if content.contains("antidebug") || content.contains("isdebugger")
                || content.contains("debugger") && content.contains("detect")
                || content.contains("ptrace") || content.contains("traceme")
                || content.contains("android.os.debug") && content.contains("isdebuggerconnected")
            {
                anti_debug = true;
            }

            if content.contains("tamper") && (content.contains("detect") || content.contains("check"))
                || content.contains("integrity") && content.contains("check")
                || content.contains("dexchecksum") || content.contains("apkchecksum")
            {
                anti_tamper = true;
            }

            if content.contains("emulator") && (content.contains("detect") || content.contains("check"))
                || content.contains("isemulator") || content.contains("genymotion")
                || content.contains("bluestacks") || content.contains("nox")
                || content.contains("goldfish") || content.contains("sdk_gphone")
            {
                emulator_detection = true;
            }

            if content.contains("repackag") || content.contains("certificatepin")
                || content.contains("signatureverif") || content.contains("appsignature")
            {
                repackaging_detection = true;
            }
        }

        if platform == "android" {
            if let Ok(_output) = Self::run_command("apktool", &["d", "-f", "-s", path, "-o", "/tmp/biosphere_tamper_tmp"]) {
                let smali_dir = "/tmp/biosphere_tamper_tmp/smali";
                if Path::new(smali_dir).exists() {
                    if let Ok(find_output) = Self::run_command("grep", &["-rl", "RootBeer", smali_dir]) {
                        if !find_output.trim().is_empty() {
                            root_detection = true;
                        }
                    }
                    if let Ok(find_output) = Self::run_command("grep", &["-rl", "SafetyNet", smali_dir]) {
                        if !find_output.trim().is_empty() {
                            integrity_check = true;
                        }
                    }
                    if let Ok(find_output) = Self::run_command("grep", &["-rl", "isDebuggerConnected", smali_dir]) {
                        if !find_output.trim().is_empty() {
                            anti_debug = true;
                        }
                    }
                }
                let _ = std::fs::remove_dir_all("/tmp/biosphere_tamper_tmp");
            }
        }

        let detected_count = [root_detection, jailbreak_detection, integrity_check, anti_debug, anti_tamper, emulator_detection, repackaging_detection]
            .iter().filter(|&&x| x).count() as f64;
        let score = (detected_count / 7.0).clamp(0.0, 1.0);

        TamperingProtection {
            root_detection,
            jailbreak_detection,
            integrity_check,
            anti_debug,
            anti_tamper,
            emulator_detection,
            repackaging_detection,
            score,
        }
    }

    fn check_privacy(path: &str, _platform: &str, permissions: &[PermissionInfo]) -> Vec<PrivacyIssue> {
        let mut issues = Vec::new();

        let privacy_sensitive_perms: std::collections::HashMap<&str, (&str, &str, bool)> = [
            ("ACCESS_FINE_LOCATION", ("Precise Location", "GDPR/PIPL", true)),
            ("ACCESS_COARSE_LOCATION", ("Coarse Location", "GDPR/PIPL", true)),
            ("ACCESS_BACKGROUND_LOCATION", ("Background Location", "GDPR/PIPL", false)),
            ("READ_CONTACTS", ("Contacts", "GDPR/PIPL", true)),
            ("READ_CALL_LOG", ("Call Log", "GDPR/PIPL", false)),
            ("READ_SMS", ("SMS", "GDPR/PIPL", false)),
            ("CAMERA", ("Camera", "GDPR/PIPL", true)),
            ("RECORD_AUDIO", ("Microphone", "GDPR/PIPL", true)),
            ("READ_PHONE_STATE", ("Device Info", "GDPR/PIPL", false)),
            ("READ_PHONE_NUMBERS", ("Phone Number", "GDPR/PIPL", false)),
            ("READ_EXTERNAL_STORAGE", ("Storage", "GDPR/PIPL", true)),
            ("BODY_SENSORS", ("Sensors", "GDPR/PIPL", true)),
        ].iter().cloned().collect();

        for perm in permissions {
            let perm_name = perm.name.split('.').next_back().unwrap_or("");
            if let Some((data, reg, necessary)) = privacy_sensitive_perms.get(perm_name) {
                issues.push(PrivacyIssue {
                    data_collected: data.to_string(),
                    purpose: "App Functionality".to_string(),
                    is_necessary: *necessary,
                    risk_level: if *necessary { "medium" } else { "high" }.to_string(),
                    regulation: reg.to_string(),
                });
            }
        }

        if let Ok(output) = Self::run_command("strings", &[path]) {
            let mut has_device_id = false;
            let mut has_advertising_id = false;
            let mut has_imei = false;

            for line in output.lines() {
                let lower = line.to_lowercase();
                if lower.contains("getdeviceid") || lower.contains("device_id") || lower.contains("uniqueid") {
                    has_device_id = true;
                }
                if lower.contains("advertisingid") || lower.contains("ad_id") || lower.contains("advertisingidentifier") {
                    has_advertising_id = true;
                }
                if lower.contains("imei") || lower.contains("meid") || lower.contains("esn") {
                    has_imei = true;
                }
            }

            if has_device_id {
                issues.push(PrivacyIssue {
                    data_collected: "Device Unique ID".to_string(),
                    purpose: "User Tracking".to_string(),
                    is_necessary: false,
                    risk_level: "critical".to_string(),
                    regulation: "GDPR/PIPL".to_string(),
                });
            }

            if has_advertising_id {
                issues.push(PrivacyIssue {
                    data_collected: "Advertising ID".to_string(),
                    purpose: "Ad Tracking".to_string(),
                    is_necessary: false,
                    risk_level: "high".to_string(),
                    regulation: "GDPR/PIPL".to_string(),
                });
            }

            if has_imei {
                issues.push(PrivacyIssue {
                    data_collected: "IMEI/MEID".to_string(),
                    purpose: "Device Tracking".to_string(),
                    is_necessary: false,
                    risk_level: "critical".to_string(),
                    regulation: "GDPR/PIPL".to_string(),
                });
            }
        }

        issues
    }

    fn calculate_score(total_issues: usize, critical_issues: usize, tampering: &TamperingProtection) -> f64 {
        let issue_penalty = (total_issues as f64 * 0.05 + critical_issues as f64 * 0.15).min(0.7);
        let protection_bonus = tampering.score * 0.3;
        (1.0 - issue_penalty + protection_bonus).clamp(0.0, 1.0)
    }

    pub fn run_frida_dynamic_analysis(_package_name: &str, device_id: Option<&str>) -> std::result::Result<DynamicAnalysisResult, String> {
        if Self::run_command("which", &["frida"]).is_err() {
            return Err("Frida not found. Install with: pip install frida-tools".to_string());
        }

        let mut hooks = Vec::new();
        let mut objection_findings = Vec::new();

        let _device_arg = device_id.map(|d| format!("-D {}", d)).unwrap_or_default();

        let frida_scripts = vec![
            ("Crypto Monitor", r#"
                if (ObjC.available) {
                    var SecKeyEncrypt = Module.findExportByName('Security', 'SecKeyEncrypt');
                    if (SecKeyEncrypt) Interceptor.attach(SecKeyEncrypt, { onEnter: function(args) { send({type:'crypto', method:'SecKeyEncrypt'}); } });
                }
                if (Java.available) {
                    Java.perform(function() {
                        var Cipher = Java.use('javax.crypto.Cipher');
                        Cipher.getInstance.overload('java.lang.String').implementation = function(alg) { send({type:'crypto', method:'Cipher.getInstance', args:[alg]}); return this.getInstance(alg); };
                    });
                }
            "#),
            ("SSL Pinning Bypass", r#"
                if (ObjC.available) {
                    var ssl = Module.findExportByName('Security', 'SSLCreateContext');
                    if (ssl) Interceptor.attach(ssl, { onEnter: function(args) { send({type:'ssl', method:'SSLCreateContext'}); } });
                }
                if (Java.available) {
                    Java.perform(function() {
                        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                        var SSLContext = Java.use('javax.net.ssl.SSLContext');
                    });
                }
            "#),
            ("Auth Bypass Monitor", r#"
                if (ObjC.available) {
                    var LAContext = ObjC.classes.LAContext;
                    if (LAContext) {
                        var evaluatePolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];
                        if (evaluatePolicy) Interceptor.attach(evaluatePolicy.implementation, { onEnter: function(args) { send({type:'auth', method:'evaluatePolicy'}); } });
                    }
                }
                if (Java.available) {
                    Java.perform(function() {
                        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
                    });
                }
            "#),
        ];

        for (name, _script) in &frida_scripts {
            hooks.push(FridaHookResult {
                method_name: name.to_string(),
                class_name: "Dynamic".to_string(),
                return_value: None,
                arguments: Vec::new(),
                is_crypto_operation: name.contains("Crypto"),
                is_auth_bypass: name.contains("Auth"),
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        if Self::run_command("which", &["objection"]).is_ok() {
            let objection_commands = vec![
                ("ios", "keychain dump", "Keychain"),
                ("android", "keystore list", "Keystore"),
                ("ios", "sqlite connect", "SQLite"),
                ("android", "sqlite connect", "SQLite"),
            ];

            for (platform, cmd, category) in &objection_commands {
                objection_findings.push(ObjectionFinding {
                    category: category.to_string(),
                    finding: format!("{} command available", cmd),
                    severity: "info".to_string(),
                    detail: format!("objection {} {}", platform, cmd),
                    remediation: None,
                });
            }
        }

        Ok(DynamicAnalysisResult {
            runtime_hooks: hooks,
            ssl_pinning_bypass: false,
            root_bypass: false,
            keychain_dump: Vec::new(),
            objection_findings,
            method_trace: Vec::new(),
            memory_dumps: Vec::new(),
        })
    }

    pub fn run_objection_exploration(_package_name: &str, platform: &str) -> std::result::Result<Vec<ObjectionFinding>, String> {
        if Self::run_command("which", &["objection"]).is_err() {
            return Err("Objection not found. Install with: pip install objection".to_string());
        }

        let mut findings = Vec::new();

        let checks = match platform {
            "ios" => vec![
                ("Security", "ios keychain dump", "Dump iOS keychain entries including passwords and tokens", "critical"),
                ("Security", "ios cookies get", "Retrieve stored cookies", "high"),
                ("Security", "ios nsurlcredentialstorage dump", "Dump URL credential storage", "high"),
                ("Privacy", "ios contacts dump", "Access contacts database", "medium"),
                ("Security", "ios pasteboard monitor", "Monitor pasteboard for sensitive data", "medium"),
                ("Bypass", "ios sslpinning disable", "Disable SSL certificate pinning", "critical"),
                ("Bypass", "ios jailbreak disable", "Disable jailbreak detection", "high"),
                ("Analysis", "ios nsuserdefaults get", "Get NSUserDefaults data", "medium"),
            ],
            _ => vec![
                ("Security", "android keystore list", "List Android Keystore entries", "high"),
                ("Security", "android sslpinning disable", "Disable SSL certificate pinning", "critical"),
                ("Bypass", "android root disable", "Disable root detection", "high"),
                ("Analysis", "android heap search", "Search heap for sensitive data", "medium"),
                ("Security", "android sqlite connect", "Connect to app SQLite databases", "high"),
                ("Privacy", "android clipboard monitor", "Monitor clipboard for sensitive data", "medium"),
                ("Security", "android keystore dump", "Dump keystore contents", "critical"),
                ("Analysis", "android intent monitor", "Monitor intent communications", "medium"),
            ],
        };

        for (category, cmd, detail, severity) in &checks {
            findings.push(ObjectionFinding {
                category: category.to_string(),
                finding: cmd.to_string(),
                severity: severity.to_string(),
                detail: detail.to_string(),
                remediation: Some("Ensure proper security controls are in place".to_string()),
            });
        }

        Ok(findings)
    }

    pub fn generate_frida_script(platform: &str, target: &str) -> String {
        match platform {
            "ios" => match target {
                "ssl_bypass" => r#"
                    if (ObjC.available) {
                        var SSLCreateContext = Module.findExportByName('Security', 'SSLCreateContext');
                        var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
                        if (SSLSetSessionOption) {
                            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(ctx, opt, val) {
                                return 0;
                            }, 'int', ['pointer', 'int', 'bool']));
                        }
                    }
                "#.to_string(),
                "jailbreak_bypass" => r#"
                    if (ObjC.available) {
                        var FileManager = ObjC.classes.NSFileManager;
                        var fileExistsAtPath = FileManager['- fileExistsAtPath:'];
                        Interceptor.attach(fileExistsAtPath.implementation, {
                            onEnter: function(args) {
                                var path = ObjC.Object(args[2]).toString();
                                if (path.indexOf('/Applications/Cydia.app') !== -1 || path.indexOf('/bin/bash') !== -1) {
                                    this.isJailbreakCheck = true;
                                }
                            },
                            onLeave: function(retval) {
                                if (this.isJailbreakCheck) retval.replace(0);
                            }
                        });
                    }
                "#.to_string(),
                _ => r#"console.log("Generic iOS Frida script");"#.to_string(),
            },
            _ => match target {
                "ssl_bypass" => r#"
                    if (Java.available) {
                        Java.perform(function() {
                            var TrustManager = Java.registerClass({
                                name: 'com.custom.TrustManager',
                                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                                methods: {
                                    checkClientTrusted: function() {},
                                    checkServerTrusted: function() {},
                                    getAcceptedIssuers: function() { return []; }
                                }
                            });
                        });
                    }
                "#.to_string(),
                "root_bypass" => r#"
                    if (Java.available) {
                        Java.perform(function() {
                            var File = Java.use('java.io.File');
                            File.exists.implementation = function() {
                                var path = this.getAbsolutePath();
                                if (path.indexOf('su') !== -1 || path.indexOf('Superuser') !== -1 || path.indexOf('magisk') !== -1) {
                                    return false;
                                }
                                return this.exists();
                            };
                        });
                    }
                "#.to_string(),
                _ => r#"console.log("Generic Android Frida script");"#.to_string(),
            },
        }
    }
}
