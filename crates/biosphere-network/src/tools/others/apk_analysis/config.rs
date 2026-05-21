use serde::{Deserialize, Serialize};
use std::path::Path;
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkAnalysisConfig {
    pub apk_path: String,
    pub extract_manifest: bool,
    pub extract_permissions: bool,
    pub extract_certificates: bool,
    pub extract_apis: bool,
    pub enable_deep_analysis: bool,
}

impl Default for ApkAnalysisConfig {
    fn default() -> Self {
        Self {
            apk_path: String::new(),
            extract_manifest: true,
            extract_permissions: true,
            extract_certificates: true,
            extract_apis: true,
            enable_deep_analysis: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkAnalysisResult {
    pub success: bool,
    pub package_name: String,
    pub version_name: String,
    pub version_code: String,
    pub min_sdk: String,
    pub target_sdk: String,
    pub file_size: u64,
    pub file_md5: String,
    pub file_sha1: String,
    pub file_sha256: String,
    pub is_debuggable: bool,
    pub is_allow_backup: bool,
    pub permissions: Vec<String>,
    pub dangerous_permissions: Vec<String>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
    pub receivers: Vec<String>,
    pub providers: Vec<String>,
    pub exported_activities: Vec<String>,
    pub exported_services: Vec<String>,
    pub exported_receivers: Vec<String>,
    pub exported_providers: Vec<String>,
    pub certificates: Vec<ApkCertificateInfo>,
    pub apis: Vec<String>,
    pub security_issues: Vec<SecurityIssue>,
    pub security_score: i32,
    pub summary: String,
    pub deep_analysis: Option<DeepAnalysisResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAnalysisResult {
    pub decompiled: bool,
    pub decompiled_path: String,
    pub source_file_count: usize,
    pub native_libs: Vec<NativeLibrary>,
    pub sensitive_findings: Vec<SensitiveFinding>,
    pub api_keys: Vec<ApiKeyFinding>,
    pub hardcoded_secrets: Vec<SecretFinding>,
    pub sql_injection_risks: Vec<CodeIssue>,
    pub crypto_issues: Vec<CryptoIssue>,
    pub webview_issues: Vec<WebViewIssue>,
    pub third_party_sdks: Vec<SdkInfo>,
    pub privacy_issues: Vec<PrivacyIssue>,
    pub network_security: NetworkSecurityAnalysis,
    pub deep_security_score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLibrary {
    pub name: String,
    pub arch: String,
    pub size: u64,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFinding {
    pub finding_type: String,
    pub file_path: String,
    pub line_number: usize,
    pub content: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyFinding {
    pub key_type: String,
    pub key_name: String,
    pub key_value: String,
    pub file_path: String,
    pub line_number: usize,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: String,
    pub secret_name: String,
    pub secret_value: String,
    pub file_path: String,
    pub line_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeIssue {
    pub issue_type: String,
    pub file_path: String,
    pub line_number: usize,
    pub code_snippet: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIssue {
    pub issue_type: String,
    pub file_path: String,
    pub line_number: usize,
    pub algorithm: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebViewIssue {
    pub file_path: String,
    pub line_number: usize,
    pub issue_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkInfo {
    pub name: String,
    pub sdk_type: String,
    pub package_name: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub data_collection: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIssue {
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub data_type: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityAnalysis {
    pub uses_cleartext_traffic: bool,
    pub certificate_pinning: bool,
    pub trust_manager_issues: Vec<String>,
    pub hostname_verifier_issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkCertificateInfo {
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
}

const DANGEROUS_PERMS: [&str; 24] = [
    "READ_CALENDAR", "WRITE_CALENDAR", "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "RECORD_AUDIO",
    "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS", "BODY_SENSORS",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
];

pub struct ApkAnalysisTool;

impl ApkAnalysisTool {
    pub async fn analyze(config: &ApkAnalysisConfig) -> std::result::Result<ApkAnalysisResult, String> {
        if config.apk_path.is_empty() {
            return Err("APK file path is required".to_string());
        }

        let path = Path::new(&config.apk_path);
        if !path.exists() {
            return Err(format!("APK file not found: {}", config.apk_path));
        }

        if let Ok(aapt_output) = Self::run_aapt(&config.apk_path) {
            return Self::parse_aapt_output(&aapt_output, config).await;
        }

        if let Ok(aapt2_output) = Self::run_aapt2(&config.apk_path) {
            return Self::parse_aapt_output(&aapt2_output, config).await;
        }

        Self::analyze_via_zip(&config.apk_path, config).await
    }

    fn run_aapt(apk_path: &str) -> std::result::Result<String, String> {
        let output = std::process::Command::new("aapt")
            .args(["dump", "badging", apk_path])
            .output()
            .map_err(|e| format!("aapt not available: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err("aapt failed".to_string())
        }
    }

    fn run_aapt2(apk_path: &str) -> std::result::Result<String, String> {
        let output = std::process::Command::new("aapt2")
            .args(["dump", "badging", apk_path])
            .output()
            .map_err(|e| format!("aapt2 not available: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err("aapt2 failed".to_string())
        }
    }

    async fn parse_aapt_output(aapt_output: &str, config: &ApkAnalysisConfig) -> std::result::Result<ApkAnalysisResult, String> {
        let mut package_name = String::new();
        let mut version_name = String::new();
        let mut version_code = String::new();
        let mut min_sdk = String::new();
        let mut target_sdk = String::new();
        let mut permissions = Vec::new();
        let mut dangerous_permissions = Vec::new();
        let mut activities = Vec::new();
        let mut services = Vec::new();
        let mut receivers = Vec::new();
        let mut providers = Vec::new();
        let mut exported_activities = Vec::new();
        let mut exported_services = Vec::new();
        let mut exported_receivers = Vec::new();
        let mut exported_providers = Vec::new();

        for line in aapt_output.lines() {
            let line = line.trim();

            if line.starts_with("package: name=") {
                for part in line.split_whitespace() {
                    if part.starts_with("name='") {
                        package_name = part.trim_start_matches("name='").trim_end_matches("'").to_string();
                    } else if part.starts_with("versionName='") {
                        version_name = part.trim_start_matches("versionName='").trim_end_matches("'").to_string();
                    } else if part.starts_with("versionCode='") {
                        version_code = part.trim_start_matches("versionCode='").trim_end_matches("'").to_string();
                    }
                }
            }

            if line.starts_with("sdkVersion:'") {
                min_sdk = line.trim_start_matches("sdkVersion:'").trim_end_matches("'").to_string();
            }

            if line.starts_with("targetSdkVersion:'") {
                target_sdk = line.trim_start_matches("targetSdkVersion:'").trim_end_matches("'").to_string();
            }

            if line.starts_with("uses-permission:") {
                if let Some(name_start) = line.find("name='") {
                    let name = &line[name_start + 6..];
                    if let Some(end) = name.find("'") {
                        let perm = &name[..end];
                        permissions.push(perm.to_string());
                        if DANGEROUS_PERMS.iter().any(|dp| perm.contains(dp)) {
                            dangerous_permissions.push(perm.to_string());
                        }
                    }
                }
            }

            if line.contains("launchable-activity") || line.starts_with("activity:") {
                if let Some(name_start) = line.find("name='") {
                    let name = &line[name_start + 6..];
                    if let Some(end) = name.find("'") {
                        let act_name = name[..end].to_string();
                        if !activities.contains(&act_name) {
                            activities.push(act_name.clone());
                        }
                        if line.contains("exported='true'") || line.contains("exported=\"true\"") {
                            if !exported_activities.contains(&act_name) {
                                exported_activities.push(act_name);
                            }
                        }
                    }
                }
            }

            if line.starts_with("service:") {
                if let Some(name_start) = line.find("name='") {
                    let name = &line[name_start + 6..];
                    if let Some(end) = name.find("'") {
                        let svc_name = name[..end].to_string();
                        services.push(svc_name.clone());
                        if line.contains("exported='true'") || line.contains("exported=\"true\"") {
                            exported_services.push(svc_name);
                        }
                    }
                }
            }

            if line.starts_with("receiver:") {
                if let Some(name_start) = line.find("name='") {
                    let name = &line[name_start + 6..];
                    if let Some(end) = name.find("'") {
                        let rcv_name = name[..end].to_string();
                        receivers.push(rcv_name.clone());
                        if line.contains("exported='true'") || line.contains("exported=\"true\"") {
                            exported_receivers.push(rcv_name);
                        }
                    }
                }
            }

            if line.starts_with("provider:") {
                if let Some(name_start) = line.find("name='") {
                    let name = &line[name_start + 6..];
                    if let Some(end) = name.find("'") {
                        let prv_name = name[..end].to_string();
                        providers.push(prv_name.clone());
                        if line.contains("exported='true'") || line.contains("exported=\"true\"") {
                            exported_providers.push(prv_name);
                        }
                    }
                }
            }
        }

        let (is_debuggable, is_allow_backup) = Self::detect_security_flags(&config.apk_path);

        let mut certificates = Vec::new();
        if config.extract_certificates {
            certificates = Self::extract_certificates(&config.apk_path);
        }

        let mut apis = Vec::new();
        if config.extract_apis {
            apis = Self::extract_apis(&config.apk_path);
        }

        let (file_size, file_md5, file_sha1, file_sha256) = Self::compute_file_info(&config.apk_path);

        let mut security_issues = Vec::new();
        if is_debuggable {
            security_issues.push(SecurityIssue {
                severity: "high".to_string(),
                category: "configuration".to_string(),
                description: "Application is debuggable".to_string(),
                detail: "android:debuggable=true allows debugging of the application, which can expose sensitive data and functionality.".to_string(),
            });
        }
        if is_allow_backup {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "configuration".to_string(),
                description: "Application allows backup".to_string(),
                detail: "android:allowBackup=true allows adb backup to extract application data including private files and databases.".to_string(),
            });
        }
        if !exported_activities.is_empty() {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "component".to_string(),
                description: format!("{} exported activities found", exported_activities.len()),
                detail: format!("Exported activities can be launched by any app: {}", exported_activities.join(", ")),
            });
        }
        if !exported_services.is_empty() {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "component".to_string(),
                description: format!("{} exported services found", exported_services.len()),
                detail: format!("Exported services can be bound/started by any app: {}", exported_services.join(", ")),
            });
        }
        if !exported_receivers.is_empty() {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "component".to_string(),
                description: format!("{} exported receivers found", exported_receivers.len()),
                detail: format!("Exported receivers can receive broadcasts from any app: {}", exported_receivers.join(", ")),
            });
        }
        if !exported_providers.is_empty() {
            security_issues.push(SecurityIssue {
                severity: "high".to_string(),
                category: "component".to_string(),
                description: format!("{} exported providers found", exported_providers.len()),
                detail: format!("Exported content providers expose data to any app: {}", exported_providers.join(", ")),
            });
        }
        if dangerous_permissions.len() > 5 {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "permission".to_string(),
                description: format!("{} dangerous permissions requested", dangerous_permissions.len()),
                detail: format!("Excessive dangerous permissions: {}", dangerous_permissions.join(", ")),
            });
        }
        for cert in &certificates {
            if let Ok(expiry) = chrono::DateTime::parse_from_str(&cert.valid_to, "%a %b %d %H:%M:%S %Z %Y") {
                if expiry.timestamp() < chrono::Utc::now().timestamp() {
                    security_issues.push(SecurityIssue {
                        severity: "high".to_string(),
                        category: "certificate".to_string(),
                        description: "Signing certificate has expired".to_string(),
                        detail: format!("Certificate expired on: {}", cert.valid_to),
                    });
                }
            }
        }
        if target_sdk.parse::<i32>().unwrap_or(0) < 28 {
            security_issues.push(SecurityIssue {
                severity: "low".to_string(),
                category: "configuration".to_string(),
                description: "Low target SDK version".to_string(),
                detail: format!("targetSdkVersion={} is below 28 (Android 9), which may weaken security enforcement.", target_sdk),
            });
        }

        let security_score = Self::calculate_security_score(
            is_debuggable,
            is_allow_backup,
            &dangerous_permissions,
            &exported_activities,
            &exported_services,
            &exported_receivers,
            &exported_providers,
            &certificates,
            &target_sdk,
        );

        let summary = format!(
            "APK Analysis | Package: {} | Version: {} | Permissions: {} (Dangerous: {}) | Activities: {} | Services: {} | Security Score: {}/100",
            package_name, version_name, permissions.len(), dangerous_permissions.len(), activities.len(), services.len(), security_score
        );

        let deep_analysis = if config.enable_deep_analysis {
            Some(Self::perform_deep_analysis(&config.apk_path, &package_name))
        } else {
            None
        };

        Ok(ApkAnalysisResult {
            success: true,
            package_name,
            version_name,
            version_code,
            min_sdk,
            target_sdk,
            file_size,
            file_md5,
            file_sha1,
            file_sha256,
            is_debuggable,
            is_allow_backup,
            permissions,
            dangerous_permissions,
            activities,
            services,
            receivers,
            providers,
            exported_activities,
            exported_services,
            exported_receivers,
            exported_providers,
            certificates,
            apis,
            security_issues,
            security_score,
            summary,
            deep_analysis,
        })
    }

    fn detect_security_flags(apk_path: &str) -> (bool, bool) {
        let mut is_debuggable = false;
        let mut is_allow_backup = false;

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["dump", "xmltree", apk_path, "AndroidManifest.xml"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.contains("android:debuggable") && (line.contains("=0xffffffff") || line.contains("=\"true\"") || line.contains("='true'")) {
                        is_debuggable = true;
                    }
                    if line.contains("android:allowBackup") && (line.contains("=0xffffffff") || line.contains("=\"true\"") || line.contains("='true'")) {
                        is_allow_backup = true;
                    }
                }
            }
        }

        if !is_debuggable && !is_allow_backup {
            if let Ok(output) = std::process::Command::new("aapt")
                .args(["dump", "badging", apk_path])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    for line in stdout.lines() {
                        let line = line.trim();
                        if line.starts_with("package:") {
                            if line.contains("debuggable='true'") || line.contains("debuggable=\"true\"") {
                                is_debuggable = true;
                            }
                        }
                    }
                }
            }
        }

        if !is_debuggable && !is_allow_backup {
            if let Ok(output) = std::process::Command::new("unzip")
                .args(["-p", apk_path, "AndroidManifest.xml"])
                .output()
            {
                if output.status.success() && !output.stdout.is_empty() {
                    let bytes = &output.stdout;
                    let content = String::from_utf8_lossy(bytes);
                    for chunk in content.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '=') {
                        if chunk == "debuggable" || chunk.contains("debuggable=") {
                            is_debuggable = true;
                        }
                        if chunk == "allowBackup" || chunk.contains("allowBackup=") {
                            is_allow_backup = true;
                        }
                    }

                    if !is_debuggable && !is_allow_backup {
                        let raw = bytes;
                        let debuggable_pattern = b"debuggable";
                        let backup_pattern = b"allowBackup";
                        for i in 0..raw.len().saturating_sub(20) {
                            if raw[i..].starts_with(debuggable_pattern) {
                                for j in i..std::cmp::min(i + 20, raw.len()) {
                                    if raw[j] == 0xFF || raw[j] == 0x01 || raw[j] == b't' {
                                        is_debuggable = true;
                                        break;
                                    }
                                }
                            }
                            if raw[i..].starts_with(backup_pattern) {
                                for j in i..std::cmp::min(i + 20, raw.len()) {
                                    if raw[j] == 0xFF || raw[j] == 0x01 || raw[j] == b't' {
                                        is_allow_backup = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        (is_debuggable, is_allow_backup)
    }

    fn compute_file_info(apk_path: &str) -> (u64, String, String, String) {
        let file_size = std::fs::metadata(apk_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let file = match std::fs::File::open(apk_path) {
            Ok(f) => f,
            Err(_) => return (file_size, String::new(), String::new(), String::new()),
        };

        let mut reader = std::io::BufReader::new(file);

        let file_md5 = {
            use md5::Digest;
            let mut hasher = md5::Md5::new();
            let _ = std::io::copy(&mut reader, &mut hasher);
            format!("{:x}", hasher.finalize())
        };

        let file = match std::fs::File::open(apk_path) {
            Ok(f) => f,
            Err(_) => return (file_size, file_md5, String::new(), String::new()),
        };
        reader = std::io::BufReader::new(file);

        let file_sha1 = {
            use sha1::Digest;
            let mut hasher = sha1::Sha1::new();
            let _ = std::io::copy(&mut reader, &mut hasher);
            format!("{:x}", hasher.finalize())
        };

        let file = match std::fs::File::open(apk_path) {
            Ok(f) => f,
            Err(_) => return (file_size, file_md5, file_sha1, String::new()),
        };
        reader = std::io::BufReader::new(file);

        let file_sha256 = {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            let _ = std::io::copy(&mut reader, &mut hasher);
            format!("{:x}", hasher.finalize())
        };

        (file_size, file_md5, file_sha1, file_sha256)
    }

    fn calculate_security_score(
        is_debuggable: bool,
        is_allow_backup: bool,
        dangerous_permissions: &[String],
        exported_activities: &[String],
        exported_services: &[String],
        exported_receivers: &[String],
        exported_providers: &[String],
        certificates: &[ApkCertificateInfo],
        target_sdk: &str,
    ) -> i32 {
        let mut score: i32 = 100;

        if is_debuggable { score -= 25; }
        if is_allow_backup { score -= 10; }

        let danger_perm_deduction = std::cmp::min(dangerous_permissions.len() as i32 * 3, 20);
        score -= danger_perm_deduction;

        let exported_activity_deduction = std::cmp::min(exported_activities.len() as i32 * 3, 10);
        score -= exported_activity_deduction;

        let exported_service_deduction = std::cmp::min(exported_services.len() as i32 * 5, 15);
        score -= exported_service_deduction;

        let exported_receiver_deduction = std::cmp::min(exported_receivers.len() as i32 * 3, 10);
        score -= exported_receiver_deduction;

        let exported_provider_deduction = std::cmp::min(exported_providers.len() as i32 * 8, 20);
        score -= exported_provider_deduction;

        for cert in certificates {
            if let Ok(expiry) = chrono::DateTime::parse_from_str(&cert.valid_to, "%a %b %d %H:%M:%S %Z %Y") {
                if expiry.timestamp() < chrono::Utc::now().timestamp() {
                    score -= 15;
                    break;
                }
            }
        }

        if target_sdk.parse::<i32>().unwrap_or(0) < 28 {
            score -= 5;
        }

        score.max(0)
    }

    fn extract_certificates(apk_path: &str) -> Vec<ApkCertificateInfo> {
        let mut certs = Vec::new();

        if let Ok(output) = std::process::Command::new("keytool")
            .args(["-printcert", "-jarfile", apk_path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let mut current_cert = CertParser::new();

                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("Owner:") {
                        if current_cert.has_data() {
                            if let Some(cert) = current_cert.build() {
                                certs.push(cert);
                            }
                        }
                        current_cert = CertParser::new();
                        current_cert.issuer = line.trim_start_matches("Owner:").trim().to_string();
                    }
                    if line.starts_with("Issuer:") {
                        current_cert.subject = line.trim_start_matches("Issuer:").trim().to_string();
                    }
                    if line.starts_with("Serial number:") {
                        current_cert.serial_number = line.trim_start_matches("Serial number:").trim().to_string();
                    }
                    if line.contains("Valid from:") && line.contains("until:") {
                        if let Some(idx) = line.find("Valid from:") {
                            let rest = &line[idx + 11..];
                            if let Some(until_idx) = rest.find("until:") {
                                current_cert.valid_from = rest[..until_idx].trim().to_string();
                                current_cert.valid_to = rest[until_idx + 6..].trim().to_string();
                            }
                        }
                    }
                    if line.contains("SHA1:") {
                        if let Some(idx) = line.find("SHA1:") {
                            let raw = line[idx + 5..].trim();
                            current_cert.fingerprint_sha1 = format_fingerprint(raw);
                        }
                    }
                    if line.contains("SHA256:") {
                        if let Some(idx) = line.find("SHA256:") {
                            let raw = line[idx + 7..].trim();
                            current_cert.fingerprint_sha256 = format_fingerprint(raw);
                        }
                    }
                }

                if current_cert.has_data() {
                    if let Some(cert) = current_cert.build() {
                        certs.push(cert);
                    }
                }
            }
        }

        if certs.is_empty() {
            if let Ok(output) = std::process::Command::new("apksigner")
                .args(["verify", "--print-certs", apk_path])
                .output()
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let mut sha1 = String::new();
                    let mut sha256 = String::new();
                    let mut dn = String::new();

                    for line in stdout.lines() {
                        let line = line.trim();
                        if line.contains("SHA-1") {
                            if let Some(idx) = line.find(':') {
                                sha1 = line[idx + 1..].trim().to_string();
                            }
                        }
                        if line.contains("SHA-256") {
                            if let Some(idx) = line.find(':') {
                                sha256 = line[idx + 1..].trim().to_string();
                            }
                        }
                        if line.contains("DN=") {
                            if let Some(idx) = line.find("DN=") {
                                dn = line[idx + 3..].trim().to_string();
                            }
                        }
                    }

                    if !sha1.is_empty() || !sha256.is_empty() {
                        certs.push(ApkCertificateInfo {
                            issuer: dn.clone(),
                            subject: dn,
                            serial_number: String::new(),
                            valid_from: String::new(),
                            valid_to: String::new(),
                            fingerprint_sha1: sha1,
                            fingerprint_sha256: sha256,
                        });
                    }
                }
            }
        }

        certs
    }

    fn extract_apis(apk_path: &str) -> Vec<String> {
        let mut apis = Vec::new();

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["dump", "xmltree", apk_path, "AndroidManifest.xml"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.contains("android:name") {
                        if let Some(idx) = line.find("android:name=") {
                            let rest = &line[idx + 14..];
                            let name = if rest.starts_with('"') {
                                &rest[1..]
                            } else {
                                rest
                            };
                            if let Some(end) = name.find('"') {
                                let api_name = &name[..end];
                                if !api_name.is_empty()
                                    && !api_name.starts_with("android.")
                                    && !apis.contains(&api_name.to_string())
                                {
                                    apis.push(api_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["list", apk_path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("classes") && line.ends_with(".dex") {
                        let entry = format!("DEX: {}", line);
                        if !apis.contains(&entry) {
                            apis.push(entry);
                        }
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["dump", "badging", apk_path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.starts_with("uses-library") {
                        if let Some(idx) = line.find("name='") {
                            let rest = &line[idx + 6..];
                            if let Some(end) = rest.find('\'') {
                                let lib_name = &rest[..end];
                                let entry = format!("Library: {}", lib_name);
                                if !apis.contains(&entry) {
                                    apis.push(entry);
                                }
                            }
                        }
                    }
                    if line.starts_with("uses-feature") {
                        if let Some(idx) = line.find("name='") {
                            let rest = &line[idx + 6..];
                            if let Some(end) = rest.find('\'') {
                                let feature = &rest[..end];
                                let entry = format!("Feature: {}", feature);
                                if !apis.contains(&entry) {
                                    apis.push(entry);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("unzip")
            .args(["-l", apk_path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.contains("META-INF/services/") {
                        if let Some(name) = line.split_whitespace().last() {
                            let entry = format!("Service: {}", name);
                            if !apis.contains(&entry) {
                                apis.push(entry);
                            }
                        }
                    }
                    if line.contains("assets/") && (line.ends_with(".json") || line.ends_with(".xml") || line.ends_with(".properties")) {
                        if let Some(name) = line.split_whitespace().last() {
                            let entry = format!("Asset: {}", name);
                            if !apis.contains(&entry) {
                                apis.push(entry);
                            }
                        }
                    }
                }
            }
        }

        apis
    }

    async fn analyze_via_zip(apk_path: &str, config: &ApkAnalysisConfig) -> std::result::Result<ApkAnalysisResult, String> {
        let mut package_name: String;
        let mut version_name = String::new();
        let mut version_code = String::new();
        let mut min_sdk = String::new();
        let mut target_sdk = String::new();
        let mut permissions = Vec::new();
        let mut dangerous_permissions = Vec::new();
        let mut activities = Vec::new();
        let mut services = Vec::new();
        let mut receivers = Vec::new();
        let mut providers = Vec::new();
        let mut apis = Vec::new();

        let mut has_manifest = false;
        let mut has_dex = false;

        if let Ok(output) = std::process::Command::new("unzip")
            .args(["-l", apk_path])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();

                for line in stdout.lines() {
                    if line.contains("AndroidManifest.xml") { has_manifest = true; }
                    if line.contains("classes.dex") { has_dex = true; }
                    if line.starts_with("classes") && line.ends_with(".dex") {
                        let entry = format!("DEX: {}", line.split_whitespace().last().unwrap_or(""));
                        if !apis.contains(&entry) {
                            apis.push(entry);
                        }
                    }
                }
            }
        }

        if !has_manifest {
            return Err("Invalid APK: AndroidManifest.xml not found".to_string());
        }
        if !has_dex {
            return Err("Invalid APK: classes.dex not found".to_string());
        }

        package_name = path_to_package_name(apk_path);

        if let Ok(output) = std::process::Command::new("unzip")
            .args(["-p", apk_path, "AndroidManifest.xml"])
            .output()
        {
            if output.status.success() {
                let bytes = &output.stdout;
                if bytes.len() > 4 {
                    let is_binary_xml = bytes[0] == 0x00 || bytes[0] == 0x03;
                    if !is_binary_xml {
                        let content = String::from_utf8_lossy(bytes);
                        for line in content.lines() {
                            let line = line.trim();
                            if line.contains("package=\"") {
                                if let Some(start) = line.find("package=\"") {
                                    let rest = &line[start + 9..];
                                    if let Some(end) = rest.find('"') {
                                        package_name = rest[..end].to_string();
                                    }
                                }
                            }
                            if line.contains("uses-permission") && line.contains("android:name=\"") {
                                if let Some(start) = line.find("android:name=\"") {
                                    let rest = &line[start + 14..];
                                    if let Some(end) = rest.find('"') {
                                        let perm = rest[..end].to_string();
                                        if !permissions.contains(&perm) {
                                            permissions.push(perm.clone());
                                            if DANGEROUS_PERMS.iter().any(|dp| perm.contains(dp)) {
                                                dangerous_permissions.push(perm);
                                            }
                                        }
                                    }
                                }
                            }
                            if line.contains("<activity") && line.contains("android:name=\"") {
                                if let Some(start) = line.find("android:name=\"") {
                                    let rest = &line[start + 14..];
                                    if let Some(end) = rest.find('"') {
                                        let act = rest[..end].to_string();
                                        if !activities.contains(&act) {
                                            activities.push(act);
                                        }
                                    }
                                }
                            }
                            if line.contains("<service") && line.contains("android:name=\"") {
                                if let Some(start) = line.find("android:name=\"") {
                                    let rest = &line[start + 14..];
                                    if let Some(end) = rest.find('"') {
                                        let svc = rest[..end].to_string();
                                        if !services.contains(&svc) {
                                            services.push(svc);
                                        }
                                    }
                                }
                            }
                            if line.contains("<receiver") && line.contains("android:name=\"") {
                                if let Some(start) = line.find("android:name=\"") {
                                    let rest = &line[start + 14..];
                                    if let Some(end) = rest.find('"') {
                                        let rcv = rest[..end].to_string();
                                        if !receivers.contains(&rcv) {
                                            receivers.push(rcv);
                                        }
                                    }
                                }
                            }
                            if line.contains("<provider") && line.contains("android:name=\"") {
                                if let Some(start) = line.find("android:name=\"") {
                                    let rest = &line[start + 14..];
                                    if let Some(end) = rest.find('"') {
                                        let prv = rest[..end].to_string();
                                        if !providers.contains(&prv) {
                                            providers.push(prv);
                                        }
                                    }
                                }
                            }
                            if line.contains("minSdkVersion") {
                                if let Some(start) = line.find("minSdkVersion=\"") {
                                    let rest = &line[start + 15..];
                                    if let Some(end) = rest.find('"') {
                                        min_sdk = rest[..end].to_string();
                                    }
                                }
                            }
                            if line.contains("targetSdkVersion") {
                                if let Some(start) = line.find("targetSdkVersion=\"") {
                                    let rest = &line[start + 18..];
                                    if let Some(end) = rest.find('"') {
                                        target_sdk = rest[..end].to_string();
                                    }
                                }
                            }
                            if line.contains("versionName=\"") {
                                if let Some(start) = line.find("versionName=\"") {
                                    let rest = &line[start + 13..];
                                    if let Some(end) = rest.find('"') {
                                        version_name = rest[..end].to_string();
                                    }
                                }
                            }
                            if line.contains("versionCode=\"") {
                                if let Some(start) = line.find("versionCode=\"") {
                                    let rest = &line[start + 13..];
                                    if let Some(end) = rest.find('"') {
                                        version_code = rest[..end].to_string();
                                    }
                                }
                            }
                        }
                    } else {
                        permissions = Self::extract_permissions_from_binary_xml(bytes);
                        for perm in &permissions {
                            if DANGEROUS_PERMS.iter().any(|dp| perm.contains(dp)) {
                                dangerous_permissions.push(perm.clone());
                            }
                        }
                    }
                }
            }
        }

        let certificates = if config.extract_certificates {
            Self::extract_certificates(apk_path)
        } else {
            Vec::new()
        };

        if package_name.is_empty() {
            package_name = path_to_package_name(apk_path);
        }

        let (is_debuggable, is_allow_backup) = Self::detect_security_flags(&config.apk_path);
        let (file_size, file_md5, file_sha1, file_sha256) = Self::compute_file_info(&config.apk_path);

        let security_score = Self::calculate_security_score(
            is_debuggable,
            is_allow_backup,
            &dangerous_permissions,
            &Vec::new(),
            &Vec::new(),
            &Vec::new(),
            &Vec::new(),
            &certificates,
            &target_sdk,
        );

        let mut security_issues = Vec::new();
        if is_debuggable {
            security_issues.push(SecurityIssue {
                severity: "high".to_string(),
                category: "configuration".to_string(),
                description: "Application is debuggable".to_string(),
                detail: "android:debuggable=true allows debugging of the application, which can expose sensitive data and functionality.".to_string(),
            });
        }
        if is_allow_backup {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "configuration".to_string(),
                description: "Application allows backup".to_string(),
                detail: "android:allowBackup=true allows adb backup to extract application data including private files and databases.".to_string(),
            });
        }
        if dangerous_permissions.len() > 5 {
            security_issues.push(SecurityIssue {
                severity: "medium".to_string(),
                category: "permission".to_string(),
                description: format!("{} dangerous permissions requested", dangerous_permissions.len()),
                detail: format!("Excessive dangerous permissions: {}", dangerous_permissions.join(", ")),
            });
        }
        if target_sdk.parse::<i32>().unwrap_or(0) < 28 {
            security_issues.push(SecurityIssue {
                severity: "low".to_string(),
                category: "configuration".to_string(),
                description: "Low target SDK version".to_string(),
                detail: format!("targetSdkVersion={} is below 28 (Android 9), which may weaken security enforcement.", target_sdk),
            });
        }

        let summary = if permissions.is_empty() && activities.is_empty() {
            format!(
                "APK Analysis (basic) | File: {} | Security Score: {}/100 | Install aapt for detailed analysis",
                Path::new(apk_path).file_name().unwrap_or_default().to_string_lossy(), security_score
            )
        } else {
            format!(
                "APK Analysis | Package: {} | Version: {} | Permissions: {} (Dangerous: {}) | Components: {} | Security Score: {}/100",
                package_name, version_name, permissions.len(), dangerous_permissions.len(),
                activities.len() + services.len() + receivers.len() + providers.len(), security_score
            )
        };

        let deep_analysis = if config.enable_deep_analysis {
            Some(Self::perform_deep_analysis(apk_path, &package_name))
        } else {
            None
        };

        Ok(ApkAnalysisResult {
            success: true,
            package_name,
            version_name,
            version_code,
            min_sdk,
            target_sdk,
            file_size,
            file_md5,
            file_sha1,
            file_sha256,
            is_debuggable,
            is_allow_backup,
            permissions,
            dangerous_permissions,
            activities,
            services,
            receivers,
            providers,
            exported_activities: Vec::new(),
            exported_services: Vec::new(),
            exported_receivers: Vec::new(),
            exported_providers: Vec::new(),
            certificates,
            apis,
            security_issues,
            security_score,
            summary,
            deep_analysis,
        })
    }

    fn perform_deep_analysis(apk_path: &str, package_name: &str) -> DeepAnalysisResult {
        let mut decompiled = false;
        let mut decompiled_path = String::new();
        let mut source_file_count = 0;
        let mut native_libs = Vec::new();
        let mut sensitive_findings = Vec::new();
        let mut api_keys = Vec::new();
        let mut hardcoded_secrets = Vec::new();
        let mut sql_injection_risks = Vec::new();
        let mut crypto_issues = Vec::new();
        let mut webview_issues = Vec::new();
        let mut third_party_sdks = Vec::new();
        let mut privacy_issues = Vec::new();
        let mut network_security = NetworkSecurityAnalysis {
            uses_cleartext_traffic: false,
            certificate_pinning: false,
            trust_manager_issues: Vec::new(),
            hostname_verifier_issues: Vec::new(),
        };

        let temp_dir = std::env::temp_dir().join(format!("apk_analysis_{}", chrono::Utc::now().timestamp()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let jadx_path = match Self::ensure_jadx() {
            Ok(path) => Some(path),
            Err(e) => {
                eprintln!("Warning: jadx not available: {}. Deep analysis will be limited.", e);
                None
            }
        };

        if let Some(ref jadx) = jadx_path {
            if let Ok(output) = std::process::Command::new(jadx)
                .args(["-d", temp_dir.to_str().unwrap_or(""), "--no-res", "--no-debug-info", apk_path])
                .output()
            {
                if output.status.success() || temp_dir.exists() {
                    decompiled = true;
                    decompiled_path = temp_dir.to_string_lossy().to_string();
                    
                    if let Ok(entries) = std::fs::read_dir(&temp_dir) {
                        for entry in entries.flatten() {
                            if let Ok(files) = Self::collect_java_files(&entry.path()) {
                                source_file_count += files.len();
                                for file_path in files {
                                    if let Ok(content) = std::fs::read_to_string(&file_path) {
                                        Self::analyze_java_file(
                                            &file_path,
                                            &content,
                                            &mut sensitive_findings,
                                            &mut api_keys,
                                            &mut hardcoded_secrets,
                                            &mut sql_injection_risks,
                                            &mut crypto_issues,
                                            &mut webview_issues,
                                            &mut third_party_sdks,
                                            &mut network_security,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(mut archive) = zip::ZipArchive::new(std::fs::File::open(apk_path).unwrap()) {
            for i in 0..archive.len() {
                if let Ok(file) = archive.by_index(i) {
                    let name = file.name().to_string();
                    if name.starts_with("lib/") && name.ends_with(".so") {
                        let arch = name.split('/').nth(1).unwrap_or("unknown").to_string();
                        let size = file.size();
                        let symbols = Self::extract_so_symbols(&name, apk_path);
                        native_libs.push(NativeLibrary {
                            name: name.split('/').last().unwrap_or(&name).to_string(),
                            arch,
                            size,
                            symbols,
                        });
                    }
                }
            }
        }

        Self::detect_privacy_issues(
            package_name,
            &third_party_sdks,
            &mut privacy_issues,
        );

        let deep_security_score = Self::calculate_deep_security_score(
            &sensitive_findings,
            &api_keys,
            &sql_injection_risks,
            &crypto_issues,
            &webview_issues,
            &privacy_issues,
            &network_security,
        );

        DeepAnalysisResult {
            decompiled,
            decompiled_path,
            source_file_count,
            native_libs,
            sensitive_findings,
            api_keys,
            hardcoded_secrets,
            sql_injection_risks,
            crypto_issues,
            webview_issues,
            third_party_sdks,
            privacy_issues,
            network_security,
            deep_security_score,
        }
    }

    fn collect_java_files(dir: &Path) -> std::result::Result<Vec<std::path::PathBuf>, std::io::Error> {
        let mut files = Vec::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    files.extend(Self::collect_java_files(&path)?);
                } else if path.extension().map_or(false, |ext| ext == "java") {
                    files.push(path);
                }
            }
        }
        Ok(files)
    }

    fn analyze_java_file(
        file_path: &Path,
        content: &str,
        sensitive_findings: &mut Vec<SensitiveFinding>,
        api_keys: &mut Vec<ApiKeyFinding>,
        hardcoded_secrets: &mut Vec<SecretFinding>,
        sql_injection_risks: &mut Vec<CodeIssue>,
        crypto_issues: &mut Vec<CryptoIssue>,
        webview_issues: &mut Vec<WebViewIssue>,
        third_party_sdks: &mut Vec<SdkInfo>,
        network_security: &mut NetworkSecurityAnalysis,
    ) {
        let file_path_str = file_path.to_string_lossy().to_string();

        let sensitive_patterns = [
            (r#"(?i)SSN\s*[:=]\s*["']?\d{3}-\d{2}-\d{4}["']?"#, "SSN", "high"),
            (r#"(?i)credit.?card\s*[:=]\s*["']?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}["']?"#, "Credit Card", "high"),
            (r#"(?i)email\s*[:=]\s*["'][\w.+-]+@[\w-]+\.[\w.-]+["']"#, "Email Address", "low"),
            (r#"(?i)phone\s*[:=]\s*["']\+?\d{10,15}["']"#, "Phone Number", "medium"),
            (r#"(?i)imei\s*[:=]\s*["']\d{15}["']"#, "IMEI", "high"),
            (r#"(?i)mac.?address\s*[:=]\s*["']([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}["']"#, "MAC Address", "medium"),
            (r#"getDeviceId\(\)"#, "Device ID Access", "high"),
            (r#"getSubscriberId\(\)"#, "IMSI Access", "high"),
            (r#"getSimSerialNumber\(\)"#, "SIM Serial Access", "high"),
            (r#"getLine1Number\(\)"#, "Phone Number Access", "high"),
            (r#"Build\.SERIAL"#, "Build Serial Access", "medium"),
            (r#"Settings\.Secure\.getString.*android_id"#, "Android ID Access", "medium"),
            (r#"WifiInfo\.getMacAddress\(\)"#, "WiFi MAC Access", "medium"),
            (r#"LocationManager"#, "Location Access", "medium"),
        ];

        for (pattern, finding_type, severity) in sensitive_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    sensitive_findings.push(SensitiveFinding {
                        finding_type: finding_type.to_string(),
                        file_path: file_path_str.clone(),
                        line_number: content[..cap.start()].lines().count() + 1,
                        content: Self::mask_sensitive_value(cap.as_str()),
                        severity: severity.to_string(),
                        description: format!("Sensitive data detected: {}", finding_type),
                    });
                }
            }
        }
        
        for (key_type, pattern, severity) in API_KEY_PATTERNS {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    api_keys.push(ApiKeyFinding {
                        key_type: key_type.to_string(),
                        key_name: String::new(),
                        key_value: Self::mask_sensitive_value(cap.as_str()),
                        file_path: file_path_str.clone(),
                        line_number: content[..cap.start()].lines().count() + 1,
                        severity: severity.to_string(),
                    });
                }
            }
        }

        let secret_patterns = [
            (r#"(?i)password\s*=\s*["']([^"']{4,})["']"#, "password"),
            (r#"(?i)secret\s*=\s*["']([^"']{4,})["']"#, "secret"),
            (r#"(?i)token\s*=\s*["']([^"']{8,})["']"#, "token"),
            (r#"(?i)api_key\s*=\s*["']([^"']{8,})["']"#, "api_key"),
            (r#"(?i)private_key\s*=\s*["']([^"']{20,})["']"#, "private_key"),
        ];

        for (pattern, secret_type) in secret_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    hardcoded_secrets.push(SecretFinding {
                        secret_type: secret_type.to_string(),
                        secret_name: String::new(),
                        secret_value: Self::mask_sensitive_value(cap.as_str()),
                        file_path: file_path_str.clone(),
                        line_number: content[..cap.start()].lines().count() + 1,
                    });
                }
            }
        }

        let sql_patterns = [
            (r#"rawQuery\s*\(\s*["']([^"']*\+[^"']*)["']"#, "rawQuery with concatenation"),
            (r#"execSQL\s*\(\s*["']([^"']*\+[^"']*)["']"#, "execSQL with concatenation"),
            (r#"\+\s*["']\s*(SELECT|INSERT|UPDATE|DELETE)"#, "SQL string concatenation"),
            (r#"String\.format\s*\([^)]*SELECT"#, "String.format SQL"),
        ];

        for (pattern, issue_type) in sql_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    sql_injection_risks.push(CodeIssue {
                        issue_type: issue_type.to_string(),
                        file_path: file_path_str.clone(),
                        line_number: content[..cap.start()].lines().count() + 1,
                        code_snippet: cap.as_str().chars().take(100).collect(),
                        severity: "high".to_string(),
                        description: "Potential SQL injection vulnerability".to_string(),
                    });
                }
            }
        }

        let crypto_patterns = [
            (r#"MessageDigest\.getInstance\s*\(\s*["']MD5["']"#, "MD5", "high"),
            (r#"MessageDigest\.getInstance\s*\(\s*["']SHA1["']"#, "SHA1", "medium"),
            (r#"Cipher\.getInstance\s*\(\s*["']DES["']"#, "DES", "high"),
            (r#"Cipher\.getInstance\s*\(\s*["']RC4["']"#, "RC4", "high"),
            (r#"AES/\w+/PKCS5Padding"#, "AES/ECB/PKCS5Padding", "medium"),
            (r#"new\s+Random\s*\(\s*\)"#, "Weak Random", "low"),
            (r#"SecureRandom\.getInstance\s*\(\s*["']SHA1PRNG["']"#, "SHA1PRNG", "low"),
        ];

        for (pattern, algorithm, severity) in crypto_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    crypto_issues.push(CryptoIssue {
                        issue_type: "Weak Crypto".to_string(),
                        file_path: file_path_str.clone(),
                        line_number: content[..cap.start()].lines().count() + 1,
                        algorithm: algorithm.to_string(),
                        severity: severity.to_string(),
                        description: format!("Use of weak or insecure cryptographic algorithm: {}", algorithm),
                    });
                }
            }
        }

        let webview_patterns = [
            (r#"setJavaScriptEnabled\s*\(\s*true"#, "JavaScript enabled", "medium"),
            (r#"loadUrl\s*\(\s*["']javascript:"#, "JavaScript URL", "high"),
            (r#"addJavascriptInterface"#, "JavaScript Interface", "high"),
            (r#"setAllowFileAccess\s*\(\s*true"#, "File access enabled", "medium"),
            (r#"setAllowFileAccessFromFileURLs\s*\(\s*true"#, "File access from URLs", "high"),
            (r#"setAllowUniversalAccessFromFileURLs\s*\(\s*true"#, "Universal file access", "high"),
            (r#"setPluginState\s*\(\s*WebSettings\.PluginState\.ON"#, "Plugins enabled", "medium"),
        ];

        for (pattern, issue_type, severity) in webview_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.find_iter(content) {
                    webview_issues.push(WebViewIssue {
                        file_path: file_path_str.clone(),
                        line_number: content[..cap.start()].lines().count() + 1,
                        issue_type: issue_type.to_string(),
                        severity: severity.to_string(),
                        description: format!("WebView security issue: {}", issue_type),
                    });
                }
            }
        }

        if content.contains("X509TrustManager") && content.contains("checkServerTrusted") {
            if content.contains("return;") || content.contains("{}") {
                network_security.trust_manager_issues.push(file_path_str.clone());
            }
        }

        if content.contains("HostnameVerifier") && content.contains("return true") {
            network_security.hostname_verifier_issues.push(file_path_str.clone());
        }

        if content.contains("usesCleartextTraffic") {
            network_security.uses_cleartext_traffic = true;
        }
        if content.contains("android:usesCleartextTraffic=\"true\"") || content.contains("android:usesCleartextTraffic='true'") {
            network_security.uses_cleartext_traffic = true;
        }
        if content.contains("NetworkSecurityConfig") && content.contains("cleartextTrafficPermitted=\"true\"") {
            network_security.uses_cleartext_traffic = true;
        }

        if content.contains("CertificatePinner") || content.contains("OkHostnameVerifier") {
            network_security.certificate_pinning = true;
        }

        for (sdk_name, package, sdk_type, permissions) in SDK_SIGNATURES {
            if content.contains(package) {
                let mut sdk = SdkInfo {
                    name: sdk_name.to_string(),
                    sdk_type: sdk_type.to_string(),
                    package_name: package.to_string(),
                    version: String::new(),
                    permissions: permissions.iter().map(|s| s.to_string()).collect(),
                    data_collection: Vec::new(),
                };
                
                match *sdk_type {
                    "analytics" => sdk.data_collection.push("Usage statistics".to_string()),
                    "push" => sdk.data_collection.push("Device info".to_string()),
                    "ad" => sdk.data_collection.extend(vec!["Device ID".to_string(), "Location".to_string()]),
                    "social" => sdk.data_collection.push("Social profile".to_string()),
                    _ => {}
                }
                
                if !third_party_sdks.iter().any(|s: &SdkInfo| s.package_name == *package) {
                    third_party_sdks.push(sdk);
                }
            }
        }
    }

    fn mask_sensitive_value(value: &str) -> String {
        if value.len() <= 8 {
            return "*".repeat(value.len());
        }
        format!("{}****{}", &value[..4], &value[value.len()-4..])
    }

    fn extract_so_symbols(lib_name: &str, apk_path: &str) -> Vec<String> {
        let mut symbols = Vec::new();

        let temp_so = std::env::temp_dir().join(format!("so_sym_{}", chrono::Utc::now().timestamp_millis()));

        if let Ok(output) = std::process::Command::new("unzip")
            .args(["-o", "-p", apk_path, lib_name])
            .output()
        {
            if output.status.success() && !output.stdout.is_empty() {
                if let Ok(mut f) = std::fs::File::create(&temp_so) {
                    let _ = f.write_all(&output.stdout);
                }

                if let Ok(nm_output) = std::process::Command::new("nm")
                    .args(["-D", temp_so.to_str().unwrap_or("")])
                    .output()
                {
                    if nm_output.status.success() {
                        for line in String::from_utf8_lossy(&nm_output.stdout).lines() {
                            if let Some(sym) = line.split_whitespace().last() {
                                if !sym.starts_with('_') && sym.len() > 2 {
                                    symbols.push(sym.to_string());
                                }
                            }
                        }
                    }
                }

                if let Ok(readelf_output) = std::process::Command::new("readelf")
                    .args(["-sW", temp_so.to_str().unwrap_or("")])
                    .output()
                {
                    if readelf_output.status.success() && symbols.is_empty() {
                        for line in String::from_utf8_lossy(&readelf_output.stdout).lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 8 {
                                let sym = parts[7];
                                if !sym.starts_with('_') && sym.len() > 2 && !symbols.contains(&sym.to_string()) {
                                    symbols.push(sym.to_string());
                                }
                            }
                        }
                    }
                }

                let _ = std::fs::remove_file(&temp_so);
            }
        }

        symbols.truncate(50);
        symbols
    }

    fn detect_privacy_issues(
        package_name: &str,
        third_party_sdks: &[SdkInfo],
        privacy_issues: &mut Vec<PrivacyIssue>,
    ) {
        let ad_sdks: Vec<_> = third_party_sdks.iter().filter(|s| s.sdk_type == "ad").collect();
        if !ad_sdks.is_empty() {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Third-party Advertising".to_string(),
                severity: "medium".to_string(),
                description: format!("App integrates {} advertising SDK(s): {}", ad_sdks.len(), ad_sdks.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")),
                data_type: "Device ID, Location, Usage data".to_string(),
                recommendation: "Review privacy policy for advertising data collection disclosure".to_string(),
            });
        }

        let analytics_sdks: Vec<_> = third_party_sdks.iter().filter(|s| s.sdk_type == "analytics").collect();
        if analytics_sdks.len() > 2 {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Multiple Analytics SDKs".to_string(),
                severity: "low".to_string(),
                description: format!("App uses {} analytics SDKs: {}", analytics_sdks.len(), analytics_sdks.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")),
                data_type: "Usage statistics, Device info".to_string(),
                recommendation: "Consider consolidating analytics providers".to_string(),
            });
        }

        let push_sdks: Vec<_> = third_party_sdks.iter().filter(|s| s.sdk_type == "push").collect();
        if push_sdks.len() > 1 {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Multiple Push SDKs".to_string(),
                severity: "low".to_string(),
                description: format!("App uses {} push notification SDKs: {}", push_sdks.len(), push_sdks.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")),
                data_type: "Device token, Registration ID".to_string(),
                recommendation: "Multiple push services may impact battery life".to_string(),
            });
        }

        let payment_sdks: Vec<_> = third_party_sdks.iter().filter(|s| s.sdk_type == "payment").collect();
        if !payment_sdks.is_empty() {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Payment SDK Integration".to_string(),
                severity: "medium".to_string(),
                description: format!("App integrates {} payment SDK(s): {}", payment_sdks.len(), payment_sdks.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")),
                data_type: "Payment info, Transaction data".to_string(),
                recommendation: "Ensure payment data is handled securely and PCI-DSS compliant".to_string(),
            });
        }

        let social_sdks: Vec<_> = third_party_sdks.iter().filter(|s| s.sdk_type == "social").collect();
        if !social_sdks.is_empty() {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Social SDK Integration".to_string(),
                severity: "low".to_string(),
                description: format!("App integrates {} social SDK(s): {}", social_sdks.len(), social_sdks.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")),
                data_type: "Social profile, Friend list".to_string(),
                recommendation: "Review social login data sharing practices".to_string(),
            });
        }

        if package_name.contains("com.tencent") || package_name.contains("com.alibaba") || package_name.contains("com.baidu") {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Chinese Ecosystem App".to_string(),
                severity: "info".to_string(),
                description: format!("App appears to be from a Chinese tech ecosystem ({})", package_name),
                data_type: "Varies by SDK".to_string(),
                recommendation: "Review compliance with China's Personal Information Protection Law (PIPL)".to_string(),
            });
        }

        let total_sdks = third_party_sdks.len();
        if total_sdks > 8 {
            privacy_issues.push(PrivacyIssue {
                issue_type: "Excessive Third-party SDKs".to_string(),
                severity: "medium".to_string(),
                description: format!("App integrates {} third-party SDKs, increasing attack surface", total_sdks),
                data_type: "Multiple data types".to_string(),
                recommendation: "Consider reducing third-party dependencies to minimize data exposure".to_string(),
            });
        }
    }

    fn calculate_deep_security_score(
        sensitive_findings: &[SensitiveFinding],
        api_keys: &[ApiKeyFinding],
        sql_injection_risks: &[CodeIssue],
        crypto_issues: &[CryptoIssue],
        webview_issues: &[WebViewIssue],
        privacy_issues: &[PrivacyIssue],
        network_security: &NetworkSecurityAnalysis,
    ) -> i32 {
        let mut score: i32 = 100;

        let critical_keys = api_keys.iter().filter(|k| k.severity == "critical").count();
        let high_keys = api_keys.iter().filter(|k| k.severity == "high").count();
        let medium_keys = api_keys.iter().filter(|k| k.severity == "medium").count();
        score -= (critical_keys * 20) as i32;
        score -= (high_keys * 10) as i32;
        score -= (medium_keys * 5) as i32;

        score -= (sensitive_findings.len() * 5) as i32;

        score -= (sql_injection_risks.len() * 15) as i32;

        let high_crypto = crypto_issues.iter().filter(|c| c.severity == "high").count();
        let medium_crypto = crypto_issues.iter().filter(|c| c.severity == "medium").count();
        score -= (high_crypto * 10) as i32;
        score -= (medium_crypto * 5) as i32;

        let high_webview = webview_issues.iter().filter(|w| w.severity == "high").count();
        let medium_webview = webview_issues.iter().filter(|w| w.severity == "medium").count();
        score -= (high_webview * 10) as i32;
        score -= (medium_webview * 5) as i32;

        if !network_security.trust_manager_issues.is_empty() {
            score -= 20;
        }
        if !network_security.hostname_verifier_issues.is_empty() {
            score -= 15;
        }
        if network_security.uses_cleartext_traffic {
            score -= 10;
        }
        if !network_security.certificate_pinning {
            score -= 5;
        }

        score -= (privacy_issues.len() * 3) as i32;

        score.max(0)
    }

    fn get_tools_dir() -> std::path::PathBuf {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let tools_dir = std::path::PathBuf::from(home).join(".biosphere").join("tools");
        let _ = std::fs::create_dir_all(&tools_dir);
        tools_dir
    }

    fn find_jadx_in_path() -> Option<String> {
        if let Ok(output) = std::process::Command::new("which")
            .arg("jadx")
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() && std::path::Path::new(&path).exists() {
                    return Some(path);
                }
            }
        }

        if let Ok(output) = std::process::Command::new("jadx")
            .arg("--version")
            .output()
        {
            if output.status.success() {
                return Some("jadx".to_string());
            }
        }

        None
    }

    fn find_local_jadx() -> Option<String> {
        let tools_dir = Self::get_tools_dir();
        let jadx_dir = tools_dir.join("jadx");

        if !jadx_dir.exists() {
            return None;
        }

        if let Ok(entries) = std::fs::read_dir(&jadx_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let bin_name = if cfg!(target_os = "windows") {
                        "jadx.bat"
                    } else {
                        "jadx"
                    };
                    let bin_path = path.join("bin").join(bin_name);
                    if bin_path.exists() {
                        if let Some(p) = bin_path.to_str() {
                            return Some(p.to_string());
                        }
                    }

                    let lib_dir = path.join("lib");
                    if lib_dir.exists() {
                        let script_name = if cfg!(target_os = "windows") {
                            "jadx.bat"
                        } else {
                            "jadx"
                        };
                        let script_path = path.join("bin").join(script_name);
                        if script_path.exists() {
                            if let Some(p) = script_path.to_str() {
                                return Some(p.to_string());
                            }
                        }

                        for sub_entry in std::fs::read_dir(&path).unwrap_or_else(|_| std::fs::read_dir(".").unwrap()) {
                            if let Ok(se) = sub_entry {
                                let sp = se.path();
                                if sp.is_dir() {
                                    let bp = sp.join("bin").join(bin_name);
                                    if bp.exists() {
                                        if let Some(p) = bp.to_str() {
                                            return Some(p.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn ensure_jadx() -> Result<String, String> {
        if let Some(path) = Self::find_jadx_in_path() {
            return Ok(path);
        }

        if let Some(path) = Self::find_local_jadx() {
            return Ok(path);
        }

        Self::download_jadx()
    }

    fn download_jadx() -> Result<String, String> {
        let tools_dir = Self::get_tools_dir();
        let jadx_install_dir = tools_dir.join("jadx");
        let _ = std::fs::create_dir_all(&jadx_install_dir);

        let os_suffix = if cfg!(target_os = "macos") {
            "mac"
        } else if cfg!(target_os = "windows") {
            "win"
        } else {
            "linux"
        };

        let download_url = format!(
            "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1-{}.zip",
            os_suffix
        );

        let zip_path = jadx_install_dir.join("jadx-download.zip");

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut response = client.get(&download_url)
            .send()
            .map_err(|e| format!("Failed to download jadx: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Failed to download jadx: HTTP {}", response.status()));
        }

        {
            let mut file = std::fs::File::create(&zip_path)
                .map_err(|e| format!("Failed to create temp file: {}", e))?;
            std::io::copy(&mut response, &mut file)
                .map_err(|e| format!("Failed to write jadx zip: {}", e))?;
        }

        let extract_dir = jadx_install_dir.join("jadx-1.5.1");
        let _ = std::fs::create_dir_all(&extract_dir);

        {
            let file = std::fs::File::open(&zip_path)
                .map_err(|e| format!("Failed to open jadx zip: {}", e))?;
            let mut archive = zip::ZipArchive::new(file)
                .map_err(|e| format!("Failed to read jadx zip: {}", e))?;

            for i in 0..archive.len() {
                let mut file = archive.by_index(i).map_err(|e| format!("Failed to read zip entry: {}", e))?;
                let outpath = match file.enclosed_name() {
                    Some(path) => extract_dir.join(path),
                    None => continue,
                };
                if file.name().ends_with('/') {
                    std::fs::create_dir_all(&outpath).map_err(|e| format!("Failed to create dir: {}", e))?;
                } else {
                    if let Some(p) = outpath.parent() {
                        if !p.exists() {
                            std::fs::create_dir_all(p).map_err(|e| format!("Failed to create parent dir: {}", e))?;
                        }
                    }
                    let mut outfile = std::fs::File::create(&outpath).map_err(|e| format!("Failed to create file: {}", e))?;
                    std::io::copy(&mut file, &mut outfile).map_err(|e| format!("Failed to write file: {}", e))?;
                }
            }
        }

        let _ = std::fs::remove_file(&zip_path);

        let bin_name = if cfg!(target_os = "windows") {
            "jadx.bat"
        } else {
            "jadx"
        };

        let jadx_bin = extract_dir.join("bin").join(bin_name);
        if jadx_bin.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&jadx_bin, std::fs::Permissions::from_mode(0o755));
            }
            return jadx_bin.to_str().map(|s| s.to_string()).ok_or("Failed to get jadx path".to_string());
        }

        for entry in std::fs::read_dir(&extract_dir).unwrap_or_else(|_| std::fs::read_dir(".").unwrap()) {
            if let Ok(e) = entry {
                let p = e.path();
                if p.is_dir() {
                    let bp = p.join("bin").join(bin_name);
                    if bp.exists() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(&bp, std::fs::Permissions::from_mode(0o755));
                        }
                        return bp.to_str().map(|s| s.to_string()).ok_or("Failed to get jadx path".to_string());
                    }
                }
            }
        }

        Err("jadx binary not found after extraction".to_string())
    }

    fn extract_permissions_from_binary_xml(bytes: &[u8]) -> Vec<String> {
        let mut permissions = Vec::new();
        let content = String::from_utf8_lossy(bytes);

        let mut offset = 0;
        while offset < content.len() {
            if let Some(pos) = content[offset..].find("android.permission.") {
                let abs_pos = offset + pos;
                let end = content[abs_pos..]
                    .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
                    .unwrap_or(content[abs_pos..].len().min(60));
                let perm = content[abs_pos..abs_pos + end].to_string();
                if !permissions.contains(&perm) {
                    permissions.push(perm);
                }
                offset = abs_pos + end;
            } else {
                break;
            }
        }

        permissions
    }
}

struct CertParser {
    issuer: String,
    subject: String,
    serial_number: String,
    valid_from: String,
    valid_to: String,
    fingerprint_sha1: String,
    fingerprint_sha256: String,
}

impl CertParser {
    fn new() -> Self {
        Self {
            issuer: String::new(),
            subject: String::new(),
            serial_number: String::new(),
            valid_from: String::new(),
            valid_to: String::new(),
            fingerprint_sha1: String::new(),
            fingerprint_sha256: String::new(),
        }
    }

    fn has_data(&self) -> bool {
        !self.issuer.is_empty() || !self.subject.is_empty()
    }

    fn build(self) -> Option<ApkCertificateInfo> {
        if !self.has_data() {
            return None;
        }
        Some(ApkCertificateInfo {
            issuer: self.issuer,
            subject: self.subject,
            serial_number: self.serial_number,
            valid_from: self.valid_from,
            valid_to: self.valid_to,
            fingerprint_sha1: self.fingerprint_sha1,
            fingerprint_sha256: self.fingerprint_sha256,
        })
    }
}

fn format_fingerprint(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() {
        return String::new();
    }
    cleaned
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some(std::str::from_utf8(chunk).unwrap_or(""))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

fn path_to_package_name(apk_path: &str) -> String {
    Path::new(apk_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

const API_KEY_PATTERNS: &[(&str, &str, &str)] = &[
    ("AWS Access Key", "AKIA[0-9A-Z]{16}", "high"),
    ("AWS Secret Key", "(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]", "high"),
    ("Google API Key", "AIza[0-9A-Za-z\\-_]{35}", "high"),
    ("Google OAuth", "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com", "medium"),
    ("Firebase API Key", "(?i)firebase(.{0,20})?['\"][0-9a-zA-Z\\-_]{20,}['\"]", "medium"),
    ("GitHub Token", "ghp_[0-9a-zA-Z]{36}", "high"),
    ("GitHub OAuth", "gho_[0-9a-zA-Z]{36}", "high"),
    ("Slack Token", "xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}", "high"),
    ("Stripe Key", "sk_live_[0-9a-zA-Z]{24}", "high"),
    ("Stripe Publishable", "pk_live_[0-9a-zA-Z]{24}", "medium"),
    ("Twilio Account SID", "AC[a-f0-9]{32}", "medium"),
    ("Twilio Auth Token", "(?i)twilio(.{0,20})?['\"][a-f0-9]{32}['\"]", "high"),
    ("SendGrid Key", "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}", "high"),
    ("Mailgun Key", "key-[0-9a-zA-Z]{32}", "high"),
    ("PayPal Client ID", "(?i)paypal(.{0,20})?['\"][A-Za-z0-9]{80}['\"]", "high"),
    ("Private Key", "-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("Generic Secret", "(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth)[\"']?\\s*[:=]\\s*[\"'][^\"']{8,}[\"']", "medium"),
];

const SDK_SIGNATURES: &[(&str, &str, &str, &[&str])] = &[
    ("Google Analytics", "com.google.android.gms.analytics", "analytics", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Firebase Analytics", "com.google.firebase.analytics", "analytics", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Umeng Analytics", "com.umeng.analytics", "analytics", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE"]),
    ("Tencent Bugly", "com.tencent.bugly", "analytics", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE"]),
    ("Alipay", "com.alipay.sdk", "payment", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("WeChat Pay", "com.tencent.mm.opensdk", "payment", &["INTERNET"]),
    ("UnionPay", "com.unionpay", "payment", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Google Pay", "com.google.android.gms.pay", "payment", &["INTERNET"]),
    ("JPush", "cn.jpush.android", "push", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE", "VIBRATE"]),
    ("Getui", "com.igexin.sdk", "push", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE", "VIBRATE", "RECEIVE_BOOT_COMPLETED"]),
    ("Xiaomi Push", "com.xiaomi.mipush", "push", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Huawei Push", "com.huawei.hms.push", "push", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Tencent Bugly", "com.tencent.bugly", "crash", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE"]),
    ("Bugsnag", "com.bugsnag.android", "crash", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Crashlytics", "com.crashlytics.android", "crash", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Facebook SDK", "com.facebook", "social", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Weibo SDK", "com.sina.weibo", "social", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("QQ SDK", "com.tencent.connect", "social", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Tencent Ads", "com.qq.e.ads", "ad", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE"]),
    ("Google AdMob", "com.google.android.gms.ads", "ad", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("Bytedance Ads", "com.bytedance.sdk.openadsdk", "ad", &["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE"]),
    ("Unity Ads", "com.unity3d.ads", "ad", &["INTERNET", "ACCESS_NETWORK_STATE"]),
    ("OkHttp", "okhttp3", "network", &[]),
    ("Retrofit", "retrofit2", "network", &[]),
    ("Volley", "com.android.volley", "network", &[]),
    ("Glide", "com.bumptech.glide", "image", &[]),
    ("Picasso", "com.squareup.picasso", "image", &[]),
    ("Fresco", "com.facebook.drawee", "image", &[]),
    ("Gson", "com.google.gson", "json", &[]),
    ("Jackson", "com.fasterxml.jackson", "json", &[]),
    ("FastJson", "com.alibaba.fastjson", "json", &[]),
    ("RxJava", "io.reactivex", "reactive", &[]),
    ("EventBus", "org.greenrobot.eventbus", "event", &[]),
    ("LeakCanary", "leakcanary", "debug", &[]),
];
