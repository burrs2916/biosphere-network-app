use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseEngineerConfig {
    pub file_path: String,
    pub file_type: String,
    pub decompile: bool,
    pub extract_strings: bool,
    pub extract_manifest: bool,
    pub extract_certificates: bool,
    pub extract_resources: bool,
    pub analyze_smali: bool,
    pub find_hardcoded_secrets: bool,
    pub output_dir: Option<String>,
    pub timeout: u64,
    pub use_ghidra: bool,
    pub use_radare2: bool,
    pub deep_analysis: bool,
    pub analyze_control_flow: bool,
    pub analyze_vulnerabilities: bool,
    pub binary_diff: Option<String>,
}

impl Default for ReverseEngineerConfig {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            file_type: "auto".to_string(),
            decompile: true,
            extract_strings: true,
            extract_manifest: true,
            extract_certificates: true,
            extract_resources: true,
            analyze_smali: true,
            find_hardcoded_secrets: true,
            output_dir: None,
            timeout: 120,
            use_ghidra: false,
            use_radare2: false,
            deep_analysis: false,
            analyze_control_flow: false,
            analyze_vulnerabilities: false,
            binary_diff: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledClass {
    pub class_name: String,
    pub package: String,
    pub source_file: Option<String>,
    pub methods: Vec<DecompiledMethod>,
    pub fields: Vec<String>,
    pub interfaces: Vec<String>,
    pub superclass: Option<String>,
    pub is_abstract: bool,
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompiledMethod {
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<String>,
    pub is_static: bool,
    pub is_public: bool,
    pub is_native: bool,
    pub is_abstract: bool,
    pub modifiers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestInfo {
    pub package_name: String,
    pub version_name: String,
    pub version_code: String,
    pub min_sdk: String,
    pub target_sdk: String,
    pub permissions: Vec<String>,
    pub activities: Vec<String>,
    pub services: Vec<String>,
    pub receivers: Vec<String>,
    pub providers: Vec<String>,
    pub intent_filters: Vec<IntentFilter>,
    pub exported_components: Vec<String>,
    pub deep_links: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    pub component: String,
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseCertificateInfo {
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    pub signature_algorithm: String,
    pub is_debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardcodedSecret {
    pub type_: String,
    pub value: String,
    pub file: String,
    pub line: Option<u32>,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmaliAnalysis {
    pub total_classes: usize,
    pub total_methods: usize,
    pub native_methods: usize,
    pub crypto_usage: Vec<String>,
    pub network_calls: Vec<String>,
    pub file_io_calls: Vec<String>,
    pub reflection_usage: Vec<String>,
    pub dynamic_code_loading: Vec<String>,
    pub root_detection: Vec<String>,
    pub anti_debug: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub total_resources: usize,
    pub layouts: usize,
    pub drawables: usize,
    pub strings_count: usize,
    pub interesting_strings: Vec<String>,
    pub urls: Vec<String>,
    pub file_paths: Vec<String>,
    pub api_endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraAnalysis {
    pub decompiled_functions: Vec<GhidraFunction>,
    pub call_graph: Vec<CallEdge>,
    pub cross_references: Vec<CrossReference>,
    pub detected_vulnerabilities: Vec<BinaryVulnerability>,
    pub function_count: usize,
    pub data_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhidraFunction {
    pub name: String,
    pub address: String,
    pub signature: String,
    pub is_library: bool,
    pub is_thunk: bool,
    pub calling_convention: Option<String>,
    pub stack_frame_size: Option<u64>,
    pub decompiled_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub from_function: String,
    pub to_function: String,
    pub call_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReference {
    pub from_address: String,
    pub to_address: String,
    pub reference_type: String,
    pub function: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryVulnerability {
    pub vuln_type: String,
    pub function: String,
    pub address: String,
    pub severity: String,
    pub description: String,
    pub cwe_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Radare2Analysis {
    pub sections: Vec<BinarySection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub entry_points: Vec<String>,
    pub strings_analysis: Vec<R2StringInfo>,
    pub functions: Vec<R2Function>,
    pub protections: BinaryProtections,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySection {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub permissions: String,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2StringInfo {
    pub string: String,
    pub address: String,
    pub section: Option<String>,
    pub references: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Function {
    pub name: String,
    pub address: String,
    pub size: u64,
    pub complexity: Option<u32>,
    pub num_locals: Option<u32>,
    pub num_args: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryProtections {
    pub nx_enabled: bool,
    pub stack_canary: bool,
    pub pie_enabled: bool,
    pub relro: String,
    pub fortify_source: bool,
    pub aslr: bool,
    pub stripped: bool,
    pub packed: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiffResult {
    pub file_a: String,
    pub file_b: String,
    pub added_functions: Vec<String>,
    pub removed_functions: Vec<String>,
    pub modified_functions: Vec<String>,
    pub added_strings: Vec<String>,
    pub removed_strings: Vec<String>,
    pub patch_analysis: Vec<PatchInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    pub function: String,
    pub address: String,
    pub change_type: String,
    pub description: String,
    pub security_impact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseEngineerResult {
    pub success: bool,
    pub file_path: String,
    pub file_type: String,
    pub file_size: u64,
    pub manifest: Option<ManifestInfo>,
    pub certificates: Vec<ReverseCertificateInfo>,
    pub decompiled_classes: Vec<DecompiledClass>,
    pub smali_analysis: Option<SmaliAnalysis>,
    pub resources: Option<ResourceInfo>,
    pub hardcoded_secrets: Vec<HardcodedSecret>,
    pub strings: Vec<String>,
    pub ghidra_analysis: Option<GhidraAnalysis>,
    pub radare2_analysis: Option<Radare2Analysis>,
    pub binary_diff: Option<BinaryDiffResult>,
    pub security_findings: Vec<ReverseSecurityFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseSecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub affected_component: Option<String>,
}

pub struct ReverseEngineerTool;

impl ReverseEngineerTool {
    pub async fn analyze(config: &ReverseEngineerConfig) -> std::result::Result<ReverseEngineerResult, String> {
        if config.file_path.is_empty() {
            return Err("请提供文件路径".to_string());
        }

        let file_path = config.file_path.trim().to_string();
        let file_type = Self::detect_file_type(&file_path, &config.file_type);

        let file_size = std::fs::metadata(&file_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let mut result = ReverseEngineerResult {
            success: true,
            file_path: file_path.clone(),
            file_type: file_type.clone(),
            file_size,
            manifest: None,
            certificates: Vec::new(),
            decompiled_classes: Vec::new(),
            smali_analysis: None,
            resources: None,
            hardcoded_secrets: Vec::new(),
            strings: Vec::new(),
            ghidra_analysis: None,
            radare2_analysis: None,
            binary_diff: None,
            security_findings: Vec::new(),
            summary: String::new(),
        };

        if config.extract_strings {
            result.strings = Self::extract_strings(&file_path, &file_type);
        }

        if config.extract_manifest && (file_type == "apk" || file_type == "android") {
            result.manifest = Some(Self::extract_manifest(&file_path));
        }

        if config.extract_certificates {
            result.certificates = Self::extract_certificates(&file_path, &file_type);
        }

        if config.decompile {
            result.decompiled_classes = Self::decompile(&file_path, &file_type);
        }

        if config.analyze_smali && (file_type == "apk" || file_type == "android") {
            result.smali_analysis = Some(Self::analyze_smali(&result.strings, &result.decompiled_classes));
        }

        if config.extract_resources {
            result.resources = Some(Self::extract_resources(&result.strings));
        }

        if config.find_hardcoded_secrets {
            result.hardcoded_secrets = Self::find_secrets(&result.strings);
        }

        result.security_findings = Self::analyze_security(&result);
        result.summary = Self::build_summary(&result);

        Ok(result)
    }

    fn detect_file_type(path: &str, config_type: &str) -> String {
        if config_type != "auto" {
            return config_type.to_string();
        }

        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "apk" => "apk".to_string(),
            "dex" => "dex".to_string(),
            "jar" => "jar".to_string(),
            "class" => "class".to_string(),
            "so" => "native".to_string(),
            "ipa" => "ipa".to_string(),
            "exe" | "dll" => "pe".to_string(),
            "elf" => "elf".to_string(),
            _ => {
                if let Ok(bytes) = std::fs::read(path) {
                    if bytes.len() >= 4 {
                        if &bytes[0..2] == b"PK" { return "apk".to_string(); }
                        if &bytes[0..4] == b"\x7fELF" { return "elf".to_string(); }
                        if &bytes[0..2] == b"MZ" { return "pe".to_string(); }
                        if &bytes[0..8] == b"dex\n035\x00" { return "dex".to_string(); }
                    }
                }
                "unknown".to_string()
            }
        }
    }

    fn extract_strings(path: &str, _file_type: &str) -> Vec<String> {
        let mut strings = Vec::new();

        if let Ok(output) = std::process::Command::new("strings")
            .args(["-n", "6", path])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines().take(5000) {
                let s = line.trim().to_string();
                if !s.is_empty() && s.len() >= 6 {
                    strings.push(s);
                }
            }
        }

        strings
    }

    fn extract_manifest(path: &str) -> ManifestInfo {
        let mut manifest = ManifestInfo {
            package_name: String::new(),
            version_name: String::new(),
            version_code: String::new(),
            min_sdk: String::new(),
            target_sdk: String::new(),
            permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
            intent_filters: Vec::new(),
            exported_components: Vec::new(),
            deep_links: Vec::new(),
        };

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["dump", "badging", path])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let line = line.trim();
                if line.starts_with("package:") {
                    for part in line.split_whitespace() {
                        if part.starts_with("name='") {
                            manifest.package_name = part.trim_start_matches("name='").trim_end_matches("'").to_string();
                        } else if part.starts_with("versionName='") {
                            manifest.version_name = part.trim_start_matches("versionName='").trim_end_matches("'").to_string();
                        } else if part.starts_with("versionCode='") {
                            manifest.version_code = part.trim_start_matches("versionCode='").trim_end_matches("'").to_string();
                        }
                    }
                }
                if line.starts_with("sdkVersion:'") {
                    manifest.min_sdk = line.trim_start_matches("sdkVersion:'").trim_end_matches("'").to_string();
                }
                if line.starts_with("targetSdkVersion:'") {
                    manifest.target_sdk = line.trim_start_matches("targetSdkVersion:'").trim_end_matches("'").to_string();
                }
            }
        }

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["dump", "permissions", path])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            for line in out.lines() {
                let line = line.trim();
                if line.starts_with("uses-permission:") {
                    if let Some(perm) = line.split("name='").nth(1) {
                        manifest.permissions.push(perm.trim_end_matches("'").to_string());
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("aapt")
            .args(["dump", "xmltree", path, "AndroidManifest.xml"])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            let mut current_component_type: Option<String> = None;
            let mut current_component_name = String::new();
            let mut is_exported = false;

            for line in out.lines() {
                let line = line.trim();
                if line.contains("E: activity") || line.contains("E: activity-alias") {
                    current_component_type = Some("activity".to_string());
                    current_component_name = String::new();
                    is_exported = false;
                } else if line.contains("E: service") {
                    current_component_type = Some("service".to_string());
                    current_component_name = String::new();
                    is_exported = false;
                } else if line.contains("E: receiver") {
                    current_component_type = Some("receiver".to_string());
                    current_component_name = String::new();
                    is_exported = false;
                } else if line.contains("E: provider") {
                    current_component_type = Some("provider".to_string());
                    current_component_name = String::new();
                    is_exported = false;
                } else if let Some(ref comp_type) = current_component_type {
                    if line.contains("A: android:name") {
                        if let Some(name) = line.split('"').nth(1) {
                            current_component_name = name.to_string();
                        }
                    } else if line.contains("A: android:exported") {
                        if line.contains("=0xffffffff") || line.contains("=0x1") || line.contains("=(type 0x12)0xffffffff") {
                            is_exported = true;
                        }
                    } else if line.starts_with("E:") && !line.contains("intent-filter") && !line.contains("meta-data") {
                        if !current_component_name.is_empty() {
                            match comp_type.as_str() {
                                "activity" => manifest.activities.push(current_component_name.clone()),
                                "service" => manifest.services.push(current_component_name.clone()),
                                "receiver" => manifest.receivers.push(current_component_name.clone()),
                                "provider" => manifest.providers.push(current_component_name.clone()),
                                _ => {}
                            }
                            if is_exported {
                                manifest.exported_components.push(current_component_name.clone());
                            }
                        }
                        current_component_type = None;
                        current_component_name = String::new();
                        is_exported = false;
                    }
                }

                if line.contains("E: data") && line.contains("android:scheme") {
                    if let Some(scheme) = line.split('"').nth(1) {
                        if !scheme.is_empty() {
                            let link = format!("{}://", scheme);
                            if !manifest.deep_links.contains(&link) {
                                manifest.deep_links.push(link);
                            }
                        }
                    }
                }
            }

            if let Some(ref comp_type) = current_component_type {
                if !current_component_name.is_empty() {
                    match comp_type.as_str() {
                        "activity" => manifest.activities.push(current_component_name.clone()),
                        "service" => manifest.services.push(current_component_name.clone()),
                        "receiver" => manifest.receivers.push(current_component_name.clone()),
                        "provider" => manifest.providers.push(current_component_name.clone()),
                        _ => {}
                    }
                    if is_exported {
                        manifest.exported_components.push(current_component_name.clone());
                    }
                }
            }
        }

        manifest
    }

    fn extract_certificates(path: &str, _file_type: &str) -> Vec<ReverseCertificateInfo> {
        let mut certs = Vec::new();

        if let Ok(output) = std::process::Command::new("keytool")
            .args(["-printcert", "-jarfile", path])
            .output()
        {
            let out = String::from_utf8_lossy(&output.stdout);
            let mut current_cert = ReverseCertificateInfo {
                issuer: String::new(),
                subject: String::new(),
                serial_number: String::new(),
                valid_from: String::new(),
                valid_to: String::new(),
                fingerprint_sha1: String::new(),
                fingerprint_sha256: String::new(),
                signature_algorithm: String::new(),
                is_debug: false,
            };

            for line in out.lines() {
                let line = line.trim();
                if line.starts_with("Issuer:") {
                    current_cert.issuer = line.trim_start_matches("Issuer:").trim().to_string();
                } else if line.starts_with("Subject:") {
                    current_cert.subject = line.trim_start_matches("Subject:").trim().to_string();
                } else if line.starts_with("Serial number:") {
                    current_cert.serial_number = line.trim_start_matches("Serial number:").trim().to_string();
                } else if line.starts_with("Valid from:") {
                    current_cert.valid_from = line.trim_start_matches("Valid from:").trim().to_string();
                } else if line.contains("SHA1:") {
                    current_cert.fingerprint_sha1 = line.split("SHA1:").nth(1).unwrap_or("").trim().to_string();
                } else if line.contains("SHA256:") {
                    current_cert.fingerprint_sha256 = line.split("SHA256:").nth(1).unwrap_or("").trim().to_string();
                } else if line.starts_with("Signature algorithm name:") {
                    current_cert.signature_algorithm = line.trim_start_matches("Signature algorithm name:").trim().to_string();
                }
            }

            current_cert.is_debug = current_cert.issuer.contains("CN=Android Debug")
                || current_cert.subject.contains("CN=Android Debug");

            if !current_cert.issuer.is_empty() || !current_cert.subject.is_empty() {
                certs.push(current_cert);
            }
        }

        certs
    }

    fn decompile(path: &str, file_type: &str) -> Vec<DecompiledClass> {
        let mut classes = Vec::new();

        if file_type == "apk" || file_type == "dex" || file_type == "android" {
            if let Ok(output) = std::process::Command::new("dexdump")
                .args(["-l", "plain", path])
                .output()
            {
                let out = String::from_utf8_lossy(&output.stdout);
                let mut current_class: Option<DecompiledClass> = None;
                let mut in_method_section = false;

                for line in out.lines() {
                    let line = line.trim();
                    if line.starts_with("Class descriptor:") {
                        if let Some(cls) = current_class.take() {
                            classes.push(cls);
                        }
                        current_class = Some(DecompiledClass {
                            class_name: line.split("'").nth(1).unwrap_or("").to_string(),
                            package: String::new(),
                            source_file: None,
                            methods: Vec::new(),
                            fields: Vec::new(),
                            interfaces: Vec::new(),
                            superclass: None,
                            is_abstract: false,
                            is_public: false,
                        });
                        in_method_section = false;
                    } else if let Some(ref mut cls) = current_class {
                        if line.starts_with("Super descriptor:") {
                            if let Some(sc) = line.split("'").nth(1) {
                                cls.superclass = Some(sc.to_string());
                            }
                        } else if line.contains("access_flags:") {
                            if line.contains("0x1") && !line.contains("0x400") {
                                cls.is_public = true;
                            }
                            if line.contains("0x400") {
                                cls.is_abstract = true;
                            }
                        } else if line.starts_with("Direct methods") || line.starts_with("Virtual methods") {
                            in_method_section = true;
                        } else if in_method_section && line.starts_with("name:") {
                            let method_name = line.trim_start_matches("name:")
                                .trim()
                                .trim_start_matches('\'')
                                .trim_end_matches('\'')
                                .to_string();
                            if !method_name.is_empty() {
                                cls.methods.push(DecompiledMethod {
                                    name: method_name,
                                    return_type: String::new(),
                                    parameters: Vec::new(),
                                    is_static: false,
                                    is_public: false,
                                    is_native: false,
                                    is_abstract: false,
                                    modifiers: Vec::new(),
                                });
                            }
                        } else if line.starts_with("source_file:") {
                            cls.source_file = line.trim_start_matches("source_file:")
                                .trim()
                                .trim_start_matches('\'')
                                .trim_end_matches('\'')
                                .to_string()
                                .into();
                        }
                    }
                }

                if let Some(cls) = current_class.take() {
                    classes.push(cls);
                }
            }
        }

        if file_type == "pe" || file_type == "elf" || file_type == "native" {
            if let Ok(output) = std::process::Command::new("nm")
                .args(["-C", path])
                .output()
            {
                let out = String::from_utf8_lossy(&output.stdout);
                let mut current_class_name = String::new();
                let mut current_methods: Vec<DecompiledMethod> = Vec::new();

                for line in out.lines() {
                    let line = line.trim();
                    if line.is_empty() { continue; }

                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    if parts.len() >= 3 {
                        let symbol = parts.last().unwrap().to_string();
                        if symbol.contains("::") {
                            let mut sym_parts = symbol.split("::");
                            if let Some(cls_name) = sym_parts.next() {
                                if cls_name != current_class_name {
                                    if !current_class_name.is_empty() && !current_methods.is_empty() {
                                        classes.push(DecompiledClass {
                                            class_name: current_class_name.clone(),
                                            package: String::new(),
                                            source_file: None,
                                            methods: current_methods.clone(),
                                            fields: Vec::new(),
                                            interfaces: Vec::new(),
                                            superclass: None,
                                            is_abstract: false,
                                            is_public: true,
                                        });
                                    }
                                    current_class_name = cls_name.to_string();
                                    current_methods.clear();
                                }
                                if let Some(method_name) = sym_parts.next() {
                                    let clean_name = method_name.split('(').next().unwrap_or(method_name).to_string();
                                    current_methods.push(DecompiledMethod {
                                        name: clean_name,
                                        return_type: String::new(),
                                        parameters: Vec::new(),
                                        is_static: line.contains(" T ") || line.contains(" t "),
                                        is_public: line.contains(" T ") || line.contains(" W "),
                                        is_native: false,
                                        is_abstract: false,
                                        modifiers: Vec::new(),
                                    });
                                }
                            }
                        }
                    }
                }

                if !current_class_name.is_empty() && !current_methods.is_empty() {
                    classes.push(DecompiledClass {
                        class_name: current_class_name,
                        package: String::new(),
                        source_file: None,
                        methods: current_methods,
                        fields: Vec::new(),
                        interfaces: Vec::new(),
                        superclass: None,
                        is_abstract: false,
                        is_public: true,
                    });
                }
            }
        }

        if classes.len() > 200 {
            classes.truncate(200);
        }

        classes
    }

    fn analyze_smali(strings: &[String], classes: &[DecompiledClass]) -> SmaliAnalysis {
        let mut analysis = SmaliAnalysis {
            total_classes: classes.len(),
            total_methods: classes.iter().map(|c| c.methods.len()).sum(),
            native_methods: classes.iter().flat_map(|c| c.methods.iter()).filter(|m| m.is_native).count(),
            crypto_usage: Vec::new(),
            network_calls: Vec::new(),
            file_io_calls: Vec::new(),
            reflection_usage: Vec::new(),
            dynamic_code_loading: Vec::new(),
            root_detection: Vec::new(),
            anti_debug: Vec::new(),
        };

        let crypto_patterns = ["Cipher", "MessageDigest", "SecretKey", "KeyGenerator", "Mac", "Signature", "AES", "RSA", "DES"];
        let network_patterns = ["HttpURLConnection", "OkHttpClient", "Retrofit", "Volley", "URL", "Socket", "HttpRequest"];
        let file_patterns = ["FileInputStream", "FileOutputStream", "SharedPreferences", "SQLiteDatabase", "ContentProvider"];
        let reflection_patterns = ["Class.forName", "getMethod", "invoke", "getDeclaredField", "setAccessible"];
        let dynamic_patterns = ["DexClassLoader", "PathClassLoader", "loadClass", "loadDex"];
        let root_patterns = ["su", "Superuser", "Magisk", "RootBeer", "isRooted", "/system/app/Superuser.apk"];
        let anti_debug_patterns = ["android.os.Debug", "isDebuggerConnected", "TracerPid", "android.os.Debug.waitingForDebugger"];

        for s in strings {
            for pattern in &crypto_patterns {
                if s.contains(pattern) && !analysis.crypto_usage.contains(&pattern.to_string()) {
                    analysis.crypto_usage.push(pattern.to_string());
                }
            }
            for pattern in &network_patterns {
                if s.contains(pattern) && !analysis.network_calls.contains(&pattern.to_string()) {
                    analysis.network_calls.push(pattern.to_string());
                }
            }
            for pattern in &file_patterns {
                if s.contains(pattern) && !analysis.file_io_calls.contains(&pattern.to_string()) {
                    analysis.file_io_calls.push(pattern.to_string());
                }
            }
            for pattern in &reflection_patterns {
                if s.contains(pattern) && !analysis.reflection_usage.contains(&pattern.to_string()) {
                    analysis.reflection_usage.push(pattern.to_string());
                }
            }
            for pattern in &dynamic_patterns {
                if s.contains(pattern) && !analysis.dynamic_code_loading.contains(&pattern.to_string()) {
                    analysis.dynamic_code_loading.push(pattern.to_string());
                }
            }
            for pattern in &root_patterns {
                if s.contains(pattern) && !analysis.root_detection.contains(&pattern.to_string()) {
                    analysis.root_detection.push(pattern.to_string());
                }
            }
            for pattern in &anti_debug_patterns {
                if s.contains(pattern) && !analysis.anti_debug.contains(&pattern.to_string()) {
                    analysis.anti_debug.push(pattern.to_string());
                }
            }
        }

        analysis
    }

    fn extract_resources(strings: &[String]) -> ResourceInfo {
        let mut resources = ResourceInfo {
            total_resources: strings.len(),
            layouts: 0,
            drawables: 0,
            strings_count: 0,
            interesting_strings: Vec::new(),
            urls: Vec::new(),
            file_paths: Vec::new(),
            api_endpoints: Vec::new(),
        };

        for s in strings {
            if s.starts_with("http://") || s.starts_with("https://") {
                resources.urls.push(s.clone());
                if s.contains("/api/") || s.contains("/v1/") || s.contains("/v2/") {
                    resources.api_endpoints.push(s.clone());
                }
            } else if s.starts_with("/") && s.len() > 3 {
                resources.file_paths.push(s.clone());
            } else if s.contains("res/layout") {
                resources.layouts += 1;
            } else if s.contains("res/drawable") || s.contains("res/mipmap") {
                resources.drawables += 1;
            }
        }

        let interesting_patterns = ["password", "secret", "token", "api_key", "private_key", "credential", "auth"];
        for s in strings {
            let lower = s.to_lowercase();
            for pattern in &interesting_patterns {
                if lower.contains(pattern) && !resources.interesting_strings.contains(s) {
                    resources.interesting_strings.push(s.clone());
                    if resources.interesting_strings.len() >= 50 {
                        break;
                    }
                }
            }
        }

        resources.strings_count = strings.len();
        resources
    }

    fn find_secrets(strings: &[String]) -> Vec<HardcodedSecret> {
        let mut secrets = Vec::new();

        let patterns: [(&str, &str, &str); 8] = [
            (r"(?i)api[_-]?key\s*[=:]\s*[a-zA-Z0-9_-]{20,}", "API Key", "high"),
            (r"(?i)secret[_-]?key\s*[=:]\s*[a-zA-Z0-9_-]{20,}", "Secret Key", "high"),
            (r"(?i)password\s*[=:]\s*\S{6,}", "Password", "high"),
            (r"(?i)token\s*[=:]\s*[a-zA-Z0-9._-]{20,}", "Token", "medium"),
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "high"),
            (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "high"),
            (r"[0-9a-f]{32}", "Possible MD5 Hash", "low"),
            (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "JWT Token", "medium"),
        ];

        for s in strings {
            for (pattern, type_, severity) in &patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if re.is_match(s) {
                        secrets.push(HardcodedSecret {
                            type_: type_.to_string(),
                            value: if s.len() > 100 { format!("{}...", &s[..100]) } else { s.clone() },
                            file: "strings".to_string(),
                            line: None,
                            severity: severity.to_string(),
                            description: format!("检测到可能的硬编码{}", type_),
                        });
                        break;
                    }
                }
            }
        }

        if secrets.len() > 100 {
            secrets.truncate(100);
        }

        secrets
    }

    fn analyze_security(result: &ReverseEngineerResult) -> Vec<ReverseSecurityFinding> {
        let mut findings = Vec::new();

        if let Some(ref manifest) = result.manifest {
            if !manifest.exported_components.is_empty() {
                findings.push(ReverseSecurityFinding {
                    severity: "high".to_string(),
                    category: "组件暴露".to_string(),
                    description: format!("发现 {} 个导出组件，可能被恶意应用利用", manifest.exported_components.len()),
                    recommendation: "除非必要，否则不要导出组件；如需导出，添加权限保护".to_string(),
                    affected_component: None,
                });
            }

            if !manifest.deep_links.is_empty() {
                findings.push(ReverseSecurityFinding {
                    severity: "medium".to_string(),
                    category: "深度链接".to_string(),
                    description: format!("发现 {} 个深度链接，需验证输入", manifest.deep_links.len()),
                    recommendation: "验证深度链接的输入参数，防止注入攻击".to_string(),
                    affected_component: None,
                });
            }

            let dangerous_perms: Vec<&str> = vec![
                "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                "android.permission.READ_SMS", "android.permission.SEND_SMS",
                "android.permission.READ_CALL_LOG", "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
            ];
            let found_dangerous: Vec<&str> = manifest.permissions.iter()
                .filter(|p| dangerous_perms.contains(&p.as_str()))
                .map(|p| p.as_str())
                .collect();
            if !found_dangerous.is_empty() {
                findings.push(ReverseSecurityFinding {
                    severity: "medium".to_string(),
                    category: "危险权限".to_string(),
                    description: format!("应用请求了 {} 个危险权限: {}", found_dangerous.len(), found_dangerous.join(", ")),
                    recommendation: "审查是否真正需要这些权限，遵循最小权限原则".to_string(),
                    affected_component: None,
                });
            }

            if manifest.target_sdk.is_empty() || manifest.target_sdk.as_str() < "28" {
                findings.push(ReverseSecurityFinding {
                    severity: "medium".to_string(),
                    category: "SDK版本".to_string(),
                    description: format!("目标SDK版本较低 ({})，可能缺少安全限制", manifest.target_sdk),
                    recommendation: "将targetSdkVersion升级到至少28以获得更好的安全保护".to_string(),
                    affected_component: None,
                });
            }
        }

        for cert in &result.certificates {
            if cert.is_debug {
                findings.push(ReverseSecurityFinding {
                    severity: "high".to_string(),
                    category: "调试签名".to_string(),
                    description: "应用使用调试签名证书，不应在生产环境使用".to_string(),
                    recommendation: "使用正式发布签名证书重新签名应用".to_string(),
                    affected_component: Some("签名证书".to_string()),
                });
            }
        }

        if !result.hardcoded_secrets.is_empty() {
            let high_secrets = result.hardcoded_secrets.iter().filter(|s| s.severity == "high").count();
            findings.push(ReverseSecurityFinding {
                severity: if high_secrets > 0 { "high" } else { "medium" }.to_string(),
                category: "硬编码密钥".to_string(),
                description: format!("发现 {} 个硬编码密钥/凭据", result.hardcoded_secrets.len()),
                recommendation: "将敏感信息移至服务端或使用安全的密钥存储方案".to_string(),
                affected_component: None,
            });
        }

        if let Some(ref smali) = result.smali_analysis {
            if !smali.dynamic_code_loading.is_empty() {
                findings.push(ReverseSecurityFinding {
                    severity: "high".to_string(),
                    category: "动态代码加载".to_string(),
                    description: format!("检测到动态代码加载: {}", smali.dynamic_code_loading.join(", ")),
                    recommendation: "审查动态加载的代码来源，确保只加载可信代码".to_string(),
                    affected_component: None,
                });
            }

            if smali.root_detection.is_empty() && smali.anti_debug.is_empty() {
                findings.push(ReverseSecurityFinding {
                    severity: "low".to_string(),
                    category: "防护缺失".to_string(),
                    description: "未检测到Root检测或反调试保护".to_string(),
                    recommendation: "添加Root检测和反调试保护以提高应用安全性".to_string(),
                    affected_component: None,
                });
            }

            if !smali.reflection_usage.is_empty() {
                findings.push(ReverseSecurityFinding {
                    severity: "low".to_string(),
                    category: "反射使用".to_string(),
                    description: format!("检测到反射调用: {}", smali.reflection_usage.join(", ")),
                    recommendation: "审查反射调用的目标，确保不被恶意利用".to_string(),
                    affected_component: None,
                });
            }
        }

        findings
    }

    fn build_summary(result: &ReverseEngineerResult) -> String {
        let mut parts = Vec::new();

        parts.push(format!("文件: {} ({}, {})", 
            std::path::Path::new(&result.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&result.file_path),
            result.file_type,
            format_size(result.file_size)
        ));

        if let Some(ref manifest) = result.manifest {
            parts.push(format!("包名: {} v{}", manifest.package_name, manifest.version_name));
            parts.push(format!("权限: {}个, 组件: {}个", manifest.permissions.len(), 
                manifest.activities.len() + manifest.services.len() + manifest.receivers.len() + manifest.providers.len()));
        }

        parts.push(format!("类: {}个, 字符串: {}个", result.decompiled_classes.len(), result.strings.len()));

        if !result.hardcoded_secrets.is_empty() {
            parts.push(format!("硬编码密钥: {}个", result.hardcoded_secrets.len()));
        }

        if !result.security_findings.is_empty() {
            let high = result.security_findings.iter().filter(|f| f.severity == "high").count();
            let medium = result.security_findings.iter().filter(|f| f.severity == "medium").count();
            parts.push(format!("安全问题: {}个高危, {}个中危", high, medium));
        }

        parts.join(" | ")
    }

    pub fn run_ghidra_analysis(file_path: &str) -> std::result::Result<GhidraAnalysis, String> {
        let analyze_headless = which("analyzeHeadless");
        if analyze_headless.is_none() {
            return Err("Ghidra analyzeHeadless not found in PATH".to_string());
        }

        let project_dir = std::env::temp_dir().join("ghidra_project");
        let _ = std::fs::create_dir_all(&project_dir);

        let output = std::process::Command::new("analyzeHeadless")
            .args([
                project_dir.to_str().unwrap_or("/tmp/ghidra_project"),
                "BiosPhereProject",
                "-import", file_path,
                "-postScript", "DecompileToStdout.java",
                "-deleteProject",
            ])
            .output()
            .map_err(|e| format!("Failed to run Ghidra: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let _stderr = String::from_utf8_lossy(&output.stderr);

        let mut functions = Vec::new();
        let mut call_edges = Vec::new();
        let xrefs = Vec::new();
        let mut vulns = Vec::new();

        if let Ok(re) = regex::Regex::new(r"Function: ([^\s]+) at ([0-9a-fx]+)") {
            for cap in re.captures_iter(&stdout) {
                functions.push(GhidraFunction {
                    name: cap[1].to_string(),
                    address: cap[2].to_string(),
                    signature: cap[1].to_string(),
                    is_library: cap[1].contains("_") || cap[1].starts_with("FUN_"),
                    is_thunk: cap[1].starts_with("thunk_"),
                    calling_convention: None,
                    stack_frame_size: None,
                    decompiled_code: None,
                });
            }
        }

        if let Ok(re) = regex::Regex::new(r"Call: ([^\s]+) -> ([^\s]+)") {
            for cap in re.captures_iter(&stdout) {
                call_edges.push(CallEdge {
                    from_function: cap[1].to_string(),
                    to_function: cap[2].to_string(),
                    call_type: "direct".to_string(),
                });
            }
        }

        let dangerous_funcs = ["strcpy", "strcat", "sprintf", "gets", "scanf", "system", "exec", "memcpy"];
        for func in &functions {
            for dangerous in &dangerous_funcs {
                if func.name.contains(dangerous) {
                    let cwe = match *dangerous {
                        "strcpy" | "strcat" => Some("CWE-120".to_string()),
                        "sprintf" => Some("CWE-134".to_string()),
                        "gets" => Some("CWE-120".to_string()),
                        "system" | "exec" => Some("CWE-78".to_string()),
                        _ => None,
                    };
                    vulns.push(BinaryVulnerability {
                        vuln_type: "dangerous_function".to_string(),
                        function: func.name.clone(),
                        address: func.address.clone(),
                        severity: "high".to_string(),
                        description: format!("Use of dangerous function: {}", dangerous),
                        cwe_id: cwe,
                    });
                }
            }
        }

        let function_count = functions.len();
        Ok(GhidraAnalysis {
            decompiled_functions: functions,
            call_graph: call_edges,
            cross_references: xrefs,
            detected_vulnerabilities: vulns,
            function_count,
            data_types: Vec::new(),
        })
    }

    pub fn run_radare2_analysis(file_path: &str) -> std::result::Result<Radare2Analysis, String> {
        if which("r2").is_none() {
            return Err("radare2 (r2) not found in PATH".to_string());
        }

        let mut sections = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        let entry_points = Vec::new();
        let mut strings_info = Vec::new();
        let mut functions = Vec::new();

        let protections = Self::check_binary_protections(file_path);

        if let Ok(output) = std::process::Command::new("r2")
            .args(["-q", "-e", "scr.color=0", "-c", "iS", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    sections.push(BinarySection {
                        name: parts[parts.len() - 1].to_string(),
                        address: parts[0].to_string(),
                        size: parts[2].parse().unwrap_or(0),
                        permissions: parts[3].to_string(),
                        entropy: None,
                    });
                }
            }
        }

        if let Ok(output) = std::process::Command::new("r2")
            .args(["-q", "-e", "scr.color=0", "-c", "ii", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('[') {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        imports.push(parts[parts.len() - 1].to_string());
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("r2")
            .args(["-q", "-e", "scr.color=0", "-c", "iE", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('[') {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        exports.push(parts[parts.len() - 1].to_string());
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("r2")
            .args(["-q", "-e", "scr.color=0", "-c", "iz", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.contains("\"") {
                    if let Some(start) = line.find('"') {
                        if let Some(end) = line.rfind('"') {
                            if start != end {
                                let s = line[start + 1..end].to_string();
                                if !s.is_empty() && s.len() > 3 {
                                    strings_info.push(R2StringInfo {
                                        string: s,
                                        address: String::new(),
                                        section: None,
                                        references: 0,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("r2")
            .args(["-q", "-e", "scr.color=0", "-c", "afl", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    functions.push(R2Function {
                        name: parts[parts.len() - 1].to_string(),
                        address: parts[0].to_string(),
                        size: parts[2].parse().unwrap_or(0),
                        complexity: None,
                        num_locals: None,
                        num_args: None,
                    });
                }
            }
        }

        Ok(Radare2Analysis {
            sections,
            imports,
            exports,
            entry_points,
            strings_analysis: strings_info,
            functions,
            protections,
        })
    }

    fn check_binary_protections(file_path: &str) -> BinaryProtections {
        let mut nx = false;
        let mut canary = false;
        let mut pie = false;
        let mut relro = "No".to_string();
        let mut fortify = false;

        if let Ok(output) = std::process::Command::new("checksec")
            .args(["--file", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            nx = stdout.contains("nx enabled") || stdout.contains("nx: enabled");
            canary = stdout.contains("canary found") || stdout.contains("stack canary: yes");
            pie = stdout.contains("pie enabled") || stdout.contains("pie: yes");
            if stdout.contains("full relro") { relro = "Full".to_string(); }
            else if stdout.contains("partial relro") { relro = "Partial".to_string(); }
            fortify = stdout.contains("fortify") && !stdout.contains("fortify: no");
        } else if let Ok(output) = std::process::Command::new("readelf")
            .args(["-l", file_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            nx = stdout.contains("gnu_stack") && !stdout.contains("execute");
        }

        BinaryProtections {
            nx_enabled: nx,
            stack_canary: canary,
            pie_enabled: pie,
            relro,
            fortify_source: fortify,
            aslr: true,
            stripped: false,
            packed: None,
        }
    }

    pub fn diff_binaries(file_a: &str, file_b: &str) -> std::result::Result<BinaryDiffResult, String> {
        let mut added_funcs = Vec::new();
        let mut removed_funcs = Vec::new();
        let mut modified_funcs = Vec::new();
        let mut added_strings = Vec::new();
        let mut removed_strings = Vec::new();
        let mut patches = Vec::new();

        let analysis_a = Self::run_radare2_analysis(file_a).ok();
        let analysis_b = Self::run_radare2_analysis(file_b).ok();

        if let (Some(a), Some(b)) = (&analysis_a, &analysis_b) {
            let funcs_a: std::collections::HashSet<_> = a.functions.iter().map(|f| f.name.clone()).collect();
            let funcs_b: std::collections::HashSet<_> = b.functions.iter().map(|f| f.name.clone()).collect();

            for f in &funcs_b {
                if !funcs_a.contains(f) { added_funcs.push(f.clone()); }
            }
            for f in &funcs_a {
                if !funcs_b.contains(f) { removed_funcs.push(f.clone()); }
            }

            let func_map_a: std::collections::HashMap<_, _> = a.functions.iter().map(|f| (f.name.clone(), f)).collect();
            let func_map_b: std::collections::HashMap<_, _> = b.functions.iter().map(|f| (f.name.clone(), f)).collect();

            for (name, func_b) in &func_map_b {
                if let Some(func_a) = func_map_a.get(name) {
                    if func_a.size != func_b.size {
                        modified_funcs.push(name.clone());
                        patches.push(PatchInfo {
                            function: name.clone(),
                            address: func_b.address.clone(),
                            change_type: "size_changed".to_string(),
                            description: format!("Size changed from {} to {} bytes", func_a.size, func_b.size),
                            security_impact: None,
                        });
                    }
                }
            }

            let strs_a: std::collections::HashSet<_> = a.strings_analysis.iter().map(|s| s.string.clone()).collect();
            let strs_b: std::collections::HashSet<_> = b.strings_analysis.iter().map(|s| s.string.clone()).collect();

            for s in &strs_b {
                if !strs_a.contains(s) { added_strings.push(s.clone()); }
            }
            for s in &strs_a {
                if !strs_b.contains(s) { removed_strings.push(s.clone()); }
            }
        }

        Ok(BinaryDiffResult {
            file_a: file_a.to_string(),
            file_b: file_b.to_string(),
            added_functions: added_funcs,
            removed_functions: removed_funcs,
            modified_functions: modified_funcs,
            added_strings,
            removed_strings,
            patch_analysis: patches,
        })
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 { format!("{}B", bytes) }
    else if bytes < 1024 * 1024 { format!("{:.1}KB", bytes as f64 / 1024.0) }
    else if bytes < 1024 * 1024 * 1024 { format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0)) }
    else { format!("{:.1}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)) }
}

fn which(cmd: &str) -> Option<String> {
    if let Ok(output) = std::process::Command::new("which").arg(cmd).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() { return Some(path); }
        }
    }
    None
}
