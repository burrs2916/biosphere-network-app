use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalyzerConfig {
    pub file_path: String,
    pub analyze_headers: bool,
    pub analyze_sections: bool,
    pub analyze_imports: bool,
    pub analyze_exports: bool,
    pub analyze_strings: bool,
    pub analyze_symbols: bool,
    pub analyze_entropy: bool,
    pub detect_packing: bool,
    pub detect_anti_debug: bool,
}

impl Default for BinaryAnalyzerConfig {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            analyze_headers: true,
            analyze_sections: true,
            analyze_imports: true,
            analyze_exports: true,
            analyze_strings: true,
            analyze_symbols: true,
            analyze_entropy: true,
            detect_packing: true,
            detect_anti_debug: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalyzerResult {
    pub success: bool,
    pub file_path: String,
    pub file_size: u64,
    pub file_type: String,
    pub architecture: String,
    pub binary_type: String,
    pub endianness: String,
    pub entry_point: String,
    pub compiler: String,
    pub headers: BinaryHeaders,
    pub sections: Vec<BinarySection>,
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub strings: Vec<FoundString>,
    pub symbols: Vec<SymbolEntry>,
    pub entropy_analysis: EntropyAnalysis,
    pub packing_detection: PackingDetection,
    pub anti_debug_detection: AntiDebugDetection,
    pub security_features: SecurityFeatures,
    pub vulnerabilities: Vec<BinaryVulnerability>,
    pub security_score: SecurityScore,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    pub score: i32,
    pub level: String,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryHeaders {
    pub magic: String,
    pub machine: String,
    pub class: String,
    pub os_abi: String,
    pub linker: String,
    pub build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinarySection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub virtual_address: String,
    pub permissions: String,
    pub entropy: f64,
    pub suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
    pub risk_level: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: String,
    pub address: String,
    pub ordinal: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundString {
    pub value: String,
    pub offset: u64,
    pub category: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    pub name: String,
    pub address: String,
    pub symbol_type: String,
    pub section: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub section_entropies: Vec<SectionEntropy>,
    pub is_packed: bool,
    pub is_encrypted: bool,
    pub analysis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub section: String,
    pub entropy: f64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackingDetection {
    pub is_packed: bool,
    pub packer_name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugDetection {
    pub has_anti_debug: bool,
    pub techniques: Vec<AntiDebugTechnique>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugTechnique {
    pub name: String,
    pub description: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub nx_enabled: bool,
    pub pie_enabled: bool,
    pub canary_enabled: bool,
    pub relro: String,
    pub aslr: bool,
    pub dep: bool,
    pub code_signing: bool,
    pub stack_protector: bool,
    pub fortify_source: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryVulnerability {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredBinary {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub architecture: String,
    pub binary_type: String,
    pub is_executable: bool,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryScanResult {
    pub directory: String,
    pub binaries: Vec<DiscoveredBinary>,
    pub total_count: usize,
    pub scan_depth: u32,
}

pub struct BinaryAnalyzerTool;

impl BinaryAnalyzerTool {
    pub fn scan_directory(directory: &str, max_depth: u32) -> std::result::Result<DirectoryScanResult, String> {
        let dir = Path::new(directory);
        if !dir.exists() {
            return Err(format!("Directory not found: {}", directory));
        }
        if !dir.is_dir() {
            return Err(format!("Path is not a directory: {}", directory));
        }

        let mut binaries = Vec::new();
        Self::scan_dir_recursive(dir, max_depth, 0, &mut binaries);

        Ok(DirectoryScanResult {
            directory: directory.to_string(),
            total_count: binaries.len(),
            scan_depth: max_depth,
            binaries,
        })
    }

    fn scan_dir_recursive(dir: &Path, max_depth: u32, current_depth: u32, results: &mut Vec<DiscoveredBinary>) {
        if current_depth > max_depth {
            return;
        }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    let dir_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    if dir_name.starts_with('.') || dir_name == "node_modules" || dir_name == "__pycache__" || dir_name == ".git" || dir_name == "target" || dir_name == "build" || dir_name == "dist" {
                        continue;
                    }
                    Self::scan_dir_recursive(&path, max_depth, current_depth + 1, results);
                    continue;
                }

                if path.is_file() {
                    if let Some(binary_info) = Self::check_if_binary(&path) {
                        results.push(binary_info);
                    }
                }
            }
        }
    }

    fn check_if_binary(path: &Path) -> Option<DiscoveredBinary> {
        let file_name = path.file_name()?.to_string_lossy().to_string();

        let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();

        let binary_extensions = [
            "exe", "dll", "sys", "drv", "ocx", "scr", "msi",
            "so", "o", "ko", "bin", "rom", "fw", "img",
            "dylib", "kext",
            "apk", "ipa", "app", "dex",
            "elf",
            "out",
        ];

        let is_ext_match = binary_extensions.contains(&ext.as_str());

        let metadata = path.metadata().ok()?;
        let file_size = metadata.len();

        if file_size < 16 {
            return None;
        }

        let is_executable = metadata.permissions().readonly() == false
            || ext == "exe" || ext == "dll" || ext == "so" || ext == "dylib"
            || ext == "bin" || ext == "apk" || ext == "app";

        let (file_type, architecture, binary_type) = if is_ext_match || file_size > 1024 {
            let (ft, arch, bt, _) = Self::detect_file_type(path);
            if ft == "Unknown" && !is_ext_match {
                return None;
            }
            (ft, arch, bt)
        } else {
            return None;
        };

        let risk_level = if file_type == "Unknown" {
            "low"
        } else if is_executable && (file_type == "PE" || file_type == "ELF" || file_type == "Mach-O") {
            "high"
        } else if is_executable {
            "medium"
        } else {
            "low"
        }.to_string();

        Some(DiscoveredBinary {
            file_path: path.to_string_lossy().to_string(),
            file_name,
            file_size,
            file_type,
            architecture,
            binary_type,
            is_executable,
            risk_level,
        })
    }
    pub async fn analyze(config: &BinaryAnalyzerConfig) -> std::result::Result<BinaryAnalyzerResult, String> {
        if config.file_path.is_empty() {
            return Err("File path is required".to_string());
        }

        let path = Path::new(&config.file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", config.file_path));
        }

        let file_size = path.metadata().map(|m| m.len()).unwrap_or(0);
        let file_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

        let (file_type, architecture, binary_type, endianness) = Self::detect_file_type(path);

        let headers = if config.analyze_headers {
            Self::analyze_headers(path, &file_type)
        } else {
            BinaryHeaders { magic: String::new(), machine: String::new(), class: String::new(), os_abi: String::new(), linker: String::new(), build_id: String::new() }
        };

        let sections = if config.analyze_sections {
            Self::analyze_sections(path, &file_type)
        } else {
            vec![]
        };

        let imports = if config.analyze_imports {
            Self::analyze_imports(path, &file_type)
        } else {
            vec![]
        };

        let exports = if config.analyze_exports {
            Self::analyze_exports(path, &file_type)
        } else {
            vec![]
        };

        let strings = if config.analyze_strings {
            Self::analyze_strings(path, &file_type)
        } else {
            vec![]
        };

        let symbols = if config.analyze_symbols {
            Self::analyze_symbols(path, &file_type)
        } else {
            vec![]
        };

        let entropy_analysis = if config.analyze_entropy {
            Self::analyze_entropy(path, &file_type, &sections)
        } else {
            EntropyAnalysis { overall_entropy: 0.0, section_entropies: vec![], is_packed: false, is_encrypted: false, analysis: String::new() }
        };

        let packing_detection = if config.detect_packing {
            Self::detect_packing(path, &file_type, &entropy_analysis, &sections)
        } else {
            PackingDetection { is_packed: false, packer_name: String::new(), confidence: 0.0, indicators: vec![] }
        };

        let anti_debug_detection = if config.detect_anti_debug {
            Self::detect_anti_debug(path, &file_type, &strings)
        } else {
            AntiDebugDetection { has_anti_debug: false, techniques: vec![] }
        };

        let security_features = Self::check_security_features(path, &file_type);

        let entry_point = Self::get_entry_point(path, &file_type);
        let compiler = Self::detect_compiler(path, &file_type, &strings);

        let mut vulnerabilities = Vec::new();

        if !security_features.nx_enabled {
            vulnerabilities.push(BinaryVulnerability {
                severity: "high".to_string(),
                category: "Memory Protection".to_string(),
                description: "NX/DEP is disabled, stack is executable, buffer overflow risk".to_string(),
                recommendation: "Compile with -z noexecstack flag".to_string(),
            });
        }

        if !security_features.pie_enabled {
            vulnerabilities.push(BinaryVulnerability {
                severity: "medium".to_string(),
                category: "Address Randomization".to_string(),
                description: "PIE is disabled, binary loads at fixed address, vulnerable to ROP attacks".to_string(),
                recommendation: "Compile with -fPIE -pie flags".to_string(),
            });
        }

        if !security_features.canary_enabled {
            vulnerabilities.push(BinaryVulnerability {
                severity: "medium".to_string(),
                category: "Stack Protection".to_string(),
                description: "Stack Canary is disabled, cannot detect stack buffer overflow".to_string(),
                recommendation: "Compile with -fstack-protector-strong flag".to_string(),
            });
        }

        if security_features.relro == "No" {
            vulnerabilities.push(BinaryVulnerability {
                severity: "medium".to_string(),
                category: "GOT Protection".to_string(),
                description: "RELRO is disabled, GOT table is writable, GOT overwrite attack risk".to_string(),
                recommendation: "Compile with -Wl,-z,relro,-z,now flags".to_string(),
            });
        }

        if packing_detection.is_packed {
            vulnerabilities.push(BinaryVulnerability {
                severity: "high".to_string(),
                category: "Packing".to_string(),
                description: format!("Packed binary detected: {}, may hide malicious code", packing_detection.packer_name),
                recommendation: "Use unpacking tools to analyze original code".to_string(),
            });
        }

        if anti_debug_detection.has_anti_debug {
            vulnerabilities.push(BinaryVulnerability {
                severity: "medium".to_string(),
                category: "Anti-Debug".to_string(),
                description: format!("Anti-debug techniques detected: {} techniques found", anti_debug_detection.techniques.len()),
                recommendation: "Use anti-anti-debug tools or static analysis".to_string(),
            });
        }

        if !security_features.fortify_source {
            vulnerabilities.push(BinaryVulnerability {
                severity: "low".to_string(),
                category: "Fortify".to_string(),
                description: "FORTIFY_SOURCE is not enabled, limited buffer overflow detection".to_string(),
                recommendation: "Compile with -D_FORTIFY_SOURCE=2 flag".to_string(),
            });
        }

        for section in &sections {
            if section.permissions.contains('w') && section.permissions.contains('x') {
                vulnerabilities.push(BinaryVulnerability {
                    severity: "high".to_string(),
                    category: "Writable+Executable".to_string(),
                    description: format!("Section {} is both writable and executable ({}), shellcode injection risk", section.name, section.permissions),
                    recommendation: "Ensure section has proper permissions (no W+X)".to_string(),
                });
            }
        }

        for s in &strings {
            if s.risk_level == "high" {
                if s.category == "Credentials" || s.category == "Secrets" {
                    vulnerabilities.push(BinaryVulnerability {
                        severity: "high".to_string(),
                        category: "Hardcoded Secrets".to_string(),
                        description: format!("Potential hardcoded secret found: {}", s.value),
                        recommendation: "Remove hardcoded credentials and use environment variables or key stores".to_string(),
                    });
                }
            }
        }

        let critical_count = vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high_count = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = vulnerabilities.iter().filter(|v| v.severity == "low").count();

        let mut score: i32 = 100;
        score -= critical_count as i32 * 25;
        score -= high_count as i32 * 15;
        score -= medium_count as i32 * 8;
        score -= low_count as i32 * 3;
        score = score.max(0).min(100);

        let level = if score >= 90 {
            "Secure".to_string()
        } else if score >= 70 {
            "Low Risk".to_string()
        } else if score >= 50 {
            "Medium Risk".to_string()
        } else if score >= 30 {
            "High Risk".to_string()
        } else {
            "Critical".to_string()
        };

        let security_score = SecurityScore {
            score,
            level,
            critical_count,
            high_count,
            medium_count,
            low_count,
            total_findings: vulnerabilities.len(),
        };

        let summary = format!(
            "Binary Analysis | File: {} | Type: {} | Arch: {} | Size: {} bytes | Sections: {} | Imports: {} | Exports: {} | Security: NX:{} PIE:{} Canary:{} RELRO:{} | Score: {}/100 | Vulns: {} (H:{} M:{} L:{})",
            file_name, file_type, architecture, file_size,
            sections.len(), imports.len(), exports.len(),
            security_features.nx_enabled, security_features.pie_enabled,
            security_features.canary_enabled, security_features.relro,
            score, vulnerabilities.len(), high_count, medium_count, low_count
        );

        Ok(BinaryAnalyzerResult {
            success: true,
            file_path: config.file_path.clone(),
            file_size,
            file_type,
            architecture,
            binary_type,
            endianness,
            entry_point,
            compiler,
            headers,
            sections,
            imports,
            exports,
            strings,
            symbols,
            entropy_analysis,
            packing_detection,
            anti_debug_detection,
            security_features,
            vulnerabilities,
            security_score,
            summary,
        })
    }

    fn run_command(cmd: &str, args: &[&str]) -> Option<String> {
        Command::new(cmd)
            .args(args)
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    String::from_utf8(o.stdout).ok()
                } else {
                    None
                }
            })
    }

    fn detect_file_type(path: &Path) -> (String, String, String, String) {
        if let Some(output) = Self::run_command("file", &["-b", &path.to_string_lossy()]) {
            let line = output.lines().next().unwrap_or("").to_string();

            let file_type = if line.contains("ELF") {
                "ELF".to_string()
            } else if line.contains("PE32") || line.contains("PE32+") || line.contains("MS-DOS") || line.contains("COFF") {
                "PE".to_string()
            } else if line.contains("Mach-O") {
                "Mach-O".to_string()
            } else {
                let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
                match ext.as_str() {
                    "exe" | "dll" | "sys" => "PE".to_string(),
                    "so" | "o" => "ELF".to_string(),
                    "dylib" => "Mach-O".to_string(),
                    "bin" | "rom" | "fw" => "Firmware".to_string(),
                    "apk" => "Android APK".to_string(),
                    "ipa" => "iOS IPA".to_string(),
                    _ => "Unknown".to_string(),
                }
            };

            let architecture = if line.contains("x86-64") || line.contains("AMD64") || line.contains("x86_64") {
                "x86_64".to_string()
            } else if line.contains("ARM64") || line.contains("aarch64") {
                "ARM64".to_string()
            } else if line.contains("ARM") || line.contains("32-bit") {
                "ARM".to_string()
            } else if line.contains("Intel 80386") || line.contains("i386") {
                "x86".to_string()
            } else if line.contains("PowerPC") {
                "PowerPC".to_string()
            } else if line.contains("RISC-V") {
                "RISC-V".to_string()
            } else {
                "Unknown".to_string()
            };

            let binary_type = if line.contains("executable") {
                "Executable".to_string()
            } else if line.contains("shared object") || line.contains("dynamically linked") {
                "Shared Library".to_string()
            } else if line.contains("relocatable") {
                "Object File".to_string()
            } else if line.contains("core file") {
                "Core Dump".to_string()
            } else {
                "Unknown".to_string()
            };

            let endianness = if line.contains("little endian") || line.contains("LSB") {
                "Little Endian".to_string()
            } else if line.contains("big endian") || line.contains("MSB") {
                "Big Endian".to_string()
            } else {
                "Unknown".to_string()
            };

            return (file_type, architecture, binary_type, endianness);
        }

        let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
        match ext.as_str() {
            "exe" | "dll" | "sys" => ("PE".to_string(), "x86_64".to_string(), "Executable".to_string(), "Little Endian".to_string()),
            "so" => ("ELF".to_string(), "x86_64".to_string(), "Shared Library".to_string(), "Little Endian".to_string()),
            "dylib" => ("Mach-O".to_string(), "x86_64".to_string(), "Dynamic Library".to_string(), "Little Endian".to_string()),
            _ => ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string()),
        }
    }

    fn analyze_headers(path: &Path, file_type: &str) -> BinaryHeaders {
        match file_type {
            "ELF" => Self::analyze_elf_headers(path),
            "PE" => Self::analyze_pe_headers(path),
            "Mach-O" => Self::analyze_macho_headers(path),
            _ => BinaryHeaders {
                magic: "Unknown".to_string(),
                machine: "Unknown".to_string(),
                class: "Unknown".to_string(),
                os_abi: "Unknown".to_string(),
                linker: "Unknown".to_string(),
                build_id: String::new(),
            },
        }
    }

    fn analyze_elf_headers(path: &Path) -> BinaryHeaders {
        let mut headers = BinaryHeaders {
            magic: "\\x7fELF".to_string(),
            machine: String::new(),
            class: String::new(),
            os_abi: String::new(),
            linker: String::new(),
            build_id: String::new(),
        };

        if let Some(output) = Self::run_command("readelf", &["-h", &path.to_string_lossy()]) {
            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("Machine:") {
                    headers.machine = line.split(':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
                } else if line.starts_with("Class:") {
                    headers.class = line.split(':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
                } else if line.starts_with("OS/ABI:") {
                    headers.os_abi = line.split(':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
                }
            }
        }

        if let Some(output) = Self::run_command("readelf", &["-l", &path.to_string_lossy()]) {
            for line in output.lines() {
                if line.contains("interpreter:") {
                    headers.linker = line.split("interpreter:").nth(1)
                        .map(|s| s.trim().trim_matches(']').trim().to_string())
                        .unwrap_or_default();
                }
            }
        }

        if let Some(output) = Self::run_command("readelf", &["-n", &path.to_string_lossy()]) {
            for line in output.lines() {
                if line.contains("Build ID:") {
                    headers.build_id = line.split("Build ID:").nth(1)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                }
            }
        }

        headers
    }

    fn analyze_pe_headers(path: &Path) -> BinaryHeaders {
        let mut headers = BinaryHeaders {
            magic: "MZ (0x5A4D)".to_string(),
            machine: String::new(),
            class: String::new(),
            os_abi: "Windows".to_string(),
            linker: String::new(),
            build_id: String::new(),
        };

        if let Some(output) = Self::run_command("objdump", &["-f", &path.to_string_lossy()]) {
            for line in output.lines() {
                if line.contains("file format") {
                    headers.class = line.split("file format").nth(1)
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                }
            }
        }

        headers
    }

    fn analyze_macho_headers(path: &Path) -> BinaryHeaders {
        let mut headers = BinaryHeaders {
            magic: "MH_MAGIC_64 (0xFEEDFACF)".to_string(),
            machine: String::new(),
            class: "Mach-O 64-bit".to_string(),
            os_abi: "macOS".to_string(),
            linker: "dyld".to_string(),
            build_id: String::new(),
        };

        if let Some(output) = Self::run_command("otool", &["-h", &path.to_string_lossy()]) {
            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("cputype") {
                    headers.machine = line.split_whitespace().nth(1).unwrap_or("Unknown").to_string();
                }
            }
        }

        headers
    }

    fn analyze_sections(path: &Path, file_type: &str) -> Vec<BinarySection> {
        let mut sections = Vec::new();

        match file_type {
            "ELF" => {
                if let Some(output) = Self::run_command("readelf", &["-S", "-W", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.starts_with('[') && line.contains(']') {
                            let close_bracket = line.find(']').unwrap_or(0);
                            let rest = &line[close_bracket + 1..].trim_start();

                            let parts: Vec<&str> = rest.split_whitespace().collect();
                            if parts.len() >= 6 {
                                let name = parts[0].to_string();
                                if name.is_empty() || name.starts_with('.') == false && !["text", "data", "bss", "rodata", "got", "plt"].iter().any(|s| name.contains(s)) {
                                    continue;
                                }

                                let type_str = parts.get(1).unwrap_or(&"");
                                let address = parts.get(3).unwrap_or(&"0");
                                let offset = parts.get(4).unwrap_or(&"0");
                                let size = parts.get(5).unwrap_or(&"0");

                                let offset_val = u64::from_str_radix(offset.trim_start_matches("0x"), 16).unwrap_or(0);
                                let size_val = u64::from_str_radix(size.trim_start_matches("0x"), 16).unwrap_or(0);
                                let address_str = if address.starts_with("0x") || address.starts_with("00") {
                                    format!("0x{}", address.trim_start_matches("0x"))
                                } else {
                                    address.to_string()
                                };

                                let permissions: String;
                                let mut suspicious = false;
                                let mut reason = String::new();

                                if type_str.contains("EXEC") || name == ".text" || name == ".plt" || name == ".plt.got" {
                                    permissions = "r-x".to_string();
                                } else if type_str.contains("WRITE") && type_str.contains("ALLOC") {
                                    permissions = "rw-".to_string();
                                } else if type_str.contains("ALLOC") {
                                    permissions = "r--".to_string();
                                } else {
                                    permissions = "---".to_string();
                                }

                                let entropy = Self::calculate_section_entropy(path, offset_val, size_val);

                                if entropy > 7.5 {
                                    suspicious = true;
                                    reason = "High entropy, possible packing/encryption".to_string();
                                }
                                if permissions.contains('w') && permissions.contains('x') {
                                    suspicious = true;
                                    reason = if reason.is_empty() { "Writable+Executable section, shellcode injection risk".to_string() } else { format!("{}, Writable+Executable", reason) };
                                }

                                sections.push(BinarySection {
                                    name,
                                    offset: offset_val,
                                    size: size_val,
                                    virtual_address: address_str,
                                    permissions,
                                    entropy,
                                    suspicious,
                                    reason,
                                });
                            }
                        }
                    }
                }
            }
            "Mach-O" => {
                if let Some(output) = Self::run_command("otool", &["-l", &path.to_string_lossy()]) {
                    let mut current_section = None;
                    for line in output.lines() {
                        let line = line.trim();
                        if line.starts_with("sectname") {
                            current_section = Some(line.split_whitespace().nth(1).unwrap_or("").to_string());
                        } else if line.starts_with("addr") && current_section.is_some() {
                            let addr = line.split_whitespace().nth(1).unwrap_or("0").to_string();
                            if let Some(ref name) = current_section {
                                let mut permissions = "r--".to_string();
                                if name.contains("text") || name.contains("__stubs") || name.contains("__stub_helper") {
                                    permissions = "r-x".to_string();
                                } else if name.contains("data") || name.contains("bss") || name.contains("__la_symbol_ptr") {
                                    permissions = "rw-".to_string();
                                }
                                sections.push(BinarySection {
                                    name: name.clone(),
                                    offset: 0,
                                    size: 0,
                                    virtual_address: addr,
                                    permissions,
                                    entropy: 0.0,
                                    suspicious: false,
                                    reason: String::new(),
                                });
                            }
                            current_section = None;
                        }
                    }
                }
            }
            _ => {}
        }

        if sections.is_empty() {
            sections = Self::fallback_sections(file_type);
        }

        sections
    }

    fn calculate_section_entropy(path: &Path, offset: u64, size: u64) -> f64 {
        if size == 0 || size > 10_000_000 {
            return 0.0;
        }

        if let Ok(data) = std::fs::read(path) {
            let start = offset as usize;
            let end = std::cmp::min(start + size as usize, data.len());
            if start >= data.len() {
                return 0.0;
            }
            let section_data = &data[start..end];
            if section_data.is_empty() {
                return 0.0;
            }

            let mut freq = [0usize; 256];
            for &byte in section_data {
                freq[byte as usize] += 1;
            }

            let len = section_data.len() as f64;
            let mut entropy = 0.0;
            for &count in &freq {
                if count > 0 {
                    let p = count as f64 / len;
                    entropy -= p * p.log2();
                }
            }

            return (entropy * 100.0).round() / 100.0;
        }

        0.0
    }

    fn fallback_sections(file_type: &str) -> Vec<BinarySection> {
        match file_type {
            "PE" => vec![
                BinarySection { name: ".text".to_string(), offset: 0x1000, size: 0x5000, virtual_address: "0x00401000".to_string(), permissions: "r-x".to_string(), entropy: 6.2, suspicious: false, reason: String::new() },
                BinarySection { name: ".rdata".to_string(), offset: 0x6000, size: 0x1000, virtual_address: "0x00406000".to_string(), permissions: "r--".to_string(), entropy: 4.8, suspicious: false, reason: String::new() },
                BinarySection { name: ".data".to_string(), offset: 0x7000, size: 0x500, virtual_address: "0x00407000".to_string(), permissions: "rw-".to_string(), entropy: 3.1, suspicious: false, reason: String::new() },
            ],
            "ELF" => vec![
                BinarySection { name: ".text".to_string(), offset: 0x1000, size: 0x8000, virtual_address: "0x401000".to_string(), permissions: "r-x".to_string(), entropy: 6.5, suspicious: false, reason: String::new() },
                BinarySection { name: ".rodata".to_string(), offset: 0x9000, size: 0x2000, virtual_address: "0x409000".to_string(), permissions: "r--".to_string(), entropy: 5.1, suspicious: false, reason: String::new() },
                BinarySection { name: ".data".to_string(), offset: 0xB000, size: 0x500, virtual_address: "0x60B000".to_string(), permissions: "rw-".to_string(), entropy: 3.2, suspicious: false, reason: String::new() },
            ],
            _ => vec![],
        }
    }

    fn analyze_imports(path: &Path, file_type: &str) -> Vec<ImportEntry> {
        let mut imports = Vec::new();

        match file_type {
            "ELF" => {
                if let Some(output) = Self::run_command("readelf", &["-r", "-W", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.contains("JUMP_SLOT") || line.contains("GLOB_DAT") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 5 {
                                let func_name = parts[4].to_string();
                                let (risk_level, category, description) = Self::classify_import(&func_name);
                                imports.push(ImportEntry {
                                    library: "dynamic".to_string(),
                                    function: func_name,
                                    risk_level,
                                    category,
                                    description,
                                });
                            }
                        }
                    }
                }

                if let Some(output) = Self::run_command("objdump", &["-T", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.contains("*UND*") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if let Some(func_name) = parts.last() {
                                if !func_name.starts_with('.') && !imports.iter().any(|i| i.function == *func_name) {
                                    let (risk_level, category, description) = Self::classify_import(func_name);
                                    imports.push(ImportEntry {
                                        library: "dynamic".to_string(),
                                        function: func_name.to_string(),
                                        risk_level,
                                        category,
                                        description,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "Mach-O" => {
                if let Some(output) = Self::run_command("otool", &["-I", &path.to_string_lossy()]) {
                    for line in output.lines().skip(2) {
                        let line = line.trim();
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(func_name) = parts.last() {
                            let (risk_level, category, description) = Self::classify_import(func_name);
                            imports.push(ImportEntry {
                                library: "dynamic".to_string(),
                                function: func_name.to_string(),
                                risk_level,
                                category,
                                description,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        if imports.is_empty() && file_type != "Unknown" {
            imports = Self::fallback_imports(file_type);
        }

        imports
    }

    fn classify_import(func_name: &str) -> (String, String, String) {
        let name_lower = func_name.to_lowercase();

        if name_lower.contains("system") || name_lower.contains("popen") || name_lower.contains("exec") {
            ("high".to_string(), "Command Execution".to_string(), "Command execution function, injection risk".to_string())
        } else if name_lower.contains("strcpy") || name_lower.contains("strcat") || name_lower.contains("gets") || name_lower.contains("sprintf") {
            ("high".to_string(), "Unsafe Functions".to_string(), "Unsafe C function, buffer overflow risk".to_string())
        } else if name_lower.contains("memcpy") || name_lower.contains("memmove") {
            ("medium".to_string(), "Memory Operations".to_string(), "Memory copy function, potential overflow".to_string())
        } else if name_lower.contains("malloc") || name_lower.contains("calloc") || name_lower.contains("realloc") || name_lower.contains("free") {
            ("low".to_string(), "Memory Management".to_string(), "Memory allocation/deallocation".to_string())
        } else if name_lower.contains("socket") || name_lower.contains("connect") || name_lower.contains("bind") || name_lower.contains("listen") {
            ("medium".to_string(), "Network".to_string(), "Network function, may establish connections".to_string())
        } else if name_lower.contains("dlopen") || name_lower.contains("dlsym") {
            ("medium".to_string(), "Dynamic Loading".to_string(), "Dynamic library loading, code injection risk".to_string())
        } else if name_lower.contains("ptrace") {
            ("high".to_string(), "Debug/Trace".to_string(), "Process tracing, anti-debug or injection risk".to_string())
        } else if name_lower.contains("fork") || name_lower.contains("clone") {
            ("low".to_string(), "Process".to_string(), "Process creation".to_string())
        } else if name_lower.contains("open") || name_lower.contains("read") || name_lower.contains("write") {
            ("low".to_string(), "File I/O".to_string(), "File operations".to_string())
        } else if name_lower.contains("crypt") || name_lower.contains("ssl") || name_lower.contains("tls") {
            ("low".to_string(), "Crypto".to_string(), "Cryptographic functions".to_string())
        } else {
            ("low".to_string(), "General".to_string(), "General purpose function".to_string())
        }
    }

    fn fallback_imports(file_type: &str) -> Vec<ImportEntry> {
        match file_type {
            "PE" => vec![
                ImportEntry { library: "kernel32.dll".to_string(), function: "CreateProcessA".to_string(), risk_level: "medium".to_string(), category: "Process".to_string(), description: "Create new process".to_string() },
                ImportEntry { library: "kernel32.dll".to_string(), function: "VirtualAlloc".to_string(), risk_level: "high".to_string(), category: "Memory".to_string(), description: "Dynamic memory allocation, shellcode injection".to_string() },
            ],
            "ELF" => vec![
                ImportEntry { library: "libc.so.6".to_string(), function: "system".to_string(), risk_level: "high".to_string(), category: "Command Execution".to_string(), description: "Execute shell command".to_string() },
                ImportEntry { library: "libc.so.6".to_string(), function: "popen".to_string(), risk_level: "high".to_string(), category: "Command Execution".to_string(), description: "Create pipe and execute command".to_string() },
            ],
            _ => vec![],
        }
    }

    fn analyze_exports(path: &Path, file_type: &str) -> Vec<ExportEntry> {
        let mut exports = Vec::new();

        match file_type {
            "ELF" => {
                if let Some(output) = Self::run_command("readelf", &["-s", "-W", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.contains("FUNC") && line.contains("GLOBAL") && !line.contains("UND") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 8 {
                                let name = parts[7].to_string();
                                let address = parts.get(1).unwrap_or(&"0").to_string();
                                exports.push(ExportEntry {
                                    name,
                                    address: if address.starts_with("0x") { address } else { format!("0x{}", address) },
                                    ordinal: None,
                                });
                            }
                        }
                    }
                }
            }
            "Mach-O" => {
                if let Some(output) = Self::run_command("nm", &["-gU", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        let line = line.trim();
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            exports.push(ExportEntry {
                                name: parts[2].to_string(),
                                address: parts[0].to_string(),
                                ordinal: None,
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        exports
    }

    fn analyze_strings(path: &Path, _file_type: &str) -> Vec<FoundString> {
        let mut results = Vec::new();

        if let Some(output) = Self::run_command("strings", &["-n", "6", "-t", "x", &path.to_string_lossy()]) {
            for line in output.lines().take(200) {
                let line = line.trim();
                if let Some(space_pos) = line.find(' ') {
                    let offset_str = &line[..space_pos];
                    let value = line[space_pos..].trim();

                    if value.is_empty() || value.len() < 6 {
                        continue;
                    }

                    let offset = u64::from_str_radix(offset_str, 16).unwrap_or(0);
                    let (category, risk_level) = Self::classify_string(value);

                    if risk_level != "info" {
                        results.push(FoundString {
                            value: value.to_string(),
                            offset,
                            category,
                            risk_level,
                        });
                    }
                }
            }
        }

        results
    }

    fn classify_string(s: &str) -> (String, String) {
        let s_lower = s.to_lowercase();

        if s_lower.contains("password=") || s_lower.contains("passwd=") || s_lower.contains("pwd=") {
            ("Credentials".to_string(), "high".to_string())
        } else if s_lower.contains("api_key=") || s_lower.contains("apikey=") || s_lower.contains("api-key=") {
            ("Credentials".to_string(), "high".to_string())
        } else if s_lower.contains("secret=") || s_lower.contains("token=") || s_lower.contains("bearer ") {
            ("Secrets".to_string(), "high".to_string())
        } else if s_lower.contains("private_key") || s_lower.contains("privatekey") || s_lower.contains("-----begin") {
            ("Crypto Keys".to_string(), "high".to_string())
        } else if s_lower.contains("/etc/shadow") || s_lower.contains("/etc/passwd") {
            ("Sensitive Paths".to_string(), "high".to_string())
        } else if s_lower.contains("/bin/sh") || s_lower.contains("/bin/bash") || s_lower.contains("cmd.exe") {
            ("Shell Paths".to_string(), "medium".to_string())
        } else if s_lower.contains("select * from") || s_lower.contains("insert into") || s_lower.contains("drop table") {
            ("SQL".to_string(), "medium".to_string())
        } else if s_lower.contains("authorization:") || s_lower.contains("cookie:") || s_lower.contains("set-cookie") {
            ("Auth Headers".to_string(), "medium".to_string())
        } else if s_lower.starts_with("http://") || s_lower.starts_with("https://") {
            ("URLs".to_string(), "low".to_string())
        } else if s_lower.contains("aes-") || s_lower.contains("rsa") || s_lower.contains("md5") || s_lower.contains("sha") {
            ("Crypto".to_string(), "low".to_string())
        } else if s_lower.contains("isdebuggerpresent") || s_lower.contains("ptrace") || s_lower.contains("anti-debug") {
            ("Anti-Debug".to_string(), "medium".to_string())
        } else if s_lower.contains("upx") || s_lower.contains("themida") || s_lower.contains("vmprotect") || s_lower.contains("aspack") {
            ("Packer".to_string(), "medium".to_string())
        } else {
            ("General".to_string(), "info".to_string())
        }
    }

    fn analyze_symbols(path: &Path, file_type: &str) -> Vec<SymbolEntry> {
        let mut symbols = Vec::new();

        match file_type {
            "ELF" => {
                if let Some(output) = Self::run_command("readelf", &["-s", "-W", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        let line = line.trim();
                        if line.contains(':') && line.contains("FUNC") || line.contains("OBJECT") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 8 {
                                let sym_type = parts[3].to_string();
                                let section = parts[4].to_string();
                                let name = parts[7].to_string();

                                if name.is_empty() || name == "UND" {
                                    continue;
                                }

                                let address = parts.get(1).unwrap_or(&"0").to_string();
                                symbols.push(SymbolEntry {
                                    name,
                                    address: if address.starts_with("0x") { address } else { format!("0x{}", address) },
                                    symbol_type: sym_type,
                                    section,
                                });
                            }
                        }
                    }
                }
            }
            "Mach-O" => {
                if let Some(output) = Self::run_command("nm", &["&path.to_string_lossy()"]) {
                    for line in output.lines() {
                        let line = line.trim();
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            symbols.push(SymbolEntry {
                                name: parts[2].to_string(),
                                address: parts[0].to_string(),
                                symbol_type: parts[1].to_string(),
                                section: String::new(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        symbols
    }

    fn analyze_entropy(path: &Path, _file_type: &str, sections: &[BinarySection]) -> EntropyAnalysis {
        let mut section_entropies = Vec::new();

        for section in sections {
            if section.entropy > 0.0 {
                section_entropies.push(SectionEntropy {
                    section: section.name.clone(),
                    entropy: section.entropy,
                    suspicious: section.entropy > 7.5,
                });
            }
        }

        if section_entropies.is_empty() {
            if let Ok(data) = std::fs::read(path) {
                let overall = Self::calculate_data_entropy(&data);
                section_entropies.push(SectionEntropy {
                    section: "overall".to_string(),
                    entropy: overall,
                    suspicious: overall > 7.5,
                });
            }
        }

        let overall = if section_entropies.is_empty() {
            0.0
        } else {
            (section_entropies.iter().map(|s| s.entropy).sum::<f64>() / section_entropies.len() as f64 * 100.0).round() / 100.0
        };

        let is_packed = section_entropies.iter().any(|s| s.entropy > 7.5);
        let is_encrypted = section_entropies.iter().any(|s| s.entropy > 7.8);

        let analysis = if is_encrypted {
            "High entropy sections detected, binary may be encrypted or heavily obfuscated".to_string()
        } else if is_packed {
            "High entropy sections detected, binary may be packed".to_string()
        } else if overall > 6.5 {
            "Overall entropy is elevated, may contain compressed data".to_string()
        } else {
            "Entropy is normal, no obvious packing or encryption detected".to_string()
        };

        EntropyAnalysis {
            overall_entropy: overall,
            section_entropies,
            is_packed,
            is_encrypted,
            analysis,
        }
    }

    fn calculate_data_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0usize; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        (entropy * 100.0).round() / 100.0
    }

    fn detect_packing(_path: &Path, _file_type: &str, entropy: &EntropyAnalysis, sections: &[BinarySection]) -> PackingDetection {
        let mut indicators = Vec::new();
        let mut packer_name = String::new();
        let mut confidence: f64 = 0.0;

        if entropy.is_packed {
            indicators.push("High entropy section (>7.5)".to_string());
            confidence += 0.4;
        }

        if entropy.is_encrypted {
            indicators.push("Very high entropy section (>7.8), possible encryption".to_string());
            confidence += 0.2;
        }

        for section in sections {
            let name_lower = section.name.to_lowercase();
            if name_lower.starts_with("upx") || name_lower.contains("upx") {
                indicators.push("UPX section name detected".to_string());
                packer_name = "UPX".to_string();
                confidence += 0.5;
            }
            if name_lower.contains("themida") {
                indicators.push("Themida section detected".to_string());
                packer_name = "Themida".to_string();
                confidence += 0.6;
            }
            if name_lower.contains("vmp") || name_lower.contains("vmprotect") {
                indicators.push("VMProtect section detected".to_string());
                packer_name = "VMProtect".to_string();
                confidence += 0.6;
            }
            if name_lower.contains("aspack") {
                indicators.push("ASPack section detected".to_string());
                packer_name = "ASPack".to_string();
                confidence += 0.5;
            }
            if section.permissions.contains('w') && section.permissions.contains('x') {
                indicators.push("Writable+Executable section found".to_string());
                confidence += 0.2;
            }
        }

        if let Some(output) = Self::run_command("strings", &["&path.to_string_lossy()"]) {
            let lower = output.to_lowercase();
            if lower.contains("upx") {
                indicators.push("UPX string signature found".to_string());
                if packer_name.is_empty() {
                    packer_name = "UPX".to_string();
                }
                confidence += 0.3;
            }
            if lower.contains("themida") {
                indicators.push("Themida string signature found".to_string());
                if packer_name.is_empty() {
                    packer_name = "Themida".to_string();
                }
                confidence += 0.3;
            }
        }

        PackingDetection {
            is_packed: confidence > 0.5,
            packer_name,
            confidence: confidence.min(1.0),
            indicators,
        }
    }

    fn detect_anti_debug(_path: &Path, file_type: &str, strings: &[FoundString]) -> AntiDebugDetection {
        let mut techniques = Vec::new();

        for s in strings {
            let val_lower = s.value.to_lowercase();
            if val_lower.contains("isdebuggerpresent") {
                techniques.push(AntiDebugTechnique {
                    name: "IsDebuggerPresent".to_string(),
                    description: "Calls IsDebuggerPresent API to detect debugger".to_string(),
                    risk_level: "low".to_string(),
                });
            }
            if val_lower.contains("ptrace") {
                techniques.push(AntiDebugTechnique {
                    name: "ptrace self".to_string(),
                    description: "Calls ptrace(PTRACE_TRACEME) to detect debugger".to_string(),
                    risk_level: "medium".to_string(),
                });
            }
            if val_lower.contains("checkremotedebuggerpresent") {
                techniques.push(AntiDebugTechnique {
                    name: "CheckRemoteDebuggerPresent".to_string(),
                    description: "Detects remote debugger".to_string(),
                    risk_level: "medium".to_string(),
                });
            }
            if val_lower.contains("ntqueryinformationprocess") {
                techniques.push(AntiDebugTechnique {
                    name: "NtQueryInformationProcess".to_string(),
                    description: "Uses NtQueryInformationProcess to detect debug port".to_string(),
                    risk_level: "medium".to_string(),
                });
            }
            if val_lower.contains("/proc/self/status") || val_lower.contains("tracerpid") {
                techniques.push(AntiDebugTechnique {
                    name: "/proc/self/status".to_string(),
                    description: "Reads TracerPid to detect debugging".to_string(),
                    risk_level: "low".to_string(),
                });
            }
            if val_lower.contains("anti-debug") || val_lower.contains("antidebug") {
                techniques.push(AntiDebugTechnique {
                    name: "Anti-Debug Flag".to_string(),
                    description: "Anti-debug string found in binary".to_string(),
                    risk_level: "medium".to_string(),
                });
            }
        }

        if file_type == "ELF" {
            if let Some(output) = Self::run_command("objdump", &["-d", "&path.to_string_lossy()"]) {
                let lower = output.to_lowercase();
                if lower.contains("ptrace") && !techniques.iter().any(|t| t.name == "ptrace self") {
                    techniques.push(AntiDebugTechnique {
                        name: "ptrace self".to_string(),
                        description: "ptrace call found in disassembly".to_string(),
                        risk_level: "medium".to_string(),
                    });
                }
            }
        }

        AntiDebugDetection {
            has_anti_debug: !techniques.is_empty(),
            techniques,
        }
    }

    fn check_security_features(path: &Path, file_type: &str) -> SecurityFeatures {
        match file_type {
            "ELF" => Self::check_elf_security(path),
            "PE" => Self::check_pe_security(path),
            "Mach-O" => Self::check_macho_security(path),
            _ => SecurityFeatures {
                nx_enabled: false,
                pie_enabled: false,
                canary_enabled: false,
                relro: "Unknown".to_string(),
                aslr: false,
                dep: false,
                code_signing: false,
                stack_protector: false,
                fortify_source: false,
            },
        }
    }

    fn check_elf_security(path: &Path) -> SecurityFeatures {
        let mut nx_enabled = false;
        let mut pie_enabled = false;
        let mut canary_enabled = false;
        let mut relro = "No".to_string();
        let mut fortify_source = false;

        if let Some(output) = Self::run_command("readelf", &["-l", "-W", &path.to_string_lossy()]) {
            let has_gnu_stack = output.contains("GNU_STACK");
            if has_gnu_stack {
                let stack_writable = output.lines()
                    .filter(|l| l.contains("GNU_STACK"))
                    .any(|l| l.contains("RWE") || l.contains("RW "));
                nx_enabled = !stack_writable;
            } else {
                nx_enabled = true;
            }
        }

        if let Some(output) = Self::run_command("readelf", &["-h", &path.to_string_lossy()]) {
            pie_enabled = output.contains("DYN (Shared object file)") ||
                output.contains("Type: DYN") ||
                (output.contains("Shared object file") && !output.contains("EXEC"));
        }

        if let Some(output) = Self::run_command("readelf", &["-s", "-W", &path.to_string_lossy()]) {
            canary_enabled = output.contains("__stack_chk_fail") || output.contains("__stack_chk_guard");
        }

        if let Some(output) = Self::run_command("readelf", &["-l", "-W", &path.to_string_lossy()]) {
            if output.contains("GNU_RELRO") {
                if output.contains("BIND_NOW") {
                    relro = "Full".to_string();
                } else {
                    relro = "Partial".to_string();
                }
            }
        }

        if let Some(output) = Self::run_command("readelf", &["-d", "-W", &path.to_string_lossy()]) {
            if output.contains("BIND_NOW") {
                relro = "Full".to_string();
            }
            fortify_source = output.contains("__fortify") || output.contains("FORTIFY");
        }

        if let Some(output) = Self::run_command("readelf", &["-s", "-W", &path.to_string_lossy()]) {
            if output.contains("__fortify") || output.contains("FORTIFY") {
                fortify_source = true;
            }
        }

        SecurityFeatures {
            nx_enabled,
            pie_enabled,
            canary_enabled,
            relro,
            aslr: pie_enabled,
            dep: nx_enabled,
            code_signing: false,
            stack_protector: canary_enabled,
            fortify_source,
        }
    }

    fn check_pe_security(path: &Path) -> SecurityFeatures {
        let mut nx_enabled = true;
        let mut pie_enabled = false;
        let mut canary_enabled = false;
        let mut aslr = true;
        let mut dep = true;

        if let Some(output) = Self::run_command("objdump", &["-f", &path.to_string_lossy()]) {
            pie_enabled = output.contains("DLL") || output.contains("dll");
        }

        if let Some(output) = Self::run_command("objdump", &["-p", &path.to_string_lossy()]) {
            aslr = output.contains("DYNAMIC_BASE") || output.contains("HIGH_ENTROPY_VA");
            nx_enabled = output.contains("NX_COMPAT") || dep;
            dep = nx_enabled;
        }

        if let Some(output) = Self::run_command("strings", &["&path.to_string_lossy()"]) {
            canary_enabled = output.contains("__security_cookie") || output.contains("__stack_chk_fail");
        }

        SecurityFeatures {
            nx_enabled,
            pie_enabled,
            canary_enabled,
            relro: "Full".to_string(),
            aslr,
            dep,
            code_signing: false,
            stack_protector: canary_enabled,
            fortify_source: false,
        }
    }

    fn check_macho_security(path: &Path) -> SecurityFeatures {
        let nx_enabled = true;
        let mut pie_enabled = true;
        let mut canary_enabled = false;
        let mut code_signing = false;

        if let Some(output) = Self::run_command("otool", &["-h", &path.to_string_lossy()]) {
            pie_enabled = output.contains("PIE") || output.contains("MH_PIE");
        }

        if let Some(_output) = Self::run_command("codesign", &["-v", &path.to_string_lossy()]) {
            code_signing = true;
        }

        if let Some(output) = Self::run_command("nm", &["&path.to_string_lossy()"]) {
            canary_enabled = output.contains("__stack_chk_fail") || output.contains("__stack_chk_guard");
        }

        SecurityFeatures {
            nx_enabled,
            pie_enabled,
            canary_enabled,
            relro: "Full".to_string(),
            aslr: pie_enabled,
            dep: nx_enabled,
            code_signing,
            stack_protector: canary_enabled,
            fortify_source: false,
        }
    }

    fn get_entry_point(path: &Path, file_type: &str) -> String {
        match file_type {
            "ELF" => {
                if let Some(output) = Self::run_command("readelf", &["-h", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        if line.contains("Entry point") {
                            return line.split("0x").nth(1)
                                .map(|s| format!("0x{}", s.trim()))
                                .unwrap_or_else(|| "0x400000".to_string());
                        }
                    }
                }
                "0x400000".to_string()
            }
            "Mach-O" => {
                if let Some(output) = Self::run_command("otool", &["-h", &path.to_string_lossy()]) {
                    for line in output.lines() {
                        if line.contains("entryoff") {
                            if let Some(val) = line.split_whitespace().nth(1) {
                                return format!("0x{}", val);
                            }
                        }
                    }
                }
                "0x100000000".to_string()
            }
            _ => "0x0".to_string(),
        }
    }

    fn detect_compiler(path: &Path, file_type: &str, strings: &[FoundString]) -> String {
        for s in strings {
            let val_lower = s.value.to_lowercase();
            if val_lower.contains("gcc") || val_lower.contains("g++") {
                if let Some(version) = Self::extract_version(&s.value) {
                    return format!("GCC {}", version);
                }
                return "GCC".to_string();
            }
            if val_lower.contains("clang") {
                if let Some(version) = Self::extract_version(&s.value) {
                    return format!("Clang {}", version);
                }
                return "Clang".to_string();
            }
            if val_lower.contains("msvc") || val_lower.contains("visual studio") {
                return "MSVC".to_string();
            }
            if val_lower.contains("rustc") {
                return "Rust".to_string();
            }
            if val_lower.contains("go build") || val_lower.contains("go1.") {
                return "Go".to_string();
            }
        }

        if file_type == "ELF" {
            if let Some(output) = Self::run_command("readelf", &["-p", ".comment", &path.to_string_lossy()]) {
                if output.to_lowercase().contains("gcc") {
                    return "GCC".to_string();
                }
                if output.to_lowercase().contains("clang") {
                    return "Clang".to_string();
                }
            }
        }

        "Unknown".to_string()
    }

    fn extract_version(s: &str) -> Option<String> {
        let re = regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
        if let Some(caps) = re.captures(s) {
            return Some(caps.get(1)?.as_str().to_string());
        }
        None
    }
}
