use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareAnalyzerConfig {
    pub firmware_path: String,
    pub vendor: String,
    pub model: String,
    pub extract_filesystem: bool,
    pub find_credentials: bool,
    pub analyze_binaries: bool,
    pub check_backdoors: bool,
}

impl Default for FirmwareAnalyzerConfig {
    fn default() -> Self {
        Self {
            firmware_path: String::new(),
            vendor: String::new(),
            model: String::new(),
            extract_filesystem: true,
            find_credentials: true,
            analyze_binaries: true,
            check_backdoors: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareInfo {
    pub vendor: String,
    pub model: String,
    pub version: String,
    pub architecture: String,
    pub file_size: u64,
    pub file_type: String,
    pub checksum: String,
    pub build_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwarePartition {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub file_system: String,
    pub is_readable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareCredential {
    pub credential_type: String,
    pub username: String,
    pub password: String,
    pub location: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareBinary {
    pub name: String,
    pub path: String,
    pub architecture: String,
    pub is_stripped: bool,
    pub has_stack_canary: bool,
    pub has_nx: bool,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareBackdoor {
    pub backdoor_type: String,
    pub description: String,
    pub location: String,
    pub severity: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareSecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareAnalyzerResult {
    pub success: bool,
    pub firmware_info: FirmwareInfo,
    pub partitions: Vec<FirmwarePartition>,
    pub credentials: Vec<FirmwareCredential>,
    pub binaries: Vec<FirmwareBinary>,
    pub backdoors: Vec<FirmwareBackdoor>,
    pub security_findings: Vec<FirmwareSecurityFinding>,
    pub summary: String,
}

pub struct FirmwareAnalyzerTool;

impl FirmwareAnalyzerTool {
    pub async fn analyze(config: &FirmwareAnalyzerConfig) -> Result<FirmwareAnalyzerResult, String> {
        if config.firmware_path.is_empty() {
            return Err("Firmware file path is required".to_string());
        }

        let path = std::path::Path::new(&config.firmware_path);
        if !path.exists() {
            return Err(format!("Firmware file not found: {}", config.firmware_path));
        }

        let mut partitions = Vec::new();
        let mut credentials = Vec::new();
        let mut binaries = Vec::new();
        let mut backdoors = Vec::new();
        let mut security_findings = Vec::new();

        let firmware_info = Self::analyze_firmware_info(config, path)?;

        if config.extract_filesystem {
            partitions = Self::extract_partitions(&config.firmware_path, &firmware_info);
        }

        let extracted_strings = Self::extract_strings_from_file(&config.firmware_path);

        if config.find_credentials {
            credentials = Self::find_credentials_in_strings(&extracted_strings);
            if !credentials.is_empty() {
                security_findings.push(FirmwareSecurityFinding {
                    severity: "critical".to_string(),
                    category: "hardcoded_credentials".to_string(),
                    description: format!("Found {} hardcoded credentials", credentials.len()),
                    recommendation: "Change default passwords and enforce strong password policies".to_string(),
                });
            }
        }

        if config.analyze_binaries {
            binaries = Self::analyze_binaries_in_file(&config.firmware_path, &extracted_strings);
            let no_canary = binaries.iter().filter(|b| !b.has_stack_canary).count();
            let no_nx = binaries.iter().filter(|b| !b.has_nx).count();
            if no_canary > 0 {
                security_findings.push(FirmwareSecurityFinding {
                    severity: "high".to_string(),
                    category: "binary_security".to_string(),
                    description: format!("{} binaries lack Stack Canary protection", no_canary),
                    recommendation: "Recompile with -fstack-protector-all flag to enable Stack Canary protection".to_string(),
                });
            }
            if no_nx > 0 {
                security_findings.push(FirmwareSecurityFinding {
                    severity: "high".to_string(),
                    category: "binary_security".to_string(),
                    description: format!("{} binaries lack NX (No-Execute) protection", no_nx),
                    recommendation: "Recompile with NX bit enabled to prevent code execution on the stack".to_string(),
                });
            }
            let stripped = binaries.iter().filter(|b| b.is_stripped).count();
            if stripped > 0 {
                security_findings.push(FirmwareSecurityFinding {
                    severity: "medium".to_string(),
                    category: "information_disclosure".to_string(),
                    description: format!("{} binaries are stripped, making security analysis difficult", stripped),
                    recommendation: "Provide unstripped binaries for security auditing when possible".to_string(),
                });
            }
        }

        if config.check_backdoors {
            backdoors = Self::detect_backdoors(&extracted_strings);
            if !backdoors.is_empty() {
                let critical_backdoors = backdoors.iter().filter(|b| b.severity == "critical").count();
                if critical_backdoors > 0 {
                    security_findings.push(FirmwareSecurityFinding {
                        severity: "critical".to_string(),
                        category: "backdoor_detection".to_string(),
                        description: format!("Found {} critical backdoor indicators", critical_backdoors),
                        recommendation: "Remove backdoor code, re-audit firmware supply chain, and verify firmware integrity".to_string(),
                    });
                }
                let high_backdoors = backdoors.iter().filter(|b| b.severity == "high").count();
                if high_backdoors > 0 {
                    security_findings.push(FirmwareSecurityFinding {
                        severity: "high".to_string(),
                        category: "backdoor_detection".to_string(),
                        description: format!("Found {} high-severity suspicious indicators", high_backdoors),
                        recommendation: "Review flagged indicators and verify they are not malicious".to_string(),
                    });
                }
            }
        }

        Self::detect_crypto_issues(&extracted_strings, &mut security_findings);
        Self::detect_info_disclosure(&extracted_strings, &mut security_findings);

        let critical = security_findings.iter().filter(|f| f.severity == "critical").count();
        let summary = if critical > 0 {
            format!("Firmware analysis complete: {} partitions, {} credentials, {} backdoors, {} critical findings", partitions.len(), credentials.len(), backdoors.len(), critical)
        } else {
            format!("Firmware analysis complete: {} partitions, {} credentials, no critical findings", partitions.len(), credentials.len())
        };

        Ok(FirmwareAnalyzerResult {
            success: true,
            firmware_info,
            partitions,
            credentials,
            binaries,
            backdoors,
            security_findings,
            summary,
        })
    }

    fn analyze_firmware_info(config: &FirmwareAnalyzerConfig, path: &std::path::Path) -> Result<FirmwareInfo, String> {
        let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let file_type = Self::detect_file_type(path);
        let checksum = Self::compute_checksum(path);
        let architecture = Self::detect_architecture(path);
        let version = Self::detect_version(path);
        let build_date = Self::detect_build_date(path);

        Ok(FirmwareInfo {
            vendor: if config.vendor.is_empty() { Self::detect_vendor(path) } else { config.vendor.clone() },
            model: if config.model.is_empty() { Self::detect_model(path) } else { config.model.clone() },
            version,
            architecture,
            file_size,
            file_type,
            checksum,
            build_date,
        })
    }

    fn detect_file_type(path: &std::path::Path) -> String {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes.len() >= 4 {
                if &bytes[0..2] == b"PK" {
                    return "ZIP Archive (Firmware Package)".to_string();
                }
                if &bytes[0..4] == b"\x7fELF" {
                    return "ELF Binary".to_string();
                }
                if &bytes[0..2] == b"MZ" {
                    return "PE Binary".to_string();
                }
                if bytes.len() >= 8 && &bytes[0..8] == b"\xd0\x0d\xfe\xed\x00\x00\x00\x01" {
                    return "U-Boot Image".to_string();
                }
                if bytes.len() >= 4 && &bytes[0..4] == b"\x27\x05\x19\x56" {
                    return "U-Boot Legacy Image".to_string();
                }
                if bytes.len() >= 4 && &bytes[0..4] == b"hsqs" {
                    return "SquashFS Filesystem".to_string();
                }
                if bytes.len() >= 4 && &bytes[0..4] == b"\x85\x19\x03\x20" {
                    return "JFFS2 Filesystem".to_string();
                }
                if bytes.len() >= 6 && &bytes[0..6] == b"\x3c\x61\x21\x3c\x61\x21" {
                    return "CramFS Filesystem".to_string();
                }
                if bytes.len() >= 4 && &bytes[0..4] == b"BZh9" {
                    return "Bzip2 Compressed".to_string();
                }
                if bytes.len() >= 3 && &bytes[0..3] == b"\x1f\x8b\x08" {
                    return "Gzip Compressed".to_string();
                }
                if bytes.len() >= 4 && &bytes[0..4] == b"\xfd\x37\x7a\x58" {
                    return "XZ Compressed".to_string();
                }
                if bytes.len() >= 6 && &bytes[0..6] == b"070701" {
                    return "CPIO Archive".to_string();
                }
                if bytes.len() >= 6 && &bytes[0..6] == b"070707" {
                    return "CPIO Archive (ODC)".to_string();
                }
                if bytes.len() >= 4 && &bytes[0..4] == b"\x28\xb5\x2f\xfd" {
                    return "Zstandard Compressed".to_string();
                }
            }
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                "bin" => return "Binary Firmware Image".to_string(),
                "img" => return "Disk/Firmware Image".to_string(),
                "fw" => return "Firmware Package".to_string(),
                "trx" => return "TRX Firmware (ASUS/Broadcom)".to_string(),
                "chk" => return "CHK Firmware (Netgear)".to_string(),
                "wrt" => return "WRT Firmware".to_string(),
                "pat" => return "PAT Firmware (Synology)".to_string(),
                _ => {}
            }
        }

        "Unknown Format".to_string()
    }

    fn compute_checksum(path: &std::path::Path) -> String {
        if let Ok(output) = std::process::Command::new("shasum")
            .args(["-a", "256", path.to_str().unwrap_or("")])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(hash) = stdout.split_whitespace().next() {
                return hash.to_string();
            }
        }

        if let Ok(output) = std::process::Command::new("sha256sum")
            .arg(path.to_str().unwrap_or(""))
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(hash) = stdout.split_whitespace().next() {
                return hash.to_string();
            }
        }

        "N/A (sha256sum not available)".to_string()
    }

    fn detect_architecture(path: &std::path::Path) -> String {
        if let Ok(output) = std::process::Command::new("file")
            .arg(path.to_str().unwrap_or(""))
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if stdout.contains("mips") { return "MIPS".to_string(); }
            if stdout.contains("arm") { return "ARM".to_string(); }
            if stdout.contains("aarch64") { return "AArch64".to_string(); }
            if stdout.contains("x86-64") || stdout.contains("x86_64") { return "x86_64".to_string(); }
            if stdout.contains("80386") || stdout.contains("i386") { return "x86".to_string(); }
            if stdout.contains("powerpc") || stdout.contains("ppc") { return "PowerPC".to_string(); }
            if stdout.contains("risc-v") || stdout.contains("riscv") { return "RISC-V".to_string(); }
        }

        if let Ok(bytes) = std::fs::read(path) {
            if bytes.len() >= 20 {
                if bytes[4..8] == [0x02, 0x00, 0x00, 0x00] { return "MIPS".to_string(); }
                if bytes[4..8] == [0x00, 0x02, 0x00, 0x00] { return "MIPS (BE)".to_string(); }
                if bytes[4..8] == [0x28, 0x00, 0x00, 0x00] { return "ARM".to_string(); }
                if bytes[4..8] == [0xb7, 0x00, 0x00, 0x00] { return "AArch64".to_string(); }
            }
        }

        "Unknown".to_string()
    }

    fn detect_version(path: &std::path::Path) -> String {
        if let Ok(output) = std::process::Command::new("strings")
            .args(["-n", "5", path.to_str().unwrap_or("")])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let version_patterns = ["version", "Version", "VERSION", "ver=", "v=", "release", "Release"];
            for line in stdout.lines().take(5000) {
                let line = line.trim();
                for pattern in &version_patterns {
                    if line.to_lowercase().contains(&pattern.to_lowercase()) {
                        if line.len() < 100 && (line.contains('.') || line.contains('-')) {
                            return line.to_string();
                        }
                    }
                }
            }
        }
        "Unknown".to_string()
    }

    fn detect_build_date(path: &std::path::Path) -> Option<String> {
        if let Ok(output) = std::process::Command::new("strings")
            .args(["-n", "8", path.to_str().unwrap_or("")])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let date_patterns = ["2020", "2021", "2022", "2023", "2024", "2025", "2026"];
            for line in stdout.lines().take(5000) {
                let line = line.trim();
                for year in &date_patterns {
                    if line.contains(year) && (line.contains('-') || line.contains('/')) && line.len() < 60 {
                        let lower = line.to_lowercase();
                        if lower.contains("date") || lower.contains("build") || lower.contains("compile") || lower.contains("time") {
                            return Some(line.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_vendor(path: &std::path::Path) -> String {
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
        let vendor_map: HashMap<&str, &str> = [
            ("asus", "ASUS"), ("netgear", "Netgear"), ("tp-link", "TP-Link"),
            ("tplink", "TP-Link"), ("dlink", "D-Link"), ("linksys", "Linksys"),
            ("cisco", "Cisco"), ("huawei", "Huawei"), ("zte", "ZTE"),
            ("mikrotik", "MikroTik"), ("ubnt", "Ubiquiti"), ("openwrt", "OpenWrt"),
            ("ddwrt", "DD-WRT"), ("synology", "Synology"), ("qnap", "QNAP"),
        ].iter().cloned().collect();

        for (key, vendor) in &vendor_map {
            if filename.contains(key) {
                return vendor.to_string();
            }
        }

        if let Ok(output) = std::process::Command::new("strings")
            .args(["-n", "5", path.to_str().unwrap_or("")])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().take(2000) {
                let line_lower = line.trim().to_lowercase();
                for (key, vendor) in &vendor_map {
                    if line_lower.contains(key) {
                        return vendor.to_string();
                    }
                }
            }
        }

        "Unknown".to_string()
    }

    fn detect_model(path: &std::path::Path) -> String {
        let filename = path.file_stem().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if !filename.is_empty() && filename != "firmware" {
            return filename;
        }
        "Unknown".to_string()
    }

    fn extract_strings_from_file(firmware_path: &str) -> Vec<String> {
        let mut strings = Vec::new();

        if let Ok(output) = std::process::Command::new("strings")
            .args(["-n", "6", firmware_path])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().take(10000) {
                let s = line.trim().to_string();
                if !s.is_empty() {
                    strings.push(s);
                }
            }
        }

        strings
    }

    fn extract_partitions(firmware_path: &str, info: &FirmwareInfo) -> Vec<FirmwarePartition> {
        let mut partitions = Vec::new();

        if let Ok(output) = std::process::Command::new("binwalk")
            .arg(firmware_path)
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("DECIMAL") || line.starts_with("---") {
                    continue;
                }
                let parts: Vec<&str> = line.splitn(4, |c: char| c.is_whitespace()).collect();
                if parts.len() >= 3 {
                    let offset = parts[0].parse::<u64>().unwrap_or(0);
                    let hex_offset = parts[1].trim_start_matches("0x").trim_start_matches("0X");
                    let _hex_val = u64::from_str_radix(hex_offset, 16).unwrap_or(0);
                    let description = if parts.len() > 3 { parts[3..].join(" ") } else { parts[2..].join(" ") };

                    let fs_type = if description.to_lowercase().contains("squashfs") { "squashfs" }
                        else if description.to_lowercase().contains("jffs2") { "jffs2" }
                        else if description.to_lowercase().contains("cramfs") { "cramfs" }
                        else if description.to_lowercase().contains("ubifs") { "ubifs" }
                        else if description.to_lowercase().contains("ext2") || description.to_lowercase().contains("ext3") || description.to_lowercase().contains("ext4") { "ext4" }
                        else if description.to_lowercase().contains("cpio") { "cpio" }
                        else if description.to_lowercase().contains("u-boot") { "raw" }
                        else if description.to_lowercase().contains("kernel") || description.to_lowercase().contains("linux") { "raw" }
                        else { "raw" };

                    let name = if description.to_lowercase().contains("u-boot") || description.to_lowercase().contains("bootloader") { "bootloader" }
                        else if description.to_lowercase().contains("kernel") || description.to_lowercase().contains("linux") { "kernel" }
                        else if description.to_lowercase().contains("rootfs") || description.to_lowercase().contains("squashfs") || description.to_lowercase().contains("jffs2") { "rootfs" }
                        else if description.to_lowercase().contains("user") { "user" }
                        else { "partition" };

                    partitions.push(FirmwarePartition {
                        name: name.to_string(),
                        offset,
                        size: 0,
                        file_system: fs_type.to_string(),
                        is_readable: fs_type != "raw",
                    });
                }
            }
        }

        if partitions.is_empty() {
            let file_size = info.file_size;
            if file_size > 0 {
                partitions.push(FirmwarePartition {
                    name: "firmware".to_string(),
                    offset: 0,
                    size: file_size,
                    file_system: info.file_type.split_whitespace().next().unwrap_or("raw").to_lowercase(),
                    is_readable: true,
                });
            }
        }

        partitions
    }

    fn find_credentials_in_strings(strings: &[String]) -> Vec<FirmwareCredential> {
        let mut credentials = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let password_patterns: [(&str, &str); 14] = [
            ("password=", "Config Password"),
            ("passwd=", "Config Password"),
            ("PASSWORD=", "Config Password"),
            ("admin:", "Default Admin"),
            ("root:", "Default Root"),
            ("user=", "Config User"),
            ("USER=", "Config User"),
            ("secret=", "Secret Key"),
            ("SECRET=", "Secret Key"),
            ("default_password", "Default Password"),
            ("pass=", "Config Password"),
            ("PASS=", "Config Password"),
            ("token=", "API Token"),
            ("TOKEN=", "API Token"),
        ];

        for s in strings {
            let lower = s.to_lowercase();
            for (pattern, cred_type) in &password_patterns {
                if lower.contains(&pattern.to_lowercase()) && !seen.contains(s) {
                    let value = if s.contains('=') {
                        s.split('=').last().unwrap_or(s).trim().to_string()
                    } else if s.contains(':') {
                        s.split(':').last().unwrap_or(s).trim().to_string()
                    } else {
                        s.trim().to_string()
                    };

                    if value.is_empty() || value.len() > 100 {
                        continue;
                    }

                    let is_weak = value == "admin" || value == "root" || value == "password"
                        || value == "123456" || value == "1234" || value == "12345"
                        || value == "default" || value == "test" || value == "guest"
                        || value == "000000" || value == "111111" || value == "pass"
                        || value == "letmein" || value == "welcome" || value == "changeme";

                    let severity = if is_weak { "critical" }
                        else if value.len() < 6 { "high" }
                        else if value.len() < 8 { "medium" }
                        else { "low" };

                    let location = Self::guess_location(s);
                    let username = if s.contains("admin:") {
                        "admin".to_string()
                    } else if s.contains("root:") {
                        "root".to_string()
                    } else {
                        String::new()
                    };

                    credentials.push(FirmwareCredential {
                        credential_type: cred_type.to_string(),
                        username,
                        password: value,
                        location,
                        severity: severity.to_string(),
                    });
                    seen.insert(s.clone());
                }
            }
        }

        let common_defaults: [(&str, &str, &str); 14] = [
            ("admin", "admin", "Web UI"),
            ("admin", "password", "Web UI"),
            ("admin", "admin123", "Web UI"),
            ("admin", "12345", "Web UI"),
            ("root", "root", "Telnet/SSH"),
            ("root", "toor", "Telnet/SSH"),
            ("root", "password", "Telnet/SSH"),
            ("user", "user", "Web UI"),
            ("guest", "guest", "Web UI"),
            ("support", "support", "Support Console"),
            ("daemon", "daemon", "System Service"),
            ("operator", "operator", "Network Equipment"),
            ("super", "super", "Superuser Account"),
            ("manager", "manager", "Network Management"),
        ];

        for s in strings {
            for (username, password, cred_type) in &common_defaults {
                let combined = format!("{}:{}", username, password);
                if s.contains(&combined) && !seen.contains(&combined) {
                    credentials.push(FirmwareCredential {
                        credential_type: cred_type.to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        location: Self::guess_location(s),
                        severity: "critical".to_string(),
                    });
                    seen.insert(combined);
                }
            }
        }

        credentials.truncate(50);
        credentials
    }

    fn guess_location(s: &str) -> String {
        let lower = s.to_lowercase();
        if lower.contains("/etc/passwd") || lower.contains("/etc/shadow") { return "/etc/passwd".to_string(); }
        if lower.contains("/etc/config/") { return "/etc/config/".to_string(); }
        if lower.contains("/etc/init.d/") { return "/etc/init.d/".to_string(); }
        if lower.contains("wireless") || lower.contains("wifi") { return "/etc/config/wireless".to_string(); }
        if lower.contains("httpd") || lower.contains("nginx") || lower.contains("lighttpd") { return "/etc/web/".to_string(); }
        if lower.contains("telnet") { return "/etc/telnet".to_string(); }
        if lower.contains("shadow") { return "/etc/shadow".to_string(); }
        if lower.contains("ssh") || lower.contains("sshd") { return "/etc/ssh/".to_string(); }
        if lower.contains("vpn") || lower.contains("openvpn") { return "/etc/vpn/".to_string(); }
        if lower.contains("database") || lower.contains("db") { return "/var/db/".to_string(); }
        "configuration file".to_string()
    }

    fn analyze_binaries_in_file(firmware_path: &str, strings: &[String]) -> Vec<FirmwareBinary> {
        let mut binaries = Vec::new();

        let common_binaries = [
            "busybox", "httpd", "dnsmasq", "dropbear", "openssl",
            "wpa_supplicant", "hostapd", "iptables", "ip", "ifconfig",
            "ping", "traceroute", "curl", "wget", "ssh", "sshd",
            "telnetd", "ftpd", "nginx", "lighttpd", "p910nd",
        ];

        let mut has_canary_global = false;
        let mut has_nx_global = false;
        let mut has_symtab_global = false;
        for st in strings {
            if st.contains("__stack_chk_fail") || st.contains("__stack_chk_guard") {
                has_canary_global = true;
            }
            if st.contains("GNU_STACK") {
                has_nx_global = true;
            }
            if st.contains(".symtab") {
                has_symtab_global = true;
            }
        }

        for s in strings {
            let lower = s.to_lowercase();
            for binary in &common_binaries {
                if lower.contains(binary) && !binaries.iter().any(|b: &FirmwareBinary| b.name == *binary) {
                    let path = if lower.contains("/bin/") || lower.contains("/sbin/") || lower.contains("/usr/") {
                        s.clone()
                    } else {
                        format!("/usr/sbin/{}", binary)
                    };

                    let is_stripped = !has_symtab_global;

                    let has_stack_canary = has_canary_global;

                    let has_nx = has_nx_global;

                    let severity = if !has_stack_canary && !has_nx && is_stripped { "critical" }
                        else if !has_stack_canary || !has_nx { "high" }
                        else if is_stripped { "medium" }
                        else { "low" };

                    let arch = if lower.contains("mips") { "MIPS" }
                        else if lower.contains("arm") { "ARM" }
                        else if lower.contains("aarch64") { "AArch64" }
                        else if lower.contains("x86_64") || lower.contains("x86-64") { "x86_64" }
                        else { "detected" };

                    binaries.push(FirmwareBinary {
                        name: binary.to_string(),
                        path,
                        architecture: arch.to_string(),
                        is_stripped,
                        has_stack_canary,
                        has_nx,
                        severity: severity.to_string(),
                    });
                }
            }
        }

        if let Ok(output) = std::process::Command::new("file")
            .arg(firmware_path)
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if stdout.contains("elf") && binaries.is_empty() {
                let is_stripped = stdout.contains("stripped");
                let has_stack_canary = has_canary_global;
                let has_nx = has_nx_global;

                let severity = if !has_stack_canary && !has_nx && is_stripped { "critical" }
                    else if !has_stack_canary || !has_nx { "high" }
                    else if is_stripped { "medium" }
                    else { "low" };

                let arch = if stdout.contains("mips") { "MIPS" }
                    else if stdout.contains("arm") { "ARM" }
                    else if stdout.contains("aarch64") { "AArch64" }
                    else if stdout.contains("x86-64") || stdout.contains("x86_64") { "x86_64" }
                    else { "Unknown" };

                binaries.push(FirmwareBinary {
                    name: firmware_path.split('/').last().unwrap_or("firmware").to_string(),
                    path: firmware_path.to_string(),
                    architecture: arch.to_string(),
                    is_stripped,
                    has_stack_canary,
                    has_nx,
                    severity: severity.to_string(),
                });
            }
        }

        binaries.truncate(30);
        binaries
    }

    fn detect_backdoors(strings: &[String]) -> Vec<FirmwareBackdoor> {
        let mut backdoors = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let backdoor_patterns: [(&str, &str, &str, &str); 16] = [
            ("telnetd", "Debug Backdoor", "Telnet daemon detected, may allow remote command execution", "critical"),
            ("backdoor", "Backdoor", "Backdoor-related string found", "critical"),
            ("reverse_shell", "Reverse Shell", "Reverse shell indicator found", "critical"),
            ("/dev/tcp/", "Network Shell", "Network shell indicator found", "critical"),
            ("nc -l", "Netcat Listener", "Netcat listen command found", "critical"),
            ("rm -rf /", "Destructive Command", "Destructive command found", "critical"),
            ("chmod 777", "Excessive Permissions", "chmod 777 permission setting found", "medium"),
            ("wget", "Download Command", "wget download command found in firmware", "medium"),
            ("curl", "Download Command", "curl download command found in firmware", "medium"),
            ("hardcoded key", "Hardcoded Key", "Hardcoded encryption key found", "high"),
            ("shellshock", "Shellshock", "Shellshock vulnerability indicator found", "critical"),
            ("/bin/sh -i", "Interactive Shell", "Interactive shell spawn indicator found", "critical"),
            ("nc -e", "Netcat Exec", "Netcat with execute flag found, potential reverse shell", "critical"),
            ("socat exec", "Socat Exec", "Socat execute pattern found, potential reverse shell", "critical"),
            ("python -c", "Python Exec", "Python one-liner execution found, potential reverse shell", "high"),
            ("perl -e", "Perl Exec", "Perl one-liner execution found, potential reverse shell", "high"),
        ];

        for s in strings {
            let lower = s.to_lowercase();
            for (pattern, bd_type, description, severity) in &backdoor_patterns {
                if lower.contains(pattern) && !seen.contains(*pattern) {
                    let indicators = vec![pattern.to_string()];
                    backdoors.push(FirmwareBackdoor {
                        backdoor_type: bd_type.to_string(),
                        description: description.to_string(),
                        location: s.clone(),
                        severity: severity.to_string(),
                        indicators,
                    });
                    seen.insert(*pattern);
                }
            }
        }

        for s in strings {
            let lower = s.to_lowercase();
            if (lower.contains("wget") || lower.contains("curl")) && lower.contains("|") && lower.contains("sh") && !seen.contains("pipe_to_sh") {
                backdoors.push(FirmwareBackdoor {
                    backdoor_type: "Remote Execution".to_string(),
                    description: "Download and pipe to shell command found".to_string(),
                    location: s.clone(),
                    severity: "critical".to_string(),
                    indicators: vec!["wget|sh or curl|sh".to_string()],
                });
                seen.insert("pipe_to_sh");
            }
        }

        for s in strings {
            let lower = s.to_lowercase();
            if lower.contains("debug") && (lower.contains("enable") || lower.contains("start") || lower.contains("mode")) && !seen.contains("debug_enable") {
                backdoors.push(FirmwareBackdoor {
                    backdoor_type: "Debug Interface".to_string(),
                    description: "Debug mode enable command found, may expose sensitive interfaces".to_string(),
                    location: s.clone(),
                    severity: "high".to_string(),
                    indicators: vec!["debug enable/start/mode".to_string()],
                });
                seen.insert("debug_enable");
            }
        }

        backdoors.truncate(20);
        backdoors
    }

    fn detect_crypto_issues(strings: &[String], findings: &mut Vec<FirmwareSecurityFinding>) {
        let mut weak_crypto_found = false;
        let mut _hardcoded_key_found = false;

        let weak_crypto_patterns = ["des", "rc4", "md5", "sha1"];
        for s in strings {
            let lower = s.to_lowercase();
            for pattern in &weak_crypto_patterns {
                if lower.contains(pattern) && !weak_crypto_found {
                    weak_crypto_found = true;
                    findings.push(FirmwareSecurityFinding {
                        severity: "high".to_string(),
                        category: "weak_crypto".to_string(),
                        description: "Weak cryptographic algorithm detected in firmware".to_string(),
                        recommendation: "Replace weak algorithms (DES, RC4, MD5, SHA1) with strong alternatives (AES-256, SHA-256+)".to_string(),
                    });
                    break;
                }
            }
            if weak_crypto_found {
                break;
            }
        }

        for s in strings {
            let lower = s.to_lowercase();
            if (lower.contains("aes_key") || lower.contains("encryption_key") || lower.contains("private_key"))
                && !_hardcoded_key_found
            {
                _hardcoded_key_found = true;
                findings.push(FirmwareSecurityFinding {
                    severity: "critical".to_string(),
                    category: "weak_crypto".to_string(),
                    description: "Hardcoded encryption key reference detected".to_string(),
                    recommendation: "Use hardware secure element or key derivation functions instead of hardcoded keys".to_string(),
                });
                break;
            }
        }
    }

    fn detect_info_disclosure(strings: &[String], findings: &mut Vec<FirmwareSecurityFinding>) {
        let mut debug_symbols_found = false;
        let mut version_disclosure = false;

        for s in strings {
            let lower = s.to_lowercase();
            if (lower.contains("debug") || lower.contains("verbose") || lower.contains("trace"))
                && !debug_symbols_found
                && (lower.contains("enable") || lower.contains("mode") || lower.contains("log"))
            {
                debug_symbols_found = true;
                findings.push(FirmwareSecurityFinding {
                    severity: "medium".to_string(),
                    category: "information_disclosure".to_string(),
                    description: "Debug/verbose logging interface detected in firmware".to_string(),
                    recommendation: "Disable debug interfaces in production firmware to prevent information leakage".to_string(),
                });
            }

            if (lower.contains("server:") || lower.contains("x-powered-by"))
                && !version_disclosure
            {
                version_disclosure = true;
                findings.push(FirmwareSecurityFinding {
                    severity: "low".to_string(),
                    category: "information_disclosure".to_string(),
                    description: "Server version disclosure detected in firmware".to_string(),
                    recommendation: "Configure server to suppress version headers (Server, X-Powered-By)".to_string(),
                });
            }

            if debug_symbols_found && version_disclosure {
                break;
            }
        }
    }
}
