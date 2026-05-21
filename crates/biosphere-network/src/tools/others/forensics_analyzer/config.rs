use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::SystemTime;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsAnalyzerConfig {
    pub file_path: String,
    pub analyze_filesystem: bool,
    pub analyze_memory: bool,
    pub analyze_network: bool,
    pub analyze_timeline: bool,
    pub analyze_registry: bool,
    pub recover_deleted: bool,
    pub extract_metadata: bool,
    pub check_anti_forensics: bool,
    pub timeout: u64,
}

impl Default for ForensicsAnalyzerConfig {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            analyze_filesystem: true,
            analyze_memory: true,
            analyze_network: true,
            analyze_timeline: true,
            analyze_registry: false,
            recover_deleted: true,
            extract_metadata: true,
            check_anti_forensics: true,
            timeout: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemInfo {
    pub file_system_type: String,
    pub total_size: u64,
    pub used_size: u64,
    pub file_count: u64,
    pub hidden_files: u64,
    pub encrypted_files: u64,
    pub suspicious_files: Vec<SuspiciousFile>,
    pub deleted_recoverable: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFile {
    pub path: String,
    pub reason: String,
    pub size: u64,
    pub modified_time: String,
    pub risk_level: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAnalysis {
    pub process_count: u32,
    pub suspicious_processes: Vec<ProcessInfo>,
    pub injected_dlls: Vec<String>,
    pub hidden_processes: Vec<String>,
    pub network_connections: Vec<NetworkConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub user: String,
    pub memory_mb: f64,
    pub suspicious: bool,
    pub reason: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub process: String,
    pub suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub source: String,
    pub significance: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInfo {
    pub run_keys: Vec<RegistryEntry>,
    pub services: Vec<RegistryEntry>,
    pub suspicious_entries: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub key: String,
    pub value: String,
    pub data: String,
    pub suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiForensicsIndicator {
    pub technique: String,
    pub description: String,
    pub detected: bool,
    pub evidence: String,
    pub severity: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsAnalyzerResult {
    pub success: bool,
    pub file_path: String,
    pub filesystem_info: FilesystemInfo,
    pub memory_analysis: MemoryAnalysis,
    pub timeline: Vec<TimelineEntry>,
    pub registry_info: RegistryInfo,
    pub anti_forensics_indicators: Vec<AntiForensicsIndicator>,
    pub recovered_artifacts: u64,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub summary: String,
}

pub struct ForensicsAnalyzerTool;

impl ForensicsAnalyzerTool {
    pub async fn analyze(config: &ForensicsAnalyzerConfig) -> std::result::Result<ForensicsAnalyzerResult, String> {
        if config.file_path.is_empty() {
            return Err("File/disk path is required".to_string());
        }

        let file_path = config.file_path.trim().to_string();
        let path = Path::new(&file_path);
        if !path.exists() {
            return Err(format!("Path does not exist: {}", file_path));
        }

        let filesystem_info = if config.analyze_filesystem {
            Self::analyze_filesystem(&file_path)
        } else {
            FilesystemInfo {
                file_system_type: String::new(), total_size: 0, used_size: 0,
                file_count: 0, hidden_files: 0, encrypted_files: 0,
                suspicious_files: vec![], deleted_recoverable: 0,
            }
        };

        let memory_analysis = if config.analyze_memory {
            Self::analyze_memory()
        } else {
            MemoryAnalysis {
                process_count: 0, suspicious_processes: vec![], injected_dlls: vec![],
                hidden_processes: vec![], network_connections: vec![],
            }
        };

        let timeline = if config.analyze_timeline {
            Self::build_timeline(&filesystem_info, &memory_analysis)
        } else {
            vec![]
        };

        let registry_info = if config.analyze_registry {
            Self::analyze_registry()
        } else {
            RegistryInfo { run_keys: vec![], services: vec![], suspicious_entries: vec![] }
        };

        let anti_forensics = if config.check_anti_forensics {
            Self::check_anti_forensics(&file_path, &filesystem_info)
        } else {
            vec![]
        };

        let total_findings = filesystem_info.suspicious_files.len()
            + memory_analysis.suspicious_processes.len()
            + registry_info.suspicious_entries.len()
            + anti_forensics.iter().filter(|a| a.detected).count();

        let critical_findings = filesystem_info.suspicious_files.iter().filter(|f| f.risk_level == "critical").count()
            + memory_analysis.suspicious_processes.iter().filter(|p| p.suspicious).count()
            + anti_forensics.iter().filter(|a| a.detected && a.severity == "critical").count();

        let recovered_artifacts = if config.recover_deleted { filesystem_info.deleted_recoverable } else { 0 };

        let summary = format!(
            "Forensics Analysis: Path={}, Suspicious Files={}, Suspicious Processes={}, Anti-Forensics={}, Total Findings={}, Critical={}",
            file_path, filesystem_info.suspicious_files.len(),
            memory_analysis.suspicious_processes.len(),
            anti_forensics.iter().filter(|a| a.detected).count(),
            total_findings, critical_findings
        );

        Ok(ForensicsAnalyzerResult {
            success: true,
            file_path,
            filesystem_info,
            memory_analysis,
            timeline,
            registry_info,
            anti_forensics_indicators: anti_forensics,
            recovered_artifacts,
            total_findings,
            critical_findings,
            summary,
        })
    }

    fn analyze_filesystem(path: &str) -> FilesystemInfo {
        let root = Path::new(path);
        let mut file_count: u64 = 0;
        let mut hidden_files: u64 = 0;
        let mut encrypted_files: u64 = 0;
        let mut total_size: u64 = 0;
        let mut suspicious_files: Vec<SuspiciousFile> = Vec::new();
        let mut file_system_type = "Unknown".to_string();

        if let Ok(metadata) = root.metadata() {
            total_size = metadata.len();
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(metadata) = root.metadata() {
                let dev = metadata.dev();
                file_system_type = format!("Device {}", dev);
            }
            if let Ok(entries) = std::fs::read_dir("/proc/mounts") {
                let _ = entries;
            }
            if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
                for line in mounts.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let mount_point = parts[1];
                        let fs_type = parts[2];
                        if path.starts_with(mount_point) || mount_point == "/" {
                            file_system_type = fs_type.to_string();
                        }
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            file_system_type = "NTFS".to_string();
        }

        let suspicious_names = [
            (".hidden_shell", "Hidden file with shell-like name - possible backdoor", "critical", "T1059"),
            ("..cache", "Abnormal directory name with double dots - possible data hiding", "high", "T1564"),
            (".ssh/authorized_keys", "SSH authorized keys file - check for unauthorized entries", "medium", "T1098"),
            (".bash_history", "Bash history file - may contain executed commands", "low", "T1059"),
            (".wget-hsts", "Wget HSTS file - indicates download activity", "low", "T1105"),
        ];

        let suspicious_extensions = [
            (".exe", "Windows executable on non-Windows system", "medium", "T1204"),
            (".dll", "Windows DLL file - check for injection", "high", "T1055"),
            (".ps1", "PowerShell script - may contain malicious commands", "medium", "T1059"),
            (".vbs", "VBScript file - commonly used in malware", "medium", "T1059"),
            (".bat", "Batch script - may contain malicious commands", "medium", "T1059"),
            (".sh", "Shell script - check for malicious commands", "low", "T1059"),
            (".py", "Python script - check for malicious code", "low", "T1059"),
            (".php", "PHP script - may be web shell", "medium", "T1505"),
            (".jsp", "JSP script - may be web shell", "medium", "T1505"),
            (".asp", "ASP script - may be web shell", "medium", "T1505"),
        ];

        let encrypted_extensions = [".enc", ".gpg", ".aes", ".crypt", ".locked", ".crypto", ".encrypted"];

        let max_depth = 5;
        Self::walk_directory(root, &mut file_count, &mut hidden_files, &mut encrypted_files,
            &mut total_size, &mut suspicious_files, &suspicious_names, &suspicious_extensions,
            &encrypted_extensions, 0, max_depth);

        let deleted_recoverable = Self::estimate_recoverable_files(root);

        FilesystemInfo {
            file_system_type,
            total_size,
            used_size: total_size,
            file_count,
            hidden_files,
            encrypted_files,
            suspicious_files,
            deleted_recoverable,
        }
    }

    fn walk_directory(
        dir: &Path,
        file_count: &mut u64,
        hidden_files: &mut u64,
        encrypted_files: &mut u64,
        total_size: &mut u64,
        suspicious_files: &mut Vec<SuspiciousFile>,
        suspicious_names: &[(&str, &str, &str, &str)],
        suspicious_extensions: &[(&str, &str, &str, &str)],
        encrypted_extensions: &[&str],
        current_depth: usize,
        max_depth: usize,
    ) {
        if current_depth > max_depth { return; }

        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                if let Ok(metadata) = entry.metadata() {
                    *file_count += 1;
                    *total_size += metadata.len();

                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    #[cfg(unix)]
                    {
                        
                        if file_name.starts_with('.') {
                            *hidden_files += 1;
                        }
                    }

                    #[cfg(windows)]
                    {
                        if metadata.file_attributes() & 0x2 != 0 {
                            *hidden_files += 1;
                        }
                    }

                    for ext in encrypted_extensions {
                        if file_name.ends_with(ext) {
                            *encrypted_files += 1;
                            break;
                        }
                    }

                    let file_name_lower = file_name.to_lowercase();

                    for (name, reason, risk, mitre) in suspicious_names {
                        if file_name_lower.contains(name) {
                            let modified_time = metadata.modified()
                                .ok()
                                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                .map(|d| {
                                    let secs = d.as_secs();
                                    let days = secs / 86400;
                                    let time_of_day = secs % 86400;
                                    let hours = time_of_day / 3600;
                                    let minutes = (time_of_day % 3600) / 60;
                                    let seconds = time_of_day % 60;
                                    format!("{}-{:02}:{:02}:{:02}", days, hours, minutes, seconds)
                                })
                                .unwrap_or_else(|| "Unknown".to_string());

                            suspicious_files.push(SuspiciousFile {
                                path: path.display().to_string(),
                                reason: reason.to_string(),
                                size: metadata.len(),
                                modified_time,
                                risk_level: risk.to_string(),
                                mitre_id: mitre.to_string(),
                            });
                            break;
                        }
                    }

                    if path.is_file() {
                        for (ext, reason, risk, mitre) in suspicious_extensions {
                            if file_name_lower.ends_with(ext) {
                                let modified_time = metadata.modified()
                                    .ok()
                                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                    .map(|d| {
                                        let secs = d.as_secs();
                                        let days = secs / 86400;
                                        let time_of_day = secs % 86400;
                                        let hours = time_of_day / 3600;
                                        let minutes = (time_of_day % 3600) / 60;
                                        let seconds = time_of_day % 60;
                                        format!("{}-{:02}:{:02}:{:02}", days, hours, minutes, seconds)
                                    })
                                    .unwrap_or_else(|| "Unknown".to_string());

                                suspicious_files.push(SuspiciousFile {
                                    path: path.display().to_string(),
                                    reason: reason.to_string(),
                                    size: metadata.len(),
                                    modified_time,
                                    risk_level: risk.to_string(),
                                    mitre_id: mitre.to_string(),
                                });
                                break;
                            }
                        }
                    }

                    if path.is_dir() && !file_name.starts_with('.') && current_depth < max_depth {
                        Self::walk_directory(&path, file_count, hidden_files, encrypted_files,
                            total_size, suspicious_files, suspicious_names, suspicious_extensions,
                            encrypted_extensions, current_depth + 1, max_depth);
                    }
                }
            }
        }
    }

    fn estimate_recoverable_files(path: &Path) -> u64 {
        let mut count: u64 = 0;

        #[cfg(unix)]
        {
            let trash_paths = [
                path.join(".local/share/Trash/files"),
                path.join(".Trash"),
                Path::new("/tmp").to_path_buf(),
            ];
            for trash_path in &trash_paths {
                if trash_path.exists() {
                    if let Ok(entries) = std::fs::read_dir(trash_path) {
                        count += entries.count() as u64;
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            let recycle_bin = Path::new("C:\\$Recycle.Bin");
            if recycle_bin.exists() {
                if let Ok(entries) = std::fs::read_dir(recycle_bin) {
                    count += entries.count() as u64;
                }
            }
        }

        count
    }

    fn analyze_memory() -> MemoryAnalysis {
        let mut process_count: u32 = 0;
        let mut suspicious_processes: Vec<ProcessInfo> = Vec::new();
        let mut network_connections: Vec<NetworkConnection> = Vec::new();

        #[cfg(unix)]
        {
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.chars().all(|c| c.is_numeric()) {
                        process_count += 1;

                        let pid: u32 = name_str.parse().unwrap_or(0);
                        if pid == 0 { continue; }

                        let cmdline_path = format!("/proc/{}/cmdline", pid);
                        let _stat_path = format!("/proc/{}/stat", pid);
                        let status_path = format!("/proc/{}/status", pid);

                        let mut process_name = String::new();
                        let mut process_path = String::new();
                        let mut process_user = String::new();
                        let mut memory_mb: f64 = 0.0;

                        if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                            process_path = cmdline.replace('\0', " ").trim().to_string();
                            if let Some(first) = process_path.split_whitespace().next() {
                                process_name = first.split('/').next_back().unwrap_or(first).to_string();
                            }
                        }

                        if let Ok(status) = std::fs::read_to_string(&status_path) {
                            for line in status.lines() {
                                if line.starts_with("Uid:") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() > 1 {
                                        if let Ok(uid) = parts[1].parse::<u32>() {
                                            process_user = if uid == 0 { "root".to_string() }
                                                else { format!("uid={}", uid) };
                                        }
                                    }
                                }
                                if line.starts_with("VmRSS:") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() > 1 {
                                        if let Ok(kb) = parts[1].parse::<f64>() {
                                            memory_mb = kb / 1024.0;
                                        }
                                    }
                                }
                            }
                        }

                        let kernel_name_mimics = [
                            "kworkerds", "kworkerd", "kswapd0", "ksoftirqd",
                            "migration", "kthread", "rcu_", "watchdog",
                        ];

                        let suspicious_process_names = [
                            ("cryptominer", "Cryptocurrency miner detected", "critical", "T1496"),
                            ("xmrig", "XMRig cryptocurrency miner", "critical", "T1496"),
                            ("minerd", "Cryptocurrency miner daemon", "critical", "T1496"),
                            ("keylogger", "Keylogger process detected", "critical", "T1056"),
                            ("rootkit", "Rootkit process detected", "critical", "T1014"),
                            ("backdoor", "Backdoor process detected", "critical", "T1059"),
                            ("reverse_shell", "Reverse shell detected", "critical", "T1059"),
                            ("ncat", "Netcat - may be used for reverse shell", "high", "T1059"),
                            ("nc.", "Netcat variant - may be used for reverse shell", "high", "T1059"),
                            ("socat", "Socat - may be used for relay/pivot", "medium", "T1090"),
                        ];

                        let mut is_suspicious = false;
                        let mut reason = String::new();
                        let mut mitre_id = String::new();

                        if process_path.contains("/tmp/") || process_path.contains("/var/tmp/") || process_path.contains("/dev/shm/") {
                            is_suspicious = true;
                            reason = format!("Process running from temporary directory: {}", process_path);
                            mitre_id = "T1059".to_string();
                        }

                        for kernel_name in &kernel_name_mimics {
                            if process_name == *kernel_name && process_path.contains("/tmp") {
                                is_suspicious = true;
                                reason = format!("Process mimics kernel thread name but runs from /tmp: {}", process_name);
                                mitre_id = "T1036".to_string();
                                break;
                            }
                        }

                        for (susp_name, susp_reason, _risk, mitre) in &suspicious_process_names {
                            if process_name.to_lowercase().contains(susp_name) {
                                is_suspicious = true;
                                reason = susp_reason.to_string();
                                mitre_id = mitre.to_string();
                                break;
                            }
                        }

                        if is_suspicious {
                            suspicious_processes.push(ProcessInfo {
                                pid,
                                name: process_name,
                                path: process_path,
                                user: process_user,
                                memory_mb,
                                suspicious: true,
                                reason,
                                mitre_id,
                            });
                        }
                    }
                }
            }

            if let Ok(tcp_content) = std::fs::read_to_string("/proc/net/tcp") {
                for line in tcp_content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let local = parts.get(1).unwrap_or(&"");
                        let remote = parts.get(2).unwrap_or(&"");
                        let state_code = parts.get(3).unwrap_or(&"");

                        let local_addr = Self::parse_hex_socket_addr(local);
                        let remote_addr = Self::parse_hex_socket_addr(remote);
                        let state = match *state_code {
                            "01" => "ESTABLISHED".to_string(),
                            "02" => "SYN_SENT".to_string(),
                            "03" => "SYN_RECV".to_string(),
                            "04" => "FIN_WAIT1".to_string(),
                            "05" => "FIN_WAIT2".to_string(),
                            "06" => "TIME_WAIT".to_string(),
                            "07" => "CLOSE".to_string(),
                            "08" => "CLOSE_WAIT".to_string(),
                            "09" => "LAST_ACK".to_string(),
                            "0A" => "LISTEN".to_string(),
                            _ => format!("UNKNOWN({})", state_code),
                        };

                        let is_suspicious = remote_addr.contains(":4444")
                            || remote_addr.contains(":1337")
                            || remote_addr.contains(":31337")
                            || remote_addr.contains(":1234")
                            || local_addr.contains(":4444")
                            || local_addr.contains("0.0.0.0:");

                        let reason = if is_suspicious {
                            "Suspicious port or binding detected - possible C2 communication".to_string()
                        } else {
                            String::new()
                        };

                        network_connections.push(NetworkConnection {
                            protocol: "TCP".to_string(),
                            local_addr,
                            remote_addr,
                            state,
                            process: String::new(),
                            suspicious: is_suspicious,
                            reason,
                        });
                    }
                }
            }

            if let Ok(udp_content) = std::fs::read_to_string("/proc/net/udp") {
                for line in udp_content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let local = parts.get(1).unwrap_or(&"");
                        let remote = parts.get(2).unwrap_or(&"");

                        let local_addr = Self::parse_hex_socket_addr(local);
                        let remote_addr = Self::parse_hex_socket_addr(remote);

                        network_connections.push(NetworkConnection {
                            protocol: "UDP".to_string(),
                            local_addr,
                            remote_addr,
                            state: "STATELESS".to_string(),
                            process: String::new(),
                            suspicious: false,
                            reason: String::new(),
                        });
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            process_count = 0;
        }

        let injected_dlls: Vec<String> = Vec::new();
        let hidden_processes: Vec<String> = Vec::new();

        MemoryAnalysis {
            process_count,
            suspicious_processes,
            injected_dlls,
            hidden_processes,
            network_connections,
        }
    }

    #[cfg(unix)]
    fn parse_hex_socket_addr(hex: &str) -> String {
        let parts: Vec<&str> = hex.split(':').collect();
        if parts.len() != 2 { return hex.to_string(); }

        let port = u32::from_str_radix(parts[1], 16).unwrap_or(0);

        let ip_hex = parts[0];
        if ip_hex.len() == 8 {
            let b1 = u32::from_str_radix(&ip_hex[6..8], 16).unwrap_or(0);
            let b2 = u32::from_str_radix(&ip_hex[4..6], 16).unwrap_or(0);
            let b3 = u32::from_str_radix(&ip_hex[2..4], 16).unwrap_or(0);
            let b4 = u32::from_str_radix(&ip_hex[0..2], 16).unwrap_or(0);
            format!("{}.{}.{}.{}:{}", b1, b2, b3, b4, port)
        } else {
            hex.to_string()
        }
    }

    #[cfg(not(unix))]
    fn parse_hex_socket_addr(hex: &str) -> String {
        hex.to_string()
    }

    fn build_timeline(filesystem_info: &FilesystemInfo, memory_analysis: &MemoryAnalysis) -> Vec<TimelineEntry> {
        let mut entries: Vec<TimelineEntry> = Vec::new();

        for sf in &filesystem_info.suspicious_files {
            entries.push(TimelineEntry {
                timestamp: sf.modified_time.clone(),
                event_type: "File Activity".to_string(),
                description: format!("Suspicious file: {} ({})", sf.path, sf.reason),
                source: "Filesystem".to_string(),
                significance: sf.risk_level.clone(),
                mitre_id: sf.mitre_id.clone(),
            });
        }

        for proc in &memory_analysis.suspicious_processes {
            entries.push(TimelineEntry {
                timestamp: "Active".to_string(),
                event_type: "Process Activity".to_string(),
                description: format!("Suspicious process: PID={} {} ({})", proc.pid, proc.name, proc.reason),
                source: "Memory".to_string(),
                significance: if proc.suspicious { "high".to_string() } else { "low".to_string() },
                mitre_id: proc.mitre_id.clone(),
            });
        }

        for conn in &memory_analysis.network_connections {
            if conn.suspicious {
                entries.push(TimelineEntry {
                    timestamp: "Active".to_string(),
                    event_type: "Network Activity".to_string(),
                    description: format!("Suspicious connection: {} {} -> {} ({})", conn.protocol, conn.local_addr, conn.remote_addr, conn.reason),
                    source: "Network".to_string(),
                    significance: "critical".to_string(),
                    mitre_id: "T1071".to_string(),
                });
            }
        }

        #[cfg(unix)]
        {
            let log_paths = [
                ("/var/log/auth.log", "Authentication Log", "T1078"),
                ("/var/log/syslog", "System Log", "T1074"),
                ("/var/log/secure", "Security Log", "T1078"),
                ("/var/log/kern.log", "Kernel Log", "T1068"),
            ];

            for (log_path, log_name, mitre_id) in &log_paths {
                let lp = Path::new(log_path);
                if lp.exists() {
                    if let Ok(metadata) = lp.metadata() {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                                let secs = duration.as_secs();
                                let days = secs / 86400;
                                let time_of_day = secs % 86400;
                                let hours = time_of_day / 3600;
                                let minutes = (time_of_day % 3600) / 60;
                                let seconds = time_of_day % 60;
                                let timestamp = format!("{}-{:02}:{:02}:{:02}", days, hours, minutes, seconds);

                                entries.push(TimelineEntry {
                                    timestamp,
                                    event_type: "Log Activity".to_string(),
                                    description: format!("{} modified: {}", log_name, log_path),
                                    source: "System Logs".to_string(),
                                    significance: "low".to_string(),
                                    mitre_id: mitre_id.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        entries.sort_by(|a, b| b.significance.cmp(&a.significance));
        entries
    }

    fn analyze_registry() -> RegistryInfo {
        RegistryInfo {
            run_keys: vec![],
            services: vec![],
            suspicious_entries: vec![],
        }
    }

    fn check_anti_forensics(path: &str, filesystem_info: &FilesystemInfo) -> Vec<AntiForensicsIndicator> {
        let mut indicators: Vec<AntiForensicsIndicator> = Vec::new();

        #[cfg(unix)]
        {
            if let Ok(auth_log) = std::fs::read_to_string("/var/log/auth.log") {
                let line_count = auth_log.lines().count();
                if line_count < 10 && std::fs::metadata("/var/log/auth.log").map(|m| m.len() > 100).unwrap_or(false) {
                    indicators.push(AntiForensicsIndicator {
                        technique: "Log Clearing".to_string(),
                        description: "Authentication log appears to have been cleared or truncated".to_string(),
                        detected: true,
                        evidence: format!("/var/log/auth.log has only {} lines", line_count),
                        severity: "high".to_string(),
                        mitre_id: "T1070.001".to_string(),
                    });
                }
            }

            if let Ok(syslog) = std::fs::read_to_string("/var/log/syslog") {
                let line_count = syslog.lines().count();
                if line_count < 10 && std::fs::metadata("/var/log/syslog").map(|m| m.len() > 100).unwrap_or(false) {
                    indicators.push(AntiForensicsIndicator {
                        technique: "Log Clearing".to_string(),
                        description: "System log appears to have been cleared or truncated".to_string(),
                        detected: true,
                        evidence: format!("/var/log/syslog has only {} lines", line_count),
                        severity: "high".to_string(),
                        mitre_id: "T1070.001".to_string(),
                    });
                }
            }

            let bash_history = format!("{}/.bash_history", path);
            if Path::new(&bash_history).exists() {
                if let Ok(content) = std::fs::read_to_string(&bash_history) {
                    if content.is_empty() {
                        indicators.push(AntiForensicsIndicator {
                            technique: "History Clearing".to_string(),
                            description: "Bash history file is empty - may have been cleared".to_string(),
                            detected: true,
                            evidence: format!("{} is empty", bash_history),
                            severity: "medium".to_string(),
                            mitre_id: "T1070.003".to_string(),
                        });
                    } else if content.contains("history -c") || content.contains("history -w") {
                        indicators.push(AntiForensicsIndicator {
                            technique: "History Clearing".to_string(),
                            description: "Bash history contains commands to clear history".to_string(),
                            detected: true,
                            evidence: format!("{} contains history clearing commands", bash_history),
                            severity: "medium".to_string(),
                            mitre_id: "T1070.003".to_string(),
                        });
                    }
                }
            }

            if let Ok(entries) = std::fs::read_dir("/tmp") {
                let tmp_count = entries.count();
                if tmp_count == 0 {
                    indicators.push(AntiForensicsIndicator {
                        technique: "Temp Directory Cleaning".to_string(),
                        description: "Temporary directory is empty - may have been cleaned to remove evidence".to_string(),
                        detected: true,
                        evidence: "/tmp directory is empty".to_string(),
                        severity: "low".to_string(),
                        mitre_id: "T1070.004".to_string(),
                    });
                }
            }
        }

        let mut timestomp_detected = false;
        for sf in &filesystem_info.suspicious_files {
            let p = Path::new(&sf.path);
            if let Ok(metadata) = p.metadata() {
                if let (Ok(modified), Ok(created)) = (metadata.modified(), metadata.created()) {
                    if modified < created {
                        timestomp_detected = true;
                        break;
                    }
                }
            }
        }

        if timestomp_detected {
            indicators.push(AntiForensicsIndicator {
                technique: "Timestomp".to_string(),
                description: "File modification time precedes creation time - timestamps may have been manipulated".to_string(),
                detected: true,
                evidence: "File modified time earlier than creation time detected".to_string(),
                severity: "high".to_string(),
                mitre_id: "T1070.006".to_string(),
            });
        }

        indicators.push(AntiForensicsIndicator {
            technique: "Timestomp".to_string(),
            description: "Use timestomp tool to modify MACE timestamps".to_string(),
            detected: false,
            evidence: String::new(),
            severity: "high".to_string(),
            mitre_id: "T1070.006".to_string(),
        });

        indicators.push(AntiForensicsIndicator {
            technique: "File Deletion".to_string(),
            description: "Files may have been securely deleted to prevent recovery".to_string(),
            detected: false,
            evidence: String::new(),
            severity: "medium".to_string(),
            mitre_id: "T1070.004".to_string(),
        });

        indicators
    }
}
