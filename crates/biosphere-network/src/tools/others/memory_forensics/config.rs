use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryForensicsConfig {
    pub dump_path: String,
    pub profile: String,
    pub analysis_type: String,
}

impl Default for MemoryForensicsConfig {
    fn default() -> Self {
        Self {
            dump_path: String::new(),
            profile: "auto".to_string(),
            analysis_type: "full".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub full_path: String,
    pub command_line: String,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConnection {
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub protocol: String,
    pub pid: u32,
    pub process_name: String,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryArtifact {
    pub artifact_type: String,
    pub name: String,
    pub description: String,
    pub location: String,
    pub severity: String,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedCode {
    pub pid: u32,
    pub process_name: String,
    pub injection_type: String,
    pub base_address: String,
    pub size: u64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub is_suspicious: bool,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySecurityFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryForensicsResult {
    pub success: bool,
    pub analysis_type: String,
    pub processes: Vec<MemoryProcess>,
    pub connections: Vec<MemoryConnection>,
    pub artifacts: Vec<MemoryArtifact>,
    pub injected_code: Vec<InjectedCode>,
    pub registry_keys: Vec<RegistryKey>,
    pub security_findings: Vec<MemorySecurityFinding>,
    pub summary: String,
}

pub struct MemoryForensicsTool;

impl MemoryForensicsTool {
    pub async fn analyze(config: &MemoryForensicsConfig) -> Result<MemoryForensicsResult, String> {
        let mut processes = Vec::new();
        let mut connections = Vec::new();
        let mut artifacts = Vec::new();
        let mut injected_code = Vec::new();
        let mut registry_keys = Vec::new();
        let mut security_findings = Vec::new();

        if !config.dump_path.is_empty() {
            let path = std::path::Path::new(&config.dump_path);
            if !path.exists() {
                return Err(format!("Memory dump file does not exist: {}", config.dump_path));
            }
            if let Ok(metadata) = std::fs::metadata(&config.dump_path) {
                if metadata.len() < 1024 {
                    return Err("Memory dump file is too small, may not be a valid dump file".to_string());
                }
            }
        }

        let analysis_type = config.analysis_type.as_str();

        if analysis_type == "full" || analysis_type == "processes" {
            processes = Self::get_running_processes(&config.profile);
        }

        if analysis_type == "full" || analysis_type == "network" {
            connections = Self::get_network_connections();
        }

        if analysis_type == "full" || analysis_type == "malware" {
            processes = Self::get_running_processes(&config.profile);
            connections = Self::get_network_connections();
            Self::detect_code_injection(&processes, &mut injected_code, &mut artifacts);
            Self::detect_suspicious_memory_regions(&processes, &mut injected_code, &mut artifacts);
        }

        if analysis_type == "full" || analysis_type == "persistence" {
            registry_keys = Self::check_persistence_mechanisms();
        }

        if analysis_type == "full" || analysis_type == "processes" || analysis_type == "network" || analysis_type == "malware" {
            Self::analyze_suspicious_processes(&processes, &connections, &mut security_findings);
            Self::analyze_suspicious_connections(&connections, &mut security_findings);
        }

        if !injected_code.is_empty() {
            security_findings.push(MemorySecurityFinding {
                severity: "critical".to_string(),
                category: "code_injection".to_string(),
                description: format!("Detected {} code injection(s)", injected_code.len()),
                recommendation: "Analyze injected code and remove malicious code".to_string(),
                mitre_technique: Some("T1055".to_string()),
            });
        }

        if !registry_keys.is_empty() {
            let suspicious_keys = registry_keys.iter().filter(|k| k.is_suspicious).count();
            if suspicious_keys > 0 {
                security_findings.push(MemorySecurityFinding {
                    severity: "high".to_string(),
                    category: "persistence".to_string(),
                    description: format!("Detected {} suspicious registry/startup items", suspicious_keys),
                    recommendation: "Remove suspicious registry entries and clean up startup items".to_string(),
                    mitre_technique: Some("T1547.001".to_string()),
                });
            }
        }

        let critical_count = security_findings.iter().filter(|f| f.severity == "critical").count();
        let summary = format!(
            "[Memory Forensics] {} processes, {} connections, {} artifacts, {} injected, {} critical findings",
            processes.len(), connections.len(), artifacts.len(), injected_code.len(), critical_count
        );

        Ok(MemoryForensicsResult {
            success: true,
            analysis_type: config.analysis_type.clone(),
            processes,
            connections,
            artifacts,
            injected_code,
            registry_keys,
            security_findings,
            summary,
        })
    }

    fn get_running_processes(profile: &str) -> Vec<MemoryProcess> {
        let mut processes = Vec::new();

        let is_windows_profile = profile.starts_with("win");
        let _is_linux_profile = profile == "linux";
        let _is_macos_profile = profile == "macos";

        #[cfg(target_os = "macos")]
        {
            if !is_windows_profile {
                if let Ok(output) = std::process::Command::new("ps")
                    .args(["-eo", "pid,ppid,comm,args"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let pid = parts[0].parse::<u32>().unwrap_or(0);
                            let ppid = parts[1].parse::<u32>().unwrap_or(0);
                            let name = parts[2].to_string();
                            let command_line = parts[3..].join(" ");

                            let (is_suspicious, reasons) = Self::check_process_suspicion(pid, ppid, &name, &command_line);

                            processes.push(MemoryProcess {
                                pid,
                                ppid,
                                name: name.clone(),
                                full_path: name,
                                command_line,
                                is_suspicious,
                                suspicion_reasons: reasons,
                            });
                        }
                    }
                }

                if let Ok(output) = std::process::Command::new("lsof")
                    .args(["-c", "", "-Fn"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.starts_with('n') && line.len() > 1 {
                            let path = &line[1..];
                            for proc in &mut processes {
                                if path.contains(&proc.name) {
                                    proc.full_path = path.to_string();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            if !is_windows_profile {
                if let Ok(output) = std::process::Command::new("ps")
                    .args(["-eo", "pid,ppid,comm,args"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let pid = parts[0].parse::<u32>().unwrap_or(0);
                            let ppid = parts[1].parse::<u32>().unwrap_or(0);
                            let name = parts[2].to_string();
                            let command_line = parts[3..].join(" ");

                            let full_path = std::fs::read_link(format!("/proc/{}/exe", pid))
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_else(|_| name.clone());

                            let (is_suspicious, reasons) = Self::check_process_suspicion(pid, ppid, &name, &command_line);

                            processes.push(MemoryProcess {
                                pid,
                                ppid,
                                name,
                                full_path,
                                command_line,
                                is_suspicious,
                                suspicion_reasons: reasons,
                            });
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if is_windows_profile || profile == "auto" {
                if let Ok(output) = std::process::Command::new("tasklist")
                    .args(["/FO", "CSV", "/V"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines().skip(1) {
                        let fields: Vec<&str> = line.split("\",\"").collect();
                        if fields.len() >= 2 {
                            let name = fields[0].trim_start_matches('"').to_string();
                            let pid = fields[1].parse::<u32>().unwrap_or(0);
                            let command_line = fields.get(0).unwrap_or(&"").to_string();

                            let (is_suspicious, reasons) = Self::check_process_suspicion(pid, 0, &name, &command_line);

                            processes.push(MemoryProcess {
                                pid,
                                ppid: 0,
                                name: name.clone(),
                                full_path: name,
                                command_line,
                                is_suspicious,
                                suspicion_reasons: reasons,
                            });
                        }
                    }
                }
            }
        }

        processes
    }

    fn check_process_suspicion(pid: u32, _ppid: u32, name: &str, command_line: &str) -> (bool, Vec<String>) {
        let mut reasons = Vec::new();
        let name_lower = name.to_lowercase();
        let cmd_lower = command_line.to_lowercase();

        let suspicious_names = [
            ("ncat", "Ncat/Reverse Shell tool"),
            ("socat", "Socat/Data relay tool"),
            ("meterpreter", "Meterpreter session"),
            ("reverse_shell", "Reverse Shell"),
            ("bind_shell", "Bind Shell"),
            ("keylogger", "Keylogger"),
            ("malware", "Malware"),
            ("backdoor", "Backdoor program"),
            ("cryptominer", "Cryptominer"),
            ("xmrig", "XMRig miner"),
            ("minerd", "CPUMiner daemon"),
            ("ccminer", "CCMiner cryptocurrency miner"),
        ];

        for (susp_name, reason) in &suspicious_names {
            if name_lower.contains(susp_name) {
                reasons.push(reason.to_string());
            }
        }

        if name_lower == "nc" || name_lower == "netcat" {
            reasons.push("Netcat/Reverse Shell tool".to_string());
        }

        if name_lower == "rat" || name_lower.ends_with("rat.exe") || name_lower.ends_with("rat.bin") {
            reasons.push("Remote Admin Tool".to_string());
        }

        let suspicious_cmd_patterns = [
            ("/dev/tcp/", "Bash reverse shell"),
            ("/dev/udp/", "UDP reverse shell"),
            ("base64 -d", "Base64 decode execution"),
            ("| bash", "Pipe to shell execution"),
            ("| sh", "Pipe to shell execution"),
            ("curl.*|.*sh", "Download and execute script"),
            ("wget.*|.*sh", "Download and execute script"),
            ("powershell -enc", "PowerShell encoded execution"),
            ("powershell -e ", "PowerShell encoded execution"),
            ("-noexit -command", "PowerShell hidden execution"),
            ("iex (", "PowerShell Invoke-Expression"),
            ("iex(", "PowerShell Invoke-Expression"),
            ("invoke-expression", "PowerShell Invoke-Expression"),
            ("new-object net.webclient", ".NET WebClient download"),
            ("start-process -windowstyle hidden", "Hidden process launch"),
            ("bypass -command", "PowerShell policy bypass"),
            ("frombase64string", "Base64 string conversion"),
        ];

        for pattern in &suspicious_cmd_patterns {
            if cmd_lower.contains(&pattern.0.to_lowercase()) {
                reasons.push(format!("Suspicious command pattern: {}", pattern.1));
            }
        }

        if command_line.contains("/tmp/") || command_line.contains("/var/tmp/") || command_line.contains("\\Temp\\") || command_line.contains("\\AppData\\Local\\Temp\\") {
            reasons.push("Running from temp directory".to_string());
        }

        if pid < 10 && !["kernel", "launchd", "init", "systemd", "kthreadd"].iter().any(|k| name_lower.contains(k)) {
            reasons.push("Low PID but non-system process".to_string());
        }

        (reasons.len() > 1, reasons)
    }

    fn get_network_connections() -> Vec<MemoryConnection> {
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
                        let protocol = if parts[4].contains("TCP") { "TCP" } else { "UDP" }.to_string();

                        let addr_part = parts[8];
                        let (local_addr, remote_addr) = if let Some(pos) = addr_part.find("->") {
                            (addr_part[..pos].to_string(), addr_part[pos+2..].to_string())
                        } else {
                            (addr_part.to_string(), String::new())
                        };

                        let state = if parts.len() > 9 {
                            parts[9].to_string()
                        } else if protocol == "UDP" {
                            "STATELESS".to_string()
                        } else {
                            "UNKNOWN".to_string()
                        };

                        let is_suspicious = Self::is_connection_suspicious(&local_addr, &remote_addr, &state, pid);

                        connections.push(MemoryConnection {
                            local_address: local_addr,
                            remote_address: remote_addr,
                            state,
                            protocol,
                            pid,
                            process_name,
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
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 {
                        let protocol = parts[0].to_string();
                        let state = parts[1].to_string();
                        let local_addr = parts[4].to_string();
                        let remote_addr = parts[5].to_string();

                        let process_info = parts.get(6).unwrap_or(&"").to_string();
                        let (process_name, pid) = if process_info.contains('"') {
                            let re = regex::Regex::new(r#""([^"]+)".*?pid=(\d+)"#).unwrap();
                            if let Some(caps) = re.captures(&process_info) {
                                (caps[1].to_string(), caps[2].parse::<u32>().unwrap_or(0))
                            } else {
                                (process_info.clone(), 0)
                            }
                        } else {
                            (process_info.clone(), 0)
                        };

                        let is_suspicious = Self::is_connection_suspicious(&local_addr, &remote_addr, &state, pid);

                        connections.push(MemoryConnection {
                            local_address: local_addr,
                            remote_address: remote_addr,
                            state,
                            protocol,
                            pid,
                            process_name,
                            is_suspicious,
                        });
                    }
                }
            }
        }

        connections
    }

    fn is_connection_suspicious(local_addr: &str, remote_addr: &str, state: &str, pid: u32) -> bool {
        if state != "ESTABLISHED" || remote_addr.is_empty() {
            return false;
        }

        let rat_ports = [4444, 5555, 1337, 31337, 6666, 6667, 9999, 12345, 27374, 54321, 1604, 5300, 2589, 3460];
        for port in &rat_ports {
            if remote_addr.contains(&format!(":{}", port)) || local_addr.contains(&format!(":{}", port)) {
                return true;
            }
        }

        let suspicious_ports = [4443, 8080, 8443, 8888];
        for port in &suspicious_ports {
            if remote_addr.contains(&format!(":{}", port)) && pid > 0 {
                return true;
            }
        }

        let private_ranges = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "192.168.", "127.", "0.0.0.0", "::1", "fe80:"];
        let is_private = private_ranges.iter().any(|r| remote_addr.starts_with(r));

        if !is_private && !remote_addr.contains("*") && !remote_addr.contains("0.0.0.0") {
            let high_ports = remote_addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
            if let Some(port) = high_ports {
                if port > 49152 {
                    return true;
                }
            }
        }

        false
    }

    fn detect_code_injection(
        processes: &[MemoryProcess],
        injected_code: &mut Vec<InjectedCode>,
        artifacts: &mut Vec<MemoryArtifact>,
    ) {
        for proc in processes {
            if !proc.is_suspicious {
                continue;
            }

            let cmd_lower = proc.command_line.to_lowercase();
            let name_lower = proc.name.to_lowercase();

            let injection_indicators = [
                ("inject", "Process injection keyword"),
                ("dll", "DLL injection indicator"),
                ("hook", "API hooking indicator"),
                ("patch", "Memory patching indicator"),
                ("shellcode", "Shellcode execution"),
                ("meterpreter", "Meterpreter injection"),
                ("beacon", "C2 beacon injection"),
            ];

            for (indicator, description) in &injection_indicators {
                if cmd_lower.contains(indicator) || name_lower.contains(indicator) {
                    injected_code.push(InjectedCode {
                        pid: proc.pid,
                        process_name: proc.name.clone(),
                        injection_type: description.to_string(),
                        base_address: "N/A".to_string(),
                        size: 0,
                        severity: "high".to_string(),
                    });

                    artifacts.push(MemoryArtifact {
                        artifact_type: "Code Injection Indicator".to_string(),
                        name: format!("{} (PID: {})", proc.name, proc.pid),
                        description: format!("Process shows {} indicators: {}", description, proc.suspicion_reasons.join(", ")),
                        location: proc.full_path.clone(),
                        severity: "high".to_string(),
                        indicators: proc.suspicion_reasons.clone(),
                    });
                    break;
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            for proc in processes {
                if proc.is_suspicious {
                    let maps_path = format!("/proc/{}/maps", proc.pid);
                    if let Ok(contents) = std::fs::read_to_string(&maps_path) {
                        for line in contents.lines() {
                            let fields: Vec<&str> = line.split_whitespace().collect();
                            if fields.len() >= 2 {
                                let perms = fields[1];
                                if perms.contains('w') && perms.contains('x') {
                                    let addr_range: Vec<&str> = fields[0].split('-').collect();
                                    let base = addr_range.first().unwrap_or(&"0x0");
                                    let end = addr_range.get(1).unwrap_or(&"0x0");
                                    let size = if let (Ok(s), Ok(e)) = (u64::from_str_radix(base.trim_start_matches("0x"), 16), u64::from_str_radix(end.trim_start_matches("0x"), 16)) {
                                        e - s
                                    } else {
                                        0
                                    };

                                    let already_detected = injected_code.iter().any(|ic| ic.pid == proc.pid);
                                    if !already_detected {
                                        injected_code.push(InjectedCode {
                                            pid: proc.pid,
                                            process_name: proc.name.clone(),
                                            injection_type: "RWX Memory Region".to_string(),
                                            base_address: base.to_string(),
                                            size,
                                            severity: "critical".to_string(),
                                        });
                                    }

                                    artifacts.push(MemoryArtifact {
                                        artifact_type: "Writable Executable Memory".to_string(),
                                        name: format!("{} (PID: {})", proc.name, proc.pid),
                                        description: "Process contains writable executable memory region, possible code injection".to_string(),
                                        location: format!("/proc/{}/maps", proc.pid),
                                        severity: "critical".to_string(),
                                        indicators: vec!["rwx".to_string(), "code injection".to_string()],
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn detect_suspicious_memory_regions(
        processes: &[MemoryProcess],
        injected_code: &mut Vec<InjectedCode>,
        artifacts: &mut Vec<MemoryArtifact>,
    ) {
        #[cfg(target_os = "macos")]
        {
            for proc in processes {
                if proc.is_suspicious {
                    if let Ok(vm_output) = std::process::Command::new("vmmap")
                        .args([&proc.pid.to_string()])
                        .output()
                    {
                        if vm_output.status.success() {
                            let vm_stdout = String::from_utf8_lossy(&vm_output.stdout);
                            for line in vm_stdout.lines() {
                                if line.contains("rwx") || line.contains("RWX") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 3 {
                                        let already_detected = injected_code.iter().any(|ic| ic.pid == proc.pid);
                                        if !already_detected {
                                            injected_code.push(InjectedCode {
                                                pid: proc.pid,
                                                process_name: proc.name.clone(),
                                                injection_type: "RWX Memory Region".to_string(),
                                                base_address: parts[0].to_string(),
                                                size: parts.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                                                severity: "critical".to_string(),
                                            });
                                        }
                                    }

                                    artifacts.push(MemoryArtifact {
                                        artifact_type: "Writable Executable Memory".to_string(),
                                        name: format!("{} (PID: {})", proc.name, proc.pid),
                                        description: "Process contains writable executable memory region, possible code injection".to_string(),
                                        location: format!("PID {}", proc.pid),
                                        severity: "critical".to_string(),
                                        indicators: vec!["rwx".to_string(), "code injection".to_string()],
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        for proc in processes {
            if proc.is_suspicious {
                let cmd_lower = proc.command_line.to_lowercase();
                if cmd_lower.contains("hook") || cmd_lower.contains("patch") || cmd_lower.contains("shellcode") {
                    let already_detected = injected_code.iter().any(|ic| ic.pid == proc.pid);
                    if !already_detected {
                        artifacts.push(MemoryArtifact {
                            artifact_type: "Suspicious Process Artifact".to_string(),
                            name: format!("{} (PID: {})", proc.name, proc.pid),
                            description: format!("Suspicious process with memory manipulation indicators: {}", proc.suspicion_reasons.join(", ")),
                            location: proc.full_path.clone(),
                            severity: "high".to_string(),
                            indicators: proc.suspicion_reasons.clone(),
                        });
                    }
                }
            }
        }
    }

    fn check_persistence_mechanisms() -> Vec<RegistryKey> {
        let mut keys = Vec::new();

        #[cfg(target_os = "macos")]
        {
            let launch_agents = [
                ("~/Library/LaunchAgents", "User LaunchAgent"),
                ("/Library/LaunchAgents", "System LaunchAgent"),
                ("/Library/LaunchDaemons", "System LaunchDaemon"),
            ];

            for (dir, category) in &launch_agents {
                let expanded_dir = if dir.starts_with("~") {
                    if let Ok(home) = std::env::var("HOME") {
                        dir.replace("~", &home)
                    } else {
                        dir.to_string()
                    }
                } else {
                    dir.to_string()
                };

                if let Ok(entries) = std::fs::read_dir(&expanded_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("plist") {
                            if let Ok(contents) = std::fs::read_to_string(&path) {
                                let is_suspicious = Self::is_plist_suspicious(&contents);
                                let program = Self::extract_plist_program(&contents);

                                keys.push(RegistryKey {
                                    key_path: path.to_string_lossy().to_string(),
                                    value_name: "Program".to_string(),
                                    value_data: program,
                                    is_suspicious,
                                    category: category.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let persistence_dirs = [
                ("/etc/cron.d", "Cron Job"),
                ("/etc/cron.daily", "Daily Cron Job"),
                ("/etc/cron.hourly", "Hourly Cron Job"),
                ("/etc/init.d", "Init Script"),
                ("/etc/systemd/system", "Systemd Service"),
                ("/etc/xdg/autostart", "XDG Autostart"),
            ];

            for (dir, category) in &persistence_dirs {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Ok(contents) = std::fs::read_to_string(&path) {
                            let is_suspicious = Self::is_persistence_script_suspicious(&contents);
                            keys.push(RegistryKey {
                                key_path: path.to_string_lossy().to_string(),
                                value_name: "Script".to_string(),
                                value_data: contents.chars().take(200).collect(),
                                is_suspicious,
                                category: category.to_string(),
                            });
                        }
                    }
                }
            }
        }

        keys
    }

    fn is_plist_suspicious(contents: &str) -> bool {
        let suspicious_patterns = [
            "/tmp/", "/var/tmp/", "bash -c", "sh -c", "python -c",
            "curl |", "wget |", "base64 -d", "nc ", "ncat ",
            "/dev/tcp", "powershell", "nohup", "chmod +x",
            "LaunchOnlyOnce", "RunAtLoad",
        ];

        for pattern in &suspicious_patterns {
            if contents.contains(pattern) {
                return true;
            }
        }

        false
    }

    fn extract_plist_program(contents: &str) -> String {
        if let Some(start) = contents.find("<string>") {
            if let Some(end) = contents.find("</string>") {
                if start + 8 < end {
                    return contents[start + 8..end].to_string();
                }
            }
        }
        String::new()
    }

    #[allow(dead_code)]
    fn is_persistence_script_suspicious(contents: &str) -> bool {
        let suspicious_patterns = [
            "curl |", "wget |", "bash -c", "sh -c", "python -c",
            "base64 -d", "nc ", "/dev/tcp", "chmod +x",
            "nohup", "disown", "/tmp/", "/var/tmp/",
        ];

        for pattern in &suspicious_patterns {
            if contents.contains(pattern) {
                return true;
            }
        }

        false
    }

    fn analyze_suspicious_processes(
        processes: &[MemoryProcess],
        connections: &[MemoryConnection],
        security_findings: &mut Vec<MemorySecurityFinding>,
    ) {
        let suspicious_procs: Vec<&MemoryProcess> = processes.iter().filter(|p| p.is_suspicious).collect();

        if !suspicious_procs.is_empty() {
            for proc in &suspicious_procs {
                let has_connection = connections.iter().any(|c| c.pid == proc.pid && c.is_suspicious);

                if has_connection {
                    security_findings.push(MemorySecurityFinding {
                        severity: "critical".to_string(),
                        category: "suspicious_process_network".to_string(),
                        description: format!("Suspicious process {} (PID: {}) has network connection: {}", proc.name, proc.pid, proc.suspicion_reasons.join(", ")),
                        recommendation: "Terminate the process immediately and perform full forensic analysis".to_string(),
                        mitre_technique: Some("T1059".to_string()),
                    });
                } else {
                    security_findings.push(MemorySecurityFinding {
                        severity: "high".to_string(),
                        category: "suspicious_process".to_string(),
                        description: format!("Suspicious process {} (PID: {}): {}", proc.name, proc.pid, proc.suspicion_reasons.join(", ")),
                        recommendation: "Check the process origin and purpose".to_string(),
                        mitre_technique: Some("T1059".to_string()),
                    });
                }
            }
        }
    }

    fn analyze_suspicious_connections(
        connections: &[MemoryConnection],
        security_findings: &mut Vec<MemorySecurityFinding>,
    ) {
        let suspicious_conns: Vec<&MemoryConnection> = connections.iter().filter(|c| c.is_suspicious).collect();

        if !suspicious_conns.is_empty() {
            security_findings.push(MemorySecurityFinding {
                severity: "high".to_string(),
                category: "c2_communication".to_string(),
                description: format!("Found {} suspicious network connection(s)", suspicious_conns.len()),
                recommendation: "Block suspicious C2 communication and analyze network traffic".to_string(),
                mitre_technique: Some("T1071".to_string()),
            });
        }
    }
}
