use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscConfig {
    pub target: String,
    pub check_type: String,
    pub os_type: String,
    pub check_suid: bool,
    pub check_sgid: bool,
    pub check_capabilities: bool,
    pub check_cron: bool,
    pub check_writable: bool,
    pub check_services: bool,
    pub check_kernel: bool,
    pub check_docker: bool,
}

impl Default for PrivilegeEscConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            check_type: "local".to_string(),
            os_type: "linux".to_string(),
            check_suid: true,
            check_sgid: true,
            check_capabilities: true,
            check_cron: true,
            check_writable: true,
            check_services: true,
            check_kernel: true,
            check_docker: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscResult {
    pub success: bool,
    pub target: String,
    pub os_type: String,
    pub current_user: UserInfo,
    pub suid_binaries: Vec<PermissionBinary>,
    pub sgid_binaries: Vec<PermissionBinary>,
    pub capabilities: Vec<CapabilityInfo>,
    pub cron_jobs: Vec<CronJobInfo>,
    pub writable_paths: Vec<WritablePath>,
    pub vulnerable_services: Vec<VulnerableService>,
    pub kernel_exploits: Vec<KernelExploit>,
    pub docker_issues: Vec<DockerIssue>,
    pub misconfigurations: Vec<Misconfiguration>,
    pub security_score: SecurityScore,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    pub score: u8,
    pub level: String,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub critical_count: usize,
    pub total_findings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<String>,
    pub is_root: bool,
    pub home_dir: String,
    pub shell: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionBinary {
    pub path: String,
    pub permissions: String,
    pub owner: String,
    pub risk_level: String,
    pub description: String,
    pub exploit_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    pub capability: String,
    pub binary: String,
    pub risk_level: String,
    pub description: String,
    pub exploit_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJobInfo {
    pub schedule: String,
    pub command: String,
    pub user: String,
    pub risk_level: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritablePath {
    pub path: String,
    pub permissions: String,
    pub risk_level: String,
    pub description: String,
    pub exploit_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableService {
    pub name: String,
    pub version: String,
    pub config_path: String,
    pub risk_level: String,
    pub description: String,
    pub exploit_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelExploit {
    pub kernel_version: String,
    pub cve: String,
    pub name: String,
    pub risk_level: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerIssue {
    pub issue_type: String,
    pub description: String,
    pub risk_level: String,
    pub exploit_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misconfiguration {
    pub category: String,
    pub description: String,
    pub risk_level: String,
    pub recommendation: String,
}

pub struct PrivilegeEscCheckTool;

impl PrivilegeEscCheckTool {
    pub async fn check(config: &PrivilegeEscConfig) -> std::result::Result<PrivilegeEscResult, String> {
        if config.target.is_empty() {
            return Err("Target address is required".to_string());
        }

        let target = config.target.trim().to_string();
        let os_type = config.os_type.to_lowercase();

        let current_user = Self::detect_current_user(&os_type);
        let mut suid_binaries = Vec::new();
        let mut sgid_binaries = Vec::new();
        let mut capabilities = Vec::new();
        let mut cron_jobs = Vec::new();
        let mut writable_paths = Vec::new();
        let mut vulnerable_services = Vec::new();
        let mut kernel_exploits = Vec::new();
        let mut docker_issues = Vec::new();
        let misconfigurations: Vec<Misconfiguration>;

        if config.check_suid {
            suid_binaries = Self::check_suid_binaries(&os_type);
        }

        if config.check_sgid {
            sgid_binaries = Self::check_sgid_binaries(&os_type);
        }

        if config.check_capabilities {
            capabilities = Self::check_capabilities(&os_type);
        }

        if config.check_cron {
            cron_jobs = Self::check_cron_jobs(&os_type);
        }

        if config.check_writable {
            writable_paths = Self::check_writable_paths(&os_type);
        }

        if config.check_services {
            vulnerable_services = Self::check_vulnerable_services(&os_type);
        }

        if config.check_kernel {
            kernel_exploits = Self::check_kernel_exploits(&os_type);
        }

        if config.check_docker {
            docker_issues = Self::check_docker_issues(&os_type);
        }

        misconfigurations = Self::check_misconfigurations(&os_type);

        let critical_count = suid_binaries.iter().filter(|b| b.risk_level == "critical").count()
            + sgid_binaries.iter().filter(|b| b.risk_level == "critical").count()
            + capabilities.iter().filter(|c| c.risk_level == "critical").count()
            + writable_paths.iter().filter(|w| w.risk_level == "critical").count()
            + vulnerable_services.iter().filter(|s| s.risk_level == "critical").count()
            + kernel_exploits.iter().filter(|k| k.risk_level == "critical").count()
            + docker_issues.iter().filter(|d| d.risk_level == "critical").count()
            + misconfigurations.iter().filter(|m| m.risk_level == "critical").count();

        let high_count = suid_binaries.iter().filter(|b| b.risk_level == "high").count()
            + sgid_binaries.iter().filter(|b| b.risk_level == "high").count()
            + capabilities.iter().filter(|c| c.risk_level == "high").count()
            + writable_paths.iter().filter(|w| w.risk_level == "high").count()
            + vulnerable_services.iter().filter(|s| s.risk_level == "high").count()
            + kernel_exploits.iter().filter(|k| k.risk_level == "high").count()
            + docker_issues.iter().filter(|d| d.risk_level == "high").count()
            + misconfigurations.iter().filter(|m| m.risk_level == "high").count();

        let medium_count = suid_binaries.iter().filter(|b| b.risk_level == "medium").count()
            + sgid_binaries.iter().filter(|b| b.risk_level == "medium").count()
            + capabilities.iter().filter(|c| c.risk_level == "medium").count()
            + writable_paths.iter().filter(|w| w.risk_level == "medium").count()
            + vulnerable_services.iter().filter(|s| s.risk_level == "medium").count()
            + kernel_exploits.iter().filter(|k| k.risk_level == "medium").count()
            + docker_issues.iter().filter(|d| d.risk_level == "medium").count()
            + misconfigurations.iter().filter(|m| m.risk_level == "medium").count();

        let low_count = suid_binaries.iter().filter(|b| b.risk_level == "low").count()
            + sgid_binaries.iter().filter(|b| b.risk_level == "low").count()
            + capabilities.iter().filter(|c| c.risk_level == "low").count()
            + writable_paths.iter().filter(|w| w.risk_level == "low").count()
            + vulnerable_services.iter().filter(|s| s.risk_level == "low").count()
            + kernel_exploits.iter().filter(|k| k.risk_level == "low").count()
            + docker_issues.iter().filter(|d| d.risk_level == "low").count()
            + misconfigurations.iter().filter(|m| m.risk_level == "low").count();

        let total_findings = critical_count + high_count + medium_count + low_count;

        let score = Self::calculate_security_score(critical_count, high_count, medium_count, low_count);
        let level = Self::score_to_level(score);

        let security_score = SecurityScore {
            score,
            level,
            high_count,
            medium_count,
            low_count,
            critical_count,
            total_findings,
        };

        let summary = format!(
            "Privilege Escalation Check | Target: {} | OS: {} | User: {} (UID:{}) | Critical:{} High:{} Medium:{} Low:{} | Score: {}/100",
            target, os_type, current_user.username, current_user.uid,
            critical_count, high_count, medium_count, low_count, score
        );

        Ok(PrivilegeEscResult {
            success: true,
            target,
            os_type,
            current_user,
            suid_binaries,
            sgid_binaries,
            capabilities,
            cron_jobs,
            writable_paths,
            vulnerable_services,
            kernel_exploits,
            docker_issues,
            misconfigurations,
            security_score,
            summary,
        })
    }

    fn calculate_security_score(critical: usize, high: usize, medium: usize, low: usize) -> u8 {
        let penalty = (critical as i32 * 30 + high as i32 * 15 + medium as i32 * 5 + low as i32 * 1).min(100);
        (100 - penalty as u8).max(0)
    }

    fn score_to_level(score: u8) -> String {
        match score {
            90..=100 => "secure".to_string(),
            70..=89 => "low_risk".to_string(),
            50..=69 => "medium_risk".to_string(),
            25..=49 => "high_risk".to_string(),
            _ => "critical".to_string(),
        }
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

    fn detect_current_user(os_type: &str) -> UserInfo {
        match os_type {
            "linux" | "macos" => {
                let username = Self::run_command("whoami", &[])
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let id_output = Self::run_command("id", &[])
                    .unwrap_or_else(|| "uid=0 gid=0".to_string());

                let uid = Self::extract_number(&id_output, "uid=")
                    .unwrap_or(0);
                let gid = Self::extract_number(&id_output, "gid=")
                    .unwrap_or(0);

                let groups = if let Some(groups_str) = id_output.split("groups=").nth(1) {
                    groups_str
                        .split(',')
                        .filter_map(|g| {
                            let parts: Vec<&str> = g.trim().split('(').collect();
                            if parts.len() >= 2 {
                                parts[1].trim_end_matches(')').to_string().into()
                            } else {
                                None
                            }
                        })
                        .collect()
                } else {
                    vec![]
                };

                let is_root = uid == 0;

                let home_dir = if is_root {
                    "/root".to_string()
                } else {
                    Self::run_command("sh", &["-c", "echo $HOME"])
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| format!("/home/{}", username))
                };

                let shell = Self::run_command("sh", &["-c", "grep \"^$(whoami):\" /etc/passwd | cut -d: -f7"])
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "/bin/sh".to_string());

                UserInfo {
                    username,
                    uid,
                    gid,
                    groups,
                    is_root,
                    home_dir,
                    shell,
                }
            }
            "windows" => {
                let username = Self::run_command("cmd", &["/C", "echo %USERNAME%"])
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                UserInfo {
                    username,
                    uid: 0,
                    gid: 0,
                    groups: vec![],
                    is_root: false,
                    home_dir: "C:\\Users".to_string(),
                    shell: "cmd.exe".to_string(),
                }
            }
            _ => UserInfo {
                username: "unknown".to_string(),
                uid: 0,
                gid: 0,
                groups: vec![],
                is_root: false,
                home_dir: String::new(),
                shell: String::new(),
            },
        }
    }

    fn extract_number(text: &str, prefix: &str) -> Option<u32> {
        text.find(prefix).and_then(|start| {
            let rest = &text[start + prefix.len()..];
            rest.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
    }

    fn check_suid_binaries(os_type: &str) -> Vec<PermissionBinary> {
        if os_type == "windows" {
            return vec![];
        }

        let find_output = if os_type == "macos" {
            Self::run_command("find", &["/", "-perm", "-4000", "-type", "f", "-maxdepth", "5", "2>/dev/null"])
        } else {
            Self::run_command("find", &["/", "-perm", "-4000", "-type", "f", "2>/dev/null"])
        };

        let paths: Vec<&str> = match &find_output {
            Some(output) => output.lines().filter(|l| !l.is_empty()).collect(),
            None => return Self::fallback_suid_binaries(),
        };

        if paths.is_empty() {
            return Self::fallback_suid_binaries();
        }

        let known_exploitable = Self::get_suid_exploit_map();
        let mut results = Vec::new();

        for path in paths {
            let path_str = path.trim().to_string();
            let (risk, desc, hint) = known_exploitable
                .get(&path_str.as_str())
                .cloned()
                .unwrap_or_else(|| ("low".to_string(), format!("SUID binary: {}", path_str), "Review if this binary is necessary with SUID bit".to_string()));

            let owner = Self::get_file_owner(&path_str);
            let perms = Self::get_file_permissions(&path_str);

            results.push(PermissionBinary {
                path: path_str,
                permissions: perms,
                owner,
                risk_level: risk,
                description: desc,
                exploit_hint: hint,
            });
        }

        results.sort_by(|a, b| {
            let order = |r: &str| match r { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
            order(&a.risk_level).cmp(&order(&b.risk_level))
        });

        results
    }

    fn get_suid_exploit_map() -> std::collections::HashMap<&'static str, (String, String, String)> {
        let mut map = std::collections::HashMap::new();
        map.insert("/usr/bin/sudo", ("high".into(), "SUID sudo - may have misconfigured sudoers".into(), "Run sudo -l to check allowed commands".into()));
        map.insert("/usr/bin/pkexec", ("high".into(), "SUID pkexec - PwnKit vulnerability (CVE-2021-4034)".into(), "Check pkexec version, <0.120 is vulnerable".into()));
        map.insert("/usr/bin/find", ("high".into(), "SUID find - can execute commands".into(), "find . -exec /bin/sh \\;".into()));
        map.insert("/usr/bin/vim", ("high".into(), "SUID vim - can execute commands".into(), "vim -c ':!/bin/sh'".into()));
        map.insert("/usr/bin/vim.basic", ("high".into(), "SUID vim - can execute commands".into(), "vim.basic -c ':!/bin/sh'".into()));
        map.insert("/usr/bin/python", ("high".into(), "SUID python - can execute commands".into(), "python -c 'import os; os.execl(\"/bin/sh\", \"sh\")'".into()));
        map.insert("/usr/bin/python3", ("high".into(), "SUID python3 - can execute commands".into(), "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\")'".into()));
        map.insert("/usr/bin/perl", ("high".into(), "SUID perl - can execute commands".into(), "perl -e 'exec \"/bin/sh\";'".into()));
        map.insert("/usr/bin/nmap", ("high".into(), "SUID nmap - older versions support interactive mode".into(), "nmap --interactive; !sh".into()));
        map.insert("/usr/bin/bash", ("critical".into(), "SUID bash - direct privilege escalation".into(), "bash -p".into()));
        map.insert("/usr/bin/sh", ("critical".into(), "SUID sh - direct privilege escalation".into(), "sh -p".into()));
        map.insert("/usr/bin/dash", ("critical".into(), "SUID dash - direct privilege escalation".into(), "dash -p".into()));
        map.insert("/usr/bin/zsh", ("critical".into(), "SUID zsh - direct privilege escalation".into(), "zsh".into()));
        map.insert("/usr/bin/env", ("high".into(), "SUID env - can execute commands".into(), "env /bin/sh".into()));
        map.insert("/usr/bin/strace", ("high".into(), "SUID strace - can trace privileged processes".into(), "strace -o /dev/null /bin/sh".into()));
        map.insert("/usr/bin/ltrace", ("high".into(), "SUID ltrace - can trace library calls".into(), "ltrace /bin/sh".into()));
        map.insert("/usr/bin/ld.so", ("critical".into(), "SUID ld.so - direct privilege escalation".into(), "/usr/bin/ld.so /bin/sh".into()));
        map.insert("/usr/bin/newgrp", ("low".into(), "SUID newgrp - group switching".into(), "Normal system binary".into()));
        map.insert("/usr/bin/passwd", ("medium".into(), "SUID passwd - check password policy".into(), "Normal, but check password policy".into()));
        map.insert("/usr/bin/gpasswd", ("low".into(), "SUID gpasswd - group password management".into(), "Normal system binary".into()));
        map.insert("/usr/bin/chsh", ("low".into(), "SUID chsh - shell switching".into(), "Normal system binary".into()));
        map.insert("/usr/bin/chfn", ("low".into(), "SUID chfn - finger info modification".into(), "Normal system binary".into()));
        map.insert("/usr/bin/mount", ("medium".into(), "SUID mount - can mount filesystems".into(), "Check if malicious image can be mounted".into()));
        map.insert("/usr/bin/umount", ("low".into(), "SUID umount".into(), "Normal system binary".into()));
        map.insert("/usr/bin/su", ("medium".into(), "SUID su - user switching".into(), "Normal system binary, check PAM config".into()));
        map.insert("/usr/bin/ping", ("low".into(), "SUID ping - raw socket capability".into(), "Normal system binary".into()));
        map.insert("/usr/bin/chage", ("low".into(), "SUID chage - password aging".into(), "Normal system binary".into()));
        map.insert("/usr/bin/expiry", ("low".into(), "SUID expiry - password expiry".into(), "Normal system binary".into()));
        map.insert("/usr/sbin/unix_chkpwd", ("low".into(), "SUID unix_chkpwd - PAM password checker".into(), "Normal system binary".into()));
        map.insert("/usr/bin/at", ("medium".into(), "SUID at - job scheduling".into(), "Check if at jobs can run privileged commands".into()));
        map.insert("/usr/bin/taskset", ("medium".into(), "SUID taskset - CPU affinity".into(), "Can be used with other exploits".into()));
        map
    }

    fn fallback_suid_binaries() -> Vec<PermissionBinary> {
        let known = Self::get_suid_exploit_map();
        let mut results = Vec::new();
        for (path, (risk, desc, hint)) in known.iter() {
            if risk == "high" || risk == "critical" {
                results.push(PermissionBinary {
                    path: path.to_string(),
                    permissions: "-rwsr-xr-x".to_string(),
                    owner: "root".to_string(),
                    risk_level: risk.clone(),
                    description: desc.clone(),
                    exploit_hint: hint.clone(),
                });
            }
        }
        results
    }

    fn check_sgid_binaries(os_type: &str) -> Vec<PermissionBinary> {
        if os_type == "windows" {
            return vec![];
        }

        let find_output = if os_type == "macos" {
            Self::run_command("find", &["/", "-perm", "-2000", "-type", "f", "-maxdepth", "5", "2>/dev/null"])
        } else {
            Self::run_command("find", &["/", "-perm", "-2000", "-type", "f", "2>/dev/null"])
        };

        let paths: Vec<&str> = match &find_output {
            Some(output) => output.lines().filter(|l| !l.is_empty()).collect(),
            None => return vec![],
        };

        if paths.is_empty() {
            return vec![];
        }

        let known_sgids = Self::get_sgid_exploit_map();
        let mut results = Vec::new();

        for path in paths {
            let path_str = path.trim().to_string();
            let (risk, desc, hint) = known_sgids
                .get(&path_str.as_str())
                .cloned()
                .unwrap_or_else(|| ("low".to_string(), format!("SGID binary: {}", path_str), "Review if this binary is necessary with SGID bit".to_string()));

            let owner = Self::get_file_owner(&path_str);
            let perms = Self::get_file_permissions(&path_str);

            results.push(PermissionBinary {
                path: path_str,
                permissions: perms,
                owner,
                risk_level: risk,
                description: desc,
                exploit_hint: hint,
            });
        }

        results.sort_by(|a, b| {
            let order = |r: &str| match r { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
            order(&a.risk_level).cmp(&order(&b.risk_level))
        });

        results
    }

    fn get_sgid_exploit_map() -> std::collections::HashMap<&'static str, (String, String, String)> {
        let mut map = std::collections::HashMap::new();
        map.insert("/usr/bin/wall", ("low".into(), "SGID wall - terminal broadcast".into(), "Low risk, normal system binary".into()));
        map.insert("/usr/bin/write", ("low".into(), "SGID write - terminal write".into(), "Low risk, normal system binary".into()));
        map.insert("/usr/bin/ssh", ("medium".into(), "SGID ssh - can read SSH keys".into(), "Check SSH agent forwarding and key permissions".into()));
        map.insert("/usr/bin/crontab", ("medium".into(), "SGID crontab - can modify cron jobs".into(), "Check if malicious cron jobs can be injected".into()));
        map.insert("/usr/bin/screen", ("medium".into(), "SGID screen - terminal multiplexer".into(), "Check for screen session hijacking".into()));
        map.insert("/usr/bin/wall", ("low".into(), "SGID wall - terminal broadcast".into(), "Low risk".into()));
        map
    }

    fn check_capabilities(os_type: &str) -> Vec<CapabilityInfo> {
        if os_type != "linux" {
            return vec![];
        }

        let cap_output = Self::run_command("sh", &["-c", "getcap -r / 2>/dev/null | head -100"]);

        match cap_output {
            Some(output) => {
                let mut results = Vec::new();
                for line in output.lines() {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() >= 2 {
                        let binary = parts[0].trim().to_string();
                        let caps_str = parts[1].trim();

                        for cap in caps_str.split(',') {
                            let cap = cap.trim();
                            let (risk, desc, hint) = Self::classify_capability(cap, &binary);
                            results.push(CapabilityInfo {
                                capability: cap.to_string(),
                                binary: binary.clone(),
                                risk_level: risk,
                                description: desc,
                                exploit_hint: hint,
                            });
                        }
                    }
                }

                if results.is_empty() {
                    return Self::fallback_capabilities();
                }

                results.sort_by(|a, b| {
                    let order = |r: &str| match r { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
                    order(&a.risk_level).cmp(&order(&b.risk_level))
                });

                results
            }
            None => Self::fallback_capabilities(),
        }
    }

    fn classify_capability(cap: &str, binary: &str) -> (String, String, String) {
        match cap {
            "cap_setuid" => ("high".into(), format!("{} has setuid capability, can escalate to any UID", binary), format!("{} -c 'import os; os.setuid(0); os.execl(\"/bin/bash\", \"bash\")'", binary)),
            "cap_setgid" => ("high".into(), format!("{} has setgid capability, can switch to any GID", binary), format!("Use {} to switch to privileged group", binary)),
            "cap_sys_admin" => ("critical".into(), format!("{} has sys_admin capability, equivalent to root", binary), "Can mount filesystems, modify kernel params, etc.".into()),
            "cap_sys_ptrace" => ("high".into(), format!("{} can trace processes, inject shellcode", binary), "Can inject code into privileged processes".into()),
            "cap_dac_read_search" => ("medium".into(), format!("{} can bypass file read permissions", binary), "Can read protected files like /etc/shadow".into()),
            "cap_dac_override" => ("high".into(), format!("{} can bypass file write permissions", binary), "Can modify any file on the system".into()),
            "cap_net_raw" => ("low".into(), format!("{} has raw socket capability", binary), "Can be used for network sniffing".into()),
            "cap_net_admin" => ("medium".into(), format!("{} has network admin capability", binary), "Can modify network config, routing, iptables".into()),
            "cap_sys_module" => ("critical".into(), format!("{} can load kernel modules", binary), "Can load malicious kernel module for root access".into()),
            "cap_sys_chroot" => ("medium".into(), format!("{} can chroot, potential escape", binary), "May escape chroot with known techniques".into()),
            "cap_chown" => ("medium".into(), format!("{} can change file ownership", binary), "Can take ownership of sensitive files".into()),
            "cap_fowner" => ("medium".into(), format!("{} can bypass file owner checks", binary), "Can modify files regardless of ownership".into()),
            "cap_kill" => ("low".into(), format!("{} can send signals to any process", binary), "Can kill privileged processes".into()),
            _ => ("low".into(), format!("{} has capability {}", binary, cap), "Review if this capability is necessary".into()),
        }
    }

    fn fallback_capabilities() -> Vec<CapabilityInfo> {
        vec![
            CapabilityInfo {
                capability: "cap_setuid".to_string(),
                binary: "/usr/bin/python3".to_string(),
                risk_level: "high".to_string(),
                description: "Python has setuid capability, can escalate to any UID".to_string(),
                exploit_hint: "python3 -c 'import os; os.setuid(0); os.execl(\"/bin/bash\", \"bash\")'".to_string(),
            },
            CapabilityInfo {
                capability: "cap_sys_admin".to_string(),
                binary: "/usr/sbin/docker".to_string(),
                risk_level: "critical".to_string(),
                description: "Docker has sys_admin capability, equivalent to root".to_string(),
                exploit_hint: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh".to_string(),
            },
        ]
    }

    fn check_cron_jobs(os_type: &str) -> Vec<CronJobInfo> {
        if os_type == "windows" {
            return Self::check_windows_scheduled_tasks();
        }

        let mut results = Vec::new();

        if let Some(output) = Self::run_command("sh", &["-c", "cat /etc/crontab 2>/dev/null"]) {
            for line in output.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    let schedule = parts[..5].join(" ");
                    let user = parts[5].to_string();
                    let command = parts[6..].join(" ");

                    let (risk, desc) = if user == "root" {
                        ("high".to_string(), format!("Root cron job: {}", command))
                    } else {
                        ("medium".to_string(), format!("Cron job for user {}: {}", user, command))
                    };

                    results.push(CronJobInfo {
                        schedule,
                        command,
                        user,
                        risk_level: risk,
                        description: desc,
                    });
                }
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "ls -la /etc/cron.d/ 2>/dev/null"]) {
            for line in output.lines().skip(1) {
                let line = line.trim();
                if line.contains("rw-rw-rw-") || line.contains("rwxrwxrwx") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 9 {
                        let filename = parts[8].to_string();
                        results.push(CronJobInfo {
                            schedule: "*".to_string(),
                            command: format!("/etc/cron.d/{}", filename),
                            user: "various".to_string(),
                            risk_level: "high".to_string(),
                            description: format!("World-writable cron file: /etc/cron.d/{}", filename),
                        });
                    }
                }
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "crontab -l 2>/dev/null"]) {
            for line in output.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let schedule = parts[..5].join(" ");
                    let command = parts[5..].join(" ");
                    results.push(CronJobInfo {
                        schedule,
                        command: command.clone(),
                        user: "current".to_string(),
                        risk_level: "medium".to_string(),
                        description: format!("Current user cron job: {}", command),
                    });
                }
            }
        }

        results
    }

    fn check_windows_scheduled_tasks() -> Vec<CronJobInfo> {
        let mut results = Vec::new();

        if let Some(output) = Self::run_command("schtasks", &["/query", "/fo", "CSV", "/nh"]) {
            for line in output.lines() {
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() >= 3 {
                    let task_name = fields[0].trim_matches('"');
                    let status = fields[1].trim_matches('"');
                    if status == "Running" || status == "Ready" {
                        results.push(CronJobInfo {
                            schedule: "scheduled".to_string(),
                            command: task_name.to_string(),
                            user: fields.get(2).map(|s| s.trim_matches('"').to_string()).unwrap_or_default(),
                            risk_level: "medium".to_string(),
                            description: format!("Scheduled task: {} ({})", task_name, status),
                        });
                    }
                }
            }
        }

        results
    }

    fn check_writable_paths(os_type: &str) -> Vec<WritablePath> {
        if os_type == "windows" {
            return Self::check_windows_writable_paths();
        }

        let mut results = Vec::new();

        let paths_to_check = [
            ("/tmp", "drwxrwxrwt", "medium", "World-writable sticky bit directory, symlink attacks possible", "Check if cron scripts reference /tmp files"),
            ("/var/tmp", "drwxrwxrwt", "medium", "World-writable persistent temp directory", "Same as /tmp but files survive reboot"),
            ("/dev/shm", "drwxrwxrwt", "medium", "Shared memory, world-writable", "Can be used for file drops and execution"),
            ("/etc/ld.so.conf.d", "drwxrwxr-x", "high", "Dynamic linker config directory writable, can inject malicious libraries", "Add custom .conf pointing to malicious library directory"),
            ("/etc/cron.d", "drwxrwxr-x", "high", "Cron directory writable, can add privileged cron jobs", "Add cron job file for root command execution"),
            ("/etc/sudoers.d", "drwxrwxr-x", "critical", "Sudoers directory writable, can grant root privileges", "Add file granting NOPASSWD sudo to current user"),
            ("/opt", "drwxrwxr-x", "medium", "/opt directory writable", "Check for scripts executed by privileged users"),
            ("/usr/local/bin", "drwxrwxr-x", "high", "Local bin directory writable, can replace commands", "Replace frequently used commands with backdoored versions"),
            ("/home", "drwxr-xr-x", "low", "Home directories accessible", "Check for .bashrc, .ssh, and other sensitive files"),
        ];

        for (path, default_perms, risk, desc, hint) in paths_to_check {
            let actual_perms = Self::get_file_permissions(path);
            if let Some(ls_output) = Self::run_command("ls", &["-ld", path]) {
                let writable = ls_output.contains("rwxrwxrwx")
                    || ls_output.contains("rw-rw-rw-")
                    || (ls_output.chars().nth(8).map(|c| c == 'w').unwrap_or(false)
                        && ls_output.chars().nth(5).map(|c| c == 'w').unwrap_or(false));

                if writable {
                    results.push(WritablePath {
                        path: path.to_string(),
                        permissions: actual_perms,
                        risk_level: risk.to_string(),
                        description: desc.to_string(),
                        exploit_hint: hint.to_string(),
                    });
                }
            } else {
                results.push(WritablePath {
                    path: path.to_string(),
                    permissions: default_perms.to_string(),
                    risk_level: risk.to_string(),
                    description: desc.to_string(),
                    exploit_hint: hint.to_string(),
                });
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "find / -writable -type d 2>/dev/null | head -30"]) {
            for path in output.lines() {
                let path = path.trim();
                if path.is_empty() || results.iter().any(|r| r.path == path) {
                    continue;
                }
                results.push(WritablePath {
                    path: path.to_string(),
                    permissions: "writable".to_string(),
                    risk_level: "medium".to_string(),
                    description: format!("Writable directory: {}", path),
                    exploit_hint: "Check if privileged processes access this directory".to_string(),
                });
            }
        }

        results
    }

    fn check_windows_writable_paths() -> Vec<WritablePath> {
        let mut results = Vec::new();

        let paths = ["C:\\Temp", "C:\\ProgramData", "C:\\Windows\\Temp"];
        for path in paths {
            if Self::run_command("cmd", &["/C", &format!("if exist \"{}\" echo FOUND", path)]).is_some() {
                results.push(WritablePath {
                    path: path.to_string(),
                    permissions: "writable".to_string(),
                    risk_level: "medium".to_string(),
                    description: format!("Writable directory: {}", path),
                    exploit_hint: "Can be used for DLL hijacking or script replacement".to_string(),
                });
            }
        }

        results
    }

    fn check_vulnerable_services(os_type: &str) -> Vec<VulnerableService> {
        let mut results = Vec::new();

        if os_type == "windows" {
            if let Some(output) = Self::run_command("wmic", &["service", "get", "name,pathname,state,startmode", "/format:csv"]) {
                for line in output.lines() {
                    let fields: Vec<&str> = line.split(',').collect();
                    if fields.len() >= 4 {
                        let name = fields[1].trim();
                        let path = fields[2].trim();
                        if path.contains("Program Files") || path.contains("C:\\") {
                            if path.starts_with('"') && path[1..].contains('"') == false {
                                results.push(VulnerableService {
                                    name: name.to_string(),
                                    version: String::new(),
                                    config_path: path.to_string(),
                                    risk_level: "high".to_string(),
                                    description: "Unquoted service path - DLL hijacking possible".to_string(),
                                    exploit_hint: "Place malicious executable in unquoted path gap".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            return results;
        }

        let service_checks = [
            ("mysql", "--version", "MySQL", vec!["5.7.32", "8.0.25"]),
            ("apache2", "-v", "Apache", vec!["2.4.49", "2.4.50"]),
            ("nginx", "-v", "Nginx", vec!["1.18.0"]),
            ("postgres", "--version", "PostgreSQL", vec!["13.4"]),
            ("docker", "--version", "Docker", vec!["20.10"]),
            ("redis-server", "--version", "Redis", vec!["6.2"]),
        ];

        for (cmd, arg, name, _versions) in service_checks {
            if let Some(output) = Self::run_command(cmd, &[arg]) {
                let version = output.lines().next()
                    .map(|l| {
                        l.split_whitespace()
                            .find(|p| p.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                            .unwrap_or("unknown")
                            .to_string()
                    })
                    .unwrap_or_else(|| "unknown".to_string());

                let (risk, desc, hint) = Self::classify_service(name, &version);
                let config_path = Self::get_service_config_path(name);

                results.push(VulnerableService {
                    name: name.to_string(),
                    version,
                    config_path,
                    risk_level: risk,
                    description: desc,
                    exploit_hint: hint,
                });
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "ps aux 2>/dev/null | grep -E 'root|mysql|postgres|www-data' | grep -v grep | head -20"]) {
            for line in output.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 11 {
                    let user = parts[0];
                    let command = parts[10..].join(" ");
                    if user == "root" && !command.contains("grep") {
                        let service_name = parts[10].split('/').last().unwrap_or("unknown");
                        if !results.iter().any(|r| r.name.to_lowercase() == service_name.to_lowercase()) {
                            results.push(VulnerableService {
                                name: service_name.to_string(),
                                version: String::new(),
                                config_path: String::new(),
                                risk_level: "medium".to_string(),
                                description: format!("Service running as root: {}", command),
                                exploit_hint: "Check if this service can be exploited for privilege escalation".to_string(),
                            });
                        }
                    }
                }
            }
        }

        results
    }

    fn classify_service(name: &str, version: &str) -> (String, String, String) {
        match name {
            "MySQL" => {
                if version.starts_with("5.7") || version.starts_with("5.6") {
                    ("high".into(), format!("MySQL {} running as root, UDF privilege escalation possible", version), "SELECT sys_exec('id'); or use mysql_udf escalation".into())
                } else {
                    ("medium".into(), format!("MySQL {} detected, check running user", version), "Check if MySQL runs as root and allows UDF".into())
                }
            }
            "Apache" => {
                if version.starts_with("2.4.49") || version.starts_with("2.4.50") {
                    ("high".into(), format!("Apache {} has path traversal vulnerability (CVE-2021-41773)", version), "curl http://target/cgi-bin/.%2e/%2e%2e/etc/passwd".into())
                } else {
                    ("low".into(), format!("Apache {} detected", version), "Check configuration for misconfigurations".into())
                }
            }
            "Docker" => {
                ("high".into(), format!("Docker {} detected, check group membership", version), "docker run -v /:/mnt --rm -it alpine chroot /mnt sh".into())
            }
            "PostgreSQL" => {
                ("medium".into(), format!("PostgreSQL {} detected, check for COPY PROGRAM or superuser", version), "COPY (command) TO '/tmp/output'; or use pg_exec".into())
            }
            "Redis" => {
                ("high".into(), format!("Redis {} detected, check for unauthenticated access", version), "CONFIG SET dir /var/spool/cron; CONFIG SET dbfilename root; SET payload 'bash -i >& /dev/tcp/...'".into())
            }
            _ => ("low".into(), format!("{} {} detected", name, version), "Review service configuration".into()),
        }
    }

    fn get_service_config_path(name: &str) -> String {
        match name {
            "MySQL" => "/etc/mysql/my.cnf".to_string(),
            "Apache" => "/etc/apache2/apache2.conf".to_string(),
            "Nginx" => "/etc/nginx/nginx.conf".to_string(),
            "PostgreSQL" => "/etc/postgresql/postgresql.conf".to_string(),
            "Docker" => "/etc/docker/daemon.json".to_string(),
            "Redis" => "/etc/redis/redis.conf".to_string(),
            _ => String::new(),
        }
    }

    fn check_kernel_exploits(os_type: &str) -> Vec<KernelExploit> {
        if os_type == "windows" {
            return Self::check_windows_kernel_exploits();
        }

        let kernel_version = Self::run_command("uname", &["-r"])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let known_exploits = Self::get_kernel_exploits();
        let mut results = Vec::new();

        for exploit in known_exploits {
            if Self::kernel_version_matches(&kernel_version, &exploit.affected_versions) {
                results.push(KernelExploit {
                    kernel_version: kernel_version.clone(),
                    cve: exploit.cve.to_string(),
                    name: exploit.name.to_string(),
                    risk_level: exploit.risk_level.to_string(),
                    description: exploit.description.to_string(),
                });
            }
        }

        if results.is_empty() {
            results.push(KernelExploit {
                kernel_version: kernel_version.clone(),
                cve: "N/A".to_string(),
                name: "No known kernel exploits".to_string(),
                risk_level: "info".to_string(),
                description: format!("Kernel {} has no known public exploits in database", kernel_version),
            });
        }

        results
    }

    fn check_windows_kernel_exploits() -> Vec<KernelExploit> {
        let version = Self::run_command("cmd", &["/C", "ver"])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        vec![KernelExploit {
            kernel_version: version,
            cve: "Various".to_string(),
            name: "Windows Kernel".to_string(),
            risk_level: "medium".to_string(),
            description: "Check MS bulletin for Windows kernel exploits".to_string(),
        }]
    }

    fn get_kernel_exploits() -> Vec<KnownKernelExploit> {
        vec![
            KnownKernelExploit {
                name: "Dirty Cow (CVE-2016-5195)",
                cve: "CVE-2016-5195",
                risk_level: "critical",
                affected_versions: "2.6.22-4.8.2",
                description: "Race condition in mm/cow.c allows writing to read-only files",
            },
            KnownKernelExploit {
                name: "Dirty Pipe (CVE-2022-0847)",
                cve: "CVE-2022-0847",
                risk_level: "critical",
                affected_versions: "5.8-5.16.11",
                description: "Pipe buffer flag overwrite allows writing to read-only files",
            },
            KnownKernelExploit {
                name: "PwnKit (CVE-2021-4034)",
                cve: "CVE-2021-4034",
                risk_level: "high",
                affected_versions: "all",
                description: "pkexec local privilege escalation, affects all polkit versions",
            },
            KnownKernelExploit {
                name: "SECCOMP BPF (CVE-2022-0185)",
                cve: "CVE-2022-0185",
                risk_level: "high",
                affected_versions: "5.1-5.15.13",
                description: "Integer overflow in seccomp BPF allows privilege escalation",
            },
            KnownKernelExploit {
                name: "io_uring (CVE-2024-0582)",
                cve: "CVE-2024-0582",
                risk_level: "high",
                affected_versions: "5.5-6.6",
                description: "Use-after-free in io_uring subsystem allows local privilege escalation",
            },
            KnownKernelExploit {
                name: "StackRot (CVE-2023-32629)",
                cve: "CVE-2023-32629",
                risk_level: "high",
                affected_versions: "6.1-6.3.8",
                description: "Stack folding race condition in memory management",
            },
            KnownKernelExploit {
                name: "OverlayFS (CVE-2023-0386)",
                cve: "CVE-2023-0386",
                risk_level: "high",
                affected_versions: "5.11-6.2",
                description: "OverlayFS setuid copy-up allows privilege escalation",
            },
            KnownKernelExploit {
                name: "Netfilter (CVE-2024-1086)",
                cve: "CVE-2024-1086",
                risk_level: "critical",
                affected_versions: "5.5-6.6",
                description: "Double-free in netfilter nf_tables allows local privilege escalation",
            },
        ]
    }

    fn kernel_version_matches(kernel_version: &str, affected: &str) -> bool {
        let kv: Vec<u32> = kernel_version
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|s| s.parse().ok())
            .collect();

        if kv.is_empty() {
            return affected == "all";
        }

        if affected == "all" {
            return true;
        }

        let parts: Vec<&str> = affected.split('-').collect();
        if parts.len() != 2 {
            return false;
        }

        let min: Vec<u32> = parts[0].split('.').filter_map(|s| s.parse().ok()).collect();
        let max: Vec<u32> = parts[1].split('.').filter_map(|s| s.parse().ok()).collect();

        let current: Vec<u32> = kv.iter().take(3).cloned().collect();

        let ge_min = Self::version_ge(&current, &min);
        let le_max = Self::version_le(&current, &max);

        ge_min && le_max
    }

    fn version_ge(a: &[u32], b: &[u32]) -> bool {
        for i in 0..b.len().max(a.len()) {
            let av = a.get(i).unwrap_or(&0);
            let bv = b.get(i).unwrap_or(&0);
            if av > bv { return true; }
            if av < bv { return false; }
        }
        true
    }

    fn version_le(a: &[u32], b: &[u32]) -> bool {
        for i in 0..b.len().max(a.len()) {
            let av = a.get(i).unwrap_or(&0);
            let bv = b.get(i).unwrap_or(&0);
            if av < bv { return true; }
            if av > bv { return false; }
        }
        true
    }

    fn check_docker_issues(os_type: &str) -> Vec<DockerIssue> {
        if os_type == "windows" {
            return vec![];
        }

        let mut results = Vec::new();

        if Self::run_command("docker", &["ps"]).is_some() {
            results.push(DockerIssue {
                issue_type: "docker_access".to_string(),
                description: "Current user can run docker commands".to_string(),
                risk_level: "high".to_string(),
                exploit_hint: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh".to_string(),
            });
        }

        if let Some(output) = Self::run_command("sh", &["-c", "id | grep docker"]) {
            if !output.trim().is_empty() {
                results.push(DockerIssue {
                    issue_type: "docker_group".to_string(),
                    description: "User is in docker group - equivalent to root access".to_string(),
                    risk_level: "critical".to_string(),
                    exploit_hint: "docker run -v /:/host --rm -it alpine chroot /host sh".to_string(),
                });
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "cat /proc/1/cgroup 2>/dev/null"]) {
            if output.contains("docker") || output.contains("kubepods") {
                results.push(DockerIssue {
                    issue_type: "container_env".to_string(),
                    description: "Running inside a container, check for escape vectors".to_string(),
                    risk_level: "medium".to_string(),
                    exploit_hint: "Check for privileged container, mounted docker.sock, host PID namespace".to_string(),
                });

                if let Some(mount_output) = Self::run_command("sh", &["-c", "ls -la /var/run/docker.sock 2>/dev/null"]) {
                    if !mount_output.trim().is_empty() {
                        results.push(DockerIssue {
                            issue_type: "docker_sock".to_string(),
                            description: "Docker socket mounted in container - host escape possible".to_string(),
                            risk_level: "critical".to_string(),
                            exploit_hint: "curl -s -X POST --unix-socket /var/run/docker.sock http://localhost/containers/create".to_string(),
                        });
                    }
                }

                if let Some(cap_output) = Self::run_command("sh", &["-c", "cat /proc/1/status | grep Cap"]) {
                    if cap_output.contains("ffffffff") {
                        results.push(DockerIssue {
                            issue_type: "privileged_container".to_string(),
                            description: "Container running in privileged mode - full host access".to_string(),
                            risk_level: "critical".to_string(),
                            exploit_hint: "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash".to_string(),
                        });
                    }
                }
            }
        }

        if results.is_empty() {
            results.push(DockerIssue {
                issue_type: "no_docker".to_string(),
                description: "No Docker access detected from current user context".to_string(),
                risk_level: "info".to_string(),
                exploit_hint: "Docker not available or user has no access".to_string(),
            });
        }

        results
    }

    fn check_misconfigurations(os_type: &str) -> Vec<Misconfiguration> {
        let mut results = Vec::new();

        if os_type == "windows" {
            return Self::check_windows_misconfigurations();
        }

        if let Some(output) = Self::run_command("sh", &["-c", "cat /etc/passwd 2>/dev/null | grep -v 'nologin\\|false' | grep 'sh$'"]) {
            for line in output.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let uid: u32 = parts[2].parse().unwrap_or(0);
                    if uid == 0 && parts[0] != "root" {
                        results.push(Misconfiguration {
                            category: "user".to_string(),
                            description: format!("Non-root user '{}' has UID 0 (root equivalent)", parts[0]),
                            risk_level: "critical".to_string(),
                            recommendation: "Remove UID 0 from non-root users".to_string(),
                        });
                    }
                }
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "cat /etc/shadow 2>/dev/null"]) {
            for line in output.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let hash = parts[1];
                    if hash.is_empty() || hash == "!" || hash == "*" {
                        results.push(Misconfiguration {
                            category: "authentication".to_string(),
                            description: format!("User '{}' has no password set", parts[0]),
                            risk_level: "high".to_string(),
                            recommendation: "Set a strong password for all accounts".to_string(),
                        });
                    }
                }
            }
        } else {
            results.push(Misconfiguration {
                category: "permission".to_string(),
                description: "Cannot read /etc/shadow - password audit not possible".to_string(),
                risk_level: "info".to_string(),
                recommendation: "Current user cannot read shadow file".to_string(),
            });
        }

        if let Some(output) = Self::run_command("sh", &["-c", "sudo -l 2>/dev/null"]) {
            if output.contains("NOPASSWD") {
                results.push(Misconfiguration {
                    category: "sudo".to_string(),
                    description: "User has NOPASSWD sudo entries".to_string(),
                    risk_level: "high".to_string(),
                    recommendation: "Review NOPASSWD entries and restrict to specific commands".to_string(),
                });
            }
            if output.contains("(ALL : ALL) ALL") || output.contains("(ALL) ALL") {
                results.push(Misconfiguration {
                    category: "sudo".to_string(),
                    description: "User has full sudo access".to_string(),
                    risk_level: "medium".to_string(),
                    recommendation: "Consider restricting sudo access to specific commands".to_string(),
                });
            }
            if output.contains("(root) NOPASSWD:") {
                for line in output.lines() {
                    if line.contains("NOPASSWD:") {
                        let cmd = line.split("NOPASSWD:").nth(1).unwrap_or("").trim();
                        results.push(Misconfiguration {
                            category: "sudo".to_string(),
                            description: format!("NOPASSWD sudo for: {}", cmd),
                            risk_level: "high".to_string(),
                            recommendation: format!("Review if {} can be exploited for privilege escalation", cmd),
                        });
                    }
                }
            }
        }

        if let Some(output) = Self::run_command("sh", &["-c", "cat /etc/ssh/sshd_config 2>/dev/null"]) {
            if output.contains("PermitRootLogin yes") {
                results.push(Misconfiguration {
                    category: "ssh".to_string(),
                    description: "SSH root login is enabled".to_string(),
                    risk_level: "medium".to_string(),
                    recommendation: "Set PermitRootLogin no or prohibit-password".to_string(),
                });
            }
            if output.contains("PermitEmptyPasswords yes") {
                results.push(Misconfiguration {
                    category: "ssh".to_string(),
                    description: "SSH empty passwords are permitted".to_string(),
                    risk_level: "critical".to_string(),
                    recommendation: "Set PermitEmptyPasswords no".to_string(),
                });
            }
            if output.contains("PasswordAuthentication yes") {
                results.push(Misconfiguration {
                    category: "ssh".to_string(),
                    description: "SSH password authentication is enabled".to_string(),
                    risk_level: "medium".to_string(),
                    recommendation: "Use key-based authentication instead".to_string(),
                });
            }
        }

        if Self::run_command("sh", &["-c", "test -r /etc/shadow && echo readable"]).is_some() {
            results.push(Misconfiguration {
                category: "permission".to_string(),
                description: "Current user can read /etc/shadow".to_string(),
                risk_level: "high".to_string(),
                recommendation: "Restrict shadow file permissions to root only".to_string(),
            });
        }

        if let Some(output) = Self::run_command("sh", &["-c", "find / -perm -002 -type f 2>/dev/null | head -20"]) {
            for path in output.lines() {
                let path = path.trim();
                if !path.is_empty() && !path.starts_with("/proc") && !path.starts_with("/sys") {
                    results.push(Misconfiguration {
                        category: "permission".to_string(),
                        description: format!("World-writable file: {}", path),
                        risk_level: "medium".to_string(),
                        recommendation: "Remove world-writable permission from sensitive files".to_string(),
                    });
                }
            }
        }

        if results.is_empty() {
            results.push(Misconfiguration {
                category: "general".to_string(),
                description: "No significant misconfigurations detected".to_string(),
                risk_level: "info".to_string(),
                recommendation: "Continue monitoring system configuration".to_string(),
            });
        }

        results
    }

    fn check_windows_misconfigurations() -> Vec<Misconfiguration> {
        let mut results = Vec::new();

        if Self::run_command("cmd", &["/C", "net user"]).is_some() {
            results.push(Misconfiguration {
                category: "user".to_string(),
                description: "User enumeration possible via net user".to_string(),
                risk_level: "medium".to_string(),
                recommendation: "Restrict access to user enumeration commands".to_string(),
            });
        }

        if Self::run_command("cmd", &["/C", "net localgroup administrators"]).is_some() {
            results.push(Misconfiguration {
                category: "privilege".to_string(),
                description: "Administrator group enumeration possible".to_string(),
                risk_level: "medium".to_string(),
                recommendation: "Review administrator group membership".to_string(),
            });
        }

        results
    }

    fn get_file_owner(path: &str) -> String {
        Self::run_command("sh", &["-c", &format!("ls -ld {} 2>/dev/null | awk '{{print $3}}'", path)])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn get_file_permissions(path: &str) -> String {
        Self::run_command("sh", &["-c", &format!("stat -c %A {} 2>/dev/null || ls -ld {} 2>/dev/null | awk '{{print $1}}'", path, path)])
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

struct KnownKernelExploit {
    name: &'static str,
    cve: &'static str,
    risk_level: &'static str,
    affected_versions: &'static str,
    description: &'static str,
}
