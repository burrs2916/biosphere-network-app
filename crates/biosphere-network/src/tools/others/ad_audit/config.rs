use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdAuditConfig {
    pub domain: String,
    pub domain_controller: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub check_kerberos: bool,
    pub check_ldap: bool,
    pub check_smb: bool,
    pub check_dns: bool,
    pub check_certs: bool,
    pub check_trusts: bool,
    pub check_gpo: bool,
    pub check_acl: bool,
    pub check_delegation: bool,
    pub timeout: u64,
}

impl Default for AdAuditConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            domain_controller: None,
            username: None,
            password: None,
            check_kerberos: true,
            check_ldap: true,
            check_smb: true,
            check_dns: true,
            check_certs: true,
            check_trusts: true,
            check_gpo: true,
            check_acl: true,
            check_delegation: true,
            timeout: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosInfo {
    pub pre_auth_not_required: Vec<String>,
    pub as_rep_roastable: Vec<String>,
    pub kerberoastable: Vec<String>,
    pub weak_encryption: Vec<String>,
    pub delegation_accounts: Vec<String>,
    pub unconstrained_delegation: Vec<String>,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapInfo {
    pub domain_name: String,
    pub domain_sid: String,
    pub functional_level: String,
    pub users_count: u32,
    pub groups_count: u32,
    pub computers_count: u32,
    pub admin_count: u32,
    pub disabled_accounts: u32,
    pub password_not_required: Vec<String>,
    pub password_never_expires: Vec<String>,
    pub anonymous_bind: bool,
    pub ldap_signing: bool,
    pub channel_binding: bool,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbInfo {
    pub shares: Vec<SmbShare>,
    pub signing_required: bool,
    pub smb_version: String,
    pub null_sessions: bool,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmbShare {
    pub name: String,
    pub path: String,
    pub comment: String,
    pub readable: bool,
    pub writable: bool,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub zones: Vec<String>,
    pub dynamic_updates: bool,
    pub zone_transfer_possible: bool,
    pub records_count: u32,
    pub wpad_record: bool,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub templates: Vec<CertTemplate>,
    pub vulnerable_templates: Vec<String>,
    pub esc1_vulnerable: Vec<String>,
    pub esc8_vulnerable: bool,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    pub name: String,
    pub enabled: bool,
    pub enrollment_allowed: bool,
    pub authentication_enabled: bool,
    pub vulnerable: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustInfo {
    pub trust_relationships: Vec<TrustRelationship>,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRelationship {
    pub trusted_domain: String,
    pub trust_type: String,
    pub trust_direction: String,
    pub transitive: bool,
    pub sid_filtering: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoInfo {
    pub gpo_count: u32,
    pub gpos: Vec<GpoEntry>,
    pub unlinked_gpos: u32,
    pub password_in_gpo: bool,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpoEntry {
    pub name: String,
    pub guid: String,
    pub status: String,
    pub applies_to: String,
    pub suspicious: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclInfo {
    pub excessive_permissions: Vec<AclEntry>,
    pub dcsync_possible: bool,
    pub issues: Vec<AdIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub object: String,
    pub principal: String,
    pub permission: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdIssue {
    pub category: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub mitre_attack: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdAuditResult {
    pub success: bool,
    pub domain: String,
    pub kerberos_info: KerberosInfo,
    pub ldap_info: LdapInfo,
    pub smb_info: SmbInfo,
    pub dns_info: DnsInfo,
    pub cert_info: CertInfo,
    pub trust_info: TrustInfo,
    pub gpo_info: GpoInfo,
    pub acl_info: AclInfo,
    pub all_issues: Vec<AdIssue>,
    pub total_issues: usize,
    pub critical_issues: usize,
    pub high_issues: usize,
    pub summary: String,
}

pub struct AdAuditTool;

impl AdAuditTool {
    pub async fn audit(config: &AdAuditConfig) -> std::result::Result<AdAuditResult, String> {
        if config.domain.is_empty() {
            return Err("Domain name is required".to_string());
        }

        let domain = config.domain.trim().to_string();
        let dc = config.domain_controller.clone().unwrap_or_else(|| domain.clone());
        let mut all_issues = Vec::new();

        let kerberos_info = if config.check_kerberos {
            let info = Self::check_kerberos(&domain, &dc, config.username.as_deref(), config.password.as_deref());
            all_issues.extend(info.issues.clone());
            info
        } else {
            KerberosInfo { pre_auth_not_required: vec![], as_rep_roastable: vec![], kerberoastable: vec![], weak_encryption: vec![], delegation_accounts: vec![], unconstrained_delegation: vec![], issues: vec![] }
        };

        let ldap_info = if config.check_ldap {
            let info = Self::check_ldap(&domain, &dc, config.username.as_deref(), config.password.as_deref());
            all_issues.extend(info.issues.clone());
            info
        } else {
            LdapInfo { domain_name: String::new(), domain_sid: String::new(), functional_level: String::new(), users_count: 0, groups_count: 0, computers_count: 0, admin_count: 0, disabled_accounts: 0, password_not_required: vec![], password_never_expires: vec![], anonymous_bind: false, ldap_signing: false, channel_binding: false, issues: vec![] }
        };

        let smb_info = if config.check_smb {
            let info = Self::check_smb(&dc);
            all_issues.extend(info.issues.clone());
            info
        } else {
            SmbInfo { shares: vec![], signing_required: false, smb_version: String::new(), null_sessions: false, issues: vec![] }
        };

        let dns_info = if config.check_dns {
            let info = Self::check_dns(&domain, &dc);
            all_issues.extend(info.issues.clone());
            info
        } else {
            DnsInfo { zones: vec![], dynamic_updates: false, zone_transfer_possible: false, records_count: 0, wpad_record: false, issues: vec![] }
        };

        let cert_info = if config.check_certs {
            let info = Self::check_certs(&domain, &dc, config.username.as_deref(), config.password.as_deref());
            all_issues.extend(info.issues.clone());
            info
        } else {
            CertInfo { templates: vec![], vulnerable_templates: vec![], esc1_vulnerable: vec![], esc8_vulnerable: false, issues: vec![] }
        };

        let trust_info = if config.check_trusts {
            let info = Self::check_trusts(&domain, &dc, config.username.as_deref(), config.password.as_deref());
            all_issues.extend(info.issues.clone());
            info
        } else {
            TrustInfo { trust_relationships: vec![], issues: vec![] }
        };

        let gpo_info = if config.check_gpo {
            let info = Self::check_gpo(&domain, &dc, config.username.as_deref(), config.password.as_deref());
            all_issues.extend(info.issues.clone());
            info
        } else {
            GpoInfo { gpo_count: 0, gpos: vec![], unlinked_gpos: 0, password_in_gpo: false, issues: vec![] }
        };

        let acl_info = if config.check_acl {
            let info = Self::check_acl(&domain, &dc, config.username.as_deref(), config.password.as_deref());
            all_issues.extend(info.issues.clone());
            info
        } else {
            AclInfo { excessive_permissions: vec![], dcsync_possible: false, issues: vec![] }
        };

        let total_issues = all_issues.len();
        let critical_issues = all_issues.iter().filter(|i| i.severity == "critical").count();
        let high_issues = all_issues.iter().filter(|i| i.severity == "high").count();

        let summary = format!(
            "AD Audit: Domain={}, Total Issues={}, Critical={}, High={}, Kerberos={}, LDAP={}, SMB={}, DNS={}",
            domain, total_issues, critical_issues, high_issues,
            kerberos_info.issues.len(), ldap_info.issues.len(),
            smb_info.issues.len(), dns_info.issues.len()
        );

        Ok(AdAuditResult {
            success: true,
            domain,
            kerberos_info,
            ldap_info,
            smb_info,
            dns_info,
            cert_info,
            trust_info,
            gpo_info,
            acl_info,
            all_issues,
            total_issues,
            critical_issues,
            high_issues,
            summary,
        })
    }

    fn run_cmd(cmd: &str, args: Vec<String>) -> std::result::Result<String, String> {
        if !Self::cmd_exists(cmd) {
            return Err(format!("Command '{}' not found", cmd));
        }
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = std::process::Command::new(cmd)
            .args(&args_ref)
            .output()
            .map_err(|e| format!("Failed to execute '{}': {}", cmd, e))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !output.status.success() && stdout.trim().is_empty() {
            return Err(format!("Command '{}' failed: {}", cmd, stderr.trim()));
        }
        Ok(stdout)
    }

    fn cmd_exists(cmd: &str) -> bool {
        which::which(cmd).is_ok()
    }

    fn domain_to_dn(domain: &str) -> String {
        domain.split('.')
            .map(|part| format!("DC={}", part))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn build_ldap_args(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>, extra_args: &[&str]) -> Vec<String> {
        let mut args = vec![
            "-H".to_string(), format!("ldap://{}", dc),
            "-b".to_string(), Self::domain_to_dn(domain),
            "-x".to_string(),
        ];

        if let (Some(user), Some(pass)) = (username, password) {
            if !user.is_empty() && !pass.is_empty() {
                args.push("-D".to_string());
                args.push(format!("{}@{}", user, domain));
                args.push("-w".to_string());
                args.push(pass.to_string());
            }
        }

        for arg in extra_args {
            args.push(arg.to_string());
        }

        args
    }

    fn parse_ldap_entries(output: &str, attr: &str) -> Vec<String> {
        let mut entries = Vec::new();
        let attr_lower = attr.to_lowercase();
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with(&attr_lower) || line.starts_with(attr) {
                if let Some(val) = line.split(':').nth(1) {
                    let val = val.trim().to_string();
                    if !val.is_empty() {
                        entries.push(val);
                    }
                }
            }
        }
        entries
    }

    fn check_kerberos(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>) -> KerberosInfo {
        let mut issues = Vec::new();
        let mut pre_auth_not_required = Vec::new();
        let mut as_rep_roastable = Vec::new();
        let mut kerberoastable = Vec::new();
        let mut weak_encryption = Vec::new();
        let mut delegation_accounts = Vec::new();
        let mut unconstrained_delegation = Vec::new();

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", "sAMAccountName", "dn"]
        )) {
            let accounts = Self::parse_ldap_entries(&output, "sAMAccountName");
            pre_auth_not_required = accounts.clone();
            as_rep_roastable = accounts;
        }

        if !pre_auth_not_required.is_empty() {
            issues.push(AdIssue {
                category: "Kerberos".to_string(),
                severity: "high".to_string(),
                title: "AS-REP Roastable Accounts".to_string(),
                description: format!("Found {} accounts without pre-authentication required: {}", pre_auth_not_required.len(), pre_auth_not_required.join(", ")),
                recommendation: "Enable Kerberos pre-authentication for these accounts".to_string(),
                mitre_attack: Some("T1110.004".to_string()),
            });
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=512))", "sAMAccountName", "servicePrincipalName"]
        )) {
            kerberoastable = Self::parse_ldap_entries(&output, "sAMAccountName");
        }

        if !kerberoastable.is_empty() {
            issues.push(AdIssue {
                category: "Kerberos".to_string(),
                severity: "high".to_string(),
                title: "Kerberoastable Accounts".to_string(),
                description: format!("Found {} SPN accounts vulnerable to Kerberoast: {}", kerberoastable.len(), kerberoastable.join(", ")),
                recommendation: "Use gMSA or rotate service account passwords regularly".to_string(),
                mitre_attack: Some("T1558.003".to_string()),
            });
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=3))", "sAMAccountName"]
        )) {
            weak_encryption = Self::parse_ldap_entries(&output, "sAMAccountName");
        }

        if !weak_encryption.is_empty() {
            issues.push(AdIssue {
                category: "Kerberos".to_string(),
                severity: "medium".to_string(),
                title: "Weak Encryption Types".to_string(),
                description: format!("Found {} accounts using weak encryption: {}", weak_encryption.len(), weak_encryption.join(", ")),
                recommendation: "Upgrade encryption type to AES256".to_string(),
                mitre_attack: Some("T1558".to_string()),
            });
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(msDS-AllowedToDelegateTo=*))", "sAMAccountName", "msDS-AllowedToDelegateTo"]
        )) {
            delegation_accounts = Self::parse_ldap_entries(&output, "sAMAccountName");
        }

        if !delegation_accounts.is_empty() {
            issues.push(AdIssue {
                category: "Kerberos".to_string(),
                severity: "critical".to_string(),
                title: "Constrained Delegation Accounts".to_string(),
                description: format!("Found {} accounts with constrained delegation: {}", delegation_accounts.len(), delegation_accounts.join(", ")),
                recommendation: "Review delegation configurations and restrict delegation scope".to_string(),
                mitre_attack: Some("T1558.001".to_string()),
            });
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))", "sAMAccountName"]
        )) {
            unconstrained_delegation = Self::parse_ldap_entries(&output, "sAMAccountName");
        }

        if !unconstrained_delegation.is_empty() {
            issues.push(AdIssue {
                category: "Kerberos".to_string(),
                severity: "critical".to_string(),
                title: "Unconstrained Delegation Accounts".to_string(),
                description: format!("Found {} accounts with unconstrained delegation: {}", unconstrained_delegation.len(), unconstrained_delegation.join(", ")),
                recommendation: "Replace unconstrained delegation with constrained or resource-based delegation".to_string(),
                mitre_attack: Some("T1558.001".to_string()),
            });
        }

        KerberosInfo {
            pre_auth_not_required,
            as_rep_roastable,
            kerberoastable,
            weak_encryption,
            delegation_accounts,
            unconstrained_delegation,
            issues,
        }
    }

    fn check_ldap(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>) -> LdapInfo {
        let mut issues = Vec::new();
        let mut domain_name = String::new();
        let mut domain_sid = String::new();
        let mut functional_level = String::new();
        let mut users_count = 0u32;
        let mut groups_count = 0u32;
        let mut computers_count = 0u32;
        let mut admin_count = 0u32;
        let mut disabled_accounts = 0u32;
        let mut password_not_required = Vec::new();
        let mut password_never_expires = Vec::new();
        let mut anonymous_bind = false;
        let mut ldap_signing = false;
        let mut channel_binding = false;

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=domain))", "name", "objectSid", "msDS-Behavior-Version"]
        )) {
            domain_name = Self::parse_ldap_entries(&output, "name").first().cloned().unwrap_or_default();
            domain_sid = Self::parse_ldap_entries(&output, "objectSid").first().cloned().unwrap_or_default();
            let level = Self::parse_ldap_entries(&output, "msDS-Behavior-Version").first().cloned().unwrap_or_default();
            functional_level = match level.as_str() {
                "0" => "Windows 2000".to_string(),
                "1" => "Windows Server 2003".to_string(),
                "2" => "Windows Server 2003 R2".to_string(),
                "3" => "Windows Server 2008".to_string(),
                "4" => "Windows Server 2008 R2".to_string(),
                "5" => "Windows Server 2012".to_string(),
                "6" => "Windows Server 2012 R2".to_string(),
                "7" => "Windows Server 2016".to_string(),
                "8" => "Windows Server 2019".to_string(),
                "9" => "Windows Server 2022".to_string(),
                _ => format!("Unknown ({})", level),
            };
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", vec![
            "-H".to_string(), format!("ldap://{}", dc),
            "-x".to_string(), "-b".to_string(), "".to_string(),
            "-s".to_string(), "base".to_string(),
            "defaultNamingContext".to_string()
        ]) {
            if output.contains("defaultNamingContext") && !output.contains("error") && !output.contains("Strong auth required") {
                anonymous_bind = true;
                issues.push(AdIssue {
                    category: "LDAP".to_string(),
                    severity: "high".to_string(),
                    title: "Anonymous LDAP Bind Enabled".to_string(),
                    description: "LDAP server allows anonymous bind, enabling unauthenticated enumeration".to_string(),
                    recommendation: "Disable anonymous LDAP bind".to_string(),
                    mitre_attack: Some("T1018".to_string()),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user))", "sAMAccountName"]
        )) {
            users_count = output.lines().filter(|l| l.contains("sAMAccountName")).count() as u32;
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=group))", "sAMAccountName"]
        )) {
            groups_count = output.lines().filter(|l| l.contains("sAMAccountName")).count() as u32;
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=computer))", "sAMAccountName"]
        )) {
            computers_count = output.lines().filter(|l| l.contains("sAMAccountName")).count() as u32;
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(adminCount=1))", "sAMAccountName"]
        )) {
            admin_count = output.lines().filter(|l| l.contains("sAMAccountName")).count() as u32;
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))", "sAMAccountName"]
        )) {
            disabled_accounts = output.lines().filter(|l| l.contains("sAMAccountName")).count() as u32;
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))", "sAMAccountName"]
        )) {
            password_not_required = Self::parse_ldap_entries(&output, "sAMAccountName");
        }

        if !password_not_required.is_empty() {
            issues.push(AdIssue {
                category: "LDAP".to_string(),
                severity: "critical".to_string(),
                title: "Accounts Without Passwords".to_string(),
                description: format!("Found {} accounts that do not require passwords: {}", password_not_required.len(), password_not_required.join(", ")),
                recommendation: "Set strong passwords for these accounts".to_string(),
                mitre_attack: Some("T1078".to_string()),
            });
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))", "sAMAccountName"]
        )) {
            password_never_expires = Self::parse_ldap_entries(&output, "sAMAccountName");
        }

        if !password_never_expires.is_empty() {
            issues.push(AdIssue {
                category: "LDAP".to_string(),
                severity: "medium".to_string(),
                title: "Passwords Never Expire".to_string(),
                description: format!("Found {} accounts with passwords that never expire: {}", password_never_expires.len(), password_never_expires.join(", ")),
                recommendation: "Configure reasonable password expiration policies".to_string(),
                mitre_attack: None,
            });
        }

        if let Ok(output) = Self::run_cmd("nmap", vec![
            "-p".to_string(), "389,636".to_string(),
            "--script=ldap-search".to_string(), dc.to_string()
        ]) {
            ldap_signing = output.contains("signing") && output.contains("required");
            channel_binding = output.contains("channel binding") && output.contains("required");

            if !ldap_signing {
                issues.push(AdIssue {
                    category: "LDAP".to_string(),
                    severity: "medium".to_string(),
                    title: "LDAP Signing Not Required".to_string(),
                    description: "LDAP signing is not enforced, susceptible to MITM attacks".to_string(),
                    recommendation: "Enable LDAP signing requirement".to_string(),
                    mitre_attack: Some("T1557".to_string()),
                });
            }

            if !channel_binding {
                issues.push(AdIssue {
                    category: "LDAP".to_string(),
                    severity: "low".to_string(),
                    title: "LDAP Channel Binding Not Required".to_string(),
                    description: "LDAP channel binding is not enforced".to_string(),
                    recommendation: "Enable LDAP channel binding for LDAPS connections".to_string(),
                    mitre_attack: None,
                });
            }
        }

        LdapInfo {
            domain_name,
            domain_sid,
            functional_level,
            users_count,
            groups_count,
            computers_count,
            admin_count,
            disabled_accounts,
            password_not_required,
            password_never_expires,
            anonymous_bind,
            ldap_signing,
            channel_binding,
            issues,
        }
    }

    fn check_smb(dc: &str) -> SmbInfo {
        let mut issues = Vec::new();
        let mut shares = Vec::new();
        let mut signing_required = false;
        let mut smb_version = String::new();
        let mut null_sessions = false;

        if let Ok(output) = Self::run_cmd("smbclient", vec![
            "-L".to_string(), format!("//{}", dc), "-N".to_string(), "-g".to_string()
        ]) {
            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("Disk|") || line.starts_with("IPC|") || line.starts_with("Printer|") {
                    let parts: Vec<&str> = line.splitn(4, '|').collect();
                    if parts.len() >= 3 {
                        let share_type = parts[0];
                        let name = parts[1].to_string();
                        let comment = if parts.len() >= 4 { parts[3].to_string() } else { String::new() };
                        let writable = comment.to_lowercase().contains("writable");
                        shares.push(SmbShare {
                            name: name.clone(),
                            path: format!("\\\\{}\\{}", dc, name),
                            comment,
                            readable: share_type != "Printer",
                            writable,
                            risk_level: if name == "C$" || name == "ADMIN$" { "critical".to_string() }
                                else if writable { "high".to_string() }
                                else { "low".to_string() },
                        });
                    }
                }
            }

            if !output.contains("NT_STATUS_ACCESS_DENIED") && !output.contains("NT_STATUS_LOGON_FAILURE") {
                null_sessions = true;
                issues.push(AdIssue {
                    category: "SMB".to_string(),
                    severity: "high".to_string(),
                    title: "Null Sessions Allowed".to_string(),
                    description: "SMB service allows null session connections, share info can be enumerated".to_string(),
                    recommendation: "Disable null sessions and restrict anonymous access".to_string(),
                    mitre_attack: Some("T1135".to_string()),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("nmap", vec![
            "-p".to_string(), "445".to_string(),
            "--script=smb2-security-mode".to_string(), dc.to_string()
        ]) {
            if output.contains("Signing required") {
                signing_required = true;
            } else if output.contains("signing not required") {
                issues.push(AdIssue {
                    category: "SMB".to_string(),
                    severity: "medium".to_string(),
                    title: "SMB Signing Not Required".to_string(),
                    description: "SMB signing is not required, susceptible to MITM attacks".to_string(),
                    recommendation: "Enable SMB signing requirement".to_string(),
                    mitre_attack: Some("T1557".to_string()),
                });
            }

            if output.contains("SMBv1") {
                smb_version = "SMBv1".to_string();
                issues.push(AdIssue {
                    category: "SMB".to_string(),
                    severity: "critical".to_string(),
                    title: "SMBv1 Enabled".to_string(),
                    description: "SMBv1 protocol has multiple known vulnerabilities (e.g., EternalBlue)".to_string(),
                    recommendation: "Disable SMBv1 and use SMBv3".to_string(),
                    mitre_attack: Some("T1210".to_string()),
                });
            } else if output.contains("SMBv2") {
                smb_version = "SMBv2".to_string();
            } else if output.contains("SMBv3") {
                smb_version = "SMBv3".to_string();
            }
        }

        let admin_shares: Vec<&SmbShare> = shares.iter().filter(|s| s.name == "C$" || s.name == "ADMIN$").collect();
        if !admin_shares.is_empty() {
            issues.push(AdIssue {
                category: "SMB".to_string(),
                severity: "high".to_string(),
                title: "Admin Shares Exposed".to_string(),
                description: format!("Found {} admin shares: {}", admin_shares.len(), admin_shares.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")),
                recommendation: "Restrict admin share access permissions".to_string(),
                mitre_attack: Some("T1021.002".to_string()),
            });
        }

        SmbInfo { shares, signing_required, smb_version, null_sessions, issues }
    }

    fn check_dns(domain: &str, dc: &str) -> DnsInfo {
        let mut issues = Vec::new();
        let mut zones = Vec::new();
        let mut dynamic_updates = false;
        let mut zone_transfer_possible = false;
        let mut records_count = 0u32;
        let mut wpad_record = false;

        if let Ok(output) = Self::run_cmd("nslookup", vec![
            "-type=any".to_string(), domain.to_string(), dc.to_string()
        ]) {
            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("name = ") || line.contains("origin =") {
                    let zone = line.split('=').next_back().unwrap_or("").trim().trim_end_matches('.').to_string();
                    if !zone.is_empty() && !zones.contains(&zone) {
                        zones.push(zone);
                    }
                }
            }
            records_count = output.lines().filter(|l| l.contains("name =") || l.contains("address")).count() as u32;
        }

        if let Ok(output) = Self::run_cmd("dig", vec![
            "axfr".to_string(), domain.to_string(), format!("@{}", dc)
        ]) {
            if output.contains("XFR size") && !output.contains("Transfer failed") {
                zone_transfer_possible = true;
                issues.push(AdIssue {
                    category: "DNS".to_string(),
                    severity: "critical".to_string(),
                    title: "DNS Zone Transfer Allowed".to_string(),
                    description: "DNS server allows zone transfer, all DNS records can be obtained".to_string(),
                    recommendation: "Restrict DNS zone transfer to authorized servers".to_string(),
                    mitre_attack: Some("T1018".to_string()),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("nslookup", vec![
            "-type=soa".to_string(), domain.to_string(), dc.to_string()
        ]) {
            if output.contains("serial") {
                let soa_info = output.lines()
                    .filter(|l| l.contains("serial") || l.contains("origin"))
                    .collect::<Vec<_>>()
                    .join(" ");
                if soa_info.to_lowercase().contains("dynamic") || soa_info.contains("update") {
                    dynamic_updates = true;
                    issues.push(AdIssue {
                        category: "DNS".to_string(),
                        severity: "high".to_string(),
                        title: "DNS Dynamic Updates Allowed".to_string(),
                        description: "DNS allows dynamic updates, attackers may modify DNS records".to_string(),
                        recommendation: "Restrict DNS dynamic updates to secure channels".to_string(),
                        mitre_attack: Some("T1134".to_string()),
                    });
                }
            }
        }

        if let Ok(output) = Self::run_cmd("nslookup", vec![
            "wpad".to_string(), domain.to_string()
        ]) {
            if output.contains("Address") && !output.contains("NXDOMAIN") && !output.contains("server can't find") {
                wpad_record = true;
                issues.push(AdIssue {
                    category: "DNS".to_string(),
                    severity: "medium".to_string(),
                    title: "WPAD Record Exists".to_string(),
                    description: "WPAD DNS record exists, potential for WPAD spoofing attacks".to_string(),
                    recommendation: "Remove WPAD record or implement WPAD server securely".to_string(),
                    mitre_attack: Some("T1557.001".to_string()),
                });
            }
        }

        DnsInfo { zones, dynamic_updates, zone_transfer_possible, records_count, wpad_record, issues }
    }

    fn check_certs(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>) -> CertInfo {
        let mut issues = Vec::new();
        let mut templates = Vec::new();
        let mut vulnerable_templates = Vec::new();
        let mut esc1_vulnerable = Vec::new();
        let mut esc8_vulnerable = false;

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=pKICertificateTemplate))", "cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Application-Policies"]
        )) {
            let mut current_name = String::new();
            let mut enrollment_allowed = false;
            let mut auth_enabled = false;
            let mut name_flag: u32 = 0;

            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("cn:") {
                    current_name = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.starts_with("msPKI-Enrollment-Flag:") {
                    let flag = line.split(':').nth(1).unwrap_or("").trim();
                    enrollment_allowed = flag != "0";
                } else if line.starts_with("msPKI-Certificate-Name-Flag:") {
                    let flag = line.split(':').nth(1).unwrap_or("").trim();
                    name_flag = flag.parse().unwrap_or(0);
                } else if line.starts_with("msPKI-RA-Application-Policies:") {
                    let val = line.split(':').nth(1).unwrap_or("").trim();
                    auth_enabled = val.contains("Authentication") || val.contains("Client");
                } else if line.is_empty() && !current_name.is_empty() {
                    let mut vulnerable = false;
                    let mut reason = String::new();

                    if enrollment_allowed && auth_enabled {
                        if name_flag & 1 != 0 {
                            vulnerable = true;
                            reason = "ESC1: Client can specify SAN with enrollment".to_string();
                            esc1_vulnerable.push(current_name.clone());
                        } else {
                            vulnerable = true;
                            reason = "Enrollment allowed with authentication enabled".to_string();
                        }
                        vulnerable_templates.push(current_name.clone());
                    }

                    templates.push(CertTemplate {
                        name: current_name.clone(),
                        enabled: true,
                        enrollment_allowed,
                        authentication_enabled: auth_enabled,
                        vulnerable,
                        reason,
                    });

                    current_name.clear();
                    enrollment_allowed = false;
                    auth_enabled = false;
                    name_flag = 0;
                }
            }
        }

        if let Ok(output) = Self::run_cmd("certutil", vec!["-catemplates".to_string()]) {
            for line in output.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.contains("CertUtil") && !line.contains("Template") {
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if !parts.is_empty() {
                        let name = parts[0].trim().to_string();
                        if !templates.iter().any(|t| t.name == name) {
                            templates.push(CertTemplate {
                                name: name.clone(),
                                enabled: true,
                                enrollment_allowed: false,
                                authentication_enabled: false,
                                vulnerable: false,
                                reason: String::new(),
                            });
                        }
                    }
                }
            }
        } else if let Ok(output) = Self::run_cmd("certipy", vec!["find".to_string(), format!("{}@{}", username.unwrap_or(""), domain), "-dc".to_string(), dc.to_string()]) {
            for line in output.lines() {
                let line = line.trim();
                if line.contains("Vulnerable") || line.contains("ESC") {
                    if let Some(name) = line.split_whitespace().next() {
                        if !templates.iter().any(|t| t.name == name) {
                            templates.push(CertTemplate {
                                name: name.to_string(),
                                enabled: true,
                                enrollment_allowed: false,
                                authentication_enabled: false,
                                vulnerable: line.contains("Vulnerable") || line.contains("ESC"),
                                reason: line.to_string(),
                            });
                        }
                    }
                }
            }
        }

        if let Ok(output) = Self::run_cmd("nmap", vec![
            "-p".to_string(), "445".to_string(),
            "--script=msrpc-enum".to_string(), dc.to_string()
        ]) {
            if output.contains("ICPR") && output.contains("HTTP") {
                esc8_vulnerable = true;
                issues.push(AdIssue {
                    category: "Certificate".to_string(),
                    severity: "critical".to_string(),
                    title: "ESC8 - NTLM Relay to AD CS HTTP Endpoints".to_string(),
                    description: "AD CS HTTP enrollment endpoints are exposed, vulnerable to NTLM relay attacks".to_string(),
                    recommendation: "Disable HTTP enrollment endpoints or enable EPA (Extended Protection for Authentication)".to_string(),
                    mitre_attack: Some("T1558.004".to_string()),
                });
            }
        }

        if !vulnerable_templates.is_empty() {
            issues.push(AdIssue {
                category: "Certificate".to_string(),
                severity: "critical".to_string(),
                title: "Vulnerable Certificate Templates".to_string(),
                description: format!("Found {} vulnerable certificate templates: {}", vulnerable_templates.len(), vulnerable_templates.join(", ")),
                recommendation: "Review certificate template configurations and restrict enrollment permissions".to_string(),
                mitre_attack: Some("T1649".to_string()),
            });
        }

        if !esc1_vulnerable.is_empty() {
            issues.push(AdIssue {
                category: "Certificate".to_string(),
                severity: "critical".to_string(),
                title: "ESC1 - Client Authentication with SAN Specifiable".to_string(),
                description: format!("Found {} ESC1 vulnerable templates: {}", esc1_vulnerable.len(), esc1_vulnerable.join(", ")),
                recommendation: "Remove SAN specifiable flag or restrict enrollment to authorized users only".to_string(),
                mitre_attack: Some("T1558.004".to_string()),
            });
        }

        CertInfo { templates, vulnerable_templates, esc1_vulnerable, esc8_vulnerable, issues }
    }

    fn check_trusts(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>) -> TrustInfo {
        let mut issues = Vec::new();
        let mut trust_relationships = Vec::new();

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=trustedDomain))", "cn", "trustType", "trustDirection", "trustAttributes"]
        )) {
            let mut current_domain = String::new();
            let mut trust_type = String::new();
            let mut trust_direction = String::new();
            let mut trust_attrs = String::new();

            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("cn:") {
                    current_domain = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.starts_with("trustType:") {
                    let val = line.split(':').nth(1).unwrap_or("").trim();
                    trust_type = match val {
                        "1" => "Downlevel (Windows NT)".to_string(),
                        "2" => "Uplevel (Windows 2000+)".to_string(),
                        "3" => "MIT Kerberos".to_string(),
                        _ => format!("Unknown ({})", val),
                    };
                } else if line.starts_with("trustDirection:") {
                    let val = line.split(':').nth(1).unwrap_or("").trim();
                    trust_direction = match val {
                        "0" => "Disabled".to_string(),
                        "1" => "Inbound".to_string(),
                        "2" => "Outbound".to_string(),
                        "3" => "Bidirectional".to_string(),
                        _ => format!("Unknown ({})", val),
                    };
                } else if line.starts_with("trustAttributes:") {
                    trust_attrs = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.is_empty() && !current_domain.is_empty() {
                    let attrs_val: i32 = trust_attrs.parse().unwrap_or(0);
                    let transitive = attrs_val & 1 != 0;
                    let sid_filtering = attrs_val & 4 != 0;

                    if !sid_filtering {
                        issues.push(AdIssue {
                            category: "Trust".to_string(),
                            severity: "high".to_string(),
                            title: "SID Filtering Not Enabled".to_string(),
                            description: format!("Trust with {} does not have SID filtering enabled", current_domain),
                            recommendation: "Enable SID filtering to prevent SID history attacks".to_string(),
                            mitre_attack: Some("T1134.005".to_string()),
                        });
                    }

                    if transitive {
                        issues.push(AdIssue {
                            category: "Trust".to_string(),
                            severity: "medium".to_string(),
                            title: "Transitive Trust Detected".to_string(),
                            description: format!("Transitive trust with {} may allow lateral movement", current_domain),
                            recommendation: "Review transitive trust relationships and minimize where possible".to_string(),
                            mitre_attack: Some("T1190".to_string()),
                        });
                    }

                    trust_relationships.push(TrustRelationship {
                        trusted_domain: current_domain.clone(),
                        trust_type: trust_type.clone(),
                        trust_direction: trust_direction.clone(),
                        transitive,
                        sid_filtering,
                    });

                    current_domain.clear();
                    trust_type.clear();
                    trust_direction.clear();
                    trust_attrs.clear();
                }
            }
        }

        TrustInfo { trust_relationships, issues }
    }

    fn check_gpo(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>) -> GpoInfo {
        let mut issues = Vec::new();
        let mut gpos = Vec::new();
        let mut gpo_count = 0u32;
        let mut unlinked_gpos = 0u32;
        let mut password_in_gpo = false;

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=groupPolicyContainer))", "cn", "displayName", "gPCFileSysPath", "gPLink"]
        )) {
            let mut current_name = String::new();
            let mut guid = String::new();
            let mut status = "Enabled".to_string();
            let mut applies_to = String::new();
            let mut suspicious = false;
            let mut reason = String::new();

            for line in output.lines() {
                let line = line.trim();
                if line.starts_with("cn:") {
                    guid = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.starts_with("displayName:") {
                    current_name = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.starts_with("gPCFileSysPath:") {
                    let _path = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.starts_with("gPLink:") {
                    applies_to = line.split(':').nth(1).unwrap_or("").trim().to_string();
                } else if line.is_empty() && !current_name.is_empty() {
                    let name_lower = current_name.to_lowercase();
                    if name_lower.contains("disable") || name_lower.contains("weak") {
                        suspicious = true;
                        reason = "Policy name may indicate security weakening".to_string();
                    }

                    if applies_to.is_empty() {
                        unlinked_gpos += 1;
                    }

                    gpos.push(GpoEntry {
                        name: current_name.clone(),
                        guid: guid.clone(),
                        status: status.clone(),
                        applies_to: applies_to.clone(),
                        suspicious,
                        reason: reason.clone(),
                    });

                    gpo_count += 1;
                    current_name.clear();
                    guid.clear();
                    status = "Enabled".to_string();
                    applies_to.clear();
                    suspicious = false;
                    reason.clear();
                }
            }
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=groupPolicyContainer))", "gPCFileSysPath"]
        )) {
            let paths = Self::parse_ldap_entries(&output, "gPCFileSysPath");
            for path in &paths {
                let xml_patterns = [
                    format!("{}/Machine/Preferences/Groups/Groups.xml", path),
                    format!("{}/User/Preferences/Groups/Groups.xml", path),
                    format!("{}/Machine/Preferences/Services/Services.xml", path),
                    format!("{}/User/Preferences/Drives/Drives.xml", path),
                    format!("{}/Machine/Preferences/DataSource/DataSource.xml", path),
                    format!("{}/User/Preferences/DataSource/DataSource.xml", path),
                ];
                for xml_path in &xml_patterns {
                    if std::path::Path::new(xml_path).exists() {
                        if let Ok(content) = std::fs::read_to_string(xml_path) {
                            if content.contains("cpassword") {
                                password_in_gpo = true;
                                issues.push(AdIssue {
                                    category: "GPO".to_string(),
                                    severity: "critical".to_string(),
                                    title: "Passwords Stored in GPO Preferences".to_string(),
                                    description: format!("GPO preferences file {} contains cpassword attributes that can be decrypted", xml_path),
                                    recommendation: "Remove password storage from GPO preferences and use local account management".to_string(),
                                    mitre_attack: Some("T1552.006".to_string()),
                                });
                                break;
                            }
                        }
                    }
                }
                if password_in_gpo { break; }
            }
            if !password_in_gpo && !paths.is_empty() {
                if let Ok(grep_output) = Self::run_cmd("grep", vec![
                    "-r".to_string(), "--include=*.xml".to_string(), "-l".to_string(),
                    "cpassword".to_string(),
                    paths[0].trim_end_matches('\\').to_string()
                ]) {
                    if !grep_output.trim().is_empty() {
                        password_in_gpo = true;
                        issues.push(AdIssue {
                            category: "GPO".to_string(),
                            severity: "critical".to_string(),
                            title: "Passwords Stored in GPO Preferences".to_string(),
                            description: "GPO preferences contain cpassword attributes with encrypted passwords that can be decrypted".to_string(),
                            recommendation: "Remove password storage from GPO preferences and use local account management".to_string(),
                            mitre_attack: Some("T1552.006".to_string()),
                        });
                    }
                }
            }
        }

        if gpos.iter().any(|g| g.suspicious) {
            let suspicious_names: Vec<&str> = gpos.iter().filter(|g| g.suspicious).map(|g| g.name.as_str()).collect();
            issues.push(AdIssue {
                category: "GPO".to_string(),
                severity: "medium".to_string(),
                title: "Suspicious GPO Policies".to_string(),
                description: format!("Found {} suspicious GPO policies: {}", suspicious_names.len(), suspicious_names.join(", ")),
                recommendation: "Review these GPO policy configurations".to_string(),
                mitre_attack: Some("T1484".to_string()),
            });
        }

        if unlinked_gpos > 0 {
            issues.push(AdIssue {
                category: "GPO".to_string(),
                severity: "low".to_string(),
                title: "Unlinked GPOs Found".to_string(),
                description: format!("Found {} unlinked GPOs that may indicate stale policies", unlinked_gpos),
                recommendation: "Review and clean up unlinked GPOs".to_string(),
                mitre_attack: None,
            });
        }

        GpoInfo { gpo_count, gpos, unlinked_gpos, password_in_gpo, issues }
    }

    fn check_acl(domain: &str, dc: &str, username: Option<&str>, password: Option<&str>) -> AclInfo {
        let mut issues = Vec::new();
        let mut excessive_permissions = Vec::new();
        let mut dcsync_possible = false;

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(adminCount=1))", "sAMAccountName", "distinguishedName"]
        )) {
            let admin_users = Self::parse_ldap_entries(&output, "sAMAccountName");
            if !admin_users.is_empty() {
                excessive_permissions.push(AclEntry {
                    object: "Domain Admins".to_string(),
                    principal: admin_users.join(", "),
                    permission: "Full Control".to_string(),
                    risk_level: "high".to_string(),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))", "sAMAccountName", "distinguishedName"]
        )) {
            let deleg_accounts = Self::parse_ldap_entries(&output, "sAMAccountName");
            if !deleg_accounts.is_empty() {
                excessive_permissions.push(AclEntry {
                    object: "Delegation Accounts".to_string(),
                    principal: deleg_accounts.join(", "),
                    permission: "Delegation Privileges".to_string(),
                    risk_level: "critical".to_string(),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=group)(adminCount=1))", "cn", "member"]
        )) {
            let admin_groups = Self::parse_ldap_entries(&output, "cn");
            let member_count = output.lines().filter(|l| l.starts_with("member:")).count();
            if !admin_groups.is_empty() {
                excessive_permissions.push(AclEntry {
                    object: "Privileged Groups".to_string(),
                    principal: format!("{} ({}, {} members)", admin_groups.join(", "), admin_groups.len(), member_count),
                    permission: "Administrative Access".to_string(),
                    risk_level: "high".to_string(),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=user)(|(UserAccountControl:1.2.840.113556.1.4.803:=4194304)(UserAccountControl:1.2.840.113556.1.4.803:=32)(UserAccountControl:1.2.840.113556.1.4.803:=65536)))", "sAMAccountName", "userAccountControl"]
        )) {
            let risky_accounts = Self::parse_ldap_entries(&output, "sAMAccountName");
            if !risky_accounts.is_empty() {
                excessive_permissions.push(AclEntry {
                    object: "Risky Account Configurations".to_string(),
                    principal: risky_accounts.join(", "),
                    permission: "Weak Account Policy".to_string(),
                    risk_level: "medium".to_string(),
                });
            }
        }

        if let Ok(output) = Self::run_cmd("ldapsearch", Self::build_ldap_args(
            domain, dc, username, password,
            &["(&(objectClass=domain)(distinguishedName=*))", "nTSecurityDescriptor"]
        )) {
            if (output.contains("DS-Replication-Get-Changes") || output.contains("1131f6aa"))
                && (output.contains("1131f6ad") || output.contains("DS-Replication-Get-Changes-All")) {
                    dcsync_possible = true;
                    issues.push(AdIssue {
                        category: "ACL".to_string(),
                        severity: "critical".to_string(),
                        title: "DCSync Attack Possible".to_string(),
                        description: "Replication permissions (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) are granted to non-DA accounts".to_string(),
                        recommendation: "Review replication permissions and restrict to Domain Admins only".to_string(),
                        mitre_attack: Some("T1003.006".to_string()),
                    });
                }
        }

        if !excessive_permissions.is_empty() {
            let high_risk = excessive_permissions.iter().filter(|e| e.risk_level == "high" || e.risk_level == "critical").count();
            if high_risk > 0 {
                issues.push(AdIssue {
                    category: "ACL".to_string(),
                    severity: "high".to_string(),
                    title: "Excessive Permission Assignments".to_string(),
                    description: format!("Found {} high-risk permission assignments", high_risk),
                    recommendation: "Follow least privilege principle and review permission assignments".to_string(),
                    mitre_attack: Some("T1068".to_string()),
                });
            }
        }

        AclInfo { excessive_permissions, dcsync_possible, issues }
    }
}
