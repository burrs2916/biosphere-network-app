use crate::core::{Result, ToolError};
use super::config::{EmailVerifyConfig, EmailVerifyResult, EmailVerifyEntry, DISPOSABLE_DOMAINS, ROLE_ACCOUNTS};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct EmailVerifierTool;

impl EmailVerifierTool {
    pub async fn verify(config: &EmailVerifyConfig) -> Result<EmailVerifyResult> {
        if config.emails.is_empty() {
            return Err(ToolError::ExecutionError("No emails provided".to_string()));
        }

        let semaphore = Arc::new(Semaphore::new(10));
        let mut join_set = tokio::task::JoinSet::new();

        for email in &config.emails {
            let email = email.trim().to_string();
            let check_smtp = config.check_smtp;
            let check_spf = config.check_spf;
            let check_dkim = config.check_dkim;
            let check_dmarc = config.check_dmarc;
            let check_breach = config.check_breach;
            let timeout = config.timeout;
            let semaphore = semaphore.clone();

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                Self::verify_single(&email, check_smtp, check_spf, check_dkim, check_dmarc, check_breach, timeout).await
            });
        }

        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(entry) = result {
                results.push(entry);
            }
        }

        let total_checked = results.len();
        let valid_count = results.iter().filter(|r| r.status == "Valid").count();
        let risky_count = results.iter().filter(|r| r.risk_level == "medium" || r.risk_level == "high").count();
        let invalid_count = total_checked - valid_count - risky_count;

        let summary = format!(
            "Checked {} emails: {} valid, {} risky, {} invalid",
            total_checked, valid_count, risky_count, invalid_count
        );

        Ok(EmailVerifyResult {
            results,
            total_checked,
            valid_count,
            invalid_count,
            risky_count,
            summary,
        })
    }

    async fn verify_single(
        email: &str,
        check_smtp: bool,
        check_spf: bool,
        check_dkim: bool,
        check_dmarc: bool,
        check_breach: bool,
        timeout: u64,
    ) -> EmailVerifyEntry {
        let parts: Vec<&str> = email.rsplitn(2, '@').collect();
        if parts.len() != 2 {
            return EmailVerifyEntry {
                email: email.to_string(),
                local_part: String::new(),
                domain: String::new(),
                is_valid_format: false,
                mx_records_found: false,
                mx_records: vec![],
                smtp_reachable: None,
                is_disposable: false,
                is_role_account: false,
                is_catch_all: None,
                spf_record: None,
                dkim_record: None,
                dmarc_record: None,
                breach_count: None,
                risk_score: 100.0,
                risk_level: "critical".to_string(),
                status: "Invalid Format".to_string(),
                details: "Email does not contain @ symbol".to_string(),
            };
        }

        let domain = parts[0];
        let local_part = parts[1];

        let is_valid_format = Self::validate_format(email);
        let is_disposable = DISPOSABLE_DOMAINS.contains(&domain.to_lowercase().as_str());
        let is_role_account = ROLE_ACCOUNTS.contains(&local_part.to_lowercase().as_str());

        let (mx_records_found, mx_records) = Self::check_mx_records(domain).await;

        let smtp_reachable = if check_smtp && mx_records_found {
            Some(Self::check_smtp_reachable(domain, timeout).await)
        } else {
            None
        };

        let is_catch_all = if mx_records_found && check_smtp {
            Some(Self::check_catch_all(domain, &local_part, timeout).await)
        } else {
            None
        };

        let spf_record = if check_spf { Self::check_spf(domain).await } else { None };
        let dkim_record = if check_dkim { Self::check_dkim(domain).await } else { None };
        let dmarc_record = if check_dmarc { Self::check_dmarc(domain).await } else { None };
        let breach_count = if check_breach { Self::check_breach(email).await } else { None };

        let risk_score = Self::calculate_risk_score(
            is_valid_format,
            is_disposable,
            is_role_account,
            mx_records_found,
            smtp_reachable,
            is_catch_all,
            &spf_record,
            &dmarc_record,
            breach_count,
        );

        let risk_level = Self::get_risk_level(risk_score);

        let (status, details) = if !is_valid_format {
            ("Invalid Format".to_string(), "Email format is invalid".to_string())
        } else if is_disposable {
            ("Disposable".to_string(), "This is a disposable/temporary email domain".to_string())
        } else if !mx_records_found {
            ("Invalid Domain".to_string(), "No MX records found for this domain".to_string())
        } else if smtp_reachable == Some(false) {
            ("Unreachable".to_string(), "SMTP server is not reachable".to_string())
        } else if is_catch_all == Some(true) {
            ("Catch-All".to_string(), "Domain accepts all email addresses (catch-all)".to_string())
        } else if is_role_account {
            ("Role Account".to_string(), "This is a role-based email address (not a personal inbox)".to_string())
        } else if breach_count.map_or(false, |c| c > 0) {
            ("Breached".to_string(), format!("Found in {} data breach(es)", breach_count.unwrap()))
        } else {
            ("Valid".to_string(), "Email appears to be valid".to_string())
        };

        EmailVerifyEntry {
            email: email.to_string(),
            local_part: local_part.to_string(),
            domain: domain.to_string(),
            is_valid_format,
            mx_records_found,
            mx_records,
            smtp_reachable,
            is_disposable,
            is_role_account,
            is_catch_all,
            spf_record,
            dkim_record,
            dmarc_record,
            breach_count,
            risk_score,
            risk_level,
            status,
            details,
        }
    }

    fn validate_format(email: &str) -> bool {
        let parts: Vec<&str> = email.splitn(2, '@').collect();
        if parts.len() != 2 {
            return false;
        }
        let local = parts[0];
        let domain = parts[1];

        if local.is_empty() || domain.is_empty() {
            return false;
        }

        if local.len() > 64 || email.len() > 254 {
            return false;
        }

        if local.starts_with('.') || local.ends_with('.') {
            return false;
        }

        if local.contains("..") {
            return false;
        }

        if !domain.contains('.') {
            return false;
        }

        let domain_parts: Vec<&str> = domain.split('.').collect();
        if domain_parts.last().map(|s| s.len()).unwrap_or(0) < 2 {
            return false;
        }

        for part in &domain_parts {
            if part.is_empty() || part.starts_with('-') || part.ends_with('-') {
                return false;
            }
        }

        let valid_local_chars = |c: char| c.is_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+';
        if !local.chars().all(valid_local_chars) {
            return false;
        }

        if local.starts_with('+') {
            return false;
        }

        true
    }

    async fn check_mx_records(domain: &str) -> (bool, Vec<String>) {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::proto::rr::RecordType;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        match resolver.lookup(domain, RecordType::MX).await {
            Ok(lookup) => {
                let records: Vec<String> = lookup.record_iter()
                    .filter_map(|r| {
                        if let Some(data) = r.data() {
                            Some(data.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                let found = !records.is_empty();
                (found, records)
            }
            Err(_) => {
                match resolver.lookup(domain, RecordType::A).await {
                    Ok(a_lookup) => {
                        let found = a_lookup.record_iter().count() > 0;
                        (found, vec![])
                    }
                    Err(_) => (false, vec![]),
                }
            }
        }
    }

    async fn check_smtp_reachable(domain: &str, timeout: u64) -> bool {
        use tokio::net::TcpStream;
        use std::time::Duration;

        let smtp_addr = format!("{}:25", domain);
        match tokio::time::timeout(
            Duration::from_secs(timeout.min(10)),
            TcpStream::connect(&smtp_addr)
        ).await {
            Ok(Ok(_)) => true,
            _ => {
                let alt_addr = format!("{}:587", domain);
                tokio::time::timeout(
                    Duration::from_secs(timeout.min(5)),
                    TcpStream::connect(&alt_addr)
                ).await.map_or(false, |r| r.is_ok())
            }
        }
    }

    async fn check_catch_all(domain: &str, _local_part: &str, timeout: u64) -> bool {
        use tokio::net::TcpStream;
        use std::time::Duration;

        let random_local = format!("catchall.test.{}.check", uuid::Uuid::new_v4().as_simple());
        let from_addr = format!("verify@{}", domain);
        let to_addr = format!("{}@{}", random_local, domain);

        let smtp_addr = format!("{}:25", domain);
        let connect_result = tokio::time::timeout(
            Duration::from_secs(timeout.min(10)),
            TcpStream::connect(&smtp_addr)
        ).await;

        if let Ok(Ok(mut stream)) = connect_result {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut buf = [0u8; 1024];

            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

            let _ = stream.write_all(b"EHLO check.local\r\n").await;
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

            let _ = stream.write_all(format!("MAIL FROM:<{}>\r\n", from_addr).as_bytes()).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

            let _ = stream.write_all(format!("RCPT TO:<{}>\r\n", to_addr).as_bytes()).await;
            let response = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

            let _ = stream.write_all(b"QUIT\r\n").await;

            if let Ok(Ok(n)) = response {
                let resp = String::from_utf8_lossy(&buf[..n]);
                if resp.starts_with("250") {
                    return true;
                }
            }
        }

        false
    }

    async fn check_spf(domain: &str) -> Option<String> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::proto::rr::RecordType;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let spf_domain = format!("_spf.{}", domain);

        if let Ok(lookup) = resolver.lookup(&spf_domain, RecordType::TXT).await {
            for record in lookup.record_iter() {
                if let Some(data) = record.data() {
                    let txt = data.to_string();
                    if txt.starts_with("\"v=spf1") {
                        return Some(txt.trim_matches('"').to_string());
                    }
                }
            }
        }

        if let Ok(lookup) = resolver.lookup(domain, RecordType::TXT).await {
            for record in lookup.record_iter() {
                if let Some(data) = record.data() {
                    let txt = data.to_string();
                    if txt.starts_with("\"v=spf1") {
                        return Some(txt.trim_matches('"').to_string());
                    }
                }
            }
        }

        None
    }

    async fn check_dkim(domain: &str) -> Option<String> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::proto::rr::RecordType;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let selectors = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "s1", "s2"];
        for selector in selectors {
            let dkim_domain = format!("{}._domainkey.{}", selector, domain);
            if let Ok(lookup) = resolver.lookup(&dkim_domain, RecordType::TXT).await {
                for record in lookup.record_iter() {
                    if let Some(data) = record.data() {
                        let txt = data.to_string();
                        if txt.contains("v=DKIM1") {
                            return Some(txt.trim_matches('"').to_string());
                        }
                    }
                }
            }
        }

        None
    }

    async fn check_dmarc(domain: &str) -> Option<String> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::proto::rr::RecordType;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let dmarc_domain = format!("_dmarc.{}", domain);

        if let Ok(lookup) = resolver.lookup(&dmarc_domain, RecordType::TXT).await {
            for record in lookup.record_iter() {
                if let Some(data) = record.data() {
                    let txt = data.to_string();
                    if txt.contains("v=DMARC1") {
                        return Some(txt.trim_matches('"').to_string());
                    }
                }
            }
        }

        None
    }

    async fn check_breach(_email: &str) -> Option<usize> {
        None
    }

    fn calculate_risk_score(
        is_valid_format: bool,
        is_disposable: bool,
        is_role_account: bool,
        mx_records_found: bool,
        smtp_reachable: Option<bool>,
        is_catch_all: Option<bool>,
        spf_record: &Option<String>,
        dmarc_record: &Option<String>,
        breach_count: Option<usize>,
    ) -> f64 {
        let mut score: f64 = 0.0;

        if !is_valid_format {
            return 100.0;
        }

        if is_disposable {
            score += 60.0;
        }

        if is_role_account {
            score += 20.0;
        }

        if !mx_records_found {
            score += 50.0;
        }

        if smtp_reachable == Some(false) {
            score += 30.0;
        }

        if is_catch_all == Some(true) {
            score += 25.0;
        }

        if spf_record.is_none() {
            score += 10.0;
        }

        if dmarc_record.is_none() {
            score += 10.0;
        }

        if let Some(count) = breach_count {
            if count > 0 {
                score += 15.0_f64.min(count as f64 * 5.0_f64);
            }
        }

        score.min(100.0_f64)
    }

    fn get_risk_level(score: f64) -> String {
        if score >= 80.0 {
            "critical".to_string()
        } else if score >= 50.0 {
            "high".to_string()
        } else if score >= 25.0 {
            "medium".to_string()
        } else if score >= 10.0 {
            "low".to_string()
        } else {
            "safe".to_string()
        }
    }
}
