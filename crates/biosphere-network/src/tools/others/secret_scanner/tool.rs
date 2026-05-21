use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use reqwest::Client;
use tokio::sync::Semaphore;
use crate::core::{Result, ToolError};
use super::config::*;

pub struct SecretScannerTool;

impl SecretScannerTool {
    pub async fn scan(config: &SecretScanConfig) -> Result<SecretScanResult> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let (max_pages, crawl_depth, concurrent) = match config.scan_mode.as_str() {
            "quick" => (5.min(config.max_pages), 0, 3),
            "balanced" => (20.min(config.max_pages), config.crawl_depth, 5),
            "deep" => (50.min(config.max_pages), (config.crawl_depth + 1).min(3), 8),
            "full" => (config.max_pages, (config.crawl_depth + 2).min(5), 10),
            _ => (20.min(config.max_pages), config.crawl_depth, 5),
        };

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .user_agent(
                config.user_agent.as_deref().unwrap_or(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            );

        if config.follow_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::limited(5));
        } else {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        if !config.verify_ssl {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref proxy) = config.proxy_url {
            if !proxy.is_empty() {
                if let Ok(proxy_parsed) = reqwest::Proxy::all(proxy.as_str()) {
                    client_builder = client_builder.proxy(proxy_parsed);
                }
            }
        }

        let client = client_builder
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut secrets: Vec<DetectedSecret> = Vec::new();
        let mut scanned_urls: HashSet<String> = HashSet::new();
        let mut urls_to_scan: Vec<(String, usize)> = vec![(target_url.clone(), 0)];
        let mut js_files_scanned: usize = 0;
        let mut css_files_scanned: usize = 0;
        let mut all_found_urls: Vec<String> = Vec::new();
        let mut duplicate_count: usize = 0;

        let base_domain = Self::extract_domain(&target_url);

        while let Some((url, depth)) = urls_to_scan.pop() {
            if scanned_urls.len() >= max_pages {
                break;
            }
            if scanned_urls.contains(&url) {
                continue;
            }
            if depth > crawl_depth {
                continue;
            }

            let url_domain = Self::extract_domain(&url);
            if url_domain != base_domain {
                continue;
            }

            scanned_urls.insert(url.clone());
            all_found_urls.push(url.clone());

            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = match resp.text().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            if config.scan_html {
                let before = secrets.len();
                Self::scan_content(&body, &url, "HTML", &mut secrets, false);
                duplicate_count += Self::count_duplicates(&secrets[before..]);
            }

            if config.scan_comments {
                let before = secrets.len();
                Self::scan_html_comments(&body, &url, &mut secrets);
                duplicate_count += Self::count_duplicates(&secrets[before..]);
            }

            if config.scan_meta {
                let before = secrets.len();
                Self::scan_meta_tags(&body, &url, &mut secrets);
                duplicate_count += Self::count_duplicates(&secrets[before..]);
            }

            if config.scan_js {
                let js_urls = Self::extract_js_urls(&body, &url);
                let semaphore = Arc::new(Semaphore::new(concurrent));
                let mut join_set = tokio::task::JoinSet::new();

                for js_url in js_urls.iter().take(max_pages) {
                    if scanned_urls.contains(js_url) {
                        continue;
                    }
                    scanned_urls.insert(js_url.clone());
                    let client = client.clone();
                    let js_url = js_url.clone();
                    let semaphore = semaphore.clone();
                    join_set.spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        match client.get(&js_url).send().await {
                            Ok(resp) => {
                                let body = resp.text().await.unwrap_or_default();
                                Some((js_url, body))
                            }
                            Err(_) => None,
                        }
                    });
                }

                while let Some(result) = join_set.join_next().await {
                    if let Ok(Some((js_url, js_body))) = result {
                        js_files_scanned += 1;
                        let before = secrets.len();
                        Self::scan_content(&js_body, &js_url, "JavaScript", &mut secrets, false);
                        duplicate_count += Self::count_duplicates(&secrets[before..]);
                    }
                }
            }

            if config.scan_css {
                let css_urls = Self::extract_css_urls(&body, &url);
                for css_url in css_urls.iter().take(max_pages) {
                    if scanned_urls.contains(css_url) {
                        continue;
                    }
                    scanned_urls.insert(css_url.clone());
                    if let Ok(resp) = client.get(css_url).send().await {
                        if let Ok(css_body) = resp.text().await {
                            css_files_scanned += 1;
                            let before = secrets.len();
                            Self::scan_css_content(&css_body, css_url, &mut secrets);
                            duplicate_count += Self::count_duplicates(&secrets[before..]);
                        }
                    }
                }
            }

            if !config.custom_patterns.is_empty() {
                let before = secrets.len();
                Self::scan_with_custom_patterns(&body, &url, &config.custom_patterns, &mut secrets);
                duplicate_count += Self::count_duplicates(&secrets[before..]);
            }

            if depth < crawl_depth {
                let links = Self::extract_page_links(&body, &url, &base_domain);
                for link in links {
                    if !scanned_urls.contains(&link) && !urls_to_scan.iter().any(|(u, _)| u == &link) {
                        urls_to_scan.push((link, depth + 1));
                    }
                }
            }
        }

        if config.deduplicate {
            let before = secrets.len();
            secrets = Self::deduplicate_secrets(secrets);
            duplicate_count += before - secrets.len();
        }

        let secrets = Self::apply_filters(secrets, config);
        let severity_stats = Self::compute_severity_stats(&secrets);
        let category_stats = Self::compute_category_stats(&secrets);
        let scan_duration_ms = start.elapsed().as_millis() as u64;
        let pages_scanned = scanned_urls.len();

        let summary = if secrets.is_empty() {
            format!("No secrets found (scanned {} pages, {} JS files, {} CSS files)", pages_scanned, js_files_scanned, css_files_scanned)
        } else {
            format!(
                "Found {} secrets ({} critical, {} high, {} medium) across {} pages, {} JS files, {} CSS files",
                secrets.len(),
                severity_stats.critical,
                severity_stats.high,
                severity_stats.medium,
                pages_scanned,
                js_files_scanned,
                css_files_scanned
            )
        };

        Ok(SecretScanResult {
            url: target_url,
            secrets,
            pages_scanned,
            js_files_scanned,
            css_files_scanned,
            scan_duration_ms,
            summary,
            severity_stats,
            category_stats,
            urls_scanned: all_found_urls,
            duplicate_count,
        })
    }

    fn count_duplicates(secrets: &[DetectedSecret]) -> usize {
        let mut seen = HashSet::new();
        let mut dups = 0;
        for s in secrets {
            let key = format!("{}:{}", s.secret_type, s.full_value);
            if seen.contains(&key) {
                dups += 1;
            } else {
                seen.insert(key);
            }
        }
        dups
    }

    fn deduplicate_secrets(secrets: Vec<DetectedSecret>) -> Vec<DetectedSecret> {
        let mut seen: HashSet<String> = HashSet::new();
        secrets.into_iter().filter(|s| {
            let key = format!("{}:{}", s.secret_type, s.full_value);
            seen.insert(key)
        }).collect()
    }

    fn extract_domain(url: &str) -> String {
        let url = url.trim();
        let after_scheme = if url.starts_with("https://") {
            &url[8..]
        } else if url.starts_with("http://") {
            &url[7..]
        } else {
            url
        };
        if let Some(slash_pos) = after_scheme.find('/') {
            after_scheme[..slash_pos].to_string()
        } else {
            after_scheme.to_string()
        }
    }

    fn extract_page_links(html: &str, base_url: &str, base_domain: &str) -> Vec<String> {
        let mut links = Vec::new();
        let href_re = regex::Regex::new(r#"(?i)href=["']([^"']+\.html?[^"']*)["']"#).unwrap();
        let src_re = regex::Regex::new(r#"(?i)src=["']([^"']+)["']"#).unwrap();

        for re in [&href_re, &src_re] {
            for cap in re.captures_iter(html) {
                let raw = cap.get(1).unwrap().as_str();
                if raw.starts_with('#') || raw.starts_with("javascript:") || raw.starts_with("data:") || raw.starts_with("mailto:") {
                    continue;
                }
                let full_url = Self::resolve_url(base_url, raw);
                if !full_url.is_empty() && Self::extract_domain(&full_url) == base_domain {
                    if !links.contains(&full_url) {
                        links.push(full_url);
                    }
                }
            }
        }
        links
    }

    fn extract_css_urls(html: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();
        let re = regex::Regex::new(r#"(?i)href=["']([^"']*\.css[^"']*)["']"#).unwrap();
        for cap in re.captures_iter(html) {
            let href = cap.get(1).unwrap().as_str();
            let full_url = Self::resolve_url(base_url, href);
            if !full_url.is_empty() {
                urls.push(full_url);
            }
        }
        urls
    }

    fn apply_filters(secrets: Vec<DetectedSecret>, config: &SecretScanConfig) -> Vec<DetectedSecret> {
        let mut filtered: Vec<DetectedSecret> = secrets
            .into_iter()
            .filter(|s| s.confidence >= config.min_confidence)
            .collect();

        if let Some(ref sev) = config.severity_filter {
            if !sev.is_empty() {
                filtered.retain(|s| s.severity == *sev);
            }
        }

        filtered.sort_by(|a, b| {
            let sev_order = |s: &str| -> i32 {
                match s {
                    "critical" => 0,
                    "high" => 1,
                    "medium" => 2,
                    "low" => 3,
                    "info" => 4,
                    _ => 5,
                }
            };
            sev_order(&a.severity).cmp(&sev_order(&b.severity))
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
        });

        filtered
    }

    fn compute_severity_stats(secrets: &[DetectedSecret]) -> SeverityStats {
        SeverityStats {
            critical: secrets.iter().filter(|s| s.severity == "critical").count(),
            high: secrets.iter().filter(|s| s.severity == "high").count(),
            medium: secrets.iter().filter(|s| s.severity == "medium").count(),
            low: secrets.iter().filter(|s| s.severity == "low").count(),
            info: secrets.iter().filter(|s| s.severity == "info").count(),
        }
    }

    fn compute_category_stats(secrets: &[DetectedSecret]) -> Vec<CategoryStat> {
        let mut map: HashMap<String, (usize, usize, usize)> = HashMap::new();
        for s in secrets {
            let entry = map.entry(s.category.clone()).or_insert((0, 0, 0));
            entry.0 += 1;
            if s.severity == "critical" {
                entry.1 += 1;
            }
            if s.severity == "high" {
                entry.2 += 1;
            }
        }
        let mut stats: Vec<CategoryStat> = map
            .into_iter()
            .map(|(category, (count, critical_count, high_count))| CategoryStat { category, count, critical_count, high_count })
            .collect();
        stats.sort_by(|a, b| b.count.cmp(&a.count));
        stats
    }

    fn get_line_number(content: &str, pos: usize) -> usize {
        content[..pos.min(content.len())].lines().count()
    }

    fn get_remediation(_secret_type: &str, category: &str) -> String {
        match category {
            "Cloud" => "Rotate the exposed cloud credential immediately. Use environment variables or secret management services instead of hardcoding.".to_string(),
            "API Key" => "Revoke the exposed API key and generate a new one. Store keys in environment variables or a secrets manager.".to_string(),
            "Payment" => "Rotate payment keys immediately through the provider dashboard. Never expose live keys in client-side code.".to_string(),
            "Crypto" => "Remove private keys from the source immediately. Generate new keypairs and revoke the compromised ones.".to_string(),
            "Database" => "Rotate database credentials and restrict connection string access. Use connection pooling with environment-based configuration.".to_string(),
            "Credential" => "Remove hardcoded credentials. Implement proper authentication flows and use secure credential storage.".to_string(),
            "Email" => "Revoke the exposed email API key. Use server-side proxy for email service calls.".to_string(),
            "Messaging" => "Rotate the messaging token/webhook. Restrict token permissions to minimum required scope.".to_string(),
            "Comment" => "Remove sensitive information from HTML comments. Audit comments before deployment.".to_string(),
            "Config" => "Remove configuration details from client-side code. Use server-side configuration management.".to_string(),
            "Custom" => "Review and remediate the matched pattern. Consider the sensitivity of the exposed data.".to_string(),
            "Meta" => "Remove sensitive information from meta tags. Review SEO and social media meta configurations.".to_string(),
            _ => "Review and remediate the exposed sensitive information immediately.".to_string(),
        }
    }

    fn scan_content(content: &str, source_url: &str, source_type: &str, secrets: &mut Vec<DetectedSecret>, is_custom: bool) {
        let patterns: Vec<(&str, &str, &str, &str, f64)> = vec![
            (r#"AKIA[0-9A-Z]{16}"#, "AWS Access Key ID", "Cloud", "critical", 0.95),
            (r#"aws_secret_access_key\s*=\s*['"]?([0-9a-zA-Z/+=]{40})['"]?"#, "AWS Secret Key (Config)", "Cloud", "critical", 0.95),
            (r#"ASIA[0-9A-Z]{16}"#, "AWS Temporary Access Key", "Cloud", "critical", 0.95),
            (r#"AIza[0-9A-Za-z\-_]{35}"#, "Google API Key", "API Key", "high", 0.90),
            (r#"ya29\.[0-9A-Za-z\-_]+"#, "Google OAuth Access Token", "API Key", "critical", 0.95),
            (r#"ghp_[0-9a-zA-Z]{36}"#, "GitHub Personal Access Token", "API Key", "critical", 0.95),
            (r#"gho_[0-9a-zA-Z]{36}"#, "GitHub OAuth Access Token", "API Key", "critical", 0.95),
            (r#"ghu_[0-9a-zA-Z]{36}"#, "GitHub User-to-Server Token", "API Key", "critical", 0.95),
            (r#"ghs_[0-9a-zA-Z]{36}"#, "GitHub Server-to-Server Token", "API Key", "critical", 0.95),
            (r#"github_pat_[0-9a-zA-Z_]{82}"#, "GitHub Fine-Grained PAT", "API Key", "critical", 0.95),
            (r#"sk-[0-9a-zA-Z]{20}T[0-9a-zA-Z]{40}"#, "OpenAI API Key", "API Key", "critical", 0.95),
            (r#"sk-proj-[0-9a-zA-Z]{40,}"#, "OpenAI Project API Key", "API Key", "critical", 0.95),
            (r#"sk-live-[0-9a-zA-Z]{24,}"#, "Stripe Secret Key", "Payment", "critical", 0.95),
            (r#"pk_live_[0-9a-zA-Z]{24,}"#, "Stripe Publishable Key", "Payment", "medium", 0.90),
            (r#"rk_live_[0-9a-zA-Z]{24,}"#, "Stripe Restricted Key", "Payment", "critical", 0.95),
            (r#"sk_test_[0-9a-zA-Z]{24,}"#, "Stripe Test Secret Key", "Payment", "high", 0.90),
            (r#"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"#, "JWT Token", "API Key", "high", 0.90),
            (r#"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"#, "Private Key (PEM)", "Crypto", "critical", 0.95),
            (r#"-----BEGIN OPENSSH PRIVATE KEY-----"#, "SSH Private Key", "Crypto", "critical", 0.95),
            (r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#, "PGP Private Key", "Crypto", "critical", 0.95),
            (r#"-----BEGIN EC PRIVATE KEY-----"#, "EC Private Key", "Crypto", "critical", 0.95),
            (r#"mongodb(\+srv)?://[^\s'"]+"#, "MongoDB Connection String", "Database", "critical", 0.95),
            (r#"mysql://[^\s'"]+"#, "MySQL Connection String", "Database", "critical", 0.95),
            (r#"postgres(ql)?://[^\s'"]+"#, "PostgreSQL Connection String", "Database", "critical", 0.95),
            (r#"redis://[^\s'"]+"#, "Redis Connection String", "Database", "critical", 0.95),
            (r#"jdbc:[a-z]+://[^\s'"]+"#, "JDBC Connection String", "Database", "critical", 0.90),
            (r#"amqp://[^\s'"]+"#, "AMQP Connection String", "Database", "high", 0.85),
            (r#"SG\.[0-9a-zA-Z_\-]{20,}\.[0-9a-zA-Z_\-]{20,}"#, "SendGrid API Key", "Email", "critical", 0.90),
            (r#"xox[baprs]-[0-9a-zA-Z\-]{10,}"#, "Slack Token", "Messaging", "critical", 0.90),
            (r#"hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}"#, "Slack Webhook", "Messaging", "high", 0.95),
            (r#"SK[0-9a-fA-F]{32}"#, "Twilio API Key", "Messaging", "critical", 0.90),
            (r#"key-[0-9a-zA-Z]{32}"#, "Mailgun API Key", "Email", "high", 0.80),
            (r#"np_[0-9a-fA-F]{32}"#, "New Relic API Key", "API Key", "high", 0.85),
            (r#"NRJS-[0-9a-fA-F]{19}"#, "New Relic Ingest License", "API Key", "high", 0.85),
            (r#"AKIA[0-9A-Z]{16}[:/][0-9a-zA-Z/+=]{40}"#, "AWS Key+Secret Pair", "Cloud", "critical", 0.98),
            (r#"EAACEdEose0cBA[0-9A-Za-z]+"#, "Facebook Access Token", "API Key", "critical", 0.90),
            (r#"EAA[0-9a-zA-Z]+"#, "Facebook Page Access Token", "API Key", "high", 0.80),
            (r#"AIza[0-9A-Za-z\-_]{35}\.apps\.googleusercontent\.com"#, "Google OAuth Client ID", "API Key", "medium", 0.85),
            (r#"sq0csp-[0-9A-Za-z\-_]{43}"#, "Square Access Token", "Payment", "critical", 0.90),
            (r#"sq0atp-[0-9A-Za-z\-_]{22}"#, "Square OAuth Secret", "Payment", "critical", 0.90),
            (r#"sk-[0-9a-fA-F]{32}"#, "Stripe Restricted API Key", "Payment", "critical", 0.90),
            (r#"rk-[0-9a-fA-F]{32}"#, "Stripe Restricted Key", "Payment", "critical", 0.90),
            (r#"key_[0-9a-fA-F]{32}"#, "Mailchimp API Key", "Email", "high", 0.85),
            (r#"dop_v1_[0-9a-fA-F]{32,64}"#, "DigitalOcean API Token", "Cloud", "critical", 0.90),
            (r#"do_v1_[0-9a-fA-F]{32,64}"#, "DigitalOcean OAuth Token", "Cloud", "critical", 0.90),
            (r#"s3\.amazonaws\.com/[^\s'"]+"#, "S3 Bucket URL", "Cloud", "medium", 0.70),
            (r#"https://storage\.googleapis\.com/[^\s'"]+"#, "GCS Bucket URL", "Cloud", "medium", 0.70),
            (r#"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.apps\.googleusercontent\.com"#, "Google OAuth Client ID (UUID)", "API Key", "medium", 0.75),
            (r#"(?i)api[_\-]?key[\s:=]+['"]?([0-9a-zA-Z_\-]{20,})['"]?"#, "API Key (Generic)", "API Key", "high", 0.75),
            (r#"(?i)secret[_\-]?key[\s:=]+['"]?([0-9a-zA-Z_\-]{20,})['"]?"#, "Secret Key (Generic)", "API Key", "high", 0.80),
            (r#"(?i)private[_\-]?key[\s:=]+['"]?([0-9a-zA-Z_\-]{20,})['"]?"#, "Private Key (Generic)", "API Key", "high", 0.80),
            (r#"(?i)access[_\-]?token[\s:=]+['"]?([0-9a-zA-Z_\-]{20,})['"]?"#, "Access Token (Generic)", "API Key", "high", 0.75),
            (r#"(?i)auth[_\-]?token[\s:=]+['"]?([0-9a-zA-Z_\-]{20,})['"]?"#, "Auth Token (Generic)", "API Key", "high", 0.75),
            (r#"(?i)bearer[\s:=]+['"]?([0-9a-zA-Z_\-\.]{20,})['"]?"#, "Bearer Token", "API Key", "high", 0.80),
            (r#"(?i)client[_\-]?secret[\s:=]+['"]?([0-9a-zA-Z_\-]{20,})['"]?"#, "Client Secret", "API Key", "critical", 0.85),
            (r#"(?i)password[\s:=]+['"]?([^\s'"]{8,})['"]?"#, "Password (Hardcoded)", "Credential", "critical", 0.70),
            (r#"(?i)firebase[_\-]?key[\s:=]+['"]?[0-9a-zA-Z_\-]{20,}['"]?"#, "Firebase Key", "Cloud", "high", 0.80),
            (r#"(?i)heroku[_\-]?api[_\-]?key[\s:=]+['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]?"#, "Heroku API Key", "Cloud", "high", 0.85),
            (r#"(?i)slack[_\-]?token[\s:=]+['"]?xox[baprs]-[0-9a-zA-Z\-]{10,}['"]?"#, "Slack Token (Config)", "Messaging", "critical", 0.90),
            (r#"(?i)webhook[_\-]?url[\s:=]+['"]?https://hooks\.slack\.com/[^\s'"]+['"]?"#, "Slack Webhook (Config)", "Messaging", "high", 0.85),
            (r#"(?i)discord[_\-]?token[\s:=]+['"]?[0-9a-zA-Z_\-]{20,}['"]?"#, "Discord Token", "Messaging", "critical", 0.85),
            (r#"(?i)ntfy[_\-]?key[\s:=]+['"]?[0-9a-zA-Z_\-]{20,}['"]?"#, "NTFY Key", "Messaging", "high", 0.75),
            (r#"(?i)pushover[_\-]?key[\s:=]+['"]?[0-9a-zA-Z_\-]{20,}['"]?"#, "Pushover Key", "Messaging", "high", 0.75),
            (r#"(?i)telegram[_\-]?bot[_\-]?token[\s:=]+['"]?[0-9]{8,10}:[0-9a-zA-Z_\-]{35}['"]?"#, "Telegram Bot Token", "Messaging", "critical", 0.90),
        ];

        for (pattern, name, category, severity, confidence) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let full_match = cap.get(0).unwrap();
                    let value = cap.get(1).map(|m| m.as_str()).unwrap_or(full_match.as_str());

                    let preview = if value.len() > 20 {
                        format!("{}...{}", &value[..8], &value[value.len()-8..])
                    } else {
                        value.to_string()
                    };

                    let line_context = Self::get_line_context(content, full_match.start());
                    let line_number = Some(Self::get_line_number(content, full_match.start()));
                    let remediation = Self::get_remediation(name, category);

                    secrets.push(DetectedSecret {
                        secret_type: name.to_string(),
                        category: category.to_string(),
                        severity: severity.to_string(),
                        value_preview: preview,
                        full_value: value.to_string(),
                        source_url: source_url.to_string(),
                        source_type: source_type.to_string(),
                        line_context,
                        line_number,
                        confidence: *confidence,
                        is_custom,
                        remediation,
                    });
                }
            }
        }
    }

    fn scan_with_custom_patterns(content: &str, source_url: &str, patterns: &[String], secrets: &mut Vec<DetectedSecret>) {
        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let full_match = cap.get(0).unwrap();
                    let value = cap.get(1).map(|m| m.as_str()).unwrap_or(full_match.as_str());

                    let preview = if value.len() > 20 {
                        format!("{}...{}", &value[..8], &value[value.len()-8..])
                    } else {
                        value.to_string()
                    };

                    let line_context = Self::get_line_context(content, full_match.start());
                    let line_number = Some(Self::get_line_number(content, full_match.start()));

                    secrets.push(DetectedSecret {
                        secret_type: format!("Custom: {}", pattern),
                        category: "Custom".to_string(),
                        severity: "high".to_string(),
                        value_preview: preview,
                        full_value: value.to_string(),
                        source_url: source_url.to_string(),
                        source_type: "Custom Pattern".to_string(),
                        line_context,
                        line_number,
                        confidence: 0.70,
                        is_custom: true,
                        remediation: Self::get_remediation("Custom", "Custom"),
                    });
                }
            }
        }
    }

    fn scan_html_comments(html: &str, source_url: &str, secrets: &mut Vec<DetectedSecret>) {
        let comment_re = regex::Regex::new(r#"<!--([\s\S]*?)-->"#).unwrap();
        for cap in comment_re.captures_iter(html) {
            let full_match = cap.get(0).unwrap();
            let comment = cap.get(1).unwrap().as_str();
            let comment_lower = comment.to_lowercase();

            let sensitive_keywords = [
                ("password", "Password in Comment", "critical"),
                ("secret", "Secret in Comment", "high"),
                ("api_key", "API Key in Comment", "high"),
                ("apikey", "API Key in Comment", "high"),
                ("token", "Token in Comment", "high"),
                ("private_key", "Private Key in Comment", "critical"),
                ("credential", "Credential in Comment", "high"),
                ("auth", "Auth Info in Comment", "medium"),
                ("debug", "Debug Info in Comment", "low"),
                ("todo", "TODO in Comment", "info"),
                ("fixme", "FIXME in Comment", "info"),
                ("hack", "Hack in Comment", "info"),
                ("temp", "Temp Code in Comment", "info"),
                ("internal", "Internal Info in Comment", "medium"),
                ("confidential", "Confidential Info in Comment", "high"),
                ("admin", "Admin Info in Comment", "medium"),
                ("backup", "Backup Info in Comment", "medium"),
                ("deprecated", "Deprecated Code in Comment", "low"),
                ("vulnerability", "Vulnerability in Comment", "high"),
                ("exploit", "Exploit Info in Comment", "high"),
            ];

            for (keyword, name, severity) in &sensitive_keywords {
                if comment_lower.contains(keyword) {
                    let preview: String = comment.chars().take(100).collect();
                    let line_number = Some(Self::get_line_number(html, full_match.start()));

                    secrets.push(DetectedSecret {
                        secret_type: name.to_string(),
                        category: "Comment".to_string(),
                        severity: severity.to_string(),
                        value_preview: if preview.len() < comment.len() {
                            format!("{}...", preview)
                        } else {
                            preview
                        },
                        full_value: comment.trim().to_string(),
                        source_url: source_url.to_string(),
                        source_type: "HTML Comment".to_string(),
                        line_context: String::new(),
                        line_number,
                        confidence: 0.60,
                        is_custom: false,
                        remediation: Self::get_remediation(name, "Comment"),
                    });
                    break;
                }
            }
        }
    }

    fn scan_meta_tags(html: &str, source_url: &str, secrets: &mut Vec<DetectedSecret>) {
        let meta_re = regex::Regex::new(r#"(?i)<meta[^>]+content=["']([^"']+)["'][^>]*>"#).unwrap();
        for cap in meta_re.captures_iter(html) {
            let content = cap.get(1).unwrap().as_str();
            let content_lower = content.to_lowercase();
            let full_match = cap.get(0).unwrap();

            let sensitive_patterns = [
                ("api_key", "API Key in Meta Tag", "high"),
                ("apikey", "API Key in Meta Tag", "high"),
                ("token", "Token in Meta Tag", "high"),
                ("secret", "Secret in Meta Tag", "high"),
                ("password", "Password in Meta Tag", "critical"),
                ("admin", "Admin Info in Meta Tag", "medium"),
                ("internal", "Internal Info in Meta Tag", "medium"),
            ];

            for (keyword, name, severity) in &sensitive_patterns {
                if content_lower.contains(keyword) {
                    let preview: String = content.chars().take(80).collect();
                    let line_number = Some(Self::get_line_number(html, full_match.start()));

                    secrets.push(DetectedSecret {
                        secret_type: name.to_string(),
                        category: "Meta".to_string(),
                        severity: severity.to_string(),
                        value_preview: if preview.len() < content.len() { format!("{}...", preview) } else { preview },
                        full_value: content.trim().to_string(),
                        source_url: source_url.to_string(),
                        source_type: "HTML Meta".to_string(),
                        line_context: String::new(),
                        line_number,
                        confidence: 0.55,
                        is_custom: false,
                        remediation: Self::get_remediation(name, "Meta"),
                    });
                    break;
                }
            }
        }
    }

    fn scan_css_content(css: &str, source_url: &str, secrets: &mut Vec<DetectedSecret>) {
        let url_re = regex::Regex::new(r#"url\(['"]?([^'")]+)['"]?\)"#).unwrap();
        for cap in url_re.captures_iter(css) {
            let url_val = cap.get(1).unwrap().as_str();
            if url_val.contains("api") || url_val.contains("token") || url_val.contains("key") || url_val.contains("secret") {
                let line_number = Some(Self::get_line_number(css, cap.get(0).unwrap().start()));

                secrets.push(DetectedSecret {
                    secret_type: "Sensitive URL in CSS".to_string(),
                    category: "Config".to_string(),
                    severity: "low".to_string(),
                    value_preview: url_val.chars().take(60).collect(),
                    full_value: url_val.to_string(),
                    source_url: source_url.to_string(),
                    source_type: "CSS".to_string(),
                    line_context: String::new(),
                    line_number,
                    confidence: 0.40,
                    is_custom: false,
                    remediation: Self::get_remediation("Sensitive URL in CSS", "Config"),
                });
            }
        }
    }

    fn extract_js_urls(html: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();
        let re = regex::Regex::new(r#"(?i)src=["']([^"']*\.js[^"']*)["']"#).unwrap();

        for cap in re.captures_iter(html) {
            let src = cap.get(1).unwrap().as_str();
            let full_url = Self::resolve_url(base_url, src);
            if !full_url.is_empty() && !urls.contains(&full_url) {
                urls.push(full_url);
            }
        }

        urls
    }

    fn resolve_url(base: &str, relative: &str) -> String {
        if relative.starts_with("http://") || relative.starts_with("https://") {
            return relative.to_string();
        }
        if relative.starts_with("//") {
            if let Some(scheme_end) = base.find("://") {
                return format!("{}:{}", &base[..scheme_end], relative);
            }
            return format!("https:{}", relative);
        }
        if relative.starts_with('/') {
            let base_trimmed = base.trim_end_matches('/');
            let after_scheme = &base_trimmed[8.min(base_trimmed.len())..];
            if let Some(slash_pos) = after_scheme.find('/') {
                return format!("{}{}", &base_trimmed[..8 + slash_pos], relative);
            }
            return format!("{}{}", base_trimmed, relative);
        }
        if let Some(last_slash) = base.rfind('/') {
            format!("{}/{}", &base[..last_slash], relative)
        } else {
            format!("{}/{}", base, relative)
        }
    }

    fn get_line_context(content: &str, pos: usize) -> String {
        let start = if pos > 50 { pos - 50 } else { 0 };
        let end = (pos + 50).min(content.len());
        let context = &content[start..end];
        context.replace('\n', " ").replace('\r', "").trim().to_string()
    }
}
