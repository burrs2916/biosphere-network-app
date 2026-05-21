use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use reqwest::Client;
use tokio::sync::Semaphore;
use crate::core::{Result, ToolError};
use super::config::*;

const QUICK_PATHS: &[&str] = &[
    "admin", "admin/", "admin/login", "administrator", "login",
    "wp-admin", "wp-login.php", "dashboard", "panel", "backend",
    "cpanel", "manager", "console", "phpmyadmin",
];

const NORMAL_PATHS: &[&str] = &[
    "admin", "admin/", "admin/login", "admin/login.php", "admin/login.html",
    "admin/index.php", "admin/index.html", "admin/dashboard", "admin/console",
    "admin/admin.php", "admin/home", "admin/home.php",
    "administrator", "administrator/", "administrator/login", "administrator/index.php",
    "login", "login.php", "login.html", "login/index.php", "login/admin",
    "wp-admin", "wp-admin/", "wp-login.php", "wp-login", "wp-admin/login.php",
    "dashboard", "dashboard/", "dashboard/login", "dashboard/index.php",
    "control", "control/", "controlpanel", "controlpanel/",
    "manager", "manager/", "manager/login", "manager/index.php",
    "backend", "backend/", "backend/login", "backend/index.php",
    "panel", "panel/", "panel/login", "panel/index.php",
    "cpanel", "cpanel/", "cpanel/login",
    "user", "user/login", "user/login.php",
    "account", "account/login", "account/login.php",
    "auth", "auth/login", "auth/signin",
    "signin", "signin.php", "signin.html", "sign-in", "sign-in/",
    "console", "console/", "console/login",
    "portal", "portal/", "portal/login",
    "system", "system/", "system/login",
    "manage", "manage/", "manage/login",
    "adm", "adm/", "adm/login",
    "cms", "cms/", "cms/admin", "cms/login",
    "phpmyadmin", "phpmyadmin/", "phpmyadmin/index.php",
    "pma", "pma/", "pma/index.php",
];

const DEEP_PATHS: &[&str] = &[
    "admin", "admin/", "admin/login", "admin/login.php", "admin/login.html",
    "admin/index.php", "admin/index.html", "admin/dashboard", "admin/console",
    "admin/admin.php", "admin/home", "admin/home.php", "admin/settings",
    "admin/profile", "admin/users", "admin/upload", "admin/api",
    "admin/config", "admin/log", "admin/stats", "admin/cache",
    "administrator", "administrator/", "administrator/login", "administrator/index.php",
    "administrator/dashboard", "administrator/config",
    "login", "login.php", "login.html", "login/index.php", "login/admin",
    "login/auth", "login/sso", "login/oauth", "login/callback",
    "wp-admin", "wp-admin/", "wp-login.php", "wp-login", "wp-admin/login.php",
    "wp-admin/admin-ajax.php", "wp-admin/options.php", "wp-admin/edit.php",
    "dashboard", "dashboard/", "dashboard/login", "dashboard/index.php",
    "dashboard/admin", "dashboard/settings", "dashboard/analytics",
    "control", "control/", "controlpanel", "controlpanel/",
    "manager", "manager/", "manager/login", "manager/index.php",
    "backend", "backend/", "backend/login", "backend/index.php",
    "panel", "panel/", "panel/login", "panel/index.php",
    "cpanel", "cpanel/", "cpanel/login", "cpanel/index.php",
    "user", "user/login", "user/login.php", "user/register",
    "account", "account/login", "account/login.php", "account/register",
    "auth", "auth/login", "auth/signin", "auth/register", "auth/forgot-password",
    "signin", "signin.php", "signin.html", "sign-in", "sign-in/",
    "signup", "signup.php", "signup.html", "sign-up",
    "console", "console/", "console/login", "console/dashboard",
    "portal", "portal/", "portal/login", "portal/dashboard",
    "system", "system/", "system/login", "system/admin",
    "manage", "manage/", "manage/login", "manage/admin",
    "adm", "adm/", "adm/login", "adm/index.php",
    "cms", "cms/", "cms/admin", "cms/login", "cms/dashboard",
    "siteadmin", "siteadmin/", "siteadmin/login",
    "adminarea", "adminarea/", "adminarea/login",
    "admin1", "admin1/", "admin1/login",
    "admin2", "admin2/", "admin2/login",
    "admin3", "admin3/", "admin3/login",
    "admin4", "admin4/", "admin4/login",
    "backoffice", "backoffice/", "backoffice/login",
    "staff", "staff/", "staff/login",
    "moderator", "moderator/", "moderator/login",
    "webadmin", "webadmin/", "webadmin/login",
    "sysadmin", "sysadmin/", "sysadmin/login",
    "admincp", "admincp/", "admincp/login",
    "modcp", "modcp/", "modcp/login",
    "phpmyadmin", "phpmyadmin/", "phpmyadmin/index.php", "phpmyadmin/setup",
    "pma", "pma/", "pma/index.php",
    "mysql", "mysql/", "mysql/admin",
    "db", "db/", "db/admin", "db/console",
    "database", "database/", "database/admin",
    "sql", "sql/", "sql/admin",
    "server", "server/", "server-status", "server-info",
    "config", "config/", "config.php", "config.json", "config.yml",
    "setup", "setup/", "setup.php",
    "install", "install/", "install.php",
    ".env", ".git", ".git/config", ".svn",
    "api", "api/", "api/docs", "api/swagger", "api/v1", "api/admin",
    "graphql", "graphiql",
    "debug", "debug/", "debug/login",
    "test", "test/", "test/admin",
    "dev", "dev/", "dev/login",
    "staging", "staging/", "staging/login",
    "monitor", "monitor/", "monitor/login", "monitor/dashboard",
    "analytics", "analytics/", "analytics/login",
    "report", "report/", "report/login",
    "crm", "crm/", "crm/login", "crm/admin",
    "erp", "erp/", "erp/login", "erp/admin",
    "hr", "hr/", "hr/login", "hr/admin",
    "mail", "mail/", "mail/admin", "webmail",
    "ftp", "ftp/", "ftp/admin",
    "ssh", "ssh/", "ssh/admin",
    "docker", "docker/", "docker/api",
    "jenkins", "jenkins/", "jenkins/login",
    "gitlab", "gitlab/", "gitlab/admin",
    "grafana", "grafana/", "grafana/login",
    "kibana", "kibana/", "kibana/app/kibana",
    "prometheus", "prometheus/", "prometheus/graph",
    "rabbitmq", "rabbitmq/", "rabbitmq/api",
    "redis", "redis/", "redis/commander",
    "minio", "minio/", "minio/console",
    "traefik", "traefik/", "traefik/dashboard",
    "swagger", "swagger-ui", "swagger-ui/", "api-docs",
    "solr", "solr/", "solr/admin",
];

fn random_ua() -> String {
    let agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ];
    let idx = rand::Rng::gen_range(&mut rand::thread_rng(), 0..agents.len());
    agents[idx].to_string()
}

fn classify_path(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.contains("wp-admin") || lower.contains("wp-login") {
        "WordPress".to_string()
    } else if lower.contains("phpmyadmin") || lower.contains("pma") || lower.contains("mysql") || lower.contains("sql") || lower.contains("db") || lower.contains("database") {
        "Database".to_string()
    } else if lower.contains("api") || lower.contains("swagger") || lower.contains("graphql") || lower.contains("api-docs") {
        "API".to_string()
    } else if lower.contains("jenkins") || lower.contains("gitlab") || lower.contains("docker") || lower.contains("grafana") || lower.contains("kibana") || lower.contains("prometheus") || lower.contains("rabbitmq") || lower.contains("redis") || lower.contains("minio") || lower.contains("traefik") {
        "DevOps".to_string()
    } else if lower.contains("config") || lower.contains("setup") || lower.contains("install") || lower.contains(".env") || lower.contains(".git") || lower.contains(".svn") {
        "Sensitive".to_string()
    } else if lower.contains("mail") || lower.contains("webmail") || lower.contains("ftp") || lower.contains("ssh") || lower.contains("solr") {
        "Service".to_string()
    } else if lower.contains("crm") || lower.contains("erp") || lower.contains("hr") || lower.contains("monitor") || lower.contains("analytics") || lower.contains("report") {
        "Business".to_string()
    } else if lower.contains("login") || lower.contains("signin") || lower.contains("sign-in") || lower.contains("auth") {
        "Login".to_string()
    } else if lower.contains("admin") || lower.contains("administrator") || lower.contains("adm") || lower.contains("backend") || lower.contains("backoffice") || lower.contains("admincp") || lower.contains("siteadmin") || lower.contains("adminarea") || lower.contains("webadmin") || lower.contains("sysadmin") {
        "Admin".to_string()
    } else if lower.contains("panel") || lower.contains("cpanel") || lower.contains("control") || lower.contains("manage") || lower.contains("manager") || lower.contains("dashboard") || lower.contains("console") {
        "Panel".to_string()
    } else if lower.contains("cms") || lower.contains("modcp") || lower.contains("moderator") || lower.contains("staff") {
        "CMS".to_string()
    } else if lower.contains("debug") || lower.contains("test") || lower.contains("dev") || lower.contains("staging") || lower.contains("server-status") || lower.contains("server-info") {
        "Debug".to_string()
    } else {
        "Other".to_string()
    }
}

fn detect_login_form(html: &str) -> bool {
    let lower = html.to_lowercase();
    (lower.contains("<form") && lower.contains("password") && (lower.contains("type=\"password\"") || lower.contains("type='password'")))
        || lower.contains("<input type=\"password\"")
        || lower.contains("<input type='password'")
}

fn calculate_confidence(path: &str, status: u16, title: Option<&str>, has_login_form: bool) -> f64 {
    let mut score: f64 = 0.0;
    let lower = path.to_lowercase();

    if status == 200 {
        score += 0.3;
    } else if (300..400).contains(&status) {
        score += 0.15;
    }

    if lower.contains("admin") || lower.contains("administrator") {
        score += 0.25;
    }
    if lower.contains("login") || lower.contains("signin") || lower.contains("sign-in") {
        score += 0.2;
    }
    if lower.contains("dashboard") || lower.contains("panel") || lower.contains("console") {
        score += 0.15;
    }
    if lower.contains("cpanel") || lower.contains("phpmyadmin") || lower.contains("wp-admin") {
        score += 0.2;
    }

    if has_login_form {
        score += 0.2;
    }

    if let Some(t) = title {
        let t_lower = t.to_lowercase();
        if t_lower.contains("admin") || t_lower.contains("login") || t_lower.contains("dashboard") {
            score += 0.15;
        }
        if t_lower.contains("sign in") || t_lower.contains("log in") || t_lower.contains("authentication") {
            score += 0.1;
        }
    }

    score.min(1.0_f64)
}

pub struct AdminFinderTool;

impl AdminFinderTool {
    pub async fn find(config: &AdminFinderConfig) -> Result<AdminFinderResult> {
        let start = std::time::Instant::now();

        let trimmed = config.url.trim();
        let base_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", trimmed.trim_end_matches('/'))
        };

        let ua = if config.randomize_ua {
            random_ua()
        } else {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
        };

        let redirect_policy = if config.follow_redirects {
            reqwest::redirect::Policy::limited(3)
        } else {
            reqwest::redirect::Policy::none()
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(redirect_policy)
            .danger_accept_invalid_certs(true)
            .user_agent(&ua)
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let wordlist: Vec<String> = if !config.wordlist.is_empty() {
            config.wordlist.clone()
        } else {
            match config.scan_mode.as_str() {
                "quick" => QUICK_PATHS.iter().map(|s| s.to_string()).collect(),
                "deep" => DEEP_PATHS.iter().map(|s| s.to_string()).collect(),
                _ => NORMAL_PATHS.iter().map(|s| s.to_string()).collect(),
            }
        };

        let semaphore = Arc::new(Semaphore::new(config.concurrent.min(30)));
        let mut join_set = tokio::task::JoinSet::new();
        let paths_tested = wordlist.len();

        for path in &wordlist {
            let test_url = format!("{}/{}", base_url, path);
            let client = client.clone();
            let path = path.clone();
            let semaphore = semaphore.clone();
            let detect_login = config.detect_login_forms;

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let req_start = std::time::Instant::now();

                match client.get(&test_url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let response_time_ms = req_start.elapsed().as_millis() as u64;
                        let content_length = resp.headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());
                        let redirect_url = if (300..400).contains(&status) {
                            resp.headers().get("location")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string())
                        } else {
                            None
                        };

                        let content_type = resp.headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();

                        let bytes = resp.bytes().await.unwrap_or_default();
                        let body = Self::decode_content(&bytes, &content_type);
                        let title = Self::extract_title(&body);

                        let has_login_form = if detect_login && status == 200 {
                            detect_login_form(&body)
                        } else {
                            false
                        };

                        let category = classify_path(&path);
                        let confidence = calculate_confidence(
                            &path, status,
                            title.as_deref(),
                            has_login_form,
                        );

                        let is_likely_admin = status != 404 && confidence >= 0.5;

                        if status != 404 {
                            Some(AdminPath {
                                url: test_url,
                                path,
                                status_code: status,
                                content_length: content_length.or_else(|| {
                                    let bl = body.len() as u64;
                                    if bl > 0 { Some(bl) } else { None }
                                }),
                                title,
                                redirect_url,
                                is_likely_admin,
                                category,
                                has_login_form,
                                response_time_ms,
                                confidence,
                            })
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            });
        }

        let mut found_paths: Vec<AdminPath> = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(path)) = result {
                found_paths.push(path);
            }
        }

        let waf_detected = if config.detect_waf {
            Self::detect_waf_from_paths(&found_paths)
        } else {
            None
        };

        found_paths.sort_by(|a, b| {
            b.is_likely_admin.cmp(&a.is_likely_admin)
                .then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
                .then(a.status_code.cmp(&b.status_code))
        });

        let mut category_map: HashMap<String, Vec<String>> = HashMap::new();
        for p in &found_paths {
            category_map
                .entry(p.category.clone())
                .or_default()
                .push(p.path.clone());
        }
        let categories: Vec<PathCategory> = category_map
            .into_iter()
            .map(|(name, paths)| PathCategory { count: paths.len(), name, paths })
            .collect();

        let likely_admin_count = found_paths.iter().filter(|p| p.is_likely_admin).count();
        let login_form_count = found_paths.iter().filter(|p| p.has_login_form).count();
        let summary = if found_paths.is_empty() {
            format!("No admin paths found ({} paths tested)", paths_tested)
        } else {
            format!(
                "Found {} paths ({} likely admin, {} with login forms) out of {} tested",
                found_paths.len(), likely_admin_count, login_form_count, paths_tested
            )
        };

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        Ok(AdminFinderResult {
            url: base_url,
            found_paths,
            paths_tested,
            scan_duration_ms,
            summary,
            waf_detected,
            categories,
        })
    }

    fn detect_waf_from_paths(paths: &[AdminPath]) -> Option<WafDetection> {
        let mut evidence: Vec<String> = Vec::new();
        let mut waf_name: Option<String> = None;

        let blocked_count = paths.iter().filter(|p| p.status_code == 403).count();
        let total = paths.len();
        if total > 0 && blocked_count as f64 / total as f64 > 0.8 {
            waf_name = Some("Aggressive WAF".to_string());
            evidence.push(format!("{}/{} paths returned 403", blocked_count, total));
        }

        let rate_limited = paths.iter().filter(|p| p.status_code == 429).count();
        if rate_limited > 0 {
            if waf_name.is_none() {
                waf_name = Some("Rate Limiting WAF".to_string());
            }
            evidence.push(format!("{} paths returned 429", rate_limited));
        }

        for p in paths {
            if p.status_code == 403 {
                if let Some(ref title) = p.title {
                    let t = title.to_lowercase();
                    if t.contains("cloudflare") {
                        waf_name = Some("Cloudflare".to_string());
                        evidence.push("403 title: cloudflare".to_string());
                    } else if t.contains("sucuri") {
                        waf_name = Some("Sucuri".to_string());
                        evidence.push("403 title: sucuri".to_string());
                    } else if t.contains("incapsula") {
                        waf_name = Some("Incapsula".to_string());
                        evidence.push("403 title: incapsula".to_string());
                    } else if t.contains("access denied") || t.contains("forbidden") {
                        if waf_name.is_none() {
                            waf_name = Some("Generic WAF".to_string());
                        }
                        evidence.push("403 title: access denied/forbidden".to_string());
                    }
                }
            }
        }

        if waf_name.is_some() {
            Some(WafDetection {
                detected: true,
                waf_name,
                evidence,
            })
        } else {
            None
        }
    }

    fn decode_content(bytes: &[u8], content_type: &str) -> String {
        let encoding = Self::detect_encoding(bytes, content_type);
        let (cow, _encoding_used, _had_errors) = encoding.decode(bytes);
        cow.into_owned()
    }

    fn detect_encoding(bytes: &[u8], content_type: &str) -> &'static encoding_rs::Encoding {
        if let Some(charset) = Self::extract_charset_from_content_type(content_type) {
            if let Some(enc) = encoding_rs::Encoding::for_label(charset.as_bytes()) {
                return enc;
            }
        }

        if bytes.len() > 100 {
            let head = &bytes[..bytes.len().min(1024)];
            let head_str = String::from_utf8_lossy(head);
            if let Some(meta_charset) = Self::extract_charset_from_meta(&head_str) {
                if let Some(enc) = encoding_rs::Encoding::for_label(meta_charset.as_bytes()) {
                    return enc;
                }
            }
        }

        encoding_rs::UTF_8
    }

    fn extract_charset_from_content_type(content_type: &str) -> Option<String> {
        let lower = content_type.to_lowercase();
        for part in lower.split(';') {
            let part = part.trim();
            if part.starts_with("charset=") {
                let charset = part.strip_prefix("charset=").unwrap();
                let charset = charset.trim().trim_matches('"').trim_matches('\'');
                return Some(charset.to_string());
            }
        }
        None
    }

    fn extract_charset_from_meta(html: &str) -> Option<String> {
        let lower = html.to_lowercase();

        if let Some(start) = lower.find("<meta") {
            if let Some(end) = lower[start..].find('>') {
                let meta = &lower[start..start + end];

                if let Some(charset_start) = meta.find("charset=") {
                    let rest = &meta[charset_start + 8..];
                    let charset: String = rest.chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                        .collect();
                    if !charset.is_empty() {
                        return Some(charset);
                    }
                }

                if let Some(content_start) = meta.find("content=\"") {
                    let rest = &meta[content_start + 9..];
                    if let Some(content_end) = rest.find('"') {
                        let content = &rest[..content_end];
                        for part in content.split(';') {
                            let part = part.trim();
                            if part.starts_with("charset=") {
                                let charset = part.strip_prefix("charset=").unwrap();
                                return Some(charset.to_string());
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn extract_title(html: &str) -> Option<String> {
        let lower = html.to_lowercase();
        let start = lower.find("<title>")? + "<title>".len();
        let end = lower.find("</title>")?;
        if end > start && end <= html.len() && start <= html.len() {
            let title = html[start..end].trim();
            let cleaned = title
                .chars()
                .filter(|c| !c.is_control() || *c == ' ')
                .collect::<String>();
            if cleaned.len() > 100 {
                Some(format!("{}...", &cleaned[..100]))
            } else {
                Some(cleaned)
            }
        } else {
            None
        }
    }
}
