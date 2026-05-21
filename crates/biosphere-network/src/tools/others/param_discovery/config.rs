use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDiscoveryConfig {
    pub url: String,
    pub timeout: u64,
    pub method: String,
    pub wordlist: Vec<String>,
    #[serde(default = "default_threads")]
    pub threads: usize,
    #[serde(default)]
    pub follow_redirects: bool,
    #[serde(default = "default_diff_threshold")]
    pub diff_threshold: f64,
    #[serde(default = "default_true")]
    pub extract_form_params: bool,
    #[serde(default = "default_true")]
    pub randomize_ua: bool,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default = "default_true")]
    pub multi_value_test: bool,
    #[serde(default)]
    pub custom_values: Vec<String>,
    #[serde(default)]
    pub scan_mode: Option<String>,
    #[serde(default = "default_true")]
    pub collect_ssl_info: bool,
    #[serde(default)]
    pub detect_reflection: bool,
    #[serde(default)]
    pub exclude_params: Vec<String>,
}

fn default_threads() -> usize { 10 }
fn default_diff_threshold() -> f64 { 0.05 }
fn default_true() -> bool { true }

impl Default for ParamDiscoveryConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 10,
            method: "GET".to_string(),
            wordlist: Vec::new(),
            threads: 10,
            follow_redirects: false,
            diff_threshold: 0.05,
            extract_form_params: true,
            randomize_ua: true,
            user_agent: None,
            multi_value_test: true,
            custom_values: Vec::new(),
            scan_mode: Some("normal".to_string()),
            collect_ssl_info: true,
            detect_reflection: true,
            exclude_params: Vec::new(),
        }
    }
}

impl ParamDiscoveryConfig {
    pub fn get_effective_threads(&self) -> usize {
        if self.threads > 0 {
            return self.threads.min(50);
        }
        let mode = self.scan_mode.as_deref().unwrap_or("normal");
        match mode {
            "quick" => 5,
            "deep" => 20,
            _ => 10,
        }
    }

    pub fn get_user_agent(&self) -> String {
        if let Some(ref ua) = self.user_agent {
            if !ua.is_empty() {
                return ua.clone();
            }
        }
        if self.randomize_ua {
            return Self::random_user_agent();
        }
        "BiosPhere-ParamDiscovery/1.0".to_string()
    }

    fn random_user_agent() -> String {
        let agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        ];
        let idx = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize % agents.len();
        agents[idx].to_string()
    }

    pub fn get_effective_wordlist(&self) -> Vec<String> {
        if !self.wordlist.is_empty() {
            return self.wordlist.clone();
        }
        let mode = self.scan_mode.as_deref().unwrap_or("normal");
        match mode {
            "quick" => QUICK_PARAM_WORDLIST.iter().map(|s| s.to_string()).collect(),
            "deep" => DEEP_PARAM_WORDLIST.iter().map(|s| s.to_string()).collect(),
            _ => DEFAULT_PARAM_WORDLIST.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn get_test_values(&self) -> Vec<String> {
        if !self.custom_values.is_empty() {
            return self.custom_values.clone();
        }
        DEFAULT_TEST_VALUES.iter().map(|s| s.to_string()).collect()
    }

    pub fn should_exclude_param(&self, param: &str) -> bool {
        for pattern in &self.exclude_params {
            if param.contains(pattern) {
                return true;
            }
        }
        false
    }
}

const DEFAULT_TEST_VALUES: &[&str] = &[
    "test", "1", "0", "true", "false", "null", "admin", "root",
    "'\"\\", "<script>alert(1)</script>", "{{7*7}}", "${7*7}", "../../../etc/passwd",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDiscoveryResult {
    pub url: String,
    pub found_params: Vec<ParamEntry>,
    pub total_found: usize,
    pub total_tested: usize,
    pub summary: String,
    pub scan_duration_ms: u64,
    pub baseline_status: u16,
    pub baseline_length: u64,
    pub form_params: Vec<String>,
    pub url_params: Vec<String>,
    pub ssl_info: Option<SslInfo>,
    pub waf_detected: Option<WafDetection>,
    pub sensitive_params: Vec<SensitiveParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamEntry {
    pub param_name: String,
    pub method: String,
    pub evidence: String,
    pub response_diff: Option<f64>,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub response_time_ms: u64,
    pub test_value: String,
    pub category: String,
    pub risk_level: String,
    pub is_reflected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub is_expired: bool,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveParam {
    pub param_name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
}

pub fn classify_param(name: &str) -> (&'static str, &'static str) {
    let lower = name.to_lowercase();
    let (cat, risk) = if SQL_PARAMS.iter().any(|p| lower.contains(p)) {
        ("database", "high")
    } else if CMD_PARAMS.iter().any(|p| lower.contains(p)) {
        ("command", "critical")
    } else if FILE_PARAMS.iter().any(|p| lower.contains(p)) {
        ("file", "critical")
    } else if SSRF_PARAMS.iter().any(|p| lower.contains(p)) {
        ("ssrf", "critical")
    } else if AUTH_PARAMS.iter().any(|p| lower.contains(p)) {
        ("auth", "high")
    } else if DEBUG_PARAMS.iter().any(|p| lower.contains(p)) {
        ("debug", "medium")
    } else if PAGINATION_PARAMS.iter().any(|p| lower.contains(p)) {
        ("pagination", "low")
    } else if I18N_PARAMS.iter().any(|p| lower.contains(p)) {
        ("i18n", "info")
    } else if CONTENT_PARAMS.iter().any(|p| lower.contains(p)) {
        ("content", "info")
    } else {
        ("other", "low")
    };
    (cat, risk)
}

pub fn classify_sensitive_param(name: &str) -> Option<SensitiveParam> {
    let lower = name.to_lowercase();
    let (category, severity, description) = if CRITICAL_PARAMS.iter().any(|p| lower.contains(p)) {
        ("critical_param", "critical", "Parameter that may allow command execution or file inclusion")
    } else if SQL_INJECTION_PARAMS.iter().any(|p| lower.contains(p)) {
        ("sql_injection", "critical", "Parameter that may be vulnerable to SQL injection")
    } else if SSRF_PARAMS_LIST.iter().any(|p| lower.contains(p)) {
        ("ssrf", "critical", "Parameter that may be vulnerable to SSRF attacks")
    } else if AUTH_PARAMS_LIST.iter().any(|p| lower.contains(p)) {
        ("auth_bypass", "high", "Parameter that may bypass authentication or authorization")
    } else if FILE_PARAMS_LIST.iter().any(|p| lower.contains(p)) {
        ("file_inclusion", "high", "Parameter that may allow local/remote file inclusion")
    } else if DEBUG_PARAMS_LIST.iter().any(|p| lower.contains(p)) {
        ("info_leak", "medium", "Parameter that may leak debug or configuration information")
    } else {
        return None;
    };
    Some(SensitiveParam {
        param_name: name.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        description: description.to_string(),
    })
}

pub fn detect_waf(status_code: u16, headers: &reqwest::header::HeaderMap, body: &str) -> WafDetection {
    let mut evidence = Vec::new();
    let mut waf_name: Option<String> = None;

    if status_code == 403 || status_code == 503 || status_code == 429 {
        if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
            let server_lower = server.to_lowercase();
            if server_lower.contains("cloudflare") {
                waf_name = Some("Cloudflare".to_string());
                evidence.push(format!("Server header: {}", server));
            } else if server_lower.contains("akamai") {
                waf_name = Some("Akamai".to_string());
                evidence.push(format!("Server header: {}", server));
            } else if server_lower.contains("sucuri") {
                waf_name = Some("Sucuri".to_string());
                evidence.push(format!("Server header: {}", server));
            }
        }

        if headers.get("cf-ray").is_some() {
            waf_name = Some("Cloudflare".to_string());
            evidence.push("CF-Ray header present".to_string());
        }
        if headers.get("x-sucuri-id").is_some() {
            waf_name = Some("Sucuri".to_string());
            evidence.push("X-Sucuri-ID header present".to_string());
        }
        if headers.get("x-protected-by").is_some() {
            if let Some(val) = headers.get("x-protected-by").and_then(|v| v.to_str().ok()) {
                waf_name = Some(val.to_string());
                evidence.push(format!("X-Protected-By: {}", val));
            }
        }

        let body_lower = body.to_lowercase();
        if body_lower.contains("cloudflare") && body_lower.contains("ray id") {
            waf_name = Some("Cloudflare".to_string());
            evidence.push("Body contains Cloudflare Ray ID".to_string());
        }
        if body_lower.contains("access denied") && body_lower.contains("incapsula") {
            waf_name = Some("Imperva/Incapsula".to_string());
            evidence.push("Body contains Incapsula reference".to_string());
        }
        if body_lower.contains("request rejected") && body_lower.contains("sucuri") {
            waf_name = Some("Sucuri".to_string());
            evidence.push("Body contains Sucuri reference".to_string());
        }
        if body_lower.contains("checking your browser") {
            waf_name = Some("Cloudflare".to_string());
            evidence.push("Body contains browser check".to_string());
        }
        if body_lower.contains("pardon our interruption") {
            waf_name = Some("Akamai".to_string());
            evidence.push("Body contains Akamai challenge".to_string());
        }
    }

    WafDetection {
        detected: waf_name.is_some(),
        waf_name,
        evidence,
    }
}

pub fn extract_form_params_from_html(html: &str) -> Vec<String> {
    let mut params = Vec::new();
    let patterns = [
        r#"<input[^>]*name\s*=\s*["']([^"']+)["']"#,
        r#"<input[^>]*name\s*=\s*([^\s>]+)"#,
        r#"<textarea[^>]*name\s*=\s*["']([^"']+)["']"#,
        r#"<textarea[^>]*name\s*=\s*([^\s>]+)"#,
        r#"<select[^>]*name\s*=\s*["']([^"']+)["']"#,
        r#"<select[^>]*name\s*=\s*([^\s>]+)"#,
    ];
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for cap in re.captures_iter(html) {
                if let Some(name) = cap.get(1) {
                    let p = name.as_str().to_string();
                    if !params.contains(&p) {
                        params.push(p);
                    }
                }
            }
        }
    }
    params
}

pub fn extract_url_params(url: &str) -> Vec<String> {
    let mut params = Vec::new();
    if let Ok(parsed) = url::Url::parse(url) {
        for (key, _) in parsed.query_pairs() {
            let k = key.into_owned();
            if !params.contains(&k) {
                params.push(k);
            }
        }
    }
    params
}

const SQL_PARAMS: &[&str] = &["sql", "query", "db", "database", "table", "column", "select", "insert", "update", "delete", "drop", "union", "order", "group", "where", "having", "nosql", "mongo"];
const CMD_PARAMS: &[&str] = &["cmd", "exec", "command", "action", "run", "execute", "system", "shell", "bash", "ping", "nslookup"];
const FILE_PARAMS: &[&str] = &["file", "path", "dir", "folder", "document", "doc", "include", "require", "load", "template", "view", "page", "lang", "render"];
const SSRF_PARAMS: &[&str] = &["url", "link", "redirect", "return", "next", "goto", "src", "source", "ref", "referer", "origin", "base", "dest", "target", "rurl", "img", "image"];
const AUTH_PARAMS: &[&str] = &["token", "api_key", "apikey", "secret", "auth", "session", "key", "password", "passwd", "credential", "access", "privilege", "role", "permission"];
const DEBUG_PARAMS: &[&str] = &["debug", "test", "dev", "admin", "mode", "trace", "verbose", "log", "env", "config", "info"];
const PAGINATION_PARAMS: &[&str] = &["page", "limit", "offset", "count", "size", "per_page", "page_size", "start", "end", "from", "to", "skip", "take"];
const I18N_PARAMS: &[&str] = &["lang", "locale", "country", "region", "timezone", "tz", "language"];
const CONTENT_PARAMS: &[&str] = &["q", "search", "keyword", "term", "filter", "sort", "order", "by", "direction", "asc", "desc", "format", "output", "type", "category", "tag", "label", "group", "section"];

const CRITICAL_PARAMS: &[&str] = &["cmd", "exec", "command", "execute", "system", "shell", "bash", "run", "action"];
const SQL_INJECTION_PARAMS: &[&str] = &["sql", "query", "db", "database", "select", "insert", "update", "delete", "drop", "union", "nosql", "mongo", "redis"];
const SSRF_PARAMS_LIST: &[&str] = &["url", "link", "redirect", "return", "next", "goto", "src", "source", "ref", "referer", "origin", "dest", "target", "rurl", "proxy", "forward"];
const AUTH_PARAMS_LIST: &[&str] = &["token", "api_key", "apikey", "secret", "auth", "session", "password", "passwd", "credential", "access", "privilege", "role", "permission", "key"];
const FILE_PARAMS_LIST: &[&str] = &["file", "path", "dir", "folder", "document", "include", "require", "load", "template", "view", "page", "render", "filepath", "filename"];
const DEBUG_PARAMS_LIST: &[&str] = &["debug", "test", "dev", "mode", "trace", "verbose", "log", "env", "config", "info", "admin"];

pub const QUICK_PARAM_WORDLIST: &[&str] = &[
    "id", "page", "q", "search", "user", "file", "url", "cmd",
    "debug", "token", "lang", "sort", "limit", "callback", "action",
    "admin", "key", "query", "type", "format", "redirect", "path",
    "auth", "session", "password", "secret", "api_key", "exec",
];

pub const DEFAULT_PARAM_WORDLIST: &[&str] = &[
    "id", "page", "q", "query", "search", "keyword", "key", "term",
    "user", "username", "name", "email", "login", "account",
    "file", "path", "dir", "folder", "document", "doc",
    "url", "link", "redirect", "return", "next", "goto",
    "cmd", "exec", "command", "action", "run", "execute",
    "debug", "test", "dev", "admin", "mode", "type",
    "format", "output", "render", "template", "view", "display",
    "lang", "locale", "country", "region", "timezone",
    "sort", "order", "by", "direction", "asc", "desc",
    "limit", "offset", "count", "size", "per_page", "page_size",
    "from", "to", "start", "end", "begin", "finish",
    "date", "time", "timestamp", "year", "month", "day",
    "token", "api_key", "apikey", "secret", "auth", "session",
    "callback", "jsonp", "cb", "function", "method", "handler",
    "src", "source", "ref", "referer", "origin", "base",
    "data", "body", "content", "payload", "message", "text",
    "width", "height", "size", "length", "depth", "level",
    "color", "theme", "style", "css", "class", "layout",
    "img", "image", "photo", "picture", "icon", "avatar",
    "cat", "category", "tag", "label", "group", "section",
    "role", "permission", "access", "privilege", "right",
    "db", "database", "table", "column", "field", "row",
    "sql", "nosql", "mongo", "redis", "cache", "store",
    "include", "require", "load", "import", "export", "download",
    "upload", "attach", "file_name", "filename", "filepath",
    "xml", "json", "yaml", "csv", "rss", "feed",
    "ajax", "xhr", "fetch", "request", "response", "callback",
    "password", "passwd", "pass", "pwd", "secret_key",
    "admin", "root", "superuser", "su", "sudo",
    "proxy", "forward", "tunnel", "redirect_url", "continue",
    "debug", "trace", "verbose", "log", "error", "warn",
    "env", "config", "setting", "option", "flag", "feature",
    "version", "v", "rev", "revision", "build", "commit",
    "channel", "platform", "device", "browser", "os", "app",
];

pub const DEEP_PARAM_WORDLIST: &[&str] = &[
    "id", "page", "q", "query", "search", "keyword", "key", "term",
    "user", "username", "name", "email", "login", "account",
    "file", "path", "dir", "folder", "document", "doc",
    "url", "link", "redirect", "return", "next", "goto",
    "cmd", "exec", "command", "action", "run", "execute",
    "debug", "test", "dev", "admin", "mode", "type",
    "format", "output", "render", "template", "view", "display",
    "lang", "locale", "country", "region", "timezone",
    "sort", "order", "by", "direction", "asc", "desc",
    "limit", "offset", "count", "size", "per_page", "page_size",
    "from", "to", "start", "end", "begin", "finish",
    "date", "time", "timestamp", "year", "month", "day",
    "token", "api_key", "apikey", "secret", "auth", "session",
    "callback", "jsonp", "cb", "function", "method", "handler",
    "src", "source", "ref", "referer", "origin", "base",
    "data", "body", "content", "payload", "message", "text",
    "width", "height", "size", "length", "depth", "level",
    "color", "theme", "style", "css", "class", "layout",
    "img", "image", "photo", "picture", "icon", "avatar",
    "cat", "category", "tag", "label", "group", "section",
    "role", "permission", "access", "privilege", "right",
    "db", "database", "table", "column", "field", "row",
    "sql", "nosql", "mongo", "redis", "cache", "store",
    "include", "require", "load", "import", "export", "download",
    "upload", "attach", "file_name", "filename", "filepath",
    "xml", "json", "yaml", "csv", "rss", "feed",
    "ajax", "xhr", "fetch", "request", "response", "callback",
    "password", "passwd", "pass", "pwd", "secret_key",
    "admin", "root", "superuser", "su", "sudo",
    "proxy", "forward", "tunnel", "redirect_url", "continue",
    "debug", "trace", "verbose", "log", "error", "warn",
    "env", "config", "setting", "option", "flag", "feature",
    "version", "v", "rev", "revision", "build", "commit",
    "channel", "platform", "device", "browser", "os", "app",
    "invoice", "order", "product", "item", "cart", "checkout",
    "payment", "amount", "currency", "price", "cost", "fee",
    "address", "city", "state", "zip", "phone", "mobile",
    "company", "organization", "department", "team", "project",
    "task", "job", "worker", "process", "thread", "queue",
    "event", "notification", "alert", "subscribe", "unsubscribe",
    "share", "like", "comment", "post", "article", "blog",
    "video", "audio", "stream", "playlist", "channel", "episode",
    "friend", "follow", "block", "report", "flag", "ban",
    "register", "signup", "signin", "logout", "reset", "verify",
    "confirm", "validate", "check", "test", "preview", "draft",
    "publish", "unpublish", "archive", "restore", "delete", "remove",
    "enable", "disable", "toggle", "switch", "upgrade", "downgrade",
    "backup", "restore", "migrate", "sync", "clone", "merge",
    "filter", "search", "find", "locate", "scan", "discover",
    "generate", "create", "update", "modify", "edit", "patch",
    "transform", "convert", "parse", "encode", "decode", "compress",
    "encrypt", "decrypt", "sign", "verify", "hash", "tokenize",
    "authenticate", "authorize", "permit", "deny", "revoke", "grant",
    "audit", "log", "monitor", "track", "trace", "debug",
    "profile", "preference", "setting", "config", "option", "flag",
];
