use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirScanConfig {
    pub url: String,
    pub timeout: u64,
    pub threads: usize,
    pub extensions: Vec<String>,
    pub wordlist: Vec<String>,
    pub follow_redirects: bool,
    pub scan_mode: Option<String>,
    pub recursive: bool,
    pub max_depth: usize,
    pub exclude_patterns: Vec<String>,
    pub user_agent: Option<String>,
    pub randomize_ua: bool,
    pub collect_ssl_info: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirScanResult {
    pub url: String,
    pub found_paths: Vec<DirEntry>,
    pub total_found: usize,
    pub total_scanned: usize,
    pub summary: String,
    pub ssl_info: Option<SslInfo>,
    pub waf_detected: Option<WafDetection>,
    pub sensitive_paths: Vec<SensitivePath>,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub path: String,
    pub full_url: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub redirect_url: Option<String>,
    pub response_time_ms: u64,
    pub depth: usize,
    pub is_directory: bool,
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
pub struct SensitivePath {
    pub path: String,
    pub category: String,
    pub severity: String,
    pub description: String,
}

impl Default for DirScanConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 10,
            threads: 20,
            extensions: vec!["".to_string(), "/".to_string(), ".html".to_string(), ".php".to_string(), ".json".to_string(), ".txt".to_string()],
            wordlist: DEFAULT_DIR_WORDLIST.iter().map(|s| s.to_string()).collect(),
            follow_redirects: false,
            scan_mode: Some("normal".to_string()),
            recursive: false,
            max_depth: 2,
            exclude_patterns: vec![],
            user_agent: None,
            randomize_ua: true,
            collect_ssl_info: true,
        }
    }
}

impl DirScanConfig {
    pub fn get_effective_wordlist(&self) -> Vec<String> {
        if !self.wordlist.is_empty() {
            return self.wordlist.clone();
        }
        let mode = self.scan_mode.as_deref().unwrap_or("normal");
        match mode {
            "quick" => QUICK_WORDLIST.iter().map(|s| s.to_string()).collect(),
            "deep" => DEEP_WORDLIST.iter().map(|s| s.to_string()).collect(),
            _ => DEFAULT_DIR_WORDLIST.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn get_effective_threads(&self) -> usize {
        if self.threads > 0 {
            return self.threads.min(50);
        }
        let mode = self.scan_mode.as_deref().unwrap_or("normal");
        match mode {
            "quick" => 10,
            "deep" => 30,
            _ => 20,
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
        "BiosPhere DirScanner/1.0".to_string()
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

    pub fn should_exclude(&self, path: &str) -> bool {
        for pattern in &self.exclude_patterns {
            if path.contains(pattern) {
                return true;
            }
        }
        false
    }
}

pub fn classify_sensitive_path(path: &str) -> Option<SensitivePath> {
    let lower = path.to_lowercase();
    let (category, severity, description) = if SENSITIVE_CREDENTIAL_FILES.iter().any(|s| lower.contains(s)) {
        ("credential", "critical", "Credential/config file that may contain secrets")
    } else if SENSITIVE_VCS_FILES.iter().any(|s| lower.contains(s)) {
        ("vcs", "critical", "Version control system directory/file")
    } else if SENSITIVE_ADMIN_PATHS.iter().any(|s| lower.contains(s)) {
        ("admin", "high", "Administrative interface or panel")
    } else if SENSITIVE_DB_PATHS.iter().any(|s| lower.contains(s)) {
        ("database", "high", "Database management interface")
    } else if SENSITIVE_DEBUG_PATHS.iter().any(|s| lower.contains(s)) {
        ("debug", "medium", "Debug/test endpoint that may leak information")
    } else if SENSITIVE_API_PATHS.iter().any(|s| lower.contains(s)) {
        ("api", "medium", "API documentation or endpoint")
    } else if SENSITIVE_BACKUP_PATHS.iter().any(|s| lower.contains(s)) {
        ("backup", "high", "Backup file that may contain sensitive data")
    } else {
        return None;
    };
    Some(SensitivePath {
        path: path.to_string(),
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

const SENSITIVE_CREDENTIAL_FILES: &[&str] = &[
    ".env", ".htpasswd", "wp-config.php", "web.config", "config.php",
    "database.yml", "credentials", "secrets", ".npmrc", ".pypirc",
    "id_rsa", "id_dsa", ".ssh", "private_key", "secret_key",
];

const SENSITIVE_VCS_FILES: &[&str] = &[
    ".git", ".svn", ".hg", ".git/config", ".git/HEAD",
    ".svn/entries", ".svn/wc.db",
];

const SENSITIVE_ADMIN_PATHS: &[&str] = &[
    "admin", "wp-admin", "phpmyadmin", "adminer", "administrator",
    "cpanel", "webadmin", "sysadmin", "manager", "console",
];

const SENSITIVE_DB_PATHS: &[&str] = &[
    "phpmyadmin", "adminer", "mysql", "postgres", "mongodb",
    "redis", "elasticsearch", "kibana",
];

const SENSITIVE_DEBUG_PATHS: &[&str] = &[
    "debug", "test", "trace", "profiler", "actuator",
    "server-status", "server-info", "phpinfo",
];

const SENSITIVE_API_PATHS: &[&str] = &[
    "swagger", "api-docs", "graphql", "api/v1", "api/v2",
    "openapi", "swagger-ui", "swagger.json",
];

const SENSITIVE_BACKUP_PATHS: &[&str] = &[
    "backup", ".bak", ".old", ".orig", ".save",
    ".tar.gz", ".zip", ".sql", ".dump",
];

pub const QUICK_WORDLIST: &[&str] = &[
    "admin", "login", "api", "config", ".env", ".git",
    "robots.txt", "sitemap.xml", "favicon.ico",
    "uploads", "backup", "test", "debug",
    "wp-admin", "wp-login.php", "phpmyadmin",
    "swagger", "swagger-ui", "graphql",
    "health", "status", ".well-known",
];

pub const DEFAULT_DIR_WORDLIST: &[&str] = &[
    "admin", "login", "dashboard", "api", "config", "backup", "db",
    "uploads", "upload", "files", "images", "img", "assets", "static",
    "css", "js", "fonts", "media", "downloads", "download",
    ".env", ".git", ".svn", ".htaccess", ".htpasswd", "robots.txt",
    "sitemap.xml", "favicon.ico", "crossdomain.xml", "wp-config.php",
    "web.config", "package.json", "composer.json", "Gemfile",
    "test", "debug", "tmp", "temp", "cache", "log", "logs",
    "console", "phpmyadmin", "adminer", "wp-admin", "wp-login.php",
    "cgi-bin", "server-status", "server-info", ".well-known",
    "swagger", "swagger-ui", "swagger.json", "api-docs", "graphql",
    "health", "status", "info", "version", "ping",
    "users", "user", "profile", "account", "accounts",
    "search", "query", "export", "import", "report",
    "index", "home", "main", "default", "start",
    "private", "secret", "hidden", "internal", "restricted",
    "old", "new", "dev", "staging", "prod", "production",
    "v1", "v2", "v3", "api/v1", "api/v2", "rest",
];

pub const DEEP_WORDLIST: &[&str] = &[
    "admin", "login", "dashboard", "api", "config", "backup", "db",
    "uploads", "upload", "files", "images", "img", "assets", "static",
    "css", "js", "fonts", "media", "downloads", "download",
    ".env", ".git", ".svn", ".htaccess", ".htpasswd", "robots.txt",
    "sitemap.xml", "favicon.ico", "crossdomain.xml", "wp-config.php",
    "web.config", "package.json", "composer.json", "Gemfile",
    "test", "debug", "tmp", "temp", "cache", "log", "logs",
    "console", "phpmyadmin", "adminer", "wp-admin", "wp-login.php",
    "cgi-bin", "server-status", "server-info", ".well-known",
    "swagger", "swagger-ui", "swagger.json", "api-docs", "graphql",
    "health", "status", "info", "version", "ping",
    "users", "user", "profile", "account", "accounts",
    "search", "query", "export", "import", "report",
    "index", "home", "main", "default", "start",
    "private", "secret", "hidden", "internal", "restricted",
    "old", "new", "dev", "staging", "prod", "production",
    "v1", "v2", "v3", "api/v1", "api/v2", "rest",
    "admin/login", "admin/dashboard", "admin/config", "admin/settings",
    "administrator", "moderator", "manage", "control", "panel",
    "cp", "cpanel", "webadmin", "sysadmin", "root",
    "setup", "install", "wizard", "init", "bootstrap",
    "data", "database", "sql", "mysql", "postgres", "mongodb", "redis",
    "mail", "email", "smtp", "imap", "pop3", "webmail",
    "ftp", "sftp", "ssh", "telnet", "rdp", "vnc",
    "oauth", "auth", "sso", "cas", "saml", "ldap",
    "callback", "webhook", "notify", "notification", "push",
    "cron", "job", "queue", "worker", "scheduler", "task",
    "monitor", "metrics", "analytics", "tracking", "telemetry",
    "docs", "documentation", "readme", "changelog", "release",
    "src", "source", "lib", "vendor", "node_modules", "bower_components",
    "public", "dist", "build", "out", "target", "bin",
    "app", "web", "site", "www", "html", "content",
    "scripts", "tools", "util", "utils", "helpers", "services",
    "certs", "cert", "ssl", "tls", "keys", "key",
    "token", "tokens", "session", "sessions", "cookie", "cookies",
    "ip", "ips", "domain", "domains", "host", "hosts",
    "proxy", "nginx", "apache", "tomcat", "iis", "caddy",
    ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
    ".svn/entries", ".svn/wc.db",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    ".bash_history", ".zsh_history", ".mysql_history",
    "wp-content", "wp-includes", "wp-json", "wp-cron.php",
    "xmlrpc.php", "wp-load.php", "wp-settings.php",
    "elasticsearch", "kibana", "logstash", "grafana", "prometheus",
    "jenkins", "gitlab", "bitbucket", "jira", "confluence",
    "docker", "kubernetes", "k8s", "container", "pod",
    "traefik", "consul", "etcd", "zookeeper", "nacos",
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "drupal", "joomla", "magento", "shopify", "prestashop",
    "laravel", "symfony", "cakephp", "codeigniter", "yii",
    "django", "flask", "fastapi", "express", "koa", "nestjs",
    "spring", "tomcat", "struts", "weblogic", "jboss",
];
