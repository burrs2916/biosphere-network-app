use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainConfig {
    pub domain: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_mode: String,
    pub use_certificate_transparency: bool,
    pub use_dns_bruteforce: bool,
    pub use_http_probe: bool,
    pub check_alive: bool,
    pub wordlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<SubdomainEntry>,
    pub total_found: usize,
    pub alive_count: usize,
    pub dead_count: usize,
    pub scan_duration_ms: u64,
    pub sources_used: Vec<String>,
    pub summary: String,
    pub categories: Vec<SubdomainCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainEntry {
    pub subdomain: String,
    pub ip_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub source: String,
    pub is_alive: bool,
    pub category: String,
    pub http_status: Option<u16>,
    pub http_title: Option<String>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainCategory {
    pub name: String,
    pub count: usize,
    pub subdomains: Vec<String>,
}

impl Default for SubdomainConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            timeout: 10,
            threads: 50,
            scan_mode: "normal".to_string(),
            use_certificate_transparency: true,
            use_dns_bruteforce: true,
            use_http_probe: false,
            check_alive: true,
            wordlist: Vec::new(),
        }
    }
}

pub const QUICK_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
    "portal", "blog", "shop", "app", "cdn", "static", "login", "vpn",
    "git", "ci", "monitor", "db", "backup", "beta", "demo", "internal",
    "web", "server", "cloud", "status", "m", "mobile",
];

pub const NORMAL_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
    "test", "admin", "portal", "blog", "shop", "store", "app", "cdn",
    "static", "assets", "media", "img", "images", "css", "js", "files",
    "docs", "doc", "wiki", "help", "support", "forum", "community",
    "login", "sso", "auth", "oauth", "vpn", "remote", "gateway", "proxy",
    "git", "gitlab", "github", "ci", "jenkins", "build", "deploy",
    "monitor", "grafana", "prometheus", "kibana", "elastic", "log",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "bak", "old", "new", "beta", "alpha", "demo", "sandbox",
    "internal", "intranet", "extranet", "office", "corp", "hr", "crm",
    "erp", "oa", "web", "web1", "web2", "server", "server1", "server2",
    "node", "node1", "node2", "cluster", "master", "slave", "worker",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "bucket",
    "panel", "cpanel", "plesk", "webmin", "adminer", "phpmyadmin",
    "status", "uptime", "health", "ping", "trace", "debug",
    "m", "mobile", "wap", "h5", "ios", "android",
    "api1", "api2", "api-v1", "api-v2", "rest", "graphql",
    "ws", "wss", "socket", "websocket", "mqtt",
    "email", "imap", "pop3", "submission", "relay",
    "ns", "ns3", "ns4", "ns5", "primary", "secondary",
    "mx3", "mx4", "mail1", "mail2", "smtp1", "smtp2",
    "vpn1", "vpn2", "proxy1", "proxy2",
    "dev1", "dev2", "stg", "stg1", "stg2", "uat",
    "prod", "prod1", "prod2", "live", "pre", "preprod",
];

pub const DEEP_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
    "test", "admin", "portal", "blog", "shop", "store", "app", "cdn",
    "static", "assets", "media", "img", "images", "css", "js", "files",
    "docs", "doc", "wiki", "help", "support", "forum", "community",
    "login", "sso", "auth", "oauth", "vpn", "remote", "gateway", "proxy",
    "git", "gitlab", "github", "ci", "jenkins", "build", "deploy",
    "monitor", "grafana", "prometheus", "kibana", "elastic", "log",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "backup", "bak", "old", "new", "beta", "alpha", "demo", "sandbox",
    "internal", "intranet", "extranet", "office", "corp", "hr", "crm",
    "erp", "oa", "web", "web1", "web2", "web3", "server", "server1", "server2", "server3",
    "node", "node1", "node2", "node3", "cluster", "master", "slave", "worker",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "bucket",
    "panel", "cpanel", "plesk", "webmin", "adminer", "phpmyadmin",
    "status", "uptime", "health", "ping", "trace", "debug",
    "m", "mobile", "wap", "h5", "ios", "android",
    "api1", "api2", "api-v1", "api-v2", "rest", "graphql",
    "ws", "wss", "socket", "websocket", "mqtt",
    "email", "imap", "pop3", "submission", "relay",
    "ns", "ns3", "ns4", "ns5", "primary", "secondary",
    "mx3", "mx4", "mail1", "mail2", "smtp1", "smtp2",
    "vpn1", "vpn2", "proxy1", "proxy2",
    "dev1", "dev2", "stg", "stg1", "stg2", "uat",
    "prod", "prod1", "prod2", "live", "pre", "preprod",
    "www1", "www2", "www3", "www4", "www5",
    "web4", "web5", "web6", "web7", "web8", "web9", "web10",
    "test1", "test2", "test3", "qa", "qa1", "qa2",
    "dev3", "dev4", "dev5", "develop", "development",
    "staging1", "staging2", "stage", "stage1", "stage2",
    "prod3", "prod4", "prod5", "production", "production1", "production2",
    "api3", "api4", "api5", "api-dev", "api-staging", "api-prod",
    "admin1", "admin2", "admin3", "manage", "management", "manager",
    "dashboard", "console", "control", "panel1", "panel2",
    "cdn1", "cdn2", "cdn3", "edge", "edge1", "edge2",
    "cache", "cache1", "cache2", "memcached", "varnish",
    "search", "search1", "search2", "solr", "elasticsearch",
    "analytics", "tracking", "telemetry", "metrics", "stats",
    "payment", "pay", "billing", "checkout", "order",
    "notification", "notify", "push", "alert", "alerts",
    "chat", "im", "message", "messaging", "socketio",
    "video", "stream", "streaming", "live", "broadcast",
    "image", "photo", "upload", "download", "attachment",
    "report", "reports", "export", "import", "sync",
    "scheduler", "cron", "job", "task", "tasks", "worker1", "worker2",
    "registry", "repo", "repository", "npm", "maven", "pypi", "gems",
    "docs1", "docs2", "readme", "guide", "tutorial", "manual",
    "sandbox1", "sandbox2", "playground", "demo1", "demo2",
    "feed", "rss", "atom", "sitemap", "robots",
    "oauth1", "oauth2", "saml", "cas", "ldap",
    "kafka", "rabbitmq", "queue", "mq", "broker",
    "consul", "etcd", "zookeeper", "nacos", "eureka",
    "traefik", "nginx", "haproxy", "envoy", "istio",
    "k8s", "kubernetes", "docker", "container", "pod",
    "argo", "flux", "helm", "rancher", "rancher1",
    "sonar", "sonarqube", "codecov", "coverage",
    "jira", "confluence", "wiki1", "wiki2",
    "mattermost", "rocketchat", "slack", "teams",
    "prestashop", "magento", "woocommerce", "shopify",
    "drupal", "joomla", "wordpress", "wp", "wp-admin",
    "nextcloud", "owncloud", "seafile", "minio",
    "rabbit", "rmq", "activemq", "artemis",
    "clickhouse", "clickhouse1", "doris", "starrocks",
    "tidb", "cockroach", "cassandra", "scylla", "hbase",
    "nebula", "janusgraph", "dgraph", "tigergraph",
];
