use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverConfig {
    pub domain: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_mode: String,
    pub check_cname: bool,
    pub check_http: bool,
    pub check_dns_dangling: bool,
    pub subdomains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub domain: String,
    pub checked_subdomains: usize,
    pub vulnerable: Vec<TakeoverEntry>,
    pub potentially_vulnerable: Vec<TakeoverEntry>,
    pub safe: Vec<TakeoverEntry>,
    pub errors: Vec<TakeoverEntry>,
    pub scan_duration_ms: u64,
    pub summary: String,
    pub service_distribution: Vec<ServiceDistribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverEntry {
    pub subdomain: String,
    pub cname: Option<String>,
    pub is_vulnerable: bool,
    pub is_potentially_vulnerable: bool,
    pub service: Option<String>,
    pub service_category: Option<String>,
    pub evidence: String,
    pub fingerprint: Option<String>,
    pub confidence: f64,
    pub http_status: Option<u16>,
    pub http_title: Option<String>,
    pub response_time_ms: Option<u64>,
    pub ip_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDistribution {
    pub service: String,
    pub category: String,
    pub count: usize,
    pub vulnerable_count: usize,
}

impl Default for TakeoverConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            timeout: 10,
            threads: 10,
            scan_mode: "normal".to_string(),
            check_cname: true,
            check_http: true,
            check_dns_dangling: true,
            subdomains: vec![],
        }
    }
}

#[derive(Debug, Clone)]
pub struct TakeoverFingerprint {
    pub cname_pattern: &'static str,
    pub service: &'static str,
    pub category: &'static str,
    pub fingerprint: &'static str,
    pub confidence: f64,
}

pub const TAKEOVER_FINGERPRINTS: &[TakeoverFingerprint] = &[
    TakeoverFingerprint { cname_pattern: "github.io", service: "GitHub Pages", category: "Hosting", fingerprint: "There isn't a GitHub Pages site here", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "github.io", service: "GitHub Pages", category: "Hosting", fingerprint: "For root domain", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "herokuapp.com", service: "Heroku", category: "Cloud", fingerprint: "No such app", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "herokuapp.com", service: "Heroku", category: "Cloud", fingerprint: "herokucdn.com/error-pages/no-such-app.html", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "herokussl.com", service: "Heroku", category: "Cloud", fingerprint: "No such app", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "aws.amazon.com", service: "AWS S3", category: "Cloud", fingerprint: "NoSuchBucket", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "aws.amazon.com", service: "AWS S3", category: "Cloud", fingerprint: "The specified bucket does not exist", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "s3.amazonaws.com", service: "AWS S3", category: "Cloud", fingerprint: "NoSuchBucket", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "s3-website", service: "AWS S3", category: "Cloud", fingerprint: "NoSuchBucket", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "cloudfront.net", service: "CloudFront", category: "CDN", fingerprint: "Bad Request", confidence: 0.7 },
    TakeoverFingerprint { cname_pattern: "cloudfront.net", service: "CloudFront", category: "CDN", fingerprint: "ERROR: The request could not be satisfied", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "azurewebsites.net", service: "Azure", category: "Cloud", fingerprint: "404 Web Site not found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "azurewebsites.net", service: "Azure", category: "Cloud", fingerprint: "This web app is stopped", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "blob.core.windows.net", service: "Azure Blob", category: "Cloud", fingerprint: "The specified blob does not exist", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "cloudapp.net", service: "Azure", category: "Cloud", fingerprint: "404 Web Site not found", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "myshopify.com", service: "Shopify", category: "Commerce", fingerprint: "Sorry, this shop is currently unavailable", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "myshopify.com", service: "Shopify", category: "Commerce", fingerprint: "Do you want to register", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "shopify.com", service: "Shopify", category: "Commerce", fingerprint: "Sorry, this shop is currently unavailable", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "fastly.net", service: "Fastly", category: "CDN", fingerprint: "Fastly error: unknown domain", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "pantheon.io", service: "Pantheon", category: "Hosting", fingerprint: "404 error unknown site", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "ghost.io", service: "Ghost", category: "CMS", fingerprint: "The thing you were looking for is no longer here", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "tumblr.com", service: "Tumblr", category: "CMS", fingerprint: "Whatever you were looking for doesn't currently exist", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "wordpress.com", service: "WordPress", category: "CMS", fingerprint: "Do you want to register", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "teamwork.com", service: "Teamwork", category: "SaaS", fingerprint: "Oops - We didn't find your site", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "helpjuice.com", service: "HelpJuice", category: "SaaS", fingerprint: "We could not find what you're looking for", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "helpscout.net", service: "HelpScout", category: "SaaS", fingerprint: "No settings were found for this company", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "cargo.site", service: "Cargo", category: "Hosting", fingerprint: "If you're moving your domain away from Cargo", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "statuspage.io", service: "StatusPage", category: "SaaS", fingerprint: "You are being redirected", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "uservoice.com", service: "UserVoice", category: "SaaS", fingerprint: "This UserVoice subdomain is currently available", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "surge.sh", service: "Surge", category: "Hosting", fingerprint: "project not found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "bitbucket.io", service: "Bitbucket", category: "Hosting", fingerprint: "Repository not found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "intercom.help", service: "Intercom", category: "SaaS", fingerprint: "This page is reserved for artistic dogs", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "webflow.io", service: "Webflow", category: "Hosting", fingerprint: "The page you are looking for doesn't exist or has been moved", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "readme.io", service: "ReadMe", category: "SaaS", fingerprint: "Project doesnt exist... yet!", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "vercel.app", service: "Vercel", category: "Hosting", fingerprint: "The deployment could not be found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "vercel.app", service: "Vercel", category: "Hosting", fingerprint: "This deployment does not exist", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "netlify.app", service: "Netlify", category: "Hosting", fingerprint: "Not Found - Request ID", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "netlify.app", service: "Netlify", category: "Hosting", fingerprint: "Page Not Found", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "firebaseapp.com", service: "Firebase", category: "Cloud", fingerprint: "Hosting Site Not Found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "web.app", service: "Firebase", category: "Cloud", fingerprint: "Hosting Site Not Found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "gitlab.io", service: "GitLab Pages", category: "Hosting", fingerprint: "The page you're looking for could not be found", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "stripe.com", service: "Stripe", category: "Payment", fingerprint: "The Stripe subdomain does not exist", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "zendesk.com", service: "Zendesk", category: "SaaS", fingerprint: "Help Center Closed", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "zendesk.com", service: "Zendesk", category: "SaaS", fingerprint: "This Help Center no longer exists", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "freshdesk.com", service: "Freshdesk", category: "SaaS", fingerprint: "The page you requested could not be found", confidence: 0.7 },
    TakeoverFingerprint { cname_pattern: "freshdesk.com", service: "Freshdesk", category: "SaaS", fingerprint: "This portal is no longer available", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "digitaloceanspaces.com", service: "DigitalOcean", category: "Cloud", fingerprint: "NoSuchBucket", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "cloudfunctions.net", service: "Google Cloud Functions", category: "Cloud", fingerprint: "Function not found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "cloud.run", service: "Google Cloud Run", category: "Cloud", fingerprint: "404 Not Found", confidence: 0.6 },
    TakeoverFingerprint { cname_pattern: "render.com", service: "Render", category: "Cloud", fingerprint: "Not Found", confidence: 0.7 },
    TakeoverFingerprint { cname_pattern: "render.com", service: "Render", category: "Cloud", fingerprint: "The page you requested was not found", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "railway.app", service: "Railway", category: "Cloud", fingerprint: "404 Not Found", confidence: 0.6 },
    TakeoverFingerprint { cname_pattern: "railway.app", service: "Railway", category: "Cloud", fingerprint: "This page could not be found", confidence: 0.7 },
    TakeoverFingerprint { cname_pattern: "kinsta.com", service: "Kinsta", category: "Hosting", fingerprint: "No site found at this address", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "hubspot.com", service: "HubSpot", category: "SaaS", fingerprint: "This page doesn't exist", confidence: 0.7 },
    TakeoverFingerprint { cname_pattern: "squarespace.com", service: "Squarespace", category: "Hosting", fingerprint: "This site is currently unavailable", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "wix.com", service: "Wix", category: "Hosting", fingerprint: "This domain is not connected to a Wix site", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "weebly.com", service: "Weebly", category: "Hosting", fingerprint: "The site you are looking for could not be found", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "fly.dev", service: "Fly.io", category: "Cloud", fingerprint: "404 Not Found", confidence: 0.6 },
    TakeoverFingerprint { cname_pattern: "fly.dev", service: "Fly.io", category: "Cloud", fingerprint: "404 the page you requested was not found", confidence: 0.7 },
    TakeoverFingerprint { cname_pattern: "smartling.com", service: "Smartling", category: "SaaS", fingerprint: "Domain is not configured", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "agilecrm.com", service: "AgileCRM", category: "SaaS", fingerprint: "Sorry, this page is no longer available", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "propel.orm.io", service: "Propel", category: "SaaS", fingerprint: "The site you were looking for could not be found", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "supabase.co", service: "Supabase", category: "Cloud", fingerprint: "Project does not exist", confidence: 1.0 },
    TakeoverFingerprint { cname_pattern: "deno.dev", service: "Deno Deploy", category: "Hosting", fingerprint: "This deployment has been deleted", confidence: 0.9 },
    TakeoverFingerprint { cname_pattern: "workers.dev", service: "Cloudflare Workers", category: "Cloud", fingerprint: "There is nothing here", confidence: 0.8 },
    TakeoverFingerprint { cname_pattern: "pages.dev", service: "Cloudflare Pages", category: "Hosting", fingerprint: "This site can't be reached", confidence: 0.7 },
];

pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
];

pub const QUICK_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
    "portal", "blog", "shop", "app", "cdn", "static", "vpn", "git",
];

pub const NORMAL_SUBDOMAINS: &[&str] = &[
    "www", "www1", "www2", "mail", "ftp", "localhost", "webmail", "smtp",
    "api", "api2", "dev", "staging", "test", "admin", "portal", "blog",
    "shop", "store", "app", "cdn", "static", "vpn", "git", "ci",
    "monitor", "db", "backup", "beta", "demo", "internal", "web",
    "server", "cloud", "status", "m", "mobile", "ns1", "ns2", "dns",
    "mx", "mx1", "remote", "intranet", "extranet", "login", "sso",
    "auth", "oauth", "docs", "wiki", "support", "help", "kb",
];

pub const DEEP_SUBDOMAINS: &[&str] = &[
    "www", "www1", "www2", "www3", "mail", "mail1", "mail2", "ftp", "localhost",
    "webmail", "smtp", "pop", "imap", "api", "api2", "api3", "dev", "dev1", "dev2",
    "staging", "staging1", "staging2", "test", "test1", "test2", "admin", "admin2",
    "portal", "blog", "shop", "store", "app", "cdn", "static", "assets", "media",
    "vpn", "git", "gitlab", "github", "ci", "jenkins", "monitor", "grafana",
    "db", "database", "backup", "beta", "demo", "internal", "intranet", "extranet",
    "web", "web1", "web2", "server", "cloud", "status", "m", "mobile", "wap",
    "ns1", "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "remote", "access",
    "login", "sso", "auth", "oauth", "docs", "wiki", "support", "help", "kb",
    "crm", "erp", "hr", "payroll", "office", "sharepoint", "teams", "zoom",
    "slack", "discord", "jira", "confluence", "trello", "asana", "notion",
    "analytics", "tracking", "pixel", "ads", "adserver", "banner",
    "payment", "pay", "billing", "checkout", "cart", "order",
    "news", "press", "media", "images", "img", "video", "videos",
    "download", "uploads", "files", "cdn2", "cache", "proxy",
    "api-gateway", "gateway", "lb", "loadbalancer", "nginx", "apache",
    "elastic", "elasticsearch", "redis", "mongo", "mysql", "postgres",
    "kafka", "rabbitmq", "queue", "worker", "cron", "scheduler",
    "sandbox", "preview", "review", "uat", "pre", "preprod", "prod",
    "production", "release", "deploy", "artifact", "registry",
    "docker", "k8s", "kubernetes", "helm", "terraform", "ansible",
    "prometheus", "alertmanager", "loki", "tempo", "tracing",
    "s3", "storage", "bucket", "blob", "minio", "ceph",
    "firebase", "supabase", "appwrite", "pocketbase",
];
