use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechDetectConfig {
    pub url: String,
    pub timeout: u64,
    pub detect_js: bool,
    pub detect_headers: bool,
    pub detect_cookies: bool,
    pub detect_html: bool,
    pub detect_css: bool,
    pub detect_meta: bool,
    pub scan_mode: String,
    pub follow_redirects: bool,
    pub randomize_ua: bool,
    pub collect_ssl_info: bool,
    pub collect_security_headers: bool,
}

impl Default for TechDetectConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            detect_js: true,
            detect_headers: true,
            detect_cookies: true,
            detect_html: true,
            detect_css: true,
            detect_meta: true,
            scan_mode: "normal".to_string(),
            follow_redirects: true,
            randomize_ua: true,
            collect_ssl_info: true,
            collect_security_headers: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechDetectResult {
    pub url: String,
    pub technologies: Vec<DetectedTech>,
    pub categories: Vec<TechCategory>,
    pub summary: String,
    pub ssl_info: Option<SslInfo>,
    pub waf_detected: Option<WafDetection>,
    pub security_headers: Option<SecurityHeaderResult>,
    pub response_info: ResponseInfo,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTech {
    pub name: String,
    pub category: String,
    pub confidence: f64,
    pub version: Option<String>,
    pub detection_method: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechCategory {
    pub name: String,
    pub count: usize,
    pub techs: Vec<String>,
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
    pub san_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderResult {
    pub headers: Vec<SecurityHeaderEntry>,
    pub score: u8,
    pub grade: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderEntry {
    pub name: String,
    pub present: bool,
    pub value: Option<String>,
    pub recommendation: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInfo {
    pub status_code: u16,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub content_length: Option<u64>,
    pub response_time_ms: u64,
    pub redirect_url: Option<String>,
    pub ip_address: Option<String>,
}
