use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCheckResult {
    pub url: String,
    pub is_online: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub redirect_url: Option<String>,
    pub is_redirect: bool,
    pub dns_resolved: bool,
    pub ssl_valid: Option<bool>,
    pub ip_address: Option<String>,
    pub x_powered_by: Option<String>,
    pub x_frame_options: Option<String>,
    pub content_security_policy: Option<String>,
    pub strict_transport_security: Option<String>,
    pub x_content_type_options: Option<String>,
    pub x_xss_protection: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub cache_control: Option<String>,
    pub etag: Option<String>,
    pub issues: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSiteCheckResult {
    pub url: String,
    pub result: Option<SiteCheckResult>,
    pub error: Option<String>,
}
