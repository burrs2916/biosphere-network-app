use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub url: String,
    pub timeout: u64,
    pub follow_redirects: bool,
    pub verify_ssl: bool,
    pub user_agent: Option<String>,
    pub proxy_url: Option<String>,
    pub custom_headers: Option<String>,
    pub max_concurrent_payloads: usize,
    pub check_cookies: bool,
    pub check_response_behavior: bool,
    pub aggressive_mode: bool,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            follow_redirects: true,
            verify_ssl: false,
            user_agent: None,
            proxy_url: None,
            custom_headers: None,
            max_concurrent_payloads: 5,
            check_cookies: true,
            check_response_behavior: true,
            aggressive_mode: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetectionResult {
    pub url: String,
    pub waf_detected: bool,
    pub waf_name: Option<String>,
    pub confidence: f64,
    pub grade: String,
    pub indicators: Vec<WafIndicator>,
    pub blocked_payloads: Vec<BlockedPayload>,
    pub cookie_indicators: Vec<CookieIndicator>,
    pub response_analysis: ResponseAnalysis,
    pub bypass_suggestions: Vec<BypassSuggestion>,
    pub severity_stats: SeverityStats,
    pub category_stats: Vec<CategoryStat>,
    pub summary: String,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafIndicator {
    pub indicator_type: String,
    pub category: String,
    pub description: String,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPayload {
    pub payload: String,
    pub attack_type: String,
    pub status_code: u16,
    pub blocked: bool,
    pub block_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieIndicator {
    pub name: String,
    pub waf_name: String,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAnalysis {
    pub status_code: u16,
    pub server_header: Option<String>,
    pub content_length: Option<u64>,
    pub has_captcha: bool,
    pub has_challenge_page: bool,
    pub redirect_url: Option<String>,
    pub response_time_ms: u64,
    pub content_type: Option<String>,
    pub x_powered_by: Option<String>,
    pub interesting_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassSuggestion {
    pub technique: String,
    pub description: String,
    pub difficulty: String,
    pub effectiveness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityStats {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub info: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStat {
    pub category: String,
    pub count: i32,
    pub max_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchWafDetectionResult {
    pub url: String,
    pub result: Option<WafDetectionResult>,
    pub error: Option<String>,
}
