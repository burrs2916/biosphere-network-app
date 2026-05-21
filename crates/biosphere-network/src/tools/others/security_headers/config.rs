use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderConfig {
    pub url: String,
    pub timeout: u64,
    pub follow_redirects: bool,
    pub verify_ssl: bool,
    pub user_agent: Option<String>,
    pub proxy_url: Option<String>,
    pub custom_headers: Option<String>,
    pub check_csp_details: bool,
    pub check_cookie_headers: bool,
    pub check_information_leakage: bool,
}

impl Default for SecurityHeaderConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            follow_redirects: true,
            verify_ssl: false,
            user_agent: None,
            proxy_url: None,
            custom_headers: None,
            check_csp_details: true,
            check_cookie_headers: true,
            check_information_leakage: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderIssue {
    pub header_name: String,
    pub issue_type: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub current_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspDirective {
    pub directive: String,
    pub value: String,
    pub is_secure: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CspAnalysis {
    pub raw_value: String,
    pub directives: Vec<CspDirective>,
    pub has_default_src: bool,
    pub has_script_src: bool,
    pub has_style_src: bool,
    pub has_img_src: bool,
    pub has_connect_src: bool,
    pub has_frame_src: bool,
    pub has_object_src: bool,
    pub has_base_uri: bool,
    pub has_form_action: bool,
    pub has_frame_ancestors: bool,
    pub uses_unsafe_inline: bool,
    pub uses_unsafe_eval: bool,
    pub uses_nonce: bool,
    pub uses_hash: bool,
    pub has_report_uri: bool,
    pub is_report_only: bool,
    pub overall_assessment: String,
    pub score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsAnalysis {
    pub raw_value: String,
    pub max_age: i64,
    pub include_sub_domains: bool,
    pub preload: bool,
    pub is_secure: bool,
    pub issues: Vec<String>,
    pub score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderDetail {
    pub name: String,
    pub value: String,
    pub status: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub importance: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformationLeakage {
    pub header_name: String,
    pub value: String,
    pub risk_level: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieSecurityInfo {
    pub name: String,
    pub has_httponly: bool,
    pub has_secure: bool,
    pub has_samesite: bool,
    pub samesite_value: Option<String>,
    pub has_path: bool,
    pub path_value: Option<String>,
    pub has_domain: bool,
    pub domain_value: Option<String>,
    pub is_session_cookie: bool,
    pub risk_level: String,
    pub issue: Option<String>,
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
    pub max_score: i32,
    pub actual_score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderReport {
    pub url: String,
    pub score: i32,
    pub grade: String,
    pub summary: String,
    pub present_headers: Vec<HeaderDetail>,
    pub missing_headers: Vec<HeaderDetail>,
    pub issues: Vec<HeaderIssue>,
    pub csp_analysis: Option<CspAnalysis>,
    pub hsts_analysis: Option<HstsAnalysis>,
    pub information_leakage: Vec<InformationLeakage>,
    pub cookie_security: Vec<CookieSecurityInfo>,
    pub severity_stats: SeverityStats,
    pub category_stats: Vec<CategoryStat>,
    pub response_status: u16,
    pub server_header: Option<String>,
    pub x_powered_by: Option<String>,
    pub scan_duration_ms: u64,
    pub redirect_chain: Vec<RedirectEntry>,
    pub https_redirect: Option<HttpsRedirectCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectEntry {
    pub url: String,
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsRedirectCheck {
    pub original_url: String,
    pub final_url: String,
    pub redirects_to_https: bool,
    pub is_permanent: bool,
    pub issue: Option<String>,
}
