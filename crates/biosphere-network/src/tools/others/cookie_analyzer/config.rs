use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAnalyzerConfig {
    pub url: String,
    pub timeout: u64,
    pub follow_redirects: bool,
    pub verify_ssl: bool,
    pub user_agent: Option<String>,
    pub proxy_url: Option<String>,
    pub check_js_cookies: bool,
    pub check_third_party: bool,
    pub check_compliance: bool,
    pub custom_headers: Option<String>,
}

impl Default for CookieAnalyzerConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            follow_redirects: true,
            verify_ssl: false,
            user_agent: None,
            proxy_url: None,
            check_js_cookies: true,
            check_third_party: true,
            check_compliance: true,
            custom_headers: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAnalyzerResult {
    pub url: String,
    pub cookies: Vec<CookieInfo>,
    pub issues: Vec<CookieIssue>,
    pub score: i32,
    pub grade: String,
    pub summary: String,
    pub severity_stats: SeverityStats,
    pub category_stats: Vec<CategoryStat>,
    pub compliance_report: ComplianceReport,
    pub response_headers: ResponseHeaderInfo,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value_preview: String,
    pub value_length: usize,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub expires: Option<String>,
    pub max_age: Option<i64>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
    pub is_session: bool,
    pub is_third_party: bool,
    pub cookie_category: String,
    pub risk_level: String,
    pub flags_status: CookieFlagsStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieFlagsStatus {
    pub has_httponly: bool,
    pub has_secure: bool,
    pub has_samesite: bool,
    pub has_path: bool,
    pub has_domain: bool,
    pub has_expiry: bool,
    pub total_flags: usize,
    pub max_flags: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieIssue {
    pub cookie_name: String,
    pub issue_type: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityStats {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStat {
    pub category: String,
    pub count: usize,
    pub critical_count: usize,
    pub high_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub gdpr_compliant: bool,
    pub pci_dss_compliant: bool,
    pub owasp_compliant: bool,
    pub gdpr_issues: Vec<String>,
    pub pci_dss_issues: Vec<String>,
    pub owasp_issues: Vec<String>,
    pub overall_compliance_score: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseHeaderInfo {
    pub has_strict_transport: bool,
    pub has_x_content_type_options: bool,
    pub has_x_frame_options: bool,
    pub has_csp: bool,
    pub server_header: Option<String>,
    pub x_powered_by: Option<String>,
    pub security_headers_score: i32,
}
