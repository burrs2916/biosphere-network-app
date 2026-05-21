use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsCheckConfig {
    pub url: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_level: String,
    pub test_origins: Vec<String>,
    pub test_methods: bool,
    pub test_preflight: bool,
    pub test_headers: bool,
}

impl Default for CorsCheckConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            threads: 5,
            scan_level: "moderate".to_string(),
            test_origins: Vec::new(),
            test_methods: true,
            test_preflight: true,
            test_headers: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsCheckResult {
    pub url: String,
    pub is_vulnerable: bool,
    pub severity: String,
    pub security_score: f64,
    pub issues: Vec<CorsIssue>,
    pub origin_results: Vec<CorsOriginResult>,
    pub method_results: Vec<CorsMethodResult>,
    pub header_analysis: CorsHeaderAnalysis,
    pub tests_performed: usize,
    pub scan_duration_ms: u64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsIssue {
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub detail: String,
    pub recommendation: String,
    pub confidence: f64,
    pub origin: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsOriginResult {
    pub origin: String,
    pub allowed: bool,
    pub allow_credentials: bool,
    pub allow_methods: Option<String>,
    pub allow_headers: Option<String>,
    pub acao_header: Option<String>,
    pub acac_header: Option<String>,
    pub is_wildcard: bool,
    pub is_null: bool,
    pub is_subdomain_bypass: bool,
    pub is_reflection: bool,
    pub http_status: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsMethodResult {
    pub method: String,
    pub acao_header: Option<String>,
    pub acac_header: Option<String>,
    pub allow_methods: Option<String>,
    pub allow_headers: Option<String>,
    pub is_allowed: bool,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsHeaderAnalysis {
    pub has_acao: bool,
    pub has_acac: bool,
    pub has_acam: bool,
    pub has_acah: bool,
    pub has_acma: bool,
    pub has_acex: bool,
    pub acao_value: Option<String>,
    pub acac_value: Option<String>,
    pub acam_value: Option<String>,
    pub acah_value: Option<String>,
    pub acma_value: Option<String>,
    pub acex_value: Option<String>,
    pub vary_origin: bool,
    pub security_headers: SecurityHeadersAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersAnalysis {
    pub has_csp: bool,
    pub csp_value: Option<String>,
    pub has_hsts: bool,
    pub hsts_value: Option<String>,
    pub has_xfo: bool,
    pub xfo_value: Option<String>,
    pub has_xcto: bool,
    pub xcto_value: Option<String>,
    pub has_xss_protection: bool,
    pub xss_protection_value: Option<String>,
    pub has_rp: bool,
    pub rp_value: Option<String>,
}

pub const BASIC_ORIGINS: &[&str] = &[
    "https://evil.com",
    "null",
];

pub const MODERATE_ORIGINS: &[&str] = &[
    "https://evil.com",
    "https://attacker.com",
    "null",
];

pub const AGGRESSIVE_ORIGINS: &[&str] = &[
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.example.com",
    "https://spoofed.evil.com",
    "https://sub.attacker.com",
];

pub const TEST_HTTP_METHODS: &[&str] = &[
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
];

pub const CORS_SECURITY_HEADERS: &[&str] = &[
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
];
