use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanConfig {
    pub url: String,
    pub timeout: u64,
    pub scan_js: bool,
    pub scan_html: bool,
    pub scan_comments: bool,
    pub max_pages: usize,
    pub custom_patterns: Vec<String>,
    pub min_confidence: f64,
    pub severity_filter: Option<String>,
    pub scan_mode: String,
    pub crawl_depth: usize,
    pub concurrent_requests: usize,
    pub user_agent: Option<String>,
    pub proxy_url: Option<String>,
    pub follow_redirects: bool,
    pub verify_ssl: bool,
    pub scan_css: bool,
    pub scan_meta: bool,
    pub deduplicate: bool,
}

impl Default for SecretScanConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            scan_js: true,
            scan_html: true,
            scan_comments: true,
            max_pages: 20,
            custom_patterns: Vec::new(),
            min_confidence: 0.5,
            severity_filter: None,
            scan_mode: "balanced".to_string(),
            crawl_depth: 1,
            concurrent_requests: 5,
            user_agent: None,
            proxy_url: None,
            follow_redirects: true,
            verify_ssl: false,
            scan_css: false,
            scan_meta: true,
            deduplicate: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScanResult {
    pub url: String,
    pub secrets: Vec<DetectedSecret>,
    pub pages_scanned: usize,
    pub js_files_scanned: usize,
    pub css_files_scanned: usize,
    pub scan_duration_ms: u64,
    pub summary: String,
    pub severity_stats: SeverityStats,
    pub category_stats: Vec<CategoryStat>,
    pub urls_scanned: Vec<String>,
    pub duplicate_count: usize,
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
pub struct DetectedSecret {
    pub secret_type: String,
    pub category: String,
    pub severity: String,
    pub value_preview: String,
    pub full_value: String,
    pub source_url: String,
    pub source_type: String,
    pub line_context: String,
    pub line_number: Option<usize>,
    pub confidence: f64,
    pub is_custom: bool,
    pub remediation: String,
}
