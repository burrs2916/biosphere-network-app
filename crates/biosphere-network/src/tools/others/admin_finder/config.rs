use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminFinderConfig {
    pub url: String,
    pub timeout: u64,
    pub concurrent: usize,
    pub wordlist: Vec<String>,
    pub scan_mode: String,
    pub follow_redirects: bool,
    pub randomize_ua: bool,
    pub detect_login_forms: bool,
    pub detect_waf: bool,
}

impl Default for AdminFinderConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            concurrent: 10,
            wordlist: Vec::new(),
            scan_mode: "normal".to_string(),
            follow_redirects: true,
            randomize_ua: true,
            detect_login_forms: true,
            detect_waf: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminFinderResult {
    pub url: String,
    pub found_paths: Vec<AdminPath>,
    pub paths_tested: usize,
    pub scan_duration_ms: u64,
    pub summary: String,
    pub waf_detected: Option<WafDetection>,
    pub categories: Vec<PathCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPath {
    pub url: String,
    pub path: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub title: Option<String>,
    pub redirect_url: Option<String>,
    pub is_likely_admin: bool,
    pub category: String,
    pub has_login_form: bool,
    pub response_time_ms: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub detected: bool,
    pub waf_name: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCategory {
    pub name: String,
    pub count: usize,
    pub paths: Vec<String>,
}
