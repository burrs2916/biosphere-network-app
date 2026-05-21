use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRedirectConfig {
    pub url: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_level: String,
    pub test_params: Vec<String>,
    pub test_payloads: Vec<String>,
    pub follow_redirects: bool,
    pub analyze_body: bool,
}

impl Default for OpenRedirectConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            threads: 5,
            scan_level: "moderate".to_string(),
            test_params: Vec::new(),
            test_payloads: Vec::new(),
            follow_redirects: false,
            analyze_body: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRedirectResult {
    pub url: String,
    pub is_vulnerable: bool,
    pub severity: String,
    pub security_score: f64,
    pub vulnerabilities: Vec<OpenRedirectVuln>,
    pub tests_performed: usize,
    pub scan_duration_ms: u64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRedirectVuln {
    pub parameter: String,
    pub payload: String,
    pub payload_type: String,
    pub severity: String,
    pub redirect_to: String,
    pub http_status: Option<u16>,
    pub confidence: f64,
    pub description: String,
    pub detail: String,
    pub recommendation: String,
    pub is_redirect_chain: bool,
    pub is_body_based: bool,
}

pub const BASIC_PARAMS: &[&str] = &[
    "url", "redirect", "redirect_url", "redirect_uri", "return",
];

pub const MODERATE_PARAMS: &[&str] = &[
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "returnTo", "return_to", "next", "goto", "dest",
    "destination", "redir", "redirect_to", "continue", "target",
];

pub const AGGRESSIVE_PARAMS: &[&str] = &[
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "returnTo", "return_to", "next", "goto", "dest",
    "destination", "redir", "redirect_to", "redirect_uri",
    "continue", "target", "callback", "ref", "rurl",
    "link", "out", "exit", "forward", "forward_url",
    "returnUrl", "return_path", "path", "location", "go",
    "to", "from", "back", "goTo", "go_url", "redirectUrl",
    "redirectUri", "origin", "source", "referrer", "referer",
    "nextUrl", "next_url", "nextPage", "next_page", "destinationUrl",
    "destination_url", "targetUrl", "target_url", "landing",
    "landingUrl", "landing_url", "view", "viewUrl", "view_url",
];

pub const BASIC_PAYLOADS: &[(&str, &str, f64)] = &[
    ("https://evil.com", "Direct HTTPS URL", 0.95),
    ("http://evil.com", "Direct HTTP URL", 0.90),
    ("//evil.com", "Protocol-relative URL", 0.90),
];

pub const MODERATE_PAYLOADS: &[(&str, &str, f64)] = &[
    ("https://evil.com", "Direct HTTPS URL", 0.95),
    ("http://evil.com", "Direct HTTP URL", 0.90),
    ("//evil.com", "Protocol-relative URL", 0.90),
    ("///evil.com", "Triple slash bypass", 0.85),
    ("\\\\evil.com", "Backslash bypass", 0.80),
    ("https:///evil.com", "Extra slash bypass", 0.80),
    ("/\\evil.com", "Mixed slash bypass", 0.75),
];

pub const AGGRESSIVE_PAYLOADS: &[(&str, &str, f64)] = &[
    ("https://evil.com", "Direct HTTPS URL", 0.95),
    ("http://evil.com", "Direct HTTP URL", 0.90),
    ("//evil.com", "Protocol-relative URL", 0.90),
    ("///evil.com", "Triple slash bypass", 0.85),
    ("\\\\evil.com", "Backslash bypass", 0.80),
    ("https:///evil.com", "Extra slash bypass", 0.80),
    ("/\\evil.com", "Mixed slash bypass", 0.75),
    ("javascript:alert(1)", "JavaScript protocol", 0.70),
    ("data:text/html,<script>alert(1)</script>", "Data URI", 0.65),
    ("vbscript:alert(1)", "VBScript protocol", 0.60),
    ("https://evil.com\\@example.com", "At sign bypass", 0.70),
    ("https://evil.com%0a@example.com", "Line feed bypass", 0.65),
    ("https://evil.com%0d@example.com", "Carriage return bypass", 0.65),
    ("https://evil.com%00@example.com", "Null byte bypass", 0.60),
    ("https://evil.com%20@example.com", "Space bypass", 0.55),
    ("https://evil.com%23@example.com", "Hash bypass", 0.55),
    ("https://evil.com%3f@example.com", "Question mark bypass", 0.55),
    ("https://evil.com%26@example.com", "Ampersand bypass", 0.50),
    ("https://evil.com%252f@example.com", "Double encoded slash", 0.50),
    ("https://evil.com%252e%252e/", "Double encoded path traversal", 0.45),
    ("https://evil.com\u{200b}", "Zero-width space", 0.40),
    ("https://evil.com\u{200d}", "Zero-width joiner", 0.40),
    ("https://evil.com\u{200e}", "Left-to-right mark", 0.40),
    ("https://evil.com\u{200f}", "Right-to-left mark", 0.40),
];

pub const EVIL_DOMAIN: &str = "evil.com";
pub const EVIL_HTTPS: &str = "https://evil.com";
pub const EVIL_HTTP: &str = "http://evil.com";
