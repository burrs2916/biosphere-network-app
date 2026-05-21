use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyDetail {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPoolConfig {
    pub proxies: Vec<String>,
    pub rotation_mode: String,
    pub retry_on_proxy_error: bool,
    pub validate_proxies: bool,
}

impl Default for ProxyPoolConfig {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            rotation_mode: "round_robin".to_string(),
            retry_on_proxy_error: true,
            validate_proxies: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub cache_dir: String,
    pub ttl_seconds: u64,
    pub respect_cache_control: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_dir: String::new(),
            ttl_seconds: 3600,
            respect_cache_control: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCertInfo {
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub is_expired: bool,
    pub days_remaining: Option<i64>,
    pub fingerprint_sha256: Option<String>,
    pub subject_alt_names: Vec<String>,
}

impl Default for SslCertInfo {
    fn default() -> Self {
        Self {
            subject: None,
            issuer: None,
            not_before: None,
            not_after: None,
            is_expired: false,
            days_remaining: None,
            fingerprint_sha256: None,
            subject_alt_names: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopupDetection {
    pub detected: bool,
    pub popup_types: Vec<String>,
    pub confidence: f64,
    pub details: Vec<String>,
}

impl Default for PopupDetection {
    fn default() -> Self {
        Self {
            detected: false,
            popup_types: Vec::new(),
            confidence: 0.0,
            details: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCrawlerConfig {
    pub url: String,
    pub max_depth: usize,
    pub max_pages: usize,
    pub timeout: u64,
    pub follow_external: bool,
    pub extract_emails: bool,
    pub extract_js: bool,
    pub extract_comments: bool,
    pub extract_images: bool,
    pub extract_css: bool,
    pub extract_fonts: bool,
    pub extract_documents: bool,
    pub extract_videos: bool,
    pub extract_audio: bool,
    pub extract_api_endpoints: bool,
    pub extract_metadata: bool,
    pub scan_directories: bool,
    pub respect_robots: bool,
    pub concurrent_requests: usize,
    pub crawl_mode: String,
    pub download_mode: String,
    pub max_retries: usize,
    pub retry_delay_ms: u64,
    pub proxy_url: String,
    pub detect_antibot: bool,
    pub keywords: String,
    pub crawl_strategy: String,
    pub request_delay_ms: u64,
    pub parse_css_resources: bool,
    pub normalize_urls: bool,
    pub cookies: String,
    pub custom_headers: String,
    pub max_download_count: usize,
    pub priority_order: String,
    pub proxy_pool: ProxyPoolConfig,
    pub cache: CacheConfig,
    pub crawl_iframes: bool,
    pub url_filter_patterns: String,
    pub url_exclude_patterns: String,
}

impl Default for WebCrawlerConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_depth: 3,
            max_pages: 200,
            timeout: 15,
            follow_external: false,
            extract_emails: true,
            extract_js: true,
            extract_comments: true,
            extract_images: true,
            extract_css: true,
            extract_fonts: true,
            extract_documents: true,
            extract_videos: true,
            extract_audio: true,
            extract_api_endpoints: true,
            extract_metadata: true,
            scan_directories: false,
            respect_robots: true,
            concurrent_requests: 8,
            crawl_mode: "full".to_string(),
            download_mode: "by_type".to_string(),
            max_retries: 3,
            retry_delay_ms: 1000,
            proxy_url: String::new(),
            detect_antibot: true,
            keywords: String::new(),
            crawl_strategy: "bfs".to_string(),
            request_delay_ms: 200,
            parse_css_resources: true,
            normalize_urls: true,
            cookies: String::new(),
            custom_headers: String::new(),
            max_download_count: 0,
            priority_order: "video,audio,image,document,font,css,js".to_string(),
            proxy_pool: ProxyPoolConfig::default(),
            cache: CacheConfig::default(),
            crawl_iframes: true,
            url_filter_patterns: String::new(),
            url_exclude_patterns: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebCrawlerResult {
    pub start_url: String,
    pub pages_crawled: usize,
    pub total_links: usize,
    pub links: Vec<CrawledLink>,
    pub emails: Vec<String>,
    pub js_files: Vec<ResourceInfo>,
    pub comments: Vec<String>,
    pub images: Vec<ResourceInfo>,
    pub css_files: Vec<ResourceInfo>,
    pub fonts: Vec<ResourceInfo>,
    pub documents: Vec<ResourceInfo>,
    pub videos: Vec<ResourceInfo>,
    pub audio_files: Vec<ResourceInfo>,
    pub api_endpoints: Vec<ApiEndpoint>,
    pub metadata: PageMetadata,
    pub technologies: Vec<String>,
    pub technology_details: Vec<TechnologyDetail>,
    pub directory_entries: Vec<DirEntryInfo>,
    pub summary: String,
    pub antibot_detection: Option<AntibotDetection>,
    pub subdomains: Vec<String>,
    pub security_info: SecurityInfo,
    pub paywall_detection: Option<PaywallDetection>,
    pub ssl_cert_info: Option<SslCertInfo>,
    pub popup_detection: Option<PopupDetection>,
    pub markdown_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaywallDetection {
    pub detected: bool,
    pub paywall_type: Option<String>,
    pub confidence: f64,
    pub details: Vec<String>,
    pub hidden_content_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntibotDetection {
    pub detected: bool,
    pub protection_type: Option<String>,
    pub confidence: f64,
    pub details: Vec<String>,
    pub waf_vendor: Option<String>,
    pub challenge_type: Option<String>,
    pub bypass_suggestions: Vec<String>,
}

impl Default for AntibotDetection {
    fn default() -> Self {
        Self {
            detected: false,
            protection_type: None,
            confidence: 0.0,
            details: Vec::new(),
            waf_vendor: None,
            challenge_type: None,
            bypass_suggestions: Vec::new(),
        }
    }
}

pub fn detect_antibot(status_code: u16, html: &str) -> AntibotDetection {
    let mut detection = AntibotDetection::default();
    let html_lower = html.to_lowercase();
    let html_len = html.len();

    let tier1_patterns: Vec<(&str, &str, &str)> = vec![
        (r"Reference\s*#\s*[\d]+\.[0-9a-f]+\.\d+\.[0-9a-f]+", "Akamai", "block"),
        (r"Pardon\s+Our\s+Interruption", "Akamai", "challenge"),
        (r"challenge-form.*?__cf_chl_f_tk=", "Cloudflare", "challenge"),
        (r#"<span\s+class="cf-error-code">\d{4}</span>"#, "Cloudflare", "block"),
        (r"/cdn-cgi/challenge-platform/\S+orchestrate", "Cloudflare", "js_challenge"),
        (r"window\._pxAppId\s*=", "PerimeterX", "block"),
        (r"captcha\.px-cdn\.net", "PerimeterX", "captcha"),
        (r"captcha-delivery\.com", "DataDome", "captcha"),
        (r"_Incapsula_Resource", "Imperva", "block"),
        (r"Incapsula\s+incident\s+ID", "Imperva", "incident"),
        (r"Sucuri\s+WebSite\s+Firewall", "Sucuri", "block"),
        (r"Access\s+Denied\s*[-–]\s*Sucuri", "Sucuri", "block"),
        (r"cf-browser-verification", "Cloudflare", "browser_check"),
        (r"Checking your browser before accessing", "Cloudflare", "browser_check"),
        (r"Please Wait.*Cloudflare", "Cloudflare", "waiting_room"),
        (r"ray ID.*cloudflare", "Cloudflare", "block"),
        (r"Attention Required.*Cloudflare", "Cloudflare", "block"),
        (r"cf_chl_opt", "Cloudflare", "challenge"),
        (r"__cf_bm", "Cloudflare", "bot_management"),
        (r"akamai.*bypass", "Akamai", "block"),
        (r"ak_bmsc", "Akamai", "bot_manager"),
        (r"bm_sv", "Akamai", "bot_manager"),
        (r"datadome.*cookie", "DataDome", "cookie_check"),
        (r"dd_cookie_test", "DataDome", "cookie_check"),
        (r"px3rdparty", "PerimeterX", "third_party"),
        (r"_pxff_", "PerimeterX", "fingerprint"),
        (r"shield.*f5.*networks", "F5", "block"),
        (r"BigIP", "F5", "block"),
        (r"Arbor.*Networks", "Arbor", "block"),
        (r"imperva.*redirect", "Imperva", "redirect"),
    ];

    for (pattern, vendor, challenge) in &tier1_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(&html_lower) || re.is_match(html) {
                detection.detected = true;
                detection.waf_vendor = Some(vendor.to_string());
                detection.challenge_type = Some(challenge.to_string());
                detection.protection_type = Some(vendor.to_string());
                detection.confidence = 0.95;
                detection.details.push(format!("Tier1 match: {} ({})", vendor, challenge));
                break;
            }
        }
    }

    if !detection.detected && (status_code == 403 || status_code == 503) && html_len > 0 {
        detection.detected = true;
        detection.confidence = 0.7;
        detection.protection_type = Some("unknown_waf".to_string());
        detection.challenge_type = Some(if status_code == 503 { "challenge" } else { "block" }.to_string());
        detection.details.push(format!("HTTP {} with HTML content suggests WAF block", status_code));
    }

    let tier2_keywords: Vec<(&str, &str)> = vec![
        ("access denied", "generic"),
        ("blocked", "generic"),
        ("captcha", "captcha"),
        ("challenge", "challenge"),
        ("bot detection", "bot_detection"),
        ("rate limit", "rate_limit"),
        ("too many requests", "rate_limit"),
        ("request blocked", "block"),
        ("security check", "security_check"),
        ("verify you are human", "human_check"),
        ("are you a robot", "robot_check"),
        ("automated access", "automation_detection"),
        ("unusual traffic", "traffic_anomaly"),
    ];

    if !detection.detected && html_len < 5000 {
        for (keyword, category) in &tier2_keywords {
            if html_lower.contains(keyword) {
                detection.detected = true;
                detection.confidence = 0.6;
                detection.protection_type = Some(category.to_string());
                detection.details.push(format!("Tier2 keyword match: '{}' ({})", keyword, category));
                break;
            }
        }
    }

    if detection.detected {
        let vendor = detection.waf_vendor.as_deref().unwrap_or("unknown");
        detection.bypass_suggestions = match vendor {
            "Cloudflare" => vec![
                "Use residential proxies with proper IP reputation".to_string(),
                "Implement proper TLS fingerprint (JA3/JA4)".to_string(),
                "Use headless browser with stealth plugins".to_string(),
                "Solve JS challenge programmatically".to_string(),
                "Rotate User-Agent with matching Client Hints".to_string(),
            ],
            "Akamai" => vec![
                "Use Akamai fingerprint spoofing".to_string(),
                "Implement proper sensor data generation".to_string(),
                "Use residential proxies".to_string(),
                "Match browser fingerprint expectations".to_string(),
            ],
            "PerimeterX" | "DataDome" => vec![
                "Use proper cookie handling and rotation".to_string(),
                "Implement canvas/WebGL fingerprint spoofing".to_string(),
                "Use residential proxies".to_string(),
                "Solve CAPTCHA challenges when needed".to_string(),
            ],
            "Imperva" => vec![
                "Handle Incapsula cookies properly".to_string(),
                "Use proper Referer and Origin headers".to_string(),
                "Implement JavaScript execution for cookie generation".to_string(),
            ],
            _ => vec![
                "Use residential proxies".to_string(),
                "Rotate User-Agent strings".to_string(),
                "Add proper request delays".to_string(),
                "Implement headless browser for JS-heavy sites".to_string(),
            ],
        };
    }

    detection
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub has_https: bool,
    pub has_hsts: bool,
    pub has_csp: bool,
    pub has_x_frame_options: bool,
    pub has_x_content_type_options: bool,
    pub server_header: Option<String>,
    pub powered_by_header: Option<String>,
    pub security_score: u8,
    pub csp_directives: Option<String>,
    pub has_strict_transport: bool,
    pub has_x_xss_protection: bool,
    pub has_referrer_policy: bool,
    pub has_permissions_policy: bool,
}

impl Default for SecurityInfo {
    fn default() -> Self {
        Self {
            has_https: false,
            has_hsts: false,
            has_csp: false,
            has_x_frame_options: false,
            has_x_content_type_options: false,
            server_header: None,
            powered_by_header: None,
            security_score: 0,
            csp_directives: None,
            has_strict_transport: false,
            has_x_xss_protection: false,
            has_referrer_policy: false,
            has_permissions_policy: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawledLink {
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub depth: usize,
    pub content_type: Option<String>,
    pub response_time_ms: Option<u64>,
    pub word_count: Option<usize>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub url: String,
    pub resource_type: String,
    pub size: Option<u64>,
    pub source_page: Option<String>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntryInfo {
    pub path: String,
    pub full_url: String,
    pub status_code: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
    pub keywords: Option<String>,
    pub og_title: Option<String>,
    pub og_description: Option<String>,
    pub og_image: Option<String>,
    pub og_video: Option<String>,
    pub og_audio: Option<String>,
    pub og_type: Option<String>,
    pub og_site_name: Option<String>,
    pub twitter_card: Option<String>,
    pub twitter_title: Option<String>,
    pub twitter_description: Option<String>,
    pub twitter_image: Option<String>,
    pub canonical: Option<String>,
    pub generator: Option<String>,
    pub author: Option<String>,
    pub viewport: Option<String>,
    pub robots: Option<String>,
}

impl Default for PageMetadata {
    fn default() -> Self {
        Self {
            title: None,
            description: None,
            keywords: None,
            og_title: None,
            og_description: None,
            og_image: None,
            og_video: None,
            og_audio: None,
            og_type: None,
            og_site_name: None,
            twitter_card: None,
            twitter_title: None,
            twitter_description: None,
            twitter_image: None,
            canonical: None,
            generator: None,
            author: None,
            viewport: None,
            robots: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    pub url: String,
    pub file_path: String,
    pub file_size: u64,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDownloadResult {
    pub total: usize,
    pub success_count: usize,
    pub failed_count: usize,
    pub results: Vec<DownloadResult>,
    pub save_dir: String,
    pub paywall_detected: Option<bool>,
    pub download_limit_detected: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteDownloadConfig {
    pub save_dir: String,
    pub download_mode: String,
    pub max_concurrent: usize,
    pub max_retries: usize,
    pub retry_delay_ms: u64,
    pub include_images: bool,
    pub include_videos: bool,
    pub include_audio: bool,
    pub include_css: bool,
    pub include_js: bool,
    pub include_fonts: bool,
    pub include_documents: bool,
    pub mirror_mode: bool,
    pub proxy_url: String,
    pub cookies: String,
    pub custom_headers: String,
    pub max_download_count: usize,
    pub priority_order: String,
    pub proxy_pool: ProxyPoolConfig,
    pub cache: CacheConfig,
    pub rewrite_urls: bool,
}

impl Default for SiteDownloadConfig {
    fn default() -> Self {
        Self {
            save_dir: String::new(),
            download_mode: "by_type".to_string(),
            max_concurrent: 5,
            max_retries: 3,
            retry_delay_ms: 1000,
            include_images: true,
            include_videos: true,
            include_audio: true,
            include_css: true,
            include_js: true,
            include_fonts: true,
            include_documents: true,
            mirror_mode: false,
            proxy_url: String::new(),
            cookies: String::new(),
            custom_headers: String::new(),
            max_download_count: 0,
            priority_order: "video,audio,image,document,font,css,js".to_string(),
            proxy_pool: ProxyPoolConfig::default(),
            cache: CacheConfig::default(),
            rewrite_urls: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub format: String,
    pub save_path: String,
    pub include_links: bool,
    pub include_resources: bool,
    pub include_emails: bool,
    pub include_apis: bool,
    pub include_metadata: bool,
    pub include_technologies: bool,
    pub include_directory: bool,
    pub include_security: bool,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            format: "json".to_string(),
            save_path: String::new(),
            include_links: true,
            include_resources: true,
            include_emails: true,
            include_apis: true,
            include_metadata: true,
            include_technologies: true,
            include_directory: true,
            include_security: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepCrawlConfig {
    pub strategy: String,
    pub max_depth: usize,
    pub max_pages: usize,
    pub filter_chain: Vec<UrlFilter>,
    pub scorer: CrawlScorer,
    pub delay_ms: u64,
    pub respect_robots: bool,
    pub follow_external: bool,
}

impl Default for DeepCrawlConfig {
    fn default() -> Self {
        Self {
            strategy: "bfs".to_string(),
            max_depth: 3,
            max_pages: 200,
            filter_chain: Vec::new(),
            scorer: CrawlScorer::default(),
            delay_ms: 200,
            respect_robots: true,
            follow_external: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlFilter {
    pub filter_type: String,
    pub pattern: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlScorer {
    pub keyword_weight: f64,
    pub depth_weight: f64,
    pub freshness_weight: f64,
    pub domain_authority_weight: f64,
    pub content_type_weight: f64,
    pub keywords: Vec<String>,
}

impl Default for CrawlScorer {
    fn default() -> Self {
        Self {
            keyword_weight: 0.4,
            depth_weight: 0.2,
            freshness_weight: 0.15,
            domain_authority_weight: 0.15,
            content_type_weight: 0.1,
            keywords: Vec::new(),
        }
    }
}

impl CrawlScorer {
    pub fn score_url(&self, url: &str, depth: usize, content_type: Option<&str>) -> f64 {
        let mut score = 1.0;

        let depth_penalty = 1.0 / (1.0 + depth as f64 * self.depth_weight);
        score *= depth_penalty;

        for keyword in &self.keywords {
            if url.to_lowercase().contains(&keyword.to_lowercase()) {
                score += self.keyword_weight;
            }
        }

        if let Some(ct) = content_type {
            if ct.contains("text/html") {
                score += self.content_type_weight;
            } else if ct.contains("application/pdf") {
                score += self.content_type_weight * 0.5;
            }
        }

        score
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAgentGenerator {
    pub browser_type: String,
    pub os_type: String,
    pub rotate: bool,
    pub pool: Vec<String>,
}

impl Default for UserAgentGenerator {
    fn default() -> Self {
        Self {
            browser_type: "chrome".to_string(),
            os_type: "mixed".to_string(),
            rotate: true,
            pool: Self::build_pool(),
        }
    }
}

impl UserAgentGenerator {
    fn build_pool() -> Vec<String> {
        vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0".to_string(),
        ]
    }

    pub fn generate(&self) -> String {
        if self.rotate && !self.pool.is_empty() {
            let idx = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as usize % self.pool.len();
            self.pool[idx].clone()
        } else {
            self.pool.first().cloned().unwrap_or_else(|| "Mozilla/5.0".to_string())
        }
    }

    pub fn generate_client_hints(user_agent: &str) -> String {
        let mut brands = Vec::new();
        if let Some(cap) = regex::Regex::new(r"Chrome/(\d+)").unwrap().captures(user_agent) {
            if let Some(ver) = cap.get(1) {
                brands.push(format!(r#""Chromium";"v={}""#, ver.as_str()));
                brands.push(r#""Not_A Brand";"v=8""#.to_string());
                if user_agent.contains("Edg/") {
                    if let Some(edg) = regex::Regex::new(r"Edg/(\d+)").unwrap().captures(user_agent) {
                        if let Some(ev) = edg.get(1) {
                            brands.push(format!(r#""Microsoft Edge";"v={}""#, ev.as_str()));
                        }
                    }
                } else {
                    brands.push(format!(r#""Google Chrome";"v={}""#, ver.as_str()));
                }
            }
        }
        if brands.is_empty() {
            r#""Not_A Brand";"v=8""#.to_string()
        } else {
            brands.join(",")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableExtractionResult {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub caption: Option<String>,
    pub row_count: usize,
    pub col_count: usize,
}

pub fn extract_tables_from_html(html: &str) -> Vec<TableExtractionResult> {
    let mut tables = Vec::new();

    let table_re = regex::Regex::new(r"(?s)<table[^>]*>(.*?)</table>").unwrap();
    let thead_re = regex::Regex::new(r"(?s)<thead[^>]*>(.*?)</thead>").unwrap();
    let th_re = regex::Regex::new(r"(?s)<th[^>]*>(.*?)</th>").unwrap();
    let tr_re = regex::Regex::new(r"(?s)<tr[^>]*>(.*?)</tr>").unwrap();
    let td_re = regex::Regex::new(r"(?s)<td[^>]*>(.*?)</td>").unwrap();
    let caption_re = regex::Regex::new(r"(?s)<caption[^>]*>(.*?)</caption>").unwrap();
    let tag_re = regex::Regex::new(r"<[^>]+>").unwrap();

    for table_cap in table_re.captures_iter(html) {
        let table_html = table_cap.get(1).unwrap().as_str();

        let caption = caption_re.captures(table_html)
            .and_then(|c| c.get(1))
            .map(|m| tag_re.replace_all(m.as_str(), "").trim().to_string());

        let mut headers = Vec::new();
        if let Some(thead) = thead_re.captures(table_html).and_then(|c| c.get(1)) {
            for th in th_re.captures_iter(thead.as_str()) {
                headers.push(tag_re.replace_all(th.get(1).unwrap().as_str(), "").trim().to_string());
            }
        }

        let mut rows = Vec::new();
        for tr in tr_re.captures_iter(table_html) {
            let tr_html = tr.get(1).unwrap().as_str();
            if thead_re.is_match(tr_html) {
                continue;
            }

            if headers.is_empty() && rows.is_empty() {
                for th in th_re.captures_iter(tr_html) {
                    headers.push(tag_re.replace_all(th.get(1).unwrap().as_str(), "").trim().to_string());
                }
                if !headers.is_empty() {
                    continue;
                }
            }

            let mut row = Vec::new();
            for td in td_re.captures_iter(tr_html) {
                row.push(tag_re.replace_all(td.get(1).unwrap().as_str(), "").trim().to_string());
            }
            if !row.is_empty() {
                rows.push(row);
            }
        }

        if !rows.is_empty() || !headers.is_empty() {
            let col_count = if !headers.is_empty() { headers.len() } else { rows.first().map(|r| r.len()).unwrap_or(0) };
            tables.push(TableExtractionResult {
                headers,
                rows,
                caption,
                row_count: tables.len(),
                col_count,
            });
        }
    }

    tables
}

pub fn html_to_markdown(html: &str) -> String {
    let mut md = html.to_string();

    let tag_replacements: Vec<(&str, &str)> = vec![
        (r"(?s)<h1[^>]*>(.*?)</h1>", "# $1"),
        (r"(?s)<h2[^>]*>(.*?)</h2>", "## $1"),
        (r"(?s)<h3[^>]*>(.*?)</h3>", "### $1"),
        (r"(?s)<h4[^>]*>(.*?)</h4>", "#### $1"),
        (r"(?s)<h5[^>]*>(.*?)</h5>", "##### $1"),
        (r"(?s)<h6[^>]*>(.*?)</h6>", "###### $1"),
        (r"(?s)<strong[^>]*>(.*?)</strong>", "**$1**"),
        (r"(?s)<b[^>]*>(.*?)</b>", "**$1**"),
        (r"(?s)<em[^>]*>(.*?)</em>", "*$1*"),
        (r"(?s)<i[^>]*>(.*?)</i>", "*$1*"),
        (r"(?s)<code[^>]*>(.*?)</code>", "`$1`"),
        (r#"(?s)<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>"#, "[$2]($1)"),
        (r#"(?s)<img[^>]*src="([^"]*)"[^>]*alt="([^"]*)"[^>]*/?\s*>"#, "![$2]($1)"),
        (r#"(?s)<img[^>]*src="([^"]*)"[^>]*/?\s*>"#, "![]($1)"),
    ];

    for (pattern, replacement) in &tag_replacements {
        if let Ok(re) = regex::Regex::new(pattern) {
            md = re.replace_all(&md, *replacement).to_string();
        }
    }

    let list_item_re = regex::Regex::new(r"(?s)<li[^>]*>(.*?)</li>").unwrap();
    md = list_item_re.replace_all(&md, "- $1").to_string();

    let block_re = regex::Regex::new(r"(?s)<blockquote[^>]*>(.*?)</blockquote>").unwrap();
    md = block_re.replace_all(&md, "> $1").to_string();

    let pre_re = regex::Regex::new(r"(?s)<pre[^>]*>(.*?)</pre>").unwrap();
    md = pre_re.replace_all(&md, "```\n$1\n```").to_string();

    let hr_re = regex::Regex::new(r"<hr[^>]*/?\s*>").unwrap();
    md = hr_re.replace_all(&md, "---").to_string();

    let br_re = regex::Regex::new(r"<br[^>]*/?\s*>").unwrap();
    md = br_re.replace_all(&md, "\n").to_string();

    let p_re = regex::Regex::new(r"(?s)<p[^>]*>(.*?)</p>").unwrap();
    md = p_re.replace_all(&md, "$1\n\n").to_string();

    let div_re = regex::Regex::new(r"(?s)<div[^>]*>(.*?)</div>").unwrap();
    md = div_re.replace_all(&md, "$1\n").to_string();

    let remaining_tag_re = regex::Regex::new(r"<[^>]+>").unwrap();
    md = remaining_tag_re.replace_all(&md, "").to_string();

    let entity_replacements: Vec<(&str, &str)> = vec![
        ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
        ("&quot;", "\""), ("&#39;", "'"), ("&nbsp;", " "),
    ];
    for (entity, replacement) in &entity_replacements {
        md = md.replace(entity, replacement);
    }

    let multi_newline = regex::Regex::new(r"\n{3,}").unwrap();
    md = multi_newline.replace_all(&md, "\n\n").to_string();

    md.trim().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFilterConfig {
    pub min_word_count: usize,
    pub max_link_density: f64,
    pub keywords: Vec<String>,
    pub exclude_selectors: Vec<String>,
    pub include_selectors: Vec<String>,
}

impl Default for ContentFilterConfig {
    fn default() -> Self {
        Self {
            min_word_count: 50,
            max_link_density: 0.5,
            keywords: Vec::new(),
            exclude_selectors: vec![
                "nav".to_string(), "footer".to_string(), "header".to_string(),
                ".sidebar".to_string(), ".ad".to_string(), ".advertisement".to_string(),
                ".cookie-banner".to_string(), ".popup".to_string(), ".modal".to_string(),
                "#comments".to_string(), ".social-share".to_string(),
            ],
            include_selectors: vec![
                "article".to_string(), "main".to_string(), ".content".to_string(),
                ".post".to_string(), ".entry".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRotationStrategy {
    pub strategy: String,
    pub current_index: usize,
    pub health_check_url: String,
    pub max_failures: u32,
    pub failure_counts: std::collections::HashMap<String, u32>,
}

impl Default for ProxyRotationStrategy {
    fn default() -> Self {
        Self {
            strategy: "round_robin".to_string(),
            current_index: 0,
            health_check_url: "https://httpbin.org/ip".to_string(),
            max_failures: 3,
            failure_counts: std::collections::HashMap::new(),
        }
    }
}

impl ProxyRotationStrategy {
    pub fn next_proxy(&mut self, proxies: &[String]) -> Option<String> {
        if proxies.is_empty() {
            return None;
        }

        let healthy_proxies: Vec<&String> = proxies.iter()
            .filter(|p| *self.failure_counts.get(*p).unwrap_or(&0) < self.max_failures)
            .collect();

        if healthy_proxies.is_empty() {
            self.failure_counts.clear();
            return proxies.first().cloned();
        }

        match self.strategy.as_str() {
            "round_robin" => {
                let proxy = healthy_proxies.get(self.current_index % healthy_proxies.len()).cloned().cloned();
                self.current_index += 1;
                proxy
            }
            "random" => {
                let idx = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as usize % healthy_proxies.len();
                healthy_proxies.get(idx).cloned().cloned()
            }
            _ => healthy_proxies.first().cloned().cloned(),
        }
    }

    pub fn report_failure(&mut self, proxy: &str) {
        *self.failure_counts.entry(proxy.to_string()).or_insert(0) += 1;
    }

    pub fn report_success(&mut self, proxy: &str) {
        self.failure_counts.remove(proxy);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlMonitorInfo {
    pub urls_queued: usize,
    pub urls_crawled: usize,
    pub urls_failed: usize,
    pub urls_skipped: usize,
    pub active_connections: usize,
    pub memory_usage_mb: f64,
    pub elapsed_secs: f64,
    pub pages_per_second: f64,
    pub errors_by_type: std::collections::HashMap<String, usize>,
    pub status_code_distribution: std::collections::HashMap<u16, usize>,
}

impl Default for CrawlMonitorInfo {
    fn default() -> Self {
        Self {
            urls_queued: 0,
            urls_crawled: 0,
            urls_failed: 0,
            urls_skipped: 0,
            active_connections: 0,
            memory_usage_mb: 0.0,
            elapsed_secs: 0.0,
            pages_per_second: 0.0,
            errors_by_type: std::collections::HashMap::new(),
            status_code_distribution: std::collections::HashMap::new(),
        }
    }
}
