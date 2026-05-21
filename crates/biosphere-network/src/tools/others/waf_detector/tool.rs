use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use reqwest::Client;
use crate::core::{Result, ToolError};
use super::config::*;
use tokio::sync::Semaphore;

struct BaselineInfo {
    status: u16,
    server: Option<String>,
    content_length: Option<u64>,
    body: String,
    headers: reqwest::header::HeaderMap,
    redirect_url: Option<String>,
    time_ms: u64,
    content_type: Option<String>,
    x_powered_by: Option<String>,
    cookies: Vec<(String, String)>,
}

struct WafSignatureDb;

impl WafSignatureDb {
    fn server_signatures() -> Vec<(&'static str, &'static str, f64)> {
        vec![
            ("cloudflare", "Cloudflare", 0.95),
            ("cloudflare-nginx", "Cloudflare", 0.98),
            ("imperva", "Imperva/Incapsula", 0.95),
            ("incapsula", "Imperva/Incapsula", 0.98),
            ("akamaighost", "Akamai Kona Site Defender", 0.95),
            ("akamai", "Akamai", 0.90),
            ("sucuri", "Sucuri CloudProxy", 0.95),
            ("awselb", "AWS WAF / Shield", 0.70),
            ("f5", "F5 BIG-IP ASM", 0.80),
            ("bigip", "F5 BIG-IP ASM", 0.85),
            ("mod_security", "ModSecurity", 0.90),
            ("modsecurity", "ModSecurity", 0.95),
            ("barracuda", "Barracuda WAF", 0.90),
            ("denied", "Deny All WAF", 0.70),
            ("fortiweb", "Fortinet FortiWeb", 0.90),
            ("fortinet", "Fortinet", 0.80),
            ("chinacache", "ChinaCache WAF", 0.70),
            ("qiniu", "Qiniu WAF", 0.60),
            ("yundun", "Alibaba Cloud WAF (Yundun)", 0.85),
            ("huaweiwaf", "Huawei Cloud WAF", 0.85),
            ("tencentwaf", "Tencent Cloud WAF", 0.85),
            ("wts", "West263 WAF", 0.70),
            ("safeline", "SafeLine WAF (Chaitin)", 0.85),
            ("nsfocus", "NSFOCUS WAF", 0.85),
            ("knownsec", "KnownSec WAF", 0.85),
            ("jiasule", "Jiasule WAF", 0.80),
            ("dbappsecurity", "DBAppSecurity WAF (Anheng)", 0.85),
            ("venustech", "Venustech WAF (Topsec)", 0.80),
            ("sangfor", "Sangfor WAF", 0.80),
            ("hillstone", "Hillstone WAF", 0.80),
            ("threatx", "ThreatX WAF", 0.85),
            ("signal sciences", "Signal Sciences WAF", 0.85),
            ("fastly", "Fastly WAF", 0.80),
            ("stackpath", "StackPath WAF", 0.85),
            ("squarespace", "Squarespace WAF", 0.70),
            ("wordfence", "Wordfence", 0.85),
            ("sucuri.net", "Sucuri Firewall", 0.90),
            ("limelight", "Limelight WAF", 0.75),
            ("instart", "Instart WAF", 0.80),
            ("shape", "Shape Security F5", 0.85),
            ("openresty", "OpenResty (possible WAF)", 0.50),
            ("nginx", "Nginx (possible WAF)", 0.30),
        ]
    }

    fn body_signatures() -> Vec<(&'static str, &'static str, f64)> {
        vec![
            ("cloudflare", "Cloudflare", 0.85),
            ("cf-ray", "Cloudflare", 0.90),
            ("cf-cache-status", "Cloudflare", 0.80),
            ("__cfduid", "Cloudflare", 0.85),
            ("attention required! cloudflare", "Cloudflare", 0.95),
            ("ray id", "Cloudflare", 0.75),
            ("incapsula", "Imperva/Incapsula", 0.90),
            ("x-iinfo", "Imperva/Incapsula", 0.85),
            ("visid_incap", "Imperva/Incapsula", 0.90),
            ("incap_ses", "Imperva/Incapsula", 0.90),
            ("akamai", "Akamai", 0.85),
            ("sucuri", "Sucuri CloudProxy", 0.90),
            ("x-sucuri-id", "Sucuri CloudProxy", 0.95),
            ("f5", "F5 BIG-IP ASM", 0.70),
            ("bigip", "F5 BIG-IP ASM", 0.75),
            ("mod_security", "ModSecurity", 0.85),
            ("modsecurity", "ModSecurity", 0.90),
            ("barracuda", "Barracuda WAF", 0.85),
            ("fortinet", "Fortinet FortiWeb", 0.80),
            ("yundun", "Alibaba Cloud WAF", 0.85),
            ("huaweiwaf", "Huawei Cloud WAF", 0.85),
            ("safeline", "SafeLine WAF", 0.85),
            ("nsfocus", "NSFOCUS WAF", 0.85),
            ("knownsec", "KnownSec WAF", 0.85),
            ("jiasule", "Jiasule WAF", 0.80),
            ("dbappsecurity", "DBAppSecurity WAF", 0.85),
            ("access denied", "Generic WAF", 0.60),
            ("forbidden", "Generic WAF", 0.40),
            ("blocked", "Generic WAF", 0.50),
            ("firewall", "Generic WAF", 0.60),
            ("waf", "Generic WAF", 0.70),
            ("request rejected", "Generic WAF", 0.70),
            ("security policy", "Generic WAF", 0.65),
            ("not acceptable", "Generic WAF", 0.40),
            ("your ip has been blocked", "Generic WAF", 0.80),
            ("unauthorized access", "Generic WAF", 0.55),
            ("request not allowed", "Generic WAF", 0.65),
            ("web application firewall", "Generic WAF", 0.90),
            ("attack detected", "Generic WAF", 0.80),
            ("malicious request", "Generic WAF", 0.75),
            ("security event", "Generic WAF", 0.60),
            ("violation", "Generic WAF", 0.55),
            ("protected by", "Generic WAF", 0.70),
            ("powered by", "Generic WAF", 0.50),
        ]
    }

    fn header_signatures() -> Vec<(&'static str, &'static str, f64)> {
        vec![
            ("x-sucuri-id", "Sucuri CloudProxy", 0.95),
            ("x-iinfo", "Imperva/Incapsula", 0.90),
            ("x-cdn", "CDN-based WAF", 0.60),
            ("x-waf", "Generic WAF", 0.90),
            ("x-firewall", "Generic WAF", 0.85),
            ("x-protected-by", "Generic WAF", 0.80),
            ("cf-ray", "Cloudflare", 0.85),
            ("x-cache", "CDN-based WAF", 0.40),
            ("x-nc", "NetScaler WAF", 0.80),
            ("x-akamai-transformed", "Akamai", 0.90),
            ("x-amz-cf-id", "AWS CloudFront WAF", 0.75),
            ("x-fastly-request-id", "Fastly WAF", 0.70),
            ("x-sucuri-cache", "Sucuri CloudProxy", 0.85),
            ("x-incap_ses", "Imperva/Incapsula", 0.90),
            ("x-ua-compatible", "Imperva/Incapsula", 0.50),
            ("x-content-type-options", "Security Header", 0.20),
            ("server-timing", "CDN-based WAF", 0.30),
        ]
    }

    fn cookie_signatures() -> Vec<(&'static str, &'static str, f64, &'static str)> {
        vec![
            ("__cfduid", "Cloudflare", 0.90, "Cloudflare tracking cookie"),
            ("cf_clearance", "Cloudflare", 0.95, "Cloudflare challenge clearance"),
            ("__cflb", "Cloudflare", 0.85, "Cloudflare load balancer"),
            ("visid_incap", "Imperva/Incapsula", 0.90, "Incapsula session cookie"),
            ("incap_ses", "Imperva/Incapsula", 0.90, "Incapsula session cookie"),
            ("nlbi_.*", "Imperva/Incapsula", 0.85, "Incapsula load balancer cookie"),
            ("sucuri_cloudproxy_uuid", "Sucuri CloudProxy", 0.95, "Sucuri tracking cookie"),
            ("X-Mapping-.*", "FirePass/F5", 0.80, "F5 load balancer cookie"),
            ("BigIPCookie", "F5 BIG-IP", 0.85, "F5 BIG-IP persistence cookie"),
            ("TS[a-z0-9]*", "Akamai", 0.75, "Akamai session cookie"),
            ("akamai_session", "Akamai", 0.90, "Akamai session cookie"),
            ("AWSALB", "AWS ALB/WAF", 0.70, "AWS load balancer cookie"),
            ("AWSALBCORS", "AWS ALB/WAF", 0.70, "AWS load balancer CORS cookie"),
            ("stssessioncookie", "Sangfor", 0.80, "Sangfor session cookie"),
            ("safeline", "SafeLine WAF", 0.85, "SafeLine tracking cookie"),
        ]
    }

    fn attack_payloads() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("?id=1' OR '1'='1", "SQL Injection", "sqli"),
            ("?id=1 AND 1=1--", "SQL Injection", "sqli"),
            ("?id=1 UNION SELECT 1,2,3--", "SQL Injection", "sqli"),
            ("?id=1' UNION SELECT NULL,NULL,NULL--", "SQL Injection", "sqli"),
            ("?id=1; DROP TABLE users--", "SQL Injection", "sqli"),
            ("?id=<script>alert(1)</script>", "XSS", "xss"),
            ("?id=<img src=x onerror=alert(1)>", "XSS", "xss"),
            ("?id=<svg/onload=alert(1)>", "XSS", "xss"),
            ("?id=javascript:alert(1)", "XSS", "xss"),
            ("?file=../../etc/passwd", "Path Traversal", "lfi"),
            ("?file=....//....//etc/passwd", "Path Traversal", "lfi"),
            ("?page=../../../../etc/passwd%00", "Null Byte Injection", "lfi"),
            ("?cmd=ls;cat+/etc/passwd", "Command Injection", "cmdi"),
            ("?cmd=|id", "Command Injection", "cmdi"),
            ("?cmd=`whoami`", "Command Injection", "cmdi"),
            ("?id={{7*7}}", "SSTI", "ssti"),
            ("?id=<%=7*7%>", "SSTI", "ssti"),
            ("?id=${7*7}", "SSTI", "ssti"),
            ("?proto[]=test", "Prototype Pollution", "proto"),
            ("?constructor.prototype.test=test", "Prototype Pollution", "proto"),
            ("?id=..%252f..%252f..%252fetc/passwd", "Double Encoding", "evasion"),
            ("?id=%00<script>alert(1)</script>", "Null Byte XSS", "evasion"),
        ]
    }

    fn bypass_suggestions(waf_name: &str) -> Vec<BypassSuggestion> {
        let mut suggestions = Vec::new();

        let generic = vec![
            BypassSuggestion {
                technique: "Header Manipulation".to_string(),
                description: "Modify User-Agent, Referer, X-Forwarded-For and other headers to appear as legitimate traffic".to_string(),
                difficulty: "low".to_string(),
                effectiveness: "medium".to_string(),
            },
            BypassSuggestion {
                technique: "Payload Encoding".to_string(),
                description: "Use URL encoding, double encoding, Unicode encoding or HTML entity encoding to bypass pattern matching".to_string(),
                difficulty: "low".to_string(),
                effectiveness: "high".to_string(),
            },
            BypassSuggestion {
                technique: "HTTP Method Switching".to_string(),
                description: "Try using different HTTP methods (POST, PUT, PATCH) as some WAFs only inspect GET requests".to_string(),
                difficulty: "low".to_string(),
                effectiveness: "medium".to_string(),
            },
            BypassSuggestion {
                technique: "Content-Type Manipulation".to_string(),
                description: "Change Content-Type header (e.g., multipart/form-data, application/json) to bypass body inspection".to_string(),
                difficulty: "medium".to_string(),
                effectiveness: "medium".to_string(),
            },
            BypassSuggestion {
                technique: "Chunked Transfer Encoding".to_string(),
                description: "Use chunked transfer encoding to split payloads across multiple chunks".to_string(),
                difficulty: "medium".to_string(),
                effectiveness: "medium".to_string(),
            },
            BypassSuggestion {
                technique: "Rate Limiting Avoidance".to_string(),
                description: "Add delays between requests, use proxy rotation, or distribute requests across IP ranges".to_string(),
                difficulty: "medium".to_string(),
                effectiveness: "high".to_string(),
            },
        ];

        let waf_lower = waf_name.to_lowercase();

        if waf_lower.contains("cloudflare") {
            suggestions.push(BypassSuggestion {
                technique: "Cloudflare Bypass".to_string(),
                description: "Use origin IP discovery, DNS history lookup, or SSL certificate search to find the real server IP behind Cloudflare".to_string(),
                difficulty: "high".to_string(),
                effectiveness: "high".to_string(),
            });
            suggestions.push(BypassSuggestion {
                technique: "Challenge Solving".to_string(),
                description: "Use headless browsers (Puppeteer/Playwright) to solve JavaScript challenges automatically".to_string(),
                difficulty: "medium".to_string(),
                effectiveness: "high".to_string(),
            });
        } else if waf_lower.contains("imperva") || waf_lower.contains("incapsula") {
            suggestions.push(BypassSuggestion {
                technique: "Incapsula Bypass".to_string(),
                description: "Find origin IP through DNS history, subdomain enumeration, or SSL certificate transparency logs".to_string(),
                difficulty: "high".to_string(),
                effectiveness: "high".to_string(),
            });
            suggestions.push(BypassSuggestion {
                technique: "Cookie Manipulation".to_string(),
                description: "Analyze and forge Incapsula session cookies (visid_incap, incap_ses) to bypass challenge pages".to_string(),
                difficulty: "high".to_string(),
                effectiveness: "medium".to_string(),
            });
        } else if waf_lower.contains("akamai") {
            suggestions.push(BypassSuggestion {
                technique: "Akamai Bypass".to_string(),
                description: "Reverse engineer Akamai sensor data script and generate valid sensor data tokens".to_string(),
                difficulty: "very_high".to_string(),
                effectiveness: "high".to_string(),
            });
        } else if waf_lower.contains("modsecurity") {
            suggestions.push(BypassSuggestion {
                technique: "ModSecurity Rule Evasion".to_string(),
                description: "Exploit known CRS rule bypass techniques: HTTP parameter pollution, JSON/XML content type, comments in SQL".to_string(),
                difficulty: "medium".to_string(),
                effectiveness: "high".to_string(),
            });
        } else if waf_lower.contains("safeline") {
            suggestions.push(BypassSuggestion {
                technique: "SafeLine Bypass".to_string(),
                description: "Try semantic-based evasion: use equivalent SQL/XSS expressions that bypass the semantic analysis engine".to_string(),
                difficulty: "high".to_string(),
                effectiveness: "medium".to_string(),
            });
        }

        suggestions.extend(generic);
        suggestions
    }
}

pub struct WafDetectorTool;

impl WafDetectorTool {
    pub async fn detect(config: &WafConfig) -> Result<WafDetectionResult> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let mut indicators: Vec<WafIndicator> = Vec::new();
        let mut blocked_payloads: Vec<BlockedPayload> = Vec::new();
        let mut cookie_indicators: Vec<CookieIndicator> = Vec::new();

        let client = Self::build_client(config)?;

        let baseline = match Self::fetch_baseline(&client, &target_url).await {
            Ok(b) => b,
            Err(e) => {
                return Ok(WafDetectionResult {
                    url: target_url,
                    waf_detected: false,
                    waf_name: None,
                    confidence: 0.0,
                    grade: "F".to_string(),
                    indicators: vec![WafIndicator {
                        indicator_type: "connection_error".to_string(),
                        category: "error".to_string(),
                        description: format!("Connection failed: {}", e),
                        value: "error".to_string(),
                        confidence: 0.0,
                        severity: "critical".to_string(),
                    }],
                    blocked_payloads: vec![],
                    cookie_indicators: vec![],
                    response_analysis: ResponseAnalysis {
                        status_code: 0,
                        server_header: None,
                        content_length: None,
                        has_captcha: false,
                        has_challenge_page: false,
                        redirect_url: None,
                        response_time_ms: 0,
                        content_type: None,
                        x_powered_by: None,
                        interesting_headers: vec![],
                    },
                    bypass_suggestions: vec![],
                    severity_stats: SeverityStats { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
                    category_stats: vec![],
                    summary: format!("Connection failed: {}", e),
                    scan_duration_ms: start.elapsed().as_millis() as u64,
                });
            }
        };

        Self::check_server_header(&baseline, &mut indicators);
        Self::check_response_body(&baseline, &mut indicators);
        Self::check_response_headers(&baseline, &mut indicators);

        if config.check_cookies {
            Self::check_cookies(&baseline, &mut cookie_indicators, &mut indicators);
        }

        Self::check_challenge_pages(&baseline, &mut indicators);

        if config.check_response_behavior {
            Self::send_attack_payloads(&client, &target_url, &baseline, config.max_concurrent_payloads, &mut indicators, &mut blocked_payloads).await;
        }

        if config.aggressive_mode {
            Self::aggressive_checks(&client, &target_url, &baseline, &mut indicators, &mut blocked_payloads).await;
        }

        let (waf_detected, waf_name, confidence) = Self::analyze_indicators(&indicators, &cookie_indicators);

        let grade = Self::calculate_grade(confidence);

        let bypass_suggestions = if waf_detected {
            let name = waf_name.as_deref().unwrap_or("Generic WAF");
            WafSignatureDb::bypass_suggestions(name)
        } else {
            vec![]
        };

        let severity_stats = Self::calculate_severity_stats(&indicators);
        let category_stats = Self::calculate_category_stats(&indicators);

        let interesting_headers: Vec<String> = baseline.headers.iter()
            .filter_map(|(k, v)| {
                let name = k.as_str().to_lowercase();
                if name.starts_with("x-") || name == "server" || name.contains("waf") || name.contains("firewall") || name.contains("cdn") {
                    Some(format!("{}: {}", k, v.to_str().unwrap_or("?")))
                } else {
                    None
                }
            })
            .collect();

        let summary = if waf_detected {
            if let Some(ref name) = waf_name {
                format!("WAF detected: {} (confidence: {:.0}%, grade: {})", name, confidence * 100.0, grade)
            } else {
                format!("WAF detected (confidence: {:.0}%, grade: {})", confidence * 100.0, grade)
            }
        } else {
            "No WAF detected - the target appears to be unprotected".to_string()
        };

        Ok(WafDetectionResult {
            url: target_url,
            waf_detected,
            waf_name,
            confidence,
            grade,
            indicators,
            blocked_payloads,
            cookie_indicators,
            response_analysis: ResponseAnalysis {
                status_code: baseline.status,
                server_header: baseline.server,
                content_length: baseline.content_length,
                has_captcha: baseline.body.to_lowercase().contains("captcha") ||
                    baseline.body.to_lowercase().contains("recaptcha") ||
                    baseline.body.to_lowercase().contains("hcaptcha") ||
                    baseline.body.to_lowercase().contains("turnstile"),
                has_challenge_page: baseline.body.to_lowercase().contains("challenge") ||
                    baseline.body.to_lowercase().contains("checking your browser") ||
                    baseline.body.to_lowercase().contains("js-challenge"),
                redirect_url: baseline.redirect_url,
                response_time_ms: baseline.time_ms,
                content_type: baseline.content_type,
                x_powered_by: baseline.x_powered_by,
                interesting_headers,
            },
            bypass_suggestions,
            severity_stats,
            category_stats,
            summary,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub async fn detect_simple(url: &str, timeout: Option<u64>) -> Result<WafDetectionResult> {
        let mut config = WafConfig { url: url.to_string(), ..Default::default() };
        if let Some(t) = timeout {
            config.timeout = t;
        }
        Self::detect(&config).await
    }

    fn build_client(config: &WafConfig) -> Result<Client> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(5)
            } else {
                reqwest::redirect::Policy::none()
            });

        if !config.verify_ssl {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref ua) = config.user_agent {
            builder = builder.user_agent(ua.as_str());
        } else {
            builder = builder.user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        }

        if let Some(ref proxy) = config.proxy_url {
            if !proxy.is_empty() {
                let proxy = reqwest::Proxy::all(proxy.as_str())
                    .map_err(|e| ToolError::ExecutionError(format!("Invalid proxy URL: {}", e)))?;
                builder = builder.proxy(proxy);
            }
        }

        builder.build()
            .map_err(|e| ToolError::ExecutionError(format!("Failed to create HTTP client: {}", e)))
    }

    fn check_server_header(baseline: &BaselineInfo, indicators: &mut Vec<WafIndicator>) {
        if let Some(ref server) = baseline.server {
            let server_lower = server.to_lowercase();
            for (sig, name, conf) in WafSignatureDb::server_signatures() {
                if server_lower.contains(sig) {
                    let severity = if conf >= 0.9 { "high" } else if conf >= 0.7 { "medium" } else { "low" };
                    indicators.push(WafIndicator {
                        indicator_type: "server_header".to_string(),
                        category: "header_analysis".to_string(),
                        description: format!("Server header contains WAF signature: {}", server),
                        value: name.to_string(),
                        confidence: conf,
                        severity: severity.to_string(),
                    });
                }
            }
        }
    }

    fn check_response_body(baseline: &BaselineInfo, indicators: &mut Vec<WafIndicator>) {
        let body_lower = baseline.body.to_lowercase();
        for (sig, name, conf) in WafSignatureDb::body_signatures() {
            if body_lower.contains(sig) {
                let severity = if conf >= 0.9 { "high" } else if conf >= 0.7 { "medium" } else { "low" };
                indicators.push(WafIndicator {
                    indicator_type: "response_body".to_string(),
                    category: "body_analysis".to_string(),
                    description: format!("Response body contains WAF signature: {}", sig),
                    value: name.to_string(),
                    confidence: conf,
                    severity: severity.to_string(),
                });
            }
        }
    }

    fn check_response_headers(baseline: &BaselineInfo, indicators: &mut Vec<WafIndicator>) {
        for (header_name, waf_name, conf) in WafSignatureDb::header_signatures() {
            if baseline.headers.get(header_name).is_some() {
                let severity = if conf >= 0.9 { "high" } else if conf >= 0.7 { "medium" } else { "low" };
                indicators.push(WafIndicator {
                    indicator_type: "response_header".to_string(),
                    category: "header_analysis".to_string(),
                    description: format!("Response header '{}' present", header_name),
                    value: waf_name.to_string(),
                    confidence: conf,
                    severity: severity.to_string(),
                });
            }
        }
    }

    fn check_cookies(baseline: &BaselineInfo, cookie_indicators: &mut Vec<CookieIndicator>, indicators: &mut Vec<WafIndicator>) {
        for (cookie_name, _value) in &baseline.cookies {
            let cookie_lower = cookie_name.to_lowercase();
            for (sig, waf_name, conf, desc) in WafSignatureDb::cookie_signatures() {
                let sig_lower = sig.to_lowercase();
                let is_match = if sig.contains(".*") {
                    let prefix = sig.replace(".*", "").to_lowercase();
                    cookie_lower.starts_with(&prefix)
                } else {
                    cookie_lower == sig_lower || cookie_lower.contains(&sig_lower)
                };

                if is_match {
                    cookie_indicators.push(CookieIndicator {
                        name: cookie_name.clone(),
                        waf_name: waf_name.to_string(),
                        confidence: conf,
                        description: desc.to_string(),
                    });

                    let severity = if conf >= 0.9 { "high" } else if conf >= 0.7 { "medium" } else { "low" };
                    indicators.push(WafIndicator {
                        indicator_type: "cookie".to_string(),
                        category: "cookie_analysis".to_string(),
                        description: format!("WAF-related cookie detected: {} ({})", cookie_name, desc),
                        value: waf_name.to_string(),
                        confidence: conf,
                        severity: severity.to_string(),
                    });
                }
            }
        }
    }

    fn check_challenge_pages(baseline: &BaselineInfo, indicators: &mut Vec<WafIndicator>) {
        let body_lower = baseline.body.to_lowercase();

        if body_lower.contains("captcha") || body_lower.contains("recaptcha") ||
            body_lower.contains("hcaptcha") || body_lower.contains("turnstile") {
            indicators.push(WafIndicator {
                indicator_type: "captcha".to_string(),
                category: "behavior_analysis".to_string(),
                description: "Response contains CAPTCHA challenge".to_string(),
                value: "captcha_detected".to_string(),
                confidence: 0.80,
                severity: "high".to_string(),
            });
        }

        if body_lower.contains("challenge") ||
            body_lower.contains("checking your browser") ||
            body_lower.contains("please wait") ||
            body_lower.contains("js-challenge") ||
            body_lower.contains("ray id") {
            indicators.push(WafIndicator {
                indicator_type: "challenge_page".to_string(),
                category: "behavior_analysis".to_string(),
                description: "Response contains browser challenge page".to_string(),
                value: "challenge_detected".to_string(),
                confidence: 0.75,
                severity: "high".to_string(),
            });
        }

        if baseline.status == 403 || baseline.status == 406 || baseline.status == 429 || baseline.status == 503 {
            indicators.push(WafIndicator {
                indicator_type: "status_code".to_string(),
                category: "behavior_analysis".to_string(),
                description: format!("Baseline request returned suspicious status code: {}", baseline.status),
                value: "suspicious_status".to_string(),
                confidence: 0.50,
                severity: "medium".to_string(),
            });
        }
    }

    async fn send_attack_payloads(
        client: &Client,
        target_url: &str,
        baseline: &BaselineInfo,
        max_concurrent: usize,
        indicators: &mut Vec<WafIndicator>,
        blocked_payloads: &mut Vec<BlockedPayload>,
    ) {
        let mut payload_join_set = tokio::task::JoinSet::new();
        let payload_semaphore = Arc::new(Semaphore::new(max_concurrent));

        for (payload, attack_type, category) in WafSignatureDb::attack_payloads() {
            let test_url = format!("{}{}", target_url, payload);
            let client = client.clone();
            let payload = payload.to_string();
            let attack_type = attack_type.to_string();
            let category = category.to_string();
            let baseline_status = baseline.status;
            let baseline_content_length = baseline.content_length.unwrap_or(0);
            let payload_semaphore = payload_semaphore.clone();

            payload_join_set.spawn(async move {
                let _permit = payload_semaphore.acquire().await.unwrap();
                match client.get(&test_url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        let body_lower = body.to_lowercase();
                        let content_len = body.len() as u64;

                        let is_blocked = if status == 403 || status == 406 || status == 429 || status == 503 {
                            true
                        } else if status == 200 {
                            let blocked_keywords = ["blocked", "denied", "forbidden", "firewall", "waf", "rejected", "not acceptable", "attack detected", "malicious"];
                            blocked_keywords.iter().any(|k| body_lower.contains(k))
                        } else if status != baseline_status {
                            (status as i32 - baseline_status as i32).abs() >= 100
                        } else if baseline_content_length > 0 && content_len > 0 {
                            let diff = (content_len as f64 - baseline_content_length as f64).abs();
                            diff / baseline_content_length as f64 > 0.5
                        } else {
                            false
                        };

                        let block_method = if status == 403 { "403 Forbidden".to_string() }
                            else if status == 406 { "406 Not Acceptable".to_string() }
                            else if status == 429 { "429 Too Many Requests".to_string() }
                            else if status == 503 { "503 Service Unavailable".to_string() }
                            else if status != baseline_status { format!("Status changed: {} -> {}", baseline_status, status) }
                            else { "Body content indicates blocking".to_string() };

                        if is_blocked {
                            let confidence = if status == 403 || status == 406 { 0.90 }
                                else if status == 429 || status == 503 { 0.85 }
                                else if status != baseline_status { 0.75 }
                                else { 0.65 };

                            let severity = if confidence >= 0.85 { "high" } else if confidence >= 0.7 { "medium" } else { "low" };

                            Some((
                                BlockedPayload {
                                    payload,
                                    attack_type: attack_type.clone(),
                                    status_code: status,
                                    blocked: true,
                                    block_method,
                                },
                                WafIndicator {
                                    indicator_type: "payload_blocked".to_string(),
                                    category: format!("payload_{}", category),
                                    description: format!("WAF blocked {} payload with {}", attack_type, status),
                                    value: format!("{}_blocked", category),
                                    confidence,
                                    severity: severity.to_string(),
                                },
                            ))
                        } else {
                            None
                        }
                    }
                    Err(_) => {
                        Some((
                            BlockedPayload {
                                payload,
                                attack_type: attack_type.clone(),
                                status_code: 0,
                                blocked: true,
                                block_method: "Connection refused/blocked".to_string(),
                            },
                            WafIndicator {
                                indicator_type: "payload_connection_refused".to_string(),
                                category: format!("payload_{}", category),
                                description: format!("Connection refused when sending {} payload", attack_type),
                                value: format!("{}_refused", category),
                                confidence: 0.60,
                                severity: "medium".to_string(),
                            },
                        ))
                    }
                }
            });
        }

        while let Some(result) = payload_join_set.join_next().await {
            if let Ok(Some((blocked, indicator))) = result {
                blocked_payloads.push(blocked);
                indicators.push(indicator);
            }
        }
    }

    async fn aggressive_checks(
        client: &Client,
        target_url: &str,
        baseline: &BaselineInfo,
        indicators: &mut Vec<WafIndicator>,
        blocked_payloads: &mut Vec<BlockedPayload>,
    ) {
        let aggressive_payloads = vec![
            ("?id=1'/**/OR/**/1=1--", "SQL Injection (comment bypass)", "sqli"),
            ("?id=1%27%20OR%20%271%27=%271", "SQL Injection (URL encoded)", "sqli"),
            ("?id=<ScRiPt>alert(1)</ScRiPt>", "XSS (case variation)", "xss"),
            ("?id=<img/src=x onerror=alert(1)>", "XSS (tag variation)", "xss"),
            ("?id=%3Cscript%3Ealert(1)%3C/script%3E", "XSS (full URL encoded)", "xss"),
        ];

        let semaphore = Arc::new(Semaphore::new(3));
        let mut join_set = tokio::task::JoinSet::new();

        for (payload, attack_type, category) in aggressive_payloads {
            let test_url = format!("{}{}", target_url, payload);
            let client = client.clone();
            let payload = payload.to_string();
            let attack_type = attack_type.to_string();
            let category = category.to_string();
            let baseline_status = baseline.status;
            let semaphore = semaphore.clone();

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                match client.get(&test_url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let is_blocked = status == 403 || status == 406 || status == 429 || status == 503 ||
                            (status != baseline_status && (status as i32 - baseline_status as i32).abs() >= 100);

                        if is_blocked {
                            Some((
                                BlockedPayload {
                                    payload,
                                    attack_type: attack_type.clone(),
                                    status_code: status,
                                    blocked: true,
                                    block_method: format!("Status: {}", status),
                                },
                                WafIndicator {
                                    indicator_type: "aggressive_payload_blocked".to_string(),
                                    category: format!("payload_{}", category),
                                    description: format!("WAF blocked aggressive {} payload", attack_type),
                                    value: format!("aggressive_{}_blocked", category),
                                    confidence: 0.70,
                                    severity: "medium".to_string(),
                                },
                            ))
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some((blocked, indicator))) = result {
                blocked_payloads.push(blocked);
                indicators.push(indicator);
            }
        }
    }

    fn analyze_indicators(indicators: &[WafIndicator], cookie_indicators: &[CookieIndicator]) -> (bool, Option<String>, f64) {
        if indicators.is_empty() && cookie_indicators.is_empty() {
            return (false, None, 0.0);
        }

        let mut waf_scores: HashMap<String, f64> = HashMap::new();

        for indicator in indicators {
            let name = &indicator.value;
            let conf = indicator.confidence;
            let entry = waf_scores.entry(name.clone()).or_insert(0.0);
            *entry += conf;
        }

        for cookie in cookie_indicators {
            let entry = waf_scores.entry(cookie.waf_name.clone()).or_insert(0.0);
            *entry += cookie.confidence * 0.8;
        }

        let mut sorted: Vec<_> = waf_scores.iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

        if sorted.is_empty() {
            return (false, None, 0.0);
        }

        let (best_name, best_score) = sorted[0];

        let total_indicator_count = indicators.len() as f64;
        let unique_categories: std::collections::HashSet<&str> = indicators.iter().map(|i| i.category.as_str()).collect();
        let category_diversity = unique_categories.len() as f64;

        let indicator_ratio = (total_indicator_count / 8.0).min(1.0);
        let category_bonus = (category_diversity / 4.0).min(1.0) * 0.15;

        let combined_confidence = (*best_score * 0.55 + indicator_ratio * 0.30 + category_bonus).min(1.0);

        let detected = combined_confidence >= 0.25;
        let name = if detected {
            Some(best_name.clone())
        } else {
            None
        };

        (detected, name, combined_confidence)
    }

    fn calculate_grade(confidence: f64) -> String {
        if confidence >= 0.9 { "A+".to_string() }
        else if confidence >= 0.8 { "A".to_string() }
        else if confidence >= 0.7 { "B+".to_string() }
        else if confidence >= 0.6 { "B".to_string() }
        else if confidence >= 0.5 { "C+".to_string() }
        else if confidence >= 0.4 { "C".to_string() }
        else if confidence >= 0.3 { "D".to_string() }
        else if confidence >= 0.2 { "E".to_string() }
        else { "F".to_string() }
    }

    fn calculate_severity_stats(indicators: &[WafIndicator]) -> SeverityStats {
        let mut stats = SeverityStats { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for ind in indicators {
            match ind.severity.as_str() {
                "critical" => stats.critical += 1,
                "high" => stats.high += 1,
                "medium" => stats.medium += 1,
                "low" => stats.low += 1,
                _ => stats.info += 1,
            }
        }
        stats
    }

    fn calculate_category_stats(indicators: &[WafIndicator]) -> Vec<CategoryStat> {
        let mut category_map: HashMap<String, (i32, f64)> = HashMap::new();
        for ind in indicators {
            let entry = category_map.entry(ind.category.clone()).or_insert((0, 0.0));
            entry.0 += 1;
            entry.1 = entry.1.max(ind.confidence);
        }

        let mut stats: Vec<CategoryStat> = category_map.into_iter()
            .map(|(category, (count, max_conf))| CategoryStat {
                category,
                count,
                max_confidence: max_conf,
            })
            .collect();

        stats.sort_by(|a, b| b.count.cmp(&a.count));
        stats
    }

    async fn fetch_baseline(client: &Client, url: &str) -> std::result::Result<BaselineInfo, String> {
        let start = Instant::now();
        let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
        let time_ms = start.elapsed().as_millis() as u64;

        let status = resp.status().as_u16();
        let server = resp.headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_length = resp.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let content_type = resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let x_powered_by = resp.headers()
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let redirect_url = if (300..400).contains(&status) {
            resp.headers().get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        let cookies: Vec<(String, String)> = resp.headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| {
                let cookie_str = v.to_str().ok()?;
                let name = cookie_str.split('=').next()?.trim().to_string();
                let value = cookie_str.split(';').next()?.trim().to_string();
                Some((name, value))
            })
            .collect();

        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();

        Ok(BaselineInfo {
            status,
            server,
            content_length,
            body,
            headers,
            redirect_url,
            time_ms,
            content_type,
            x_powered_by,
            cookies,
        })
    }
}
