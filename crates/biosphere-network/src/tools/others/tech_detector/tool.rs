use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::time::Duration;
use reqwest::Client;
use crate::core::{Result, ToolError};
use super::config::*;

fn random_ua() -> String {
    let agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ];
    let idx = rand::Rng::gen_range(&mut rand::thread_rng(), 0..agents.len());
    agents[idx].to_string()
}

pub struct TechDetectorTool;

impl TechDetectorTool {
    pub async fn detect(config: &TechDetectConfig) -> Result<TechDetectResult> {
        let start = std::time::Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let ua = if config.randomize_ua {
            random_ua()
        } else {
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
        };

        let redirect_policy = if config.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(redirect_policy)
            .danger_accept_invalid_certs(true)
            .user_agent(&ua)
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut retries = 2u32;
        let (status, headers, body, response_time_ms, final_url) = loop {
            let req_start = std::time::Instant::now();
            match client.get(&target_url).send().await {
                Ok(resp) => {
                    let s = resp.status().as_u16();
                    let h = resp.headers().clone();
                    let rt = req_start.elapsed().as_millis() as u64;
                    let b = resp.text().await.unwrap_or_default();
                    let fu = target_url.clone();

                    if (s == 429 || s == 503) && retries > 0 {
                        retries -= 1;
                        let wait = if s == 429 {
                            h.get("retry-after")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok())
                                .map(|v| Duration::from_secs(v.min(10)))
                                .unwrap_or_else(|| Duration::from_millis(500 * (3 - retries) as u64))
                        } else {
                            Duration::from_millis(300 * (3 - retries) as u64)
                        };
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    break (s, h, b, rt, fu);
                }
                Err(e) => {
                    return Err(ToolError::ExecutionError(format!("Request failed: {}", e)));
                }
            }
        };

        let body_lower = body.to_lowercase();

        let ip_address = Self::resolve_ip(&target_url).await;

        let mut raw_techs: Vec<DetectedTech> = Vec::new();

        if config.detect_headers {
            Self::detect_from_headers(&headers, &mut raw_techs);
        }

        if config.detect_cookies {
            Self::detect_from_cookies(&headers, &mut raw_techs);
        }

        if config.detect_html {
            Self::detect_from_html(&body, &body_lower, &mut raw_techs);
        }

        if config.detect_js {
            Self::detect_from_js(&body, &body_lower, &mut raw_techs);
        }

        if config.detect_css && config.scan_mode != "quick" {
            Self::detect_from_css(&body, &body_lower, &mut raw_techs);
        }

        if config.detect_meta && config.scan_mode != "quick" {
            Self::detect_from_meta(&body, &body_lower, &mut raw_techs);
        }

        if config.scan_mode == "deep" {
            Self::detect_from_script_src(&body, &mut raw_techs);
            Self::detect_from_link_href(&body, &mut raw_techs);
        }

        let technologies = Self::merge_dedup(raw_techs);

        let mut category_map: HashMap<String, Vec<String>> = HashMap::new();
        for tech in &technologies {
            category_map
                .entry(tech.category.clone())
                .or_default()
                .push(tech.name.clone());
        }

        let categories: Vec<TechCategory> = category_map
            .into_iter()
            .map(|(name, techs)| TechCategory {
                count: techs.len(),
                name,
                techs,
            })
            .collect();

        let ssl_info = if config.collect_ssl_info && target_url.starts_with("https://") {
            Self::collect_ssl_info(&target_url).await
        } else {
            None
        };

        let waf_detected = Self::detect_waf(status, &headers, &body_lower);

        let security_headers = if config.collect_security_headers {
            Some(Self::analyze_security_headers(&headers))
        } else {
            None
        };

        let content_type = headers.get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());

        let server = headers.get("server")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let content_length = headers.get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| {
                let bl = body.len() as u64;
                if bl > 0 { Some(bl) } else { None }
            });

        let redirect_url = if (300..400).contains(&(status as usize)) {
            headers.get("location").and_then(|v| v.to_str().ok()).map(|v| v.to_string())
        } else {
            None
        };

        let response_info = ResponseInfo {
            status_code: status,
            content_type,
            server,
            content_length,
            response_time_ms,
            redirect_url,
            ip_address,
        };

        let summary = if technologies.is_empty() {
            format!("No technologies detected (status: {})", status)
        } else {
            let tech_names: Vec<&str> = technologies.iter().map(|t| t.name.as_str()).collect();
            format!("Detected {} technologies: {}", tech_names.len(), tech_names.join(", "))
        };

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        Ok(TechDetectResult {
            url: final_url,
            technologies,
            categories,
            summary,
            ssl_info,
            waf_detected,
            security_headers,
            response_info,
            scan_duration_ms,
        })
    }

    async fn resolve_ip(url: &str) -> Option<String> {
        let host = url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()?
            .split(':')
            .next()?;

        match (host, 0).to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    return Some(addr.ip().to_string());
                }
                None
            }
            Err(_) => None,
        }
    }

    async fn collect_ssl_info(url: &str) -> Option<SslInfo> {
        let url_owned = url.to_string();
        tokio::task::spawn_blocking(move || {
            let parsed = url::Url::parse(&url_owned).ok()?;
            let host = parsed.host_str()?;
            let port = parsed.port().unwrap_or(443);
            let addr = format!("{}:{}", host, port);

            let stream = std::net::TcpStream::connect_timeout(
                &addr.parse().ok()?,
                std::time::Duration::from_secs(5),
            ).ok()?;

            let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).ok()?;
            builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            let connector = builder.build();

            let ssl_stream = connector.connect(host, stream).ok()?;
            let ssl = ssl_stream.ssl();

            let cert = ssl.peer_certificate()?;
            let subject = cert.subject_name().entries().map(|e| {
                let val = String::from_utf8_lossy(e.data().as_slice()).to_string();
                let obj = e.object().nid();
                format!("{:?}={}", obj, val)
            }).collect::<Vec<_>>().join(", ");
            let issuer = cert.issuer_name().entries().map(|e| {
                let val = String::from_utf8_lossy(e.data().as_slice()).to_string();
                let obj = e.object().nid();
                format!("{:?}={}", obj, val)
            }).collect::<Vec<_>>().join(", ");
            let not_before = cert.not_before().to_string();
            let not_after = cert.not_after().to_string();

            let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
            let is_expired = cert.not_after() < now;

            let version = ssl.version_str().to_string();
            let cipher = ssl.current_cipher().map(|c| c.name().to_string());

            Some(SslInfo {
                subject: Some(subject),
                issuer: Some(issuer),
                valid_from: Some(not_before),
                valid_to: Some(not_after),
                is_expired,
                protocol: Some(version),
                cipher,
                san_domains: vec![],
            })
        }).await.ok()?
    }

    fn detect_waf(status: u16, headers: &reqwest::header::HeaderMap, body_lower: &str) -> Option<WafDetection> {
        let mut evidence: Vec<String> = Vec::new();
        let mut waf_name: Option<String> = None;

        if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
            let s = server.to_lowercase();
            if s.contains("cloudflare") {
                waf_name = Some("Cloudflare".to_string());
                evidence.push(format!("Server: {}", server));
            }
            if s.contains("sucuri") {
                waf_name = Some("Sucuri".to_string());
                evidence.push(format!("Server: {}", server));
            }
            if s.contains("imperva") || s.contains("incapsula") {
                waf_name = Some("Imperva/Incapsula".to_string());
                evidence.push(format!("Server: {}", server));
            }
            if s.contains("akamai") {
                waf_name = Some("Akamai".to_string());
                evidence.push(format!("Server: {}", server));
            }
        }

        if headers.get("cf-ray").is_some() {
            if waf_name.is_none() {
                waf_name = Some("Cloudflare".to_string());
            }
            evidence.push("Header: cf-ray".to_string());
        }
        if headers.get("x-sucuri-id").is_some() {
            waf_name = Some("Sucuri".to_string());
            evidence.push("Header: x-sucuri-id".to_string());
        }
        if headers.get("x-iinfo").is_some() || headers.get("x-cdn").is_some() {
            if waf_name.is_none() {
                waf_name = Some("Incapsula".to_string());
            }
            evidence.push("Header: x-iinfo/x-cdn".to_string());
        }
        if headers.get("x-akamai-transformed").is_some() {
            waf_name = Some("Akamai".to_string());
            evidence.push("Header: x-akamai-transformed".to_string());
        }
        if headers.get("x-waf-event-info").is_some() {
            if waf_name.is_none() {
                waf_name = Some("AWS WAF".to_string());
            }
            evidence.push("Header: x-waf-event-info".to_string());
        }

        if status == 403 {
            if body_lower.contains("cloudflare") {
                waf_name = Some("Cloudflare".to_string());
                evidence.push("403 + body: cloudflare".to_string());
            } else if body_lower.contains("sucuri") {
                waf_name = Some("Sucuri".to_string());
                evidence.push("403 + body: sucuri".to_string());
            } else if body_lower.contains("incapsula") {
                waf_name = Some("Incapsula".to_string());
                evidence.push("403 + body: incapsula".to_string());
            } else if body_lower.contains("access denied") || body_lower.contains("forbidden") {
                if waf_name.is_none() {
                    waf_name = Some("Generic WAF".to_string());
                }
                evidence.push("403 + body: access denied/forbidden".to_string());
            }
        }

        if status == 429 {
            if waf_name.is_none() {
                waf_name = Some("Rate Limiting WAF".to_string());
            }
            evidence.push("429 Too Many Requests".to_string());
        }

        if body_lower.contains("request rejected") && body_lower.contains("mod_security") {
            waf_name = Some("ModSecurity".to_string());
            evidence.push("Body: ModSecurity".to_string());
        }

        if waf_name.is_some() {
            Some(WafDetection {
                detected: true,
                waf_name,
                evidence,
            })
        } else {
            None
        }
    }

    fn analyze_security_headers(headers: &reqwest::header::HeaderMap) -> SecurityHeaderResult {
        let checks: Vec<(&str, &str, &str)> = vec![
            ("strict-transport-security", "high", "Enforce HTTPS connections"),
            ("content-security-policy", "high", "Prevent XSS and data injection"),
            ("x-content-type-options", "medium", "Prevent MIME type sniffing"),
            ("x-frame-options", "medium", "Prevent clickjacking"),
            ("x-xss-protection", "low", "Enable browser XSS filter (legacy)"),
            ("referrer-policy", "low", "Control referrer information leakage"),
            ("permissions-policy", "low", "Control browser feature access"),
            ("cross-origin-opener-policy", "medium", "Isolate browsing context"),
            ("cross-origin-resource-policy", "medium", "Prevent cross-origin resource theft"),
            ("cross-origin-embedder-policy", "medium", "Control cross-origin embedding"),
        ];

        let mut entries: Vec<SecurityHeaderEntry> = Vec::new();
        let mut score: u8 = 0;
        let total = checks.len() as u8;

        for (name, severity, recommendation) in &checks {
            let present = headers.get(*name).is_some();
            let value = headers.get(*name).and_then(|v| v.to_str().ok()).map(|v| v.to_string());

            if present {
                match *severity {
                    "high" => score += 3,
                    "medium" => score += 2,
                    "low" => score += 1,
                    _ => {}
                }
            }

            entries.push(SecurityHeaderEntry {
                name: name.to_string(),
                present,
                value,
                recommendation: recommendation.to_string(),
                severity: severity.to_string(),
            });
        }

        let max_score = total * 3;
        let percentage = (score as f64 / max_score as f64 * 100.0) as u8;
        let grade = if percentage >= 90 {
            "A".to_string()
        } else if percentage >= 75 {
            "B".to_string()
        } else if percentage >= 55 {
            "C".to_string()
        } else if percentage >= 35 {
            "D".to_string()
        } else {
            "F".to_string()
        };

        SecurityHeaderResult {
            headers: entries,
            score: percentage,
            grade,
        }
    }

    fn merge_dedup(raw_techs: Vec<DetectedTech>) -> Vec<DetectedTech> {
        let mut merged: HashMap<String, DetectedTech> = HashMap::new();

        for tech in raw_techs {
            let base_name = tech.name.split_whitespace().next().unwrap_or(&tech.name).to_string();
            let key = format!("{}::{}", base_name.to_lowercase(), tech.category.to_lowercase());

            merged.entry(key)
                .and_modify(|existing| {
                    if tech.confidence > existing.confidence {
                        existing.confidence = tech.confidence;
                    }
                    if tech.version.is_some() && existing.version.is_none() {
                        existing.version = tech.version.clone();
                    }
                    if !existing.detail.contains(&tech.detail) {
                        existing.detail = format!("{}; {}", existing.detail, tech.detail);
                    }
                    let methods: Vec<&str> = existing.detection_method.split(", ").collect();
                    if !methods.contains(&tech.detection_method.as_str()) {
                        existing.detection_method = format!("{}, {}", existing.detection_method, tech.detection_method);
                    }
                })
                .or_insert(tech);
        }

        let mut result: Vec<DetectedTech> = merged.into_values().collect();
        result.sort_by(|a, b| {
            b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        result
    }

    fn extract_version(text: &str, keyword: &str) -> Option<String> {
        let p1 = format!(r"(?i){}[/\s-]v?(\d+(?:\.\d+)+(?:[\w.-]*)?)", keyword);
        let p2 = format!(r"(?i){}[/\s-](\d+(?:\.\d+)+(?:[\w.-]*)?)", keyword);
        let p3 = format!(r"(?i){}\s*v?(\d+(?:\.\d+)+)", keyword);
        let patterns = [&p1, &p2, &p3];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(m) = caps.get(1) {
                        let v = m.as_str().to_string();
                        if v.len() < 20 && v.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                            return Some(v);
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_version_for_tech(lower: &str, _original: &str, tech_name: &str) -> Option<String> {
        let keyword = tech_name.to_lowercase();
        Self::extract_version(lower, &keyword)
    }

    fn detect_from_headers(headers: &reqwest::header::HeaderMap, techs: &mut Vec<DetectedTech>) {
        let header_signatures: Vec<(&str, &str, &str, f64)> = vec![
            ("server", "apache", "Web Server", 0.90),
            ("server", "nginx", "Web Server", 0.90),
            ("server", "microsoft-iis", "Web Server", 0.95),
            ("server", "litespeed", "Web Server", 0.95),
            ("server", "caddy", "Web Server", 0.95),
            ("server", "openresty", "Web Server", 0.90),
            ("server", "cloudflare", "CDN", 0.90),
            ("server", "amazons3", "Hosting", 0.95),
            ("server", "gws", "Web Server", 0.85),
            ("server", "cowboy", "Web Server", 0.90),
            ("server", "jetty", "Web Server", 0.85),
            ("server", "tomcat", "Web Server", 0.85),
            ("x-powered-by", "php", "Programming Language", 0.95),
            ("x-powered-by", "asp.net", "Framework", 0.95),
            ("x-powered-by", "express", "Framework", 0.95),
            ("x-powered-by", "next", "Framework", 0.90),
            ("x-powered-by", "nuxt", "Framework", 0.90),
            ("x-powered-by", "rails", "Framework", 0.90),
            ("x-powered-by", "laravel", "Framework", 0.85),
            ("x-aspnet-version", "", "Framework", 0.95),
            ("x-drupal-cache", "", "CMS", 0.90),
            ("x-generator", "drupal", "CMS", 0.90),
            ("x-generator", "hugo", "Static Site Generator", 0.90),
            ("x-generator", "joomla", "CMS", 0.90),
            ("x-varnish", "", "Cache", 0.85),
            ("x-squid-error", "", "Cache", 0.85),
            ("x-amz-cf-id", "", "CDN", 0.90),
            ("x-fastly-request-id", "", "CDN", 0.90),
            ("x-vercel-id", "", "Hosting", 0.95),
            ("x-vercel-cache", "", "Hosting", 0.90),
            ("x-netlify-request-id", "", "Hosting", 0.90),
            ("x-firebase-locale", "", "Hosting", 0.85),
            ("x-hubspot", "", "Marketing", 0.90),
            ("cf-ray", "", "CDN", 0.90),
            ("x-request-id", "", "Miscellaneous", 0.30),
        ];

        for (header_name, keyword, category, confidence) in &header_signatures {
            if let Some(value) = headers.get(*header_name) {
                if let Ok(v) = value.to_str() {
                    let v_lower = v.to_lowercase();
                    if keyword.is_empty() || v_lower.contains(keyword) {
                        let display_name = if keyword.is_empty() {
                            let display = header_name.trim_start_matches("x-")
                                .split('-')
                                .next()
                                .unwrap_or(header_name);
                            let first: String = display.chars().next().unwrap().to_uppercase().collect();
                            first + &display[1..]
                        } else {
                            let base = keyword.chars().next().unwrap().to_uppercase().collect::<String>()
                                + &keyword[1..];
                            base
                        };

                        let version = if !keyword.is_empty() {
                            Self::extract_version(&v_lower, keyword)
                        } else {
                            None
                        };

                        let name = match &version {
                            Some(ver) => format!("{} {}", display_name, ver),
                            None => display_name,
                        };

                        techs.push(DetectedTech {
                            name,
                            category: category.to_string(),
                            confidence: *confidence,
                            version,
                            detection_method: "HTTP Header".to_string(),
                            detail: format!("{}: {}", header_name, v),
                        });
                    }
                }
            }
        }
    }

    fn detect_from_cookies(headers: &reqwest::header::HeaderMap, techs: &mut Vec<DetectedTech>) {
        let cookie_signatures: Vec<(&str, &str, &str, f64)> = vec![
            ("phpsessid", "PHP", "Programming Language", 0.90),
            ("asp.net_sessionid", "ASP.NET", "Framework", 0.95),
            ("aspnetsessionid", "ASP.NET", "Framework", 0.90),
            ("jsessionid", "Java", "Programming Language", 0.85),
            ("cf_clearance", "Cloudflare", "CDN", 0.95),
            ("__cfduid", "Cloudflare", "CDN", 0.95),
            ("_ga", "Google Analytics", "Analytics", 0.90),
            ("_gid", "Google Analytics", "Analytics", 0.90),
            ("_gat", "Google Analytics", "Analytics", 0.90),
            ("_fbp", "Facebook Pixel", "Analytics", 0.90),
            ("_fbc", "Facebook Pixel", "Analytics", 0.85),
            ("hubspotutk", "HubSpot", "Marketing", 0.95),
            ("intercom-id", "Intercom", "Customer Support", 0.95),
            ("mp_", "Mixpanel", "Analytics", 0.85),
            ("ajs_user_id", "Segment", "Analytics", 0.90),
            ("ajs_anonymous_id", "Segment", "Analytics", 0.90),
            ("laravel_session", "Laravel", "Framework", 0.95),
            ("xsrf-token", "Laravel", "Framework", 0.70),
            ("django_language", "Django", "Framework", 0.90),
            ("csrftoken", "Django", "Framework", 0.70),
            ("sessionid", "Django", "Framework", 0.60),
            ("wp-settings-", "WordPress", "CMS", 0.90),
            ("wordpress_logged_in", "WordPress", "CMS", 0.95),
            ("drupal_session", "Drupal", "CMS", 0.90),
            ("ssess", "Drupal", "CMS", 0.80),
            ("shopify_s", "Shopify", "E-commerce", 0.95),
            ("_shopify_s", "Shopify", "E-commerce", 0.95),
            ("_shopify_y", "Shopify", "E-commerce", 0.90),
            ("magento_", "Magento", "E-commerce", 0.90),
            ("stripe_mid", "Stripe", "Payment", 0.85),
        ];

        if let Some(cookie_header) = headers.get("set-cookie") {
            if let Ok(cookies) = cookie_header.to_str() {
                let cookies_lower = cookies.to_lowercase();
                for (cookie_name, tech_name, category, confidence) in &cookie_signatures {
                    if cookies_lower.contains(cookie_name) {
                        techs.push(DetectedTech {
                            name: tech_name.to_string(),
                            category: category.to_string(),
                            confidence: *confidence,
                            version: None,
                            detection_method: "Cookie".to_string(),
                            detail: format!("Cookie: {}", cookie_name),
                        });
                    }
                }
            }
        }
    }

    fn detect_from_html(html: &str, html_lower: &str, techs: &mut Vec<DetectedTech>) {
        let html_signatures: Vec<(&str, &str, &str, f64)> = vec![
            ("wp-content", "WordPress", "CMS", 0.90),
            ("wp-includes", "WordPress", "CMS", 0.90),
            ("wordpress", "WordPress", "CMS", 0.80),
            ("drupal.js", "Drupal", "CMS", 0.90),
            ("drupal", "Drupal", "CMS", 0.70),
            ("sites/default/files", "Drupal", "CMS", 0.85),
            ("joomla", "Joomla", "CMS", 0.85),
            ("/media/jui/", "Joomla", "CMS", 0.85),
            ("shopify", "Shopify", "E-commerce", 0.80),
            ("cdn.shopify.com", "Shopify", "E-commerce", 0.95),
            ("magento", "Magento", "E-commerce", 0.80),
            ("skin/frontend", "Magento", "E-commerce", 0.85),
            ("media/catalog", "Magento", "E-commerce", 0.80),
            ("__next", "Next.js", "Framework", 0.90),
            ("_next/static", "Next.js", "Framework", 0.95),
            ("next-route-announcer", "Next.js", "Framework", 0.95),
            ("__nuxt", "Nuxt.js", "Framework", 0.90),
            ("_nuxt/", "Nuxt.js", "Framework", 0.95),
            ("ng-version", "Angular", "Framework", 0.95),
            ("ng-app", "Angular", "Framework", 0.90),
            ("__react", "React", "Framework", 0.80),
            ("data-reactroot", "React", "Framework", 0.85),
            ("data-v-", "Vue.js", "Framework", 0.85),
            ("svelte-", "Svelte", "Framework", 0.85),
            ("astro-island", "Astro", "Framework", 0.90),
            ("astro-root", "Astro", "Framework", 0.90),
            ("gatsby", "Gatsby", "Static Site Generator", 0.85),
            ("___gatsby", "Gatsby", "Static Site Generator", 0.90),
            ("hugo", "Hugo", "Static Site Generator", 0.60),
            ("jekyll", "Jekyll", "Static Site Generator", 0.70),
            ("eleventy", "Eleventy", "Static Site Generator", 0.80),
            ("hexo", "Hexo", "Static Site Generator", 0.80),
            ("bootstrap", "Bootstrap", "UI Framework", 0.80),
            ("tailwind", "Tailwind CSS", "UI Framework", 0.75),
            ("jquery", "jQuery", "JavaScript Library", 0.85),
            ("lodash", "Lodash", "JavaScript Library", 0.85),
            ("moment.js", "Moment.js", "JavaScript Library", 0.85),
            ("gsap", "GSAP", "JavaScript Library", 0.85),
            ("three.js", "Three.js", "JavaScript Library", 0.85),
            ("chart.js", "Chart.js", "JavaScript Library", 0.85),
            ("d3.js", "D3.js", "JavaScript Library", 0.85),
            ("discourse", "Discourse", "Forum", 0.85),
            ("phpbb", "phpBB", "Forum", 0.85),
            ("mediawiki", "MediaWiki", "Wiki", 0.90),
            ("confluence", "Confluence", "Wiki", 0.85),
            ("gitlab", "GitLab", "DevOps", 0.80),
            ("grafana", "Grafana", "Monitoring", 0.85),
            ("@vite/client", "Vite", "Build Tool", 0.95),
            ("webpack", "Webpack", "Build Tool", 0.70),
            ("__webpack_require__", "Webpack", "Build Tool", 0.85),
            ("cloudflare", "Cloudflare", "CDN", 0.70),
            ("cdn-cgi", "Cloudflare", "CDN", 0.85),
            ("google-analytics.com", "Google Analytics", "Analytics", 0.90),
            ("googletagmanager.com", "Google Tag Manager", "Analytics", 0.90),
            ("connect.facebook.net", "Facebook Pixel", "Analytics", 0.90),
            ("static.hotjar.com", "Hotjar", "Analytics", 0.90),
            ("hubspot.com", "HubSpot", "Marketing", 0.85),
            ("stripe.com", "Stripe", "Payment", 0.90),
            ("paypal.com", "PayPal", "Payment", 0.85),
            ("paypalobjects.com", "PayPal", "Payment", 0.90),
            ("intercom", "Intercom", "Customer Support", 0.80),
            ("zendesk.com", "Zendesk", "Customer Support", 0.90),
            ("zdassets.com", "Zendesk", "Customer Support", 0.90),
            ("wix.com", "Wix", "Website Builder", 0.85),
            ("wixstatic.com", "Wix", "Website Builder", 0.90),
            ("squarespace.com", "Squarespace", "Website Builder", 0.85),
        ];

        for (signature, name, category, confidence) in &html_signatures {
            if html_lower.contains(signature) {
                let version = Self::extract_version_for_tech(html_lower, html, name);
                let display_name = match &version {
                    Some(v) => format!("{} {}", name, v),
                    None => name.to_string(),
                };

                techs.push(DetectedTech {
                    name: display_name,
                    category: category.to_string(),
                    confidence: *confidence,
                    version,
                    detection_method: "HTML Content".to_string(),
                    detail: format!("Found '{}' in page content", signature),
                });
            }
        }

        let generator_re = regex::Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#).unwrap();
        if let Some(caps) = generator_re.captures(html) {
            let gen_value = caps.get(1).unwrap().as_str();
            let gen_lower = gen_value.to_lowercase();

            let gen_signatures: Vec<(&str, &str, &str, f64)> = vec![
                ("wordpress", "WordPress", "CMS", 0.98),
                ("joomla", "Joomla", "CMS", 0.98),
                ("drupal", "Drupal", "CMS", 0.98),
                ("hugo", "Hugo", "Static Site Generator", 0.98),
                ("jekyll", "Jekyll", "Static Site Generator", 0.98),
                ("gatsby", "Gatsby", "Static Site Generator", 0.98),
                ("hexo", "Hexo", "Static Site Generator", 0.98),
                ("ghost", "Ghost", "CMS", 0.98),
                ("typo3", "TYPO3", "CMS", 0.98),
                ("contao", "Contao", "CMS", 0.98),
                ("concrete5", "Concrete5", "CMS", 0.98),
                ("silverstripe", "SilverStripe", "CMS", 0.98),
                ("blogger", "Blogger", "CMS", 0.98),
                ("wix", "Wix", "Website Builder", 0.98),
                ("squarespace", "Squarespace", "Website Builder", 0.98),
                ("weebly", "Weebly", "Website Builder", 0.98),
            ];

            for (sig, name, category, confidence) in &gen_signatures {
                if gen_lower.contains(sig) {
                    let version = Self::extract_version(&gen_lower, sig);
                    let display_name = match &version {
                        Some(v) => format!("{} {}", name, v),
                        None => name.to_string(),
                    };
                    techs.push(DetectedTech {
                        name: display_name,
                        category: category.to_string(),
                        confidence: *confidence,
                        version,
                        detection_method: "Meta Generator".to_string(),
                        detail: format!("Generator: {}", gen_value),
                    });
                }
            }
        }
    }

    fn detect_from_js(html: &str, html_lower: &str, techs: &mut Vec<DetectedTech>) {
        let js_signatures: Vec<(&str, &str, &str, f64)> = vec![
            ("react.production.min.js", "React", "Framework", 0.95),
            ("react-dom.production.min.js", "React", "Framework", 0.95),
            ("react.development.js", "React", "Framework", 0.90),
            ("react-dom.development.js", "React", "Framework", 0.90),
            ("vue.global.js", "Vue.js", "Framework", 0.95),
            ("vue.global.prod.js", "Vue.js", "Framework", 0.95),
            ("vue.runtime", "Vue.js", "Framework", 0.90),
            ("angular.min.js", "AngularJS", "Framework", 0.95),
            ("zone.js", "Angular", "Framework", 0.85),
            ("svelte/internal", "Svelte", "Framework", 0.90),
            ("jquery.min.js", "jQuery", "JavaScript Library", 0.90),
            ("jquery.js", "jQuery", "JavaScript Library", 0.85),
            ("bootstrap.min.js", "Bootstrap", "UI Framework", 0.90),
            ("bootstrap.bundle.min.js", "Bootstrap", "UI Framework", 0.90),
            ("popper.min.js", "Popper.js", "JavaScript Library", 0.85),
            ("lodash.min.js", "Lodash", "JavaScript Library", 0.90),
            ("moment.min.js", "Moment.js", "JavaScript Library", 0.90),
            ("gsap.min.js", "GSAP", "JavaScript Library", 0.90),
            ("three.min.js", "Three.js", "JavaScript Library", 0.90),
            ("chart.min.js", "Chart.js", "JavaScript Library", 0.90),
            ("d3.min.js", "D3.js", "JavaScript Library", 0.90),
            ("axios.min.js", "Axios", "JavaScript Library", 0.90),
            ("socket.io.js", "Socket.IO", "JavaScript Library", 0.95),
            ("firebase-app.js", "Firebase", "PaaS", 0.95),
            ("firebase.js", "Firebase", "PaaS", 0.90),
            ("gtag/js", "Google Analytics", "Analytics", 0.90),
            ("analytics.js", "Google Analytics", "Analytics", 0.85),
            ("googletagmanager.com/gtm.js", "Google Tag Manager", "Analytics", 0.90),
            ("fbevents.js", "Facebook Pixel", "Analytics", 0.95),
            ("static.hotjar.com", "Hotjar", "Analytics", 0.90),
            ("recaptcha", "reCAPTCHA", "Security", 0.90),
            ("hcaptcha", "hCaptcha", "Security", 0.90),
            ("stripe.com/v3", "Stripe", "Payment", 0.95),
            ("paypal.com/sdk/js", "PayPal", "Payment", 0.95),
            ("cdn.jsdelivr.net/npm/algoliasearch", "Algolia", "Search", 0.90),
            ("cdn.jsdelivr.net/npm/@elastic", "Elastic", "Search", 0.85),
            ("cdn.jsdelivr.net/npm/swiper", "Swiper", "JavaScript Library", 0.85),
            ("cdn.jsdelivr.net/npm/aos", "AOS", "JavaScript Library", 0.85),
            ("cdnjs.cloudflare.com/ajax/libs/font-awesome", "Font Awesome", "UI Framework", 0.90),
            ("unpkg.com/antd", "Ant Design", "UI Framework", 0.90),
            ("unpkg.com/@mui", "Material UI", "UI Framework", 0.90),
            ("cdn.tailwindcss.com", "Tailwind CSS", "UI Framework", 0.90),
            ("gatsby-browser", "Gatsby", "Static Site Generator", 0.90),
            ("@vite/client", "Vite", "Build Tool", 0.95),
            ("vite/modulepreload-polyfill", "Vite", "Build Tool", 0.95),
            ("cdn.shopify.com", "Shopify", "E-commerce", 0.95),
            ("widget.intercom.io", "Intercom", "Customer Support", 0.90),
            ("zdassets.com", "Zendesk", "Customer Support", 0.90),
            ("hubspot.com", "HubSpot", "Marketing", 0.85),
            ("hs-analytics", "HubSpot", "Marketing", 0.90),
            ("mailchimp", "Mailchimp", "Marketing", 0.85),
            ("list-manage.com", "Mailchimp", "Marketing", 0.85),
        ];

        for (signature, name, category, confidence) in &js_signatures {
            if html_lower.contains(signature) {
                let version = Self::extract_version_for_tech(html_lower, html, name);
                let display_name = match &version {
                    Some(v) => format!("{} {}", name, v),
                    None => name.to_string(),
                };
                techs.push(DetectedTech {
                    name: display_name,
                    category: category.to_string(),
                    confidence: *confidence,
                    version,
                    detection_method: "JavaScript".to_string(),
                    detail: format!("Found '{}' reference", signature),
                });
            }
        }

        let script_src_re = regex::Regex::new(r#"(?i)src=["']([^"']*\.js[^"']*)["']"#).unwrap();
        for cap in script_src_re.captures_iter(html) {
            let src = cap.get(1).unwrap().as_str().to_lowercase();

            let js_file_signatures: Vec<(&str, &str, &str, f64)> = vec![
                ("jquery", "jQuery", "JavaScript Library", 0.80),
                ("bootstrap", "Bootstrap", "UI Framework", 0.80),
                ("angular", "Angular", "Framework", 0.80),
                ("react", "React", "Framework", 0.75),
                ("vue", "Vue.js", "Framework", 0.75),
                ("lodash", "Lodash", "JavaScript Library", 0.85),
                ("moment", "Moment.js", "JavaScript Library", 0.85),
                ("gsap", "GSAP", "JavaScript Library", 0.85),
                ("three", "Three.js", "JavaScript Library", 0.85),
                ("chart", "Chart.js", "JavaScript Library", 0.80),
                ("d3", "D3.js", "JavaScript Library", 0.80),
                ("axios", "Axios", "JavaScript Library", 0.85),
                ("socket.io", "Socket.IO", "JavaScript Library", 0.90),
                ("firebase", "Firebase", "PaaS", 0.85),
                ("stripe", "Stripe", "Payment", 0.85),
                ("paypal", "PayPal", "Payment", 0.85),
                ("recaptcha", "reCAPTCHA", "Security", 0.85),
                ("hcaptcha", "hCaptcha", "Security", 0.85),
                ("sentry", "Sentry", "Monitoring", 0.85),
                ("datadog", "Datadog", "Monitoring", 0.85),
                ("newrelic", "New Relic", "Monitoring", 0.85),
            ];

            for (keyword, name, category, confidence) in &js_file_signatures {
                if src.contains(keyword) && !html_lower.contains(&format!("{}.js", keyword)) {
                    let already = techs.iter().any(|t| t.name.starts_with(name));
                    if !already {
                        techs.push(DetectedTech {
                            name: name.to_string(),
                            category: category.to_string(),
                            confidence: *confidence,
                            version: None,
                            detection_method: "JS Bundle".to_string(),
                            detail: format!("Script: {}", cap.get(1).unwrap().as_str()),
                        });
                    }
                }
            }
        }

        let js_globals: Vec<(&str, &str, &str, f64)> = vec![
            ("window.__REACT", "React", "Framework", 0.85),
            ("window.__NEXT", "Next.js", "Framework", 0.90),
            ("window.__NUXT", "Nuxt.js", "Framework", 0.90),
            ("window.Vue", "Vue.js", "Framework", 0.85),
            ("window.angular", "Angular", "Framework", 0.85),
            ("window.jQuery", "jQuery", "JavaScript Library", 0.85),
            ("window._gaq", "Google Analytics", "Analytics", 0.85),
            ("window.dataLayer", "Google Tag Manager", "Analytics", 0.85),
            ("window.Intercom", "Intercom", "Customer Support", 0.85),
            ("window.Stripe", "Stripe", "Payment", 0.85),
            ("window.Sentry", "Sentry", "Monitoring", 0.85),
        ];

        for (global, name, category, confidence) in &js_globals {
            if html.contains(global) {
                let already = techs.iter().any(|t| t.name.starts_with(name));
                if !already {
                    techs.push(DetectedTech {
                        name: name.to_string(),
                        category: category.to_string(),
                        confidence: *confidence,
                        version: None,
                        detection_method: "JS Global".to_string(),
                        detail: format!("Global: {}", global),
                    });
                }
            }
        }
    }

    fn detect_from_css(html: &str, html_lower: &str, techs: &mut Vec<DetectedTech>) {
        let css_signatures: Vec<(&str, &str, &str, f64)> = vec![
            ("bootstrap.min.css", "Bootstrap", "UI Framework", 0.90),
            ("bootstrap.css", "Bootstrap", "UI Framework", 0.85),
            ("tailwind.min.css", "Tailwind CSS", "UI Framework", 0.90),
            ("tailwind.css", "Tailwind CSS", "UI Framework", 0.85),
            ("font-awesome", "Font Awesome", "UI Framework", 0.90),
            ("fontawesome", "Font Awesome", "UI Framework", 0.85),
            ("material-icons", "Material Icons", "UI Framework", 0.85),
            ("animate.css", "Animate.css", "UI Framework", 0.85),
            ("bulma", "Bulma", "UI Framework", 0.85),
            ("foundation.min.css", "Foundation", "UI Framework", 0.90),
            ("semantic.min.css", "Semantic UI", "UI Framework", 0.90),
            ("ant-design", "Ant Design", "UI Framework", 0.85),
            ("element-ui", "Element UI", "UI Framework", 0.85),
        ];

        for (signature, name, category, confidence) in &css_signatures {
            if html_lower.contains(signature) {
                let already = techs.iter().any(|t| t.name.starts_with(name));
                if !already {
                    techs.push(DetectedTech {
                        name: name.to_string(),
                        category: category.to_string(),
                        confidence: *confidence,
                        version: None,
                        detection_method: "CSS".to_string(),
                        detail: format!("Found '{}' in CSS references", signature),
                    });
                }
            }
        }

        let link_href_re = regex::Regex::new(r#"(?i)<link[^>]+href=["']([^"']*\.css[^"']*)["']"#).unwrap();
        for cap in link_href_re.captures_iter(html) {
            let href = cap.get(1).unwrap().as_str().to_lowercase();
            let css_file_sigs: Vec<(&str, &str, &str, f64)> = vec![
                ("bootstrap", "Bootstrap", "UI Framework", 0.80),
                ("tailwind", "Tailwind CSS", "UI Framework", 0.80),
                ("font-awesome", "Font Awesome", "UI Framework", 0.85),
                ("bulma", "Bulma", "UI Framework", 0.85),
                ("foundation", "Foundation", "UI Framework", 0.85),
                ("semantic", "Semantic UI", "UI Framework", 0.85),
            ];

            for (keyword, name, category, confidence) in &css_file_sigs {
                if href.contains(keyword) {
                    let already = techs.iter().any(|t| t.name.starts_with(name));
                    if !already {
                        techs.push(DetectedTech {
                            name: name.to_string(),
                            category: category.to_string(),
                            confidence: *confidence,
                            version: None,
                            detection_method: "CSS Link".to_string(),
                            detail: format!("Stylesheet: {}", cap.get(1).unwrap().as_str()),
                        });
                    }
                }
            }
        }
    }

    fn detect_from_meta(html: &str, _html_lower: &str, techs: &mut Vec<DetectedTech>) {
        let viewport_re = regex::Regex::new(r#"(?i)<meta\s+name=["']viewport["']"#).unwrap();
        if viewport_re.is_match(html) {
            techs.push(DetectedTech {
                name: "Responsive Design".to_string(),
                category: "Miscellaneous".to_string(),
                confidence: 0.80,
                version: None,
                detection_method: "Meta Tag".to_string(),
                detail: "Viewport meta tag present".to_string(),
            });
        }

        let charset_re = regex::Regex::new(r#"(?i)<meta\s+charset=["']([^"']+)["']"#).unwrap();
        if let Some(caps) = charset_re.captures(html) {
            let charset = caps.get(1).unwrap().as_str().to_uppercase();
            if charset != "UTF-8" {
                techs.push(DetectedTech {
                    name: format!("Charset: {}", charset),
                    category: "Miscellaneous".to_string(),
                    confidence: 0.90,
                    version: None,
                    detection_method: "Meta Tag".to_string(),
                    detail: format!("Character encoding: {}", charset),
                });
            }
        }

        let og_re = regex::Regex::new(r#"(?i)<meta\s+property=["']og:""#).unwrap();
        if og_re.is_match(html) {
            techs.push(DetectedTech {
                name: "Open Graph".to_string(),
                category: "Miscellaneous".to_string(),
                confidence: 0.85,
                version: None,
                detection_method: "Meta Tag".to_string(),
                detail: "Open Graph meta tags present".to_string(),
            });
        }

        let twitter_re = regex::Regex::new(r#"(?i)<meta\s+(?:name|property)=["']twitter:"#).unwrap();
        if twitter_re.is_match(html) {
            techs.push(DetectedTech {
                name: "Twitter Cards".to_string(),
                category: "Miscellaneous".to_string(),
                confidence: 0.85,
                version: None,
                detection_method: "Meta Tag".to_string(),
                detail: "Twitter Card meta tags present".to_string(),
            });
        }

        let theme_re = regex::Regex::new(r#"(?i)<meta\s+name=["']theme-color["']\s+content=["']([^"']+)["']"#).unwrap();
        if let Some(caps) = theme_re.captures(html) {
            techs.push(DetectedTech {
                name: "PWA Ready".to_string(),
                category: "Miscellaneous".to_string(),
                confidence: 0.60,
                version: None,
                detection_method: "Meta Tag".to_string(),
                detail: format!("Theme color: {}", caps.get(1).unwrap().as_str()),
            });
        }

        let msvalidate_re = regex::Regex::new(r#"(?i)<meta\s+name=["']msvalidate\.01["']"#).unwrap();
        if msvalidate_re.is_match(html) {
            techs.push(DetectedTech {
                name: "Bing Webmaster".to_string(),
                category: "Analytics".to_string(),
                confidence: 0.85,
                version: None,
                detection_method: "Meta Tag".to_string(),
                detail: "Bing validation meta tag present".to_string(),
            });
        }

        let googlesite_re = regex::Regex::new(r#"(?i)<meta\s+name=["']google-site-verification["']"#).unwrap();
        if googlesite_re.is_match(html) {
            techs.push(DetectedTech {
                name: "Google Search Console".to_string(),
                category: "Analytics".to_string(),
                confidence: 0.85,
                version: None,
                detection_method: "Meta Tag".to_string(),
                detail: "Google site verification meta tag present".to_string(),
            });
        }
    }

    fn detect_from_script_src(html: &str, techs: &mut Vec<DetectedTech>) {
        let script_src_re = regex::Regex::new(r#"(?i)src=["']([^"']+)["']"#).unwrap();
        let mut seen_srcs: std::collections::HashSet<String> = std::collections::HashSet::new();

        for cap in script_src_re.captures_iter(html) {
            let src = cap.get(1).unwrap().as_str().to_string();
            let src_lower = src.to_lowercase();

            let deep_sigs: Vec<(&str, &str, &str, f64)> = vec![
                ("plausible.io", "Plausible Analytics", "Analytics", 0.90),
                ("matomo", "Matomo", "Analytics", 0.90),
                ("piwik", "Matomo", "Analytics", 0.85),
                ("amplitude", "Amplitude", "Analytics", 0.90),
                ("segment.com", "Segment", "Analytics", 0.90),
                ("cdn.amplitude.com", "Amplitude", "Analytics", 0.95),
                ("sentry.io", "Sentry", "Monitoring", 0.90),
                ("browser.sentry-cdn.com", "Sentry", "Monitoring", 0.95),
                ("cdn.datadog-static.com", "Datadog", "Monitoring", 0.95),
                ("js-agent.newrelic.com", "New Relic", "Monitoring", 0.95),
                ("cdn.rollbar.com", "Rollbar", "Monitoring", 0.90),
                ("cdn.jsdelivr.net/npm/algoliasearch", "Algolia", "Search", 0.90),
                ("cdn.jsdelivr.net/npm/instantsearch", "Algolia", "Search", 0.85),
                ("cdn.jsdelivr.net/npm/lunr", "Lunr.js", "Search", 0.85),
                ("unpkg.com/swiper", "Swiper", "JavaScript Library", 0.85),
                ("unpkg.com/aos", "AOS", "JavaScript Library", 0.85),
                ("unpkg.com/gsap", "GSAP", "JavaScript Library", 0.85),
                ("cdn.jsdelivr.net/npm/plyr", "Plyr", "JavaScript Library", 0.85),
                ("cdn.jsdelivr.net/npm/video.js", "Video.js", "JavaScript Library", 0.85),
                ("cdn.jsdelivr.net/npm/leaflet", "Leaflet", "JavaScript Library", 0.85),
                ("cdn.jsdelivr.net/npm/mapbox", "Mapbox", "JavaScript Library", 0.85),
                ("api.mapbox.com", "Mapbox", "JavaScript Library", 0.90),
                ("cdn.tiny.cloud", "TinyMCE", "JavaScript Library", 0.90),
                ("cdn.ckeditor.com", "CKEditor", "JavaScript Library", 0.90),
                ("cdn.quilljs.com", "Quill", "JavaScript Library", 0.90),
                ("cdn.jsdelivr.net/npm/dayjs", "Day.js", "JavaScript Library", 0.85),
                ("cdn.jsdelivr.net/npm/date-fns", "date-fns", "JavaScript Library", 0.85),
            ];

            for (sig, name, category, confidence) in &deep_sigs {
                if src_lower.contains(sig) {
                    let key = name.to_string();
                    if seen_srcs.insert(key.clone()) {
                        let already = techs.iter().any(|t| t.name.starts_with(*name));
                        if !already {
                            techs.push(DetectedTech {
                                name: name.to_string(),
                                category: category.to_string(),
                                confidence: *confidence,
                                version: None,
                                detection_method: "Script Source".to_string(),
                                detail: format!("Script: {}", src),
                            });
                        }
                    }
                }
            }
        }
    }

    fn detect_from_link_href(html: &str, techs: &mut Vec<DetectedTech>) {
        let link_re = regex::Regex::new(r#"(?i)<link[^>]+(?:href|rel)=["']([^"']+)["']"#).unwrap();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for cap in link_re.captures_iter(html) {
            let val = cap.get(1).unwrap().as_str().to_lowercase();

            let link_sigs: Vec<(&str, &str, &str, f64)> = vec![
                ("fonts.googleapis.com", "Google Fonts", "UI Framework", 0.90),
                ("fonts.bunny.net", "Bunny Fonts", "UI Framework", 0.85),
                ("use.typekit.net", "Adobe Fonts", "UI Framework", 0.90),
                ("cdn.typekit.net", "Adobe Fonts", "UI Framework", 0.90),
                ("fast.fonts.net", "Fonts.com", "UI Framework", 0.85),
                ("api.mapbox.com", "Mapbox", "JavaScript Library", 0.90),
                ("unpkg.com/leaflet", "Leaflet", "JavaScript Library", 0.85),
                ("cdn.jsdelivr.net/npm/leaflet", "Leaflet", "JavaScript Library", 0.85),
            ];

            for (sig, name, category, confidence) in &link_sigs {
                if val.contains(sig) {
                    let key = name.to_string();
                    if seen.insert(key.clone()) {
                        let already = techs.iter().any(|t| t.name.starts_with(*name));
                        if !already {
                            techs.push(DetectedTech {
                                name: name.to_string(),
                                category: category.to_string(),
                                confidence: *confidence,
                                version: None,
                                detection_method: "Link Reference".to_string(),
                                detail: format!("Link: {}", cap.get(1).unwrap().as_str()),
                            });
                        }
                    }
                }
            }
        }

        let manifest_re = regex::Regex::new(r#"(?i)<link[^>]+rel=["']manifest["']"#).unwrap();
        if manifest_re.is_match(html) {
            let already = techs.iter().any(|t| t.name == "PWA Ready");
            if !already {
                techs.push(DetectedTech {
                    name: "PWA Ready".to_string(),
                    category: "Miscellaneous".to_string(),
                    confidence: 0.85,
                    version: None,
                    detection_method: "Link Reference".to_string(),
                    detail: "Web app manifest present".to_string(),
                });
            }
        }

        let rss_re = regex::Regex::new(r#"(?i)<link[^>]+type=["']application/rss\+xml["']"#).unwrap();
        if rss_re.is_match(html) {
            techs.push(DetectedTech {
                name: "RSS Feed".to_string(),
                category: "Miscellaneous".to_string(),
                confidence: 0.80,
                version: None,
                detection_method: "Link Reference".to_string(),
                detail: "RSS feed link present".to_string(),
            });
        }

        let atom_re = regex::Regex::new(r#"(?i)<link[^>]+type=["']application/atom\+xml["']"#).unwrap();
        if atom_re.is_match(html) {
            techs.push(DetectedTech {
                name: "Atom Feed".to_string(),
                category: "Miscellaneous".to_string(),
                confidence: 0.80,
                version: None,
                detection_method: "Link Reference".to_string(),
                detail: "Atom feed link present".to_string(),
            });
        }
    }
}
