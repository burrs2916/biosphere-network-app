use super::config::*;
use crate::core::ToolError;
use reqwest::header::HeaderMap;
use std::time::Instant;

struct HeaderDefinition {
    name: String,
    display_name: String,
    description: String,
    recommendation: String,
    category: String,
    importance: i32,
    missing_severity: String,
    cwe_id: Option<String>,
    owasp_category: Option<String>,
}

pub struct SecurityHeaderAnalyzer;

impl SecurityHeaderAnalyzer {
    pub async fn analyze(config: &SecurityHeaderConfig) -> Result<SecurityHeaderReport, ToolError> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        if trimmed.is_empty() {
            return Err(ToolError::ExecutionError("URL cannot be empty".to_string()));
        }

        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .user_agent(
                config.user_agent.as_deref().unwrap_or(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            );

        if !config.verify_ssl {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        if config.follow_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::limited(10));
        } else {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        if let Some(proxy) = &config.proxy_url {
            if let Ok(proxy_url) = reqwest::Proxy::all(proxy) {
                client_builder = client_builder.proxy(proxy_url);
            }
        }

        let client = client_builder
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut request = client.get(&target_url);
        if let Some(custom_headers_str) = &config.custom_headers {
            for line in custom_headers_str.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim();
                    let value = value.trim();
                    if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                        if let Ok(header_value) = reqwest::header::HeaderValue::from_str(value) {
                            request = request.header(header_name, header_value);
                        }
                    }
                }
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| ToolError::ExecutionError(format!("Request failed: {}", e)))?;

        let status_code = response.status().as_u16();
        let headers = response.headers().clone();

        let final_url = response.url().to_string();

        let server_header = headers.get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let x_powered_by = headers.get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let redirect_chain: Vec<RedirectEntry> = Vec::new();

        let https_redirect = if target_url.starts_with("http://") {
            let redirects_to_https = final_url.starts_with("https://");
            let issue = if !redirects_to_https {
                Some("HTTP URL does not redirect to HTTPS - users can access the site over unencrypted connection".to_string())
            } else {
                None
            };
            Some(HttpsRedirectCheck {
                original_url: target_url.clone(),
                final_url,
                redirects_to_https,
                is_permanent: redirects_to_https,
                issue,
            })
        } else {
            None
        };

        let mut present_headers: Vec<HeaderDetail> = Vec::new();
        let mut missing_headers: Vec<HeaderDetail> = Vec::new();
        let mut issues: Vec<HeaderIssue> = Vec::new();

        let header_definitions = Self::get_header_definitions();

        for def in &header_definitions {
            if let Some(value) = headers.get(&def.name) {
                let value_str = value.to_str().unwrap_or("").to_string();
                let (status, severity, desc, rec, cwe, owasp, _score) =
                    Self::evaluate_header(&def.name, &value_str);

                let is_good = status == "good";
                let is_warning = status == "warning";

                present_headers.push(HeaderDetail {
                    name: def.display_name.clone(),
                    value: value_str.clone(),
                    status,
                    severity: severity.clone(),
                    category: def.category.clone(),
                    description: desc,
                    recommendation: rec.clone(),
                    cwe_id: cwe,
                    owasp_category: owasp,
                    importance: def.importance,
                });

                if !is_good {
                    issues.push(HeaderIssue {
                        header_name: def.display_name.clone(),
                        issue_type: if is_warning { "Suboptimal Configuration".to_string() } else { "Misconfigured Header".to_string() },
                        severity: severity.clone(),
                        category: def.category.clone(),
                        description: format!("{} is present but not optimally configured", def.display_name),
                        recommendation: rec,
                        cwe_id: None,
                        owasp_category: None,
                        current_value: Some(value_str),
                    });
                }
            } else {
                missing_headers.push(HeaderDetail {
                    name: def.display_name.clone(),
                    value: String::new(),
                    status: "missing".to_string(),
                    severity: def.missing_severity.clone(),
                    category: def.category.clone(),
                    description: def.description.clone(),
                    recommendation: def.recommendation.clone(),
                    cwe_id: def.cwe_id.clone(),
                    owasp_category: def.owasp_category.clone(),
                    importance: def.importance,
                });

                issues.push(HeaderIssue {
                    header_name: def.display_name.clone(),
                    issue_type: "Missing Header".to_string(),
                    severity: def.missing_severity.clone(),
                    category: def.category.clone(),
                    description: format!("{} is missing", def.display_name),
                    recommendation: def.recommendation.clone(),
                    cwe_id: def.cwe_id.clone(),
                    owasp_category: def.owasp_category.clone(),
                    current_value: None,
                });
            }
        }

        let csp_analysis = if config.check_csp_details {
            if let Some(value) = headers.get("content-security-policy").and_then(|v| v.to_str().ok()) {
                Some(Self::analyze_csp(value, false))
            } else if let Some(value) = headers.get("content-security-policy-report-only").and_then(|v| v.to_str().ok()) {
                Some(Self::analyze_csp(value, true))
            } else {
                None
            }
        } else {
            None
        };

        let hsts_analysis = headers.get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .map(|v| Self::analyze_hsts(v));

        let information_leakage = if config.check_information_leakage {
            Self::check_information_leakage(&headers)
        } else {
            Vec::new()
        };

        let cookie_security = if config.check_cookie_headers {
            Self::check_cookie_security(&headers)
        } else {
            Vec::new()
        };

        let score = Self::calculate_score(&present_headers, &missing_headers, &csp_analysis, &hsts_analysis);
        let grade = Self::score_to_grade(score);

        let severity_stats = Self::calculate_severity_stats(&issues);
        let category_stats = Self::calculate_category_stats(&present_headers, &missing_headers);

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        let summary = format!(
            "Security Score: {}/100 (Grade: {}) - {} headers present, {} headers missing, {} issues found",
            score, grade, present_headers.len(), missing_headers.len(), issues.len()
        );

        Ok(SecurityHeaderReport {
            url: target_url,
            score,
            grade,
            summary,
            present_headers,
            missing_headers,
            issues,
            csp_analysis,
            hsts_analysis,
            information_leakage,
            cookie_security,
            severity_stats,
            category_stats,
            response_status: status_code,
            server_header,
            x_powered_by,
            scan_duration_ms,
            redirect_chain,
            https_redirect,
        })
    }

    fn get_header_definitions() -> Vec<HeaderDefinition> {
        vec![
            HeaderDefinition {
                name: "content-security-policy".to_string(),
                display_name: "Content-Security-Policy".to_string(),
                description: "Controls which resources the browser can load. Most important defense against XSS attacks.".to_string(),
                recommendation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'".to_string(),
                category: "XSS Protection".to_string(),
                importance: 20,
                missing_severity: "high".to_string(),
                cwe_id: Some("CWE-693".to_string()),
                owasp_category: Some("A05:2021-Security Misconfiguration".to_string()),
            },
            HeaderDefinition {
                name: "strict-transport-security".to_string(),
                display_name: "Strict-Transport-Security".to_string(),
                description: "Forces browsers to only use HTTPS connections. Protects against protocol downgrade attacks and cookie hijacking.".to_string(),
                recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".to_string(),
                category: "Transport Security".to_string(),
                importance: 15,
                missing_severity: "high".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                owasp_category: Some("A02:2021-Cryptographic Failures".to_string()),
            },
            HeaderDefinition {
                name: "x-frame-options".to_string(),
                display_name: "X-Frame-Options".to_string(),
                description: "Prevents clickjacking by controlling iframe embedding. Protects against UI redress attacks.".to_string(),
                recommendation: "Add: X-Frame-Options: DENY or SAMEORIGIN".to_string(),
                category: "Clickjacking Protection".to_string(),
                importance: 10,
                missing_severity: "medium".to_string(),
                cwe_id: Some("CWE-1021".to_string()),
                owasp_category: Some("A04:2021-Insecure Design".to_string()),
            },
            HeaderDefinition {
                name: "x-content-type-options".to_string(),
                display_name: "X-Content-Type-Options".to_string(),
                description: "Prevents MIME type sniffing. Stops browsers from interpreting files as a different MIME type than declared.".to_string(),
                recommendation: "Add: X-Content-Type-Options: nosniff".to_string(),
                category: "Content Sniffing".to_string(),
                importance: 5,
                missing_severity: "low".to_string(),
                cwe_id: Some("CWE-693".to_string()),
                owasp_category: None,
            },
            HeaderDefinition {
                name: "referrer-policy".to_string(),
                display_name: "Referrer-Policy".to_string(),
                description: "Controls how much referrer information is passed to other sites. Prevents information leakage via Referer header.".to_string(),
                recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin".to_string(),
                category: "Privacy".to_string(),
                importance: 5,
                missing_severity: "low".to_string(),
                cwe_id: Some("CWE-200".to_string()),
                owasp_category: None,
            },
            HeaderDefinition {
                name: "permissions-policy".to_string(),
                display_name: "Permissions-Policy".to_string(),
                description: "Controls which browser features and APIs can be used. Limits access to camera, microphone, geolocation, etc.".to_string(),
                recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()".to_string(),
                category: "Feature Control".to_string(),
                importance: 10,
                missing_severity: "low".to_string(),
                cwe_id: None,
                owasp_category: None,
            },
            HeaderDefinition {
                name: "cross-origin-opener-policy".to_string(),
                display_name: "Cross-Origin-Opener-Policy".to_string(),
                description: "Isolates your page from cross-origin documents. Protects against Spectre-style side-channel attacks.".to_string(),
                recommendation: "Add: Cross-Origin-Opener-Policy: same-origin".to_string(),
                category: "Cross-Origin Isolation".to_string(),
                importance: 5,
                missing_severity: "low".to_string(),
                cwe_id: None,
                owasp_category: None,
            },
            HeaderDefinition {
                name: "cross-origin-resource-policy".to_string(),
                display_name: "Cross-Origin-Resource-Policy".to_string(),
                description: "Controls cross-origin resource sharing at the resource level. Prevents cross-origin resource theft.".to_string(),
                recommendation: "Add: Cross-Origin-Resource-Policy: same-origin".to_string(),
                category: "Cross-Origin Isolation".to_string(),
                importance: 5,
                missing_severity: "low".to_string(),
                cwe_id: None,
                owasp_category: None,
            },
            HeaderDefinition {
                name: "cross-origin-embedder-policy".to_string(),
                display_name: "Cross-Origin-Embedder-Policy".to_string(),
                description: "Controls which cross-origin resources can be loaded. Enables SharedArrayBuffer and other powerful APIs.".to_string(),
                recommendation: "Add: Cross-Origin-Embedder-Policy: require-corp".to_string(),
                category: "Cross-Origin Isolation".to_string(),
                importance: 5,
                missing_severity: "info".to_string(),
                cwe_id: None,
                owasp_category: None,
            },
            HeaderDefinition {
                name: "x-xss-protection".to_string(),
                display_name: "X-XSS-Protection".to_string(),
                description: "Legacy browser XSS filter. Deprecated in modern browsers but still useful for older browser support.".to_string(),
                recommendation: "Add: X-XSS-Protection: 0 (or 1; mode=block for legacy support)".to_string(),
                category: "XSS Protection".to_string(),
                importance: 3,
                missing_severity: "info".to_string(),
                cwe_id: Some("CWE-79".to_string()),
                owasp_category: None,
            },
            HeaderDefinition {
                name: "x-permitted-cross-domain-policies".to_string(),
                display_name: "X-Permitted-Cross-Domain-Policies".to_string(),
                description: "Controls cross-domain access for Flash and PDF documents. Prevents unauthorized cross-domain data access.".to_string(),
                recommendation: "Add: X-Permitted-Cross-Domain-Policies: none".to_string(),
                category: "Content Sniffing".to_string(),
                importance: 3,
                missing_severity: "info".to_string(),
                cwe_id: None,
                owasp_category: None,
            },
            HeaderDefinition {
                name: "cache-control".to_string(),
                display_name: "Cache-Control".to_string(),
                description: "Controls caching behavior. Sensitive pages should use no-store to prevent data leakage through browser cache.".to_string(),
                recommendation: "For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate".to_string(),
                category: "Privacy".to_string(),
                importance: 5,
                missing_severity: "info".to_string(),
                cwe_id: Some("CWE-524".to_string()),
                owasp_category: None,
            },
        ]
    }

    fn evaluate_header(name: &str, value: &str) -> (String, String, String, String, Option<String>, Option<String>, i32) {
        match name.to_lowercase().as_str() {
            "strict-transport-security" => {
                let max_age: i64 = value.split(';')
                    .find_map(|part| {
                        part.trim().strip_prefix("max-age=")
                            .and_then(|v| v.parse().ok())
                    })
                    .unwrap_or(0);

                let has_include_subdomains = value.to_lowercase().contains("includesubdomains");
                let has_preload = value.to_lowercase().contains("preload");

                if max_age >= 31536000 && has_include_subdomains && has_preload {
                    ("good".to_string(), "info".to_string(),
                     "HSTS is fully configured with long max-age, includeSubDomains and preload".to_string(),
                     "Well configured".to_string(), None, None, 15)
                } else if max_age >= 31536000 && has_include_subdomains {
                    ("good".to_string(), "info".to_string(),
                     "HSTS is well configured with long max-age and includeSubDomains".to_string(),
                     "Consider adding the preload directive for maximum security".to_string(), None, None, 13)
                } else if max_age >= 31536000 {
                    ("warning".to_string(), "low".to_string(),
                     "HSTS max-age is sufficient but missing includeSubDomains".to_string(),
                     "Add includeSubDomains and preload directives for comprehensive protection".to_string(),
                     Some("CWE-319".to_string()), None, 10)
                } else if max_age > 0 {
                    ("warning".to_string(), "medium".to_string(),
                     format!("HSTS max-age is only {} seconds (less than 1 year)", max_age),
                     "Increase max-age to at least 31536000 (1 year)".to_string(),
                     Some("CWE-319".to_string()), None, 5)
                } else {
                    ("bad".to_string(), "high".to_string(),
                     "HSTS max-age is invalid or zero".to_string(),
                     "Set max-age to at least 31536000".to_string(),
                     Some("CWE-319".to_string()), None, 0)
                }
            }
            "content-security-policy" => {
                let has_unsafe_inline = value.contains("'unsafe-inline'");
                let has_unsafe_eval = value.contains("'unsafe-eval'");
                let has_default_src = value.contains("default-src");
                let _has_script_src = value.contains("script-src");
                let has_object_src = value.contains("object-src");
                let has_base_uri = value.contains("base-uri");

                if has_unsafe_inline && has_unsafe_eval {
                    ("warning".to_string(), "high".to_string(),
                     "CSP allows both 'unsafe-inline' and 'unsafe-eval', severely weakening protection".to_string(),
                     "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes instead".to_string(),
                     Some("CWE-693".to_string()), Some("A05:2021".to_string()), 5)
                } else if has_unsafe_eval {
                    ("warning".to_string(), "high".to_string(),
                     "CSP allows 'unsafe-eval', which enables eval() and similar functions".to_string(),
                     "Remove 'unsafe-eval' and refactor code to avoid eval()".to_string(),
                     Some("CWE-693".to_string()), None, 8)
                } else if has_unsafe_inline {
                    ("warning".to_string(), "medium".to_string(),
                     "CSP allows 'unsafe-inline', which weakens XSS protection".to_string(),
                     "Replace 'unsafe-inline' with nonce-based or hash-based CSP".to_string(),
                     Some("CWE-693".to_string()), None, 10)
                } else if !has_default_src {
                    ("warning".to_string(), "medium".to_string(),
                     "CSP is present but missing default-src fallback directive".to_string(),
                     "Add default-src as a fallback for unspecified directive types".to_string(),
                     None, None, 12)
                } else if !has_object_src {
                    ("warning".to_string(), "low".to_string(),
                     "CSP is present but missing object-src directive (allows Flash/Java plugins)".to_string(),
                     "Add object-src 'none' to block plugin content".to_string(),
                     None, None, 14)
                } else if !has_base_uri {
                    ("warning".to_string(), "low".to_string(),
                     "CSP is present but missing base-uri directive".to_string(),
                     "Add base-uri 'self' or base-uri 'none' to prevent base tag injection".to_string(),
                     None, None, 16)
                } else {
                    ("good".to_string(), "info".to_string(),
                     "CSP is properly configured with appropriate directives".to_string(),
                     "Well configured".to_string(), None, None, 20)
                }
            }
            "x-frame-options" => {
                let upper = value.trim().to_uppercase();
                if upper == "DENY" {
                    ("good".to_string(), "info".to_string(),
                     "X-Frame-Options is set to DENY, blocking all iframe embedding".to_string(),
                     "Well configured".to_string(), None, None, 10)
                } else if upper == "SAMEORIGIN" {
                    ("good".to_string(), "info".to_string(),
                     "X-Frame-Options is set to SAMEORIGIN, allowing same-origin embedding only".to_string(),
                     "Well configured. Consider DENY for maximum protection if iframes are not needed".to_string(), None, None, 9)
                } else if upper.starts_with("ALLOW-FROM") {
                    ("warning".to_string(), "medium".to_string(),
                     "X-Frame-Options ALLOW-FROM is deprecated and not supported by modern browsers".to_string(),
                     "Use CSP frame-ancestors directive instead".to_string(),
                     Some("CWE-1021".to_string()), None, 5)
                } else {
                    ("warning".to_string(), "medium".to_string(),
                     "X-Frame-Options has an unrecognized value".to_string(),
                     "Use DENY or SAMEORIGIN".to_string(),
                     Some("CWE-1021".to_string()), None, 3)
                }
            }
            "x-content-type-options" => {
                if value.trim().to_lowercase() == "nosniff" {
                    ("good".to_string(), "info".to_string(),
                     "X-Content-Type-Options is properly set to nosniff".to_string(),
                     "Well configured".to_string(), None, None, 5)
                } else {
                    ("warning".to_string(), "low".to_string(),
                     "X-Content-Type-Options is set but not to 'nosniff'".to_string(),
                     "Set to 'nosniff'".to_string(), None, None, 2)
                }
            }
            "referrer-policy" => {
                let secure_values = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"];
                let weak_values = ["no-referrer-when-downgrade", "origin", "origin-when-cross-origin"];
                let insecure_values = ["unsafe-url"];

                if insecure_values.iter().any(|v| value.trim() == *v) {
                    ("bad".to_string(), "medium".to_string(),
                     "Referrer-Policy is set to unsafe-url, which sends full URL as referrer to any destination".to_string(),
                     "Use strict-origin-when-cross-origin or no-referrer instead".to_string(),
                     Some("CWE-200".to_string()), None, 0)
                } else if weak_values.iter().any(|v| value.trim() == *v) {
                    ("warning".to_string(), "low".to_string(),
                     "Referrer-Policy uses a moderately secure value".to_string(),
                     "Consider using strict-origin-when-cross-origin for better privacy".to_string(),
                     None, None, 3)
                } else if secure_values.iter().any(|v| value.trim() == *v) {
                    ("good".to_string(), "info".to_string(),
                     "Referrer-Policy is properly configured".to_string(),
                     "Well configured".to_string(), None, None, 5)
                } else {
                    ("warning".to_string(), "low".to_string(),
                     "Referrer-Policy has an unrecognized value".to_string(),
                     "Use strict-origin-when-cross-origin or no-referrer".to_string(),
                     None, None, 2)
                }
            }
            "permissions-policy" => {
                let lower = value.trim().to_lowercase();
                let restricted_features = [
                    "camera", "microphone", "geolocation", "payment",
                    "usb", "magnetometer", "accelerometer", "gyroscope",
                    "ambient-light-sensor", "vr", "xr-spatial-tracking",
                    "local-fonts", "display-capture", "screen-wake-lock",
                ];
                let mut restricted_count = 0;
                let mut total_checked = 0;
                for feature in &restricted_features {
                    if lower.contains(feature) {
                        total_checked += 1;
                        let feature_part: Option<&str> = lower.split(feature).nth(1);
                        if let Some(rest) = feature_part {
                            let after_feature = rest.trim_start_matches(|c: char| c == '=' || c == ' ');
                            if after_feature.starts_with("()") || after_feature.starts_with("none") {
                                restricted_count += 1;
                            }
                        }
                    }
                }
                let has_restrictions = lower.contains("=()") || lower.contains("=self") || restricted_count > 0;
                if total_checked > 0 && restricted_count == total_checked {
                    ("good".to_string(), "info".to_string(),
                     format!("Permissions-Policy restricts all {} detected features", total_checked),
                     "Well configured".to_string(), None, None, 10)
                } else if has_restrictions && restricted_count > 0 {
                    ("warning".to_string(), "low".to_string(),
                     format!("Permissions-Policy restricts {} of {} detected features", restricted_count, total_checked),
                     "Restrict all unused features for maximum security".to_string(),
                     None, None, 7)
                } else if has_restrictions {
                    ("warning".to_string(), "low".to_string(),
                     "Permissions-Policy is present but may not restrict any features".to_string(),
                     "Add feature restrictions like camera=(), microphone=(), geolocation=()".to_string(),
                     None, None, 5)
                } else {
                    ("warning".to_string(), "medium".to_string(),
                     "Permissions-Policy is present but no features are restricted".to_string(),
                     "Restrict unused browser features: camera=(), microphone=(), geolocation=(), payment=()".to_string(),
                     None, None, 3)
                }
            }
            "cross-origin-opener-policy" => {
                let lower = value.trim().to_lowercase();
                if lower == "same-origin" {
                    ("good".to_string(), "info".to_string(),
                     "COOP is set to same-origin, providing cross-origin isolation".to_string(),
                     "Well configured".to_string(), None, None, 5)
                } else if lower == "same-origin-allow-popups" {
                    ("warning".to_string(), "low".to_string(),
                     "COOP same-origin-allow-popups provides weaker isolation".to_string(),
                     "Use same-origin for full cross-origin isolation".to_string(),
                     None, None, 3)
                } else {
                    ("warning".to_string(), "low".to_string(),
                     "COOP may not provide optimal isolation".to_string(),
                     "Use same-origin for cross-origin isolation".to_string(),
                     None, None, 2)
                }
            }
            "cross-origin-resource-policy" => {
                let lower = value.trim().to_lowercase();
                if lower == "same-origin" || lower == "same-site" {
                    ("good".to_string(), "info".to_string(),
                     "CORP is properly configured".to_string(),
                     "Well configured".to_string(), None, None, 5)
                } else if lower == "cross-origin" {
                    ("warning".to_string(), "medium".to_string(),
                     "CORP is set to cross-origin, allowing all sites to embed resources".to_string(),
                     "Use same-origin or same-site for better protection".to_string(),
                     None, None, 2)
                } else {
                    ("warning".to_string(), "low".to_string(),
                     "CORP has an unrecognized value".to_string(),
                     "Use same-origin or same-site".to_string(),
                     None, None, 2)
                }
            }
            "cross-origin-embedder-policy" => {
                let lower = value.trim().to_lowercase();
                if lower == "require-corp" {
                    ("good".to_string(), "info".to_string(),
                     "COEP is set to require-corp, enabling full cross-origin isolation".to_string(),
                     "Well configured".to_string(), None, None, 5)
                } else if lower == "credentialless" {
                    ("good".to_string(), "info".to_string(),
                     "COEP is set to credentialless".to_string(),
                     "Well configured".to_string(), None, None, 5)
                } else {
                    ("warning".to_string(), "low".to_string(),
                     "COEP may not provide cross-origin isolation".to_string(),
                     "Use require-corp or credentialless".to_string(),
                     None, None, 2)
                }
            }
            "x-xss-protection" => {
                if value.contains("1; mode=block") {
                    ("good".to_string(), "info".to_string(),
                     "X-XSS-Protection is set to 1; mode=block for legacy browser support".to_string(),
                     "Consider setting to 0 as modern browsers use CSP instead".to_string(),
                     None, None, 3)
                } else if value.contains("1") {
                    ("warning".to_string(), "info".to_string(),
                     "X-XSS-Protection is enabled without mode=block, which can introduce vulnerabilities".to_string(),
                     "Set to '0' (recommended) or '1; mode=block'".to_string(),
                     Some("CWE-79".to_string()), None, 2)
                } else if value.contains("0") {
                    ("good".to_string(), "info".to_string(),
                     "X-XSS-Protection is disabled (recommended for modern browsers with CSP)".to_string(),
                     "Well configured. Ensure CSP is properly set".to_string(),
                     None, None, 3)
                } else {
                    ("warning".to_string(), "info".to_string(),
                     "X-XSS-Protection has an unrecognized value".to_string(),
                     "Set to '0' for modern browsers or '1; mode=block' for legacy support".to_string(),
                     None, None, 1)
                }
            }
            "x-permitted-cross-domain-policies" => {
                let lower = value.trim().to_lowercase();
                if lower == "none" {
                    ("good".to_string(), "info".to_string(),
                     "X-Permitted-Cross-Domain-Policies is set to none, blocking cross-domain access".to_string(),
                     "Well configured".to_string(), None, None, 3)
                } else if lower == "master-only" {
                    ("warning".to_string(), "low".to_string(),
                     "X-Permitted-Cross-Domain-Policies allows master-only policy".to_string(),
                     "Use 'none' for maximum security".to_string(), None, None, 2)
                } else {
                    ("warning".to_string(), "medium".to_string(),
                     "X-Permitted-Cross-Domain-Policies may allow cross-domain access".to_string(),
                     "Set to 'none' to block all cross-domain access".to_string(),
                     None, None, 1)
                }
            }
            "cache-control" => {
                let lower = value.trim().to_lowercase();
                let has_no_store = lower.contains("no-store");
                let has_no_cache = lower.contains("no-cache");
                let has_private = lower.contains("private");
                let has_public = lower.contains("public");

                if has_no_store && has_no_cache {
                    ("good".to_string(), "info".to_string(),
                     "Cache-Control properly prevents caching with no-store and no-cache".to_string(),
                     "Well configured for sensitive content".to_string(), None, None, 5)
                } else if has_no_store {
                    ("good".to_string(), "info".to_string(),
                     "Cache-Control uses no-store to prevent caching".to_string(),
                     "Consider adding no-cache for additional protection".to_string(), None, None, 4)
                } else if has_private && !has_public {
                    ("warning".to_string(), "low".to_string(),
                     "Cache-Control uses private but content may still be cached".to_string(),
                     "Use no-store for sensitive content to prevent any caching".to_string(),
                     Some("CWE-524".to_string()), None, 3)
                } else if has_public {
                    ("warning".to_string(), "medium".to_string(),
                     "Cache-Control allows public caching, which may expose sensitive data".to_string(),
                     "Use no-store for sensitive content or private for semi-sensitive content".to_string(),
                     Some("CWE-524".to_string()), None, 1)
                } else {
                    ("warning".to_string(), "low".to_string(),
                     "Cache-Control is present but may not adequately prevent caching".to_string(),
                     "Add no-store, no-cache for sensitive content".to_string(),
                     None, None, 2)
                }
            }
            _ => ("info".to_string(), "info".to_string(), "Unknown header".to_string(), String::new(), None, None, 0),
        }
    }

    fn analyze_csp(value: &str, is_report_only: bool) -> CspAnalysis {
        let mut directives: Vec<CspDirective> = Vec::new();
        let mut has_default_src = false;
        let mut has_script_src = false;
        let mut has_style_src = false;
        let mut has_img_src = false;
        let mut has_connect_src = false;
        let mut has_frame_src = false;
        let mut has_object_src = false;
        let mut has_base_uri = false;
        let mut has_form_action = false;
        let mut has_frame_ancestors = false;
        let mut uses_unsafe_inline = false;
        let mut uses_unsafe_eval = false;
        let mut uses_nonce = false;
        let mut uses_hash = false;
        let mut has_report_uri = false;
        let mut score = 20i32;

        if is_report_only {
            score -= 10;
        }

        for part in value.split(';') {
            let part = part.trim();
            if part.is_empty() { continue; }

            let mut parts = part.splitn(2, ' ');
            let directive_name = parts.next().unwrap_or("").to_lowercase();
            let directive_value = parts.next().unwrap_or("").to_string();

            let mut is_secure = true;
            let mut dir_issues: Vec<String> = Vec::new();

            match directive_name.as_str() {
                "default-src" => { has_default_src = true; }
                "script-src" => {
                    has_script_src = true;
                    if directive_value.contains("'unsafe-inline'") {
                        uses_unsafe_inline = true;
                        is_secure = false;
                        dir_issues.push("Allows unsafe-inline scripts".to_string());
                        score -= 5;
                    }
                    if directive_value.contains("'unsafe-eval'") {
                        uses_unsafe_eval = true;
                        is_secure = false;
                        dir_issues.push("Allows unsafe-eval".to_string());
                        score -= 5;
                    }
                    if directive_value.contains("nonce-") { uses_nonce = true; score += 2; }
                    if directive_value.contains("'sha") { uses_hash = true; score += 2; }
                    if directive_value.contains("*") && !directive_value.contains("'nonce-") && !directive_value.contains("'sha") {
                        is_secure = false;
                        dir_issues.push("Wildcard source allows scripts from anywhere".to_string());
                        score -= 3;
                    }
                }
                "style-src" => {
                    has_style_src = true;
                    if directive_value.contains("'unsafe-inline'") {
                        dir_issues.push("Allows unsafe-inline styles (common for CSS frameworks)".to_string());
                    }
                }
                "img-src" => { has_img_src = true; }
                "connect-src" => { has_connect_src = true; }
                "frame-src" => { has_frame_src = true; }
                "object-src" => {
                    has_object_src = true;
                    if directive_value.contains("'none'") { score += 2; }
                    else if !directive_value.is_empty() {
                        is_secure = false;
                        dir_issues.push("Should be set to 'none' to block plugins".to_string());
                        score -= 2;
                    }
                }
                "base-uri" => { has_base_uri = true; score += 1; }
                "form-action" => { has_form_action = true; score += 1; }
                "frame-ancestors" => { has_frame_ancestors = true; score += 1; }
                "report-uri" | "report-to" => { has_report_uri = true; score += 1; }
                _ => {}
            }

            directives.push(CspDirective {
                directive: directive_name,
                value: directive_value,
                is_secure,
                issues: dir_issues,
            });
        }

        if !has_default_src { score -= 3; }
        if !has_script_src { score -= 2; }
        if !has_object_src { score -= 2; }
        if !has_base_uri { score -= 1; }

        score = score.clamp(0, 20);

        let overall_assessment = if is_report_only {
            "CSP is in Report-Only mode - violations are logged but NOT enforced. Deploy enforcement policy for protection.".to_string()
        } else if score >= 18 {
            "Excellent CSP configuration".to_string()
        } else if score >= 14 {
            "Good CSP configuration with minor improvements needed".to_string()
        } else if score >= 10 {
            "Moderate CSP configuration - several improvements recommended".to_string()
        } else if score > 0 {
            "Weak CSP configuration - significant improvements needed".to_string()
        } else {
            "CSP is present but severely misconfigured".to_string()
        };

        CspAnalysis {
            raw_value: value.to_string(),
            directives,
            has_default_src,
            has_script_src,
            has_style_src,
            has_img_src,
            has_connect_src,
            has_frame_src,
            has_object_src,
            has_base_uri,
            has_form_action,
            has_frame_ancestors,
            uses_unsafe_inline,
            uses_unsafe_eval,
            uses_nonce,
            uses_hash,
            has_report_uri,
            is_report_only,
            overall_assessment,
            score,
        }
    }

    fn analyze_hsts(value: &str) -> HstsAnalysis {
        let max_age: i64 = value.split(';')
            .find_map(|part| {
                part.trim().strip_prefix("max-age=")
                    .or_else(|| part.trim().strip_prefix("Max-Age="))
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(0);

        let include_sub_domains = value.to_lowercase().contains("includesubdomains");
        let preload = value.to_lowercase().contains("preload");

        let mut hsts_issues: Vec<String> = Vec::new();
        let mut score = 15i32;

        if max_age < 31536000 && max_age > 0 {
            hsts_issues.push(format!("max-age is {} seconds, should be at least 31536000 (1 year)", max_age));
            score -= 5;
        }
        if max_age == 0 {
            hsts_issues.push("max-age is 0, effectively disabling HSTS".to_string());
            score = 0;
        }
        if !include_sub_domains {
            hsts_issues.push("Missing includeSubDomains directive".to_string());
            score -= 2;
        }
        if !preload {
            hsts_issues.push("Missing preload directive".to_string());
            score -= 1;
        }

        score = score.clamp(0, 15);

        HstsAnalysis {
            raw_value: value.to_string(),
            max_age,
            include_sub_domains,
            preload,
            is_secure: max_age >= 31536000 && include_sub_domains,
            issues: hsts_issues,
            score,
        }
    }

    fn check_information_leakage(headers: &HeaderMap) -> Vec<InformationLeakage> {
        let mut leakage: Vec<InformationLeakage> = Vec::new();

        if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
            let server_str = server.to_string();
            let risk = if server_str.contains('/') || server_str.len() > 20 {
                "medium"
            } else {
                "low"
            };
            leakage.push(InformationLeakage {
                header_name: "Server".to_string(),
                value: server_str.clone(),
                risk_level: risk.to_string(),
                description: format!("Server header reveals technology: {}", server_str),
                recommendation: "Remove or obfuscate the Server header".to_string(),
            });
        }

        if let Some(powered_by) = headers.get("x-powered-by").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Powered-By".to_string(),
                value: powered_by.to_string(),
                risk_level: "medium".to_string(),
                description: format!("X-Powered-By reveals technology: {}", powered_by),
                recommendation: "Remove the X-Powered-By header".to_string(),
            });
        }

        if let Some(aspnet) = headers.get("x-aspnet-version").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-AspNet-Version".to_string(),
                value: aspnet.to_string(),
                risk_level: "medium".to_string(),
                description: "X-AspNet-Version reveals ASP.NET version".to_string(),
                recommendation: "Remove the X-AspNet-Version header in web.config".to_string(),
            });
        }

        if let Some(aspnetmvc) = headers.get("x-aspnetmvc-version").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-AspNetMvc-Version".to_string(),
                value: aspnetmvc.to_string(),
                risk_level: "medium".to_string(),
                description: "X-AspNetMvc-Version reveals MVC version".to_string(),
                recommendation: "Remove the X-AspNetMvc-Version header".to_string(),
            });
        }

        if let Some(generator) = headers.get("x-generator").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Generator".to_string(),
                value: generator.to_string(),
                risk_level: "low".to_string(),
                description: "X-Generator reveals CMS/platform".to_string(),
                recommendation: "Remove the X-Generator header".to_string(),
            });
        }

        if let Some(via) = headers.get("via").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "Via".to_string(),
                value: via.to_string(),
                risk_level: "low".to_string(),
                description: format!("Via header reveals proxy/CDN infrastructure: {}", via),
                recommendation: "Remove or obfuscate the Via header if possible".to_string(),
            });
        }

        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Forwarded-For".to_string(),
                value: xff.to_string(),
                risk_level: "low".to_string(),
                description: "X-Forwarded-For reveals internal IP addresses or proxy chain".to_string(),
                recommendation: "Sanitize X-Forwarded-For before sending to clients".to_string(),
            });
        }

        if let Some(debug_token) = headers.get("x-debug-token").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Debug-Token".to_string(),
                value: debug_token.to_string(),
                risk_level: "high".to_string(),
                description: "X-Debug-Token indicates debug mode is enabled (likely Symfony)".to_string(),
                recommendation: "Disable debug mode in production environment".to_string(),
            });
        }

        if let Some(debug_link) = headers.get("x-debug-token-link").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Debug-Token-Link".to_string(),
                value: debug_link.to_string(),
                risk_level: "high".to_string(),
                description: "X-Debug-Token-Link exposes debug panel URL".to_string(),
                recommendation: "Disable debug mode and remove debug headers in production".to_string(),
            });
        }

        if let Some(runtime) = headers.get("x-runtime").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Runtime".to_string(),
                value: runtime.to_string(),
                risk_level: "low".to_string(),
                description: "X-Runtime reveals server processing time, useful for timing attacks".to_string(),
                recommendation: "Remove the X-Runtime header in production".to_string(),
            });
        }

        if let Some(varnish) = headers.get("x-varnish").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Varnish".to_string(),
                value: varnish.to_string(),
                risk_level: "low".to_string(),
                description: "X-Varnish reveals Varnish cache server and cache hit/miss status".to_string(),
                recommendation: "Remove or obfuscate the X-Varnish header".to_string(),
            });
        }

        if let Some(drupal) = headers.get("x-drupal-cache").and_then(|v| v.to_str().ok()) {
            leakage.push(InformationLeakage {
                header_name: "X-Drupal-Cache".to_string(),
                value: drupal.to_string(),
                risk_level: "low".to_string(),
                description: "X-Drupal-Cache reveals Drupal CMS and cache status".to_string(),
                recommendation: "Remove the X-Drupal-Cache header".to_string(),
            });
        }

        if let Some(request_id) = headers.get("x-request-id").and_then(|v| v.to_str().ok()) {
            if request_id.len() > 36 {
                leakage.push(InformationLeakage {
                    header_name: "X-Request-ID".to_string(),
                    value: request_id.to_string(),
                    risk_level: "info".to_string(),
                    description: "X-Request-ID may reveal internal request tracking format".to_string(),
                    recommendation: "Use UUID format for request IDs to avoid information leakage".to_string(),
                });
            }
        }

        leakage
    }

    fn check_cookie_security(headers: &HeaderMap) -> Vec<CookieSecurityInfo> {
        let mut cookies: Vec<CookieSecurityInfo> = Vec::new();

        for value in headers.get_all("set-cookie") {
            if let Ok(cookie_str) = value.to_str() {
                let lower = cookie_str.to_lowercase();
                let name = cookie_str.split('=').next().unwrap_or("unknown").trim().to_string();
                let has_httponly = lower.contains("httponly");
                let has_secure = lower.contains("secure");
                let has_samesite = lower.contains("samesite");

                let samesite_value = if has_samesite {
                    lower.split("samesite")
                        .nth(1)
                        .and_then(|rest| rest.trim_start_matches(|c: char| c == '=' || c == ' ').split(';').next())
                        .map(|v| v.trim().to_string())
                } else {
                    None
                };

                let path_value = if lower.contains("path") {
                    lower.split("path")
                        .nth(1)
                        .and_then(|rest| rest.trim_start_matches(|c: char| c == '=' || c == ' ').split(';').next())
                        .map(|v| v.trim().to_string())
                } else {
                    None
                };
                let has_path = path_value.is_some();

                let domain_value = if lower.contains("domain") {
                    lower.split("domain")
                        .nth(1)
                        .and_then(|rest| rest.trim_start_matches(|c: char| c == '=' || c == ' ').split(';').next())
                        .map(|v| v.trim().to_string())
                } else {
                    None
                };
                let has_domain = domain_value.is_some();

                let is_session_cookie = !lower.contains("max-age") && !lower.contains("expires");

                let mut risk_level = "info".to_string();
                let mut issues: Vec<String> = Vec::new();

                if !has_secure {
                    risk_level = "high".to_string();
                    issues.push("Cookie lacks Secure flag - can be sent over HTTP".to_string());
                }
                if !has_httponly {
                    if risk_level != "high" { risk_level = "medium".to_string(); }
                    issues.push("Cookie lacks HttpOnly flag - accessible via JavaScript".to_string());
                }
                if !has_samesite {
                    if risk_level == "info" { risk_level = "low".to_string(); }
                    issues.push("Cookie lacks SameSite attribute - vulnerable to CSRF".to_string());
                } else if let Some(ref sv) = samesite_value {
                    if sv == "none" {
                        if risk_level == "info" { risk_level = "medium".to_string(); }
                        issues.push("SameSite=None allows cross-site cookie sending (requires Secure flag)".to_string());
                    } else if sv == "lax" {
                        if risk_level == "info" { risk_level = "low".to_string(); }
                        issues.push("SameSite=Lax provides partial CSRF protection".to_string());
                    }
                }
                if let Some(ref pv) = path_value {
                    if pv == "/" {
                        if risk_level == "info" { risk_level = "low".to_string(); }
                        issues.push("Cookie path is root '/' - accessible from all paths".to_string());
                    }
                }
                if let Some(ref dv) = domain_value {
                    if dv.starts_with('.') {
                        if risk_level == "info" { risk_level = "low".to_string(); }
                        issues.push(format!("Cookie domain '{}' includes all subdomains", dv));
                    }
                }

                let issue = if issues.is_empty() { None } else { Some(issues.join("; ")) };

                cookies.push(CookieSecurityInfo {
                    name,
                    has_httponly,
                    has_secure,
                    has_samesite,
                    samesite_value,
                    has_path,
                    path_value,
                    has_domain,
                    domain_value,
                    is_session_cookie,
                    risk_level,
                    issue,
                });
            }
        }

        cookies
    }

    fn calculate_score(
        present: &[HeaderDetail],
        missing: &[HeaderDetail],
        csp_analysis: &Option<CspAnalysis>,
        hsts_analysis: &Option<HstsAnalysis>,
    ) -> i32 {
        let mut score = 0i32;

        for h in present {
            score += match h.status.as_str() {
                "good" => h.importance,
                "warning" => h.importance / 2,
                "bad" => 0,
                _ => 0,
            };
        }

        if let Some(csp) = csp_analysis {
            score = score - 20 + csp.score;
        } else {
            let csp_missing = missing.iter().any(|h| h.name == "Content-Security-Policy");
            if csp_missing {
                score -= 10;
            }
        }

        if let Some(hsts) = hsts_analysis {
            score = score - 15 + hsts.score;
        } else {
            let hsts_missing = missing.iter().any(|h| h.name == "Strict-Transport-Security");
            if hsts_missing {
                score -= 8;
            }
        }

        score.clamp(0, 100)
    }

    fn score_to_grade(score: i32) -> String {
        match score {
            s if s >= 90 => "A".to_string(),
            s if s >= 75 => "B".to_string(),
            s if s >= 60 => "C".to_string(),
            s if s >= 40 => "D".to_string(),
            _ => "F".to_string(),
        }
    }

    fn calculate_severity_stats(issues: &[HeaderIssue]) -> SeverityStats {
        let mut stats = SeverityStats { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for issue in issues {
            match issue.severity.as_str() {
                "critical" => stats.critical += 1,
                "high" => stats.high += 1,
                "medium" => stats.medium += 1,
                "low" => stats.low += 1,
                _ => stats.info += 1,
            }
        }
        stats
    }

    fn calculate_category_stats(present: &[HeaderDetail], missing: &[HeaderDetail]) -> Vec<CategoryStat> {
        let mut category_map: std::collections::HashMap<String, (i32, i32, i32)> = std::collections::HashMap::new();

        for h in present {
            let entry = category_map.entry(h.category.clone()).or_insert((0, 0, 0));
            entry.0 += 1;
            entry.2 += match h.status.as_str() {
                "good" => h.importance,
                "warning" => h.importance / 2,
                _ => 0,
            };
        }

        for h in missing {
            let entry = category_map.entry(h.category.clone()).or_insert((0, 0, 0));
            entry.1 += 1;
        }

        let mut result: Vec<CategoryStat> = category_map.into_iter().map(|(category, (present_count, missing_count, actual_score))| {
            let max_score = (present_count + missing_count) * 20;
            CategoryStat {
                category,
                count: present_count + missing_count,
                max_score,
                actual_score,
            }
        }).collect();

        result.sort_by(|a, b| b.actual_score.cmp(&a.actual_score));
        result
    }
}
