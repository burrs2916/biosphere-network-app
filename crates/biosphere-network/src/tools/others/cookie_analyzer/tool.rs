use std::collections::HashMap;
use std::time::{Duration, Instant};
use reqwest::Client;
use crate::core::{Result, ToolError};
use super::config::*;

pub struct CookieAnalyzerTool;

impl CookieAnalyzerTool {
    pub async fn analyze(config: &CookieAnalyzerConfig) -> Result<CookieAnalyzerResult> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let is_https = target_url.starts_with("https://");
        let base_domain = Self::extract_domain(&target_url);

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .user_agent(
                config.user_agent.as_deref().unwrap_or(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            );

        if config.follow_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::limited(5));
        } else {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        if !config.verify_ssl {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref proxy) = config.proxy_url {
            if !proxy.is_empty() {
                if let Ok(proxy_parsed) = reqwest::Proxy::all(proxy.as_str()) {
                    client_builder = client_builder.proxy(proxy_parsed);
                }
            }
        }

        let client = client_builder
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut request = client.get(&target_url);
        if let Some(ref headers_str) = config.custom_headers {
            for line in headers_str.lines() {
                let line = line.trim();
                if let Some(colon_pos) = line.find(':') {
                    let key = line[..colon_pos].trim();
                    let val = line[colon_pos + 1..].trim();
                    if !key.is_empty() && !val.is_empty() {
                        request = request.header(key, val);
                    }
                }
            }
        }

        let resp = request.send().await
            .map_err(|e| ToolError::ExecutionError(format!("Request failed: {}", e)))?;

        let headers = resp.headers().clone();
        let mut cookies: Vec<CookieInfo> = Vec::new();
        let mut issues: Vec<CookieIssue> = Vec::new();

        for value in headers.get_all("set-cookie") {
            if let Ok(cookie_str) = value.to_str() {
                let cookie = Self::parse_cookie(cookie_str, &base_domain);
                cookies.push(cookie);
            }
        }

        let response_headers = Self::analyze_response_headers(&headers);
        let mut gdpr_issues: Vec<String> = Vec::new();
        let mut pci_dss_issues: Vec<String> = Vec::new();
        let mut owasp_issues: Vec<String> = Vec::new();

        for cookie in &cookies {
            let name_lower = cookie.name.to_lowercase();

            if !cookie.secure && is_https {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Missing Secure Flag".to_string(),
                    severity: "high".to_string(),
                    category: "Transport Security".to_string(),
                    description: "Cookie lacks the Secure flag and will be sent over unencrypted connections, exposing it to man-in-the-middle attacks".to_string(),
                    recommendation: "Add the Secure flag to ensure the cookie is only sent over HTTPS connections".to_string(),
                    cwe_id: Some("CWE-614".to_string()),
                    owasp_category: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }

            if !cookie.http_only && Self::is_sensitive_cookie(&name_lower) {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Missing HttpOnly Flag".to_string(),
                    severity: "high".to_string(),
                    category: "XSS Protection".to_string(),
                    description: "Sensitive cookie lacks HttpOnly flag and is accessible via JavaScript, making it vulnerable to XSS-based cookie theft".to_string(),
                    recommendation: "Add the HttpOnly flag to prevent client-side scripts from accessing the cookie".to_string(),
                    cwe_id: Some("CWE-1004".to_string()),
                    owasp_category: Some("A03:2021 - Injection".to_string()),
                });
            }

            if cookie.same_site.is_none() && Self::is_sensitive_cookie(&name_lower) {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Missing SameSite Attribute".to_string(),
                    severity: "medium".to_string(),
                    category: "CSRF Protection".to_string(),
                    description: "Cookie lacks SameSite attribute, making it vulnerable to cross-site request forgery (CSRF) attacks".to_string(),
                    recommendation: "Add SameSite=Strict or SameSite=Lax to prevent CSRF attacks".to_string(),
                    cwe_id: Some("CWE-352".to_string()),
                    owasp_category: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }

            if cookie.same_site.as_deref() == Some("None") && !cookie.secure {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "SameSite=None without Secure".to_string(),
                    severity: "high".to_string(),
                    category: "Browser Compatibility".to_string(),
                    description: "SameSite=None requires the Secure flag; modern browsers will reject this cookie".to_string(),
                    recommendation: "Either add the Secure flag or change SameSite to Lax/Strict".to_string(),
                    cwe_id: Some("CWE-614".to_string()),
                    owasp_category: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }

            if cookie.is_session && Self::is_sensitive_cookie(&name_lower) {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Session Cookie Without Expiry".to_string(),
                    severity: "low".to_string(),
                    category: "Session Management".to_string(),
                    description: "Session cookie has no expiration; it will persist until browser closes, increasing the window for session hijacking".to_string(),
                    recommendation: "Consider setting an appropriate expiration for session cookies to limit the attack window".to_string(),
                    cwe_id: Some("CWE-613".to_string()),
                    owasp_category: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                });
            }

            if cookie.domain.as_ref().map(|d| d.starts_with('.')).unwrap_or(false) {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Overly Broad Domain".to_string(),
                    severity: "medium".to_string(),
                    category: "Scope Control".to_string(),
                    description: format!("Cookie domain '{}' starts with a dot, making it accessible to all subdomains", cookie.domain.as_ref().unwrap()),
                    recommendation: "Use a more specific domain to limit cookie scope and prevent subdomain-based attacks".to_string(),
                    cwe_id: Some("CWE-284".to_string()),
                    owasp_category: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }

            if cookie.path.as_deref() == Some("/") && Self::is_sensitive_cookie(&name_lower) {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Overly Broad Path".to_string(),
                    severity: "low".to_string(),
                    category: "Scope Control".to_string(),
                    description: "Cookie path is '/' making it accessible across the entire site".to_string(),
                    recommendation: "Restrict the cookie path to the specific directory that needs it".to_string(),
                    cwe_id: Some("CWE-284".to_string()),
                    owasp_category: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }

            if cookie.value_length > 4096 {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Oversized Cookie".to_string(),
                    severity: "info".to_string(),
                    category: "Performance".to_string(),
                    description: format!("Cookie value is {} bytes, exceeding the 4096 byte recommended limit", cookie.value_length),
                    recommendation: "Reduce cookie size to improve performance and avoid browser truncation".to_string(),
                    cwe_id: None,
                    owasp_category: None,
                });
            }

            if cookie.is_third_party {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Third-Party Cookie".to_string(),
                    severity: "info".to_string(),
                    category: "Privacy".to_string(),
                    description: format!("Cookie domain '{}' differs from the target domain '{}', classified as a third-party cookie", cookie.domain.as_deref().unwrap_or("unknown"), base_domain),
                    recommendation: "Review third-party cookies for privacy compliance; many browsers are blocking them by default".to_string(),
                    cwe_id: None,
                    owasp_category: None,
                });
            }

            if !cookie.has_prefix() && Self::is_sensitive_cookie(&name_lower) {
                issues.push(CookieIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "Missing Cookie Prefix".to_string(),
                    severity: "low".to_string(),
                    category: "Defense in Depth".to_string(),
                    description: "Sensitive cookie does not use __Secure- or __Host- prefix for additional protection".to_string(),
                    recommendation: "Consider using __Secure- prefix (requires Secure flag) or __Host- prefix (requires Secure, no Domain, Path=/)".to_string(),
                    cwe_id: None,
                    owasp_category: None,
                });
            }

            if config.check_compliance {
                if cookie.is_session && Self::is_tracking_cookie(&name_lower) {
                    gdpr_issues.push(format!("Tracking cookie '{}' has no expiry (GDPR Art. 5(1)(e))", cookie.name));
                }
                if !cookie.secure {
                    pci_dss_issues.push(format!("Cookie '{}' lacks Secure flag (PCI DSS Req. 4.1)", cookie.name));
                }
                if !cookie.http_only && Self::is_sensitive_cookie(&name_lower) {
                    owasp_issues.push(format!("Cookie '{}' lacks HttpOnly flag (OWASP Session Management)", cookie.name));
                }
                if cookie.same_site.is_none() {
                    owasp_issues.push(format!("Cookie '{}' lacks SameSite attribute (OWASP CSRF Prevention)", cookie.name));
                }
            }
        }

        if config.check_js_cookies {
            if cookies.iter().any(|c| !c.http_only) {
                let js_accessible: Vec<&CookieInfo> = cookies.iter().filter(|c| !c.http_only).collect();
                if js_accessible.iter().any(|c| Self::is_sensitive_cookie(&c.name.to_lowercase())) {
                    issues.push(CookieIssue {
                        cookie_name: "Multiple".to_string(),
                        issue_type: "JavaScript-Accessible Sensitive Cookies".to_string(),
                        severity: "medium".to_string(),
                        category: "XSS Protection".to_string(),
                        description: format!("{} sensitive cookies are accessible via JavaScript, increasing XSS attack impact", js_accessible.iter().filter(|c| Self::is_sensitive_cookie(&c.name.to_lowercase())).count()),
                        recommendation: "Set HttpOnly flag on all sensitive cookies to minimize XSS attack surface".to_string(),
                        cwe_id: Some("CWE-1004".to_string()),
                        owasp_category: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        if !response_headers.has_strict_transport && is_https {
            issues.push(CookieIssue {
                cookie_name: "N/A".to_string(),
                issue_type: "Missing HSTS Header".to_string(),
                severity: "medium".to_string(),
                category: "Transport Security".to_string(),
                description: "Strict-Transport-Security header is not set, allowing downgrade attacks from HTTPS to HTTP".to_string(),
                recommendation: "Add Strict-Transport-Security header (e.g., max-age=31536000; includeSubDomains)".to_string(),
                cwe_id: Some("CWE-319".to_string()),
                owasp_category: Some("A02:2021 - Cryptographic Failures".to_string()),
            });
        }

        if cookies.is_empty() {
            let scan_duration = start.elapsed().as_millis() as u64;
            return Ok(CookieAnalyzerResult {
                url: target_url,
                cookies: vec![],
                issues: vec![],
                score: 100,
                grade: "A".to_string(),
                summary: "No cookies found in response".to_string(),
                severity_stats: SeverityStats { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                category_stats: vec![],
                compliance_report: ComplianceReport {
                    gdpr_compliant: true,
                    pci_dss_compliant: true,
                    owasp_compliant: true,
                    gdpr_issues: vec![],
                    pci_dss_issues: vec![],
                    owasp_issues: vec![],
                    overall_compliance_score: 100,
                },
                response_headers,
                scan_duration_ms: scan_duration,
            });
        }

        let severity_stats = SeverityStats {
            critical: issues.iter().filter(|i| i.severity == "critical").count(),
            high: issues.iter().filter(|i| i.severity == "high").count(),
            medium: issues.iter().filter(|i| i.severity == "medium").count(),
            low: issues.iter().filter(|i| i.severity == "low").count(),
            info: issues.iter().filter(|i| i.severity == "info").count(),
        };

        let mut category_map: HashMap<String, (usize, usize, usize)> = HashMap::new();
        for issue in &issues {
            let entry = category_map.entry(issue.category.clone()).or_insert((0, 0, 0));
            entry.0 += 1;
            if issue.severity == "critical" { entry.1 += 1; }
            if issue.severity == "high" { entry.2 += 1; }
        }
        let category_stats: Vec<CategoryStat> = category_map
            .into_iter()
            .map(|(category, (count, critical_count, high_count))| CategoryStat {
                category,
                count,
                critical_count,
                high_count,
            })
            .collect();

        let issue_deductions: i32 = issues.iter().map(|i| match i.severity.as_str() {
            "critical" => 20,
            "high" => 15,
            "medium" => 8,
            "low" => 3,
            "info" => 1,
            _ => 0,
        }).sum();
        let score = (100 - issue_deductions).max(0);

        let grade = match score {
            90..=100 => "A",
            80..=89 => "B",
            70..=79 => "C",
            60..=69 => "D",
            _ => "F",
        };

        let high_count = severity_stats.high;
        let medium_count = severity_stats.medium;
        let low_count = severity_stats.low;
        let critical_count = severity_stats.critical;

        let summary = if critical_count > 0 {
            format!("CRITICAL: {} cookies analyzed, {} critical, {} high, {} medium, {} low issues - Score: {}/100 ({})", cookies.len(), critical_count, high_count, medium_count, low_count, score, grade)
        } else {
            format!("Analyzed {} cookies, found {} issues ({} high, {} medium, {} low) - Score: {}/100 ({})", cookies.len(), issues.len(), high_count, medium_count, low_count, score, grade)
        };

        let gdpr_compliant = gdpr_issues.is_empty();
        let pci_dss_compliant = pci_dss_issues.is_empty();
        let owasp_compliant = owasp_issues.is_empty();
        let compliance_deductions = (gdpr_issues.len() + pci_dss_issues.len() + owasp_issues.len()) as i32 * 5;
        let overall_compliance_score = (100 - compliance_deductions).max(0);

        let scan_duration = start.elapsed().as_millis() as u64;

        Ok(CookieAnalyzerResult {
            url: target_url,
            cookies,
            issues,
            score,
            grade: grade.to_string(),
            summary,
            severity_stats,
            category_stats,
            compliance_report: ComplianceReport {
                gdpr_compliant,
                pci_dss_compliant,
                owasp_compliant,
                gdpr_issues,
                pci_dss_issues,
                owasp_issues,
                overall_compliance_score,
            },
            response_headers,
            scan_duration_ms: scan_duration,
        })
    }

    fn parse_cookie(cookie_str: &str, base_domain: &str) -> CookieInfo {
        let parts: Vec<&str> = cookie_str.split(';').collect();
        let mut name = String::new();
        let mut value_preview = String::new();
        let mut value_length: usize = 0;
        let mut domain: Option<String> = None;
        let mut path: Option<String> = None;
        let mut expires: Option<String> = None;
        let mut max_age: Option<i64> = None;
        let mut http_only = false;
        let mut secure = false;
        let mut same_site: Option<String> = None;

        if let Some(first) = parts.first() {
            if let Some(eq_pos) = first.find('=') {
                name = first[..eq_pos].trim().to_string();
                let val = first[eq_pos + 1..].trim();
                value_length = val.len();
                value_preview = if val.len() > 30 {
                    format!("{}...", &val[..15])
                } else {
                    val.to_string()
                };
            }
        }

        for part in parts.iter().skip(1) {
            let part = part.trim();
            let lower = part.to_lowercase();

            if lower == "httponly" {
                http_only = true;
            } else if lower == "secure" {
                secure = true;
            } else if lower.starts_with("domain=") {
                domain = Some(part[7..].trim().to_string());
            } else if lower.starts_with("path=") {
                path = Some(part[5..].trim().to_string());
            } else if lower.starts_with("expires=") {
                expires = Some(part[8..].trim().to_string());
            } else if lower.starts_with("max-age=") {
                let age_str = part[8..].trim();
                if let Ok(secs) = age_str.parse::<i64>() {
                    max_age = Some(secs);
                    if secs <= 0 {
                        expires = Some("Expired".to_string());
                    } else {
                        expires = Some(format!("{} seconds", secs));
                    }
                }
            } else if lower.starts_with("samesite=") {
                same_site = Some(part[9..].trim().to_string());
            }
        }

        let is_session = expires.is_none() && max_age.is_none();

        let cookie_domain = domain.as_deref().unwrap_or(base_domain);
        let is_third_party = !cookie_domain.contains(base_domain) && !base_domain.contains(cookie_domain.trim_start_matches('.'));

        let name_lower = name.to_lowercase();
        let cookie_category = Self::classify_cookie(&name_lower);
        let risk_level = Self::assess_risk_level(http_only, secure, same_site.as_deref(), is_session, &name_lower);

        let flags_status = CookieFlagsStatus {
            has_httponly: http_only,
            has_secure: secure,
            has_samesite: same_site.is_some(),
            has_path: path.is_some(),
            has_domain: domain.is_some(),
            has_expiry: expires.is_some() || max_age.is_some(),
            total_flags: [http_only, secure, same_site.is_some(), path.is_some(), domain.is_some(), expires.is_some() || max_age.is_some()].iter().filter(|&&x| x).count(),
            max_flags: 6,
        };

        CookieInfo {
            name,
            value_preview,
            value_length,
            domain,
            path,
            expires,
            max_age,
            http_only,
            secure,
            same_site,
            is_session,
            is_third_party,
            cookie_category,
            risk_level,
            flags_status,
        }
    }

    fn is_sensitive_cookie(name_lower: &str) -> bool {
        let sensitive_patterns = [
            "session", "sess", "token", "auth", "login", "sid",
            "phpsessid", "jsessionid", "asp.net", "csrf", "xsrf",
            "remember", "user", "pass", "key", "secret", "jwt",
            "access", "refresh", "id_token", "credential",
        ];
        sensitive_patterns.iter().any(|p| name_lower.contains(p))
    }

    fn is_tracking_cookie(name_lower: &str) -> bool {
        let tracking_patterns = [
            "_ga", "_gid", "_gat", "_fbp", "_fbc", "fr", "tr",
            "analytics", "track", "visitor", "utm", "ads",
            "doubleclick", "adsense", "marketing", "pixel",
            "_hjid", "_hjSession", "amplitude", "mixpanel",
            "intercom", "hubspot", "marketo", "salesforce",
        ];
        tracking_patterns.iter().any(|p| name_lower.contains(p))
    }

    fn classify_cookie(name_lower: &str) -> String {
        if Self::is_tracking_cookie(name_lower) {
            return "Tracking/Analytics".to_string();
        }
        if name_lower.contains("csrf") || name_lower.contains("xsrf") || name_lower.contains("token") {
            return "Security".to_string();
        }
        if name_lower.contains("session") || name_lower.contains("sess") || name_lower.contains("sid")
            || name_lower.contains("auth") || name_lower.contains("login") || name_lower.contains("remember") {
            return "Authentication".to_string();
        }
        if name_lower.contains("pref") || name_lower.contains("lang") || name_lower.contains("theme")
            || name_lower.contains("settings") || name_lower.contains("config") {
            return "Preferences".to_string();
        }
        if name_lower.contains("cart") || name_lower.contains("shop") || name_lower.contains("checkout") {
            return "E-Commerce".to_string();
        }
        if name_lower.contains("consent") || name_lower.contains("cookie") || name_lower.contains("gdpr")
            || name_lower.contains("privacy") {
            return "Consent/Privacy".to_string();
        }
        "Other".to_string()
    }

    fn assess_risk_level(http_only: bool, secure: bool, same_site: Option<&str>, is_session: bool, name_lower: &str) -> String {
        if !http_only && !secure && same_site.is_none() && Self::is_sensitive_cookie(name_lower) {
            return "critical".to_string();
        }
        if (!http_only || !secure) && Self::is_sensitive_cookie(name_lower) {
            return "high".to_string();
        }
        if same_site.is_none() && Self::is_sensitive_cookie(name_lower) {
            return "medium".to_string();
        }
        if is_session && Self::is_sensitive_cookie(name_lower) {
            return "medium".to_string();
        }
        if !secure || !http_only {
            return "low".to_string();
        }
        "info".to_string()
    }

    fn analyze_response_headers(headers: &reqwest::header::HeaderMap) -> ResponseHeaderInfo {
        let has_strict_transport = headers.contains_key("strict-transport-security");
        let has_x_content_type_options = headers.contains_key("x-content-type-options");
        let has_x_frame_options = headers.contains_key("x-frame-options");
        let has_csp = headers.contains_key("content-security-policy");

        let server_header = headers.get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let x_powered_by = headers.get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut security_score = 0;
        if has_strict_transport { security_score += 25; }
        if has_x_content_type_options { security_score += 25; }
        if has_x_frame_options { security_score += 25; }
        if has_csp { security_score += 25; }

        ResponseHeaderInfo {
            has_strict_transport,
            has_x_content_type_options,
            has_x_frame_options,
            has_csp,
            server_header,
            x_powered_by,
            security_headers_score: security_score,
        }
    }

    fn extract_domain(url: &str) -> String {
        let stripped = url.trim_start_matches("http://").trim_start_matches("https://");
        let domain = stripped.split('/').next().unwrap_or(stripped);
        domain.split(':').next().unwrap_or(domain).to_string()
    }
}

impl CookieInfo {
    fn has_prefix(&self) -> bool {
        self.name.starts_with("__Secure-") || self.name.starts_with("__Host-")
    }
}
