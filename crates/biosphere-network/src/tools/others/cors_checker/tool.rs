use std::sync::Arc;
use std::time::{Duration, Instant};
use reqwest::Client;
use tokio::sync::Semaphore;
use crate::core::{Result, ToolError};
use super::config::*;

pub struct CorsCheckerTool;

impl CorsCheckerTool {
    pub async fn check(config: &CorsCheckConfig) -> Result<CorsCheckResult> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let target_domain = Self::extract_domain(&target_url)
            .ok_or_else(|| ToolError::ExecutionError("Invalid URL".to_string()))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(reqwest::redirect::Policy::limited(3))
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut test_origins = config.test_origins.clone();
        if test_origins.is_empty() {
            test_origins = match config.scan_level.as_str() {
                "basic" => BASIC_ORIGINS.iter().map(|s| s.to_string()).collect(),
                "moderate" => {
                    let mut origins: Vec<String> = MODERATE_ORIGINS.iter().map(|s| s.to_string()).collect();
                    origins.push(format!("https://evil.{}", target_domain));
                    origins.push(format!("https://{}.evil.com", target_domain));
                    origins
                }
                "aggressive" => {
                    let mut origins: Vec<String> = AGGRESSIVE_ORIGINS.iter().map(|s| s.to_string()).collect();
                    origins.push(format!("https://evil.{}", target_domain));
                    origins.push(format!("https://{}.evil.com", target_domain));
                    origins.push(format!("http://{}", target_domain));
                    origins.push(format!("https://{}.spoofed.com", target_domain));
                    origins.push(format!("https://{}{}.evil.com", "a", target_domain));
                    origins
                }
                _ => MODERATE_ORIGINS.iter().map(|s| s.to_string()).collect(),
            };
        }

        let mut issues: Vec<CorsIssue> = Vec::new();
        let mut origin_results: Vec<CorsOriginResult> = Vec::new();
        let mut method_results: Vec<CorsMethodResult> = Vec::new();
        let mut tests_performed: usize = 0;

        let baseline_resp = client.get(&target_url).send().await
            .map_err(|e| ToolError::ExecutionError(format!("Baseline request failed: {}", e)))?;
        tests_performed += 1;

        let header_analysis = Self::analyze_headers(baseline_resp.headers());

        if let Some(ref acao) = header_analysis.acao_value {
            if acao == "*" {
                issues.push(CorsIssue {
                    issue_type: "Wildcard Origin".to_string(),
                    severity: "medium".to_string(),
                    description: "ACAO header is set to wildcard (*)".to_string(),
                    detail: "Access-Control-Allow-Origin: * allows any origin to access the resource. While browsers don't allow credentials with wildcard, this still exposes data to any origin.".to_string(),
                    recommendation: "Replace the wildcard with specific allowed origins.".to_string(),
                    confidence: 0.95,
                    origin: None,
                    method: Some("GET".to_string()),
                });
            }

            if header_analysis.acac_value.as_deref() == Some("true") && acao == "*" {
                issues.push(CorsIssue {
                    issue_type: "Wildcard + Credentials".to_string(),
                    severity: "high".to_string(),
                    description: "ACAO wildcard with credentials is a misconfiguration".to_string(),
                    detail: "Browsers block ACAO: * with credentials, but the server intent suggests misconfiguration and the server may reflect specific origins with credentials.".to_string(),
                    recommendation: "Never use wildcard origin with credentials. Specify exact origins.".to_string(),
                    confidence: 0.9,
                    origin: None,
                    method: Some("GET".to_string()),
                });
            }
        }

        let semaphore = Arc::new(Semaphore::new(config.threads.clamp(1, 20)));
        let mut join_set = tokio::task::JoinSet::new();

        for origin in &test_origins {
            let client = client.clone();
            let target_url = target_url.clone();
            let origin = origin.clone();
            let target_domain = target_domain.clone();
            let semaphore = semaphore.clone();

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let req_start = Instant::now();

                let resp = match client
                    .get(&target_url)
                    .header("Origin", &origin)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(_) => return None,
                };

                let response_time = req_start.elapsed().as_millis() as u64;
                let http_status = resp.status().as_u16();

                let acao = resp.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let acac = resp.headers()
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let acam = resp.headers()
                    .get("access-control-allow-methods")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let acah = resp.headers()
                    .get("access-control-allow-headers")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let allowed = acao.is_some();
                let allow_credentials = acac.as_deref() == Some("true");
                let is_wildcard = acao.as_deref() == Some("*");
                let is_null = origin == "null" && acao.is_some();
                let is_reflection = !is_wildcard && acao.as_ref().map(|a| a.to_lowercase() == origin.to_lowercase()).unwrap_or(false);
                let is_subdomain_bypass = !is_wildcard && acao.as_ref().map(|a| {
                    let a_lower = a.to_lowercase();
                    a_lower != origin.to_lowercase() && a_lower.contains(&target_domain.to_lowercase())
                }).unwrap_or(false);

                let risk_level = if is_null || (allowed && allow_credentials && !is_wildcard) {
                    "critical".to_string()
                } else if is_subdomain_bypass || (allowed && !is_wildcard && origin.contains("evil")) {
                    "high".to_string()
                } else if is_wildcard {
                    "medium".to_string()
                } else if allowed {
                    "low".to_string()
                } else {
                    "safe".to_string()
                };

                Some(CorsOriginResult {
                    origin,
                    allowed,
                    allow_credentials,
                    allow_methods: acam,
                    allow_headers: acah,
                    acao_header: acao,
                    acac_header: acac,
                    is_wildcard,
                    is_null,
                    is_subdomain_bypass,
                    is_reflection,
                    http_status: Some(http_status),
                    response_time_ms: Some(response_time),
                    risk_level,
                })
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(origin_result)) = result {
                tests_performed += 1;

                if origin_result.allowed && !origin_result.is_wildcard {
                    if origin_result.is_null {
                        issues.push(CorsIssue {
                            issue_type: "Null Origin Allowed".to_string(),
                            severity: "high".to_string(),
                            description: "Server allows 'null' origin".to_string(),
                            detail: "The null origin can be spoofed via iframe sandbox or data URI, allowing attackers to bypass CORS restrictions.".to_string(),
                            recommendation: "Do not allow 'null' origin in ACAO header.".to_string(),
                            confidence: 0.95,
                            origin: Some(origin_result.origin.clone()),
                            method: Some("GET".to_string()),
                        });
                    }

                    if origin_result.origin.contains("evil.com") || origin_result.origin.contains("attacker.com") {
                        if origin_result.allow_credentials {
                            issues.push(CorsIssue {
                                issue_type: "Arbitrary Origin with Credentials".to_string(),
                                severity: "critical".to_string(),
                                description: format!("Server allows origin '{}' with credentials", origin_result.origin),
                                detail: "An attacker can make authenticated cross-origin requests, stealing sensitive data including cookies and tokens.".to_string(),
                                recommendation: "Whitelist only trusted origins. Never reflect arbitrary origins with credentials.".to_string(),
                                confidence: 0.98,
                                origin: Some(origin_result.origin.clone()),
                                method: Some("GET".to_string()),
                            });
                        } else {
                            issues.push(CorsIssue {
                                issue_type: "Arbitrary Origin Allowed".to_string(),
                                severity: "high".to_string(),
                                description: format!("Server allows arbitrary origin '{}'", origin_result.origin),
                                detail: "Any origin can read responses, potentially exposing sensitive data.".to_string(),
                                recommendation: "Whitelist only trusted origins in the ACAO header.".to_string(),
                                confidence: 0.9,
                                origin: Some(origin_result.origin.clone()),
                                method: Some("GET".to_string()),
                            });
                        }
                    }

                    if origin_result.is_reflection && origin_result.allow_credentials {
                        issues.push(CorsIssue {
                            issue_type: "Origin Reflection with Credentials".to_string(),
                            severity: "critical".to_string(),
                            description: "Server reflects the Origin header and allows credentials".to_string(),
                            detail: format!("Origin '{}' was reflected in ACAO with credentials enabled. This is the most dangerous CORS misconfiguration.", origin_result.origin),
                            recommendation: "Validate the Origin against a whitelist before reflecting it. Never reflect arbitrary origins with credentials.".to_string(),
                            confidence: 0.97,
                            origin: Some(origin_result.origin.clone()),
                            method: Some("GET".to_string()),
                        });
                    }

                    if origin_result.is_subdomain_bypass {
                        issues.push(CorsIssue {
                            issue_type: "Subdomain Bypass".to_string(),
                            severity: "high".to_string(),
                            description: "Server trusts subdomain origins that could be attacker-controlled".to_string(),
                            detail: format!("Origin '{}' was allowed. If subdomains can be compromised, CORS can be bypassed.", origin_result.origin),
                            recommendation: "Only allow specific, trusted subdomains. Do not use pattern matching for origin validation.".to_string(),
                            confidence: 0.85,
                            origin: Some(origin_result.origin.clone()),
                            method: Some("GET".to_string()),
                        });
                    }
                }

                origin_results.push(origin_result);
            }
        }

        if config.test_methods {
            let method_results_data = Self::test_http_methods(
                &client, &target_url, &test_origins, &semaphore, &mut tests_performed,
            ).await;
            method_results = method_results_data;

            for mr in &method_results {
                if mr.is_allowed && mr.acao_header.is_some() {
                    let acao = mr.acao_header.as_ref().unwrap();
                    if acao != "*" {
                        issues.push(CorsIssue {
                            issue_type: "Method-Specific CORS".to_string(),
                            severity: "medium".to_string(),
                            description: format!("CORS allowed for {} method", mr.method),
                            detail: format!("The {} method is allowed via CORS. If this method is not needed, it should be restricted.", mr.method),
                            recommendation: format!("Restrict CORS access for {} method if not required.", mr.method),
                            confidence: 0.7,
                            origin: None,
                            method: Some(mr.method.clone()),
                        });
                    }
                }
            }
        }

        if config.test_preflight {
            tests_performed += Self::test_preflight_requests(
                &client, &target_url, &test_origins, &semaphore, &mut issues,
            ).await;
        }

        if config.test_headers {
            Self::analyze_security_headers(&header_analysis.security_headers, &mut issues);
        }

        let is_vulnerable = issues.iter().any(|i| i.severity == "critical" || i.severity == "high");
        let severity = if issues.iter().any(|i| i.severity == "critical") {
            "critical"
        } else if issues.iter().any(|i| i.severity == "high") {
            "high"
        } else if issues.iter().any(|i| i.severity == "medium") {
            "medium"
        } else if !issues.is_empty() {
            "low"
        } else {
            "info"
        };

        let security_score = Self::calculate_security_score(&issues, &origin_results, &header_analysis);

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        let summary = if issues.is_empty() {
            "No CORS misconfiguration detected. The target appears to have proper CORS configuration.".to_string()
        } else {
            let critical = issues.iter().filter(|i| i.severity == "critical").count();
            let high = issues.iter().filter(|i| i.severity == "high").count();
            let medium = issues.iter().filter(|i| i.severity == "medium").count();
            let low = issues.iter().filter(|i| i.severity == "low").count();
            format!("Found {} CORS issues ({} critical, {} high, {} medium, {} low). Security score: {:.0}/100",
                issues.len(), critical, high, medium, low, security_score)
        };

        Ok(CorsCheckResult {
            url: target_url,
            is_vulnerable,
            severity: severity.to_string(),
            security_score,
            issues,
            origin_results,
            method_results,
            header_analysis,
            tests_performed,
            scan_duration_ms,
            summary,
        })
    }

    fn analyze_headers(headers: &reqwest::header::HeaderMap) -> CorsHeaderAnalysis {
        let get_header = |name: &str| -> Option<String> {
            headers.get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_string())
        };

        let acao_value = get_header("access-control-allow-origin");
        let acac_value = get_header("access-control-allow-credentials");
        let acam_value = get_header("access-control-allow-methods");
        let acah_value = get_header("access-control-allow-headers");
        let acma_value = get_header("access-control-max-age");
        let acex_value = get_header("access-control-expose-headers");

        let vary_origin = headers.get("vary")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase().contains("origin"))
            .unwrap_or(false);

        let security_headers = SecurityHeadersAnalysis {
            has_csp: get_header("content-security-policy").is_some(),
            csp_value: get_header("content-security-policy"),
            has_hsts: get_header("strict-transport-security").is_some(),
            hsts_value: get_header("strict-transport-security"),
            has_xfo: get_header("x-frame-options").is_some(),
            xfo_value: get_header("x-frame-options"),
            has_xcto: get_header("x-content-type-options").is_some(),
            xcto_value: get_header("x-content-type-options"),
            has_xss_protection: get_header("x-xss-protection").is_some(),
            xss_protection_value: get_header("x-xss-protection"),
            has_rp: get_header("referrer-policy").is_some(),
            rp_value: get_header("referrer-policy"),
        };

        CorsHeaderAnalysis {
            has_acao: acao_value.is_some(),
            has_acac: acac_value.is_some(),
            has_acam: acam_value.is_some(),
            has_acah: acah_value.is_some(),
            has_acma: acma_value.is_some(),
            has_acex: acex_value.is_some(),
            acao_value,
            acac_value,
            acam_value,
            acah_value,
            acma_value,
            acex_value,
            vary_origin,
            security_headers,
        }
    }

    async fn test_http_methods(
        client: &Client,
        target_url: &str,
        test_origins: &[String],
        semaphore: &Arc<Semaphore>,
        tests_performed: &mut usize,
    ) -> Vec<CorsMethodResult> {
        let mut results = Vec::new();
        let test_origin = test_origins.first().cloned().unwrap_or_else(|| "https://evil.com".to_string());

        let mut join_set = tokio::task::JoinSet::new();

        for method in TEST_HTTP_METHODS {
            let client = client.clone();
            let target_url = target_url.to_string();
            let semaphore = semaphore.clone();
            let test_origin = test_origin.clone();

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let req = match *method {
                    "GET" => client.get(&target_url),
                    "POST" => client.post(&target_url),
                    "PUT" => client.put(&target_url),
                    "DELETE" => client.delete(&target_url),
                    "PATCH" => client.patch(&target_url),
                    _ => client.get(&target_url),
                };

                let resp = match req
                    .header("Origin", test_origin)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(_) => return None,
                };

                let http_status = resp.status().as_u16();
                let acao = resp.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let acac = resp.headers()
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let acam = resp.headers()
                    .get("access-control-allow-methods")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let acah = resp.headers()
                    .get("access-control-allow-headers")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let is_allowed = acao.is_some();

                Some(CorsMethodResult {
                    method: method.to_string(),
                    acao_header: acao,
                    acac_header: acac,
                    allow_methods: acam,
                    allow_headers: acah,
                    is_allowed,
                    http_status: Some(http_status),
                })
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(method_result)) = result {
                *tests_performed += 1;
                results.push(method_result);
            }
        }

        results
    }

    async fn test_preflight_requests(
        client: &Client,
        target_url: &str,
        test_origins: &[String],
        semaphore: &Arc<Semaphore>,
        issues: &mut Vec<CorsIssue>,
    ) -> usize {
        let mut tests = 0;
        let test_origin = test_origins.first().map(|s| s.as_str()).unwrap_or("https://evil.com");

        let _permit = match semaphore.acquire().await {
            Ok(p) => p,
            Err(_) => return tests,
        };

        if let Ok(resp) = client
            .request(reqwest::Method::OPTIONS, target_url)
            .header("Origin", test_origin)
            .header("Access-Control-Request-Method", "PUT")
            .header("Access-Control-Request-Headers", "Content-Type, Authorization")
            .send()
            .await {
            tests += 1;
            let acao = resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let acam = resp.headers()
                .get("access-control-allow-methods")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let acac = resp.headers()
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            if let Some(ref acao_val) = acao {
                if acao_val == test_origin || acao_val == "*" {
                    let has_put = acam.as_ref().map(|m| {
                        m.to_uppercase().contains("PUT")
                    }).unwrap_or(false);

                    if has_put && acac.as_deref() == Some("true") {
                        issues.push(CorsIssue {
                            issue_type: "Preflight Allows PUT with Credentials".to_string(),
                            severity: "high".to_string(),
                            description: "Preflight response allows PUT method with credentials".to_string(),
                            detail: format!("The OPTIONS preflight for origin '{}' allows PUT with credentials, enabling cross-origin data modification.", test_origin),
                            recommendation: "Restrict allowed methods and origins in preflight responses.".to_string(),
                            confidence: 0.9,
                            origin: Some(test_origin.to_string()),
                            method: Some("OPTIONS".to_string()),
                        });
                    }
                }
            }
        }

        tests
    }

    fn analyze_security_headers(sec_headers: &SecurityHeadersAnalysis, issues: &mut Vec<CorsIssue>) {
        let mut missing_headers: Vec<&str> = Vec::new();

        if !sec_headers.has_csp { missing_headers.push("Content-Security-Policy"); }
        if !sec_headers.has_hsts { missing_headers.push("Strict-Transport-Security"); }
        if !sec_headers.has_xfo { missing_headers.push("X-Frame-Options"); }
        if !sec_headers.has_xcto { missing_headers.push("X-Content-Type-Options"); }

        if !missing_headers.is_empty() {
            issues.push(CorsIssue {
                issue_type: "Missing Security Headers".to_string(),
                severity: "low".to_string(),
                description: format!("Missing security headers: {}", missing_headers.join(", ")),
                detail: "Missing security headers can increase the impact of CORS misconfigurations and other web vulnerabilities.".to_string(),
                recommendation: "Implement all recommended security headers to reduce attack surface.".to_string(),
                confidence: 1.0,
                origin: None,
                method: None,
            });
        }
    }

    fn calculate_security_score(
        issues: &[CorsIssue],
        origin_results: &[CorsOriginResult],
        header_analysis: &CorsHeaderAnalysis,
    ) -> f64 {
        let mut score: f64 = 100.0;

        for issue in issues {
            let penalty = match issue.severity.as_str() {
                "critical" => 25.0,
                "high" => 15.0,
                "medium" => 8.0,
                "low" => 3.0,
                _ => 1.0,
            };
            score -= penalty * issue.confidence;
        }

        let vulnerable_origins = origin_results.iter().filter(|o| o.risk_level == "critical" || o.risk_level == "high").count();
        if vulnerable_origins > 0 {
            score -= (vulnerable_origins as f64) * 5.0;
        }

        if !header_analysis.vary_origin && header_analysis.has_acao {
            score -= 5.0;
        }

        if !header_analysis.security_headers.has_csp { score -= 3.0; }
        if !header_analysis.security_headers.has_hsts { score -= 3.0; }
        if !header_analysis.security_headers.has_xfo { score -= 2.0; }

        score.clamp(0.0, 100.0)
    }

    fn extract_domain(url: &str) -> Option<String> {
        let url = url.trim_start_matches("http://").trim_start_matches("https://");
        let domain = url.split('/').next()?;
        let domain = domain.split(':').next()?;
        Some(domain.to_string())
    }
}
