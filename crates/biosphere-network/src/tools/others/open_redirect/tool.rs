use std::sync::Arc;
use std::time::Instant;
use std::time::Duration;
use reqwest::Client;
use tokio::sync::Semaphore;
use crate::core::{Result, ToolError};
use super::config::*;

pub struct OpenRedirectTool;

impl OpenRedirectTool {
    pub async fn check(config: &OpenRedirectConfig) -> Result<OpenRedirectResult> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(3)
            } else {
                reqwest::redirect::Policy::none()
            })
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let (params, payloads) = Self::get_test_suite(config);
        let mut tests_performed: usize = 0;
        let mut vulnerabilities: Vec<OpenRedirectVuln> = Vec::new();

        let semaphore = Arc::new(Semaphore::new(config.threads));
        let mut join_set = tokio::task::JoinSet::new();

        for param in &params {
            for (payload, payload_type, confidence) in &payloads {
                let test_url = Self::build_test_url(&target_url, param, payload);
                let client = client.clone();
                let payload = payload.to_string();
                let payload_type = payload_type.to_string();
                let param = param.to_string();
                let confidence = *confidence;
                let semaphore = semaphore.clone();
                let analyze_body = config.analyze_body;
                let follow_redirects = config.follow_redirects;

                join_set.spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    Self::test_single_payload(
                        &client,
                        &test_url,
                        &param,
                        &payload,
                        &payload_type,
                        confidence,
                        analyze_body,
                        follow_redirects,
                    ).await
                });

                tests_performed += 1;
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(vuln)) = result {
                vulnerabilities.push(vuln);
            }
        }

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        vulnerabilities.retain(|v| {
            let key = format!("{}:{}", v.parameter, v.payload);
            seen.insert(key)
        });

        vulnerabilities.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap())
        });

        let (is_vulnerable, severity, security_score, summary) = Self::compute_summary(
            &target_url,
            &vulnerabilities,
            tests_performed,
        );

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        Ok(OpenRedirectResult {
            url: target_url,
            is_vulnerable,
            severity,
            security_score,
            vulnerabilities,
            tests_performed,
            scan_duration_ms,
            summary,
        })
    }

    fn get_test_suite(config: &OpenRedirectConfig) -> (Vec<String>, Vec<(String, String, f64)>) {
        let params = if !config.test_params.is_empty() {
            config.test_params.clone()
        } else {
            match config.scan_level.as_str() {
                "basic" => BASIC_PARAMS.iter().map(|s| s.to_string()).collect(),
                "moderate" => MODERATE_PARAMS.iter().map(|s| s.to_string()).collect(),
                "aggressive" => AGGRESSIVE_PARAMS.iter().map(|s| s.to_string()).collect(),
                _ => MODERATE_PARAMS.iter().map(|s| s.to_string()).collect(),
            }
        };

        let payloads = if !config.test_payloads.is_empty() {
            config.test_payloads.iter().map(|s| (s.clone(), "Custom".to_string(), 0.80)).collect()
        } else {
            match config.scan_level.as_str() {
                "basic" => BASIC_PAYLOADS.iter().map(|(p, t, c)| (p.to_string(), t.to_string(), *c)).collect(),
                "moderate" => MODERATE_PAYLOADS.iter().map(|(p, t, c)| (p.to_string(), t.to_string(), *c)).collect(),
                "aggressive" => AGGRESSIVE_PAYLOADS.iter().map(|(p, t, c)| (p.to_string(), t.to_string(), *c)).collect(),
                _ => MODERATE_PAYLOADS.iter().map(|(p, t, c)| (p.to_string(), t.to_string(), *c)).collect(),
            }
        };

        (params, payloads)
    }

    fn build_test_url(base_url: &str, param: &str, payload: &str) -> String {
        if base_url.contains('?') {
            let (path, existing_params) = base_url.split_once('?').unwrap_or((base_url, ""));
            if existing_params.is_empty() {
                format!("{}?{}={}", path, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}&{}={}", path, existing_params, param, urlencoding::encode(payload))
            }
        } else {
            format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
        }
    }

    async fn test_single_payload(
        client: &Client,
        test_url: &str,
        param: &str,
        payload: &str,
        payload_type: &str,
        base_confidence: f64,
        analyze_body: bool,
        follow_redirects: bool,
    ) -> Option<OpenRedirectVuln> {
        match client.get(test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let location = resp.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let mut body_vuln = None;
                if analyze_body {
                    if let Ok(body_text) = resp.text().await {
                        if body_text.contains(EVIL_DOMAIN) {
                            let (severity, confidence, description, recommendation) = Self::classify_payload(
                                payload, payload_type, base_confidence,
                            );

                            body_vuln = Some(OpenRedirectVuln {
                                parameter: param.to_string(),
                                payload: payload.to_string(),
                                payload_type: payload_type.to_string(),
                                severity,
                                redirect_to: format!("Body contains: {}", EVIL_DOMAIN),
                                http_status: Some(status),
                                confidence: confidence * 0.7,
                                description,
                                detail: format!("Response body contains redirect target (status: {})", status),
                                recommendation,
                                is_redirect_chain: follow_redirects,
                                is_body_based: true,
                            });
                        }
                    }
                }

                if let Some(ref loc) = location {
                    let loc_lower = loc.to_lowercase();

                    let has_evil_domain = loc_lower.contains(EVIL_DOMAIN);
                    let has_javascript = loc_lower.starts_with("javascript:");
                    let has_data_uri = loc_lower.starts_with("data:");
                    let has_vbscript = loc_lower.starts_with("vbscript:");

                    if has_evil_domain || has_javascript || has_data_uri || has_vbscript {
                        let (severity, confidence, description, recommendation) = Self::classify_payload(
                            payload, payload_type, base_confidence,
                        );

                        return Some(OpenRedirectVuln {
                            parameter: param.to_string(),
                            payload: payload.to_string(),
                            payload_type: payload_type.to_string(),
                            severity,
                            redirect_to: loc.clone(),
                            http_status: Some(status),
                            confidence,
                            description,
                            detail: format!("{} - Redirects to '{}' (status: {})", payload_type, loc, status),
                            recommendation,
                            is_redirect_chain: follow_redirects,
                            is_body_based: false,
                        });
                    }

                    if (300..400).contains(&status) {
                        let payload_clean = payload
                            .trim_start_matches("https://")
                            .trim_start_matches("http://")
                            .trim_start_matches("//");
                        
                        if loc.contains(payload_clean) {
                            let (severity, confidence, description, recommendation) = Self::classify_payload(
                                payload, payload_type, base_confidence * 0.7,
                            );

                            return Some(OpenRedirectVuln {
                                parameter: param.to_string(),
                                payload: payload.to_string(),
                                payload_type: payload_type.to_string(),
                                severity,
                                redirect_to: loc.clone(),
                                http_status: Some(status),
                                confidence,
                                description,
                                detail: format!("{} - Partial redirect match (status: {})", payload_type, status),
                                recommendation,
                                is_redirect_chain: follow_redirects,
                                is_body_based: false,
                            });
                        }
                    }
                }

                body_vuln
            }
            Err(_) => None,
        }
    }

    fn classify_payload(
        payload: &str,
        _payload_type: &str,
        base_confidence: f64,
    ) -> (String, f64, String, String) {
        let payload_lower = payload.to_lowercase();

        let (severity, confidence, description, recommendation) = if payload_lower.starts_with("javascript:") {
            ("critical".to_string(), base_confidence * 1.0,
             "JavaScript URL protocol redirection - XSS injection vector".to_string(),
             "Restrict redirection URLs to allowlist; block JavaScript/data protocols".to_string())
        } else if payload_lower.starts_with("data:") {
            ("high".to_string(), base_confidence * 0.95,
             "Data URI redirection - potential XSS/phishing vector".to_string(),
             "Block data URI redirections; implement strict URL validation".to_string())
        } else if payload_lower.starts_with("vbscript:") {
            ("high".to_string(), base_confidence * 0.9,
             "VBScript URL protocol redirection - IE-specific XSS vector".to_string(),
             "Block VBScript protocols; restrict to HTTP/HTTPS only".to_string())
        } else if payload_lower.contains("\\@") || payload_lower.contains("%0a") || payload_lower.contains("%0d") || payload_lower.contains("%00") {
            ("high".to_string(), base_confidence * 0.9,
             "Encoding bypass redirection - exploit vector".to_string(),
             "Normalize and validate all URL components; reject bypass characters".to_string())
        } else if payload_lower.starts_with("//") || payload_lower.contains("///") || payload_lower.contains("\\\\") || payload_lower.contains("/\\") {
            ("medium".to_string(), base_confidence * 0.85,
             "Protocol-relative or slash bypass redirection".to_string(),
             "Normalize URL paths; restrict to absolute URLs with proper protocol".to_string())
        } else {
            ("high".to_string(), base_confidence,
             "Open redirect to untrusted domain".to_string(),
             "Implement allowlist for valid redirect destinations; validate all URL parameters".to_string())
        };

        (severity, confidence, description, recommendation)
    }

    fn compute_summary(
        url: &str,
        vulnerabilities: &[OpenRedirectVuln],
        tests_performed: usize,
    ) -> (bool, String, f64, String) {
        if vulnerabilities.is_empty() {
            return (
                false,
                "safe".to_string(),
                100.0,
                format!("No open redirect vulnerabilities found ({} tests performed)", tests_performed),
            );
        }

        let critical_count = vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high_count = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = vulnerabilities.iter().filter(|v| v.severity == "low").count();

        let mut score = 100.0;
        score -= (critical_count as f64) * 25.0;
        score -= (high_count as f64) * 15.0;
        score -= (medium_count as f64) * 8.0;
        score -= (low_count as f64) * 3.0;
        score = score.clamp(0.0, 100.0);

        let overall_severity = if critical_count > 0 {
            "critical".to_string()
        } else if high_count > 0 {
            "high".to_string()
        } else if medium_count > 0 {
            "medium".to_string()
        } else {
            "low".to_string()
        };

        let summary = format!(
            "Found {} open redirect vulnerabilities ({} critical, {} high, {} medium, {} low) across {} tests on '{}'",
            vulnerabilities.len(), critical_count, high_count, medium_count, low_count, tests_performed, url
        );

        (true, overall_severity, score, summary)
    }
}
