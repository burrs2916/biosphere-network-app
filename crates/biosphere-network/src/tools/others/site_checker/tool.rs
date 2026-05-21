use crate::core::{Result, ToolError};
use super::config::{SiteCheckResult, BatchSiteCheckResult};
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub struct SiteCheckerTool;

impl SiteCheckerTool {
    pub async fn check(url: &str, timeout: Option<u64>) -> Result<SiteCheckResult> {
        let trimmed = url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let timeout_secs = timeout.unwrap_or(10);
        let mut issues = Vec::new();
        let mut dns_resolved = false;
        let mut ssl_valid: Option<bool> = None;
        let mut ip_address: Option<String> = None;

        let host = target_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();

        if host.is_empty() {
            return Err(ToolError::ExecutionError("Empty host".to_string()));
        }

        match tokio::net::lookup_host(format!("{}:443", &host)).await {
            Ok(addrs) => {
                dns_resolved = true;
                let addrs: Vec<_> = addrs.collect();
                if let Some(addr) = addrs.first() {
                    ip_address = Some(addr.ip().to_string());
                }
            }
            Err(_) => {
                match tokio::net::lookup_host(format!("{}:80", &host)).await {
                    Ok(addrs) => {
                        dns_resolved = true;
                        let addrs: Vec<_> = addrs.collect();
                        if let Some(addr) = addrs.first() {
                            ip_address = Some(addr.ip().to_string());
                        }
                    }
                    Err(_) => {
                        issues.push("DNS resolution failed".to_string());
                    }
                }
            }
        }

        let client_no_verify = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(10))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("Failed to create HTTP client: {}", e)))?;

        let start = Instant::now();
        let response = client_no_verify.get(&target_url).send().await;
        let response_time_ms = start.elapsed().as_millis() as u64;

        if target_url.starts_with("https://") {
            let client_verify = Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .redirect(reqwest::redirect::Policy::limited(10))
                .build();

            if let Ok(client) = client_verify {
                let verify_result = client.get(&target_url).send().await;
                match verify_result {
                    Ok(_) => { ssl_valid = Some(true); }
                    Err(e) => {
                        if e.to_string().contains("certificate") || e.to_string().contains("tls") || e.to_string().contains("ssl") {
                            ssl_valid = Some(false);
                            issues.push("SSL/TLS certificate is invalid or untrusted".to_string());
                        } else {
                            ssl_valid = None;
                        }
                    }
                }
            }
        }

        match response {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                let is_redirect = resp.status().is_redirection();
                let headers = resp.headers().clone();

                let server = headers.get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let content_type = headers.get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let content_length = headers.get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());

                let redirect_url = headers.get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let x_powered_by = headers.get("x-powered-by")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let x_frame_options = headers.get("x-frame-options")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let content_security_policy = headers.get("content-security-policy")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let strict_transport_security = headers.get("strict-transport-security")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let x_content_type_options = headers.get("x-content-type-options")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let x_xss_protection = headers.get("x-xss-protection")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let referrer_policy = headers.get("referrer-policy")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let permissions_policy = headers.get("permissions-policy")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let cache_control = headers.get("cache-control")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let etag = headers.get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let body = resp.text().await.unwrap_or_default();

                let title = Self::extract_title(&body);

                let is_online = (200..400).contains(&status_code);

                if status_code >= 400 {
                    issues.push(format!("HTTP error: {} {}", status_code, Self::status_text(status_code)));
                }

                if is_redirect {
                    issues.push(format!("Redirect detected ({}), target: {}", status_code, redirect_url.as_deref().unwrap_or("unknown")));
                }

                if let Some(ref ct) = content_type {
                    if ct.contains("text/html") && title.is_none() && !body.is_empty() {
                        issues.push("HTML page has no <title> tag".to_string());
                    }
                }

                if ssl_valid == Some(false) {
                    issues.push("SSL certificate is invalid - visitors will see security warnings".to_string());
                }

                if x_frame_options.is_none() && content_security_policy.is_none() {
                    issues.push("Missing X-Frame-Options or Content-Security-Policy header - vulnerable to clickjacking".to_string());
                }

                if strict_transport_security.is_none() && target_url.starts_with("https://") {
                    issues.push("Missing Strict-Transport-Security header - HSTS not enabled".to_string());
                }

                if x_content_type_options.is_none() {
                    issues.push("Missing X-Content-Type-Options header - MIME type sniffing possible".to_string());
                }

                let summary = if is_online {
                    format!("Site is ONLINE - Status: {} - Response: {}ms{}", 
                        status_code, response_time_ms,
                        if let Some(ref t) = title { format!(" - Title: {}", t) } else { String::new() }
                    )
                } else {
                    format!("Site has ISSUES - Status: {} - Response: {}ms", status_code, response_time_ms)
                };

                Ok(SiteCheckResult {
                    url: target_url,
                    is_online,
                    status_code: Some(status_code),
                    response_time_ms: Some(response_time_ms),
                    title,
                    server,
                    content_type,
                    content_length,
                    redirect_url,
                    is_redirect,
                    dns_resolved,
                    ssl_valid,
                    ip_address,
                    x_powered_by,
                    x_frame_options,
                    content_security_policy,
                    strict_transport_security,
                    x_content_type_options,
                    x_xss_protection,
                    referrer_policy,
                    permissions_policy,
                    cache_control,
                    etag,
                    issues,
                    summary,
                })
            }
            Err(e) => {
                let is_timeout = e.is_timeout();
                let is_connect = e.is_connect();

                if is_timeout {
                    issues.push("Request timed out".to_string());
                } else if is_connect {
                    issues.push("Connection refused or unreachable".to_string());
                }

                let summary = if is_timeout {
                    "Site is OFFLINE - Request timed out".to_string()
                } else if is_connect {
                    "Site is OFFLINE - Connection failed".to_string()
                } else {
                    format!("Site check failed: {}", e)
                };

                Ok(SiteCheckResult {
                    url: target_url,
                    is_online: false,
                    status_code: None,
                    response_time_ms: Some(response_time_ms),
                    title: None,
                    server: None,
                    content_type: None,
                    content_length: None,
                    redirect_url: None,
                    is_redirect: false,
                    dns_resolved,
                    ssl_valid,
                    ip_address,
                    x_powered_by: None,
                    x_frame_options: None,
                    content_security_policy: None,
                    strict_transport_security: None,
                    x_content_type_options: None,
                    x_xss_protection: None,
                    referrer_policy: None,
                    permissions_policy: None,
                    cache_control: None,
                    etag: None,
                    issues,
                    summary,
                })
            }
        }
    }

    pub async fn batch_check(urls: &[String], timeout: Option<u64>) -> Vec<BatchSiteCheckResult> {
        let semaphore = Arc::new(Semaphore::new(10));
        let mut join_set = tokio::task::JoinSet::new();

        for url in urls {
            let url = url.clone();
            let timeout = timeout;
            let semaphore = semaphore.clone();
            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                match Self::check(&url, timeout).await {
                    Ok(result) => BatchSiteCheckResult {
                        url: url.clone(),
                        result: Some(result),
                        error: None,
                    },
                    Err(e) => BatchSiteCheckResult {
                        url: url.clone(),
                        result: None,
                        error: Some(e.to_string()),
                    },
                }
            });
        }

        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(batch_result) = result {
                results.push(batch_result);
            }
        }

        let mut url_order: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, url) in urls.iter().enumerate() {
            url_order.insert(url.clone(), i);
        }
        results.sort_by_key(|r| url_order.get(&r.url).copied().unwrap_or(0));

        results
    }

    fn extract_title(html: &str) -> Option<String> {
        let lower = html.to_lowercase();
        if let Some(start) = lower.find("<title>") {
            if let Some(end) = lower.find("</title>") {
                let content_start = start + 7;
                if content_start < end {
                    let title = html[content_start..end].trim();
                    if !title.is_empty() {
                        return Some(title.to_string());
                    }
                }
            }
        }
        None
    }

    fn status_text(code: u16) -> &'static str {
        match code {
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "",
        }
    }
}
