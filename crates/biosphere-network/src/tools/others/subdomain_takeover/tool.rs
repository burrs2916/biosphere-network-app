use crate::core::{Result, ToolError};
use super::config::{
    TakeoverConfig, TakeoverResult, TakeoverEntry, ServiceDistribution,
    TAKEOVER_FINGERPRINTS, QUICK_SUBDOMAINS, NORMAL_SUBDOMAINS, DEEP_SUBDOMAINS,
    USER_AGENTS,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use std::collections::HashMap;

pub struct SubdomainTakeoverTool;

static UA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_random_user_agent() -> &'static str {
    let idx = UA_COUNTER.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
    USER_AGENTS[idx]
}

impl SubdomainTakeoverTool {
    pub async fn check(config: &TakeoverConfig) -> Result<TakeoverResult> {
        let domain = config.domain.trim().to_string();
        if domain.is_empty() {
            return Err(ToolError::ExecutionError("Domain is empty".to_string()));
        }

        let start = std::time::Instant::now();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let subdomains = if !config.subdomains.is_empty() {
            config.subdomains.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect::<Vec<_>>()
        } else {
            Self::get_subdomains(&domain, &config.scan_mode)
        };

        if subdomains.is_empty() {
            return Err(ToolError::ExecutionError("No subdomains to check".to_string()));
        }

        let semaphore = Arc::new(Semaphore::new(config.threads.clamp(1, 50)));
        let mut join_set = tokio::task::JoinSet::new();

        for subdomain in &subdomains {
            let subdomain = subdomain.clone();
            let full_subdomain = if subdomain.contains(&domain) {
                subdomain.clone()
            } else {
                format!("{}.{}", subdomain, domain)
            };

            let url = if full_subdomain.starts_with("http://") || full_subdomain.starts_with("https://") {
                full_subdomain.clone()
            } else {
                format!("https://{}", full_subdomain)
            };

            let client = client.clone();
            let semaphore = semaphore.clone();
            let check_cname = config.check_cname;
            let check_http = config.check_http;
            let check_dns_dangling = config.check_dns_dangling;

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let mut cname: Option<String> = None;
                let mut ip_addresses: Vec<String> = Vec::new();

                if check_cname || check_dns_dangling {
                    let (c, ips) = Self::resolve_dns_with_retry(&full_subdomain, 2).await;
                    cname = c;
                    ip_addresses = ips;
                }

                let mut http_status: Option<u16> = None;
                let mut http_title: Option<String> = None;
                let mut response_time_ms: Option<u64> = None;
                let mut body = String::new();
                let mut http_error: Option<String> = None;
                let ua = get_random_user_agent().to_string();

                if check_http {
                    let req_start = std::time::Instant::now();
                    match client.get(&url).header("User-Agent", &ua).send().await {
                        Ok(resp) => {
                            response_time_ms = Some(req_start.elapsed().as_millis() as u64);
                            http_status = Some(resp.status().as_u16());
                            body = resp.text().await.unwrap_or_default();
                            http_title = Self::extract_title(&body);
                        }
                        Err(e) => { http_error = Some(format!("HTTPS: {}", e)); }
                    }

                    if http_status.is_none() {
                        let http_url = format!("http://{}", full_subdomain);
                        let req_start2 = std::time::Instant::now();
                        match client.get(&http_url).header("User-Agent", &ua).send().await {
                            Ok(resp) => {
                                response_time_ms = Some(req_start2.elapsed().as_millis() as u64);
                                http_status = Some(resp.status().as_u16());
                                body = resp.text().await.unwrap_or_default();
                                http_title = Self::extract_title(&body);
                            }
                            Err(e2) => {
                                if let Some(first_err) = http_error.take() {
                                    http_error = Some(format!("{}; HTTP: {}", first_err, e2));
                                } else {
                                    http_error = Some(format!("HTTP: {}", e2));
                                }
                            }
                        }
                    }
                }

                let body_lower = body.to_lowercase();

                if let Some(ref cname_val) = cname {
                    let cname_lower = cname_val.to_lowercase();

                    let mut best_body_match: Option<&super::config::TakeoverFingerprint> = None;
                    let mut best_cname_match: Option<&super::config::TakeoverFingerprint> = None;

                    for fp in TAKEOVER_FINGERPRINTS {
                        if !cname_lower.contains(fp.cname_pattern) {
                            continue;
                        }
                        if best_cname_match.is_none() || fp.confidence > best_cname_match.unwrap().confidence {
                            best_cname_match = Some(fp);
                        }
                        if check_cname && !body_lower.is_empty() && body_lower.contains(&fp.fingerprint.to_lowercase())
                            && (best_body_match.is_none() || fp.confidence > best_body_match.unwrap().confidence) {
                                best_body_match = Some(fp);
                            }
                    }

                    if let Some(fp) = best_body_match {
                        return (0, TakeoverEntry {
                            subdomain: full_subdomain.clone(),
                            cname: Some(cname_val.clone()),
                            is_vulnerable: true,
                            is_potentially_vulnerable: false,
                            service: Some(fp.service.to_string()),
                            service_category: Some(fp.category.to_string()),
                            evidence: format!("CNAME: {} → Fingerprint matched: {}", cname_val, fp.fingerprint),
                            fingerprint: Some(fp.fingerprint.to_string()),
                            confidence: fp.confidence,
                            http_status,
                            http_title,
                            response_time_ms,
                            ip_addresses,
                        });
                    }

                    if let Some(fp) = best_cname_match {
                        if check_dns_dangling && check_http {
                            let is_dangling = http_status.is_none()
                                || http_status == Some(404)
                                || http_status == Some(503)
                                || http_status == Some(502);

                            if is_dangling {
                                return (0, TakeoverEntry {
                                    subdomain: full_subdomain.clone(),
                                    cname: Some(cname_val.clone()),
                                    is_vulnerable: false,
                                    is_potentially_vulnerable: true,
                                    service: Some(fp.service.to_string()),
                                    service_category: Some(fp.category.to_string()),
                                    evidence: format!("CNAME: {} → DNS dangling detected (HTTP {})", cname_val, http_status.map(|s| s.to_string()).unwrap_or_else(|| "unreachable".to_string())),
                                    fingerprint: None,
                                    confidence: fp.confidence * 0.5,
                                    http_status,
                                    http_title,
                                    response_time_ms,
                                    ip_addresses,
                                });
                            }
                        }

                        return (1, TakeoverEntry {
                            subdomain: full_subdomain.clone(),
                            cname: Some(cname_val.clone()),
                            is_vulnerable: false,
                            is_potentially_vulnerable: false,
                            service: Some(fp.service.to_string()),
                            service_category: Some(fp.category.to_string()),
                            evidence: format!("CNAME: {} → Service: {} (Status: {})", cname_val, fp.service, http_status.map(|s| s.to_string()).unwrap_or_else(|| "N/A".to_string())),
                            fingerprint: None,
                            confidence: 0.0,
                            http_status,
                            http_title,
                            response_time_ms,
                            ip_addresses,
                        });
                    }
                }

                if check_cname && !body_lower.is_empty() {
                    let mut best_fp: Option<&super::config::TakeoverFingerprint> = None;
                    for fp in TAKEOVER_FINGERPRINTS {
                        if body_lower.contains(&fp.fingerprint.to_lowercase())
                            && (best_fp.is_none() || fp.confidence > best_fp.unwrap().confidence) {
                                best_fp = Some(fp);
                            }
                    }
                    if let Some(fp) = best_fp {
                        return (0, TakeoverEntry {
                            subdomain: full_subdomain.clone(),
                            cname: cname.clone(),
                            is_vulnerable: true,
                            is_potentially_vulnerable: false,
                            service: Some(fp.service.to_string()),
                            service_category: Some(fp.category.to_string()),
                            evidence: format!("Fingerprint matched: {} (Status: {})", fp.fingerprint, http_status.map(|s| s.to_string()).unwrap_or_else(|| "N/A".to_string())),
                            fingerprint: Some(fp.fingerprint.to_string()),
                            confidence: fp.confidence * 0.9,
                            http_status,
                            http_title,
                            response_time_ms,
                            ip_addresses,
                        });
                    }
                }

                if http_error.is_some() && cname.is_none() {
                    return (2, TakeoverEntry {
                        subdomain: full_subdomain.clone(),
                        cname,
                        is_vulnerable: false,
                        is_potentially_vulnerable: false,
                        service: None,
                        service_category: None,
                        evidence: http_error.unwrap_or_default(),
                        fingerprint: None,
                        confidence: 0.0,
                        http_status,
                        http_title,
                        response_time_ms,
                        ip_addresses,
                    });
                }

                (1, TakeoverEntry {
                    subdomain: full_subdomain.clone(),
                    cname,
                    is_vulnerable: false,
                    is_potentially_vulnerable: false,
                    service: None,
                    service_category: None,
                    evidence: format!("Status: {}, No takeover fingerprints detected", http_status.map(|s| s.to_string()).unwrap_or_else(|| "unreachable".to_string())),
                    fingerprint: None,
                    confidence: 0.0,
                    http_status,
                    http_title,
                    response_time_ms,
                    ip_addresses,
                })
            });
        }

        let mut vulnerable = Vec::new();
        let mut potentially_vulnerable = Vec::new();
        let mut safe = Vec::new();
        let mut errors = Vec::new();

        while let Some(result) = join_set.join_next().await {
            if let Ok((category, entry)) = result {
                match category {
                    0 => {
                        if entry.is_vulnerable {
                            vulnerable.push(entry);
                        } else if entry.is_potentially_vulnerable {
                            potentially_vulnerable.push(entry);
                        } else {
                            safe.push(entry);
                        }
                    }
                    1 => safe.push(entry),
                    _ => errors.push(entry),
                }
            }
        }

        vulnerable.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        potentially_vulnerable.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        let service_distribution = Self::build_service_distribution(&vulnerable, &potentially_vulnerable);

        let checked_subdomains = vulnerable.len() + potentially_vulnerable.len() + safe.len() + errors.len();
        let scan_duration_ms = start.elapsed().as_millis() as u64;

        let summary = if !vulnerable.is_empty() {
            format!(
                "⚠️ Found {} vulnerable + {} potentially vulnerable subdomains out of {} checked",
                vulnerable.len(), potentially_vulnerable.len(), checked_subdomains
            )
        } else if !potentially_vulnerable.is_empty() {
            format!(
                "🔍 Found {} potentially vulnerable subdomains out of {} checked",
                potentially_vulnerable.len(), checked_subdomains
            )
        } else {
            format!(
                "✅ No vulnerable subdomains found out of {} checked",
                checked_subdomains
            )
        };

        Ok(TakeoverResult {
            domain,
            checked_subdomains,
            vulnerable,
            potentially_vulnerable,
            safe,
            errors,
            scan_duration_ms,
            summary,
            service_distribution,
        })
    }

    fn get_subdomains(domain: &str, scan_mode: &str) -> Vec<String> {
        let list: &[&str] = match scan_mode {
            "quick" => QUICK_SUBDOMAINS,
            "deep" => DEEP_SUBDOMAINS,
            _ => NORMAL_SUBDOMAINS,
        };
        list.iter().map(|s| format!("{}.{}", s, domain)).collect()
    }

    async fn resolve_dns(domain: &str) -> (Option<String>, Vec<String>) {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::proto::rr::{RecordType, RData};

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let mut cname: Option<String> = None;
        let mut ip_addresses: Vec<String> = Vec::new();

        if let Ok(lookup) = resolver.lookup(domain, RecordType::CNAME).await {
            for record in lookup.record_iter() {
                if let Some(RData::CNAME(c)) = record.data() {
                    cname = Some(c.to_string());
                    break;
                }
            }
        }

        if let Ok(lookup) = resolver.lookup_ip(domain).await {
            for ip in lookup.iter() {
                ip_addresses.push(ip.to_string());
            }
        }

        (cname, ip_addresses)
    }

    async fn resolve_dns_with_retry(domain: &str, max_retries: usize) -> (Option<String>, Vec<String>) {
        let mut last_result = (None, Vec::new());
        for attempt in 0..=max_retries {
            let result = Self::resolve_dns(domain).await;
            if result.0.is_some() || !result.1.is_empty() {
                return result;
            }
            if attempt < max_retries {
                tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt as u64 + 1))).await;
            }
            last_result = result;
        }
        last_result
    }

    fn extract_title(body: &str) -> Option<String> {
        let lower = body.to_lowercase();
        if let Some(start) = lower.find("<title>") {
            if let Some(end) = lower.find("</title>") {
                let content_start = start + 7;
                if content_start < end {
                    let title = body[content_start..end].trim().to_string();
                    if !title.is_empty() {
                        return Some(title);
                    }
                }
            }
        }
        None
    }

    fn build_service_distribution(vulnerable: &[TakeoverEntry], potentially_vulnerable: &[TakeoverEntry]) -> Vec<ServiceDistribution> {
        let mut map: HashMap<(String, String), (usize, usize)> = HashMap::new();

        for entry in vulnerable {
            if let (Some(service), Some(category)) = (&entry.service, &entry.service_category) {
                let key = (service.clone(), category.clone());
                let (count, vuln_count) = map.entry(key).or_insert((0, 0));
                *count += 1;
                *vuln_count += 1;
            }
        }

        for entry in potentially_vulnerable {
            if let (Some(service), Some(category)) = (&entry.service, &entry.service_category) {
                let key = (service.clone(), category.clone());
                let (count, _vuln_count) = map.entry(key).or_insert((0, 0));
                *count += 1;
            }
        }

        let mut dist: Vec<ServiceDistribution> = map.into_iter().map(|((service, category), (count, vulnerable_count))| {
            ServiceDistribution { service, category, count, vulnerable_count }
        }).collect();

        dist.sort_by(|a, b| b.count.cmp(&a.count));
        dist
    }
}
