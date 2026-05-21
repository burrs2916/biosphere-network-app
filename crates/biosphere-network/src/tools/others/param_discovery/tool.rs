use crate::core::{Result, ToolError};
use super::config::{
    ParamDiscoveryConfig, ParamDiscoveryResult, ParamEntry, SslInfo, WafDetection,
    classify_param, classify_sensitive_param, detect_waf, extract_form_params_from_html, extract_url_params,
};
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct ParamDiscoveryTool;

impl ParamDiscoveryTool {
    pub async fn discover(config: &ParamDiscoveryConfig) -> Result<ParamDiscoveryResult> {
        let scan_start = std::time::Instant::now();

        let url = config.url.trim().to_string();
        let target_url = if url.starts_with("http://") || url.starts_with("https://") {
            url
        } else {
            format!("https://{}", url)
        };

        let wordlist = config.get_effective_wordlist();
        let test_values = config.get_test_values();
        let max_concurrent = config.get_effective_threads();
        let user_agent = config.get_user_agent();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(5)
            } else {
                reqwest::redirect::Policy::none()
            })
            .danger_accept_invalid_certs(true)
            .user_agent(&user_agent)
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let ssl_info = if config.collect_ssl_info && target_url.starts_with("https://") {
            Self::collect_ssl_info(&target_url).await
        } else {
            None
        };

        let baseline_resp = client.get(&target_url).send().await
            .map_err(|e| ToolError::ExecutionError(format!("Baseline request failed: {}", e)))?;
        let baseline_status = baseline_resp.status().as_u16();
        let baseline_headers = baseline_resp.headers().clone();
        let baseline_length = baseline_resp.content_length();
        let baseline_body = baseline_resp.text().await.unwrap_or_default();
        let baseline_body_len = baseline_body.len() as u64;
        let baseline_cmp = baseline_length.unwrap_or(baseline_body_len);

        let mut form_params = Vec::new();
        if config.extract_form_params {
            form_params = extract_form_params_from_html(&baseline_body);
        }

        let url_params = extract_url_params(&target_url);

        let mut waf_detection: Option<WafDetection> = None;
        if baseline_status == 403 || baseline_status == 503 || baseline_status == 429 {
            let waf = detect_waf(baseline_status, &baseline_headers, &baseline_body);
            if waf.detected {
                waf_detection = Some(waf);
            }
        }

        let mut all_wordlist = wordlist.clone();
        if config.extract_form_params {
            for fp in &form_params {
                if !all_wordlist.contains(fp) {
                    all_wordlist.push(fp.clone());
                }
            }
        }
        for up in &url_params {
            if !all_wordlist.contains(up) {
                all_wordlist.push(up.clone());
            }
        }

        all_wordlist.retain(|p| !config.should_exclude_param(p));

        let primary_test_value = test_values.first().cloned().unwrap_or_else(|| "test".to_string());

        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut join_set = tokio::task::JoinSet::new();
        let total_scanned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waf_result: Arc<tokio::sync::Mutex<Option<WafDetection>>> = Arc::new(tokio::sync::Mutex::new(None));

        for param in &all_wordlist {
            let test_url = if target_url.contains('?') {
                format!("{}&{}={}", target_url, param, urlencoding::encode(&primary_test_value))
            } else {
                format!("{}?{}={}", target_url, param, urlencoding::encode(&primary_test_value))
            };

            let client = client.clone();
            let param = param.clone();
            let method = config.method.clone();
            let semaphore = semaphore.clone();
            let total_scanned = total_scanned.clone();
            let waf_result = waf_result.clone();
            let test_value = primary_test_value.clone();
            let detect_reflection = config.detect_reflection;
            let diff_threshold = config.diff_threshold;

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                total_scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut retries = 2u32;
                let final_result: Option<ParamEntry> = loop {
                    let start = std::time::Instant::now();

                    let request = if method.to_uppercase() == "POST" {
                        client.post(&test_url)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .body(format!("{}={}", param, urlencoding::encode(&test_value)))
                    } else {
                        client.get(&test_url)
                    };

                    match request.send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time_ms = start.elapsed().as_millis() as u64;
                            let headers = resp.headers().clone();
                            let content_length = resp.content_length();
                            let body = resp.text().await.unwrap_or_default();
                            let body_len = body.len() as u64;
                            let current_cmp = content_length.unwrap_or(body_len);

                            if (status == 429 || status == 503) && retries > 0 {
                                retries -= 1;
                                let wait = if status == 429 {
                                    if let Some(retry_after) = headers.get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()) {
                                        std::time::Duration::from_secs(retry_after.min(10))
                                    } else {
                                        std::time::Duration::from_millis(500 * (3 - retries) as u64)
                                    }
                                } else {
                                    std::time::Duration::from_millis(300 * (3 - retries) as u64)
                                };
                                tokio::time::sleep(wait).await;
                                continue;
                            }

                            if status == 403 || status == 429 || status == 503 {
                                let waf = detect_waf(status, &headers, &body);
                                if waf.detected {
                                    let mut guard = waf_result.lock().await;
                                    if guard.is_none() {
                                        *guard = Some(waf);
                                    }
                                }
                            }

                            let diff = if baseline_cmp > 0 {
                                ((current_cmp as f64 - baseline_cmp as f64) / baseline_cmp as f64).abs()
                            } else if current_cmp > 0 {
                                1.0
                            } else {
                                0.0
                            };

                            let is_different = status != baseline_status || diff > diff_threshold;

                            let is_reflected = if detect_reflection {
                                body.contains(&test_value)
                            } else {
                                false
                            };

                            if is_different || is_reflected {
                                let (category, risk_level) = classify_param(&param);
                                let evidence = if is_different && is_reflected {
                                    format!("Status/length changed & value reflected (diff {:.1}%)", diff * 100.0)
                                } else if is_reflected {
                                    "Value reflected in response".to_string()
                                } else if status != baseline_status {
                                    format!("Status changed: {} -> {}", baseline_status, status)
                                } else {
                                    format!("Content length changed: {} -> {} ({:.1}%)", baseline_cmp, current_cmp, diff * 100.0)
                                };

                                break Some(ParamEntry {
                                    param_name: param,
                                    method,
                                    evidence,
                                    response_diff: Some(diff),
                                    status_code: status,
                                    content_length,
                                    response_time_ms,
                                    test_value,
                                    category: category.to_string(),
                                    risk_level: risk_level.to_string(),
                                    is_reflected,
                                })
                            } else {
                                break None
                            }
                        }
                        Err(_) => break None,
                    }
                };

                final_result
            });
        }

        let mut found_params = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(entry)) = result {
                found_params.push(entry);
            }
        }

        if waf_detection.is_none() {
            let waf = waf_result.lock().await;
            if waf.is_some() {
                waf_detection = waf.clone();
            }
        }

        if config.multi_value_test && !found_params.is_empty() && test_values.len() > 1 {
            let confirmed_params: Vec<ParamEntry> = found_params.clone();
            let mut mv_join_set = tokio::task::JoinSet::new();
            let mv_semaphore = Arc::new(Semaphore::new(max_concurrent));

            for entry in &found_params {
                for test_val in test_values.iter().skip(1).take(2) {
                    let test_url = if target_url.contains('?') {
                        format!("{}&{}={}", target_url, entry.param_name, urlencoding::encode(test_val))
                    } else {
                        format!("{}?{}={}", target_url, entry.param_name, urlencoding::encode(test_val))
                    };

                    let client = client.clone();
                    let param_name = entry.param_name.clone();
                    let method = config.method.clone();
                    let test_val = test_val.clone();
                    let diff_threshold = config.diff_threshold;
                    let detect_reflection = config.detect_reflection;
                    let mv_semaphore = mv_semaphore.clone();

                    mv_join_set.spawn(async move {
                        let _permit = mv_semaphore.acquire().await.unwrap();
                        let start = std::time::Instant::now();

                        let request = if method.to_uppercase() == "POST" {
                            client.post(&test_url)
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .body(format!("{}={}", param_name, urlencoding::encode(&test_val)))
                        } else {
                            client.get(&test_url)
                        };

                        match request.send().await {
                            Ok(resp) => {
                                let status = resp.status().as_u16();
                                let response_time_ms = start.elapsed().as_millis() as u64;
                                let content_length = resp.content_length();
                                let body = resp.text().await.unwrap_or_default();
                                let body_len = body.len() as u64;
                                let current_cmp = content_length.unwrap_or(body_len);

                                let diff = if baseline_cmp > 0 {
                                    ((current_cmp as f64 - baseline_cmp as f64) / baseline_cmp as f64).abs()
                                } else if current_cmp > 0 {
                                    1.0
                                } else {
                                    0.0
                                };

                                let is_different = status != baseline_status || diff > diff_threshold;
                                let is_reflected = if detect_reflection { body.contains(&test_val) } else { false };

                                if is_different || is_reflected {
                                    let (category, risk_level) = classify_param(&param_name);
                                    let evidence = if is_different && is_reflected {
                                        format!("Confirmed: status/length changed & value reflected with '{}' (diff {:.1}%)", test_val, diff * 100.0)
                                    } else if is_reflected {
                                        format!("Confirmed: value '{}' reflected in response", test_val)
                                    } else if status != baseline_status {
                                        format!("Confirmed: status changed with '{}' ({} -> {})", test_val, baseline_status, status)
                                    } else {
                                        format!("Confirmed: content changed with '{}' (diff {:.1}%)", test_val, diff * 100.0)
                                    };

                                    Some(ParamEntry {
                                        param_name,
                                        method,
                                        evidence,
                                        response_diff: Some(diff),
                                        status_code: status,
                                        content_length,
                                        response_time_ms,
                                        test_value: test_val,
                                        category: category.to_string(),
                                        risk_level: risk_level.to_string(),
                                        is_reflected,
                                    })
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        }
                    });
                }
            }

            let mut all_params = confirmed_params;
            while let Some(result) = mv_join_set.join_next().await {
                if let Ok(Some(entry)) = result {
                    if !all_params.iter().any(|p| p.param_name == entry.param_name && p.test_value == entry.test_value) {
                        all_params.push(entry);
                    }
                }
            }

            found_params = all_params;
        }

        found_params.sort_by(|a, b| {
            let a_risk = match a.risk_level.as_str() { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };
            let b_risk = match b.risk_level.as_str() { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };
            a_risk.cmp(&b_risk).then(
                b.response_diff.unwrap_or(0.0).partial_cmp(&a.response_diff.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal)
            )
        });

        let mut sensitive_params = Vec::new();
        for entry in &found_params {
            if let Some(sp) = classify_sensitive_param(&entry.param_name) {
                sensitive_params.push(sp);
            }
        }
        sensitive_params.sort_by(|a, b| {
            let a_sev = match a.severity.as_str() { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
            let b_sev = match b.severity.as_str() { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
            a_sev.cmp(&b_sev)
        });

        let total_tested = total_scanned.load(std::sync::atomic::Ordering::Relaxed);
        let total_found = found_params.len();
        let scan_duration_ms = scan_start.elapsed().as_millis() as u64;
        let summary = format!(
            "Found {} parameters from {} tested on {} in {}ms",
            total_found, total_tested, target_url, scan_duration_ms
        );

        Ok(ParamDiscoveryResult {
            url: target_url,
            found_params,
            total_found,
            total_tested,
            summary,
            scan_duration_ms,
            baseline_status,
            baseline_length: baseline_cmp,
            form_params,
            url_params,
            ssl_info,
            waf_detected: waf_detection,
            sensitive_params,
        })
    }

    async fn collect_ssl_info(url_str: &str) -> Option<SslInfo> {
        let url_owned = url_str.to_string();
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
            })
        }).await.ok()?
    }
}
