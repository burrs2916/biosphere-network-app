use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::collections::HashMap;
use reqwest::Client;
use tokio::sync::Semaphore;
use crate::core::{Result, ToolError};
use super::config::*;

static UA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_random_user_agent() -> &'static str {
    let idx = UA_COUNTER.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
    USER_AGENTS[idx]
}

pub struct SqliScannerTool;

impl SqliScannerTool {
    pub async fn scan(config: &SqliScanConfig) -> Result<SqliScanResult> {
        let start = std::time::Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        if target_url.is_empty() {
            return Err(ToolError::ExecutionError("URL is empty".to_string()));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(reqwest::redirect::Policy::limited(3))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let ua = get_random_user_agent().to_string();
        let baseline_resp = client.get(&target_url)
            .header("User-Agent", &ua)
            .send().await
            .map_err(|e| ToolError::ExecutionError(format!("Baseline request failed: {}", e)))?;
        let baseline_status = baseline_resp.status().as_u16();
        let baseline_body = baseline_resp.text().await.unwrap_or_default();
        let baseline_length = baseline_body.len();

        let payloads: &[(&str, &str, &str)] = match config.scan_level.as_str() {
            "basic" => BASIC_PAYLOADS,
            "aggressive" => AGGRESSIVE_PAYLOADS,
            _ => MODERATE_PAYLOADS,
        };

        let mut params = Self::extract_parameters(&target_url, &baseline_body);

        if !config.custom_parameters.is_empty() {
            for p in &config.custom_parameters {
                let p = p.trim().to_string();
                if !p.is_empty() && !params.contains(&p) {
                    params.push(p);
                }
            }
        }

        if params.is_empty() {
            for p in DEFAULT_PARAMETERS {
                if !params.contains(&p.to_string()) {
                    params.push(p.to_string());
                }
            }
        }

        let semaphore = Arc::new(Semaphore::new(config.threads.max(1).min(20)));
        let mut join_set = tokio::task::JoinSet::new();
        let mut tests_performed: usize = 0;

        if config.test_get {
            for param in &params {
                for (payload, category, desc) in payloads {
                    let test_url = format!("{}?{}={}", target_url, param, urlencoding::encode(payload));
                    let client = client.clone();
                    let payload = payload.to_string();
                    let category = category.to_string();
                    let desc = desc.to_string();
                    let param = param.clone();
                    let baseline_length = baseline_length;
                    let baseline_status = baseline_status;
                    let semaphore = semaphore.clone();
                    let is_time_based = category == "Time-based";

                    join_set.spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let ua = get_random_user_agent().to_string();
                        let req_start = std::time::Instant::now();

                        match client.get(&test_url)
                            .header("User-Agent", &ua)
                            .send().await
                        {
                            Ok(resp) => {
                                let elapsed = req_start.elapsed().as_millis() as u64;
                                let status = resp.status().as_u16();
                                let body = resp.text().await.unwrap_or_default();
                                let body_lower = body.to_lowercase();
                                let body_len = body.len();

                                if is_time_based {
                                    if elapsed >= 2800 {
                                        return (0, Some(SqliVulnerability {
                                            parameter: param.clone(),
                                            injection_type: format!("{} - {}", category, desc),
                                            injection_category: category.clone(),
                                            severity: "high".to_string(),
                                            payload: payload.clone(),
                                            evidence: format!("Response delayed {}ms (threshold: 2800ms)", elapsed),
                                            request_url: test_url.clone(),
                                            confidence: 0.85,
                                            db_type: if payload.contains("SLEEP") { "MySQL".to_string() }
                                                else if payload.contains("WAITFOR") { "MSSQL".to_string() }
                                                else if payload.contains("pg_sleep") { "PostgreSQL".to_string() }
                                                else { "Unknown".to_string() },
                                            response_time_ms: Some(elapsed),
                                            http_status: Some(status),
                                            method: "GET".to_string(),
                                        }), None, None);
                                    }
                                    return (2, None, None, None);
                                }

                                if let Some(vuln) = Self::check_error_patterns(
                                    &param, &category, &desc, &payload, &test_url,
                                    &body_lower, status, Some(elapsed), "GET",
                                ) {
                                    return (0, Some(vuln), None, None);
                                }

                                if status != baseline_status && (status == 500 || status == 400) {
                                    return (0, Some(SqliVulnerability {
                                        parameter: param.clone(),
                                        injection_type: format!("{} - {} (Status anomaly)", category, desc),
                                        injection_category: category.clone(),
                                        severity: "medium".to_string(),
                                        payload: payload.clone(),
                                        evidence: format!("Status changed from {} to {}", baseline_status, status),
                                        request_url: test_url.clone(),
                                        confidence: 0.60,
                                        db_type: "Unknown".to_string(),
                                        response_time_ms: Some(elapsed),
                                        http_status: Some(status),
                                        method: "GET".to_string(),
                                    }), None, None);
                                }

                                let length_diff = (body_len as i64 - baseline_length as i64).abs() as f64;
                                let length_ratio = if baseline_length > 0 { length_diff / baseline_length as f64 } else { 0.0 };

                                if length_ratio > 0.3 && (payload.contains("OR") || payload.contains("or")) {
                                    return (0, Some(SqliVulnerability {
                                        parameter: param.clone(),
                                        injection_type: format!("{} - {} (Content change)", category, desc),
                                        injection_category: category.clone(),
                                        severity: "medium".to_string(),
                                        payload: payload.clone(),
                                        evidence: format!("Response length changed significantly ({} -> {})", baseline_length, body_len),
                                        request_url: test_url.clone(),
                                        confidence: 0.55,
                                        db_type: "Unknown".to_string(),
                                        response_time_ms: Some(elapsed),
                                        http_status: Some(status),
                                        method: "GET".to_string(),
                                    }), None, None);
                                }

                                (1, None, Some(SqliSafeEntry {
                                    parameter: param.clone(),
                                    tests_run: 1,
                                    method: "GET".to_string(),
                                }), None)
                            }
                            Err(e) => (2, None, None, Some(SqliErrorEntry {
                                parameter: param.clone(),
                                payload: payload.clone(),
                                error: e.to_string(),
                                method: "GET".to_string(),
                            })),
                        }
                    });
                    tests_performed += 1;
                }
            }
        }

        if config.test_post {
            for param in &params {
                for (payload, category, desc) in payloads {
                    if *category == "Time-based" { continue; }
                    let client = client.clone();
                    let payload = payload.to_string();
                    let category = category.to_string();
                    let desc = desc.to_string();
                    let param = param.clone();
                    let target_url = target_url.clone();
                    let _baseline_length = baseline_length;
                    let baseline_status = baseline_status;
                    let semaphore = semaphore.clone();

                    join_set.spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let ua = get_random_user_agent().to_string();
                        let req_start = std::time::Instant::now();
                        let form_body = format!("{}={}", param, urlencoding::encode(&payload));

                        match client.post(&target_url)
                            .header("User-Agent", &ua)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .body(form_body)
                            .send().await
                        {
                            Ok(resp) => {
                                let elapsed = req_start.elapsed().as_millis() as u64;
                                let status = resp.status().as_u16();
                                let body = resp.text().await.unwrap_or_default();
                                let body_lower = body.to_lowercase();

                                if let Some(vuln) = Self::check_error_patterns(
                                    &param, &category, &desc, &payload, &target_url,
                                    &body_lower, status, Some(elapsed), "POST",
                                ) {
                                    return (0, Some(vuln), None, None);
                                }

                                if status != baseline_status && (status == 500 || status == 400) {
                                    return (0, Some(SqliVulnerability {
                                        parameter: param.clone(),
                                        injection_type: format!("{} - {} (Status anomaly)", category, desc),
                                        injection_category: category.clone(),
                                        severity: "medium".to_string(),
                                        payload: payload.clone(),
                                        evidence: format!("Status changed from {} to {}", baseline_status, status),
                                        request_url: target_url.clone(),
                                        confidence: 0.55,
                                        db_type: "Unknown".to_string(),
                                        response_time_ms: Some(elapsed),
                                        http_status: Some(status),
                                        method: "POST".to_string(),
                                    }), None, None);
                                }

                                (1, None, Some(SqliSafeEntry {
                                    parameter: param.clone(),
                                    tests_run: 1,
                                    method: "POST".to_string(),
                                }), None)
                            }
                            Err(e) => (2, None, None, Some(SqliErrorEntry {
                                parameter: param.clone(),
                                payload: payload.clone(),
                                error: e.to_string(),
                                method: "POST".to_string(),
                            })),
                        }
                    });
                    tests_performed += 1;
                }
            }
        }

        if config.test_cookies {
            for param in &params {
                for (payload, category, desc) in payloads {
                    if *category == "Time-based" || *category == "UNION-based" || *category == "Stacked" { continue; }
                    let client = client.clone();
                    let payload = payload.to_string();
                    let category = category.to_string();
                    let desc = desc.to_string();
                    let param = param.clone();
                    let target_url = target_url.clone();
                    let semaphore = semaphore.clone();

                    join_set.spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let ua = get_random_user_agent().to_string();
                        let cookie_val = format!("{}={}", param, urlencoding::encode(&payload));
                        let req_start = std::time::Instant::now();

                        match client.get(&target_url)
                            .header("User-Agent", &ua)
                            .header("Cookie", &cookie_val)
                            .send().await
                        {
                            Ok(resp) => {
                                let elapsed = req_start.elapsed().as_millis() as u64;
                                let status = resp.status().as_u16();
                                let body = resp.text().await.unwrap_or_default();
                                let body_lower = body.to_lowercase();

                                if let Some(vuln) = Self::check_error_patterns(
                                    &param, &category, &desc, &payload, &target_url,
                                    &body_lower, status, Some(elapsed), "Cookie",
                                ) {
                                    return (0, Some(vuln), None, None);
                                }

                                (1, None, Some(SqliSafeEntry {
                                    parameter: param.clone(),
                                    tests_run: 1,
                                    method: "Cookie".to_string(),
                                }), None)
                            }
                            Err(e) => (2, None, None, Some(SqliErrorEntry {
                                parameter: param.clone(),
                                payload: payload.clone(),
                                error: e.to_string(),
                                method: "Cookie".to_string(),
                            })),
                        }
                    });
                    tests_performed += 1;
                }
            }
        }

        if config.test_headers {
            let header_names = ["X-Forwarded-For", "X-Real-IP", "Referer", "User-Agent"];
            for header_name in header_names {
                for (payload, category, desc) in payloads {
                    if *category == "Time-based" || *category == "UNION-based" || *category == "Stacked" { continue; }
                    let client = client.clone();
                    let payload = payload.to_string();
                    let category = category.to_string();
                    let desc = desc.to_string();
                    let header_name = header_name.to_string();
                    let target_url = target_url.clone();
                    let semaphore = semaphore.clone();

                    join_set.spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let ua = get_random_user_agent().to_string();
                        let req_start = std::time::Instant::now();

                        let mut req = client.get(&target_url)
                            .header("User-Agent", &ua);

                        req = req.header(&header_name, &payload);

                        match req.send().await {
                            Ok(resp) => {
                                let elapsed = req_start.elapsed().as_millis() as u64;
                                let status = resp.status().as_u16();
                                let body = resp.text().await.unwrap_or_default();
                                let body_lower = body.to_lowercase();

                                if let Some(vuln) = Self::check_error_patterns(
                                    &header_name, &category, &desc, &payload, &target_url,
                                    &body_lower, status, Some(elapsed), "Header",
                                ) {
                                    return (0, Some(vuln), None, None);
                                }

                                (1, None, Some(SqliSafeEntry {
                                    parameter: header_name.clone(),
                                    tests_run: 1,
                                    method: "Header".to_string(),
                                }), None)
                            }
                            Err(e) => (2, None, None, Some(SqliErrorEntry {
                                parameter: header_name.clone(),
                                payload: payload.clone(),
                                error: e.to_string(),
                                method: "Header".to_string(),
                            })),
                        }
                    });
                    tests_performed += 1;
                }
            }
        }

        let mut vulnerabilities: Vec<SqliVulnerability> = Vec::new();
        let mut safe_map: HashMap<String, SqliSafeEntry> = HashMap::new();
        let mut errors: Vec<SqliErrorEntry> = Vec::new();

        while let Some(result) = join_set.join_next().await {
            if let Ok((category, vuln, safe, err)) = result {
                match category {
                    0 => { if let Some(v) = vuln { vulnerabilities.push(v); } }
                    1 => {
                        if let Some(s) = safe {
                            let key = format!("{}:{}", s.parameter, s.method);
                            let entry = safe_map.entry(key).or_insert_with(|| SqliSafeEntry {
                                parameter: s.parameter.clone(),
                                tests_run: 0,
                                method: s.method.clone(),
                            });
                            entry.tests_run += 1;
                        }
                    }
                    _ => { if let Some(e) = err { errors.push(e); } }
                }
            }
        }

        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut deduped: Vec<SqliVulnerability> = Vec::new();
        for v in &vulnerabilities {
            let key = format!("{}:{}:{}", v.parameter, v.injection_category, v.method);
            if let Some(existing_idx) = seen.get(&key) {
                if v.confidence > deduped[*existing_idx].confidence {
                    deduped[*existing_idx] = v.clone();
                }
            } else {
                seen.insert(key, deduped.len());
                deduped.push(v.clone());
            }
        }
        vulnerabilities = deduped;

        vulnerabilities.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        let safe_parameters: Vec<SqliSafeEntry> = safe_map.into_values().collect();

        let db_type_distribution = Self::build_db_type_distribution(&vulnerabilities);

        let scan_duration_ms = start.elapsed().as_millis() as u64;

        let high_count = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = vulnerabilities.iter().filter(|v| v.severity == "low").count();

        let summary = if vulnerabilities.is_empty() {
            format!("No SQL injection vulnerabilities found ({} tests on {} parameters)", tests_performed, params.len())
        } else {
            format!(
                "Found {} SQL injection vulnerabilities ({} high, {} medium, {} low) across {} parameters",
                vulnerabilities.len(), high_count, medium_count, low_count, params.len()
            )
        };

        Ok(SqliScanResult {
            url: target_url,
            vulnerabilities,
            safe_parameters,
            errors,
            tests_performed,
            parameters_tested: params,
            scan_duration_ms,
            summary,
            db_type_distribution,
        })
    }

    fn check_error_patterns(
        param: &str,
        category: &str,
        desc: &str,
        payload: &str,
        request_url: &str,
        body_lower: &str,
        status: u16,
        response_time_ms: Option<u64>,
        method: &str,
    ) -> Option<SqliVulnerability> {
        for (pattern, db_type, confidence) in ERROR_PATTERNS {
            let is_match = if pattern.contains("ora-") {
                body_lower.contains("ora-")
            } else {
                body_lower.contains(pattern)
            };

            if is_match {
                let severity = if *confidence >= 0.85 { "high" } else if *confidence >= 0.65 { "medium" } else { "low" };
                return Some(SqliVulnerability {
                    parameter: param.to_string(),
                    injection_type: format!("{} - {}", category, desc),
                    injection_category: category.to_string(),
                    severity: severity.to_string(),
                    payload: payload.to_string(),
                    evidence: pattern.to_string(),
                    request_url: request_url.to_string(),
                    confidence: *confidence,
                    db_type: db_type.to_string(),
                    response_time_ms,
                    http_status: Some(status),
                    method: method.to_string(),
                });
            }
        }
        None
    }

    fn extract_parameters(url: &str, body: &str) -> Vec<String> {
        let mut params = Vec::new();

        if let Some(query) = url.split('?').nth(1) {
            for pair in query.split('&') {
                if let Some(key) = pair.split('=').next() {
                    let key = key.trim().to_string();
                    if !key.is_empty() && !params.contains(&key) {
                        params.push(key);
                    }
                }
            }
        }

        let form_input_pattern = regex::Regex::new(r#"name=["']([^"']+)["']"#).unwrap();
        for cap in form_input_pattern.captures_iter(body) {
            let name = cap[1].to_string();
            if !name.is_empty() && !params.contains(&name) {
                params.push(name);
            }
        }

        params
    }

    fn build_db_type_distribution(vulnerabilities: &[SqliVulnerability]) -> Vec<DbTypeDistribution> {
        let mut map: HashMap<String, (usize, usize)> = HashMap::new();

        for v in vulnerabilities {
            let (count, vuln_count) = map.entry(v.db_type.clone()).or_insert((0, 0));
            *count += 1;
            if v.severity == "high" {
                *vuln_count += 1;
            }
        }

        let mut dist: Vec<DbTypeDistribution> = map.into_iter()
            .map(|(db_type, (count, vulnerable_count))| DbTypeDistribution { db_type, count, vulnerable_count })
            .collect();

        dist.sort_by(|a, b| b.count.cmp(&a.count));
        dist
    }
}
