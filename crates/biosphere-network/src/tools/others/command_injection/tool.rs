use crate::tools::others::command_injection::config::*;
use regex::Regex;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use url::Url;

static UA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_next_user_agent() -> &'static str {
    let idx = UA_COUNTER.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
    USER_AGENTS[idx]
}

pub struct CommandInjectionTool;

impl CommandInjectionTool {
    pub async fn scan(config: &CommandInjectionConfig) -> Result<CommandInjectionResult, String> {
        let start = Instant::now();

        let trimmed = config.url.trim();
        let target_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{}", trimmed)
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .redirect(reqwest::redirect::Policy::limited(3))
            .danger_accept_invalid_certs(true)
            .user_agent(get_next_user_agent())
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let baseline_resp = client.get(&target_url).send().await
            .map_err(|e| format!("Baseline request failed: {}", e))?;
        let baseline_body = baseline_resp.text().await.unwrap_or_default();
        let baseline_time = start.elapsed().as_millis() as u64;

        let payloads: Vec<&CiPayload> = match config.scan_level.as_str() {
            "basic" => BASIC_PAYLOADS.iter().collect(),
            "moderate" => MODERATE_PAYLOADS.iter().collect(),
            "aggressive" => AGGRESSIVE_PAYLOADS.iter().collect(),
            _ => MODERATE_PAYLOADS.iter().collect(),
        };

        let mut params = Self::extract_parameters(&target_url, &baseline_body);
        for custom_param in &config.custom_parameters {
            if !params.contains(custom_param) {
                params.push(custom_param.clone());
            }
        }

        let semaphore = Arc::new(Semaphore::new(config.threads));
        let mut vulnerabilities: Vec<CommandInjectionVuln> = Vec::new();
        let mut safe_parameters: Vec<CommandInjectionSafeEntry> = Vec::new();
        let mut error_entries: Vec<CommandInjectionErrorEntry> = Vec::new();
        let mut tests_performed: usize = 0;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let mut param_test_counts: HashMap<String, (usize, usize)> = HashMap::new();

        if config.test_get {
            let (vulns, errs, tests) = Self::test_get_parameters(
                &client, &target_url, &params, &payloads, &semaphore, &baseline_body,
            ).await;
            tests_performed += tests;
            for vuln in vulns {
                let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                param_test_counts.entry(vuln.parameter.clone()).or_insert((0, 0)).1 += 1;
                if seen.insert(key) {
                    vulnerabilities.push(vuln);
                }
            }
            for err in errs {
                param_test_counts.entry(err.parameter.clone()).or_insert((0, 0)).0 += 1;
                error_entries.push(err);
            }
        }

        if config.test_post {
            let (vulns, errs, tests) = Self::test_post_parameters(
                &client, &target_url, &params, &payloads, &semaphore, &baseline_body,
            ).await;
            tests_performed += tests;
            for vuln in vulns {
                let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                param_test_counts.entry(vuln.parameter.clone()).or_insert((0, 0)).1 += 1;
                if seen.insert(key) {
                    vulnerabilities.push(vuln);
                }
            }
            for err in errs {
                param_test_counts.entry(err.parameter.clone()).or_insert((0, 0)).0 += 1;
                error_entries.push(err);
            }
        }

        if config.test_cookies {
            let (vulns, errs, tests) = Self::test_cookie_parameters(
                &client, &target_url, &params, &payloads, &semaphore, &baseline_body,
            ).await;
            tests_performed += tests;
            for vuln in vulns {
                let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                param_test_counts.entry(vuln.parameter.clone()).or_insert((0, 0)).1 += 1;
                if seen.insert(key) {
                    vulnerabilities.push(vuln);
                }
            }
            for err in errs {
                param_test_counts.entry(err.parameter.clone()).or_insert((0, 0)).0 += 1;
                error_entries.push(err);
            }
        }

        if config.test_headers {
            let (vulns, errs, tests) = Self::test_header_parameters(
                &client, &target_url, &params, &payloads, &semaphore, &baseline_body,
            ).await;
            tests_performed += tests;
            for vuln in vulns {
                let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                param_test_counts.entry(vuln.parameter.clone()).or_insert((0, 0)).1 += 1;
                if seen.insert(key) {
                    vulnerabilities.push(vuln);
                }
            }
            for err in errs {
                param_test_counts.entry(err.parameter.clone()).or_insert((0, 0)).0 += 1;
                error_entries.push(err);
            }
        }

        if config.scan_level == "aggressive" {
            let (time_vulns, time_tests) = Self::test_time_based(
                &client, &target_url, &params, &semaphore, baseline_time,
            ).await;
            tests_performed += time_tests;
            for vuln in time_vulns {
                let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                if seen.insert(key) {
                    vulnerabilities.push(vuln);
                }
            }
        }

        for param in &params {
            let (_total, vuln_count) = param_test_counts.get(param).copied().unwrap_or((0, 0));
            if vuln_count == 0 {
                let total_tests = payloads.len();
                safe_parameters.push(CommandInjectionSafeEntry {
                    parameter: param.clone(),
                    tests_run: total_tests,
                    method: "ALL".to_string(),
                });
            }
        }

        let os_type_distribution = Self::calculate_os_distribution(&vulnerabilities);
        let scan_duration_ms = start.elapsed().as_millis() as u64;
        let summary = Self::generate_summary(
            &vulnerabilities, tests_performed, &params, scan_duration_ms,
        );

        Ok(CommandInjectionResult {
            url: target_url,
            vulnerabilities,
            safe_parameters,
            errors: error_entries,
            tests_performed,
            parameters_tested: params,
            scan_duration_ms,
            exploit_results: Vec::new(),
            blind_injection_results: Vec::new(),
            encoded_bypass_results: Vec::new(),
            summary,
            os_type_distribution,
        })
    }

    fn extract_parameters(url: &str, body: &str) -> Vec<String> {
        let mut params: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        if let Ok(parsed_url) = Url::parse(url) {
            for (key, _) in parsed_url.query_pairs() {
                let key_str: String = key.into_owned();
                if seen.insert(key_str.clone()) {
                    params.push(key_str);
                }
            }
        }

        let form_patterns = vec![
            r#"<input[^>]*name\s*=\s*["']([^"']+)["']"#,
            r#"<input[^>]*name\s*=\s*([^\s>]+)"#,
            r#"<textarea[^>]*name\s*=\s*["']([^"']+)["']"#,
            r#"<select[^>]*name\s*=\s*["']([^"']+)["']"#,
        ];

        for pattern in form_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(body) {
                    if let Some(name) = cap.get(1) {
                        let param = name.as_str().to_string();
                        if seen.insert(param.clone()) {
                            params.push(param);
                        }
                    }
                }
            }
        }

        if params.is_empty() {
            let defaults = vec!["id", "q", "search", "query", "page", "cmd", "exec", "file", "dir", "path", "action", "name", "user", "input"];
            for d in defaults {
                if seen.insert(d.to_string()) {
                    params.push(d.to_string());
                }
            }
        }

        params
    }

    async fn test_get_parameters(
        client: &Client,
        url: &str,
        parameters: &[String],
        payloads: &[&CiPayload],
        semaphore: &Arc<Semaphore>,
        baseline_body: &str,
    ) -> (Vec<CommandInjectionVuln>, Vec<CommandInjectionErrorEntry>, usize) {
        let mut vulnerabilities: Vec<CommandInjectionVuln> = Vec::new();
        let mut error_entries: Vec<CommandInjectionErrorEntry> = Vec::new();
        let mut tests_performed: usize = 0;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let mut join_set = tokio::task::JoinSet::new();

        for param in parameters {
            for payload_info in payloads {
                tests_performed += 1;

                let client_clone = client.clone();
                let url_clone = url.to_string();
                let param_clone = param.clone();
                let payload_str = payload_info.payload.to_string();
                let severity = payload_info.severity.to_string();
                let injection_type = payload_info.injection_type.to_string();
                let os_type = payload_info.os_type.to_string();
                let semaphore_clone = semaphore.clone();
                let baseline_body_owned = baseline_body.to_string();

                join_set.spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();

                    let test_url = Self::build_url_with_param(&url_clone, &param_clone, &payload_str);
                    let request_start = Instant::now();

                    match client_clone.get(&test_url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time = request_start.elapsed().as_millis() as u64;
                            if let Ok(body) = resp.text().await {
                                if let Some((os_detected, confidence)) = Self::check_injection_response(&body, &baseline_body_owned) {
                                    let final_os = if os_detected != "unknown" { os_detected } else { os_type };
                                    return Some((Some(CommandInjectionVuln {
                                        parameter: param_clone,
                                        injection_type,
                                        os_type: final_os,
                                        severity,
                                        payload: payload_str,
                                        evidence: body.chars().take(500).collect(),
                                        request_url: test_url,
                                        confidence,
                                        method: "GET".to_string(),
                                        response_time_ms: Some(response_time),
                                        http_status: Some(status),
                                    }), None));
                                }
                            }
                        }
                        Err(e) => {
                            return Some((None, Some(CommandInjectionErrorEntry {
                                parameter: param_clone,
                                payload: payload_str,
                                error: e.to_string(),
                                method: "GET".to_string(),
                            })));
                        }
                    }
                    None
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some((vuln_opt, err_opt))) = result {
                if let Some(vuln) = vuln_opt {
                    let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                    if seen.insert(key) {
                        vulnerabilities.push(vuln);
                    }
                }
                if let Some(err) = err_opt {
                    error_entries.push(err);
                }
            }
        }

        (vulnerabilities, error_entries, tests_performed)
    }

    async fn test_post_parameters(
        client: &Client,
        url: &str,
        parameters: &[String],
        payloads: &[&CiPayload],
        semaphore: &Arc<Semaphore>,
        baseline_body: &str,
    ) -> (Vec<CommandInjectionVuln>, Vec<CommandInjectionErrorEntry>, usize) {
        let mut vulnerabilities: Vec<CommandInjectionVuln> = Vec::new();
        let mut error_entries: Vec<CommandInjectionErrorEntry> = Vec::new();
        let mut tests_performed: usize = 0;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let mut join_set = tokio::task::JoinSet::new();

        for param in parameters {
            for payload_info in payloads {
                tests_performed += 1;

                let client_clone = client.clone();
                let url_clone = url.to_string();
                let param_clone = param.clone();
                let payload_str = payload_info.payload.to_string();
                let severity = payload_info.severity.to_string();
                let injection_type = payload_info.injection_type.to_string();
                let os_type = payload_info.os_type.to_string();
                let semaphore_clone = semaphore.clone();
                let baseline_body_owned = baseline_body.to_string();

                join_set.spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();

                    let mut form_data = std::collections::HashMap::new();
                    form_data.insert(param_clone.clone(), payload_str.clone());

                    let request_start = Instant::now();

                    match client_clone.post(&url_clone).form(&form_data).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time = request_start.elapsed().as_millis() as u64;
                            if let Ok(body) = resp.text().await {
                                if let Some((os_detected, confidence)) = Self::check_injection_response(&body, &baseline_body_owned) {
                                    let final_os = if os_detected != "unknown" { os_detected } else { os_type };
                                    return Some((Some(CommandInjectionVuln {
                                        parameter: param_clone,
                                        injection_type,
                                        os_type: final_os,
                                        severity,
                                        payload: payload_str,
                                        evidence: body.chars().take(500).collect(),
                                        request_url: url_clone,
                                        confidence,
                                        method: "POST".to_string(),
                                        response_time_ms: Some(response_time),
                                        http_status: Some(status),
                                    }), None));
                                }
                            }
                        }
                        Err(e) => {
                            return Some((None, Some(CommandInjectionErrorEntry {
                                parameter: param_clone,
                                payload: payload_str,
                                error: e.to_string(),
                                method: "POST".to_string(),
                            })));
                        }
                    }
                    None
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some((vuln_opt, err_opt))) = result {
                if let Some(vuln) = vuln_opt {
                    let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                    if seen.insert(key) {
                        vulnerabilities.push(vuln);
                    }
                }
                if let Some(err) = err_opt {
                    error_entries.push(err);
                }
            }
        }

        (vulnerabilities, error_entries, tests_performed)
    }

    async fn test_cookie_parameters(
        client: &Client,
        url: &str,
        parameters: &[String],
        payloads: &[&CiPayload],
        semaphore: &Arc<Semaphore>,
        baseline_body: &str,
    ) -> (Vec<CommandInjectionVuln>, Vec<CommandInjectionErrorEntry>, usize) {
        let mut vulnerabilities: Vec<CommandInjectionVuln> = Vec::new();
        let mut error_entries: Vec<CommandInjectionErrorEntry> = Vec::new();
        let mut tests_performed: usize = 0;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let mut join_set = tokio::task::JoinSet::new();

        for param in parameters {
            for payload_info in payloads {
                tests_performed += 1;

                let client_clone = client.clone();
                let url_clone = url.to_string();
                let param_clone = param.clone();
                let payload_str = payload_info.payload.to_string();
                let severity = payload_info.severity.to_string();
                let injection_type = payload_info.injection_type.to_string();
                let os_type = payload_info.os_type.to_string();
                let semaphore_clone = semaphore.clone();
                let baseline_body_owned = baseline_body.to_string();

                join_set.spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();

                    let cookie_value = format!("{}={}", param_clone, payload_str);
                    let request_start = Instant::now();

                    match client_clone
                        .get(&url_clone)
                        .header("Cookie", &cookie_value)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time = request_start.elapsed().as_millis() as u64;
                            if let Ok(body) = resp.text().await {
                                if let Some((os_detected, confidence)) = Self::check_injection_response(&body, &baseline_body_owned) {
                                    let final_os = if os_detected != "unknown" { os_detected } else { os_type };
                                    return Some((Some(CommandInjectionVuln {
                                        parameter: param_clone,
                                        injection_type,
                                        os_type: final_os,
                                        severity,
                                        payload: payload_str,
                                        evidence: body.chars().take(500).collect(),
                                        request_url: url_clone,
                                        confidence,
                                        method: "Cookie".to_string(),
                                        response_time_ms: Some(response_time),
                                        http_status: Some(status),
                                    }), None));
                                }
                            }
                        }
                        Err(e) => {
                            return Some((None, Some(CommandInjectionErrorEntry {
                                parameter: param_clone,
                                payload: payload_str,
                                error: e.to_string(),
                                method: "Cookie".to_string(),
                            })));
                        }
                    }
                    None
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some((vuln_opt, err_opt))) = result {
                if let Some(vuln) = vuln_opt {
                    let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                    if seen.insert(key) {
                        vulnerabilities.push(vuln);
                    }
                }
                if let Some(err) = err_opt {
                    error_entries.push(err);
                }
            }
        }

        (vulnerabilities, error_entries, tests_performed)
    }

    async fn test_header_parameters(
        client: &Client,
        url: &str,
        parameters: &[String],
        payloads: &[&CiPayload],
        semaphore: &Arc<Semaphore>,
        baseline_body: &str,
    ) -> (Vec<CommandInjectionVuln>, Vec<CommandInjectionErrorEntry>, usize) {
        let mut vulnerabilities: Vec<CommandInjectionVuln> = Vec::new();
        let mut error_entries: Vec<CommandInjectionErrorEntry> = Vec::new();
        let mut tests_performed: usize = 0;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let mut join_set = tokio::task::JoinSet::new();

        for param in parameters {
            for payload_info in payloads {
                tests_performed += 1;

                let client_clone = client.clone();
                let url_clone = url.to_string();
                let param_clone = param.clone();
                let payload_str = payload_info.payload.to_string();
                let severity = payload_info.severity.to_string();
                let injection_type = payload_info.injection_type.to_string();
                let os_type = payload_info.os_type.to_string();
                let semaphore_clone = semaphore.clone();
                let baseline_body_owned = baseline_body.to_string();

                join_set.spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();

                    let request_start = Instant::now();

                    let header_name = match param_clone.to_lowercase().as_str() {
                        "referer" | "ref" => "Referer".to_string(),
                        "user-agent" | "ua" => "User-Agent".to_string(),
                        "x-forwarded-for" | "xff" => "X-Forwarded-For".to_string(),
                        "origin" => "Origin".to_string(),
                        "accept" => "Accept".to_string(),
                        _ => format!("X-{}", param_clone),
                    };

                    match client_clone
                        .get(&url_clone)
                        .header(&header_name, &payload_str)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time = request_start.elapsed().as_millis() as u64;
                            if let Ok(body) = resp.text().await {
                                if let Some((os_detected, confidence)) = Self::check_injection_response(&body, &baseline_body_owned) {
                                    let final_os = if os_detected != "unknown" { os_detected } else { os_type };
                                    return Some((Some(CommandInjectionVuln {
                                        parameter: format!("{}: {}", param_clone, header_name),
                                        injection_type,
                                        os_type: final_os,
                                        severity,
                                        payload: payload_str,
                                        evidence: body.chars().take(500).collect(),
                                        request_url: url_clone,
                                        confidence,
                                        method: "Header".to_string(),
                                        response_time_ms: Some(response_time),
                                        http_status: Some(status),
                                    }), None));
                                }
                            }
                        }
                        Err(e) => {
                            return Some((None, Some(CommandInjectionErrorEntry {
                                parameter: param_clone,
                                payload: payload_str,
                                error: e.to_string(),
                                method: "Header".to_string(),
                            })));
                        }
                    }
                    None
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some((vuln_opt, err_opt))) = result {
                if let Some(vuln) = vuln_opt {
                    let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                    if seen.insert(key) {
                        vulnerabilities.push(vuln);
                    }
                }
                if let Some(err) = err_opt {
                    error_entries.push(err);
                }
            }
        }

        (vulnerabilities, error_entries, tests_performed)
    }

    async fn test_time_based(
        client: &Client,
        url: &str,
        parameters: &[String],
        semaphore: &Arc<Semaphore>,
        baseline_time_ms: u64,
    ) -> (Vec<CommandInjectionVuln>, usize) {
        let mut vulnerabilities: Vec<CommandInjectionVuln> = Vec::new();
        let mut tests_performed: usize = 0;
        let mut seen: HashSet<(String, String, String)> = HashSet::new();

        let mut join_set = tokio::task::JoinSet::new();

        for param in parameters {
            for (payload, delay_secs) in TIME_DELAY_PAYLOADS {
                tests_performed += 1;

                let client_clone = client.clone();
                let url_clone = url.to_string();
                let param_clone = param.clone();
                let payload_str = payload.to_string();
                let semaphore_clone = semaphore.clone();
                let delay_ms = *delay_secs as u64 * 1000;
                let baseline = baseline_time_ms;

                join_set.spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();

                    let test_url = Self::build_url_with_param(&url_clone, &param_clone, &payload_str);
                    let request_start = Instant::now();

                    match client_clone.get(&test_url).send().await {
                        Ok(resp) => {
                            let response_time = request_start.elapsed().as_millis() as u64;
                            let _ = resp.text().await;

                            if response_time >= baseline + delay_ms {
                                return Some(CommandInjectionVuln {
                                    parameter: param_clone,
                                    injection_type: "time-based".to_string(),
                                    os_type: "unknown".to_string(),
                                    severity: "high".to_string(),
                                    payload: payload_str,
                                    evidence: format!("Response delayed {}ms (baseline: {}ms, expected delay: {}ms)", response_time, baseline, delay_ms),
                                    request_url: test_url,
                                    confidence: 0.7,
                                    method: "GET".to_string(),
                                    response_time_ms: Some(response_time),
                                    http_status: None,
                                });
                            }
                        }
                        Err(_) => {}
                    }
                    None
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(vuln)) = result {
                let key = (vuln.parameter.clone(), vuln.payload.clone(), vuln.method.clone());
                if seen.insert(key) {
                    vulnerabilities.push(vuln);
                }
            }
        }

        (vulnerabilities, tests_performed)
    }

    fn check_injection_response(body: &str, baseline_body: &str) -> Option<(String, f64)> {
        let body_lower = body.to_lowercase();
        let baseline_lower = baseline_body.to_lowercase();

        let mut linux_matches: usize = 0;
        let mut windows_matches: usize = 0;

        for indicator in LINUX_INDICATORS {
            if body_lower.contains(&indicator.to_lowercase()) && !baseline_lower.contains(&indicator.to_lowercase()) {
                linux_matches += 1;
            }
        }

        for indicator in WINDOWS_INDICATORS {
            if body_lower.contains(&indicator.to_lowercase()) && !baseline_lower.contains(&indicator.to_lowercase()) {
                windows_matches += 1;
            }
        }

        if linux_matches > 0 && windows_matches > 0 {
            let confidence = if linux_matches >= 3 || windows_matches >= 3 { 0.95 } else { 0.8 };
            return Some(("mixed".to_string(), confidence));
        }

        if linux_matches >= 2 {
            let confidence = if linux_matches >= 4 { 0.95 } else if linux_matches >= 3 { 0.9 } else { 0.8 };
            return Some(("linux".to_string(), confidence));
        }

        if windows_matches >= 2 {
            let confidence = if windows_matches >= 4 { 0.95 } else if windows_matches >= 3 { 0.9 } else { 0.8 };
            return Some(("windows".to_string(), confidence));
        }

        if linux_matches == 1 {
            return Some(("linux".to_string(), 0.6));
        }

        if windows_matches == 1 {
            return Some(("windows".to_string(), 0.6));
        }

        if body.len() != baseline_body.len() {
            let diff_ratio = (body.len() as f64 - baseline_body.len() as f64).abs()
                / baseline_body.len().max(1) as f64;
            if diff_ratio > 0.3 {
                return Some(("unknown".to_string(), 0.4));
            }
        }

        None
    }

    fn build_url_with_param(base_url: &str, param: &str, value: &str) -> String {
        let mut url: Url = match Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return base_url.to_string(),
        };

        url.query_pairs_mut().append_pair(param, value);
        url.to_string()
    }

    fn calculate_os_distribution(vulnerabilities: &[CommandInjectionVuln]) -> Vec<OsTypeDistribution> {
        let mut os_map: HashMap<String, (usize, usize)> = HashMap::new();

        for vuln in vulnerabilities {
            let entry = os_map.entry(vuln.os_type.clone()).or_insert((0, 0));
            entry.0 += 1;
            if vuln.severity == "high" || vuln.severity == "critical" {
                entry.1 += 1;
            }
        }

        let mut dist: Vec<OsTypeDistribution> = os_map
            .into_iter()
            .map(|(os_type, (count, vulnerable_count))| OsTypeDistribution {
                os_type,
                count,
                vulnerable_count,
            })
            .collect();

        dist.sort_by(|a, b| b.count.cmp(&a.count));
        dist
    }

    fn generate_summary(
        vulnerabilities: &[CommandInjectionVuln],
        tests_performed: usize,
        parameters_tested: &[String],
        scan_duration_ms: u64,
    ) -> String {
        let critical = vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium = vulnerabilities.iter().filter(|v| v.severity == "medium").count();

        let os_types: HashSet<&str> = vulnerabilities.iter().map(|v| v.os_type.as_str()).collect();
        let injection_types: HashSet<&str> = vulnerabilities.iter().map(|v| v.injection_type.as_str()).collect();

        let duration_str = if scan_duration_ms < 1000 {
            format!("{}ms", scan_duration_ms)
        } else {
            format!("{:.1}s", scan_duration_ms as f64 / 1000.0)
        };

        if vulnerabilities.is_empty() {
            format!(
                "Command injection scan completed: {} parameters tested, {} tests performed in {}. No vulnerabilities found.",
                parameters_tested.len(), tests_performed, duration_str
            )
        } else {
            format!(
                "Command injection scan completed: {} parameters tested, {} tests performed in {}. Found {} vulnerabilities ({} critical, {} high, {} medium). OS types: {}. Injection types: {}.",
                parameters_tested.len(),
                tests_performed,
                duration_str,
                vulnerabilities.len(),
                critical,
                high,
                medium,
                os_types.into_iter().collect::<Vec<_>>().join(", "),
                injection_types.into_iter().collect::<Vec<_>>().join(", "),
            )
        }
    }
}
