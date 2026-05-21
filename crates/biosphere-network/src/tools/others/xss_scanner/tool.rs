use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use reqwest::Client;
use tokio::sync::Semaphore;
use url::Url;
use crate::core::{Result, ToolError};
use super::config::*;

static UA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_next_user_agent() -> &'static str {
    let idx = UA_COUNTER.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
    USER_AGENTS[idx]
}

pub struct XssScannerTool;

impl XssScannerTool {
    pub async fn scan(config: &XssScanConfig) -> Result<XssScanResult> {
        let start_time = Instant::now();

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
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let baseline_resp = client.get(&target_url).send().await;
        let (baseline_body, _baseline_status) = match baseline_resp {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                (body, Some(status))
            }
            Err(e) => {
                return Err(ToolError::ExecutionError(format!("Baseline request failed: {}", e)));
            }
        };

        let mut vulnerabilities: Vec<XssVulnerability> = Vec::new();
        let mut safe_parameters: Vec<XssSafeEntry> = Vec::new();
        let mut errors: Vec<XssErrorEntry> = Vec::new();
        let mut tests_performed: usize = 0;

        let mut params = Self::extract_parameters(&target_url, &baseline_body);

        for custom_param in &config.custom_parameters {
            if !params.contains(custom_param) {
                params.push(custom_param.clone());
            }
        }

        if params.is_empty() {
            let default_params: Vec<String> = DEFAULT_PARAMETERS.iter().take(10).map(|s| s.to_string()).collect();
            params = default_params;
        }

        let payloads = get_payloads_for_level(&config.scan_level);
        let semaphore = Arc::new(Semaphore::new(config.threads.max(1).min(20)));

        let mut param_test_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        if config.test_get {
            let (vulns, errs, test_count) = Self::test_get_parameters(
                &client,
                &target_url,
                &params,
                &payloads,
                &semaphore,
            ).await;
            vulnerabilities.extend(vulns);
            errors.extend(errs);
            tests_performed += test_count;
            for param in &params {
                *param_test_counts.entry(param.clone()).or_insert(0) += payloads.len();
            }
        }

        if config.test_post {
            let (vulns, errs, test_count) = Self::test_post_parameters(
                &client,
                &target_url,
                &params,
                &payloads,
                &semaphore,
            ).await;
            vulnerabilities.extend(vulns);
            errors.extend(errs);
            tests_performed += test_count;
            for param in &params {
                *param_test_counts.entry(format!("{}:POST", param)).or_insert(0) += payloads.len();
            }
        }

        if config.test_cookies {
            let (vulns, errs, test_count) = Self::test_cookie_parameters(
                &client,
                &target_url,
                &params,
                &payloads,
                &semaphore,
            ).await;
            vulnerabilities.extend(vulns);
            errors.extend(errs);
            tests_performed += test_count;
            for param in &params {
                *param_test_counts.entry(format!("{}:Cookie", param)).or_insert(0) += payloads.len();
            }
        }

        if config.test_headers {
            let (vulns, errs, test_count) = Self::test_header_parameters(
                &client,
                &target_url,
                &params,
                &payloads,
                &semaphore,
            ).await;
            vulnerabilities.extend(vulns);
            errors.extend(errs);
            tests_performed += test_count;
            for param in &params {
                *param_test_counts.entry(format!("{}:Header", param)).or_insert(0) += payloads.len();
            }
        }

        let dom_vulns = Self::detect_dom_xss(&baseline_body, &target_url);
        vulnerabilities.extend(dom_vulns);

        let vuln_params: HashSet<String> = vulnerabilities.iter().map(|v| v.parameter.clone()).collect();
        for param in &params {
            if !vuln_params.contains(param) {
                let total_tests = param_test_counts.get(param).copied().unwrap_or(0)
                    + param_test_counts.get(&format!("{}:POST", param)).copied().unwrap_or(0)
                    + param_test_counts.get(&format!("{}:Cookie", param)).copied().unwrap_or(0)
                    + param_test_counts.get(&format!("{}:Header", param)).copied().unwrap_or(0);
                if total_tests > 0 {
                    safe_parameters.push(XssSafeEntry {
                        parameter: param.clone(),
                        tests_run: total_tests,
                        method: "GET".to_string(),
                    });
                }
            }
        }

        let xss_type_distribution = Self::calculate_type_distribution(&vulnerabilities);
        let scan_duration_ms = start_time.elapsed().as_millis() as u64;
        let summary = Self::generate_summary(&vulnerabilities, tests_performed, &params, scan_duration_ms);

        Ok(XssScanResult {
            url: target_url,
            vulnerabilities,
            safe_parameters,
            errors,
            tests_performed,
            parameters_tested: params,
            scan_duration_ms,
            summary,
            xss_type_distribution,
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
            r#"<textarea[^>]*name\s*=\s*([^\s>]+)"#,
            r#"<select[^>]*name\s*=\s*["']([^"']+)["']"#,
            r#"<select[^>]*name\s*=\s*([^\s>]+)"#,
        ];

        for pattern in form_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
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

        params
    }

    async fn test_get_parameters(
        client: &Client,
        url: &str,
        parameters: &[String],
        payloads: &[&XssPayload],
        semaphore: &Arc<Semaphore>,
    ) -> (Vec<XssVulnerability>, Vec<XssErrorEntry>, usize) {
        let mut vulnerabilities: Vec<XssVulnerability> = Vec::new();
        let mut error_entries: Vec<XssErrorEntry> = Vec::new();
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
                let xss_type = payload_info.xss_type.to_string();
                let injection_context = payload_info.injection_context.to_string();
                let semaphore_clone = semaphore.clone();

                join_set.spawn(async move {
                    let _permit = semaphore_clone.acquire().await.unwrap();

                    let test_url = Self::build_url_with_param(&url_clone, &param_clone, &payload_str);
                    let request_start = Instant::now();

                    match client_clone.get(&test_url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time = request_start.elapsed().as_millis() as u64;
                            if let Ok(body) = resp.text().await {
                                if let Some(confidence) = Self::check_xss_reflection(&body, &payload_str, &injection_context) {
                                    return Some((Some(XssVulnerability {
                                        parameter: param_clone,
                                        xss_type,
                                        injection_context,
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
                            return Some((None, Some(XssErrorEntry {
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
        payloads: &[&XssPayload],
        semaphore: &Arc<Semaphore>,
    ) -> (Vec<XssVulnerability>, Vec<XssErrorEntry>, usize) {
        let mut vulnerabilities: Vec<XssVulnerability> = Vec::new();
        let mut error_entries: Vec<XssErrorEntry> = Vec::new();
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
                let xss_type = payload_info.xss_type.to_string();
                let injection_context = payload_info.injection_context.to_string();
                let semaphore_clone = semaphore.clone();

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
                                if let Some(confidence) = Self::check_xss_reflection(&body, &payload_str, &injection_context) {
                                    return Some((Some(XssVulnerability {
                                        parameter: param_clone,
                                        xss_type,
                                        injection_context,
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
                            return Some((None, Some(XssErrorEntry {
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
        payloads: &[&XssPayload],
        semaphore: &Arc<Semaphore>,
    ) -> (Vec<XssVulnerability>, Vec<XssErrorEntry>, usize) {
        let mut vulnerabilities: Vec<XssVulnerability> = Vec::new();
        let mut error_entries: Vec<XssErrorEntry> = Vec::new();
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
                let xss_type = payload_info.xss_type.to_string();
                let injection_context = payload_info.injection_context.to_string();
                let semaphore_clone = semaphore.clone();

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
                                if let Some(confidence) = Self::check_xss_reflection(&body, &payload_str, &injection_context) {
                                    return Some((Some(XssVulnerability {
                                        parameter: param_clone,
                                        xss_type,
                                        injection_context,
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
                            return Some((None, Some(XssErrorEntry {
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
        payloads: &[&XssPayload],
        semaphore: &Arc<Semaphore>,
    ) -> (Vec<XssVulnerability>, Vec<XssErrorEntry>, usize) {
        let mut vulnerabilities: Vec<XssVulnerability> = Vec::new();
        let mut error_entries: Vec<XssErrorEntry> = Vec::new();
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
                let xss_type = payload_info.xss_type.to_string();
                let injection_context = payload_info.injection_context.to_string();
                let semaphore_clone = semaphore.clone();

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
                                if let Some(confidence) = Self::check_xss_reflection(&body, &payload_str, &injection_context) {
                                    return Some((Some(XssVulnerability {
                                        parameter: format!("{}: {}", param_clone, header_name),
                                        xss_type,
                                        injection_context,
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
                            return Some((None, Some(XssErrorEntry {
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

    fn detect_dom_xss(body: &str, url: &str) -> Vec<XssVulnerability> {
        let mut vulnerabilities = Vec::new();
        let body_lower = body.to_lowercase();

        let mut found_sinks: Vec<&str> = Vec::new();
        for sink in DOM_SINKS {
            if body_lower.contains(&sink.to_lowercase()) {
                found_sinks.push(sink);
            }
        }

        let mut found_sources: Vec<&str> = Vec::new();
        for source in DOM_SOURCES {
            if body_lower.contains(&source.to_lowercase()) {
                found_sources.push(source);
            }
        }

        if !found_sinks.is_empty() && !found_sources.is_empty() {
            let evidence = format!(
                "DOM XSS potential: sinks [{}] with sources [{}]",
                found_sinks.join(", "),
                found_sources.join(", ")
            );

            vulnerabilities.push(XssVulnerability {
                parameter: "DOM".to_string(),
                xss_type: "dom".to_string(),
                injection_context: "dom".to_string(),
                severity: "medium".to_string(),
                payload: "DOM-based (no direct payload)".to_string(),
                evidence,
                request_url: url.to_string(),
                confidence: 0.6,
                method: "DOM".to_string(),
                response_time_ms: None,
                http_status: None,
            });
        }

        vulnerabilities
    }

    fn check_xss_reflection(body: &str, payload: &str, context: &str) -> Option<f64> {
        let normalized_body = body.to_lowercase();
        let normalized_payload = payload.to_lowercase();

        match context {
            "html" => {
                if normalized_body.contains(&normalized_payload) {
                    return Some(0.9);
                }

                let decoded_payload = Self::decode_payload_variants(payload);
                for decoded in &decoded_payload {
                    if normalized_body.contains(&decoded.to_lowercase()) {
                        return Some(0.75);
                    }
                }

                let html_indicators = [
                    "<script", "<img", "<svg", "<iframe", "<body",
                    "<input", "<select", "<textarea", "<button",
                    "<div", "<a ", "<object", "<embed", "<video",
                    "<audio", "<details", "<marquee", "<math",
                ];
                for indicator in &html_indicators {
                    if normalized_payload.contains(indicator) && normalized_body.contains(indicator) {
                        let event_indicators = ["onerror", "onload", "onfocus", "onclick", "ontoggle", "onmouseover", "onstart", "onpageshow", "onanimationstart", "ontransitionend"];
                        for event in &event_indicators {
                            if normalized_payload.contains(event) && normalized_body.contains(event) {
                                return Some(0.85);
                            }
                        }
                    }
                }
            }
            "js" => {
                if normalized_body.contains(&normalized_payload) {
                    return Some(0.9);
                }

                let js_indicators = ["alert(", "alert`", "eval(", "confirm(", "prompt("];
                for indicator in &js_indicators {
                    if normalized_payload.contains(indicator) && normalized_body.contains(indicator) {
                        return Some(0.8);
                    }
                }

                if normalized_payload.contains("alert(1)") && normalized_body.contains("alert(1)") {
                    return Some(0.85);
                }
            }
            "attribute" => {
                if normalized_body.contains(&normalized_payload) {
                    return Some(0.9);
                }

                if normalized_payload.contains("javascript:") && normalized_body.contains("javascript:") {
                    return Some(0.85);
                }

                let attr_indicators = ["onfocus=", "onmouseover=", "onclick=", "onerror=", "onload="];
                for indicator in &attr_indicators {
                    if normalized_payload.contains(indicator) && normalized_body.contains(indicator) {
                        return Some(0.8);
                    }
                }
            }
            "dom" => {
                if normalized_body.contains(&normalized_payload) {
                    return Some(0.7);
                }
            }
            _ => {
                if normalized_body.contains(&normalized_payload) {
                    return Some(0.8);
                }
            }
        }

        None
    }

    fn decode_payload_variants(payload: &str) -> Vec<String> {
        let mut variants = Vec::new();

        if payload.contains("&#x3C;") || payload.contains("&#60;") {
            let decoded = payload
                .replace("&#x3C;", "<").replace("&#x3E;", ">")
                .replace("&#60;", "<").replace("&#62;", ">")
                .replace("&#40;", "(").replace("&#41;", ")")
                .replace("&lpar;", "(").replace("&rpar;", ")");
            variants.push(decoded);
        }

        if payload.contains("%3C") || payload.contains("%3E") {
            let decoded = payload
                .replace("%3C", "<").replace("%3E", ">")
                .replace("%2F", "/").replace("%28", "(")
                .replace("%29", ")");
            variants.push(decoded);
        }

        if payload.contains("%25") {
            let decoded = payload
                .replace("%253C", "<").replace("%253E", ">")
                .replace("%252F", "/");
            variants.push(decoded);
        }

        variants
    }

    fn build_url_with_param(base_url: &str, param: &str, value: &str) -> String {
        let mut url: Url = match Url::parse(base_url) {
            Ok(u) => u,
            Err(_) => return base_url.to_string(),
        };

        url.query_pairs_mut().append_pair(param, value);
        url.to_string()
    }

    fn calculate_type_distribution(vulnerabilities: &[XssVulnerability]) -> Vec<XssTypeDistribution> {
        let mut type_map: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();

        for vuln in vulnerabilities {
            let entry = type_map.entry(vuln.xss_type.clone()).or_insert((0, 0));
            entry.0 += 1;
            if vuln.severity == "high" || vuln.severity == "medium" {
                entry.1 += 1;
            }
        }

        let mut dist: Vec<XssTypeDistribution> = type_map
            .into_iter()
            .map(|(xss_type, (count, vulnerable_count))| XssTypeDistribution {
                xss_type,
                count,
                vulnerable_count,
            })
            .collect();

        dist.sort_by(|a, b| b.count.cmp(&a.count));
        dist
    }

    fn generate_summary(
        vulnerabilities: &[XssVulnerability],
        tests_performed: usize,
        parameters_tested: &[String],
        scan_duration_ms: u64,
    ) -> String {
        let high_count = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = vulnerabilities.iter().filter(|v| v.severity == "low").count();
        let reflected_count = vulnerabilities.iter().filter(|v| v.xss_type == "reflected").count();
        let dom_count = vulnerabilities.iter().filter(|v| v.xss_type == "dom").count();

        let duration_str = if scan_duration_ms < 1000 {
            format!("{}ms", scan_duration_ms)
        } else {
            format!("{:.1}s", scan_duration_ms as f64 / 1000.0)
        };

        format!(
            "XSS scan completed: {} params tested, {} tests performed in {}. Found {} vulnerabilities (Reflected: {}, DOM: {}) - High: {}, Medium: {}, Low: {}",
            parameters_tested.len(),
            tests_performed,
            duration_str,
            vulnerabilities.len(),
            reflected_count,
            dom_count,
            high_count,
            medium_count,
            low_count
        )
    }
}
