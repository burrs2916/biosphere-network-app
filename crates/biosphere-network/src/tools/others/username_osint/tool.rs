use crate::core::{Result, ToolError};
use crate::infrastructure::database::models::OsintPlatform;
use crate::infrastructure::database::Database;
use super::config::{
    UsernameOsintConfig, UsernameOsintResult, PlatformResult, CategorySummary,
    BatchUsernameResult, OsintProgress, ErrorAnalysis, ErrorCategory, ExtractedUserInfo, PLATFORM_CATEGORIES,
    generate_username_permutations, RecursiveSearchResult,
};
use super::error_detection::{detect_common_errors, detect_error_page};
use super::id_types::{ExtractedId, extract_ids_from_html, extract_ids_from_results};
use super::request_profile::RequestProfile;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::Semaphore;
use regex::Regex;

const MIN_RESPONSE_SIZE: usize = 50;

const BAD_CHARS: &[char] = &['#', '/', ' ', '&', '?', '%'];

pub struct UsernameOsintTool;

impl UsernameOsintTool {
    pub fn resolve_platforms(db: &Database, config: &UsernameOsintConfig) -> Result<Vec<OsintPlatform>> {
        let mut platforms = if !config.platforms.is_empty() {
            let mut result = Vec::new();
            for name in &config.platforms {
                if let Ok(Some(p)) = db.get_osint_platform_by_name(name) {
                    if config.use_disabled_sites || p.is_active {
                        result.push(p);
                    }
                }
            }
            result
        } else if !config.categories.is_empty() {
            let mut result = Vec::new();
            for cat in &config.categories {
                if let Ok(plats) = db.get_osint_platforms(Some(cat), !config.use_disabled_sites) {
                    result.extend(plats);
                }
            }
            result.sort_by(|a, b| b.priority.cmp(&a.priority));
            result.dedup_by(|a, b| a.name == b.name);
            result
        } else {
            db.get_osint_platforms(None, !config.use_disabled_sites)
                .map_err(|e| ToolError::ExecutionError(format!("Failed to load platforms: {}", e)))?
        };

        if !config.tags.is_empty() {
            platforms.retain(|p| {
                let p_tags = p.parse_tags();
                config.tags.iter().any(|t| p_tags.iter().any(|pt| pt.eq_ignore_ascii_case(t)))
            });
        }

        if !config.exclude_tags.is_empty() {
            platforms.retain(|p| {
                let p_tags = p.parse_tags();
                !config.exclude_tags.iter().any(|t| p_tags.iter().any(|pt| pt.eq_ignore_ascii_case(t)))
            });
        }

        if !config.id_type.is_empty() && config.id_type != "username" {
            platforms.retain(|p| {
                p.id_type == config.id_type || p.id_type.is_empty()
            });
        }

        platforms.sort_by(|a, b| {
            let rank_a = a.alexa_rank.unwrap_or(i64::MAX);
            let rank_b = b.alexa_rank.unwrap_or(i64::MAX);
            rank_a.cmp(&rank_b).then_with(|| b.priority.cmp(&a.priority))
        });

        if config.top_sites > 0 && platforms.len() > config.top_sites {
            platforms.truncate(config.top_sites);
        }

        Ok(platforms)
    }

    pub async fn check_with_platforms<F>(
        config: &UsernameOsintConfig,
        platforms: Vec<OsintPlatform>,
        progress_callback: F,
    ) -> Result<UsernameOsintResult>
    where
        F: Fn(OsintProgress) + Send + Sync + 'static,
    {
        let username = config.username.trim().to_string();
        if username.is_empty() && config.usernames.is_empty() {
            return Err(ToolError::ExecutionError("Username is empty".to_string()));
        }

        if platforms.is_empty() {
            return Err(ToolError::ExecutionError(
                "No active platforms found. Please add platforms via the platform registry.".to_string()
            ));
        }

        let primary_username = if !username.is_empty() { username.clone() } else {
            config.usernames.first().cloned().unwrap_or_default()
        };

        let unsupported_chars: Vec<char> = BAD_CHARS.iter().filter(|c| primary_username.contains(**c)).copied().collect();
        if !unsupported_chars.is_empty() {
            return Err(ToolError::ExecutionError(
                format!("Username contains unsupported URL characters: {:?}", unsupported_chars)
            ));
        }

        let mut all_usernames = vec![primary_username.clone()];
        if !config.usernames.is_empty() {
            for u in &config.usernames {
                if !all_usernames.contains(u) {
                    all_usernames.push(u.clone());
                }
            }
        }

        let permutations = if config.generate_permutations && all_usernames.len() >= 2 {
            let perms = generate_username_permutations(&all_usernames);
            let mut unique = all_usernames.clone();
            for p in &perms {
                if !unique.contains(p) {
                    unique.push(p.clone());
                }
            }
            unique
        } else {
            all_usernames.clone()
        };

        let mut batch_results = Vec::new();
        let mut combined_found = Vec::new();
        let mut combined_not_found = Vec::new();
        let mut combined_errors = Vec::new();
        let mut all_extracted_ids = Vec::new();

        let cb = Arc::new(progress_callback) as Arc<dyn Fn(OsintProgress) + Send + Sync>;

        for (idx, uname) in permutations.iter().enumerate() {
            let is_primary = idx == 0;
            let (found, not_found, errors) = Self::check_single_username(
                uname, &platforms, config, cb.clone(),
            ).await?;

            if is_primary {
                combined_found = found.clone();
                combined_not_found = not_found.clone();
                combined_errors = errors.clone();
            }

            for r in &found {
                if let Some(ref info) = r.extracted_info {
                    if let Some(ref id_val) = info.id_value {
                        all_extracted_ids.push(ExtractedId {
                            id_value: id_val.clone(),
                            id_type: "username".to_string(),
                            source_platform: r.platform.clone(),
                            source_url: r.url.clone(),
                        });
                    }
                }
            }

            let found_count = found.len();
            let total_checked = found.len() + not_found.len() + errors.len();
            let score = Self::calculate_footprint_score(found_count, total_checked);
            let risk = Self::get_risk_level(score);

            batch_results.push(BatchUsernameResult {
                username: uname.clone(),
                found_count,
                total_checked,
                digital_footprint_score: score,
                risk_level: risk,
                found_on: found,
            });
        }

        let mut recursive_results = Vec::new();
        if config.recursive_search {
            recursive_results = Self::recursive_search(
                &platforms, config, cb.clone(), &combined_found, &mut all_extracted_ids,
            ).await?;
        }

        let total_found = combined_found.len();
        let total_errors = combined_errors.len();
        let total_checked = combined_found.len() + combined_not_found.len() + combined_errors.len();
        let category_summary = Self::build_category_summary(&combined_found, &combined_not_found, &combined_errors);
        let digital_footprint_score = Self::calculate_footprint_score(total_found, total_checked);
        let risk_level = Self::get_risk_level(digital_footprint_score);

        let summary = if permutations.len() > 1 {
            format!(
                "Username '{}' found on {} out of {} platforms (footprint score: {:.0}/100, risk: {}). Checked {} username variants.",
                primary_username, total_found, total_checked, digital_footprint_score, risk_level, permutations.len()
            )
        } else {
            format!(
                "Username '{}' found on {} out of {} platforms (footprint score: {:.0}/100, risk: {})",
                primary_username, total_found, total_checked, digital_footprint_score, risk_level
            )
        };

        let perm_list = if permutations.len() > 1 {
            permutations
        } else {
            Vec::new()
        };

        let error_analysis = if total_errors > 0 {
            Some(Self::analyze_errors(&combined_errors, total_checked))
        } else {
            None
        };

        Ok(UsernameOsintResult {
            username: primary_username,
            found_on: combined_found,
            not_found_on: combined_not_found,
            errors: combined_errors,
            total_found,
            total_checked,
            total_errors,
            digital_footprint_score,
            risk_level,
            category_summary,
            summary,
            permutations: perm_list,
            batch_results,
            error_analysis,
            recursive_results,
            extracted_ids: all_extracted_ids,
        })
    }

    async fn recursive_search(
        platforms: &[OsintPlatform],
        config: &UsernameOsintConfig,
        progress_callback: Arc<dyn Fn(OsintProgress) + Send + Sync>,
        primary_results: &[PlatformResult],
        all_extracted_ids: &mut Vec<ExtractedId>,
    ) -> Result<Vec<RecursiveSearchResult>> {
        let mut results = Vec::new();
        let mut already_checked: Vec<String> = Vec::new();
        let mut queue: Vec<(String, String, String, u32)> = Vec::new();

        let extracted = extract_ids_from_results(primary_results, platforms);
        for id in &extracted.extracted_ids {
            if !all_extracted_ids.iter().any(|e| e.id_value == id.id_value && e.id_type == id.id_type) {
                all_extracted_ids.push(id.clone());
            }
            let key = format!("{}:{}", id.id_type, id.id_value.to_lowercase());
            if !already_checked.contains(&key) {
                queue.push((id.id_value.clone(), id.id_type.clone(), id.source_platform.clone(), 1));
                already_checked.push(key);
            }
        }

        let mut depth = 0;
        while !queue.is_empty() && depth < config.max_recursive_depth {
            depth += 1;
            let current_batch: Vec<(String, String, String, u32)> = queue.drain(..).collect();

            for (id_value, id_type, source_platform, current_depth) in current_batch {
                let filtered_platforms: Vec<OsintPlatform> = platforms
                    .iter()
                    .filter(|p| p.id_type == id_type || (id_type == "username" && (p.id_type.is_empty() || p.id_type == "username")))
                    .cloned()
                    .collect();

                if filtered_platforms.is_empty() {
                    continue;
                }

                let (found, _, _) = Self::check_single_username(
                    &id_value, &filtered_platforms, config, progress_callback.clone(),
                ).await?;

                let found_ids = extract_ids_from_results(&found, platforms);
                for id in &found_ids.extracted_ids {
                    if !all_extracted_ids.iter().any(|e| e.id_value == id.id_value && e.id_type == id.id_type) {
                        all_extracted_ids.push(id.clone());
                    }

                    if current_depth < config.max_recursive_depth {
                        let key = format!("{}:{}", id.id_type, id.id_value.to_lowercase());
                        if !already_checked.contains(&key) {
                            queue.push((id.id_value.clone(), id.id_type.clone(), id.source_platform.clone(), current_depth + 1));
                            already_checked.push(key);
                        }
                    }
                }

                results.push(RecursiveSearchResult {
                    id_value: id_value.clone(),
                    id_type: id_type.clone(),
                    source_platform: source_platform.clone(),
                    found_count: found.len(),
                    total_checked: filtered_platforms.len(),
                    found_on: found,
                    depth: current_depth,
                });
            }
        }

        Ok(results)
    }

    async fn check_single_username(
        username: &str,
        platforms: &[OsintPlatform],
        config: &UsernameOsintConfig,
        progress_callback: Arc<dyn Fn(OsintProgress) + Send + Sync>,
    ) -> Result<(Vec<PlatformResult>, Vec<PlatformResult>, Vec<PlatformResult>)> {
        let _profile = RequestProfile::rotating();
        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout))
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(true);

        if let Some(ref proxy_url) = config.proxy_url {
            if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
                client_builder = client_builder.proxy(proxy);
            }
        }

        let client = client_builder
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let semaphore = Arc::new(Semaphore::new(config.concurrent_limit));
        let checked = Arc::new(AtomicUsize::new(0));
        let found_count = Arc::new(AtomicUsize::new(0));
        let error_count = Arc::new(AtomicUsize::new(0));
        let total = platforms.len();
        let mut join_set = tokio::task::JoinSet::new();

        for platform in platforms {
            let url = platform.build_url(username);
            let client = client.clone();
            let platform = platform.clone();
            let semaphore = semaphore.clone();
            let checked = checked.clone();
            let found_count = found_count.clone();
            let error_count = error_count.clone();
            let retries = config.retries;
            let username_owned = username.to_string();
            let cb = progress_callback.clone();

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();

                let mut result = Self::check_platform_with_retry(
                    &client, &platform, &url, &username_owned, retries,
                ).await;

                result.response_time_ms = Some(start.elapsed().as_millis() as u64);

                let c = checked.fetch_add(1, Ordering::Relaxed) + 1;
                if result.found {
                    found_count.fetch_add(1, Ordering::Relaxed);
                }
                if result.error.is_some() {
                    error_count.fetch_add(1, Ordering::Relaxed);
                }

                cb(OsintProgress {
                    checked: c,
                    total,
                    found: found_count.load(Ordering::Relaxed),
                    errors: error_count.load(Ordering::Relaxed),
                    current_platform: platform.name.clone(),
                    username: username_owned.clone(),
                    latest_result: Some(result.clone()),
                });

                result
            });
        }

        let mut found_on = Vec::new();
        let mut not_found_on = Vec::new();
        let mut errors = Vec::new();

        while let Some(result) = join_set.join_next().await {
            if let Ok(platform_result) = result {
                if platform_result.error.is_some() {
                    errors.push(platform_result);
                } else if platform_result.found {
                    found_on.push(platform_result);
                } else {
                    not_found_on.push(platform_result);
                }
            }
        }

        found_on.sort_by(|a, b| a.platform.cmp(&b.platform));
        not_found_on.sort_by(|a, b| a.platform.cmp(&b.platform));
        errors.sort_by(|a, b| a.platform.cmp(&b.platform));

        Ok((found_on, not_found_on, errors))
    }

    async fn check_platform_with_retry(
        client: &reqwest::Client,
        platform: &OsintPlatform,
        url: &str,
        username: &str,
        max_retries: u32,
    ) -> PlatformResult {
        let mut last_result = Self::check_platform(client, platform, url, username).await;
        let mut retry_count = 0;

        while retry_count < max_retries {
            let should_retry = match &last_result {
                r if r.is_captcha => false,
                r if r.is_censored => false,
                r if r.error.is_some() => {
                    let err = r.error.as_ref().unwrap();
                    err.contains("timeout")
                        || err.contains("connection")
                        || err.contains("reset")
                        || err.contains("refused")
                        || err.contains("broken pipe")
                        || err.contains("temporary")
                }
                _ => false,
            };

            if !should_retry { break; }

            retry_count += 1;
            let delay = std::time::Duration::from_millis(500 * retry_count as u64);
            tokio::time::sleep(delay).await;

            last_result = Self::check_platform(client, platform, url, username).await;
        }

        last_result.retry_count = retry_count;
        last_result
    }

    async fn check_platform(
        client: &reqwest::Client,
        platform: &OsintPlatform,
        url: &str,
        username: &str,
    ) -> PlatformResult {
        let actual_url = if platform.url_probe.is_some() {
            platform.build_probe_url(username)
        } else {
            url.to_string()
        };

        let effective_method = platform.effective_request_method();
        let use_head = platform.request_head_only && platform.check_type == "status_code";

        let profile = RequestProfile::rotating();
        let site_headers = platform.parse_headers();
        let merged_headers = profile.merge_site_headers(&site_headers);

        let request = match effective_method.to_uppercase().as_str() {
            "POST" => client.post(&actual_url),
            "HEAD" if use_head => client.head(&actual_url),
            _ => client.get(&actual_url),
        };

        let mut request = request;
        for (key, value) in &merged_headers {
            if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(header_value) = reqwest::header::HeaderValue::from_str(value) {
                    request = request.header(header_name, header_value);
                }
            }
        }

        if let Some(ref payload_str) = platform.payload {
            if effective_method.to_uppercase() == "POST" {
                let body = payload_str.replace("{username}", username);
                request = request.body(body);
            }
        }

        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let location_header = resp.headers().get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let content_length = resp.headers().get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<usize>().ok());

                let need_body = !use_head
                    || matches!(platform.check_type.as_str(), "message" | "regex" | "presence_strs")
                    || status == 403
                    || status == 503
                    || status == 200
                    || status == 301
                    || status == 302
                    || content_length.map_or(false, |cl| cl < MIN_RESPONSE_SIZE);

                let body_text = if need_body {
                    resp.text().await.ok()
                } else {
                    let _ = resp.bytes().await;
                    None
                };

                let body_size = body_text.as_ref().map(|b| b.len());

                let page_title = body_text.as_ref()
                    .and_then(|b| Self::extract_title(b));

                let site_errors = platform.parse_errors();
                let (is_captcha, is_censored, detected_error) = if let Some(ref body) = body_text {
                    let common_err = detect_common_errors(body);
                    let site_err = detect_error_page(body, status, &site_errors, platform.ignore403);

                    let is_captcha = common_err.as_ref().map_or(false, |e| e.error_type == "Captcha" || e.error_type == "Bot protection")
                        || site_err.as_ref().map_or(false, |e| e.error_type == "Captcha" || e.error_type == "Bot protection");
                    let is_censored = common_err.as_ref().map_or(false, |e| e.error_type == "Censorship")
                        || site_err.as_ref().map_or(false, |e| e.error_type == "Censorship");

                    (is_captcha, is_censored, common_err.or(site_err))
                } else {
                    (false, false, None)
                };

                let is_suspiciously_small = body_size.map_or(false, |s| s < MIN_RESPONSE_SIZE);

                let should_ignore_403 = platform.ignore403 && status == 403;

                let error_type = if is_captcha {
                    Some("captcha".to_string())
                } else if is_censored {
                    Some("censored".to_string())
                } else if should_ignore_403 {
                    None
                } else if is_suspiciously_small && status != 404 {
                    Some("empty_response".to_string())
                } else if let Some(ref err) = detected_error {
                    Some(err.error_type.clone())
                } else {
                    None
                };

                let found = if is_captcha || is_censored {
                    false
                } else if should_ignore_403 {
                    Self::detect_account_by_content(platform, body_text.as_deref())
                        .unwrap_or(true)
                } else if is_suspiciously_small && status != 404 {
                    false
                } else {
                    Self::detect_account_static(platform, status, location_header.as_deref(), body_text.as_deref())
                };

                let detection_method = Some(platform.check_type.clone());
                let protection_type = if is_captcha {
                    Some("captcha".to_string())
                } else if is_censored {
                    Some("censorship".to_string())
                } else if platform.ignore403 && status == 403 {
                    Some("ignore403".to_string())
                } else {
                    platform.protection.as_ref().and_then(|p| {
                        serde_json::from_str::<Vec<String>>(p).ok()
                            .and_then(|v| v.first().cloned())
                    })
                };

                let suggested_action = if is_captcha {
                    detected_error.as_ref().and_then(|e| e.solution.clone())
                        .or_else(|| Some("Try reducing request rate or use TLS fingerprinting".to_string()))
                } else if is_censored {
                    detected_error.as_ref().and_then(|e| e.solution.clone())
                        .or_else(|| Some("Try using a proxy from a different region".to_string()))
                } else if detected_error.is_some() {
                    detected_error.as_ref().and_then(|e| e.solution.clone())
                } else {
                    None
                };

                let extracted_info = if found {
                    body_text.as_ref().map(|b| {
                        let mut info = Self::extract_user_info(b, platform);
                        let id_extraction = extract_ids_from_html(b, &platform.name, url);
                        if info.id_value.is_none() {
                            if let Some(first_id) = id_extraction.extracted_ids.first() {
                                info.id_value = Some(first_id.id_value.clone());
                            }
                        }
                        info
                    })
                } else {
                    None
                };

                PlatformResult {
                    platform: platform.name.clone(),
                    url: url.to_string(),
                    found,
                    status_code: Some(status),
                    error: None,
                    error_type,
                    category: platform.category.clone(),
                    response_time_ms: None,
                    page_title,
                    is_captcha,
                    is_censored,
                    retry_count: 0,
                    detection_method,
                    protection_type,
                    suggested_action,
                    extracted_info,
                }
            }
            Err(e) => {
                let error_str = e.to_string();
                let error_type = if error_str.contains("timeout") {
                    Some("timeout".to_string())
                } else if error_str.contains("connect") || error_str.contains("dns") {
                    Some("connection".to_string())
                } else if error_str.contains("tls") || error_str.contains("certificate") {
                    Some("ssl".to_string())
                } else {
                    Some("network".to_string())
                };

                PlatformResult {
                    platform: platform.name.clone(),
                    url: url.to_string(),
                    found: false,
                    status_code: None,
                    error: Some(error_str),
                    error_type,
                    category: platform.category.clone(),
                    response_time_ms: None,
                    page_title: None,
                    is_captcha: false,
                    is_censored: false,
                    retry_count: 0,
                    detection_method: Some(platform.check_type.clone()),
                    protection_type: None,
                    suggested_action: Some("Retry scan later".to_string()),
                    extracted_info: None,
                }
            }
        }
    }

    fn extract_title(html: &str) -> Option<String> {
        let re = Regex::new(r"(?i)<title[^>]*>(.*?)</title>").ok()?;
        let caps = re.captures(html)?;
        let title = caps.get(1)?.as_str().trim();
        if title.is_empty() {
            return None;
        }
        let decoded = title
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'");
        Some(decoded)
    }

    fn extract_user_info(html: &str, platform: &OsintPlatform) -> ExtractedUserInfo {
        let full_name = Self::extract_meta_content(html, "og:title")
            .or_else(|| Self::extract_meta_content(html, "twitter:title"))
            .or_else(|| Self::extract_title(html).map(|t| {
                t.split('|').next().map(|s| s.trim().to_string()).unwrap_or(t)
            }));

        let bio = Self::extract_meta_content(html, "og:description")
            .or_else(|| Self::extract_meta_content(html, "twitter:description"))
            .or_else(|| Self::extract_meta_content(html, "description"));

        let location = Self::extract_location(html);

        let profile_image_url = Self::extract_meta_content(html, "og:image")
            .or_else(|| Self::extract_meta_content(html, "twitter:image"));

        let external_links = Self::extract_external_links(html, platform.url_main.as_deref());

        let id_value = if platform.similar_search {
            Self::extract_id_from_page(html)
        } else {
            None
        };

        ExtractedUserInfo {
            full_name,
            location,
            bio,
            profile_image_url,
            external_links,
            id_value,
        }
    }

    fn extract_meta_content(html: &str, property: &str) -> Option<String> {
        let patterns = if property == "description" {
            vec![format!(r#"(?i)<meta\s+name="description"\s+content="([^"]*)""#),
                 format!(r#"(?i)<meta\s+content="([^"]*)"\s+name="description""#)]
        } else {
            vec![format!(r#"(?i)<meta\s+(?:property|name)="{}"\s+content="([^"]*)""#, regex::escape(property)),
                 format!(r#"(?i)<meta\s+content="([^"]*)"\s+(?:property|name)="{}""#, regex::escape(property))]
        };

        for pattern in patterns {
            if let Ok(re) = Regex::new(&pattern) {
                if let Some(caps) = re.captures(html) {
                    if let Some(m) = caps.get(1) {
                        let val = m.as_str().trim().to_string();
                        if !val.is_empty() {
                            return Some(val);
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_location(html: &str) -> Option<String> {
        let patterns = [
            r#"(?i)<[^>]*(?:location|address|city|country)[^>]*>([^<]{2,100})<"#,
            r#"(?i)"(?:location|address|city)"\s*:\s*"([^"]{2,100})""#,
        ];
        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(html) {
                    if let Some(m) = caps.get(1) {
                        let val = m.as_str().trim().to_string();
                        if !val.is_empty() && val.len() < 100 {
                            return Some(val);
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_external_links(html: &str, base_url: Option<&str>) -> Vec<String> {
        let re = match Regex::new(r#"(?i)<a\s+[^>]*href="(https?://[^"]*)""#) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let base_domain = base_url
            .and_then(|u| {
                let stripped = u.strip_prefix("https://").unwrap_or(u);
                let stripped = stripped.strip_prefix("http://").unwrap_or(stripped);
                stripped.split('/').next().map(|s| s.to_string())
            });

        let mut links = Vec::new();
        for caps in re.captures_iter(html) {
            if let Some(m) = caps.get(1) {
                let url = m.as_str().to_string();
                if let Some(ref domain) = base_domain {
                    if url.contains(domain) {
                        continue;
                    }
                }
                if !links.contains(&url) && links.len() < 10 {
                    links.push(url);
                }
            }
        }
        links
    }

    fn extract_id_from_page(html: &str) -> Option<String> {
        let patterns = [
            r#"(?i)"(?:user_?id|uid|account_?id|profile_?id)"\s*:\s*"?(\d+)"?"#,
            r#"(?i)/users/(\d+)"#,
            r#"(?i)/profile/(\d+)"#,
            r#"(?i)member[\./](\d+)"#,
        ];
        for pattern in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(html) {
                    if let Some(m) = caps.get(1) {
                        let val = m.as_str().to_string();
                        if !val.is_empty() {
                            return Some(val);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn detect_account_static(
        platform: &OsintPlatform,
        status_code: u16,
        location_header: Option<&str>,
        body_text: Option<&str>,
    ) -> bool {
        let error_codes = platform.parse_error_codes();
        let is_error_status = error_codes.contains(&status_code);

        match platform.check_type.as_str() {
            "status_code" => {
                if is_error_status {
                    return false;
                }
                !Self::check_error_messages(platform, body_text)
            }
            "message" => {
                if is_error_status {
                    return false;
                }
                Self::detect_account_by_content(platform, body_text).unwrap_or(true)
            }
            "presence_strs" => {
                if is_error_status && !platform.ignore403 {
                    return false;
                }
                Self::detect_account_by_content(platform, body_text).unwrap_or(false)
            }
            "redirect" => {
                if let Some(error_url) = &platform.error_url {
                    if let Some(loc_str) = location_header {
                        return !loc_str.contains(error_url);
                    }
                }
                if is_error_status {
                    return false;
                }
                true
            }
            "regex" => {
                if is_error_status {
                    return false;
                }
                if let Some(pattern) = &platform.regex_check {
                    if let Ok(re) = Regex::new(pattern) {
                        if let Some(text) = body_text {
                            return re.is_match(text);
                        }
                    }
                }
                status_code == 200
            }
            _ => {
                if status_code == 404 {
                    false
                } else if status_code == 200 || status_code == 302 || status_code == 301 {
                    true
                } else if status_code == 403 {
                    if let Some(text) = body_text {
                        let detected = detect_common_errors(text);
                        detected.is_none()
                    } else {
                        true
                    }
                } else {
                    false
                }
            }
        }
    }

    fn detect_account_by_content(
        platform: &OsintPlatform,
        body_text: Option<&str>,
    ) -> Option<bool> {
        let text = body_text?;

        let presence_strs = platform.parse_presence_strs();
        let absence_strs = platform.parse_absence_strs();

        if !presence_strs.is_empty() || !absence_strs.is_empty() {
            let has_presence = if presence_strs.is_empty() {
                true
            } else {
                presence_strs.iter().any(|s| text.contains(s))
            };

            let has_absence = if absence_strs.is_empty() {
                false
            } else {
                absence_strs.iter().any(|s| text.contains(s))
            };

            return Some(has_presence && !has_absence);
        }

        let error_messages = platform.parse_error_messages();
        if !error_messages.is_empty() {
            let has_error = error_messages.iter().any(|msg| text.contains(msg));
            return Some(!has_error);
        }

        None
    }

    fn check_error_messages(
        platform: &OsintPlatform,
        body_text: Option<&str>,
    ) -> bool {
        if let Some(text) = body_text {
            let error_messages = platform.parse_error_messages();
            error_messages.iter().any(|msg| text.contains(msg))
        } else {
            false
        }
    }

    fn build_category_summary(
        found_on: &[PlatformResult],
        not_found_on: &[PlatformResult],
        errors: &[PlatformResult],
    ) -> Vec<CategorySummary> {
        let mut cat_map: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();

        for p in found_on {
            let entry = cat_map.entry(p.category.clone()).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += 1;
        }
        for p in not_found_on {
            let entry = cat_map.entry(p.category.clone()).or_insert((0, 0));
            entry.1 += 1;
        }
        for p in errors {
            let entry = cat_map.entry(p.category.clone()).or_insert((0, 0));
            entry.1 += 1;
        }

        let mut result: Vec<CategorySummary> = cat_map
            .into_iter()
            .map(|(category, (found, total))| CategorySummary { category, total, found })
            .collect();

        let cat_order: Vec<&str> = PLATFORM_CATEGORIES.iter().map(|(k, _)| *k).collect();
        result.sort_by(|a, b| {
            let ai = cat_order.iter().position(|&c| c == a.category).unwrap_or(999);
            let bi = cat_order.iter().position(|&c| c == b.category).unwrap_or(999);
            ai.cmp(&bi)
        });

        result
    }

    fn calculate_footprint_score(found: usize, total: usize) -> f64 {
        if total == 0 {
            return 0.0;
        }
        let ratio = found as f64 / total as f64;
        let base_score = ratio * 100.0;
        let absolute_bonus = if found >= 20 { 10.0 } else if found >= 10 { 5.0 } else if found >= 5 { 2.0 } else { 0.0 };
        (base_score + absolute_bonus).min(100.0)
    }

    fn get_risk_level(score: f64) -> String {
        if score >= 80.0 {
            "critical".to_string()
        } else if score >= 60.0 {
            "high".to_string()
        } else if score >= 40.0 {
            "medium".to_string()
        } else if score >= 20.0 {
            "low".to_string()
        } else {
            "minimal".to_string()
        }
    }

    fn analyze_errors(errors: &[PlatformResult], total_checked: usize) -> ErrorAnalysis {
        let mut captcha_platforms = Vec::new();
        let mut censored_platforms = Vec::new();
        let mut timeout_platforms = Vec::new();
        let mut connection_platforms = Vec::new();
        let mut ssl_platforms = Vec::new();
        let mut network_platforms = Vec::new();
        let mut other_platforms = Vec::new();

        for e in errors {
            if e.is_captcha {
                captcha_platforms.push(e.platform.clone());
            } else if e.is_censored {
                censored_platforms.push(e.platform.clone());
            } else if let Some(ref et) = e.error_type {
                match et.as_str() {
                    "timeout" => timeout_platforms.push(e.platform.clone()),
                    "connection" => connection_platforms.push(e.platform.clone()),
                    "ssl" => ssl_platforms.push(e.platform.clone()),
                    "network" => network_platforms.push(e.platform.clone()),
                    _ => other_platforms.push(e.platform.clone()),
                }
            } else {
                other_platforms.push(e.platform.clone());
            }
        }

        let captcha_count = captcha_platforms.len();
        let censored_count = censored_platforms.len();
        let network_error_count = timeout_platforms.len() + connection_platforms.len() + ssl_platforms.len() + network_platforms.len();
        let total_error_count = errors.len();
        let error_rate = if total_checked > 0 {
            total_error_count as f64 / total_checked as f64 * 100.0
        } else {
            0.0
        };

        let mut categories = Vec::new();

        if !captcha_platforms.is_empty() {
            categories.push(ErrorCategory {
                category: "captcha".to_string(),
                count: captcha_platforms.len(),
                platforms: captcha_platforms,
                severity: "high".to_string(),
                description: "Anti-bot protection detected (CAPTCHA/WAF)".to_string(),
                suggested_fix: "Consider using TLS fingerprinting or reducing request rate".to_string(),
            });
        }

        if !censored_platforms.is_empty() {
            categories.push(ErrorCategory {
                category: "censored".to_string(),
                count: censored_platforms.len(),
                platforms: censored_platforms,
                severity: "medium".to_string(),
                description: "Geographic or content censorship detected".to_string(),
                suggested_fix: "Use proxy/VPN from different region".to_string(),
            });
        }

        if !timeout_platforms.is_empty() {
            categories.push(ErrorCategory {
                category: "timeout".to_string(),
                count: timeout_platforms.len(),
                platforms: timeout_platforms,
                severity: "low".to_string(),
                description: "Request timed out".to_string(),
                suggested_fix: "Increase timeout or retry later".to_string(),
            });
        }

        if !connection_platforms.is_empty() {
            categories.push(ErrorCategory {
                category: "connection".to_string(),
                count: connection_platforms.len(),
                platforms: connection_platforms,
                severity: "medium".to_string(),
                description: "Connection failed (DNS or network)".to_string(),
                suggested_fix: "Check DNS resolution and network connectivity".to_string(),
            });
        }

        let ssl_platforms_count = ssl_platforms.len();
        if !ssl_platforms.is_empty() {
            categories.push(ErrorCategory {
                category: "ssl".to_string(),
                count: ssl_platforms_count,
                platforms: ssl_platforms,
                severity: "low".to_string(),
                description: "SSL/TLS certificate error".to_string(),
                suggested_fix: "Site may have expired or misconfigured certificate".to_string(),
            });
        }

        if !network_platforms.is_empty() {
            categories.push(ErrorCategory {
                category: "network".to_string(),
                count: network_platforms.len(),
                platforms: network_platforms,
                severity: "low".to_string(),
                description: "General network error".to_string(),
                suggested_fix: "Retry scan later".to_string(),
            });
        }

        let mut recommendations = Vec::new();
        if error_rate > 50.0 {
            recommendations.push("High error rate detected. Consider reducing concurrent requests or adding delays between checks.".to_string());
        }
        if captcha_count > 5 {
            recommendations.push("Multiple CAPTCHA protections detected. Consider implementing TLS fingerprinting (like Maigret's curl_cffi approach).".to_string());
        }
        if censored_count > 3 {
            recommendations.push("Multiple censored sites detected. Consider using proxies from different regions.".to_string());
        }
        if ssl_platforms_count > 0 {
            recommendations.push("Some sites have SSL issues. These may be temporarily unavailable.".to_string());
        }
        if recommendations.is_empty() && total_error_count > 0 {
            recommendations.push("Some errors occurred but overall scan quality is acceptable.".to_string());
        }

        ErrorAnalysis {
            error_categories: categories,
            captcha_count,
            censored_count,
            network_error_count,
            total_error_count,
            error_rate,
            recommendations,
        }
    }
}
