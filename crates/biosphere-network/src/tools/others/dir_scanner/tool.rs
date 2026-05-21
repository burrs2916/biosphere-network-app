use crate::core::{Result, ToolError};
use super::config::{DirScanConfig, DirScanResult, DirEntry, SslInfo, WafDetection, classify_sensitive_path, detect_waf};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct DirScannerTool;

impl DirScannerTool {
    pub async fn scan(config: &DirScanConfig) -> Result<DirScanResult> {
        let scan_start = std::time::Instant::now();

        let url = config.url.trim().to_string();
        let target_url = if url.starts_with("http://") || url.starts_with("https://") {
            url
        } else {
            format!("https://{}", url)
        };
        let target_url = target_url.trim_end_matches('/').to_string();

        let wordlist = config.get_effective_wordlist();
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

        let default_extensions: Vec<String> = vec![
            "".to_string(), "/".to_string(), ".html".to_string(),
            ".php".to_string(), ".json".to_string(), ".txt".to_string(),
        ];
        let extensions = if config.extensions.is_empty() {
            &default_extensions
        } else {
            &config.extensions
        };

        let mut all_found = Vec::new();
        let mut total_scanned: usize = 0;
        let mut waf_detection: Option<WafDetection> = None;
        let mut visited_urls: HashSet<String> = HashSet::new();
        visited_urls.insert(target_url.clone());

        let mut scan_queue: Vec<(String, usize)> = vec![(target_url.clone(), 0)];

        while let Some((base_url, depth)) = scan_queue.pop() {
            if config.recursive && depth >= config.max_depth {
                continue;
            }

            let (found, scanned, waf) = Self::scan_level(
                &client,
                &base_url,
                &wordlist,
                extensions,
                max_concurrent,
                depth,
                config,
                &mut visited_urls,
            ).await;

            total_scanned += scanned;

            if let Some(w) = waf {
                if waf_detection.is_none() {
                    waf_detection = Some(w);
                }
            }

            if config.recursive {
                for entry in &found {
                    if entry.is_directory && entry.status_code >= 200 && entry.status_code < 400 {
                        let dir_url = entry.full_url.trim_end_matches('/').to_string();
                        if !visited_urls.contains(&dir_url) && !config.should_exclude(&entry.path) {
                            visited_urls.insert(dir_url.clone());
                            scan_queue.push((dir_url, depth + 1));
                        }
                    }
                }
            }

            all_found.extend(found);
        }

        let mut sensitive_paths = Vec::new();
        for entry in &all_found {
            if let Some(sp) = classify_sensitive_path(&entry.path) {
                sensitive_paths.push(sp);
            }
        }
        sensitive_paths.sort_by(|a, b| {
            let a_sev = match a.severity.as_str() { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
            let b_sev = match b.severity.as_str() { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
            a_sev.cmp(&b_sev)
        });

        all_found.sort_by(|a, b| {
            let a_group = a.status_code / 100;
            let b_group = b.status_code / 100;
            b_group.cmp(&a_group).then(a.path.cmp(&b.path))
        });

        let total_found = all_found.len();
        let scan_duration_ms = scan_start.elapsed().as_millis() as u64;
        let summary = format!(
            "Found {} paths from {} scanned on {} in {}ms",
            total_found, total_scanned, target_url, scan_duration_ms
        );

        Ok(DirScanResult {
            url: target_url,
            found_paths: all_found,
            total_found,
            total_scanned,
            summary,
            ssl_info,
            waf_detected: waf_detection,
            sensitive_paths,
            scan_duration_ms,
        })
    }

    async fn scan_level(
        client: &reqwest::Client,
        base_url: &str,
        wordlist: &[String],
        extensions: &[String],
        max_concurrent: usize,
        depth: usize,
        config: &DirScanConfig,
        visited_urls: &mut HashSet<String>,
    ) -> (Vec<DirEntry>, usize, Option<WafDetection>) {
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut join_set = tokio::task::JoinSet::new();
        let total_scanned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waf_result: Arc<tokio::sync::Mutex<Option<WafDetection>>> = Arc::new(tokio::sync::Mutex::new(None));

        let base = base_url.trim_end_matches('/');

        for word in wordlist {
            for ext in extensions {
                let path = format!("{}{}", word, ext);
                if config.should_exclude(&path) {
                    continue;
                }
                let full_url = format!("{}/{}", base, path);
                let normalized = full_url.trim_end_matches('/').to_string();
                if visited_urls.contains(&normalized) {
                    continue;
                }

                let client = client.clone();
                let total_scanned = total_scanned.clone();
                let path_clone = path.clone();
                let semaphore = semaphore.clone();
                let waf_result = waf_result.clone();

                join_set.spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    total_scanned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let start = std::time::Instant::now();
                    match client.get(&full_url).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let response_time_ms = start.elapsed().as_millis() as u64;
                            let headers = resp.headers().clone();

                            let content_length = resp.content_length();
                            let content_type = headers
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            let redirect_url = headers
                                .get("location")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());

                            let is_directory = path_clone.ends_with('/')
                                || content_type.as_deref().map(|ct| ct.contains("text/html")).unwrap_or(false);

                            if status != 404 && status != 0 {
                                if status == 403 || status == 429 || status == 503 {
                                    let body = String::new();
                                    let waf = detect_waf(status, &headers, &body);
                                    if waf.detected {
                                        let mut guard = waf_result.lock().await;
                                        if guard.is_none() {
                                            *guard = Some(waf);
                                        }
                                    }
                                }
                                Some(DirEntry {
                                    path: path_clone,
                                    full_url,
                                    status_code: status,
                                    content_length,
                                    content_type,
                                    redirect_url,
                                    response_time_ms,
                                    depth,
                                    is_directory,
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

        let mut found_paths = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(entry)) = result {
                found_paths.push(entry);
            }
        }

        let scanned = total_scanned.load(std::sync::atomic::Ordering::Relaxed);
        let waf = waf_result.lock().await.take();
        (found_paths, scanned, waf)
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
