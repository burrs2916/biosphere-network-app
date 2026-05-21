use crate::core::{Result, ToolError};
use crate::infrastructure::database::models::OsintPlatform;
use crate::infrastructure::database::Database;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCheckResult {
    pub platform_name: String,
    pub claimed_test: ClaimedTestResult,
    pub unclaimed_test: UnclaimedTestResult,
    pub overall_status: SiteCheckStatus,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedTestResult {
    pub username: String,
    pub found: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnclaimedTestResult {
    pub username: String,
    pub found: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SiteCheckStatus {
    Healthy,
    Degraded,
    Broken,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCheckReport {
    pub total_checked: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub broken: usize,
    pub unknown: usize,
    pub results: Vec<SiteCheckResult>,
}

pub struct SiteSelfChecker;

impl SiteSelfChecker {
    pub async fn check_platforms(
        db: &Database,
        platforms: Vec<OsintPlatform>,
        concurrent_limit: usize,
        timeout_secs: u64,
    ) -> Result<SiteCheckReport> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let semaphore = Arc::new(Semaphore::new(concurrent_limit));
        let mut join_set = tokio::task::JoinSet::new();

        for platform in platforms {
            let client = client.clone();
            let semaphore = semaphore.clone();
            let platform_clone = platform.clone();

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                Self::check_single_platform(&client, &platform_clone).await
            });
        }

        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(Ok(r)) = result {
                results.push(r);
            }
        }

        let healthy = results.iter().filter(|r| r.overall_status == SiteCheckStatus::Healthy).count();
        let degraded = results.iter().filter(|r| r.overall_status == SiteCheckStatus::Degraded).count();
        let broken = results.iter().filter(|r| r.overall_status == SiteCheckStatus::Broken).count();
        let unknown = results.iter().filter(|r| r.overall_status == SiteCheckStatus::Unknown).count();

        for result in &results {
            if result.overall_status == SiteCheckStatus::Broken {
                if let Ok(Some(mut platform)) = db.get_osint_platform_by_name(&result.platform_name) {
                    platform.is_active = false;
                    let _ = db.update_osint_platform(&platform);
                }
            }
        }

        Ok(SiteCheckReport {
            total_checked: results.len(),
            healthy,
            degraded,
            broken,
            unknown,
            results,
        })
    }

    async fn check_single_platform(
        client: &reqwest::Client,
        platform: &OsintPlatform,
    ) -> Result<SiteCheckResult> {
        let claimed_username = platform.username_claimed.as_deref().unwrap_or("");
        let unclaimed_username = platform.username_unclaimed.as_deref().unwrap_or("");

        let mut issues = Vec::new();

        let claimed_test = if !claimed_username.is_empty() {
            let start = std::time::Instant::now();
            let url = platform.build_url(claimed_username);
            let result = Self::make_test_request(client, platform, &url).await;
            ClaimedTestResult {
                username: claimed_username.to_string(),
                found: result.found,
                status_code: result.status_code,
                response_time_ms: Some(start.elapsed().as_millis() as u64),
            }
        } else {
            ClaimedTestResult {
                username: String::new(),
                found: false,
                status_code: None,
                response_time_ms: None,
            }
        };

        if !claimed_username.is_empty() && !claimed_test.found {
            issues.push(format!(
                "Claimed username '{}' was not detected as found (status: {:?})",
                claimed_username, claimed_test.status_code
            ));
        }

        let unclaimed_test = if !unclaimed_username.is_empty() {
            let start = std::time::Instant::now();
            let url = platform.build_url(unclaimed_username);
            let result = Self::make_test_request(client, platform, &url).await;
            UnclaimedTestResult {
                username: unclaimed_username.to_string(),
                found: result.found,
                status_code: result.status_code,
                response_time_ms: Some(start.elapsed().as_millis() as u64),
            }
        } else {
            UnclaimedTestResult {
                username: String::new(),
                found: false,
                status_code: None,
                response_time_ms: None,
            }
        };

        if !unclaimed_username.is_empty() && unclaimed_test.found {
            issues.push(format!(
                "Unclaimed username '{}' was incorrectly detected as found (status: {:?})",
                unclaimed_username, unclaimed_test.status_code
            ));
        }

        let overall_status = if claimed_username.is_empty() && unclaimed_username.is_empty() {
            SiteCheckStatus::Unknown
        } else if !claimed_username.is_empty() && !unclaimed_username.is_empty() {
            if claimed_test.found && !unclaimed_test.found {
                SiteCheckStatus::Healthy
            } else if claimed_test.found || !unclaimed_test.found {
                SiteCheckStatus::Degraded
            } else {
                SiteCheckStatus::Broken
            }
        } else if !claimed_username.is_empty() {
            if claimed_test.found {
                SiteCheckStatus::Healthy
            } else {
                SiteCheckStatus::Degraded
            }
        } else if !unclaimed_test.found {
            SiteCheckStatus::Healthy
        } else {
            SiteCheckStatus::Broken
        };

        Ok(SiteCheckResult {
            platform_name: platform.name.clone(),
            claimed_test,
            unclaimed_test,
            overall_status,
            issues,
        })
    }

    async fn make_test_request(
        client: &reqwest::Client,
        platform: &OsintPlatform,
        url: &str,
    ) -> TestRequestResult {
        let request = match platform.request_method.to_uppercase().as_str() {
            "POST" => client.post(url),
            "HEAD" => client.head(url),
            _ => client.get(url),
        };

        let headers = platform.parse_headers();
        let mut request = request;
        for (key, value) in &headers {
            if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(header_value) = reqwest::header::HeaderValue::from_str(value) {
                    request = request.header(header_name, header_value);
                }
            }
        }

        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let location_header = resp.headers().get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let need_body = matches!(platform.check_type.as_str(), "message" | "regex" | "presence_strs")
                    || status == 403
                    || status == 503;

                let body_text = if need_body {
                    resp.text().await.ok()
                } else {
                    let _ = resp.bytes().await;
                    None
                };

                let found = super::tool::UsernameOsintTool::detect_account_static(
                    platform, status, location_header.as_deref(), body_text.as_deref(),
                );

                TestRequestResult {
                    found,
                    status_code: Some(status),
                }
            }
            Err(_) => {
                TestRequestResult {
                    found: false,
                    status_code: None,
                }
            }
        }
    }
}

struct TestRequestResult {
    found: bool,
    status_code: Option<u16>,
}
