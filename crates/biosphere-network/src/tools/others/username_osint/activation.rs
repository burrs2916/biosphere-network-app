use crate::core::{Result, ToolError};
use crate::infrastructure::database::models::OsintPlatform;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRequest {
    pub url: String,
    pub method: String,
    pub headers: Option<HashMap<String, String>>,
    pub payload: Option<HashMap<String, String>>,
    pub get_params: Option<HashMap<String, String>>,
    pub marks: Vec<String>,
    pub src: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationResult {
    pub success: bool,
    pub updated_headers: HashMap<String, String>,
    pub updated_cookies: HashMap<String, String>,
    pub activation_method: String,
    pub error: Option<String>,
}

impl ActivationResult {
    pub fn success(method: &str) -> Self {
        Self {
            success: true,
            updated_headers: HashMap::new(),
            updated_cookies: HashMap::new(),
            activation_method: method.to_string(),
            error: None,
        }
    }

    pub fn failure(method: &str, error: &str) -> Self {
        Self {
            success: false,
            updated_headers: HashMap::new(),
            updated_cookies: HashMap::new(),
            activation_method: method.to_string(),
            error: Some(error.to_string()),
        }
    }
}

pub struct ActivationEngine;

impl ActivationEngine {
    pub fn parse_activation(platform: &OsintPlatform) -> Option<ActivationRequest> {
        let activation = platform.parse_activation()?;
        let url = activation.get("url")?.as_str()?.to_string();
        let method = activation.get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("get")
            .to_string();

        let marks = activation.get("marks")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let src = activation.get("src")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let headers = activation.get("headers")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let payload = activation.get("payload")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let get_params = activation.get("GETParams")
            .or_else(|| activation.get("get_params"))
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        Some(ActivationRequest {
            url,
            method,
            headers,
            payload,
            get_params,
            marks,
            src,
        })
    }

    pub fn is_activation_needed(platform: &OsintPlatform, html: &str) -> bool {
        if let Some(req) = Self::parse_activation(platform) {
            if req.marks.is_empty() {
                return false;
            }
            return req.marks.iter().any(|m| html.contains(m));
        }
        false
    }

    pub async fn activate(
        platform: &OsintPlatform,
        html: &str,
    ) -> Result<ActivationResult> {
        let req = match Self::parse_activation(platform) {
            Some(r) => r,
            None => return Ok(ActivationResult::success("none")),
        };

        if !Self::is_activation_needed(platform, html) {
            return Ok(ActivationResult::success("none"));
        }

        let method = req.method.to_lowercase();
        match method.as_str() {
            "twitter" => Self::activate_twitter(platform, &req).await,
            "vimeo" => Self::activate_vimeo(platform, &req).await,
            "weibo" => Self::activate_weibo(platform, &req).await,
            "onlyfans" => Self::activate_onlyfans(platform, &req).await,
            "get" | "post" => Self::activate_generic(platform, &req).await,
            _ => {
                Self::activate_generic(platform, &req).await
            }
        }
    }

    async fn activate_twitter(
        platform: &OsintPlatform,
        req: &ActivationRequest,
    ) -> Result<ActivationResult> {
        let mut result = ActivationResult::success("twitter");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut headers = platform.parse_headers();
        headers.remove("x-guest-token");

        let response = client.post(&req.url)
            .headers(Self::build_header_map(&headers))
            .send()
            .await
            .map_err(|e| ToolError::ExecutionError(format!("Twitter activation request failed: {}", e)))?;

        if response.status().is_success() {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(src) = &req.src {
                    if let Some(token) = json.get(src).and_then(|v| v.as_str()) {
                        result.updated_headers.insert("x-guest-token".to_string(), token.to_string());
                    }
                }
            }
        } else {
            return Ok(ActivationResult::failure("twitter", &format!("HTTP {}", response.status())));
        }

        Ok(result)
    }

    async fn activate_vimeo(
        platform: &OsintPlatform,
        req: &ActivationRequest,
    ) -> Result<ActivationResult> {
        let mut result = ActivationResult::success("vimeo");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut headers = platform.parse_headers();
        headers.remove("Authorization");

        let response = client.get(&req.url)
            .headers(Self::build_header_map(&headers))
            .send()
            .await
            .map_err(|e| ToolError::ExecutionError(format!("Vimeo activation request failed: {}", e)))?;

        if response.status().is_success() {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(jwt) = json.get("jwt").and_then(|v| v.as_str()) {
                    result.updated_headers.insert("Authorization".to_string(), format!("jwt {}", jwt));
                }
            }
        }

        Ok(result)
    }

    async fn activate_weibo(
        _platform: &OsintPlatform,
        _req: &ActivationRequest,
    ) -> Result<ActivationResult> {
        let result = ActivationResult::success("weibo");
        Ok(result)
    }

    async fn activate_onlyfans(
        _platform: &OsintPlatform,
        _req: &ActivationRequest,
    ) -> Result<ActivationResult> {
        let result = ActivationResult::success("onlyfans");
        Ok(result)
    }

    async fn activate_generic(
        platform: &OsintPlatform,
        req: &ActivationRequest,
    ) -> Result<ActivationResult> {
        let mut result = ActivationResult::success(&req.method);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut headers = platform.parse_headers();
        if let Some(ref req_headers) = req.headers {
            headers.extend(req_headers.clone());
        }

        let mut url = req.url.clone();
        if let Some(ref params) = req.get_params {
            let separator = if url.contains('?') { "&" } else { "?" };
            let query: Vec<String> = params.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            url.push_str(separator);
            url.push_str(&query.join("&"));
        }

        let response = match req.method.to_lowercase().as_str() {
            "post" => {
                let mut builder = client.post(&url).headers(Self::build_header_map(&headers));
                if let Some(ref payload) = req.payload {
                    builder = builder.json(payload);
                }
                builder.send().await
            }
            _ => {
                client.get(&url).headers(Self::build_header_map(&headers)).send().await
            }
        };

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if let Some(src) = &req.src {
                            if let Some(token) = json.get(src).and_then(|v| v.as_str()) {
                                result.updated_headers.insert(src.clone(), token.to_string());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                return Ok(ActivationResult::failure(&req.method, &e.to_string()));
            }
        }

        Ok(result)
    }

    fn build_header_map(headers: &HashMap<String, String>) -> reqwest::header::HeaderMap {
        let mut map = reqwest::header::HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                map.insert(name, value);
            }
        }
        map
    }
}
