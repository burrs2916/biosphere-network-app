use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CookieJar {
    pub cookies: HashMap<String, Vec<Cookie>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_netscape_format(content: &str) -> Result<Self, String> {
        let mut jar = CookieJar::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 7 {
                let domain = parts[0].to_string();
                let _httponly = parts[1] == "TRUE";
                let path = parts[2].to_string();
                let secure = parts[3] == "TRUE";
                let _expires = parts[4];
                let name = parts[5].to_string();
                let value = parts[6].to_string();

                let cookie = Cookie {
                    name,
                    value,
                    domain: Some(domain.clone()),
                    path: Some(path),
                    secure,
                    http_only: _httponly,
                };

                jar.cookies.entry(domain).or_default().push(cookie);
            }
        }

        Ok(jar)
    }

    pub fn from_json_format(content: &str) -> Result<Self, String> {
        let cookies: Vec<serde_json::Value> = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse JSON cookies: {}", e))?;

        let mut jar = CookieJar::new();

        for cookie_val in cookies {
            let name = cookie_val.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = cookie_val.get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let domain = cookie_val.get("domain")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let path = cookie_val.get("path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let secure = cookie_val.get("secure")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let http_only = cookie_val.get("httpOnly")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !name.is_empty() {
                let cookie = Cookie { name, value, domain: domain.clone(), path, secure, http_only };
                let key = domain.unwrap_or_default();
                jar.cookies.entry(key).or_default().push(cookie);
            }
        }

        Ok(jar)
    }

    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read cookie file {}: {}", path, e))?;

        if content.trim().starts_with('[') {
            Self::from_json_format(&content)
        } else {
            Self::from_netscape_format(&content)
        }
    }

    pub fn get_cookies_for_domain(&self, domain: &str) -> Vec<&Cookie> {
        let mut result = Vec::new();

        for (cookie_domain, cookies) in &self.cookies {
            if domain.ends_with(cookie_domain.trim_start_matches('.')) ||
               domain == cookie_domain ||
               cookie_domain.trim_start_matches('.').starts_with(domain) {
                for cookie in cookies {
                    result.push(cookie);
                }
            }
        }

        result
    }

    pub fn to_cookie_header(&self, domain: &str) -> Option<String> {
        let cookies = self.get_cookies_for_domain(domain);
        if cookies.is_empty() {
            return None;
        }

        let header: Vec<String> = cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();

        Some(header.join("; "))
    }

    pub fn merge(&mut self, other: CookieJar) {
        for (domain, cookies) in other.cookies {
            let entry = self.cookies.entry(domain).or_default();
            for cookie in cookies {
                if let Some(existing) = entry.iter_mut().find(|c| c.name == cookie.name) {
                    *existing = cookie;
                } else {
                    entry.push(cookie);
                }
            }
        }
    }
}
