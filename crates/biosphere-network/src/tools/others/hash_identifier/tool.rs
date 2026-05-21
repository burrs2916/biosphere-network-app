use crate::core::{Result, ToolError};
use super::config::{HashIdentification, HashTypeMatch, IpGeoInfo};
use regex::Regex;

pub struct HashIdentifierTool;

impl Default for HashIdentifierTool {
    fn default() -> Self {
        Self::new()
    }
}

impl HashIdentifierTool {
    pub fn new() -> Self {
        Self
    }

    pub fn identify_hash(input: &str) -> Result<HashIdentification> {
        let trimmed = input.trim();

        if trimmed.is_empty() {
            return Err(ToolError::ExecutionError("Empty input".to_string()));
        }

        if !Self::is_valid_hex(trimmed) {
            return Err(ToolError::ExecutionError(
                "Input does not appear to be a valid hash (must contain only hex characters)".to_string(),
            ));
        }

        let mut matches = Vec::new();
        let len = trimmed.len();

        let rules = Self::get_hash_rules();

        for rule in &rules {
            if rule.lengths.contains(&len) {
                if let Some(ref pattern) = rule.pattern {
                    let re = Regex::new(pattern).map_err(|e| ToolError::ExecutionError(format!("Regex error: {}", e)))?;
                    if !re.is_match(trimmed) {
                        continue;
                    }
                }

                let confidence = if rule.lengths.len() == 1 && rule.lengths[0] == len {
                    0.9
                } else {
                    0.7
                };

                matches.push(HashTypeMatch {
                    hash_type: rule.name.clone(),
                    description: rule.description.clone(),
                    confidence: rule.confidence.unwrap_or(confidence),
                    length: len,
                });
            }
        }

        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        Ok(HashIdentification {
            hash_value: trimmed.to_string(),
            possible_types: matches,
        })
    }

    fn is_valid_hex(s: &str) -> bool {
        s.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn get_hash_rules() -> Vec<HashRule> {
        vec![
            HashRule {
                name: "MD5".to_string(),
                description: "MD5 (Message-Digest Algorithm 5) - 128-bit hash".to_string(),
                lengths: vec![32],
                pattern: None,
                confidence: Some(0.9),
            },
            HashRule {
                name: "MD4".to_string(),
                description: "MD4 (Message-Digest Algorithm 4) - 128-bit hash".to_string(),
                lengths: vec![32],
                pattern: None,
                confidence: Some(0.5),
            },
            HashRule {
                name: "NTLM".to_string(),
                description: "NTLM (Windows NT LAN Manager) hash".to_string(),
                lengths: vec![32],
                pattern: None,
                confidence: Some(0.4),
            },
            HashRule {
                name: "LM".to_string(),
                description: "LM (Lan Manager) hash - deprecated Windows hash".to_string(),
                lengths: vec![32],
                pattern: Some(String::from(r"^[A-F0-9]{32}$")),
                confidence: Some(0.3),
            },
            HashRule {
                name: "SHA-1".to_string(),
                description: "SHA-1 (Secure Hash Algorithm 1) - 160-bit hash".to_string(),
                lengths: vec![40],
                pattern: None,
                confidence: Some(0.9),
            },
            HashRule {
                name: "MySQL5".to_string(),
                description: "MySQL 5.x password hash (SHA-1 based)".to_string(),
                lengths: vec![40],
                pattern: Some(String::from(r"^\*[A-F0-9]{40}$")),
                confidence: Some(0.95),
            },
            HashRule {
                name: "SHA-224".to_string(),
                description: "SHA-224 (Secure Hash Algorithm 224-bit)".to_string(),
                lengths: vec![56],
                pattern: None,
                confidence: Some(0.9),
            },
            HashRule {
                name: "SHA-256".to_string(),
                description: "SHA-256 (Secure Hash Algorithm 256-bit)".to_string(),
                lengths: vec![64],
                pattern: None,
                confidence: Some(0.9),
            },
            HashRule {
                name: "HMAC-SHA256".to_string(),
                description: "HMAC using SHA-256".to_string(),
                lengths: vec![64],
                pattern: None,
                confidence: Some(0.5),
            },
            HashRule {
                name: "SHA3-256".to_string(),
                description: "SHA3-256 (Keccak 256-bit)".to_string(),
                lengths: vec![64],
                pattern: None,
                confidence: Some(0.5),
            },
            HashRule {
                name: "RIPEMD-256".to_string(),
                description: "RIPEMD-256 hash".to_string(),
                lengths: vec![64],
                pattern: None,
                confidence: Some(0.3),
            },
            HashRule {
                name: "SHA-384".to_string(),
                description: "SHA-384 (Secure Hash Algorithm 384-bit)".to_string(),
                lengths: vec![96],
                pattern: None,
                confidence: Some(0.9),
            },
            HashRule {
                name: "SHA-512".to_string(),
                description: "SHA-512 (Secure Hash Algorithm 512-bit)".to_string(),
                lengths: vec![128],
                pattern: None,
                confidence: Some(0.9),
            },
            HashRule {
                name: "HMAC-SHA512".to_string(),
                description: "HMAC using SHA-512".to_string(),
                lengths: vec![128],
                pattern: None,
                confidence: Some(0.5),
            },
            HashRule {
                name: "SHA3-512".to_string(),
                description: "SHA3-512 (Keccak 512-bit)".to_string(),
                lengths: vec![128],
                pattern: None,
                confidence: Some(0.5),
            },
            HashRule {
                name: "Whirlpool".to_string(),
                description: "Whirlpool hash - 512-bit".to_string(),
                lengths: vec![128],
                pattern: None,
                confidence: Some(0.3),
            },
            HashRule {
                name: "CRC-16".to_string(),
                description: "CRC-16 (Cyclic Redundancy Check 16-bit)".to_string(),
                lengths: vec![4],
                pattern: None,
                confidence: Some(0.7),
            },
            HashRule {
                name: "CRC-32".to_string(),
                description: "CRC-32 (Cyclic Redundancy Check 32-bit)".to_string(),
                lengths: vec![8],
                pattern: None,
                confidence: Some(0.7),
            },
            HashRule {
                name: "Adler-32".to_string(),
                description: "Adler-32 checksum".to_string(),
                lengths: vec![8],
                pattern: None,
                confidence: Some(0.4),
            },
            HashRule {
                name: "MySQL323".to_string(),
                description: "MySQL 3.x password hash (deprecated)".to_string(),
                lengths: vec![16],
                pattern: None,
                confidence: Some(0.6),
            },
            HashRule {
                name: "SHA-512/256".to_string(),
                description: "SHA-512/256 truncated hash".to_string(),
                lengths: vec![64],
                pattern: None,
                confidence: Some(0.3),
            },
            HashRule {
                name: "SHA3-384".to_string(),
                description: "SHA3-384 (Keccak 384-bit)".to_string(),
                lengths: vec![96],
                pattern: None,
                confidence: Some(0.5),
            },
        ]
    }
}

struct HashRule {
    name: String,
    description: String,
    lengths: Vec<usize>,
    pattern: Option<String>,
    confidence: Option<f64>,
}

pub struct IpGeoTool;

impl Default for IpGeoTool {
    fn default() -> Self {
        Self::new()
    }
}

impl IpGeoTool {
    pub fn new() -> Self {
        Self
    }

    pub async fn lookup(ip: &str) -> Result<IpGeoInfo> {
        let trimmed = ip.trim();

        if trimmed.is_empty() {
            return Err(ToolError::ExecutionError("Empty IP address".to_string()));
        }

        let url = format!("http://ip-api.com/json/{}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,timezone", trimmed);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut last_error = None;
        for attempt in 0..3 {
            let response = client
                .get(&url)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let json: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| ToolError::ExecutionError(format!("JSON parse error: {}", e)))?;

                        if json["status"].as_str() == Some("fail") {
                            let msg = json["message"].as_str().unwrap_or("Unknown error");
                            return Err(ToolError::ExecutionError(format!("IP lookup failed: {}", msg)));
                        }

                        return Ok(IpGeoInfo {
                            ip: trimmed.to_string(),
                            country: json["country"].as_str().unwrap_or("Unknown").to_string(),
                            country_code: json["countryCode"].as_str().unwrap_or("").to_string(),
                            region: json["regionName"].as_str().unwrap_or("Unknown").to_string(),
                            city: json["city"].as_str().unwrap_or("Unknown").to_string(),
                            latitude: json["lat"].as_f64().unwrap_or(0.0),
                            longitude: json["lon"].as_f64().unwrap_or(0.0),
                            isp: json["isp"].as_str().unwrap_or("Unknown").to_string(),
                            org: json["org"].as_str().unwrap_or("Unknown").to_string(),
                            timezone: json["timezone"].as_str().unwrap_or("Unknown").to_string(),
                        });
                    } else if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        let wait_secs = if attempt < 2 { 2u64 ^ attempt } else { 4 };
                        tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
                        last_error = Some("Rate limited by API".to_string());
                        continue;
                    } else {
                        return Err(ToolError::ExecutionError(format!("HTTP error: {}", resp.status())));
                    }
                }
                Err(e) => {
                    if attempt < 2 {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        last_error = Some(e.to_string());
                        continue;
                    }
                    return Err(ToolError::ExecutionError(format!("Request failed: {}", e)));
                }
            }
        }

        Err(ToolError::ExecutionError(format!("IP lookup failed after retries: {}", last_error.unwrap_or_default())))
    }
}

pub fn identify_hash(input: &str) -> Result<HashIdentification> {
    HashIdentifierTool::identify_hash(input)
}

pub async fn lookup_ip_geo(ip: &str) -> Result<IpGeoInfo> {
    IpGeoTool::lookup(ip).await
}
