use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone)]
pub struct CsrfTokenManager {
    secret: String,
    token_ttl_secs: u64,
}

impl CsrfTokenManager {
    pub fn new(secret: String, token_ttl_secs: u64) -> Self {
        Self { secret, token_ttl_secs }
    }

    pub fn generate_token(&self, session_id: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let payload = format!("{}:{}:{}", self.secret, session_id, now);
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let hash = hasher.finalize();

        let timestamp_bytes = now.to_le_bytes();
        let mut token_bytes = Vec::with_capacity(32 + 8);
        token_bytes.extend_from_slice(&hash);
        token_bytes.extend_from_slice(&timestamp_bytes);

        hex::encode(token_bytes)
    }

    pub fn validate_token(&self, token: &str, session_id: &str) -> bool {
        let token_bytes = match hex::decode(token) {
            Ok(b) => b,
            Err(_) => return false,
        };

        if token_bytes.len() != 40 {
            return false;
        }

        let timestamp_bytes = &token_bytes[32..40];
        let timestamp = u64::from_le_bytes(
            timestamp_bytes.try_into().unwrap_or([0u8; 8])
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(timestamp) > self.token_ttl_secs {
            return false;
        }

        let expected_payload = format!("{}:{}:{}", self.secret, session_id, timestamp);
        let mut hasher = Sha256::new();
        hasher.update(expected_payload.as_bytes());
        let expected_hash = hasher.finalize();

        token_bytes[..32] == expected_hash[..]
    }

    pub fn generate_token_pair(&self, session_id: &str) -> (String, String) {
        let csrf_token = self.generate_token(session_id);
        let cookie_token = self.generate_token(&format!("cookie:{}", session_id));
        (csrf_token, cookie_token)
    }

    pub fn double_submit_validate(
        &self,
        header_token: &str,
        cookie_token: &str,
        session_id: &str,
    ) -> bool {
        if !self.validate_token(header_token, session_id) {
            return false;
        }
        if !self.validate_token(cookie_token, &format!("cookie:{}", session_id)) {
            return false;
        }
        header_token != cookie_token
    }
}

impl Default for CsrfTokenManager {
    fn default() -> Self {
        Self {
            secret: uuid::Uuid::new_v4().to_string(),
            token_ttl_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityHeaders {
    pub content_type_options: String,
    pub frame_guard: String,
    pub xss_protection: String,
    pub hsts: Option<String>,
    pub csp: Option<String>,
    pub referrer_policy: String,
    pub permissions_policy: Option<String>,
    pub cache_control: String,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            content_type_options: "nosniff".to_string(),
            frame_guard: "DENY".to_string(),
            xss_protection: "1; mode=block".to_string(),
            hsts: Some("max-age=31536000; includeSubDomains".to_string()),
            csp: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'".to_string()),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: Some("camera=(), microphone=(), geolocation=()".to_string()),
            cache_control: "no-store, no-cache, must-revalidate".to_string(),
        }
    }
}

impl SecurityHeaders {
    pub fn to_header_map(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("X-Content-Type-Options".to_string(), self.content_type_options.clone());
        headers.insert("X-Frame-Options".to_string(), self.frame_guard.clone());
        headers.insert("X-XSS-Protection".to_string(), self.xss_protection.clone());
        headers.insert("Referrer-Policy".to_string(), self.referrer_policy.clone());
        headers.insert("Cache-Control".to_string(), self.cache_control.clone());

        if let Some(ref hsts) = self.hsts {
            headers.insert("Strict-Transport-Security".to_string(), hsts.clone());
        }
        if let Some(ref csp) = self.csp {
            headers.insert("Content-Security-Policy".to_string(), csp.clone());
        }
        if let Some(ref pp) = self.permissions_policy {
            headers.insert("Permissions-Policy".to_string(), pp.clone());
        }

        headers
    }

    pub fn strict() -> Self {
        Self {
            content_type_options: "nosniff".to_string(),
            frame_guard: "DENY".to_string(),
            xss_protection: "1; mode=block".to_string(),
            hsts: Some("max-age=63072000; includeSubDomains; preload".to_string()),
            csp: Some("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'".to_string()),
            referrer_policy: "no-referrer".to_string(),
            permissions_policy: Some("camera=(), microphone=(), geolocation=(), payment=()".to_string()),
            cache_control: "no-store".to_string(),
        }
    }

    pub fn relaxed() -> Self {
        Self {
            content_type_options: "nosniff".to_string(),
            frame_guard: "SAMEORIGIN".to_string(),
            xss_protection: "1; mode=block".to_string(),
            hsts: None,
            csp: None,
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: None,
            cache_control: "no-cache".to_string(),
        }
    }
}
