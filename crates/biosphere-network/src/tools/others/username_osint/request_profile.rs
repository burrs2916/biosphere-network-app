use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};

static UA_INDEX: AtomicUsize = AtomicUsize::new(0);

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.122 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.122 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
];

const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8,es;q=0.7",
];

const ACCEPT_HEADERS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProfile {
    pub user_agent: String,
    pub accept: String,
    pub accept_language: String,
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub sec_fetch_dest: String,
    pub sec_fetch_mode: String,
    pub sec_fetch_site: String,
}

impl RequestProfile {
    pub fn chrome_desktop() -> Self {
        let mut rng = rand::thread_rng();
        let chrome_uas: Vec<&&str> = USER_AGENTS.iter().filter(|ua| !ua.contains("Firefox")).collect();
        let ua = chrome_uas.choose(&mut rng).copied().unwrap_or(&USER_AGENTS[0] );
        Self {
            user_agent: ua.to_string(),
            accept: ACCEPT_HEADERS.choose(&mut rng).unwrap().to_string(),
            accept_language: ACCEPT_LANGUAGES.choose(&mut rng).unwrap().to_string(),
            sec_ch_ua: Some(r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#.to_string()),
            sec_ch_ua_platform: Some("\"Windows\"".to_string()),
            sec_fetch_dest: "document".to_string(),
            sec_fetch_mode: "navigate".to_string(),
            sec_fetch_site: "none".to_string(),
        }
    }

    pub fn firefox_desktop() -> Self {
        let mut rng = rand::thread_rng();
        let ff_uas: Vec<&&str> = USER_AGENTS.iter().filter(|ua| ua.contains("Firefox")).collect();
        let ua = ff_uas.choose(&mut rng).copied().unwrap_or(&USER_AGENTS[2] );
        Self {
            user_agent: ua.to_string(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".to_string(),
            accept_language: ACCEPT_LANGUAGES.choose(&mut rng).unwrap().to_string(),
            sec_ch_ua: None,
            sec_ch_ua_platform: None,
            sec_fetch_dest: "document".to_string(),
            sec_fetch_mode: "navigate".to_string(),
            sec_fetch_site: "none".to_string(),
        }
    }

    pub fn rotating() -> Self {
        let idx = UA_INDEX.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
        let ua = USER_AGENTS[idx];
        if ua.contains("Firefox") {
            Self::firefox_desktop()
        } else {
            Self::chrome_desktop()
        }
    }

    pub fn apply_to_request_builder(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        let mut builder = builder
            .header("User-Agent", &self.user_agent)
            .header("Accept", &self.accept)
            .header("Accept-Language", &self.accept_language)
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Connection", "keep-alive")
            .header("Upgrade-Insecure-Requests", "1")
            .header("Sec-Fetch-Dest", &self.sec_fetch_dest)
            .header("Sec-Fetch-Mode", &self.sec_fetch_mode)
            .header("Sec-Fetch-Site", &self.sec_fetch_site);

        if let Some(ref sec_ch_ua) = self.sec_ch_ua {
            builder = builder.header("Sec-CH-UA", sec_ch_ua);
        }
        if let Some(ref platform) = self.sec_ch_ua_platform {
            builder = builder.header("Sec-CH-UA-Platform", platform);
        }

        builder
    }

    pub fn merge_site_headers(
        &self,
        site_headers: &std::collections::HashMap<String, String>,
    ) -> std::collections::HashMap<String, String> {
        let mut headers = std::collections::HashMap::new();
        headers.insert("User-Agent".to_string(), self.user_agent.clone());
        headers.insert("Accept".to_string(), self.accept.clone());
        headers.insert("Accept-Language".to_string(), self.accept_language.clone());
        headers.insert("Accept-Encoding".to_string(), "gzip, deflate, br".to_string());
        headers.insert("Connection".to_string(), "close".to_string());
        headers.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
        headers.insert("Sec-Fetch-Dest".to_string(), self.sec_fetch_dest.clone());
        headers.insert("Sec-Fetch-Mode".to_string(), self.sec_fetch_mode.clone());
        headers.insert("Sec-Fetch-Site".to_string(), self.sec_fetch_site.clone());

        if let Some(ref sec_ch_ua) = self.sec_ch_ua {
            headers.insert("Sec-CH-UA".to_string(), sec_ch_ua.clone());
        }
        if let Some(ref platform) = self.sec_ch_ua_platform {
            headers.insert("Sec-CH-UA-Platform".to_string(), platform.clone());
        }

        for (k, v) in site_headers {
            headers.insert(k.clone(), v.clone());
        }

        headers
    }
}

pub fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(2)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .tcp_keepalive(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default()
}

pub fn needs_tls_impersonation(platform: &crate::infrastructure::database::models::OsintPlatform) -> bool {
    let protection = platform.parse_protection();
    protection.iter().any(|p| p == "tls_fingerprint")
}
