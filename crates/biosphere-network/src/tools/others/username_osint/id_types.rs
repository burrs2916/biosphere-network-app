use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const SUPPORTED_IDS: &[&str] = &[
    "username",
    "yandex_public_id",
    "gaia_id",
    "vk_id",
    "ok_id",
    "wikimapia_uid",
    "steam_id",
    "uidme_uguid",
    "yelp_userid",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(Default)]
pub enum IdType {
    #[default]
    Username,
    YandexPublicId,
    GaiaId,
    VkId,
    OkId,
    WikimapiaUid,
    SteamId,
    UidmeUguid,
    YelpUserid,
}

impl IdType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IdType::Username => "username",
            IdType::YandexPublicId => "yandex_public_id",
            IdType::GaiaId => "gaia_id",
            IdType::VkId => "vk_id",
            IdType::OkId => "ok_id",
            IdType::WikimapiaUid => "wikimapia_uid",
            IdType::SteamId => "steam_id",
            IdType::UidmeUguid => "uidme_uguid",
            IdType::YelpUserid => "yelp_userid",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "username" => Some(IdType::Username),
            "yandex_public_id" => Some(IdType::YandexPublicId),
            "gaia_id" => Some(IdType::GaiaId),
            "vk_id" => Some(IdType::VkId),
            "ok_id" => Some(IdType::OkId),
            "wikimapia_uid" => Some(IdType::WikimapiaUid),
            "steam_id" => Some(IdType::SteamId),
            "uidme_uguid" => Some(IdType::UidmeUguid),
            "yelp_userid" => Some(IdType::YelpUserid),
            _ => None,
        }
    }

    pub fn is_username(&self) -> bool {
        self == &IdType::Username
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedId {
    pub id_value: String,
    pub id_type: String,
    pub source_platform: String,
    pub source_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdExtractionResult {
    pub extracted_ids: Vec<ExtractedId>,
    pub extracted_usernames: HashMap<String, String>,
    pub extracted_links: Vec<String>,
}

impl IdExtractionResult {
    pub fn merge(&mut self, other: IdExtractionResult) {
        for id in other.extracted_ids {
            if !self.extracted_ids.iter().any(|e| e.id_value == id.id_value && e.id_type == id.id_type) {
                self.extracted_ids.push(id);
            }
        }
        for (k, v) in other.extracted_usernames {
            self.extracted_usernames.entry(k).or_insert(v);
        }
        for link in other.extracted_links {
            if !self.extracted_links.contains(&link) {
                self.extracted_links.push(link);
            }
        }
    }

    pub fn get_new_search_targets(&self, already_checked: &[String]) -> Vec<(String, String)> {
        let mut targets = Vec::new();
        for id in &self.extracted_ids {
            let key = format!("{}:{}", id.id_type, id.id_value.to_lowercase());
            if !already_checked.iter().any(|c| c.to_lowercase() == key) {
                targets.push((id.id_value.clone(), id.id_type.clone()));
            }
        }
        for (username, id_type) in &self.extracted_usernames {
            let key = format!("{}:{}", id_type, username.to_lowercase());
            if !already_checked.iter().any(|c| c.to_lowercase() == key) {
                targets.push((username.clone(), id_type.clone()));
            }
        }
        targets
    }
}

pub fn extract_ids_from_html(
    html: &str,
    platform_name: &str,
    platform_url: &str,
) -> IdExtractionResult {
    let mut result = IdExtractionResult::default();

    extract_username_ids(html, platform_name, platform_url, &mut result);
    extract_numeric_ids(html, platform_name, platform_url, &mut result);
    extract_external_profile_links(html, platform_name, platform_url, &mut result);
    extract_json_ld_ids(html, platform_name, platform_url, &mut result);

    result
}

fn extract_username_ids(
    html: &str,
    platform_name: &str,
    platform_url: &str,
    result: &mut IdExtractionResult,
) {
    let patterns = [
        (r#""username"\s*:\s*"([^"]+)""#, "username"),
        (r#""screen_name"\s*:\s*"([^"]+)""#, "username"),
        (r#""user_name"\s*:\s*"([^"]+)""#, "username"),
        (r#""nickname"\s*:\s*"([^"]+)""#, "username"),
        (r#""login"\s*:\s*"([^"]+)""#, "username"),
        (r#""handle"\s*:\s*"([^"]+)""#, "username"),
        (r#"data-username="([^"]+)""#, "username"),
        (r#"@"([a-zA-Z0-9_]{3,30})""#, "username"),
    ];

    for (pattern, id_type) in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for caps in re.captures_iter(html) {
                if let Some(m) = caps.get(1) {
                    let val = m.as_str().to_string();
                    if val.len() >= 2 && val.len() <= 50 {
                        result.extracted_usernames.insert(val.clone(), id_type.to_string());
                        result.extracted_ids.push(ExtractedId {
                            id_value: val,
                            id_type: id_type.to_string(),
                            source_platform: platform_name.to_string(),
                            source_url: platform_url.to_string(),
                        });
                    }
                }
            }
        }
    }
}

fn extract_numeric_ids(
    html: &str,
    platform_name: &str,
    platform_url: &str,
    result: &mut IdExtractionResult,
) {
    let patterns = [
        (r#""vk_id"\s*:\s*"?(\d+)"?"#, "vk_id"),
        (r#""ok_id"\s*:\s*"?(\d+)"?"#, "ok_id"),
        (r#""steam_id"\s*:\s*"?(\d{17})""#, "steam_id"),
        (r#""gaia_id"\s*:\s*"?(\d+)"?"#, "gaia_id"),
        (r#""yandex_public_id"\s*:\s*"([^"]+)""#, "yandex_public_id"),
        (r#""wikimapia_uid"\s*:\s*"?(\d+)"?"#, "wikimapia_uid"),
        (r#""uidme_uguid"\s*:\s*"([^"]+)""#, "uidme_uguid"),
        (r#""yelp_userid"\s*:\s*"([^"]+)""#, "yelp_userid"),
        (r#""user_id"\s*:\s*"?(\d+)"?"#, "username"),
        (r#""profile_id"\s*:\s*"?(\d+)"?"#, "username"),
        (r#""account_id"\s*:\s*"?(\d+)"?"#, "username"),
        (r#""uid"\s*:\s*"?(\d+)"?"#, "username"),
    ];

    for (pattern, id_type) in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for caps in re.captures_iter(html) {
                if let Some(m) = caps.get(1) {
                    let val = m.as_str().to_string();
                    if !val.is_empty() {
                        result.extracted_ids.push(ExtractedId {
                            id_value: val,
                            id_type: id_type.to_string(),
                            source_platform: platform_name.to_string(),
                            source_url: platform_url.to_string(),
                        });
                    }
                }
            }
        }
    }
}

fn extract_external_profile_links(
    html: &str,
    platform_name: &str,
    platform_url: &str,
    result: &mut IdExtractionResult,
) {
    let profile_patterns = [
        (r#"href="https?://(?:www\.)?twitter\.com/([a-zA-Z0-9_]{1,15})""#, "twitter.com"),
        (r#"href="https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_.]{1,30})""#, "instagram.com"),
        (r#"href="https?://(?:www\.)?github\.com/([a-zA-Z0-9_-]{1,39})""#, "github.com"),
        (r#"href="https?://(?:www\.)?reddit\.com/user/([a-zA-Z0-9_-]{3,21})""#, "reddit.com"),
        (r#"href="https?://(?:www\.)?facebook\.com/([a-zA-Z0-9.]{5,50})""#, "facebook.com"),
        (r#"href="https?://(?:www\.)?linkedin\.com/in/([a-zA-Z0-9_-]{3,100})""#, "linkedin.com"),
        (r#"href="https?://(?:www\.)?youtube\.com/(?:c/|channel/|user/|@)([a-zA-Z0-9_.-]{1,100})""#, "youtube.com"),
        (r#"href="https?://(?:www\.)?tiktok\.com/@([a-zA-Z0-9_.]{2,24})""#, "tiktok.com"),
        (r#"href="https?://(?:www\.)?pinterest\.com/([a-zA-Z0-9_]{3,30})""#, "pinterest.com"),
        (r#"href="https?://(?:www\.)?tumblr\.com/([a-zA-Z0-9-]{1,32})""#, "tumblr.com"),
        (r#"href="https?://(?:www\.)?vk\.com/([a-zA-Z0-9_.]{1,32})""#, "vk.com"),
        (r#"href="https?://(?:www\.)?steamcommunity\.com/(?:id|profiles)/([a-zA-Z0-9_/]{1,50})""#, "steamcommunity.com"),
        (r#"href="https?://(?:www\.)?t\.me/([a-zA-Z0-9_]{5,32})""#, "t.me"),
        (r#"href="https?://(?:www\.)?mastodon\.social/@([a-zA-Z0-9_]{1,30})""#, "mastodon.social"),
    ];

    for (pattern, domain) in &profile_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for caps in re.captures_iter(html) {
                if let Some(m) = caps.get(1) {
                    let username = m.as_str().to_string();
                    if !username.is_empty() {
                        result.extracted_usernames.insert(username.clone(), "username".to_string());
                        result.extracted_ids.push(ExtractedId {
                            id_value: username,
                            id_type: "username".to_string(),
                            source_platform: platform_name.to_string(),
                            source_url: platform_url.to_string(),
                        });
                        result.extracted_links.push(format!("https://{}", domain));
                    }
                }
            }
        }
    }
}

fn extract_json_ld_ids(
    html: &str,
    platform_name: &str,
    platform_url: &str,
    result: &mut IdExtractionResult,
) {
    if let Ok(re) = regex::Regex::new(r#"<script\s+type="application/ld\+json"[^>]*>(.*?)</script>"#) {
        for caps in re.captures_iter(html) {
            if let Some(m) = caps.get(1) {
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(m.as_str()) {
                    extract_ids_from_json_value(&json_val, platform_name, platform_url, result);
                }
            }
        }
    }
}

fn extract_ids_from_json_value(
    val: &serde_json::Value,
    platform_name: &str,
    platform_url: &str,
    result: &mut IdExtractionResult,
) {
    if let Some(obj) = val.as_object() {
        for (key, v) in obj {
            match key.as_str() {
                "name" | "alternateName" | "username" | "screen_name" => {
                    if let Some(s) = v.as_str() {
                        if s.len() >= 2 && s.len() <= 50 {
                            result.extracted_usernames.insert(s.to_string(), "username".to_string());
                            result.extracted_ids.push(ExtractedId {
                                id_value: s.to_string(),
                                id_type: "username".to_string(),
                                source_platform: platform_name.to_string(),
                                source_url: platform_url.to_string(),
                            });
                        }
                    }
                }
                "url" => {
                    if let Some(s) = v.as_str() {
                        result.extracted_links.push(s.to_string());
                    }
                }
                "sameAs" => {
                    if let Some(arr) = v.as_array() {
                        for link in arr {
                            if let Some(s) = link.as_str() {
                                result.extracted_links.push(s.to_string());
                            }
                        }
                    }
                }
                _ => {
                    extract_ids_from_json_value(v, platform_name, platform_url, result);
                }
            }
        }
    } else if let Some(arr) = val.as_array() {
        for item in arr {
            extract_ids_from_json_value(item, platform_name, platform_url, result);
        }
    }
}

pub fn extract_ids_from_urls(
    urls: &[String],
    platforms: &[crate::infrastructure::database::models::OsintPlatform],
) -> IdExtractionResult {
    let mut result = IdExtractionResult::default();

    for url in urls {
        for platform in platforms {
            if let Some(username) = detect_username_from_url(url, platform) {
                result.extracted_usernames.insert(username.clone(), platform.id_type.clone());
                result.extracted_ids.push(ExtractedId {
                    id_value: username,
                    id_type: platform.id_type.clone(),
                    source_platform: platform.name.clone(),
                    source_url: url.clone(),
                });
            }
        }
    }

    result
}

fn detect_username_from_url(
    url: &str,
    platform: &crate::infrastructure::database::models::OsintPlatform,
) -> Option<String> {
    if let Some(ref regex_check) = platform.regex_check {
        if let Ok(re) = regex::Regex::new(regex_check) {
            if let Some(caps) = re.captures(url) {
                for i in (1..caps.len()).rev() {
                    if let Some(m) = caps.get(i) {
                        let val = m.as_str().trim_end_matches('/').to_string();
                        if !val.is_empty() {
                            return Some(val);
                        }
                    }
                }
            }
        }
    }

    if let Some(ref url_main) = platform.url_main {
        let base = url_main.trim_end_matches('/');
        if url.starts_with(base) {
            let rest = url.strip_prefix(base).unwrap();
            let rest = rest.trim_start_matches('/');
            let username = rest.split('/').next().unwrap_or("");
            let username = username.trim_end_matches('/');
            if !username.is_empty() && !username.is_empty() && username.len() <= 50
                && username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
                    return Some(username.to_string());
                }
        }
    }

    None
}

pub fn extract_ids_from_results(
    results: &[super::config::PlatformResult],
    platforms: &[crate::infrastructure::database::models::OsintPlatform],
) -> IdExtractionResult {
    let mut combined = IdExtractionResult::default();

    for r in results {
        if let Some(ref info) = r.extracted_info {
            if let Some(ref id_val) = info.id_value {
                combined.extracted_ids.push(ExtractedId {
                    id_value: id_val.clone(),
                    id_type: "username".to_string(),
                    source_platform: r.platform.clone(),
                    source_url: r.url.clone(),
                });
                combined.extracted_usernames.insert(id_val.clone(), "username".to_string());
            }
            for link in &info.external_links {
                combined.extracted_links.push(link.clone());
                let link_result = extract_ids_from_urls(std::slice::from_ref(link), platforms);
                combined.merge(link_result);
            }
        }
    }

    combined
}
