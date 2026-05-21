use crate::core::{Result, ToolError};
use super::config::*;
use std::collections::{HashSet, HashMap, VecDeque, BinaryHeap};
use std::sync::Arc;
use tokio::sync::Semaphore;
use rand::Rng;
use std::cmp::Ordering;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

struct ProxyPool {
    proxies: Vec<String>,
    current_index: AtomicUsize,
    rotation_mode: String,
    failed_proxies: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

impl ProxyPool {
    fn new(config: &ProxyPoolConfig) -> Self {
        let proxies: Vec<String> = config.proxies.iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect();
        Self {
            proxies,
            current_index: AtomicUsize::new(0),
            rotation_mode: config.rotation_mode.clone(),
            failed_proxies: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        }
    }

    fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    fn get_next(&self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }
        match self.rotation_mode.as_str() {
            "random" => {
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..self.proxies.len());
                Some(self.proxies[idx].clone())
            }
            _ => {
                let idx = self.current_index.fetch_add(1, AtomicOrdering::Relaxed) % self.proxies.len();
                Some(self.proxies[idx].clone())
            }
        }
    }

    async fn mark_failed(&self, proxy: &str) {
        let mut failed = self.failed_proxies.lock().await;
        failed.insert(proxy.to_string());
    }

    async fn get_next_healthy(&self) -> Option<String> {
        let failed = self.failed_proxies.lock().await;
        for _ in 0..self.proxies.len() {
            let proxy = self.get_next()?;
            if !failed.contains(&proxy) {
                return Some(proxy);
            }
        }
        drop(failed);
        self.failed_proxies.lock().await.clear();
        self.get_next()
    }
}

struct CrawlCache {
    cache_dir: String,
    ttl_seconds: u64,
    enabled: bool,
}

impl CrawlCache {
    fn new(config: &CacheConfig) -> Self {
        Self {
            cache_dir: if config.cache_dir.is_empty() {
                std::env::temp_dir().join("biosphere_crawl_cache").to_string_lossy().to_string()
            } else {
                config.cache_dir.clone()
            },
            ttl_seconds: config.ttl_seconds,
            enabled: config.enabled,
        }
    }

    fn cache_key(&self, url: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    fn get(&self, url: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let key = self.cache_key(url);
        let path = std::path::Path::new(&self.cache_dir).join(&key);
        if path.exists() {
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        if elapsed.as_secs() < self.ttl_seconds {
                            return std::fs::read_to_string(&path).ok();
                        }
                    }
                }
            }
        }
        None
    }

    fn set(&self, url: &str, content: &str) {
        if !self.enabled {
            return;
        }
        let _ = std::fs::create_dir_all(&self.cache_dir);
        let key = self.cache_key(url);
        let path = std::path::Path::new(&self.cache_dir).join(&key);
        let _ = std::fs::write(&path, content);
    }
}

fn detect_popup_overlay(html: &str) -> PopupDetection {
    let mut popup_types: Vec<String> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let mut confidence: f64 = 0.0;
    let lower = html.to_lowercase();

    let cookie_patterns = [
        ("cookie-banner", "Cookie Banner"),
        ("cookie-consent", "Cookie Consent"),
        ("cookie-notice", "Cookie Notice"),
        ("cookie-policy", "Cookie Policy"),
        ("cc-banner", "Cookie Banner"),
        ("gdpr-banner", "GDPR Banner"),
        ("consent-banner", "Consent Banner"),
    ];

    for (pattern, name) in &cookie_patterns {
        if lower.contains(pattern) {
            popup_types.push(name.to_string());
            details.push(format!("Cookie/consent element: '{}'", pattern));
            confidence += 0.3;
        }
    }

    let modal_patterns = [
        (r#"class\s*=\s*"[^"]*(?:modal|popup|overlay|dialog)[^"]*""#, "Modal/Popup"),
        (r#"id\s*=\s*"[^"]*(?:modal|popup|overlay|dialog)[^"]*""#, "Modal/Popup"),
        (r#"role\s*=\s*"(?:dialog|alertdialog)""#, "ARIA Dialog"),
    ];

    for (pattern, name) in &modal_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(html) {
                if !popup_types.contains(&name.to_string()) {
                    popup_types.push(name.to_string());
                }
                details.push(format!("Modal element detected: {}", name));
                confidence += 0.25;
            }
        }
    }

    let newsletter_patterns = [
        ("newsletter", "Newsletter Popup"),
        ("subscribe-popup", "Subscribe Popup"),
        ("email-popup", "Email Popup"),
    ];

    for (pattern, name) in &newsletter_patterns {
        if lower.contains(pattern) {
            popup_types.push(name.to_string());
            details.push(format!("Newsletter/subscribe element: '{}'", pattern));
            confidence += 0.2;
        }
    }

    if lower.contains("position:fixed") && (lower.contains("z-index") || lower.contains("zindex")) {
        let fixed_overlay_re = regex::Regex::new(
            r#"position\s*:\s*fixed[^}]*z-index\s*:\s*\d{3,}"#
        ).ok();
        if let Some(re) = fixed_overlay_re {
            if re.is_match(html) {
                popup_types.push("Fixed Overlay".to_string());
                details.push("High z-index fixed position overlay detected".to_string());
                confidence += 0.15;
            }
        }
    }

    PopupDetection {
        detected: confidence >= 0.3,
        popup_types,
        confidence: confidence.min(1.0),
        details,
    }
}

fn html_to_markdown(html: &str) -> String {
    let mut md = String::new();
    let mut in_tag = false;
    let mut current_tag = String::new();
    let mut tag_buffer = String::new();
    let mut skip_content = false;
    let skip_tags = ["script", "style", "noscript", "svg", "path"];
    let mut tag_stack: Vec<String> = Vec::new();
    let mut list_depth: usize = 0;
    let mut in_pre = false;
    let mut in_code = false;
    let mut in_blockquote = false;
    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == '<' {
            in_tag = true;
            current_tag.clear();
            tag_buffer.clear();
            i += 1;
            continue;
        }

        if c == '>' && in_tag {
            in_tag = false;
            let tag_full = tag_buffer.trim();
            let is_closing = tag_full.starts_with('/');
            let tag_name_raw = tag_full.trim_start_matches('/').split_whitespace().next().unwrap_or("").to_lowercase();

            if is_closing {
                if let Some(last) = tag_stack.last() {
                    if last == &tag_name_raw {
                        tag_stack.pop();
                    }
                }
                skip_content = tag_stack.iter().any(|t| skip_tags.contains(&t.as_str()));

                match tag_name_raw.as_str() {
                    "h1" => md.push_str("\n\n"),
                    "h2" => md.push_str("\n\n"),
                    "h3" => md.push_str("\n\n"),
                    "h4" => md.push_str("\n\n"),
                    "h5" => md.push_str("\n\n"),
                    "h6" => md.push_str("\n\n"),
                    "p" | "div" => md.push_str("\n\n"),
                    "li" => { list_depth = list_depth.saturating_sub(1); md.push('\n'); }
                    "pre" => in_pre = false,
                    "code" => { if !in_pre { in_code = false; md.push('`'); } }
                    "blockquote" => { in_blockquote = false; md.push('\n'); }
                    "a" => md.push(')'),
                    "tr" => md.push_str("|\n"),
                    "img" => {}
                    _ => {}
                }
            } else {
                if !skip_content && !skip_tags.contains(&tag_name_raw.as_str()) {
                    match tag_name_raw.as_str() {
                        "h1" => md.push_str("\n\n# "),
                        "h2" => md.push_str("\n\n## "),
                        "h3" => md.push_str("\n\n### "),
                        "h4" => md.push_str("\n\n#### "),
                        "h5" => md.push_str("\n\n##### "),
                        "h6" => md.push_str("\n\n###### "),
                        "p" => md.push_str("\n\n"),
                        "br" => md.push_str("  \n"),
                        "hr" => md.push_str("\n---\n"),
                        "strong" | "b" => md.push_str("**"),
                        "em" | "i" => md.push('*'),
                        "ul" | "ol" => { list_depth += 1; md.push('\n'); }
                        "li" => {
                            let indent = "  ".repeat(list_depth.saturating_sub(1));
                            md.push_str(&format!("{}- ", indent));
                        }
                        "pre" => { in_pre = true; md.push_str("\n```\n"); }
                        "code" => { if !in_pre { in_code = true; md.push('`'); } }
                        "blockquote" => { in_blockquote = true; md.push_str("> "); }
                        "a" => {
                            if let Some(href_start) = tag_full.find("href=\"") {
                                if let Some(href_end) = tag_full[href_start + 6..].find('"') {
                                    let href = &tag_full[href_start + 6..href_start + 6 + href_end];
                                    md.push_str(&format!("[") );
                                    current_tag = format!("href:{}", href);
                                }
                            } else {
                                md.push('[');
                            }
                        }
                        "img" => {
                            let mut src_val = "";
                            let mut alt_val = "";
                            if let Some(s) = extract_attr_from_tag(tag_full, "src") {
                                src_val = s;
                            }
                            if let Some(a) = extract_attr_from_tag(tag_full, "alt") {
                                alt_val = a;
                            }
                            md.push_str(&format!("![{}]({})", alt_val, src_val));
                        }
                        "th" | "td" => md.push_str("| "),
                        _ => {}
                    }
                }
                if !is_closing && !tag_name_raw.is_empty() && !tag_name_raw.starts_with('!') {
                    let self_closing = ["br", "hr", "img", "input", "meta", "link"];
                    if !self_closing.contains(&tag_name_raw.as_str()) {
                        tag_stack.push(tag_name_raw.clone());
                    }
                }
                skip_content = tag_stack.iter().any(|t| skip_tags.contains(&t.as_str()));
            }
            i += 1;
            continue;
        }

        if in_tag {
            tag_buffer.push(c);
            i += 1;
            continue;
        }

        if !skip_content {
            let mut text = c.to_string();
            if in_blockquote && c == '\n' {
                text = "\n> ".to_string();
            }
            if in_pre {
                md.push_str(&text);
            } else {
                let trimmed = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&nbsp;", " ");
                md.push_str(&trimmed);
            }
        }
        i += 1;
    }

    let lines: Vec<&str> = md.lines().collect();
    let mut result = String::new();
    let mut prev_empty = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !prev_empty {
                result.push('\n');
                prev_empty = true;
            }
        } else {
            result.push_str(line);
            result.push('\n');
            prev_empty = false;
        }
    }

    result.trim().to_string()
}

fn extract_attr_from_tag<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let pattern = format!("{}=\"", attr);
    if let Some(start) = tag.find(&pattern) {
        let val_start = start + pattern.len();
        if let Some(end) = tag[val_start..].find('"') {
            return Some(&tag[val_start..val_start + end]);
        }
    }
    None
}

fn apply_url_filters(url: &str, include_patterns: &str, exclude_patterns: &str) -> bool {
    if !exclude_patterns.is_empty() {
        for pattern in exclude_patterns.split(',').map(|s| s.trim()) {
            if pattern.is_empty() { continue; }
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(url) {
                    return false;
                }
            } else if url.contains(pattern) {
                return false;
            }
        }
    }

    if !include_patterns.is_empty() {
        let mut matched = false;
        for pattern in include_patterns.split(',').map(|s| s.trim()) {
            if pattern.is_empty() { continue; }
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(url) {
                    matched = true;
                    break;
                }
            } else if url.contains(pattern) {
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }

    true
}

fn get_random_user_agent() -> String {
    let agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    ];
    let mut rng = rand::thread_rng();
    agents[rng.gen_range(0..agents.len())].to_string()
}

fn resolve_url_proper(base: &str, relative: &str) -> Option<String> {
    let base_url = url::Url::parse(base).ok()?;
    base_url.join(relative).ok().map(|u| u.to_string())
}

struct ResourceRule {
    selector_pattern: &'static str,
    #[allow(dead_code)]
    attr: &'static str,
    resource_type: &'static str,
}

const IMAGE_RESOURCE_RULES: &[ResourceRule] = &[
    ResourceRule { selector_pattern: r#"<img[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "img" },
    ResourceRule { selector_pattern: r#"<img[^>]+data-src\s*=\s*"([^"]+)""#, attr: "data-src", resource_type: "lazy" },
    ResourceRule { selector_pattern: r#"<img[^>]+data-lazy-src\s*=\s*"([^"]+)""#, attr: "data-lazy-src", resource_type: "lazy" },
    ResourceRule { selector_pattern: r#"<img[^>]+data-original\s*=\s*"([^"]+)""#, attr: "data-original", resource_type: "lazy" },
    ResourceRule { selector_pattern: r#"<img[^>]+data-lazy\s*=\s*"([^"]+)""#, attr: "data-lazy", resource_type: "lazy" },
    ResourceRule { selector_pattern: r#"<input[^>]+type\s*=\s*"image"[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "input-image" },
    ResourceRule { selector_pattern: r#"<link[^>]+rel\s*=\s*"[^"]*icon[^"]*"[^>]+href\s*=\s*"([^"]+)""#, attr: "href", resource_type: "favicon" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:image[^"]*"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-image" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:image:url"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-image" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:image:secure_url"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-image" },
    ResourceRule { selector_pattern: r#"<meta[^>]+name="twitter:image"[^>]+content="([^"]+)""#, attr: "content", resource_type: "twitter-image" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="twitter:image"[^>]+content="([^"]+)""#, attr: "content", resource_type: "twitter-image" },
    ResourceRule { selector_pattern: r#"(?:<svg|<use|<image)[^>]+(?:xlink:href|href)\s*=\s*"([^"]+)""#, attr: "href", resource_type: "svg-ref" },
    ResourceRule { selector_pattern: r#"<[a-zA-Z][^>]+background\s*=\s*"([^"]+)""#, attr: "background", resource_type: "background" },
];

const VIDEO_RESOURCE_RULES: &[ResourceRule] = &[
    ResourceRule { selector_pattern: r#"<video[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "video" },
    ResourceRule { selector_pattern: r#"<video[^>]*>[\s\S]*?<source[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "video-source" },
    ResourceRule { selector_pattern: r#"<video[^>]*>[\s\S]*?<track[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "video-track" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:video[^"]*"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-video" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:video:url"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-video" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:video:secure_url"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-video" },
    ResourceRule { selector_pattern: r#"<iframe[^>]+src\s*=\s*"([^"]*(?:youtube|vimeo|dailymotion|bilibili|twitch)[^"]*)""#, attr: "src", resource_type: "embed" },
];

const AUDIO_RESOURCE_RULES: &[ResourceRule] = &[
    ResourceRule { selector_pattern: r#"<audio[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "audio" },
    ResourceRule { selector_pattern: r#"<audio[^>]*>[\s\S]*?<source[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "audio-source" },
    ResourceRule { selector_pattern: r#"<audio[^>]*>[\s\S]*?<track[^>]+src\s*=\s*"([^"]+)""#, attr: "src", resource_type: "audio-track" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:audio[^"]*"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-audio" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:audio:url"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-audio" },
    ResourceRule { selector_pattern: r#"<meta[^>]+property="og:audio:secure_url"[^>]+content="([^"]+)""#, attr: "content", resource_type: "og-audio" },
];

const LINK_RESOURCE_RULES: &[ResourceRule] = &[
    ResourceRule { selector_pattern: r#"<link[^>]+rel\s*=\s*"[^"]*preload[^"]*"[^>]+href\s*=\s*"([^"]+)""#, attr: "href", resource_type: "preload" },
    ResourceRule { selector_pattern: r#"<link[^>]+rel\s*=\s*"[^"]*prefetch[^"]*"[^>]+href\s*=\s*"([^"]+)""#, attr: "href", resource_type: "prefetch" },
    ResourceRule { selector_pattern: r#"<link[^>]+rel\s*=\s*"[^"]*preconnect[^"]*"[^>]+href\s*=\s*"([^"]+)""#, attr: "href", resource_type: "preconnect" },
    ResourceRule { selector_pattern: r#"<param[^>]+name\s*=\s*"movie"[^>]+value\s*=\s*"([^"]+)""#, attr: "value", resource_type: "flash" },
];

const TRACKING_PARAMS: &[&str] = &[
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid",
    "mc_eid", "mc_cid", "_ga", "_gl", "_hsenc", "_hsmi",
    "hsCtaTracking", "vero_id", "oly_anon_id", "oly_enc_id",
    "otc", "igshid", "wickedid", "twclid", "ttclid",
    "li_fat_id", "li_shid", "spm", "scm",
];

fn normalize_url(url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        parsed.set_fragment(None);
        let pairs: Vec<(String, String)> = parsed.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .filter(|(k, _)| {
                let lower_k = k.to_lowercase();
                !TRACKING_PARAMS.contains(&lower_k.as_str())
            })
            .collect();
        if !pairs.is_empty() {
            let mut sorted_pairs = pairs;
            sorted_pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            let query_str: String = sorted_pairs.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            let _ = parsed.set_query(Some(&query_str));
        } else {
            let _ = parsed.set_query(None);
        }
        return parsed.to_string();
    }
    url.to_string()
}

fn is_crawlable_url(url: &str) -> bool {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return false;
    }
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            if host.is_empty() || host == "localhost" || host == "127.0.0.1" {
                return false;
            }
            if !host.contains('.') {
                return false;
            }
        } else {
            return false;
        }
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return false;
        }
    } else {
        return false;
    }
    let lower = url.to_lowercase();
    if lower.starts_with("mailto:") || lower.starts_with("tel:") || lower.starts_with("javascript:") || lower.starts_with("data:") || lower.starts_with("blob:") {
        return false;
    }
    if lower.contains("void(0)") || lower.contains("about:blank") {
        return false;
    }
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path().to_lowercase();
        let static_extensions = [
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
            ".mp4", ".webm", ".ogg", ".avi", ".mov", ".flv", ".wmv", ".m4v",
            ".mp3", ".wav", ".flac", ".aac", ".m4a", ".wma", ".opus",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".woff", ".woff2", ".ttf", ".otf", ".eot",
            ".css", ".js", ".json", ".xml", ".txt", ".rss",
        ];
        for ext in &static_extensions {
            if path.ends_with(ext) {
                return false;
            }
        }
    }
    true
}

fn is_disallowed_by_robots(url: &str, disallowed_paths: &HashSet<String>) -> bool {
    if disallowed_paths.is_empty() {
        return false;
    }
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        for disallowed in disallowed_paths {
            if path.starts_with(disallowed) {
                return true;
            }
        }
    }
    false
}

fn extract_base_href(html: &str) -> Option<String> {
    let re = regex::Regex::new(r#"<base[^>]+href\s*=\s*"([^"]+)""#).ok()?;
    re.captures(html).map(|cap| cap[1].to_string())
}

fn parse_css_urls(css: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let url_re = regex::Regex::new(r#"url\(\s*['"]?([^'")\s]+)['"]?\s*\)"#).unwrap();
    for cap in url_re.captures_iter(css) {
        let url = &cap[1];
        if !url.starts_with("data:") && !url.starts_with("#") && !url.starts_with("blob:") {
            if seen.insert(url.to_string()) {
                urls.push(url.to_string());
            }
        }
    }

    let import_re = regex::Regex::new(r##"@import\s+(?:url\(\s*['"]?|['"])([^'")\s;]+)(?:['"]?\s*\)|['"])"##).unwrap();
    for cap in import_re.captures_iter(css) {
        let url = &cap[1];
        if !url.starts_with("data:") && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    let font_face_re = regex::Regex::new(r#"@font-face\s*\{[^}]*\}"#).unwrap();
    for cap in font_face_re.captures_iter(css) {
        let font_block = &cap[0];
        let font_url_re = regex::Regex::new(r#"url\(\s*['"]?([^'")\s]+)['"]?\s*\)"#).unwrap();
        for font_cap in font_url_re.captures_iter(font_block) {
            let url = &font_cap[1];
            if !url.starts_with("data:") && !url.starts_with("#") && !url.starts_with("blob:") {
                if seen.insert(url.to_string()) {
                    urls.push(url.to_string());
                }
            }
        }
    }

    let image_set_re = regex::Regex::new(r#"image-set\(\s*([^)]+)\)"#).unwrap();
    for cap in image_set_re.captures_iter(css) {
        let image_set_content = &cap[1];
        for entry in image_set_content.split(',') {
            let parts: Vec<&str> = entry.trim().split_whitespace().collect();
            if let Some(url_part) = parts.first() {
                let clean_url = url_part.trim_matches('\'').trim_matches('"');
                if !clean_url.starts_with("data:") && !clean_url.starts_with("#") && !clean_url.starts_with("blob:") {
                    if seen.insert(clean_url.to_string()) {
                        urls.push(clean_url.to_string());
                    }
                }
            }
        }
    }

    let var_url_re = regex::Regex::new(r#"var\(\s*--[\w-]+\s*,\s*url\(\s*['"]?([^'")\s]+)['"]?\s*\)\s*\)"#).unwrap();
    for cap in var_url_re.captures_iter(css) {
        let url = &cap[1];
        if !url.starts_with("data:") && !url.starts_with("#") && !url.starts_with("blob:") {
            if seen.insert(url.to_string()) {
                urls.push(url.to_string());
            }
        }
    }

    urls
}

#[derive(Debug, Clone)]
struct ScoredUrl {
    url: String,
    score: f64,
    depth: usize,
}

impl PartialEq for ScoredUrl {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for ScoredUrl {}

impl PartialOrd for ScoredUrl {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredUrl {
    fn cmp(&self, other: &Self) -> Ordering {
        other.score.partial_cmp(&self.score).unwrap_or(Ordering::Equal)
    }
}

fn build_client(config: &WebCrawlerConfig, timeout_secs: u64) -> Result<reqwest::Client> {
    let ua = get_random_user_agent();
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(10))
        .danger_accept_invalid_certs(true)
        .user_agent(&ua);

    if !config.proxy_url.is_empty() {
        let proxy = reqwest::Proxy::all(&config.proxy_url)
            .map_err(|e| ToolError::ExecutionError(format!("Invalid proxy: {}", e)))?;
        builder = builder.proxy(proxy);
    }

    builder.build()
        .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))
}

fn build_download_client(proxy_url: &str) -> Result<reqwest::Client> {
    build_download_client_with_auth(proxy_url, "", "")
}

fn build_download_client_with_auth(proxy_url: &str, cookies: &str, custom_headers: &str) -> Result<reqwest::Client> {
    let ua = get_random_user_agent();
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::limited(10))
        .danger_accept_invalid_certs(true)
        .user_agent(&ua);

    if !proxy_url.is_empty() {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ToolError::ExecutionError(format!("Invalid proxy: {}", e)))?;
        builder = builder.proxy(proxy);
    }

    let mut default_headers = reqwest::header::HeaderMap::new();

    if !cookies.is_empty() {
        if let Ok(cookie_header) = reqwest::header::HeaderValue::from_str(cookies) {
            default_headers.insert(reqwest::header::COOKIE, cookie_header);
        }
    }

    if !custom_headers.is_empty() {
        for line in custom_headers.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if let (Ok(header_name), Ok(header_value)) = (
                    reqwest::header::HeaderName::from_bytes(key.as_bytes()),
                    reqwest::header::HeaderValue::from_str(value),
                ) {
                    default_headers.insert(header_name, header_value);
                }
            }
        }
    }

    if !default_headers.is_empty() {
        builder = builder.default_headers(default_headers);
    }

    builder.build()
        .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))
}

fn is_downloadable_url(url: &str) -> bool {
    if url.starts_with("data:") || url.starts_with("blob:") || url.starts_with("javascript:") {
        return false;
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return false;
    }
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            if host.is_empty() || host == "localhost" || host == "127.0.0.1" {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }
    let lower = url.to_lowercase();
    if lower.starts_with("mailto:") || lower.starts_with("tel:") {
        return false;
    }
    if lower.contains("javascript:") || lower.contains("void(0)") || lower.contains("about:blank") {
        return false;
    }
    true
}

fn sanitize_filename(name: &str) -> String {
    let sanitized: String = name.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() { "resource".to_string() } else { trimmed.to_string() }
}

fn score_url(url: &str, keywords: &[String]) -> f64 {
    let mut score: f64 = 0.5;
    let lower = url.to_lowercase();

    for kw in keywords {
        if lower.contains(&kw.to_lowercase()) {
            score += 0.2;
        }
    }

    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let depth = segments.len();
        if depth <= 2 {
            score += 0.2;
        } else if depth <= 4 {
            score += 0.15;
        } else if depth <= 6 {
            score += 0.05;
        } else {
            score -= 0.1;
        }

        let ext = path.rsplit('.').next().unwrap_or("");
        match ext {
            "html" | "htm" => score += 0.15,
            "php" | "asp" | "jsp" => score += 0.1,
            "pdf" | "doc" | "docx" => score += 0.1,
            _ => {}
        }

        if let Some(query) = parsed.query() {
            if query.contains("page=") || query.contains("p=") || query.contains("offset=") {
                score += 0.05;
            }
            let param_count = query.split('&').count();
            if param_count > 5 {
                score -= 0.05 * (param_count as f64 - 5.0).min(3.0);
            }
        }

        let low_value_segments: &[&str] = &["tag", "tags", "category", "categories", "archive", "author", "feed", "rss", "atom", "comment", "comments", "page"];
        for seg in &segments {
            if low_value_segments.contains(seg) {
                score -= 0.05;
            }
        }

        let high_value_segments: &[&str] = &["blog", "article", "news", "post", "docs", "documentation", "guide", "tutorial", "about", "product", "feature"];
        for seg in &segments {
            if high_value_segments.contains(seg) {
                score += 0.1;
            }
        }

        if path.ends_with('/') && depth <= 3 {
            score += 0.05;
        }

        let skip_extensions = ["jpg", "jpeg", "png", "gif", "svg", "webp", "ico", "bmp", "css", "js", "woff", "woff2", "ttf", "otf", "eot", "mp4", "mp3", "wav", "avi", "mov", "zip", "rar", "7z", "tar", "gz", "pdf"];
        if skip_extensions.contains(&ext) {
            score -= 0.3;
        }
    }

    if lower.contains("login") || lower.contains("signin") || lower.contains("signup") || lower.contains("register") || lower.contains("password") || lower.contains("auth") {
        score -= 0.2;
    }

    if lower.contains("search") || lower.contains("filter") || lower.contains("sort") {
        score += 0.05;
    }

    if score < 0.0 { score = 0.0; }
    if score > 1.0 { score = 1.0; }
    score
}

fn detect_paywall(html: &str, status_code: u16) -> PaywallDetection {
    let mut details = Vec::new();
    let mut paywall_type: Option<String> = None;
    let mut confidence = 0.0;
    let mut hidden_content_detected = false;
    let lower = html.to_lowercase();

    let hard_paywall_patterns: &[(&str, &str)] = &[
        (r#"class\s*=\s*"[^"]*(?:paywall|premium-wall|subscriber-wall|subscription-wall|paid-content|locked-content|gated-content)[^"]*""#, "Hard Paywall"),
        (r#"id\s*=\s*"[^"]*(?:paywall|premium-content|subscriber-content|paid-content|locked-content|gated-content)[^"]*""#, "Hard Paywall"),
        (r#"class\s*=\s*"[^"]*(?:subscribe|subscription|premium-required|login-required|register-to-read)[^"]*""#, "Subscription Required"),
        (r#"id\s*=\s*"[^"]*(?:subscribe|subscription|premium-required|login-required|register-to-read)[^"]*""#, "Subscription Required"),
    ];

    for (pattern, name) in hard_paywall_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(html) {
                details.push(format!("Detected: {}", name));
                if paywall_type.is_none() {
                    paywall_type = Some(name.to_string());
                }
                confidence += 0.5;
            }
        }
    }

    let soft_paywall_patterns: &[(&str, &str)] = &[
        (r#"class\s*=\s*"[^"]*(?:truncat|preview|excerpt|teaser|read-more|continue-reading|show-more|article-limit)[^"]*""#, "Soft Paywall"),
        (r#"style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|overflow\s*:\s*hidden|clip\s*:|height\s*:\s*0|opacity\s*:\s*0)[^"]*""#, "Hidden Content"),
        (r#"class\s*=\s*"[^"]*(?:blur|obfuscat|overlay|fade-out|masked|redact)[^"]*""#, "Content Obfuscation"),
        (r#"class\s*=\s*"[^"]*(?:metered|meter-wall|article-meter|free-article|free-preview)[^"]*""#, "Metered Paywall"),
    ];

    for (pattern, name) in soft_paywall_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(html) {
                details.push(format!("Detected: {}", name));
                if paywall_type.is_none() {
                    paywall_type = Some(name.to_string());
                }
                confidence += 0.4;
                if name == &"Hidden Content" {
                    hidden_content_detected = true;
                }
            }
        }
    }

    let text_indicators = [
        ("subscribe to continue", "Subscription Wall"),
        ("sign in to read", "Login Wall"),
        ("register to continue", "Registration Wall"),
        ("premium content", "Premium Content"),
        ("free articles remaining", "Metered Paywall"),
        ("articles left this month", "Metered Paywall"),
        ("free articles left", "Metered Paywall"),
        ("you've reached your limit", "Download/Read Limit"),
        ("download limit reached", "Download Limit"),
        ("download limit exceeded", "Download Limit"),
        ("maximum downloads", "Download Limit"),
        ("daily download limit", "Download Limit"),
        ("upgrade to download", "Premium Download"),
        ("premium to download", "Premium Download"),
        ("purchase to download", "Purchase Required"),
        ("buy credits to download", "Credit System"),
        ("insufficient credits", "Credit System"),
        ("members only", "Members Only"),
        ("paid members only", "Paid Members"),
        ("subscribe now to access", "Subscription Required"),
        ("unlock full access", "Premium Access"),
        ("continue reading for free", "Metered Paywall"),
        ("free trial expired", "Trial Expired"),
    ];

    for (indicator, name) in &text_indicators {
        if lower.contains(indicator) {
            details.push(format!("Text indicator: '{}' ({})", indicator, name));
            if paywall_type.is_none() {
                paywall_type = Some(name.to_string());
            }
            confidence += 0.3;
            if *name == "Download Limit" || *name == "Download/Read Limit" || *name == "Credit System" {
                confidence += 0.2;
            }
        }
    }

    let hidden_style_re = regex::Regex::new(r#"<[^>]+style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|overflow\s*:\s*hidden)[^"]*"[^>]*>"#).unwrap();
    let hidden_count = hidden_style_re.find_iter(html).count();
    if hidden_count > 3 {
        details.push(format!("{} elements with hidden style detected", hidden_count));
        confidence += 0.15;
        hidden_content_detected = true;
    }

    let overlay_re = regex::Regex::new(r#"<div[^>]+class\s*=\s*"[^"]*(?:overlay|modal|popup|interstitial)[^"]*"[^>]*>[\s\S]*?(?:subscribe|sign.up|register|premium|upgrade|unlock)[\s\S]*?</div>"#).unwrap();
    if overlay_re.is_match(&lower) {
        details.push("Subscription overlay/popup detected".to_string());
        confidence += 0.3;
        if paywall_type.is_none() {
            paywall_type = Some("Overlay Paywall".to_string());
        }
    }

    if status_code == 402 {
        details.push("HTTP 402 Payment Required".to_string());
        confidence += 0.6;
        if paywall_type.is_none() {
            paywall_type = Some("Payment Required".to_string());
        }
    }

    if confidence > 1.0 { confidence = 1.0; }

    PaywallDetection {
        detected: confidence >= 0.4,
        paywall_type,
        confidence,
        details,
        hidden_content_detected,
    }
}

fn get_resource_priority(resource_type: &str, priority_order: &str) -> usize {
    let priorities: Vec<&str> = priority_order.split(',').map(|s| s.trim()).collect();
    let type_lower = resource_type.to_lowercase();
    for (idx, priority) in priorities.iter().enumerate() {
        let p = priority.to_lowercase();
        if type_lower.contains(&p) || p.contains(&type_lower) {
            return idx;
        }
    }
    priorities.len()
}

fn sort_resources_by_priority(resources: &mut Vec<ResourceInfo>, priority_order: &str) {
    let order = priority_order.to_string();
    resources.sort_by(|a, b| {
        let pa = get_resource_priority(&a.resource_type, &order);
        let pb = get_resource_priority(&b.resource_type, &order);
        pa.cmp(&pb).then_with(|| {
            let sa = b.score.unwrap_or(0.5);
            let sb = a.score.unwrap_or(0.5);
            sa.partial_cmp(&sb).unwrap_or(Ordering::Equal)
        })
    });
}

fn collect_prioritized_urls(crawl_result: &WebCrawlerResult, config: &SiteDownloadConfig) -> Vec<String> {
    let mut all_resources: Vec<ResourceInfo> = Vec::new();

    if config.include_images {
        all_resources.extend(crawl_result.images.clone());
    }
    if config.include_videos {
        all_resources.extend(crawl_result.videos.clone());
    }
    if config.include_audio {
        all_resources.extend(crawl_result.audio_files.clone());
    }
    if config.include_css {
        all_resources.extend(crawl_result.css_files.clone());
    }
    if config.include_js {
        all_resources.extend(crawl_result.js_files.clone());
    }
    if config.include_fonts {
        all_resources.extend(crawl_result.fonts.clone());
    }
    if config.include_documents {
        all_resources.extend(crawl_result.documents.clone());
    }

    sort_resources_by_priority(&mut all_resources, &config.priority_order);

    let mut urls: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    if config.mirror_mode {
        for link in &crawl_result.links {
            if seen.insert(link.url.clone()) {
                urls.push(link.url.clone());
            }
        }
    }

    for resource in &all_resources {
        if is_downloadable_url(&resource.url) && seen.insert(resource.url.clone()) {
            urls.push(resource.url.clone());
        }
    }

    if config.max_download_count > 0 && urls.len() > config.max_download_count {
        urls.truncate(config.max_download_count);
    }

    urls
}

fn detect_antibot(html: &str, status_code: u16) -> AntibotDetection {
    let mut details = Vec::new();
    let mut protection_type: Option<String> = None;
    let mut confidence = 0.0;
    let lower = html.to_lowercase();

    if status_code == 403 || status_code == 503 {
        confidence += 0.3;
    }

    let tier1_patterns: &[(&str, &str)] = &[
        (r"Reference\s*#\s*[\d]+\.[0-9a-f]+\.\d+\.[0-9a-f]+", "Akamai"),
        (r"Pardon\s+Our\s+Interruption", "Akamai"),
        (r"challenge-form.*?__cf_chl_f_tk=", "Cloudflare"),
        (r#"cf-error-code">\d{4}</span>"#, "Cloudflare"),
        (r"/cdn-cgi/challenge-platform/", "Cloudflare"),
        (r"window\._pxAppId\s*=", "PerimeterX"),
        (r"captcha\.px-cdn\.net", "PerimeterX"),
        (r"captcha-delivery\.com", "DataDome"),
        (r"_Incapsula_Resource", "Imperva"),
        (r"Incapsula\s+incident\s+ID", "Imperva"),
        (r"Sucuri\s+WebSite\s+Firewall", "Sucuri"),
        (r"kasada\.js", "Kasada"),
        (r"ksd\.js", "Kasada"),
        (r"Fx\.shadow\.css", "Kasada"),
        (r"recaptcha/api\.js", "reCAPTCHA"),
        (r"hcaptcha\.com/1/api\.js", "hCaptcha"),
        (r"arkoselabs\.com", "FunCaptcha"),
        (r"geo\.captcha\.com", "Captcha.com"),
        (r"aws-waf-captcha", "AWS WAF"),
        (r"aws-waf-session", "AWS WAF"),
        (r"challenge\.cloudflare\.com", "Cloudflare Turnstile"),
        (r"turnstile\.cloudflare\.com", "Cloudflare Turnstile"),
        (r"shield\.squarespace\.com", "Squarespace Shield"),
    ];

    for (pattern, waf) in tier1_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(html) {
                details.push(format!("Detected {} protection", waf));
                if protection_type.is_none() {
                    protection_type = Some(waf.to_string());
                }
                confidence += 0.5;
            }
        }
    }

    if html.len() < 10240 {
        let tier2_patterns: &[(&str, &str)] = &[
            (r"Access\s+Denied", "Access Denied"),
            (r"Checking\s+your\s+browser", "Cloudflare Browser Check"),
            (r"Just\s+a\s+moment", "Cloudflare Challenge"),
            (r"Please\s+enable\s+JavaScript", "Bot Protection"),
            (r"are\s+you\s+a\s+robot", "Captcha"),
            (r"cf-browser-verification", "Cloudflare"),
            (r"verify\s+you\s+are\s+human", "Bot Verification"),
            (r"human\s+verification", "Bot Verification"),
            (r"bot\s+detection", "Bot Detection"),
            (r"rate\s+limit", "Rate Limiting"),
            (r"too\s+many\s+requests", "Rate Limiting"),
            (r"blocked\s+your\s+access", "Access Block"),
            (r"unusual\s+traffic", "Traffic Alert"),
            (r"security\s+check", "Security Check"),
            (r"ray\s*id", "Cloudflare Ray ID"),
        ];

        for (pattern, name) in tier2_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(&lower) {
                    details.push(format!("Detected: {}", name));
                    if protection_type.is_none() {
                        protection_type = Some(name.to_string());
                    }
                    confidence += 0.3;
                }
            }
        }
    }

    let empty_indicators = ["<body></body>", "<body> </body>"];
    for indicator in &empty_indicators {
        if lower.contains(indicator) {
            details.push("Empty body detected".to_string());
            confidence += 0.2;
            break;
        }
    }

    let has_scripts = lower.contains("<script");
    let has_links = lower.contains("<a ") || lower.contains("<a>");
    let has_content = lower.contains("<p>") || lower.contains("<div") || lower.contains("<h1") || lower.contains("<h2") || lower.contains("<span");
    let has_meta_refresh = lower.contains("http-equiv=\"refresh\"") || lower.contains("http-equiv='refresh'");

    if has_scripts && !has_links && !has_content {
        details.push("Shell page: has scripts but no visible content".to_string());
        confidence += 0.25;
        if protection_type.is_none() {
            protection_type = Some("SPA/JS-Rendered".to_string());
        }
    }

    if has_meta_refresh {
        if let Ok(re) = regex::Regex::new(r#"content\s*=\s*"[^"]*url=([^"]+)""#) {
            if let Some(cap) = re.captures(html) {
                let redirect_url = &cap[1];
                if redirect_url.contains("challenge") || redirect_url.contains("verify") || redirect_url.contains("captcha") {
                    details.push(format!("Meta-refresh redirect to challenge page: {}", redirect_url));
                    confidence += 0.3;
                }
            }
        }
    }

    if lower.contains("window.location") && html.len() < 5000 {
        let js_redirect_patterns = [
            r#"window\.location\s*=\s*["']([^"']+)["']"#,
            r#"window\.location\.href\s*=\s*["']([^"']+)["']"#,
            r#"window\.location\.replace\s*\(\s*["']([^"']+)["']"#,
        ];
        for pattern in &js_redirect_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(cap) = re.captures(html) {
                    let redirect_url = &cap[1];
                    if redirect_url.contains("challenge") || redirect_url.contains("verify") || redirect_url.contains("captcha") {
                        details.push(format!("JS redirect to challenge: {}", redirect_url));
                        confidence += 0.3;
                        break;
                    }
                }
            }
        }
    }

    let content_length = lower.len();
    if content_length < 500 && status_code == 200 {
        let has_only_js = lower.contains("<script") && !lower.contains("<body");
        if has_only_js {
            details.push("Minimal response with only JavaScript".to_string());
            confidence += 0.2;
        }
    }

    AntibotDetection {
        detected: confidence >= 0.4,
        protection_type,
        confidence: if confidence > 1.0 { 1.0 } else { confidence },
        details,
        waf_vendor: None,
        challenge_type: None,
        bypass_suggestions: Vec::new(),
    }
}

fn extract_security_info(url: &str, resp: &reqwest::Response) -> SecurityInfo {
    let headers = resp.headers();
    let has_https = url.starts_with("https://");
    let has_hsts = headers.contains_key("strict-transport-security");
    let has_csp = headers.contains_key("content-security-policy");
    let has_x_frame_options = headers.contains_key("x-frame-options");
    let has_x_content_type_options = headers.contains_key("x-content-type-options");
    let server_header = headers.get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let powered_by_header = headers.get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let csp_directives = headers.get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let has_strict_transport = has_hsts;
    let has_x_xss_protection = headers.contains_key("x-xss-protection");
    let has_referrer_policy = headers.contains_key("referrer-policy");
    let has_permissions_policy = headers.contains_key("permissions-policy");

    let mut score: u8 = 0;
    if has_https { score += 20; }
    if has_hsts { score += 15; }
    if has_csp { score += 15; }
    if has_x_frame_options { score += 10; }
    if has_x_content_type_options { score += 10; }
    if has_x_xss_protection { score += 5; }
    if has_referrer_policy { score += 5; }
    if has_permissions_policy { score += 5; }
    if server_header.is_none() { score += 5; }
    if powered_by_header.is_none() { score += 5; }
    if csp_directives.is_some() { score += 5; }

    SecurityInfo {
        has_https,
        has_hsts,
        has_csp,
        has_x_frame_options,
        has_x_content_type_options,
        server_header,
        powered_by_header,
        security_score: score,
        csp_directives,
        has_strict_transport,
        has_x_xss_protection,
        has_referrer_policy,
        has_permissions_policy,
    }
}

fn extract_subdomains(links: &[CrawledLink], base_domain: &str) -> Vec<String> {
    let mut subdomains: HashSet<String> = HashSet::new();
    for link in links {
        if let Ok(parsed) = url::Url::parse(&link.url) {
            if let Some(host) = parsed.host_str() {
                if host != base_domain && host.ends_with(&format!(".{}", base_domain)) {
                    subdomains.insert(host.to_string());
                }
            }
        }
    }
    let mut result: Vec<String> = subdomains.into_iter().collect();
    result.sort();
    result
}

struct RobotsRule {
    path: String,
    is_allow: bool,
}

struct ParsedRobots {
    rules: Vec<RobotsRule>,
    #[allow(dead_code)]
    crawl_delay: Option<u64>,
    #[allow(dead_code)]
    sitemaps: Vec<String>,
}

fn parse_robots_txt(text: &str, user_agent: &str) -> ParsedRobots {
    let mut rules: Vec<RobotsRule> = Vec::new();
    let mut crawl_delay: Option<u64> = None;
    let mut sitemaps: Vec<String> = Vec::new();
    let mut current_agent_relevant = false;
    let ua_lower = user_agent.to_lowercase();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() < 2 {
            continue;
        }
        let directive = parts[0].trim().to_lowercase();
        let value = parts[1].trim();

        match directive.as_str() {
            "user-agent" => {
                let agent = value.to_lowercase();
                current_agent_relevant = agent == "*" || ua_lower.contains(&agent) || agent.contains(&ua_lower);
            }
            "disallow" if current_agent_relevant => {
                if !value.is_empty() && value != "/" {
                    rules.push(RobotsRule { path: value.to_string(), is_allow: false });
                }
            }
            "allow" if current_agent_relevant => {
                if !value.is_empty() {
                    rules.push(RobotsRule { path: value.to_string(), is_allow: true });
                }
            }
            "crawl-delay" if current_agent_relevant => {
                if let Ok(delay) = value.parse::<u64>() {
                    crawl_delay = Some(delay);
                }
            }
            "sitemap" => {
                if !value.is_empty() {
                    sitemaps.push(value.to_string());
                }
            }
            _ => {}
        }
    }

    ParsedRobots { rules, crawl_delay, sitemaps }
}

#[allow(dead_code)]
fn is_disallowed_by_robots_v2(url: &str, parsed: &ParsedRobots) -> bool {
    if parsed.rules.is_empty() {
        return false;
    }
    if let Ok(parsed_url) = url::Url::parse(url) {
        let path = parsed_url.path();
        let mut best_match_len = 0;
        let mut best_match_is_allow = false;

        for rule in &parsed.rules {
            if path.starts_with(&rule.path) && rule.path.len() >= best_match_len {
                if rule.path.len() > best_match_len || rule.is_allow {
                    best_match_len = rule.path.len();
                    best_match_is_allow = rule.is_allow;
                }
            }
        }

        if best_match_len > 0 {
            return !best_match_is_allow;
        }
    }
    false
}

async fn fetch_robots_txt(base_url: &str, client: &reqwest::Client) -> HashSet<String> {
    let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
    let mut disallowed = HashSet::new();
    match client.get(&robots_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(text) = resp.text().await {
                let parsed = parse_robots_txt(&text, "BiosPhereCrawler");
                for rule in &parsed.rules {
                    if !rule.is_allow {
                        disallowed.insert(rule.path.clone());
                    }
                }
            }
        }
        _ => {}
    }
    disallowed
}

async fn fetch_sitemap_urls(base_url: &str, client: &reqwest::Client) -> Vec<String> {
    let mut urls = Vec::new();

    let sitemap_paths = [
        "sitemap.xml",
        "sitemap_index.xml",
        "sitemap-index.xml",
        "sitemap/sitemap.xml",
        "sitemaps/sitemap.xml",
    ];

    let base = base_url.trim_end_matches('/');

    for path in &sitemap_paths {
        let sitemap_url = format!("{}/{}", base, path);
        match client.get(&sitemap_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text().await {
                    let loc_re = regex::Regex::new(r"<loc>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</loc>").unwrap();
                    for cap in loc_re.captures_iter(&text) {
                        let url = cap[1].trim().to_string();
                        if url.starts_with("http://") || url.starts_with("https://") {
                            urls.push(url);
                        }
                    }
                    if !urls.is_empty() {
                        eprintln!("[WebCrawler] Found {} URLs in sitemap: {}", urls.len(), sitemap_url);
                        break;
                    }
                }
            }
            _ => continue,
        }
    }

    if urls.is_empty() {
        let robots_url = format!("{}/robots.txt", base);
        if let Ok(resp) = client.get(&robots_url).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with("Sitemap:") {
                            let sitemap_url = line["Sitemap:".len()..].trim().to_string();
                            if !sitemap_url.is_empty() {
                                eprintln!("[WebCrawler] Found sitemap in robots.txt: {}", sitemap_url);
                                if let Ok(resp) = client.get(&sitemap_url).send().await {
                                    if resp.status().is_success() {
                                        if let Ok(text) = resp.text().await {
                                            let loc_re = regex::Regex::new(r"<loc>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</loc>").unwrap();
                                            for cap in loc_re.captures_iter(&text) {
                                                let url = cap[1].trim().to_string();
                                                if url.starts_with("http://") || url.starts_with("https://") {
                                                    urls.push(url);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    urls
}

fn extract_inline_style_urls(html: &str, base_url: &str) -> Vec<ResourceInfo> {
    let mut resources = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let style_attr_re = regex::Regex::new(r#"style\s*=\s*"([^"]+)""#).unwrap();
    for cap in style_attr_re.captures_iter(html) {
        let style_content = &cap[1];
        let url_re = regex::Regex::new(r#"url\(\s*['"]?([^'")\s]+)['"]?\s*\)"#).unwrap();
        for url_cap in url_re.captures_iter(style_content) {
            let url_str = &url_cap[1];
            if !url_str.starts_with("data:") && !url_str.starts_with("#") && !url_str.starts_with("blob:") {
                let full_url = WebCrawlerTool::resolve_url(base_url, url_str);
                if seen.insert(full_url.clone()) {
                    let lower = full_url.to_lowercase();
                    let resource_type = if lower.contains(".woff") || lower.contains(".ttf") || lower.contains(".otf") || lower.contains(".eot") {
                        "inline-style-font"
                    } else if lower.contains(".png") || lower.contains(".jpg") || lower.contains(".jpeg") || lower.contains(".gif") || lower.contains(".svg") || lower.contains(".webp") || lower.contains(".ico") {
                        "inline-style-image"
                    } else {
                        "inline-style-ref"
                    };
                    resources.push(ResourceInfo {
                        url: full_url,
                        resource_type: resource_type.to_string(),
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }
    }

    resources
}

fn extract_iframe_urls(html: &str, base_url: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let iframe_re = regex::Regex::new(r#"<iframe[^>]+src\s*=\s*"([^"]+)""#).unwrap();
    for cap in iframe_re.captures_iter(html) {
        let src = &cap[1];
        if !src.starts_with("javascript:") && !src.starts_with("data:") && !src.starts_with("about:") {
            let full_url = WebCrawlerTool::resolve_url(base_url, src);
            if (full_url.starts_with("http://") || full_url.starts_with("https://")) && seen.insert(full_url.clone()) {
                urls.push(full_url);
            }
        }
    }

    let frame_re = regex::Regex::new(r#"<frame[^>]+src\s*=\s*"([^"]+)""#).unwrap();
    for cap in frame_re.captures_iter(html) {
        let src = &cap[1];
        if !src.starts_with("javascript:") && !src.starts_with("data:") {
            let full_url = WebCrawlerTool::resolve_url(base_url, src);
            if (full_url.starts_with("http://") || full_url.starts_with("https://")) && seen.insert(full_url.clone()) {
                urls.push(full_url);
            }
        }
    }

    let object_re = regex::Regex::new(r#"<object[^>]+data\s*=\s*"([^"]+)""#).unwrap();
    for cap in object_re.captures_iter(html) {
        let data = &cap[1];
        if !data.starts_with("javascript:") && !data.starts_with("data:") {
            let full_url = WebCrawlerTool::resolve_url(base_url, data);
            if (full_url.starts_with("http://") || full_url.starts_with("https://")) && seen.insert(full_url.clone()) {
                urls.push(full_url);
            }
        }
    }

    let embed_re = regex::Regex::new(r#"<embed[^>]+src\s*=\s*"([^"]+)""#).unwrap();
    for cap in embed_re.captures_iter(html) {
        let src = &cap[1];
        if !src.starts_with("javascript:") && !src.starts_with("data:") {
            let full_url = WebCrawlerTool::resolve_url(base_url, src);
            if (full_url.starts_with("http://") || full_url.starts_with("https://")) && seen.insert(full_url.clone()) {
                urls.push(full_url);
            }
        }
    }

    let data_src_re = regex::Regex::new(r#"<iframe[^>]+data-src\s*=\s*"([^"]+)""#).unwrap();
    for cap in data_src_re.captures_iter(html) {
        let src = &cap[1];
        if !src.starts_with("javascript:") && !src.starts_with("data:") && !src.starts_with("about:") {
            let full_url = WebCrawlerTool::resolve_url(base_url, src);
            if (full_url.starts_with("http://") || full_url.starts_with("https://")) && seen.insert(full_url.clone()) {
                urls.push(full_url);
            }
        }
    }

    urls
}

pub struct WebCrawlerTool;

impl WebCrawlerTool {
    pub async fn crawl(config: &WebCrawlerConfig) -> Result<WebCrawlerResult> {
        let url = config.url.trim().to_string();
        let start_url = if url.starts_with("http://") || url.starts_with("https://") {
            url
        } else {
            format!("https://{}", url)
        };

        let base_domain = Self::extract_domain(&start_url)
            .ok_or_else(|| ToolError::ExecutionError("Invalid URL".to_string()))?;

        let client = build_client(config, config.timeout)?;

        let mut visited: HashSet<String> = HashSet::new();
        let mut links: Vec<CrawledLink> = Vec::new();
        let mut emails: HashSet<String> = HashSet::new();
        let mut js_files: HashMap<String, ResourceInfo> = HashMap::new();
        let mut comments: HashSet<String> = HashSet::new();
        let mut images: HashMap<String, ResourceInfo> = HashMap::new();
        let mut css_files: HashMap<String, ResourceInfo> = HashMap::new();
        let mut fonts: HashMap<String, ResourceInfo> = HashMap::new();
        let mut documents: HashMap<String, ResourceInfo> = HashMap::new();
        let mut videos: HashMap<String, ResourceInfo> = HashMap::new();
        let mut audio_files: HashMap<String, ResourceInfo> = HashMap::new();
        let mut api_endpoints: HashMap<String, ApiEndpoint> = HashMap::new();
        let mut technologies: HashSet<String> = HashSet::new();
        let mut technology_details: HashMap<String, TechnologyDetail> = HashMap::new();
        let mut page_metadata: Option<PageMetadata> = None;
        let mut antibot_detection: Option<AntibotDetection> = None;
        let mut paywall_detection: Option<PaywallDetection> = None;
        let mut popup_detection: Option<PopupDetection> = None;
        let mut markdown_content: Option<String> = None;
        let mut security_info: Option<SecurityInfo> = None;

        let keywords: Arc<Vec<String>> = Arc::new(if config.keywords.is_empty() {
            vec![]
        } else {
            config.keywords.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        });

        let disallowed_paths: Arc<HashSet<String>> = Arc::new(if config.respect_robots {
            fetch_robots_txt(&start_url, &client).await
        } else {
            HashSet::new()
        });

        let sitemap_urls: Vec<String> = fetch_sitemap_urls(&start_url, &client).await;
        if !sitemap_urls.is_empty() {
            eprintln!("[WebCrawler] Sitemap provided {} seed URLs", sitemap_urls.len());
        }

        let normalize = config.normalize_urls;
        let concurrency = config.concurrent_requests.max(1).min(30);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let request_delay = config.request_delay_ms;
        let max_depth = config.max_depth;
        let max_pages = config.max_pages;

        match config.crawl_strategy.as_str() {
            "dfs" => {
                let mut stack: Vec<(String, usize)> = vec![(start_url.clone(), 0)];
                for sitemap_url in &sitemap_urls {
                    let link_domain = Self::extract_domain(sitemap_url);
                    if config.follow_external || link_domain.as_deref() == Some(&base_domain) {
                        if is_crawlable_url(sitemap_url) && !is_disallowed_by_robots(sitemap_url, &disallowed_paths) {
                            stack.push((sitemap_url.clone(), 1));
                        }
                    }
                }
                eprintln!("[WebCrawler] Starting DFS crawl from: {} ({} sitemap seeds)", start_url, sitemap_urls.len());
                while !stack.is_empty() && links.len() < max_pages {
                    let (current_url, current_depth) = stack.pop().unwrap();
                    if current_depth > max_depth { continue; }

                    let norm_url = if normalize { normalize_url(&current_url) } else { current_url.clone() };
                    if visited.contains(&norm_url) { continue; }
                    visited.insert(norm_url);

                    if request_delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(request_delay)).await;
                    }

                    if let Some(result) = Self::crawl_page(&client, &current_url, current_depth, &base_domain, config, &keywords, &semaphore).await {
                        let (link, new_links, found_emails, found_js, found_comments, found_images, found_css, found_fonts, found_docs, found_videos, found_audio, found_apis, found_tech, found_tech_details, metadata, antibot, paywall, popup, markdown, sec_info) = result;
                        links.push(link);
                        for email in found_emails { emails.insert(email); }
                        for js in found_js { if Self::is_valid_resource_url(&js.url) { js_files.entry(js.url.clone()).or_insert(js); } }
                        for comment in found_comments { comments.insert(comment); }
                        for img in found_images { if Self::is_valid_resource_url(&img.url) { images.entry(img.url.clone()).or_insert(img); } }
                        for css in found_css { if Self::is_valid_resource_url(&css.url) { css_files.entry(css.url.clone()).or_insert(css); } }
                        for font in found_fonts { if Self::is_valid_resource_url(&font.url) { fonts.entry(font.url.clone()).or_insert(font); } }
                        for doc in found_docs { if Self::is_valid_resource_url(&doc.url) { documents.entry(doc.url.clone()).or_insert(doc); } }
                        for video in found_videos { if Self::is_valid_resource_url(&video.url) { videos.entry(video.url.clone()).or_insert(video); } }
                        for audio in found_audio { if Self::is_valid_resource_url(&audio.url) { audio_files.entry(audio.url.clone()).or_insert(audio); } }
                        for api in found_apis { api_endpoints.entry(api.url.clone()).or_insert(api); }
                        for tech in found_tech { technologies.insert(tech); }
                        for td in found_tech_details { technology_details.entry(td.name.clone()).or_insert(td); }
                        if let Some(meta) = metadata { if page_metadata.is_none() { page_metadata = Some(meta); } }
                        if let Some(ab) = antibot { if ab.detected && antibot_detection.is_none() { antibot_detection = Some(ab); } }
                        if let Some(pw) = paywall { if pw.detected && paywall_detection.is_none() { paywall_detection = Some(pw); } }
                        if let Some(pp) = popup { if pp.detected && popup_detection.is_none() { popup_detection = Some(pp); } }
                        if let Some(md) = markdown { if markdown_content.is_none() { markdown_content = Some(md); } }
                        if let Some(si) = sec_info { if security_info.is_none() { security_info = Some(si); } }

                        for link in new_links {
                            let norm_link = if normalize { normalize_url(&link) } else { link.clone() };
                            if !visited.contains(&norm_link) {
                                let link_domain = Self::extract_domain(&link);
                                if config.follow_external || link_domain.as_ref() == Some(&base_domain) {
                                    if is_crawlable_url(&link) && !is_disallowed_by_robots(&link, &disallowed_paths) {
                                        stack.push((link, current_depth + 1));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "best_first" => {
                let mut heap: BinaryHeap<ScoredUrl> = BinaryHeap::new();
                heap.push(ScoredUrl { url: start_url.clone(), score: 1.0, depth: 0 });
                for sitemap_url in &sitemap_urls {
                    let link_domain = Self::extract_domain(sitemap_url);
                    if config.follow_external || link_domain.as_deref() == Some(&base_domain) {
                        if is_crawlable_url(sitemap_url) && !is_disallowed_by_robots(sitemap_url, &disallowed_paths) {
                            let link_score = score_url(sitemap_url, &keywords);
                            heap.push(ScoredUrl { url: sitemap_url.clone(), score: link_score * 0.8, depth: 1 });
                        }
                    }
                }
                eprintln!("[WebCrawler] Starting Best-First crawl from: {} ({} sitemap seeds)", start_url, sitemap_urls.len());

                while !heap.is_empty() && links.len() < max_pages {
                    let ScoredUrl { url: current_url, depth: current_depth, .. } = heap.pop().unwrap();
                    if current_depth > max_depth { continue; }

                    let norm_url = if normalize { normalize_url(&current_url) } else { current_url.clone() };
                    if visited.contains(&norm_url) { continue; }
                    visited.insert(norm_url);

                    if request_delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(request_delay)).await;
                    }

                    if let Some(result) = Self::crawl_page(&client, &current_url, current_depth, &base_domain, config, &keywords, &semaphore).await {
                        let (link, new_links, found_emails, found_js, found_comments, found_images, found_css, found_fonts, found_docs, found_videos, found_audio, found_apis, found_tech, found_tech_details, metadata, antibot, paywall, popup, markdown, sec_info) = result;
                        links.push(link);
                        for email in found_emails { emails.insert(email); }
                        for js in found_js { if Self::is_valid_resource_url(&js.url) { js_files.entry(js.url.clone()).or_insert(js); } }
                        for comment in found_comments { comments.insert(comment); }
                        for img in found_images { if Self::is_valid_resource_url(&img.url) { images.entry(img.url.clone()).or_insert(img); } }
                        for css in found_css { if Self::is_valid_resource_url(&css.url) { css_files.entry(css.url.clone()).or_insert(css); } }
                        for font in found_fonts { if Self::is_valid_resource_url(&font.url) { fonts.entry(font.url.clone()).or_insert(font); } }
                        for doc in found_docs { if Self::is_valid_resource_url(&doc.url) { documents.entry(doc.url.clone()).or_insert(doc); } }
                        for video in found_videos { if Self::is_valid_resource_url(&video.url) { videos.entry(video.url.clone()).or_insert(video); } }
                        for audio in found_audio { if Self::is_valid_resource_url(&audio.url) { audio_files.entry(audio.url.clone()).or_insert(audio); } }
                        for api in found_apis { api_endpoints.entry(api.url.clone()).or_insert(api); }
                        for tech in found_tech { technologies.insert(tech); }
                        for td in found_tech_details { technology_details.entry(td.name.clone()).or_insert(td); }
                        if let Some(meta) = metadata { if page_metadata.is_none() { page_metadata = Some(meta); } }
                        if let Some(ab) = antibot { if ab.detected && antibot_detection.is_none() { antibot_detection = Some(ab); } }
                        if let Some(pw) = paywall { if pw.detected && paywall_detection.is_none() { paywall_detection = Some(pw); } }
                        if let Some(pp) = popup { if pp.detected && popup_detection.is_none() { popup_detection = Some(pp); } }
                        if let Some(md) = markdown { if markdown_content.is_none() { markdown_content = Some(md); } }
                        if let Some(si) = sec_info { if security_info.is_none() { security_info = Some(si); } }

                        for link in new_links {
                            let norm_link = if normalize { normalize_url(&link) } else { link.clone() };
                            if !visited.contains(&norm_link) {
                                let link_domain = Self::extract_domain(&link);
                                if config.follow_external || link_domain.as_ref() == Some(&base_domain) {
                                    if is_crawlable_url(&link) && !is_disallowed_by_robots(&link, &disallowed_paths) {
                                        let link_score = score_url(&link, &keywords);
                                        heap.push(ScoredUrl { url: link, score: link_score, depth: current_depth + 1 });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                let mut queue: VecDeque<(String, usize)> = VecDeque::new();
                queue.push_back((start_url.clone(), 0));
                for sitemap_url in &sitemap_urls {
                    let link_domain = Self::extract_domain(sitemap_url);
                    if config.follow_external || link_domain.as_deref() == Some(&base_domain) {
                        if is_crawlable_url(sitemap_url) && !is_disallowed_by_robots(sitemap_url, &disallowed_paths) {
                            queue.push_back((sitemap_url.clone(), 1));
                        }
                    }
                }
                eprintln!("[WebCrawler] Starting BFS crawl from: {} ({} sitemap seeds)", start_url, sitemap_urls.len());

                while !queue.is_empty() && links.len() < max_pages {
                    let current_depth = queue.front().map(|(_, d)| *d).unwrap_or(0);
                    if current_depth > max_depth {
                        break;
                    }

                    let mut batch = Vec::new();
                    while let Some((url, depth)) = queue.pop_front() {
                        if depth != current_depth {
                            queue.push_front((url, depth));
                            break;
                        }
                        let norm_url = if normalize { normalize_url(&url) } else { url.clone() };
                        if visited.contains(&norm_url) {
                            continue;
                        }
                        if links.len() + batch.len() >= max_pages {
                            queue.push_front((url, depth));
                            break;
                        }
                        visited.insert(norm_url);
                        batch.push(url);
                    }

                    if request_delay > 0 && !batch.is_empty() {
                        tokio::time::sleep(std::time::Duration::from_millis(request_delay)).await;
                    }

                    let mut join_set = tokio::task::JoinSet::new();
                    for current_url in batch {
                        let client = client.clone();
                        let semaphore = semaphore.clone();
                        let cfg = config.clone();
                        let base_domain_clone = base_domain.clone();
                        let keywords_clone = keywords.clone();

                        join_set.spawn(async move {
                            let _permit = semaphore.acquire().await.unwrap();
                            Self::crawl_page(&client, &current_url, current_depth, &base_domain_clone, &cfg, &keywords_clone, &semaphore).await
                        });
                    }

                    while let Some(result) = join_set.join_next().await {
                        if let Ok(Some((link, new_links, found_emails, found_js, found_comments, found_images, found_css, found_fonts, found_docs, found_videos, found_audio, found_apis, found_tech, found_tech_details, metadata, antibot, paywall, popup, markdown, sec_info))) = result {
                            let current_depth = link.depth;
                            links.push(link);
                            for email in found_emails { emails.insert(email); }
                            for js in found_js { if Self::is_valid_resource_url(&js.url) { js_files.entry(js.url.clone()).or_insert(js); } }
                            for comment in found_comments { comments.insert(comment); }
                            for img in found_images { if Self::is_valid_resource_url(&img.url) { images.entry(img.url.clone()).or_insert(img); } }
                            for css in found_css { if Self::is_valid_resource_url(&css.url) { css_files.entry(css.url.clone()).or_insert(css); } }
                            for font in found_fonts { if Self::is_valid_resource_url(&font.url) { fonts.entry(font.url.clone()).or_insert(font); } }
                            for doc in found_docs { if Self::is_valid_resource_url(&doc.url) { documents.entry(doc.url.clone()).or_insert(doc); } }
                            for video in found_videos { if Self::is_valid_resource_url(&video.url) { videos.entry(video.url.clone()).or_insert(video); } }
                            for audio in found_audio { if Self::is_valid_resource_url(&audio.url) { audio_files.entry(audio.url.clone()).or_insert(audio); } }
                            for api in found_apis { api_endpoints.entry(api.url.clone()).or_insert(api); }
                            for tech in found_tech { technologies.insert(tech); }
                            for td in found_tech_details { technology_details.entry(td.name.clone()).or_insert(td); }
                            if let Some(meta) = metadata { if page_metadata.is_none() { page_metadata = Some(meta); } }
                            if let Some(ab) = antibot { if ab.detected && antibot_detection.is_none() { antibot_detection = Some(ab); } }
                            if let Some(pw) = paywall { if pw.detected && paywall_detection.is_none() { paywall_detection = Some(pw); } }
                            if let Some(pp) = popup { if pp.detected && popup_detection.is_none() { popup_detection = Some(pp); } }
                            if let Some(md) = markdown { if markdown_content.is_none() { markdown_content = Some(md); } }
                            if let Some(si) = sec_info { if security_info.is_none() { security_info = Some(si); } }

                            for link in new_links {
                                let norm_link = if normalize { normalize_url(&link) } else { link.clone() };
                                if !visited.contains(&norm_link) {
                                    let link_domain = Self::extract_domain(&link);
                                    if config.follow_external || link_domain.as_ref() == Some(&base_domain) {
                                        if is_crawlable_url(&link) && !is_disallowed_by_robots(&link, &disallowed_paths) {
                                            queue.push_back((link, current_depth + 1));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if config.parse_css_resources {
            let css_urls: Vec<String> = css_files.keys().cloned().collect();
            for css_url in css_urls {
                match client.get(&css_url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(css_content) = resp.text().await {
                            let css_resource_urls = parse_css_urls(&css_content);
                            for res_url in css_resource_urls {
                                let full_url = Self::resolve_url(&css_url, &res_url);
                                if Self::is_valid_resource_url(&full_url) {
                                    let lower = full_url.to_lowercase();
                                    let url_path = lower.split('?').next().unwrap_or("");
                                    if url_path.ends_with(".woff") || url_path.ends_with(".woff2") || url_path.ends_with(".ttf") || url_path.ends_with(".otf") || url_path.ends_with(".eot") {
                                        fonts.entry(full_url.clone()).or_insert(ResourceInfo {
                                            url: full_url,
                                            resource_type: "css-font".to_string(),
                                            size: None,
                                            source_page: Some(css_url.clone()),
                                            score: None,
                                        });
                                    } else if url_path.ends_with(".png") || url_path.ends_with(".jpg") || url_path.ends_with(".jpeg") || url_path.ends_with(".gif") || url_path.ends_with(".svg") || url_path.ends_with(".webp") || url_path.ends_with(".ico") {
                                        images.entry(full_url.clone()).or_insert(ResourceInfo {
                                            url: full_url,
                                            resource_type: "css-image".to_string(),
                                            size: None,
                                            source_page: Some(css_url.clone()),
                                            score: None,
                                        });
                                    } else if url_path.ends_with(".css") {
                                        css_files.entry(full_url.clone()).or_insert(ResourceInfo {
                                            url: full_url,
                                            resource_type: "css-import".to_string(),
                                            size: None,
                                            source_page: Some(css_url.clone()),
                                            score: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let directory_entries = if config.scan_directories {
            Self::scan_directories(&start_url, &client, config.timeout).await
        } else {
            vec![]
        };

        let pages_crawled = links.len();
        let total_links = links.len();
        let summary = format!(
            "爬取完成 | 页面: {} | 链接: {} | 邮箱: {} | JS: {} | 图片: {} | CSS: {} | 视频: {} | 音频: {} | 文档: {} | API: {} | 目录: {} | 技术: {}",
            pages_crawled,
            total_links,
            emails.len(),
            js_files.len(),
            images.len(),
            css_files.len(),
            videos.len(),
            audio_files.len(),
            documents.len(),
            api_endpoints.len(),
            directory_entries.len(),
            technologies.len(),
        );

        let subdomains = extract_subdomains(&links, &base_domain);

        Ok(WebCrawlerResult {
            start_url,
            pages_crawled,
            total_links,
            links,
            emails: emails.into_iter().collect(),
            js_files: js_files.into_values().collect(),
            comments: comments.into_iter().collect(),
            images: images.into_values().collect(),
            css_files: css_files.into_values().collect(),
            fonts: fonts.into_values().collect(),
            documents: documents.into_values().collect(),
            videos: videos.into_values().collect(),
            audio_files: audio_files.into_values().collect(),
            api_endpoints: api_endpoints.into_values().collect(),
            metadata: page_metadata.unwrap_or_default(),
            technologies: technologies.into_iter().collect(),
            technology_details: technology_details.into_values().collect(),
            directory_entries,
            summary,
            antibot_detection,
            subdomains,
            security_info: security_info.unwrap_or_default(),
            paywall_detection,
            ssl_cert_info: None,
            popup_detection,
            markdown_content,
        })
    }

    async fn crawl_page(
        client: &reqwest::Client,
        current_url: &str,
        current_depth: usize,
        base_domain: &str,
        config: &WebCrawlerConfig,
        keywords: &Arc<Vec<String>>,
        _semaphore: &Arc<Semaphore>,
    ) -> Option<(
        CrawledLink,
        Vec<String>,
        Vec<String>,
        Vec<ResourceInfo>,
        Vec<String>,
        Vec<ResourceInfo>,
        Vec<ResourceInfo>,
        Vec<ResourceInfo>,
        Vec<ResourceInfo>,
        Vec<ResourceInfo>,
        Vec<ResourceInfo>,
        Vec<ApiEndpoint>,
        Vec<String>,
        Vec<TechnologyDetail>,
        Option<PageMetadata>,
        Option<AntibotDetection>,
        Option<PaywallDetection>,
        Option<PopupDetection>,
        Option<String>,
        Option<SecurityInfo>,
    )> {
        let start_time = std::time::Instant::now();
        eprintln!("[WebCrawler] Crawling page: {} (depth: {})", current_url, current_depth);

        match client.get(current_url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8")
            .header("Cache-Control", "no-cache")
            .send().await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let sec_info = if current_depth == 0 {
                    Some(extract_security_info(current_url, &resp))
                } else {
                    None
                };

                let is_html = content_type.as_ref().map(|ct| ct.contains("text/html")).unwrap_or_else(|| {
                    let lower_url = current_url.to_lowercase();
                    lower_url.ends_with("/") || lower_url.ends_with(".html") || lower_url.ends_with(".htm") || lower_url.ends_with(".php") || lower_url.ends_with(".asp") || lower_url.ends_with(".jsp") || (!lower_url.contains("."))
                });

                let bytes = resp.bytes().await.unwrap_or_default();
                let elapsed = start_time.elapsed().as_millis() as u64;
                let body = Self::decode_bytes(&bytes, content_type.as_deref());

                let is_html = if !is_html && body.len() > 50 {
                    let lower_body = body.to_lowercase();
                    lower_body.contains("<html") || lower_body.contains("<!doctype html") || lower_body.contains("<head") || lower_body.contains("<body")
                } else {
                    is_html
                };

                eprintln!("[WebCrawler] Page {} status={} content_type={:?} is_html={} body_len={}", current_url, status, content_type, is_html, body.len());

                if !is_html {
                    return Some((
                        CrawledLink {
                            url: current_url.to_string(),
                            status_code: status,
                            title: None,
                            depth: current_depth,
                            content_type,
                            response_time_ms: Some(elapsed),
                            word_count: None,
                            score: Some(score_url(current_url, keywords)),
                        },
                        vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![], vec![],
                        None, None, None, None, None, sec_info,
                    ));
                }

                let effective_base = extract_base_href(&body)
                    .unwrap_or_else(|| current_url.to_string());

                let title = Self::extract_title(&body);
                let word_count = Some(Self::count_words(&body));
                let new_links = Self::extract_links(&body, &effective_base);
                let new_links_count = new_links.len();

                let found_emails = if config.extract_emails { Self::extract_emails_from_html(&body) } else { vec![] };
                let found_js = if config.extract_js { Self::extract_js_files(&body, &effective_base) } else { vec![] };
                let found_comments = if config.extract_comments { Self::extract_html_comments(&body) } else { vec![] };
                let found_images = if config.extract_images { 
                    let mut imgs = Self::extract_images(&body, &effective_base);
                    let inline_res = extract_inline_style_urls(&body, &effective_base);
                    imgs.extend(inline_res.into_iter().filter(|r| r.resource_type.contains("image")));
                    imgs
                } else { vec![] };
                let found_css = if config.extract_css { Self::extract_css_files(&body, &effective_base) } else { vec![] };
                let found_fonts = if config.extract_fonts { 
                    let mut fts = Self::extract_font_files(&body, &effective_base);
                    let inline_res = extract_inline_style_urls(&body, &effective_base);
                    fts.extend(inline_res.into_iter().filter(|r| r.resource_type.contains("font")));
                    fts
                } else { vec![] };
                let found_docs = if config.extract_documents { Self::extract_document_links(&body, &effective_base) } else { vec![] };
                let found_videos = if config.extract_videos { Self::extract_video_sources(&body, &effective_base) } else { vec![] };
                let found_audio = if config.extract_audio { Self::extract_audio_sources(&body, &effective_base) } else { vec![] };
                let found_apis = if config.extract_api_endpoints { Self::extract_api_endpoints(&body, &effective_base) } else { vec![] };
                let found_tech = Self::detect_technologies(&body);
                let found_tech_details = Self::detect_technologies_detailed(&body);
                let metadata = if config.extract_metadata && current_depth == 0 { Some(Self::extract_metadata(&body, &effective_base)) } else { None };
                let link_score = score_url(current_url, keywords);
                let antibot = if config.detect_antibot { Some(detect_antibot(&body, status)) } else { None };
                let paywall = if current_depth == 0 { Some(detect_paywall(&body, status)) } else { None };
                let popup = if current_depth == 0 { Some(detect_popup_overlay(&body)) } else { None };
                let markdown = if current_depth == 0 { Some(html_to_markdown(&body)) } else { None };

                let _inline_style_resources = extract_inline_style_urls(&body, &effective_base);
                let iframe_urls = if config.crawl_iframes { extract_iframe_urls(&body, &effective_base) } else { vec![] };

                let url_filter_patterns = &config.url_filter_patterns;
                let url_exclude_patterns = &config.url_exclude_patterns;

                let filtered_links: Vec<String> = new_links.into_iter()
                    .chain(iframe_urls.into_iter())
                    .filter(|link| {
                        let link_domain = Self::extract_domain(link);
                        if config.follow_external { true } else { link_domain.as_deref() == Some(base_domain) }
                    })
                    .filter(|link| is_crawlable_url(link))
                    .filter(|link| apply_url_filters(link, url_filter_patterns, url_exclude_patterns))
                    .collect();

                eprintln!("[WebCrawler] Page {} extracted: {} links, {} emails, {} js, {} images, {} css, {} fonts, {} docs, {} videos, {} audio, {} apis, {} crawlable_links", 
                    current_url, new_links_count, found_emails.len(), found_js.len(), found_images.len(), found_css.len(), found_fonts.len(), found_docs.len(), found_videos.len(), found_audio.len(), found_apis.len(), filtered_links.len());

                Some((
                    CrawledLink {
                        url: current_url.to_string(),
                        status_code: status,
                        title,
                        depth: current_depth,
                        content_type,
                        response_time_ms: Some(elapsed),
                        word_count,
                        score: Some(link_score),
                    },
                    filtered_links,
                    found_emails,
                    found_js,
                    found_comments,
                    found_images,
                    found_css,
                    found_fonts,
                    found_docs,
                    found_videos,
                    found_audio,
                    found_apis,
                    found_tech,
                    found_tech_details,
                    metadata,
                    antibot,
                    paywall,
                    popup,
                    markdown,
                    sec_info,
                ))
            }
            Err(e) => {
                eprintln!("[WebCrawler] Request failed for {}: {}", current_url, e);
                None
            }
        }
    }

    pub async fn download_resource(url: &str, save_dir: &str) -> Result<DownloadResult> {
        Self::download_resource_with_retry(url, save_dir, 3, 1000).await
    }

    const MAX_DOWNLOAD_SIZE: u64 = 100 * 1024 * 1024;

    pub async fn download_resource_with_retry(url: &str, save_dir: &str, max_retries: usize, retry_delay_ms: u64) -> Result<DownloadResult> {
        if !is_downloadable_url(url) {
            return Ok(DownloadResult {
                url: url.to_string(),
                file_path: String::new(),
                file_size: 0,
                success: false,
                error: Some(format!("Non-downloadable URL: {}", url)),
            });
        }

        let client = build_download_client("")?;
        let referer = Self::extract_referer(url);

        if let Ok(head_resp) = client.head(url)
            .header("Referer", &referer)
            .header("Accept", "*/*")
            .send().await
        {
            if let Some(content_length) = head_resp.headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                if content_length > Self::MAX_DOWNLOAD_SIZE {
                    return Ok(DownloadResult {
                        url: url.to_string(),
                        file_path: String::new(),
                        file_size: content_length,
                        success: false,
                        error: Some(format!("File too large: {} bytes (max {} bytes)", content_length, Self::MAX_DOWNLOAD_SIZE)),
                    });
                }
            }
        }

        let mut last_error = String::new();
        for attempt in 0..=max_retries {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms * attempt as u64)).await;
            }

            let mut req = client.get(url)
                .header("Referer", &referer)
                .header("Accept", "*/*")
                .header("Accept-Language", "en-US,en;q=0.9");

            if attempt > 0 {
                req = req.header("Range", "bytes=0-");
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 403 || status.as_u16() == 401 {
                        last_error = format!("HTTP {} - Access denied", status);
                        if attempt == max_retries {
                            return Ok(DownloadResult {
                                url: url.to_string(),
                                file_path: String::new(),
                                file_size: 0,
                                success: false,
                                error: Some(last_error),
                            });
                        }
                        continue;
                    }
                    if status.as_u16() == 404 {
                        return Ok(DownloadResult {
                            url: url.to_string(),
                            file_path: String::new(),
                            file_size: 0,
                            success: false,
                            error: Some("HTTP 404 - Not Found".to_string()),
                        });
                    }
                    if !status.is_success() && status.as_u16() != 206 {
                        last_error = format!("HTTP {}", status);
                        if attempt == max_retries {
                            return Ok(DownloadResult {
                                url: url.to_string(),
                                file_path: String::new(),
                                file_size: 0,
                                success: false,
                                error: Some(last_error),
                            });
                        }
                        continue;
                    }

                    let content_type = resp.headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    let content_length = resp.headers()
                        .get("content-length")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());

                    if let Some(ref ct) = content_type {
                        let lower_ct = ct.to_lowercase();
                        if lower_ct.contains("text/html") && !url.ends_with(".html") && !url.ends_with(".htm") {
                            let is_actually_resource = url.contains(".css") || url.contains(".js")
                                || url.contains(".png") || url.contains(".jpg") || url.contains(".jpeg")
                                || url.contains(".gif") || url.contains(".svg") || url.contains(".webp")
                                || url.contains(".mp4") || url.contains(".mp3") || url.contains(".pdf")
                                || url.contains(".woff") || url.contains(".ttf");
                            if !is_actually_resource {
                                return Ok(DownloadResult {
                                    url: url.to_string(),
                                    file_path: String::new(),
                                    file_size: 0,
                                    success: false,
                                    error: Some("HTML page instead of resource (likely redirect)".to_string()),
                                });
                            }
                        }
                    }

                    let bytes = match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            last_error = format!("Read body failed: {}", e);
                            if attempt == max_retries {
                                return Ok(DownloadResult {
                                    url: url.to_string(),
                                    file_path: String::new(),
                                    file_size: 0,
                                    success: false,
                                    error: Some(last_error),
                                });
                            }
                            continue;
                        }
                    };

                    if bytes.len() == 0 {
                        return Ok(DownloadResult {
                            url: url.to_string(),
                            file_path: String::new(),
                            file_size: 0,
                            success: false,
                            error: Some("Empty response body".to_string()),
                        });
                    }

                    let file_size = content_length.unwrap_or(bytes.len() as u64);
                    let file_name = Self::extract_filename(url, content_type.as_deref());
                    let save_path = std::path::Path::new(save_dir).join(&file_name);

                    if let Some(parent) = save_path.parent() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            return Ok(DownloadResult {
                                url: url.to_string(),
                                file_path: String::new(),
                                file_size: 0,
                                success: false,
                                error: Some(format!("Create dir failed: {}", e)),
                            });
                        }
                    }

                    let final_path = if save_path.exists() {
                        let mut counter = 1u32;
                        loop {
                            let stem = save_path.file_stem().and_then(|s| s.to_str()).unwrap_or("resource");
                            let ext = save_path.extension().and_then(|s| s.to_str()).unwrap_or("bin");
                            let new_name = format!("{}_{}.{}", stem, counter, ext);
                            let new_path = save_path.with_file_name(&new_name);
                            if !new_path.exists() {
                                break new_path;
                            }
                            counter += 1;
                            if counter > 1000 {
                                break save_path.clone();
                            }
                        }
                    } else {
                        save_path
                    };

                    match std::fs::write(&final_path, &bytes) {
                        Ok(_) => {
                            return Ok(DownloadResult {
                                url: url.to_string(),
                                file_path: final_path.to_string_lossy().to_string(),
                                file_size,
                                success: true,
                                error: None,
                            });
                        }
                        Err(e) => {
                            return Ok(DownloadResult {
                                url: url.to_string(),
                                file_path: String::new(),
                                file_size: 0,
                                success: false,
                                error: Some(format!("Write file failed: {}", e)),
                            });
                        }
                    }
                }
                Err(e) => {
                    last_error = format!("Download failed: {}", e);
                    if attempt == max_retries {
                        return Ok(DownloadResult {
                            url: url.to_string(),
                            file_path: String::new(),
                            file_size: 0,
                            success: false,
                            error: Some(last_error),
                        });
                    }
                }
            }
        }

        Ok(DownloadResult {
            url: url.to_string(),
            file_path: String::new(),
            file_size: 0,
            success: false,
            error: Some(last_error),
        })
    }

    fn extract_referer(url: &str) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
        } else {
            String::new()
        }
    }

    pub async fn download_resources_batch(urls: &[String], save_dir: &str) -> Result<BatchDownloadResult> {
        Self::download_resources_batch_with_config(urls, save_dir, "by_type", 5, 3, 1000, false).await
    }

    pub async fn download_resources_batch_with_config(
        urls: &[String],
        save_dir: &str,
        download_mode: &str,
        max_concurrent: usize,
        max_retries: usize,
        retry_delay_ms: u64,
        mirror_mode: bool,
    ) -> Result<BatchDownloadResult> {
        Self::download_resources_batch_with_auth(
            urls, save_dir, download_mode, max_concurrent, max_retries, retry_delay_ms, mirror_mode, "", "", 0,
        ).await
    }

    pub async fn download_resources_batch_with_auth(
        urls: &[String],
        save_dir: &str,
        download_mode: &str,
        max_concurrent: usize,
        max_retries: usize,
        retry_delay_ms: u64,
        mirror_mode: bool,
        cookies: &str,
        custom_headers: &str,
        max_download_count: usize,
    ) -> Result<BatchDownloadResult> {
        std::fs::create_dir_all(save_dir)
            .map_err(|e| ToolError::ExecutionError(format!("Create dir failed: {}", e)))?;

        let mut valid_urls: Vec<String> = urls.iter()
            .filter(|u| is_downloadable_url(u))
            .cloned()
            .collect();

        if max_download_count > 0 && valid_urls.len() > max_download_count {
            valid_urls.truncate(max_download_count);
        }

        if valid_urls.is_empty() {
            return Ok(BatchDownloadResult {
                total: 0,
                success_count: 0,
                failed_count: 0,
                results: vec![],
                save_dir: save_dir.to_string(),
                paywall_detected: None,
                download_limit_detected: None,
            });
        }

        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failed_count = 0;
        let mut paywall_detected = false;
        let mut download_limit_detected = false;

        let client = build_download_client_with_auth("", cookies, custom_headers)?;

        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut join_set = tokio::task::JoinSet::new();

        for url in &valid_urls {
            let client = client.clone();
            let semaphore = semaphore.clone();
            let url = url.clone();
            let save_dir = save_dir.to_string();
            let download_mode = download_mode.to_string();
            let mirror_mode = mirror_mode;
            let max_retries = max_retries;
            let retry_delay_ms = retry_delay_ms;

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let effective_save_dir = if download_mode == "by_type" {
                    let ext = url.split('.').last().unwrap_or("unknown").to_lowercase();
                    let ext_without_query = ext.split('?').next().unwrap_or("unknown");
                    let subdir = match ext_without_query {
                        "jpg" | "jpeg" | "png" | "gif" | "svg" | "webp" | "ico" | "bmp" | "tiff" => "images",
                        "mp4" | "webm" | "ogg" | "ogv" | "avi" | "mov" | "flv" | "wmv" | "m4v" | "ts" | "m3u8" => "videos",
                        "mp3" | "wav" | "oga" | "flac" | "aac" | "m4a" | "wma" | "opus" => "audio",
                        "css" => "css",
                        "js" | "mjs" => "js",
                        "woff" | "woff2" | "ttf" | "otf" | "eot" => "fonts",
                        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "zip" | "rar" | "7z" | "tar" | "gz" => "documents",
                        _ => "other",
                    };
                    format!("{}/{}", save_dir, subdir)
                } else if download_mode == "by_site" {
                    if let Ok(parsed) = url::Url::parse(&url) {
                        let path = parsed.path().trim_start_matches('/');
                        let parent = std::path::Path::new(path).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                        if parent.is_empty() {
                            save_dir.clone()
                        } else {
                            format!("{}/{}", save_dir, parent)
                        }
                    } else {
                        save_dir.clone()
                    }
                } else {
                    save_dir.clone()
                };

                let referer = WebCrawlerTool::extract_referer(&url);
                let mut last_error = String::new();

                for attempt in 0..=max_retries {
                    if attempt > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms * attempt as u64)).await;
                    }

                    let mut req = client.get(&url)
                        .header("Referer", &referer)
                        .header("Accept", "*/*")
                        .header("Accept-Language", "en-US,en;q=0.9");

                    if attempt > 0 {
                        req = req.header("Range", "bytes=0-");
                    }

                    match req.send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.as_u16() == 404 {
                                return DownloadResult {
                                    url: url.clone(),
                                    file_path: String::new(),
                                    file_size: 0,
                                    success: false,
                                    error: Some("HTTP 404 - Not Found".to_string()),
                                };
                            }
                            if status.as_u16() == 403 || status.as_u16() == 401 {
                                last_error = format!("HTTP {} - Access denied", status);
                                if attempt == max_retries {
                                    return DownloadResult {
                                        url: url.clone(),
                                        file_path: String::new(),
                                        file_size: 0,
                                        success: false,
                                        error: Some(last_error),
                                    };
                                }
                                continue;
                            }
                            if !status.is_success() && status.as_u16() != 206 {
                                last_error = format!("HTTP {}", status);
                                if attempt == max_retries {
                                    return DownloadResult {
                                        url: url.clone(),
                                        file_path: String::new(),
                                        file_size: 0,
                                        success: false,
                                        error: Some(last_error),
                                    };
                                }
                                continue;
                            }

                            let content_type = resp.headers()
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());

                            let content_length = resp.headers()
                                .get("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|s| s.parse::<u64>().ok());

                            if let Some(ref ct) = content_type {
                                let lower_ct = ct.to_lowercase();
                                if lower_ct.contains("text/html") && !mirror_mode {
                                    let url_path = url.split('?').next().unwrap_or("");
                                    if !url_path.ends_with(".html") && !url_path.ends_with(".htm") {
                                        let is_actually_resource = url.contains(".css") || url.contains(".js")
                                            || url.contains(".png") || url.contains(".jpg") || url.contains(".jpeg")
                                            || url.contains(".gif") || url.contains(".svg") || url.contains(".webp")
                                            || url.contains(".mp4") || url.contains(".mp3") || url.contains(".pdf")
                                            || url.contains(".woff") || url.contains(".ttf");
                                        if !is_actually_resource {
                                            return DownloadResult {
                                                url: url.clone(),
                                                file_path: String::new(),
                                                file_size: 0,
                                                success: false,
                                                error: Some("HTML page instead of resource".to_string()),
                                            };
                                        }
                                    }
                                }
                            }

                            let bytes = match resp.bytes().await {
                                Ok(b) => b,
                                Err(e) => {
                                    last_error = format!("Read body failed: {}", e);
                                    if attempt == max_retries {
                                        return DownloadResult {
                                            url: url.clone(),
                                            file_path: String::new(),
                                            file_size: 0,
                                            success: false,
                                            error: Some(last_error),
                                        };
                                    }
                                    continue;
                                }
                            };

                            if bytes.len() == 0 {
                                return DownloadResult {
                                    url: url.clone(),
                                    file_path: String::new(),
                                    file_size: 0,
                                    success: false,
                                    error: Some("Empty response body".to_string()),
                                };
                            }

                            let file_size = content_length.unwrap_or(bytes.len() as u64);
                            let file_name = WebCrawlerTool::extract_filename(&url, content_type.as_deref());
                            let save_path = std::path::Path::new(&effective_save_dir).join(&file_name);

                            if let Some(parent) = save_path.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }

                            let final_path = if save_path.exists() {
                                let mut counter = 1u32;
                                loop {
                                    let stem = save_path.file_stem().and_then(|s| s.to_str()).unwrap_or("resource");
                                    let ext = save_path.extension().and_then(|s| s.to_str()).unwrap_or("bin");
                                    let new_name = format!("{}_{}.{}", stem, counter, ext);
                                    let new_path = save_path.with_file_name(&new_name);
                                    if !new_path.exists() {
                                        break new_path;
                                    }
                                    counter += 1;
                                    if counter > 1000 {
                                        break save_path.clone();
                                    }
                                }
                            } else {
                                save_path
                            };

                            match std::fs::write(&final_path, &bytes) {
                                Ok(_) => {
                                    return DownloadResult {
                                        url: url.clone(),
                                        file_path: final_path.to_string_lossy().to_string(),
                                        file_size,
                                        success: true,
                                        error: None,
                                    };
                                }
                                Err(e) => {
                                    return DownloadResult {
                                        url: url.clone(),
                                        file_path: String::new(),
                                        file_size: 0,
                                        success: false,
                                        error: Some(format!("Write file failed: {}", e)),
                                    };
                                }
                            }
                        }
                        Err(e) => {
                            last_error = format!("Download failed: {}", e);
                            if attempt == max_retries {
                                return DownloadResult {
                                    url: url.clone(),
                                    file_path: String::new(),
                                    file_size: 0,
                                    success: false,
                                    error: Some(last_error),
                                };
                            }
                        }
                    }
                }

                DownloadResult {
                    url: url.clone(),
                    file_path: String::new(),
                    file_size: 0,
                    success: false,
                    error: Some(last_error),
                }
            });
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(dl_result) = result {
                if dl_result.success {
                    success_count += 1;
                } else {
                    failed_count += 1;
                    if let Some(ref err) = dl_result.error {
                        let err_lower = err.to_lowercase();
                        if err_lower.contains("paywall") || err_lower.contains("premium") || err_lower.contains("subscribe") || err_lower.contains("payment required") {
                            paywall_detected = true;
                        }
                        if err_lower.contains("limit") || err_lower.contains("quota") || err_lower.contains("exceeded") || err_lower.contains("too many") {
                            download_limit_detected = true;
                        }
                    }
                }
                results.push(dl_result);
            }
        }

        Ok(BatchDownloadResult {
            total: valid_urls.len(),
            success_count,
            failed_count,
            results,
            save_dir: save_dir.to_string(),
            paywall_detected: if paywall_detected { Some(true) } else { None },
            download_limit_detected: if download_limit_detected { Some(true) } else { None },
        })
    }

    pub async fn download_site(config: &SiteDownloadConfig, crawl_result: &WebCrawlerResult) -> Result<BatchDownloadResult> {
        let urls = collect_prioritized_urls(crawl_result, config);

        if urls.is_empty() {
            return Ok(BatchDownloadResult {
                total: 0,
                success_count: 0,
                failed_count: 0,
                results: vec![],
                save_dir: config.save_dir.clone(),
                paywall_detected: None,
                download_limit_detected: None,
            });
        }

        Self::download_resources_batch_with_auth(
            &urls,
            &config.save_dir,
            &config.download_mode,
            config.max_concurrent,
            config.max_retries,
            config.retry_delay_ms,
            config.mirror_mode,
            &config.cookies,
            &config.custom_headers,
            config.max_download_count,
        ).await
    }

    pub async fn download_full_site(
        start_url: &str,
        save_dir: &str,
        max_depth: usize,
        max_pages: usize,
        max_concurrent: usize,
        follow_external: bool,
    ) -> Result<BatchDownloadResult> {
        std::fs::create_dir_all(save_dir)
            .map_err(|e| ToolError::ExecutionError(format!("Create dir failed: {}", e)))?;

        let client = build_download_client("")?;
        let base_domain = Self::extract_domain(start_url).unwrap_or_default();
        let save_dir_owned = save_dir.to_string();

        let mut url_to_local: HashMap<String, String> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: Vec<(String, usize)> = vec![(start_url.to_string(), 0)];
        let mut all_results: Vec<DownloadResult> = Vec::new();
        let mut success_count = 0usize;
        let mut failed_count = 0usize;

        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        while !queue.is_empty() {
            let mut next_queue: Vec<(String, usize)> = Vec::new();
            let mut batch_urls: Vec<String> = Vec::new();

            for (url, depth) in queue {
                let normalized = if let Ok(parsed) = url::Url::parse(&url) {
                    let mut normalized = parsed.clone();
                    normalized.set_fragment(None);
                    normalized.to_string()
                } else {
                    url.clone()
                };

                if visited.contains(&normalized) {
                    continue;
                }
                if depth > max_depth {
                    continue;
                }
                if !follow_external {
                    let link_domain = Self::extract_domain(&normalized).unwrap_or_default();
                    if link_domain != base_domain {
                        continue;
                    }
                }

                visited.insert(normalized.clone());
                batch_urls.push(normalized);
            }

            if batch_urls.is_empty() {
                break;
            }

            if all_results.len() >= max_pages {
                break;
            }

            let batch_size = max_pages.saturating_sub(all_results.len()).min(batch_urls.len());
            let batch: Vec<String> = batch_urls.into_iter().take(batch_size).collect();

            let mut join_set = tokio::task::JoinSet::new();

            for url in &batch {
                let client = client.clone();
                let semaphore = semaphore.clone();
                let url = url.clone();

                join_set.spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    let referer = WebCrawlerTool::extract_referer(&url);
                    let resp = match client.get(&url)
                        .header("Referer", &referer)
                        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                        .header("Accept-Language", "en-US,en;q=0.9")
                        .send().await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            return (url, None, Vec::new(), format!("Request failed: {}", e));
                        }
                    };

                    let status = resp.status();
                    if !status.is_success() {
                        return (url, None, Vec::new(), format!("HTTP {}", status));
                    }

                    let content_type = resp.headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    let bytes = match resp.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            return (url, None, Vec::new(), format!("Read body failed: {}", e));
                        }
                    };

                    let is_html = content_type.as_ref().map(|ct| ct.to_lowercase().contains("text/html")).unwrap_or(false);

                    let body = if is_html {
                        Self::decode_bytes(&bytes, content_type.as_deref())
                    } else {
                        String::new()
                    };

                    let resource_urls = if is_html {
                        let mut resources = Vec::new();

                        let img_re = regex::Regex::new(r#"<img[^>]+src\s*=\s*"([^"]+)""#).unwrap();
                        for cap in img_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") && !src.starts_with("blob:") && !src.starts_with("javascript:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        let data_src_re = regex::Regex::new(r#"<img[^>]+data-src\s*=\s*"([^"]+)""#).unwrap();
                        for cap in data_src_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") && !src.starts_with("blob:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        let srcset_re = regex::Regex::new(r#"srcset\s*=\s*"([^"]+)""#).unwrap();
                        for cap in srcset_re.captures_iter(&body) {
                            for entry in cap[1].split(',') {
                                if let Some(src) = entry.trim().split_whitespace().next() {
                                    if !src.starts_with("data:") {
                                        resources.push(WebCrawlerTool::resolve_url(&url, src));
                                    }
                                }
                            }
                        }

                        let link_re = regex::Regex::new(r#"<link[^>]+href\s*=\s*"([^"]+)""#).unwrap();
                        for cap in link_re.captures_iter(&body) {
                            let href = &cap[1];
                            if !href.starts_with("data:") && !href.starts_with("blob:") && !href.starts_with("javascript:") {
                                let tag = &cap[0].to_lowercase();
                                if tag.contains("stylesheet") || href.to_lowercase().ends_with(".css") || tag.contains("icon") || tag.contains("preload") || tag.contains("prefetch") {
                                    resources.push(WebCrawlerTool::resolve_url(&url, href));
                                }
                            }
                        }

                        let script_re = regex::Regex::new(r#"<script[^>]+src\s*=\s*"([^"]+)""#).unwrap();
                        for cap in script_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") && !src.starts_with("blob:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        let style_re = regex::Regex::new(r#"<style[^>]*>([\s\S]*?)</style>"#).unwrap();
                        for cap in style_re.captures_iter(&body) {
                            let css = &cap[1];
                            let url_re = regex::Regex::new(r#"url\(\s*['"]?([^'")]+)['"]?\s*\)"#).unwrap();
                            for url_cap in url_re.captures_iter(css) {
                                let u = &url_cap[1];
                                if !u.starts_with("data:") && !u.starts_with("#") {
                                    resources.push(WebCrawlerTool::resolve_url(&url, u));
                                }
                            }
                        }

                        let style_attr_re = regex::Regex::new(r#"style\s*=\s*"([^"]+)""#).unwrap();
                        for cap in style_attr_re.captures_iter(&body) {
                            let css = &cap[1];
                            let url_re = regex::Regex::new(r#"url\(\s*['"]?([^'")\s]+)['"]?\s*\)"#).unwrap();
                            for url_cap in url_re.captures_iter(css) {
                                let u = &url_cap[1];
                                if !u.starts_with("data:") && !u.starts_with("#") && !u.starts_with("blob:") {
                                    resources.push(WebCrawlerTool::resolve_url(&url, u));
                                }
                            }
                        }

                        let video_re = regex::Regex::new(r#"<video[^>]+src\s*=\s*"([^"]+)""#).unwrap();
                        for cap in video_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        let source_re = regex::Regex::new(r#"<source[^>]+src\s*=\s*"([^"]+)""#).unwrap();
                        for cap in source_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        let audio_re = regex::Regex::new(r#"<audio[^>]+src\s*=\s*"([^"]+)""#).unwrap();
                        for cap in audio_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        let embed_re = regex::Regex::new(r#"<(?:embed|object)[^>]+(?:src|data)\s*=\s*"([^"]+)""#).unwrap();
                        for cap in embed_re.captures_iter(&body) {
                            let src = &cap[1];
                            if !src.starts_with("data:") && !src.starts_with("javascript:") {
                                resources.push(WebCrawlerTool::resolve_url(&url, src));
                            }
                        }

                        resources
                    } else {
                        Vec::new()
                    };

                    (url, Some((bytes, content_type, is_html)), resource_urls, String::new())
                });
            }

            while let Some(result) = join_set.join_next().await {
                if let Ok((url, data, resource_urls, error)) = result {
                    if !error.is_empty() {
                        failed_count += 1;
                        all_results.push(DownloadResult {
                            url,
                            file_path: String::new(),
                            file_size: 0,
                            success: false,
                            error: Some(error),
                        });
                        continue;
                    }

                    if let Some((bytes, content_type, is_html)) = data {
                        let local_path = Self::url_to_local_path(&url, &save_dir_owned, is_html);
                        if let Some(parent) = std::path::Path::new(&local_path).parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }

                        let file_size = bytes.len() as u64;

                        if is_html {
                            let body = Self::decode_bytes(&bytes, content_type.as_deref());
                            let mut html = body.clone();

                            for res_url in &resource_urls {
                                let res_local = Self::url_to_local_path(res_url, &save_dir_owned, false);
                                let relative = Self::make_relative_path(&local_path, &res_local);
                                html = html.replace(res_url, &relative);

                                if let Ok(parsed) = url::Url::parse(res_url) {
                                    let path_only = format!("{}{}", 
                                        if parsed.path().starts_with('/') { "" } else { "/" }, 
                                        parsed.path()
                                    );
                                    html = html.replace(&path_only, &relative);
                                }
                            }

                            match std::fs::write(&local_path, &html) {
                                Ok(_) => {
                                    url_to_local.insert(url.clone(), local_path.clone());
                                    success_count += 1;
                                    all_results.push(DownloadResult {
                                        url,
                                        file_path: local_path,
                                        file_size,
                                        success: true,
                                        error: None,
                                    });
                                }
                                Err(e) => {
                                    failed_count += 1;
                                    all_results.push(DownloadResult {
                                        url,
                                        file_path: String::new(),
                                        file_size: 0,
                                        success: false,
                                        error: Some(format!("Write failed: {}", e)),
                                    });
                                }
                            }
                        } else {
                            match std::fs::write(&local_path, &bytes) {
                                Ok(_) => {
                                    url_to_local.insert(url.clone(), local_path.clone());
                                    success_count += 1;
                                    all_results.push(DownloadResult {
                                        url,
                                        file_path: local_path,
                                        file_size,
                                        success: true,
                                        error: None,
                                    });
                                }
                                Err(e) => {
                                    failed_count += 1;
                                    all_results.push(DownloadResult {
                                        url,
                                        file_path: String::new(),
                                        file_size: 0,
                                        success: false,
                                        error: Some(format!("Write failed: {}", e)),
                                    });
                                }
                            }
                        }

                        for res_url in resource_urls {
                            if !visited.contains(&res_url) {
                                let res_domain = Self::extract_domain(&res_url).unwrap_or_default();
                                if follow_external || res_domain == base_domain {
                                    next_queue.push((res_url, 0));
                                }
                            }
                        }
                    }
                }
            }

            let link_re = regex::Regex::new(r#"<a[^>]+href\s*=\s*"([^"]+)""#).unwrap();
            for page_url in &batch {
                if let Some(result) = all_results.iter().find(|r| r.url == *page_url && r.success) {
                    if let Ok(content) = std::fs::read_to_string(&result.file_path) {
                        for cap in link_re.captures_iter(&content) {
                            let href = &cap[1];
                            if href.starts_with("javascript:") || href.starts_with("#") || href.starts_with("mailto:") || href.starts_with("tel:") || href.starts_with("data:") {
                                continue;
                            }
                            let full_url = Self::resolve_url(page_url, href);
                            let normalized = if let Ok(parsed) = url::Url::parse(&full_url) {
                                let mut n = parsed.clone();
                                n.set_fragment(None);
                                n.to_string()
                            } else {
                                full_url
                            };
                            if !visited.contains(&normalized) {
                                let link_domain = Self::extract_domain(&normalized).unwrap_or_default();
                                if follow_external || link_domain == base_domain {
                                    let current_depth = 1;
                                    if current_depth <= max_depth {
                                        next_queue.push((normalized, current_depth));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            queue = next_queue;
        }

        Self::rewrite_downloaded_resources(&save_dir_owned, &url_to_local);

        Ok(BatchDownloadResult {
            total: all_results.len(),
            success_count,
            failed_count,
            results: all_results,
            save_dir: save_dir_owned,
            paywall_detected: None,
            download_limit_detected: None,
        })
    }

    fn url_to_local_path(url: &str, save_dir: &str, is_html: bool) -> String {
        if let Ok(parsed) = url::Url::parse(url) {
            let mut path = parsed.path().trim_start_matches('/').to_string();

            if path.is_empty() {
                path = "index".to_string();
            }

            if path.ends_with('/') {
                path.push_str("index.html");
            }

            let has_extension = std::path::Path::new(&path).extension().is_some();
            if !has_extension {
                if is_html {
                    path.push_str(".html");
                } else {
                    path.push_str(".bin");
                }
            }

            let sanitized = path.split('/')
                .map(|segment| sanitize_filename(segment))
                .collect::<Vec<_>>()
                .join("/");

            format!("{}/{}", save_dir, sanitized)
        } else {
            let hash = Self::simple_hash(url);
            let ext = if is_html { "html" } else { "bin" };
            format!("{}/resource_{}.{}", save_dir, hash, ext)
        }
    }

    fn make_relative_path(from_path: &str, to_path: &str) -> String {
        let from = std::path::Path::new(from_path);
        let to = std::path::Path::new(to_path);

        if let (Some(from_parent), Some(to_file_name)) = (from.parent(), to.file_name()) {
            if let (Some(from_dir), Some(to_dir)) = (from_parent.to_str(), to.parent().and_then(|p| p.to_str())) {
                if from_dir == to_dir {
                    return to_file_name.to_string_lossy().to_string();
                }
            }
        }

        let from_parts: Vec<&str> = from.iter().filter_map(|p| p.to_str()).collect();
        let to_parts: Vec<&str> = to.iter().filter_map(|p| p.to_str()).collect();

        let common_len = from_parts.iter().zip(to_parts.iter())
            .take_while(|(a, b)| a == b)
            .count();

        let up_count = from_parts.len().saturating_sub(common_len).saturating_sub(1);
        let mut relative = String::new();
        for _ in 0..up_count {
            if !relative.is_empty() { relative.push('/'); }
            relative.push_str("..");
        }
        for part in &to_parts[common_len..] {
            if !relative.is_empty() { relative.push('/'); }
            relative.push_str(part);
        }

        if relative.is_empty() {
            to_path.to_string()
        } else {
            relative
        }
    }

    fn rewrite_downloaded_resources(save_dir: &str, url_to_local: &HashMap<String, String>) {
        let css_re = regex::Regex::new(r#"url\(\s*['"]?([^'")]+)['"]?\s*\)"#).unwrap();

        if let Ok(entries) = std::fs::read_dir(save_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    Self::rewrite_css_in_dir(&path, url_to_local, &css_re);
                } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "css" {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let rewritten = Self::rewrite_css_urls(&content, url_to_local, &css_re, &path.to_string_lossy());
                            let _ = std::fs::write(&path, rewritten);
                        }
                    }
                }
            }
        }
    }

    fn rewrite_css_in_dir(dir: &std::path::Path, url_to_local: &HashMap<String, String>, css_re: &regex::Regex) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    Self::rewrite_css_in_dir(&path, url_to_local, css_re);
                } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "css" {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let rewritten = Self::rewrite_css_urls(&content, url_to_local, css_re, &path.to_string_lossy());
                            let _ = std::fs::write(&path, rewritten);
                        }
                    }
                }
            }
        }
    }

    fn rewrite_css_urls(css: &str, url_to_local: &HashMap<String, String>, css_re: &regex::Regex, css_path: &str) -> String {
        let mut result = css.to_string();
        for cap in css_re.captures_iter(css) {
            let original_url = &cap[1];
            if original_url.starts_with("data:") || original_url.starts_with("#") || original_url.starts_with("blob:") {
                continue;
            }
            for (remote_url, local_path) in url_to_local {
                if original_url == remote_url || original_url.ends_with(&remote_url[remote_url.find("://").map(|i| i+3).unwrap_or(0)..]) {
                    let relative = Self::make_relative_path(css_path, local_path);
                    result = result.replace(original_url, &relative);
                    break;
                }
            }
        }
        result
    }

    fn extract_filename(url: &str, content_type: Option<&str>) -> String {
        if let Some(path) = url.split('?').next() {
            if let Some(name) = path.rsplit('/').next() {
                if !name.is_empty() && name.len() < 200 && name.contains('.') {
                    let sanitized = sanitize_filename(name);
                    if !sanitized.is_empty() && sanitized != "." && sanitized != ".." {
                        return sanitized;
                    }
                }
            }
        }

        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path();
            if let Some(name) = path.rsplit('/').next() {
                if !name.is_empty() && name.contains('.') {
                    let sanitized = sanitize_filename(name);
                    if !sanitized.is_empty() && sanitized != "." && sanitized != ".." {
                        return sanitized;
                    }
                }
            }
            if let Some(segments) = parsed.path_segments() {
                let segments: Vec<&str> = segments.collect();
                if segments.len() >= 2 {
                    let parent = segments[segments.len() - 2];
                    let last = segments[segments.len() - 1];
                    if !last.is_empty() {
                        let combined = format!("{}_{}", parent, last);
                        let sanitized = sanitize_filename(&combined);
                        if !sanitized.is_empty() && sanitized != "." && sanitized != ".." {
                            return sanitized;
                        }
                    }
                }
            }
        }

        let ext = content_type
            .and_then(|ct| ct.split(';').next())
            .and_then(|ct| match ct.trim() {
                "image/jpeg" => Some("jpg"),
                "image/png" => Some("png"),
                "image/gif" => Some("gif"),
                "image/svg+xml" => Some("svg"),
                "image/webp" => Some("webp"),
                "image/x-icon" | "image/vnd.microsoft.icon" => Some("ico"),
                "image/bmp" => Some("bmp"),
                "image/tiff" => Some("tiff"),
                "video/mp4" => Some("mp4"),
                "video/webm" => Some("webm"),
                "video/ogg" => Some("ogv"),
                "video/x-msvideo" => Some("avi"),
                "video/quicktime" => Some("mov"),
                "audio/mpeg" => Some("mp3"),
                "audio/wav" => Some("wav"),
                "audio/ogg" => Some("oga"),
                "audio/flac" => Some("flac"),
                "audio/aac" => Some("aac"),
                "application/pdf" => Some("pdf"),
                "application/javascript" | "text/javascript" => Some("js"),
                "text/css" => Some("css"),
                "text/html" => Some("html"),
                "font/woff" => Some("woff"),
                "font/woff2" => Some("woff2"),
                "font/ttf" => Some("ttf"),
                "font/otf" => Some("otf"),
                "application/zip" => Some("zip"),
                "application/x-rar-compressed" => Some("rar"),
                "application/x-7z-compressed" => Some("7z"),
                "application/gzip" | "application/x-gzip" => Some("gz"),
                "application/msword" => Some("doc"),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("docx"),
                "application/vnd.ms-excel" => Some("xls"),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
                "application/json" => Some("json"),
                "application/xml" | "text/xml" => Some("xml"),
                _ => None,
            })
            .unwrap_or("bin");

        format!("resource_{}.{}", Self::simple_hash(url), ext)
    }

    fn simple_hash(s: &str) -> u64 {
        let mut hash: u64 = 5381;
        for byte in s.bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
        }
        hash % 100000
    }

    async fn scan_directories(start_url: &str, client: &reqwest::Client, timeout: u64) -> Vec<DirEntryInfo> {
        let base_url = start_url.trim_end_matches('/');
        let mut entries = Vec::new();

        let common_paths = [
            "admin", "login", "dashboard", "api", "config", "backup", "db",
            "uploads", "upload", "files", "images", "img", "assets", "static",
            "css", "js", "fonts", "media", "downloads", "download", "videos",
            ".env", ".git", ".svn", ".htaccess", "robots.txt",
            "sitemap.xml", "favicon.ico", "crossdomain.xml",
            "test", "debug", "tmp", "temp", "cache", "log", "logs",
            "console", "phpmyadmin", "wp-admin", "wp-login.php",
            "cgi-bin", "server-status", "server-info", ".well-known",
            "swagger", "swagger-ui", "swagger.json", "api-docs", "graphql",
            "health", "status", "info", "version", "ping",
            "users", "user", "profile", "account", "accounts",
            "search", "query", "export", "import", "report",
            "index", "home", "main", "default", "start",
            "private", "secret", "hidden", "internal", "restricted",
            "old", "new", "dev", "staging", "prod", "production",
            "v1", "v2", "v3", "api/v1", "api/v2", "rest",
            "wp-content", "wp-includes", "administrator",
            "cgi-bin", "bin", "lib", "src", "app", "public",
            "dist", "build", "out", "docs", "documentation",
            "scripts", "styles", "templates", "views", "layouts",
            "components", "modules", "plugins", "themes",
            "data", "database", "sql", "migrations",
            "certs", "certificates", "keys", "ssl",
            "oauth", "auth", "login", "register", "signup",
            "feed", "rss", "atom", "sitemap",
            "archive", "releases", "packages", "npm",
            ".github", ".gitlab", ".vscode", ".idea",
            "Dockerfile", "docker-compose.yml", "Makefile",
            "package.json", "composer.json", "Gemfile", "requirements.txt",
            "README.md", "CHANGELOG.md", "LICENSE",
        ];

        let extensions = ["", "/", ".html", ".php", ".json", ".txt", ".xml", ".bak", ".old", ".zip", ".tar.gz"];

        let semaphore = Arc::new(Semaphore::new(10));
        let mut join_set = tokio::task::JoinSet::new();
        let client_timeout = std::time::Duration::from_secs(timeout);

        for path in &common_paths {
            for ext in &extensions {
                let full_path = format!("{}{}", path, ext);
                let full_url = format!("{}/{}", base_url, full_path);
                let client = client.clone();
                let semaphore = semaphore.clone();
                let client_timeout = client_timeout;

                join_set.spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    let result = tokio::time::timeout(client_timeout, async {
                        match client.head(&full_url).send().await {
                            Ok(resp) => {
                                let status = resp.status().as_u16();
                                if status >= 200 && status < 400 {
                                    let content_length = resp.headers()
                                        .get("content-length")
                                        .and_then(|v| v.to_str().ok())
                                        .and_then(|s| s.parse::<u64>().ok());
                                    let content_type = resp.headers()
                                        .get("content-type")
                                        .and_then(|v| v.to_str().ok())
                                        .map(|s| s.to_string());
                                    let is_dir = full_url.ends_with('/') ||
                                        content_type.as_ref().map(|ct| ct.contains("text/html")).unwrap_or(false);
                                    Some(DirEntryInfo {
                                        path: full_path,
                                        full_url,
                                        status_code: status,
                                        content_length,
                                        content_type,
                                        is_directory: is_dir,
                                    })
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        }
                    }).await;

                    match result {
                        Ok(Some(entry)) => Some(entry),
                        _ => None,
                    }
                });
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(entry)) = result {
                entries.push(entry);
            }
        }

        entries.sort_by(|a, b| {
            a.is_directory.cmp(&b.is_directory).reverse()
                .then(a.path.cmp(&b.path))
        });

        entries
    }

    fn extract_video_sources(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut videos = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();

        let rule_videos = Self::extract_resources_by_rules(html, base_url, VIDEO_RESOURCE_RULES, &mut seen_urls, true);
        videos.extend(rule_videos);

        let video_exts = [".mp4", ".webm", ".ogg", ".ogv", ".avi", ".mov", ".flv", ".wmv", ".m4v", ".3gp", ".ts", ".m3u8"];
        let link_re = regex::Regex::new(r#"<a[^>]+href\s*=\s*"([^"]+)""#).unwrap();
        for cap in link_re.captures_iter(html) {
            let href = &cap[1];
            let lower = href.to_lowercase();
            for ext in &video_exts {
                if lower.contains(ext) {
                    let url = Self::resolve_url(base_url, href);
                    if seen_urls.insert(url.clone()) {
                        videos.push(ResourceInfo {
                            url,
                            resource_type: ext.trim_start_matches('.').to_string(),
                            size: None,
                            source_page: Some(base_url.to_string()),
                            score: None,
                        });
                    }
                    break;
                }
            }
        }

        let embed_re = regex::Regex::new(r#"<embed[^>]+src\s*=\s*"([^"]+\.(?:mp4|webm|ogg|avi|mov|flv|wmv)[^"]*)""#).unwrap();
        for cap in embed_re.captures_iter(html) {
            let url = Self::resolve_url(base_url, &cap[1]);
            if seen_urls.insert(url.clone()) {
                videos.push(ResourceInfo {
                    url,
                    resource_type: Self::video_type_from_url(&cap[1]),
                    size: None,
                    source_page: Some(base_url.to_string()),
                    score: None,
                });
            }
        }

        videos
    }

    fn video_type_from_url(url: &str) -> String {
        let lower = url.to_lowercase();
        let url_without_query = lower.split('?').next().unwrap_or("");
        if url_without_query.ends_with(".mp4") { "mp4".to_string() }
        else if url_without_query.ends_with(".webm") { "webm".to_string() }
        else if url_without_query.ends_with(".ogg") || url_without_query.ends_with(".ogv") { "ogg".to_string() }
        else if url_without_query.ends_with(".avi") { "avi".to_string() }
        else if url_without_query.ends_with(".mov") { "mov".to_string() }
        else if url_without_query.ends_with(".flv") { "flv".to_string() }
        else if url_without_query.ends_with(".wmv") { "wmv".to_string() }
        else if url_without_query.ends_with(".m3u8") { "hls".to_string() }
        else if url_without_query.ends_with(".ts") { "ts".to_string() }
        else { "video".to_string() }
    }

    fn extract_audio_sources(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut audios = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();

        let rule_audios = Self::extract_resources_by_rules(html, base_url, AUDIO_RESOURCE_RULES, &mut seen_urls, true);
        audios.extend(rule_audios);

        let audio_exts = [".mp3", ".wav", ".ogg", ".oga", ".flac", ".aac", ".m4a", ".wma", ".opus"];
        let link_re = regex::Regex::new(r#"<a[^>]+href\s*=\s*"([^"]+)""#).unwrap();
        for cap in link_re.captures_iter(html) {
            let href = &cap[1];
            let lower = href.to_lowercase();
            for ext in &audio_exts {
                if lower.contains(ext) {
                    let url = Self::resolve_url(base_url, href);
                    if seen_urls.insert(url.clone()) {
                        audios.push(ResourceInfo {
                            url,
                            resource_type: ext.trim_start_matches('.').to_string(),
                            size: None,
                            source_page: Some(base_url.to_string()),
                            score: None,
                        });
                    }
                    break;
                }
            }
        }

        audios
    }

    #[allow(dead_code)]
    fn audio_type_from_url(url: &str) -> String {
        let lower = url.to_lowercase();
        let url_without_query = lower.split('?').next().unwrap_or("");
        if url_without_query.ends_with(".mp3") { "mp3".to_string() }
        else if url_without_query.ends_with(".wav") { "wav".to_string() }
        else if url_without_query.ends_with(".ogg") || url_without_query.ends_with(".oga") { "ogg".to_string() }
        else if url_without_query.ends_with(".flac") { "flac".to_string() }
        else if url_without_query.ends_with(".aac") { "aac".to_string() }
        else if url_without_query.ends_with(".m4a") { "m4a".to_string() }
        else if url_without_query.ends_with(".wma") { "wma".to_string() }
        else if url_without_query.ends_with(".opus") { "opus".to_string() }
        else { "audio".to_string() }
    }

    fn extract_domain(url: &str) -> Option<String> {
        let url = url.trim_start_matches("http://").trim_start_matches("https://");
        let domain = url.split('/').next()?;
        let domain = domain.split(':').next()?;
        Some(domain.to_string())
    }

    fn extract_title(html: &str) -> Option<String> {
        let lower = html.to_lowercase();
        let start = lower.find("<title>")? + "<title>".len();
        let end = lower.find("</title>")?;
        if end > start && end <= html.len() && start <= html.len() {
            Some(html[start..end].trim().to_string())
        } else {
            None
        }
    }

    fn count_words(html: &str) -> usize {
        let text = Self::strip_html_tags(html);
        text.split_whitespace().count()
    }

    fn strip_html_tags(html: &str) -> String {
        let mut result = String::new();
        let mut in_tag = false;
        let mut in_script = false;
        let lower = html.to_lowercase();
        let mut tag_start = 0;

        for (i, c) in html.char_indices() {
            if !in_script && c == '<' {
                in_tag = true;
                tag_start = i;
            } else if in_tag && c == '>' {
                in_tag = false;
                let tag_content = &lower[tag_start..i + 1];
                if tag_content.starts_with("<script") {
                    in_script = true;
                }
            } else if !in_tag && !in_script {
                result.push(c);
            } else if in_script && c == '>' {
                let tag_content = &lower[tag_start..i + 1];
                if tag_content.starts_with("</script") {
                    in_script = false;
                }
            }
        }

        result
    }

    #[allow(dead_code)]
    fn extract_main_content(html: &str) -> String {
        let lower = html.to_lowercase();

        let semantic_selectors = [
            (r#"<article[^>]*>([\s\S]*?)</article>"#, "article"),
            (r#"<main[^>]*>([\s\S]*?)</main>"#, "main"),
            (r#"<section[^>]*>([\s\S]*?)</section>"#, "section"),
            (r#"<div[^>]+role\s*=\s*"main"[^>]*>([\s\S]*?)</div>"#, "role-main"),
            (r#"<div[^>]+id\s*=\s*"[^"]*(?:content|article|post|entry|body|main)[^"]*"[^>]*>([\s\S]*?)</div>"#, "content-div"),
            (r#"<div[^>]+class\s*=\s*"[^"]*(?:content|article|post|entry|body|main)[^"]*"[^>]*>([\s\S]*?)</div>"#, "content-div"),
        ];

        for (pattern, _) in &semantic_selectors {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(cap) = re.captures(&lower) {
                    let content_html = &cap[1];
                    if content_html.len() > 200 {
                        return Self::strip_html_tags(content_html);
                    }
                }
            }
        }

        let mut cleaned = html.to_string();
        let remove_patterns = [
            (r#"<nav[^>]*>[\s\S]*?</nav>"#, "nav"),
            (r#"<header[^>]*>[\s\S]*?</header>"#, "header"),
            (r#"<footer[^>]*>[\s\S]*?</footer>"#, "footer"),
            (r#"<aside[^>]*>[\s\S]*?</aside>"#, "aside"),
            (r#"<form[^>]*>[\s\S]*?</form>"#, "form"),
            (r#"<div[^>]+class\s*=\s*"[^"]*(?:sidebar|widget|ad|advertisement|banner|cookie|popup|modal|overlay|social|share|comment|navigation|menu|nav)[^"]*"[^>]*>[\s\S]*?</div>"#, "noise-div"),
            (r#"<div[^>]+id\s*=\s*"[^"]*(?:sidebar|widget|ad|advertisement|banner|cookie|popup|modal|overlay|social|share|comment|navigation|menu|nav)[^"]*"[^>]*>[\s\S]*?</div>"#, "noise-div"),
        ];

        for (pattern, _) in &remove_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                cleaned = re.replace_all(&cleaned, "").to_string();
            }
        }

        Self::strip_html_tags(&cleaned)
    }

    fn extract_links(html: &str, base_url: &str) -> Vec<String> {
        let mut links = Vec::new();
        let lower = html.to_lowercase();

        for pattern in &["href=\"", "src=\"", "action=\"", "data-href=\"", "data-url=\"", "data-link=\""] {
            let mut search_from = 0;
            while let Some(start) = lower[search_from..].find(pattern) {
                let attr_start = search_from + start + pattern.len();
                if let Some(end) = html[attr_start..].find('"') {
                    let href = &html[attr_start..attr_start + end];
                    if !href.is_empty() && !href.starts_with('#') && !href.starts_with("javascript:") && !href.starts_with("mailto:") && !href.starts_with("data:") && !href.starts_with("tel:") && !href.starts_with("blob:") {
                        let full_url = Self::resolve_url(base_url, href);
                        links.push(full_url);
                    }
                    search_from = attr_start + end + 1;
                } else {
                    break;
                }
                if links.len() > 1000 {
                    break;
                }
            }
        }

        if let Ok(re) = regex::Regex::new(r#"srcset\s*=\s*"([^"]+)""#) {
            for cap in re.captures_iter(html) {
                let srcset = &cap[1];
                for entry in srcset.split(',') {
                    let url_part = entry.trim().split_whitespace().next().unwrap_or("");
                    if !url_part.is_empty() && !url_part.starts_with("data:") {
                        let full_url = Self::resolve_url(base_url, url_part);
                        links.push(full_url);
                    }
                }
            }
        }

        let href_single_re = regex::Regex::new(r#"href\s*=\s*'([^']+)'"#).unwrap();
        for cap in href_single_re.captures_iter(html) {
            let href = &cap[1];
            if !href.is_empty() && !href.starts_with('#') && !href.starts_with("javascript:") && !href.starts_with("mailto:") && !href.starts_with("data:") && !href.starts_with("tel:") {
                let full_url = Self::resolve_url(base_url, href);
                links.push(full_url);
            }
        }

        Self::extract_js_navigation_urls(html, base_url, &mut links);

        links
    }

    fn extract_js_navigation_urls(html: &str, base_url: &str, links: &mut Vec<String>) {
        let js_url_patterns: &[&str] = &[
            r#"location\.href\s*=\s*['"]([^'"]+)['"]"#,
            r#"location\s*=\s*['"]([^'"]+)['"]"#,
            r#"window\.location\s*=\s*['"]([^'"]+)['"]"#,
            r#"window\.location\.href\s*=\s*['"]([^'"]+)['"]"#,
            r#"window\.location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
            r#"window\.open\s*\(\s*['"]([^'"]+)['"]"#,
            r#"location\.assign\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
            r#"router\.push\s*\(\s*['"]([^'"]+)['"]"#,
            r#"router\.replace\s*\(\s*['"]([^'"]+)['"]"#,
            r#"navigate\s*\(\s*['"]([^'"]+)['"]"#,
            r#"href\s*:\s*['"](/[^'"]+)['"]"#,
            r#"path\s*:\s*['"](/[^'"]+)['"]"#,
            r#"url\s*:\s*['"](/[^'"]+)['"]"#,
            r#"to\s*:\s*['"](/[^'"]+)['"]"#,
        ];

        for pattern in js_url_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(html) {
                    let url = &cap[1];
                    if !url.is_empty() && !url.starts_with('#') && !url.starts_with("javascript:") && !url.starts_with("data:") {
                        let full_url = Self::resolve_url(base_url, url);
                        if full_url.starts_with("http://") || full_url.starts_with("https://") {
                            links.push(full_url);
                        }
                    }
                }
            }
        }

        if let Ok(re) = regex::Regex::new(r#"onclick\s*=\s*["']([^"']+)["']"#) {
            for cap in re.captures_iter(html) {
                let onclick = &cap[1];
                if let Ok(url_re) = regex::Regex::new(r#"(?:location\.href|location|window\.location|window\.location\.href)\s*=\s*['"]([^'"]+)['"]"#) {
                    for url_cap in url_re.captures_iter(onclick) {
                        let url = &url_cap[1];
                        if !url.is_empty() && !url.starts_with('#') && !url.starts_with("javascript:") {
                            let full_url = Self::resolve_url(base_url, url);
                            if full_url.starts_with("http://") || full_url.starts_with("https://") {
                                links.push(full_url);
                            }
                        }
                    }
                }
                if let Ok(url_re) = regex::Regex::new(r#"window\.open\s*\(\s*['"]([^'"]+)['"]"#) {
                    for url_cap in url_re.captures_iter(onclick) {
                        let url = &url_cap[1];
                        if !url.is_empty() && !url.starts_with('#') {
                            let full_url = Self::resolve_url(base_url, url);
                            if full_url.starts_with("http://") || full_url.starts_with("https://") {
                                links.push(full_url);
                            }
                        }
                    }
                }
            }
        }

        if let Ok(re) = regex::Regex::new(r#"<a[^>]+data-[\w-]+\s*=\s*["'](/[^"']+)["']"#) {
            for cap in re.captures_iter(html) {
                let url = &cap[1];
                if !url.is_empty() {
                    let full_url = Self::resolve_url(base_url, url);
                    if full_url.starts_with("http://") || full_url.starts_with("https://") {
                        links.push(full_url);
                    }
                }
            }
        }
    }

    fn resolve_url(base: &str, relative: &str) -> String {
        if relative.starts_with("data:") || relative.starts_with("blob:") || relative.starts_with("javascript:") {
            return relative.to_string();
        }

        if let Some(resolved) = resolve_url_proper(base, relative) {
            if resolved.starts_with("http://") || resolved.starts_with("https://") {
                return resolved;
            }
        }

        if relative.starts_with("http://") || relative.starts_with("https://") {
            return relative.to_string();
        }

        let base_trimmed = base.trim_end_matches('/');

        if relative.starts_with("//") {
            if let Some(scheme_end) = base.find("://") {
                return format!("{}:{}", &base[..scheme_end], relative);
            }
            return format!("https:{}", relative);
        }

        if relative.starts_with('/') {
            let after_scheme = &base_trimmed[8.min(base_trimmed.len())..];
            if let Some(slash_pos) = after_scheme.find('/') {
                return format!("{}{}", &base_trimmed[..8 + slash_pos], relative);
            }
            return format!("{}{}", base_trimmed, relative);
        }

        if let Some(last_slash) = base_trimmed.rfind('/') {
            format!("{}/{}", &base_trimmed[..last_slash], relative)
        } else {
            format!("{}/{}", base_trimmed, relative)
        }
    }

    fn is_valid_resource_url(url: &str) -> bool {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return false;
        }
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return host.contains('.') && !host.starts_with('.');
            }
        }
        false
    }

    fn extract_emails_from_html(html: &str) -> Vec<String> {
        let re = regex::Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
        re.find_iter(html)
            .filter_map(|m| {
                let email = m.as_str().to_string();
                if !email.ends_with(".png") && !email.ends_with(".jpg") && !email.ends_with(".svg") && !email.ends_with(".gif") && !email.ends_with(".webp") {
                    Some(email)
                } else {
                    None
                }
            })
            .collect()
    }

    fn extract_js_files(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut files = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        let script_re = regex::Regex::new(r#"<script[^>]+src\s*=\s*"([^"]+)""#).unwrap();
        for cap in script_re.captures_iter(html) {
            let src = &cap[1];
            if !src.starts_with("data:") && !src.starts_with("blob:") {
                let url = Self::resolve_url(base_url, src);
                if seen.insert(url.clone()) {
                    let lower_src = src.to_lowercase();
                    let resource_type = if lower_src.contains("module") || lower_src.contains(".mjs") {
                        "esmodule".to_string()
                    } else {
                        "javascript".to_string()
                    };
                    files.push(ResourceInfo {
                        url,
                        resource_type,
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }

        let script_re_single = regex::Regex::new(r#"<script[^>]+src\s*=\s*'([^']+)'"#).unwrap();
        for cap in script_re_single.captures_iter(html) {
            let src = &cap[1];
            if !src.starts_with("data:") && !src.starts_with("blob:") {
                let url = Self::resolve_url(base_url, src);
                if seen.insert(url.clone()) {
                    files.push(ResourceInfo {
                        url,
                        resource_type: "javascript".to_string(),
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }

        let dynamic_load_re = regex::Regex::new(r#"(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap();
        for cap in dynamic_load_re.captures_iter(html) {
            let src = &cap[1];
            if !src.starts_with("data:") && !src.starts_with("blob:") && !src.starts_with(".") && (src.starts_with("/") || src.starts_with("http")) {
                let url = Self::resolve_url(base_url, src);
                if seen.insert(url.clone()) {
                    files.push(ResourceInfo {
                        url,
                        resource_type: "dynamic-import".to_string(),
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }

        files
    }

    fn extract_resources_by_rules(html: &str, base_url: &str, rules: &[ResourceRule], seen_urls: &mut HashSet<String>, skip_data_uri: bool) -> Vec<ResourceInfo> {
        let mut resources = Vec::new();
        for rule in rules {
            if let Ok(re) = regex::Regex::new(rule.selector_pattern) {
                for cap in re.captures_iter(html) {
                    let value = &cap[1];
                    if skip_data_uri && (value.starts_with("data:") || value.starts_with("blob:")) {
                        continue;
                    }
                    if value.starts_with("javascript:") || value.starts_with("about:") {
                        continue;
                    }
                    if value.starts_with("#") {
                        continue;
                    }
                    let url = Self::resolve_url(base_url, value);
                    if (url.starts_with("http://") || url.starts_with("https://")) && seen_urls.insert(url.clone()) {
                        resources.push(ResourceInfo {
                            url,
                            resource_type: rule.resource_type.to_string(),
                            size: None,
                            source_page: Some(base_url.to_string()),
                            score: None,
                        });
                    }
                }
            }
        }
        resources
    }

    fn parse_srcset(srcset_value: &str, base_url: &str, seen_urls: &mut HashSet<String>, resource_type: &str) -> Vec<ResourceInfo> {
        let mut resources = Vec::new();
        for entry in srcset_value.split(',') {
            let parts: Vec<&str> = entry.trim().split_whitespace().collect();
            if let Some(url_part) = parts.first() {
                if url_part.starts_with("data:") || url_part.starts_with("blob:") {
                    continue;
                }
                let url = Self::resolve_url(base_url, url_part);
                if (url.starts_with("http://") || url.starts_with("https://")) && seen_urls.insert(url.clone()) {
                    let descriptor = if parts.len() > 1 { parts[1].to_string() } else { String::new() };
                    let rt = if descriptor.ends_with('w') {
                        format!("{}-{}w", resource_type, descriptor.trim_end_matches('w'))
                    } else if descriptor.ends_with('x') {
                        format!("{}-{}x", resource_type, descriptor.trim_end_matches('x'))
                    } else {
                        resource_type.to_string()
                    };
                    resources.push(ResourceInfo {
                        url,
                        resource_type: rt,
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }
        resources
    }

    fn extract_images(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut images = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();

        images.extend(Self::extract_resources_by_rules(html, base_url, IMAGE_RESOURCE_RULES, &mut seen_urls, true));

        let srcset_re = regex::Regex::new(r#"srcset\s*=\s*"([^"]+)""#).unwrap();
        for cap in srcset_re.captures_iter(html) {
            images.extend(Self::parse_srcset(&cap[1], base_url, &mut seen_urls, "responsive"));
        }

        let picture_re = regex::Regex::new(r#"<picture[^>]*>[\s\S]*?</picture>"#).unwrap();
        for cap in picture_re.captures_iter(html) {
            let picture_html = &cap[0];
            let source_re = regex::Regex::new(r#"<source[^>]+srcset\s*=\s*"([^"]+)""#).unwrap();
            for source_cap in source_re.captures_iter(picture_html) {
                images.extend(Self::parse_srcset(&source_cap[1], base_url, &mut seen_urls, "picture"));
            }
        }

        let bg_re = regex::Regex::new(r#"background-image\s*:\s*url\(['"]?([^'")\s]+)['"]?\)"#).unwrap();
        for cap in bg_re.captures_iter(html) {
            let url = Self::resolve_url(base_url, &cap[1]);
            if seen_urls.insert(url.clone()) {
                images.push(ResourceInfo {
                    url,
                    resource_type: "background".to_string(),
                    size: None,
                    source_page: Some(base_url.to_string()),
                    score: None,
                });
            }
        }

        let style_bg_re = regex::Regex::new(r#"style\s*=\s*"[^"]*background[^"]*url\(['"]?([^'")\s]+)['"]?\)"#).unwrap();
        for cap in style_bg_re.captures_iter(html) {
            let url = Self::resolve_url(base_url, &cap[1]);
            if seen_urls.insert(url.clone()) {
                images.push(ResourceInfo {
                    url,
                    resource_type: "inline-bg".to_string(),
                    size: None,
                    source_page: Some(base_url.to_string()),
                    score: None,
                });
            }
        }

        let svg_re = regex::Regex::new(r#"<svg[^>]*>[\s\S]*?</svg>"#).unwrap();
        for _ in svg_re.captures_iter(html) {
            images.push(ResourceInfo {
                url: format!("{}#inline-svg-{}", base_url, images.len()),
                resource_type: "inline-svg".to_string(),
                size: None,
                source_page: Some(base_url.to_string()),
                score: None,
            });
        }

        images
    }

    #[allow(dead_code)]
    fn image_type_from_url(url: &str) -> String {
        let lower = url.to_lowercase();
        let url_without_query = lower.split('?').next().unwrap_or("");
        if url_without_query.ends_with(".svg") { "svg".to_string() }
        else if url_without_query.ends_with(".webp") { "webp".to_string() }
        else if url_without_query.ends_with(".png") { "png".to_string() }
        else if url_without_query.ends_with(".jpg") || url_without_query.ends_with(".jpeg") { "jpeg".to_string() }
        else if url_without_query.ends_with(".gif") { "gif".to_string() }
        else if url_without_query.ends_with(".ico") { "ico".to_string() }
        else { "image".to_string() }
    }

    fn extract_css_files(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut files = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();

        let re = regex::Regex::new(r#"<link[^>]+href\s*=\s*"([^"]+)"[^>]*>"#).unwrap();
        for cap in re.captures_iter(html) {
            let href = &cap[1];
            let tag = &cap[0].to_lowercase();
            if tag.contains("stylesheet") || href.to_lowercase().ends_with(".css") {
                let url = Self::resolve_url(base_url, href);
                if seen_urls.insert(url.clone()) {
                    files.push(ResourceInfo {
                        url,
                        resource_type: "stylesheet".to_string(),
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }

        let link_resources = Self::extract_resources_by_rules(html, base_url, LINK_RESOURCE_RULES, &mut seen_urls, true);
        files.extend(link_resources);

        let inline_style_re = regex::Regex::new(r#"<style[^>]*>([\s\S]*?)</style>"#).unwrap();
        for cap in inline_style_re.captures_iter(html) {
            let css_content = &cap[1];
            let css_urls = parse_css_urls(css_content);
            for url_str in css_urls {
                let lower = url_str.to_lowercase();
                let is_font = lower.ends_with(".woff") || lower.ends_with(".woff2") || lower.ends_with(".ttf") || lower.ends_with(".otf") || lower.ends_with(".eot");
                let is_image = lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg") || lower.ends_with(".gif") || lower.ends_with(".svg") || lower.ends_with(".webp") || lower.ends_with(".ico");
                if !is_font && !is_image {
                    let url = Self::resolve_url(base_url, &url_str);
                    if seen_urls.insert(url.clone()) {
                        files.push(ResourceInfo {
                            url,
                            resource_type: "inline-css-ref".to_string(),
                            size: None,
                            source_page: Some(base_url.to_string()),
                            score: None,
                        });
                    }
                }
            }
        }

        let import_re = regex::Regex::new(r##"@import\s+(?:url\(['"]?|['"])([^'")\s;]+)(?:['"]?\)|['"])#"##).unwrap();
        for cap in import_re.captures_iter(html) {
            let url_str = &cap[1];
            if !url_str.starts_with("data:") {
                let url = Self::resolve_url(base_url, url_str);
                if seen_urls.insert(url.clone()) {
                    files.push(ResourceInfo {
                        url,
                        resource_type: "css-import".to_string(),
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }

        files
    }

    fn extract_font_files(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut fonts = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();

        let font_pattern = regex::Regex::new(r#"(?i)url\(['"]?([^'")]+\.(woff2?|ttf|otf|eot))['"]?\)"#).unwrap();
        for cap in font_pattern.captures_iter(html) {
            let url = Self::resolve_url(base_url, &cap[1]);
            if seen_urls.insert(url.clone()) {
                fonts.push(ResourceInfo {
                    url,
                    resource_type: cap[2].to_string(),
                    size: None,
                    source_page: Some(base_url.to_string()),
                    score: None,
                });
            }
        }

        let link_pattern = regex::Regex::new(r#"<link[^>]+href\s*=\s*"([^"]+)"[^>]*>"#).unwrap();
        for cap in link_pattern.captures_iter(html) {
            let href = &cap[1];
            let lower = href.to_lowercase();
            if lower.contains("fonts.googleapis.com") || lower.contains("fonts.gstatic.com") || lower.contains("cdn.jsdelivr.net") && lower.contains("font") {
                let url = Self::resolve_url(base_url, href);
                if seen_urls.insert(url.clone()) {
                    fonts.push(ResourceInfo {
                        url,
                        resource_type: "webfont".to_string(),
                        size: None,
                        source_page: Some(base_url.to_string()),
                        score: None,
                    });
                }
            }
        }

        fonts
    }

    fn extract_document_links(html: &str, base_url: &str) -> Vec<ResourceInfo> {
        let mut docs = Vec::new();
        let mut seen_urls: HashSet<String> = HashSet::new();
        let doc_extensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".7z", ".tar.gz", ".csv", ".xml", ".json", ".txt", ".md", ".rtf", ".odt", ".ods", ".odp", ".epub", ".mobi"];

        let re = regex::Regex::new(r#"<a[^>]+href\s*=\s*"([^"]+)""#).unwrap();
        for cap in re.captures_iter(html) {
            let href = &cap[1];
            let lower = href.to_lowercase();
            for ext in &doc_extensions {
                if lower.contains(ext) {
                    let url = Self::resolve_url(base_url, href);
                    if seen_urls.insert(url.clone()) {
                        docs.push(ResourceInfo {
                            url,
                            resource_type: ext.trim_start_matches('.').to_string(),
                            size: None,
                            source_page: Some(base_url.to_string()),
                            score: None,
                        });
                    }
                    break;
                }
            }
        }

        docs
    }

    fn extract_api_endpoints(html: &str, base_url: &str) -> Vec<ApiEndpoint> {
        let mut endpoints = Vec::new();

        let api_patterns = [
            (r#"fetch\(['"]([^'"]+)['"]"#, "GET"),
            (r#"\.get\(['"]([^'"]+)['"]"#, "GET"),
            (r#"\.post\(['"]([^'"]+)['"]"#, "POST"),
            (r#"\.put\(['"]([^'"]+)['"]"#, "PUT"),
            (r#"\.delete\(['"]([^'"]+)['"]"#, "DELETE"),
            (r#"axios\.\w+\(['"]([^'"]+)['"]"#, "GET"),
            (r#"url:\s*['"]([^'"]+)['"]"#, "GET"),
            (r#"action\s*=\s*['"]([^'"]+)['"]"#, "POST"),
        ];

        for (pattern, method) in &api_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(html) {
                    let url = &cap[1];
                    if !url.starts_with("javascript:") && !url.starts_with("#") && !url.is_empty() {
                        let full_url = Self::resolve_url(base_url, url);
                        let is_api = full_url.contains("/api/") || full_url.contains("/v1/") || full_url.contains("/v2/") || full_url.contains("/v3/") || full_url.contains("/graphql") || full_url.contains("/rest/") || full_url.ends_with(".json") || full_url.contains("?") || url.starts_with("/");
                        if is_api {
                            endpoints.push(ApiEndpoint {
                                url: full_url,
                                method: method.to_string(),
                                source: "javascript".to_string(),
                            });
                        }
                    }
                }
            }
        }

        let form_re = regex::Regex::new(r#"<form[^>]+action\s*=\s*"([^"]+)""#).unwrap();
        for cap in form_re.captures_iter(html) {
            let action = &cap[1];
            if !action.is_empty() {
                endpoints.push(ApiEndpoint {
                    url: Self::resolve_url(base_url, action),
                    method: "POST".to_string(),
                    source: "form".to_string(),
                });
            }
        }

        endpoints
    }

    fn detect_technologies(html: &str) -> Vec<String> {
        let details = Self::detect_technologies_detailed(html);
        let mut names: Vec<String> = details.iter().map(|d| d.name.clone()).collect();
        names.sort();
        names.dedup();
        names
    }

    fn detect_technologies_detailed(html: &str) -> Vec<TechnologyDetail> {
        let mut techs: HashMap<String, TechnologyDetail> = HashMap::new();
        let lower = html.to_lowercase();

        struct TechRule {
            name: &'static str,
            category: &'static str,
            icon: &'static str,
            patterns: Vec<&'static str>,
            js_globals: Vec<&'static str>,
            meta_names: Vec<&'static str>,
            css_classes: Vec<&'static str>,
            script_patterns: Vec<&'static str>,
            version_pattern: Option<&'static str>,
            min_confidence: f64,
        }

        let rules: Vec<TechRule> = vec![
            TechRule {
                name: "React",
                category: "Framework",
                icon: "⚛️",
                patterns: vec![],
                js_globals: vec!["__REACT", "React"],
                meta_names: vec![],
                css_classes: vec!["react-root", "react-app"],
                script_patterns: vec!["react.production.min.js", "react.development.js", "/react.", "react-dom"],
                version_pattern: Some(r#"react[^/]*?/([\d.]+)"#),
                min_confidence: 0.5,
            },
            TechRule {
                name: "Next.js",
                category: "Framework",
                icon: "▲",
                patterns: vec!["__next", "_next/static", "next-route-announcer"],
                js_globals: vec!["__NEXT_DATA__", "next"],
                meta_names: vec!["next-head-count"],
                css_classes: vec!["__next"],
                script_patterns: vec!["_next/static", "next/dist"],
                version_pattern: Some(r#"next/([\d.]+)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "Vue.js",
                category: "Framework",
                icon: "💚",
                patterns: vec![],
                js_globals: vec!["__VUE__", "Vue"],
                meta_names: vec![],
                css_classes: vec!["v-app", "vue-app"],
                script_patterns: vec!["vue.global.js", "vue.runtime", "/vue.", "vue.min.js"],
                version_pattern: Some(r#"vue[@/](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.5,
            },
            TechRule {
                name: "Nuxt.js",
                category: "Framework",
                icon: "💚",
                patterns: vec!["__nuxt", "__NUXT__", "nuxt"],
                js_globals: vec!["__NUXT__"],
                meta_names: vec![],
                css_classes: vec!["__nuxt"],
                script_patterns: vec!["nuxt", "_nuxt/"],
                version_pattern: Some(r#"nuxt/([\d.]+)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "Angular",
                category: "Framework",
                icon: "🔴",
                patterns: vec!["ng-version", "ng-app", "ng-controller"],
                js_globals: vec!["ng", "angular"],
                meta_names: vec![],
                css_classes: vec!["ng-binding", "ng-scope", "ng-controller"],
                script_patterns: vec!["angular.min.js", "angular.js", "/angular.", "zone.js"],
                version_pattern: Some(r#"ng-version="([\d.]+)""#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "Svelte",
                category: "Framework",
                icon: "🔥",
                patterns: vec![],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec!["svelte-"],
                script_patterns: vec!["svelte", "svelte/internal"],
                version_pattern: None,
                min_confidence: 0.5,
            },
            TechRule {
                name: "jQuery",
                category: "Library",
                icon: "📜",
                patterns: vec![],
                js_globals: vec!["jQuery", "$.fn"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["jquery.min.js", "jquery.js", "/jquery.", "jquery/"],
                version_pattern: Some(r#"jquery[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.5,
            },
            TechRule {
                name: "Bootstrap",
                category: "UI Framework",
                icon: "🅱️",
                patterns: vec![],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec!["container-fluid", "row", "col-md-", "col-lg-", "btn-primary", "navbar", "card-body"],
                script_patterns: vec!["bootstrap.min.js", "bootstrap.js", "/bootstrap/", "bootstrap/"],
                version_pattern: Some(r#"bootstrap[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.4,
            },
            TechRule {
                name: "Tailwind CSS",
                category: "UI Framework",
                icon: "🌊",
                patterns: vec![],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec!["flex-", "grid-", "bg-", "text-", "p-", "m-", "rounded-", "shadow-"],
                script_patterns: vec!["tailwindcss", "tailwind.min.css", "/tailwind."],
                version_pattern: None,
                min_confidence: 0.3,
            },
            TechRule {
                name: "WordPress",
                category: "CMS",
                icon: "📝",
                patterns: vec!["wp-content", "wp-includes", "wp-json", "wp-admin"],
                js_globals: vec!["wpApiSettings", "wp"],
                meta_names: vec![],
                css_classes: vec!["wp-block", "wordpress"],
                script_patterns: vec!["wp-includes", "wp-content", "wp-json"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Drupal",
                category: "CMS",
                icon: "💧",
                patterns: vec!["Drupal.settings", "drupal.org"],
                js_globals: vec!["Drupal"],
                meta_names: vec!["Generator"],
                css_classes: vec!["drupal"],
                script_patterns: vec!["drupal.js", "/drupal/"],
                version_pattern: Some(r#"Drupal\s+([\d.]+)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "Joomla",
                category: "CMS",
                icon: "🏗️",
                patterns: vec!["/media/jui/", "Joomla!"],
                js_globals: vec!["Joomla"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["joomla", "/media/jui/"],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Shopify",
                category: "E-Commerce",
                icon: "🛒",
                patterns: vec!["shopify.com", "Shopify.theme", "cdn.shopify.com"],
                js_globals: vec!["Shopify"],
                meta_names: vec![],
                css_classes: vec!["shopify-section"],
                script_patterns: vec!["cdn.shopify.com", "shopify"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Magento",
                category: "E-Commerce",
                icon: "🟧",
                patterns: vec!["mage-cache", "Magento_"],
                js_globals: vec!["Mage", "requirejs"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["magento", "mage/"],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Wix",
                category: "Website Builder",
                icon: "🔷",
                patterns: vec!["wix.com", "wixstatic.com", "wix-code"],
                js_globals: vec!["wixBiSession"],
                meta_names: vec![],
                css_classes: vec!["wixui"],
                script_patterns: vec!["wix", "parastorage"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Squarespace",
                category: "Website Builder",
                icon: "⬛",
                patterns: vec!["squarespace.com", "static.squarespace.com"],
                js_globals: vec!["Squarespace"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["squarespace"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Gatsby",
                category: "Framework",
                icon: "💜",
                patterns: vec!["gatsby", "___GATSBY"],
                js_globals: vec!["___GATSBY"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["gatsby", "gatsby-browser"],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Astro",
                category: "Framework",
                icon: "🚀",
                patterns: vec!["astro-island", "astro-slot", "astro-root"],
                js_globals: vec!["Astro"],
                meta_names: vec![],
                css_classes: vec!["astro-"],
                script_patterns: vec!["astro"],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Vite",
                category: "Build Tool",
                icon: "⚡",
                patterns: vec!["@vite/client", "vite/modulepreload-polyfill"],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["@vite/client", "vite/dist"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Webpack",
                category: "Build Tool",
                icon: "📦",
                patterns: vec!["webpack", "__webpack_require__"],
                js_globals: vec!["__webpack_require__"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["webpack", "bundle.js", "chunk.js"],
                version_pattern: None,
                min_confidence: 0.5,
            },
            TechRule {
                name: "Cloudflare",
                category: "CDN",
                icon: "☁️",
                patterns: vec!["cloudflare", "cf-beacon", "cf-browser-metrics"],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["cloudflare", "cdn-cgi"],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Google Analytics",
                category: "Analytics",
                icon: "📊",
                patterns: vec!["google-analytics.com", "ga('create'", "gtag('config'"],
                js_globals: vec!["ga", "gtag"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["google-analytics.com", "analytics.js", "gtag/js"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Google Tag Manager",
                category: "Analytics",
                icon: "🏷️",
                patterns: vec!["googletagmanager.com", "GTM-"],
                js_globals: vec!["dataLayer"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["googletagmanager.com/gtm.js"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Facebook Pixel",
                category: "Analytics",
                icon: "📘",
                patterns: vec!["connect.facebook.net", "fbq('init'"],
                js_globals: vec!["fbq"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["connect.facebook.net", "fbevents.js"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Hotjar",
                category: "Analytics",
                icon: "🌡️",
                patterns: vec!["static.hotjar.com", "hotjar.com"],
                js_globals: vec!["hj", "_hjSettings"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["static.hotjar.com"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Segment",
                category: "Analytics",
                icon: "🔀",
                patterns: vec!["segment.com", "cdn.segment.com"],
                js_globals: vec!["analytics"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["cdn.segment.com/analytics.js"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Intercom",
                category: "Customer Support",
                icon: "💬",
                patterns: vec!["widget.intercom.io", "intercom"],
                js_globals: vec!["Intercom"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["intercom", "widget.intercom.io"],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Zendesk",
                category: "Customer Support",
                icon: "🎧",
                patterns: vec!["zendesk.com", "zdassets.com"],
                js_globals: vec!["zE"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["zendesk", "zdassets"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "HubSpot",
                category: "Marketing",
                icon: "🧡",
                patterns: vec!["hubspot.com", "hs-analytics", "hs-scripts"],
                js_globals: vec!["_hsq"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["hubspot.com", "hs-analytics"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Mailchimp",
                category: "Marketing",
                icon: "🐵",
                patterns: vec!["mailchimp.com", "mc.us1.list-manage.com"],
                js_globals: vec!["mc4wp"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["mailchimp", "list-manage.com"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Stripe",
                category: "Payment",
                icon: "💳",
                patterns: vec!["stripe.com", "stripe.js"],
                js_globals: vec!["Stripe"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["stripe.com/v3", "stripe.js"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "PayPal",
                category: "Payment",
                icon: "💰",
                patterns: vec!["paypal.com", "paypalobjects.com"],
                js_globals: vec!["paypal"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["paypal.com", "paypalobjects.com"],
                version_pattern: None,
                min_confidence: 0.7,
            },
            TechRule {
                name: "Lodash",
                category: "Library",
                icon: "🔧",
                patterns: vec![],
                js_globals: vec!["_"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["lodash.min.js", "lodash.js", "/lodash."],
                version_pattern: Some(r#"lodash[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.5,
            },
            TechRule {
                name: "Three.js",
                category: "Library",
                icon: "🎮",
                patterns: vec![],
                js_globals: vec!["THREE"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["three.min.js", "three.js", "/three."],
                version_pattern: Some(r#"three[./](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "D3.js",
                category: "Library",
                icon: "📈",
                patterns: vec![],
                js_globals: vec!["d3"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["d3.min.js", "d3.js", "/d3.", "d3.v"],
                version_pattern: Some(r#"d3\.v(\d+)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "Chart.js",
                category: "Library",
                icon: "📉",
                patterns: vec![],
                js_globals: vec!["Chart"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["chart.min.js", "chart.js", "/chart.", "Chart.js"],
                version_pattern: Some(r#"chart\.js[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "GSAP",
                category: "Library",
                icon: "✨",
                patterns: vec![],
                js_globals: vec!["gsap", "TweenMax", "TweenLite"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["gsap.min.js", "gsap.js", "TweenMax", "TweenLite"],
                version_pattern: Some(r#"gsap[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "Ember.js",
                category: "Framework",
                icon: "🐹",
                patterns: vec![],
                js_globals: vec!["Ember"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["ember.min.js", "ember.js", "/ember."],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Backbone.js",
                category: "Framework",
                icon: "🦴",
                patterns: vec![],
                js_globals: vec!["Backbone"],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec!["backbone.min.js", "backbone.js", "/backbone."],
                version_pattern: None,
                min_confidence: 0.6,
            },
            TechRule {
                name: "Material UI",
                category: "UI Framework",
                icon: "🎨",
                patterns: vec!["MuiThemeProvider", "material-ui"],
                js_globals: vec!["MaterialUI"],
                meta_names: vec![],
                css_classes: vec!["MuiButton", "MuiPaper", "MuiTypography", "MuiGrid"],
                script_patterns: vec!["material-ui", "@mui"],
                version_pattern: None,
                min_confidence: 0.5,
            },
            TechRule {
                name: "Ant Design",
                category: "UI Framework",
                icon: "🐜",
                patterns: vec!["ant-design", "antd"],
                js_globals: vec!["antd"],
                meta_names: vec![],
                css_classes: vec!["ant-btn", "ant-input", "ant-table", "ant-modal"],
                script_patterns: vec!["antd.min.js", "antd.js", "ant-design"],
                version_pattern: Some(r#"antd[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.5,
            },
            TechRule {
                name: "Element UI",
                category: "UI Framework",
                icon: "🌿",
                patterns: vec!["element-ui"],
                js_globals: vec!["ELEMENT"],
                meta_names: vec![],
                css_classes: vec!["el-button", "el-input", "el-table", "el-form"],
                script_patterns: vec!["element-ui", "element-plus"],
                version_pattern: None,
                min_confidence: 0.5,
            },
            TechRule {
                name: "Font Awesome",
                category: "Library",
                icon: "🔤",
                patterns: vec!["fontawesome", "font-awesome"],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec!["fa-", "fas ", "far ", "fab "],
                script_patterns: vec!["fontawesome", "font-awesome", "all.min.js"],
                version_pattern: Some(r#"font-awesome[/-](\d+\.\d+[\.\d]*)"#),
                min_confidence: 0.6,
            },
            TechRule {
                name: "TypeScript",
                category: "Language",
                icon: "🔷",
                patterns: vec![],
                js_globals: vec![],
                meta_names: vec![],
                css_classes: vec![],
                script_patterns: vec![],
                version_pattern: None,
                min_confidence: 0.0,
            },
        ];

        let script_src_re = regex::Regex::new(r#"<script[^>]+src="([^"]+)""#).unwrap();
        let script_srcs: Vec<String> = script_src_re.captures_iter(html)
            .map(|cap| cap[1].to_lowercase())
            .collect();

        let link_href_re = regex::Regex::new(r#"<link[^>]+href="([^"]+)""#).unwrap();
        let link_hrefs: Vec<String> = link_href_re.captures_iter(html)
            .map(|cap| cap[1].to_lowercase())
            .collect();

        let all_external: Vec<&str> = script_srcs.iter()
            .chain(link_hrefs.iter())
            .map(|s| s.as_str())
            .collect();

        let meta_generator_re = regex::Regex::new(r#"<meta[^>]+name="generator"[^>]+content="([^"]+)""#).unwrap();
        let generator_value = meta_generator_re.captures(html).map(|cap| cap[1].to_string());

        for rule in &rules {
            let mut confidence: f64 = 0.0;
            let mut evidence: Vec<String> = Vec::new();
            let mut version: Option<String> = None;

            for pattern in &rule.patterns {
                if lower.contains(pattern) {
                    confidence += 0.35;
                    evidence.push(format!("Pattern matched: '{}'", pattern));
                }
            }

            for global in &rule.js_globals {
                let search = format!("var {} ", global);
                let search2 = format!("window.{} ", global);
                let search3 = format!("{} =", global);
                let search4 = format!("{}[", global);
                let search5 = format!("{}(", global);
                if html.contains(&search) || html.contains(&search2) || html.contains(&search3)
                    || html.contains(&search4) || html.contains(&search5) {
                    confidence += 0.4;
                    evidence.push(format!("JS global detected: '{}'", global));
                }
            }

            for meta in &rule.meta_names {
                let pattern = format!("<meta name=\"{}\"", meta);
                if lower.contains(&pattern.to_lowercase()) {
                    confidence += 0.3;
                    evidence.push(format!("Meta tag detected: '{}'", meta));
                }
            }

            let mut css_match_count = 0;
            for cls in &rule.css_classes {
                let class_pattern = format!("class=\"{}\"", cls);
                let class_pattern2 = format!("class=\"[^\"]*{}[^\"]*\"", cls.replace("-", "[-]"));
                if let Ok(re) = regex::Regex::new(&class_pattern2) {
                    if re.is_match(html) {
                        css_match_count += 1;
                    }
                } else if lower.contains(&class_pattern) || lower.contains(cls) {
                    css_match_count += 1;
                }
            }
            if css_match_count > 0 {
                let css_conf = (0.15 * css_match_count as f64).min(0.4);
                confidence += css_conf;
                evidence.push(format!("CSS classes matched: {} pattern(s)", css_match_count));
            }

            let mut script_match_count = 0;
            for sp in &rule.script_patterns {
                for ext in &all_external {
                    if ext.contains(sp) {
                        script_match_count += 1;
                        if let Some(vp) = rule.version_pattern {
                            if let Ok(re) = regex::Regex::new(vp) {
                                if let Some(cap) = re.captures(ext) {
                                    version = Some(cap[1].to_string());
                                }
                            }
                        }
                        break;
                    }
                }
                if lower.contains(sp) && !all_external.iter().any(|e| e.contains(sp)) {
                    script_match_count += 1;
                }
            }
            if script_match_count > 0 {
                confidence += 0.35;
                evidence.push(format!("Script/resource matched: {} pattern(s)", script_match_count));
            }

            if let Some(ref gen) = generator_value {
                let gen_lower = gen.to_lowercase();
                let name_lower = rule.name.to_lowercase();
                if gen_lower.contains(&name_lower) {
                    confidence += 0.5;
                    evidence.push(format!("Generator meta: '{}'", gen));
                    if version.is_none() {
                        let ver_re = regex::Regex::new(r#"(\d+\.\d+[\.\d]*)"#).unwrap();
                        if let Some(cap) = ver_re.captures(gen) {
                            version = Some(cap[1].to_string());
                        }
                    }
                }
            }

            if let Some(vp) = rule.version_pattern {
                if version.is_none() {
                    if let Ok(re) = regex::Regex::new(vp) {
                        if let Some(cap) = re.captures(html) {
                            version = Some(cap[1].to_string());
                        }
                    }
                }
            }

            if confidence >= rule.min_confidence {
                confidence = confidence.min(1.0);
                let key = rule.name.to_string();
                techs.entry(key.clone())
                    .and_modify(|existing| {
                        if confidence > existing.confidence {
                            existing.confidence = confidence;
                        }
                        for e in &evidence {
                            if !existing.evidence.contains(e) {
                                existing.evidence.push(e.clone());
                            }
                        }
                        if version.is_some() && existing.version.is_none() {
                            existing.version = version.clone();
                        }
                    })
                    .or_insert_with(|| TechnologyDetail {
                        name: key,
                        category: rule.category.to_string(),
                        version: version.clone(),
                        confidence,
                        evidence,
                        icon: rule.icon.to_string(),
                    });
            }
        }

        let mut result: Vec<TechnologyDetail> = techs.into_values().collect();
        result.sort_by(|a, b| {
            b.confidence.partial_cmp(&a.confidence).unwrap_or(Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        result
    }

    fn extract_metadata(html: &str, base_url: &str) -> PageMetadata {
        let title = Self::extract_title(html);

        let description = Self::extract_meta_content(html, "description");
        let keywords = Self::extract_meta_content(html, "keywords");
        let generator = Self::extract_meta_content(html, "generator");
        let author = Self::extract_meta_content(html, "author");
        let viewport = Self::extract_meta_content(html, "viewport");
        let robots = Self::extract_meta_content(html, "robots");

        let og_title = Self::extract_meta_property(html, "og:title");
        let og_description = Self::extract_meta_property(html, "og:description");
        let og_image = Self::extract_meta_property(html, "og:image").map(|img| Self::resolve_url(base_url, &img));
        let og_video = Self::extract_meta_property(html, "og:video").map(|v| Self::resolve_url(base_url, &v));
        let og_audio = Self::extract_meta_property(html, "og:audio").map(|a| Self::resolve_url(base_url, &a));
        let og_type = Self::extract_meta_property(html, "og:type");
        let og_site_name = Self::extract_meta_property(html, "og:site_name");

        let twitter_card = Self::extract_meta_name_or_property(html, "twitter:card");
        let twitter_title = Self::extract_meta_name_or_property(html, "twitter:title");
        let twitter_description = Self::extract_meta_name_or_property(html, "twitter:description");
        let twitter_image = Self::extract_meta_name_or_property(html, "twitter:image").map(|img| Self::resolve_url(base_url, &img));

        let canonical_re = regex::Regex::new(r#"<link[^>]+rel="canonical"[^>]+href="([^"]+)""#).unwrap();
        let canonical = canonical_re.captures(html).map(|cap| cap[1].to_string());

        PageMetadata {
            title,
            description,
            keywords,
            og_title,
            og_description,
            og_image,
            og_video,
            og_audio,
            og_type,
            og_site_name,
            twitter_card,
            twitter_title,
            twitter_description,
            twitter_image,
            canonical,
            generator,
            author,
            viewport,
            robots,
        }
    }

    fn extract_meta_name_or_property(html: &str, name: &str) -> Option<String> {
        if let Some(val) = Self::extract_meta_property(html, name) {
            return Some(val);
        }
        let pattern = format!(r#"<meta[^>]+name="{}"[^>]+content="([^"]+)""#, regex::escape(name));
        if let Ok(re) = regex::Regex::new(&pattern) {
            if let Some(cap) = re.captures(html) {
                return Some(cap[1].to_string());
            }
        }
        let pattern2 = format!(r#"<meta[^>]+content="([^"]+)"[^>]+name="{}""#, regex::escape(name));
        if let Ok(re) = regex::Regex::new(&pattern2) {
            if let Some(cap) = re.captures(html) {
                return Some(cap[1].to_string());
            }
        }
        None
    }

    fn extract_meta_content(html: &str, name: &str) -> Option<String> {
        let pattern = format!(r#"<meta[^>]+name="{}"[^>]+content="([^"]+)""#, regex::escape(name));
        if let Ok(re) = regex::Regex::new(&pattern) {
            if let Some(cap) = re.captures(html) {
                return Some(cap[1].to_string());
            }
        }
        let pattern2 = format!(r#"<meta[^>]+content="([^"]+)"[^>]+name="{}""#, regex::escape(name));
        if let Ok(re) = regex::Regex::new(&pattern2) {
            if let Some(cap) = re.captures(html) {
                return Some(cap[1].to_string());
            }
        }
        None
    }

    fn extract_meta_property(html: &str, property: &str) -> Option<String> {
        let pattern = format!(r#"<meta[^>]+property="{}"[^>]+content="([^"]+)""#, regex::escape(property));
        if let Ok(re) = regex::Regex::new(&pattern) {
            if let Some(cap) = re.captures(html) {
                return Some(cap[1].to_string());
            }
        }
        None
    }

    fn extract_html_comments(html: &str) -> Vec<String> {
        let mut comments = Vec::new();
        let mut search_from = 0;

        while let Some(start) = html[search_from..].find("<!--") {
            let comment_start = search_from + start + 4;
            if let Some(end) = html[comment_start..].find("-->") {
                let comment = html[comment_start..comment_start + end].trim().to_string();
                if !comment.is_empty() && comment.len() < 500 && !comment.starts_with("[if") && !comment.starts_with("[endif") {
                    comments.push(comment);
                }
                search_from = comment_start + end + 3;
            } else {
                break;
            }
        }

        comments
    }

    fn decode_bytes(bytes: &[u8], content_type: Option<&str>) -> String {
        let encoding = Self::detect_encoding(bytes, content_type);
        let (cow, _encoding_used, _had_errors) = encoding.decode(bytes);
        cow.into_owned()
    }

    fn detect_encoding(bytes: &[u8], content_type: Option<&str>) -> &'static encoding_rs::Encoding {
        if let Some(ct) = content_type {
            if let Some(encoding) = Self::encoding_from_content_type(ct) {
                return encoding;
            }
        }

        let preview = &bytes[..bytes.len().min(1024)];
        if let Some(encoding) = Self::encoding_from_meta(preview) {
            return encoding;
        }

        encoding_rs::UTF_8
    }

    fn encoding_from_content_type(content_type: &str) -> Option<&'static encoding_rs::Encoding> {
        let lower = content_type.to_lowercase();
        if let Some(start) = lower.find("charset=") {
            let charset_start = start + 8;
            let charset_str = &lower[charset_start..];
            let charset = charset_str
                .split(&[';', ' ', '"', '\''][..])
                .next()
                .unwrap_or("")
                .trim();
            if !charset.is_empty() {
                return encoding_rs::Encoding::for_label(charset.as_bytes());
            }
        }
        None
    }

    fn encoding_from_meta(html: &[u8]) -> Option<&'static encoding_rs::Encoding> {
        let html_str = String::from_utf8_lossy(html);
        let lower = html_str.to_lowercase();

        let mut search_from = 0;
        while let Some(start) = lower[search_from..].find("<meta") {
            let meta_start = search_from + start;
            let meta_content = &lower[meta_start..];
            if let Some(end) = meta_content.find('>') {
                let meta_tag = &meta_content[..end];
                if let Some(charset_pos) = meta_tag.find("charset=") {
                    let charset_start = charset_pos + 8;
                    let charset_str = &meta_tag[charset_start..];
                    let charset = charset_str
                        .split(&['"', '\'', ' ', ';', '>'][..])
                        .next()
                        .unwrap_or("")
                        .trim();
                    if !charset.is_empty() {
                        return encoding_rs::Encoding::for_label(charset.as_bytes());
                    }
                }

                if let Some(content_pos) = meta_tag.find("content=\"text/html;") {
                    let content_str = &meta_tag[content_pos..];
                    if let Some(charset_pos) = content_str.find("charset=") {
                        let charset_start = charset_pos + 8;
                        let charset_str = &content_str[charset_start..];
                        let charset = charset_str
                            .split(&['"', '\'', ' ', ';'][..])
                            .next()
                            .unwrap_or("")
                            .trim();
                        if !charset.is_empty() {
                            return encoding_rs::Encoding::for_label(charset.as_bytes());
                        }
                    }
                }

                search_from = meta_start + end + 1;
            } else {
                break;
            }

            if search_from > 4096 {
                break;
            }
        }

        None
    }

    pub fn export_result(result: &WebCrawlerResult, config: &ExportConfig) -> Result<String> {
        let mut data = serde_json::Map::new();

        data.insert("start_url".to_string(), serde_json::Value::String(result.start_url.clone()));
        data.insert("pages_crawled".to_string(), serde_json::Value::Number(serde_json::Number::from(result.pages_crawled)));
        data.insert("total_links".to_string(), serde_json::Value::Number(serde_json::Number::from(result.total_links)));

        if config.include_links {
            let links: Vec<serde_json::Value> = result.links.iter().map(|l| {
                let mut m = serde_json::Map::new();
                m.insert("url".to_string(), serde_json::Value::String(l.url.clone()));
                m.insert("status_code".to_string(), serde_json::Value::Number(serde_json::Number::from(l.status_code)));
                if let Some(ref title) = l.title { m.insert("title".to_string(), serde_json::Value::String(title.clone())); }
                m.insert("depth".to_string(), serde_json::Value::Number(serde_json::Number::from(l.depth)));
                if let Some(ref ct) = l.content_type { m.insert("content_type".to_string(), serde_json::Value::String(ct.clone())); }
                if let Some(rt) = l.response_time_ms { m.insert("response_time_ms".to_string(), serde_json::Value::Number(serde_json::Number::from(rt))); }
                if let Some(wc) = l.word_count { m.insert("word_count".to_string(), serde_json::Value::Number(serde_json::Number::from(wc))); }
                if let Some(s) = l.score { m.insert("score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(s).unwrap_or(serde_json::Number::from(0)))); }
                serde_json::Value::Object(m)
            }).collect();
            data.insert("links".to_string(), serde_json::Value::Array(links));
        }

        if config.include_emails && !result.emails.is_empty() {
            let emails: Vec<serde_json::Value> = result.emails.iter().map(|e| serde_json::Value::String(e.clone())).collect();
            data.insert("emails".to_string(), serde_json::Value::Array(emails));
        }

        if config.include_resources {
            let resource_sections = [
                ("js_files", &result.js_files),
                ("images", &result.images),
                ("css_files", &result.css_files),
                ("fonts", &result.fonts),
                ("documents", &result.documents),
                ("videos", &result.videos),
                ("audio_files", &result.audio_files),
            ];
            for (key, resources) in &resource_sections {
                if !resources.is_empty() {
                    let items: Vec<serde_json::Value> = resources.iter().map(|r| {
                        let mut m = serde_json::Map::new();
                        m.insert("url".to_string(), serde_json::Value::String(r.url.clone()));
                        m.insert("resource_type".to_string(), serde_json::Value::String(r.resource_type.clone()));
                        if let Some(ref sp) = r.source_page { m.insert("source_page".to_string(), serde_json::Value::String(sp.clone())); }
                        if let Some(s) = r.score { m.insert("score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(s).unwrap_or(serde_json::Number::from(0)))); }
                        serde_json::Value::Object(m)
                    }).collect();
                    data.insert(key.to_string(), serde_json::Value::Array(items));
                }
            }
        }

        if config.include_apis && !result.api_endpoints.is_empty() {
            let apis: Vec<serde_json::Value> = result.api_endpoints.iter().map(|a| {
                let mut m = serde_json::Map::new();
                m.insert("url".to_string(), serde_json::Value::String(a.url.clone()));
                m.insert("method".to_string(), serde_json::Value::String(a.method.clone()));
                m.insert("source".to_string(), serde_json::Value::String(a.source.clone()));
                serde_json::Value::Object(m)
            }).collect();
            data.insert("api_endpoints".to_string(), serde_json::Value::Array(apis));
        }

        if config.include_metadata {
            let mut meta = serde_json::Map::new();
            if let Some(ref t) = result.metadata.title { meta.insert("title".to_string(), serde_json::Value::String(t.clone())); }
            if let Some(ref d) = result.metadata.description { meta.insert("description".to_string(), serde_json::Value::String(d.clone())); }
            if let Some(ref k) = result.metadata.keywords { meta.insert("keywords".to_string(), serde_json::Value::String(k.clone())); }
            if let Some(ref g) = result.metadata.generator { meta.insert("generator".to_string(), serde_json::Value::String(g.clone())); }
            if let Some(ref a) = result.metadata.author { meta.insert("author".to_string(), serde_json::Value::String(a.clone())); }
            data.insert("metadata".to_string(), serde_json::Value::Object(meta));
        }

        if config.include_technologies && !result.technologies.is_empty() {
            let techs: Vec<serde_json::Value> = result.technologies.iter().map(|t| serde_json::Value::String(t.clone())).collect();
            data.insert("technologies".to_string(), serde_json::Value::Array(techs));
        }

        if config.include_security {
            let mut sec = serde_json::Map::new();
            sec.insert("has_https".to_string(), serde_json::Value::Bool(result.security_info.has_https));
            sec.insert("has_hsts".to_string(), serde_json::Value::Bool(result.security_info.has_hsts));
            sec.insert("has_csp".to_string(), serde_json::Value::Bool(result.security_info.has_csp));
            sec.insert("security_score".to_string(), serde_json::Value::Number(serde_json::Number::from(result.security_info.security_score)));
            if let Some(ref s) = result.security_info.server_header { sec.insert("server".to_string(), serde_json::Value::String(s.clone())); }
            data.insert("security_info".to_string(), serde_json::Value::Object(sec));
        }

        if config.include_directory && !result.directory_entries.is_empty() {
            let dirs: Vec<serde_json::Value> = result.directory_entries.iter().map(|d| {
                let mut m = serde_json::Map::new();
                m.insert("path".to_string(), serde_json::Value::String(d.path.clone()));
                m.insert("full_url".to_string(), serde_json::Value::String(d.full_url.clone()));
                m.insert("status_code".to_string(), serde_json::Value::Number(serde_json::Number::from(d.status_code)));
                m.insert("is_directory".to_string(), serde_json::Value::Bool(d.is_directory));
                serde_json::Value::Object(m)
            }).collect();
            data.insert("directory_entries".to_string(), serde_json::Value::Array(dirs));
        }

        if let Some(ref ab) = result.antibot_detection {
            let mut ab_map = serde_json::Map::new();
            ab_map.insert("detected".to_string(), serde_json::Value::Bool(ab.detected));
            if let Some(ref pt) = ab.protection_type { ab_map.insert("protection_type".to_string(), serde_json::Value::String(pt.clone())); }
            ab_map.insert("confidence".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(ab.confidence).unwrap_or(serde_json::Number::from(0))));
            data.insert("antibot_detection".to_string(), serde_json::Value::Object(ab_map));
        }

        if !result.subdomains.is_empty() {
            let subs: Vec<serde_json::Value> = result.subdomains.iter().map(|s| serde_json::Value::String(s.clone())).collect();
            data.insert("subdomains".to_string(), serde_json::Value::Array(subs));
        }

        match config.format.as_str() {
            "csv" => {
                let dq = '"';
                let esc = "\"\"".to_string();
                let mut csv_rows: Vec<String> = Vec::new();
                if config.include_links {
                    csv_rows.push("Type,URL,Status,Detail1,Detail2".to_string());
                    for link in &result.links {
                        csv_rows.push(format!("link,\"{}\",{},\"{}\",\"{}\"",
                            link.url.replace(dq, &esc),
                            link.status_code,
                            link.title.as_deref().unwrap_or("").replace(dq, &esc),
                            link.content_type.as_deref().unwrap_or("").replace(dq, &esc)
                        ));
                    }
                }
                if config.include_resources {
                    let resource_sections: Vec<(&str, &Vec<ResourceInfo>)> = vec![
                        ("image", &result.images),
                        ("js", &result.js_files),
                        ("css", &result.css_files),
                        ("video", &result.videos),
                        ("audio", &result.audio_files),
                        ("font", &result.fonts),
                        ("document", &result.documents),
                    ];
                    for (rtype, resources) in resource_sections {
                        for r in resources {
                            csv_rows.push(format!("{},\"{}\",,\"{}\",\"\"",
                                rtype,
                                r.url.replace(dq, &esc),
                                r.resource_type.replace(dq, &esc)
                            ));
                        }
                    }
                }
                if config.include_emails {
                    for email in &result.emails {
                        csv_rows.push(format!("email,\"{}\",,,", email.replace(dq, &esc)));
                    }
                }
                let newline = String::from_utf8(vec![10]).unwrap();
                Ok(csv_rows.join(&newline))
            }
            _ => {
                serde_json::to_string_pretty(&serde_json::Value::Object(data))
                    .map_err(|e| ToolError::ExecutionError(format!("JSON export error: {}", e)))
            }
        }
    }
}

async fn download_resource(client: &reqwest::Client, url: &str, save_dir: &str, subdir: &str) -> std::result::Result<DownloadResult, ToolError> {
    let response = client.get(url).send().await
        .map_err(|e| ToolError::ExecutionError(format!("Download failed for {}: {}", url, e)))?;

    let status = response.status();
    if !status.is_success() {
        return Ok(DownloadResult {
            url: url.to_string(),
            file_path: String::new(),
            file_size: 0,
            success: false,
            error: Some(format!("HTTP {}", status.as_u16())),
        });
    }

    let content_type = response.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let bytes = response.bytes().await
        .map_err(|e| ToolError::ExecutionError(format!("Read body failed: {}", e)))?;

    let filename = generate_filename(url, &content_type);
    let file_path = format!("{}/{}", save_dir, subdir);

    tokio::fs::create_dir_all(&file_path).await
        .map_err(|e| ToolError::ExecutionError(format!("Create dir failed: {}", e)))?;

    let full_path = format!("{}/{}", file_path, filename);
    let file_size = bytes.len() as u64;

    tokio::fs::write(&full_path, &bytes).await
        .map_err(|e| ToolError::ExecutionError(format!("Write file failed: {}", e)))?;

    Ok(DownloadResult {
        url: url.to_string(),
        file_path: full_path,
        file_size,
        success: true,
        error: None,
    })
}

fn generate_filename(url: &str, content_type: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        if let Some(name) = path.rsplit('/').next() {
            if !name.is_empty() && name.contains('.') {
                return name.to_string();
            }
        }
    }

    let ext = match content_type {
        ct if ct.contains("image/jpeg") => "jpg",
        ct if ct.contains("image/png") => "png",
        ct if ct.contains("image/gif") => "gif",
        ct if ct.contains("image/svg") => "svg",
        ct if ct.contains("image/webp") => "webp",
        ct if ct.contains("javascript") => "js",
        ct if ct.contains("css") => "css",
        ct if ct.contains("font/woff2") => "woff2",
        ct if ct.contains("font/woff") => "woff",
        ct if ct.contains("font/ttf") => "ttf",
        ct if ct.contains("video/") => "mp4",
        ct if ct.contains("audio/") => "mp3",
        ct if ct.contains("pdf") => "pdf",
        ct if ct.contains("html") => "html",
        _ => "bin",
    };

    let hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    };

    format!("resource_{}.{}", hash, ext)
}

async fn generate_mirror_index(save_dir: &str, results: &[DownloadResult]) -> std::result::Result<String, std::io::Error> {
    let mut html = String::from(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Site Mirror</title><style>body{font-family:sans-serif;margin:20px}h1{color:#333}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#f5f5f5}.success{color:green}.failed{color:red}</style></head><body><h1>Site Mirror Index</h1><table><tr><th>File</th><th>Size</th><th>Status</th></tr>"#);

    for result in results {
        if result.success {
            let rel_path = result.file_path.replace(save_dir, ".");
            html.push_str(&format!(
                r#"<tr><td><a href="{}">{}</a></td><td>{}</td><td class="success">OK</td></tr>"#,
                rel_path,
                result.url,
                format_size(result.file_size)
            ));
        } else {
            html.push_str(&format!(
                r#"<tr><td>{}</td><td>-</td><td class="failed">FAILED</td></tr>"#,
                result.url
            ));
        }
    }

    html.push_str("</table></body></html>");
    Ok(html)
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 { format!("{} B", bytes) }
    else if bytes < 1024 * 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
    else if bytes < 1024 * 1024 * 1024 { format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0)) }
    else { format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)) }
}
