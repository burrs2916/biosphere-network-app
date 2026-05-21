use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialCrawlConfig {
    pub platform: String,
    pub target: String,
    pub max_items: usize,
    pub include_comments: bool,
    pub include_media: bool,
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub keywords: Vec<String>,
    pub cookie: String,
    pub proxy_url: String,
    pub search_query: String,
    pub search_mode: bool,
    pub proxy_pool: SocialProxyPool,
    pub ip_block_detection: IpBlockDetection,
    pub persistence: PersistenceConfig,
    pub rate_limit: RateLimitConfig,
    pub login_config: LoginConfig,
    pub media_download: MediaDownloadConfig,
}

impl Default for SocialCrawlConfig {
    fn default() -> Self {
        Self {
            platform: "xiaohongshu".to_string(),
            target: String::new(),
            max_items: 50,
            include_comments: false,
            include_media: false,
            date_from: None,
            date_to: None,
            keywords: Vec::new(),
            cookie: String::new(),
            proxy_url: String::new(),
            search_query: String::new(),
            search_mode: false,
            proxy_pool: SocialProxyPool::default(),
            ip_block_detection: IpBlockDetection::default(),
            persistence: PersistenceConfig::default(),
            rate_limit: RateLimitConfig::default(),
            login_config: LoginConfig::default(),
            media_download: MediaDownloadConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialProxyPool {
    pub proxies: Vec<String>,
    pub rotation_mode: String,
    pub max_failures: u32,
    pub validate_on_start: bool,
    pub health_check_url: String,
}

impl Default for SocialProxyPool {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            rotation_mode: "round_robin".to_string(),
            max_failures: 3,
            validate_on_start: false,
            health_check_url: "https://httpbin.org/ip".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockDetection {
    pub enabled: bool,
    pub block_status_codes: Vec<u16>,
    pub block_keywords: Vec<String>,
    pub auto_switch_proxy: bool,
    pub max_retries: usize,
    pub retry_delay_ms: u64,
}

impl Default for IpBlockDetection {
    fn default() -> Self {
        Self {
            enabled: true,
            block_status_codes: vec![403, 429, 503],
            block_keywords: vec![
                "access denied".to_string(),
                "blocked".to_string(),
                "rate limit".to_string(),
                "too many requests".to_string(),
                "ip banned".to_string(),
                "频繁".to_string(),
                "限制".to_string(),
                "验证".to_string(),
                "滑块".to_string(),
            ],
            auto_switch_proxy: true,
            max_retries: 3,
            retry_delay_ms: 2000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub format: String,
    pub save_dir: String,
    pub save_raw_html: bool,
    pub save_raw_json: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            format: "json".to_string(),
            save_dir: String::new(),
            save_raw_html: false,
            save_raw_json: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst_size: usize,
    pub delay_between_requests_ms: u64,
    pub jitter_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 2.0,
            burst_size: 5,
            delay_between_requests_ms: 500,
            jitter_ms: 200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginConfig {
    pub login_mode: String,
    pub cookie_string: String,
    pub user_agent: String,
    pub stealth_mode: bool,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            login_mode: "cookie".to_string(),
            cookie_string: String::new(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            stealth_mode: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaDownloadConfig {
    pub enabled: bool,
    pub save_dir: String,
    pub max_concurrent: usize,
    pub max_file_size_mb: u64,
    pub include_images: bool,
    pub include_videos: bool,
    pub include_audio: bool,
    pub rename_pattern: String,
}

impl Default for MediaDownloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            save_dir: String::new(),
            max_concurrent: 3,
            max_file_size_mb: 100,
            include_images: true,
            include_videos: true,
            include_audio: true,
            rename_pattern: "{platform}_{id}_{index}".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SocialCrawlResult {
    pub platform: String,
    pub target: String,
    pub posts: Vec<SocialPost>,
    pub users: Vec<SocialUser>,
    pub comments: Vec<SocialComment>,
    pub media_downloads: Vec<MediaDownloadResult>,
    pub search_results: Vec<SocialPost>,
    pub total_items: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub duration_ms: u64,
    pub ip_block_events: Vec<IpBlockEvent>,
    pub proxy_stats: ProxyStats,
    pub persistence_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialPost {
    pub id: String,
    pub title: String,
    pub content: String,
    pub author: String,
    pub author_id: String,
    pub likes: u64,
    pub comments_count: u64,
    pub shares: u64,
    pub views: u64,
    pub url: String,
    pub created_at: String,
    pub media_urls: Vec<String>,
    pub tags: Vec<String>,
    pub location: String,
    pub is_original: bool,
    pub crawl_time: String,
}

impl Default for SocialPost {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            content: String::new(),
            author: String::new(),
            author_id: String::new(),
            likes: 0,
            comments_count: 0,
            shares: 0,
            views: 0,
            url: String::new(),
            created_at: String::new(),
            media_urls: Vec::new(),
            tags: Vec::new(),
            location: String::new(),
            is_original: true,
            crawl_time: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct SocialUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub bio: String,
    pub avatar_url: String,
    pub followers: u64,
    pub following: u64,
    pub posts_count: usize,
    pub verified: bool,
    pub verified_type: String,
    pub url: String,
    pub gender: String,
    pub location: String,
    pub registered_at: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct SocialComment {
    pub id: String,
    pub post_id: String,
    pub content: String,
    pub author: String,
    pub author_id: String,
    pub likes: u64,
    pub created_at: String,
    pub reply_to: String,
    pub sub_comments: Vec<SocialComment>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaDownloadResult {
    pub url: String,
    pub file_path: String,
    pub file_size: u64,
    pub media_type: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockEvent {
    pub timestamp: String,
    pub url: String,
    pub status_code: u16,
    pub detection_type: String,
    pub proxy_used: String,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStats {
    pub total_requests: usize,
    pub proxy_requests: usize,
    pub direct_requests: usize,
    pub proxy_failures: usize,
    pub ip_block_count: usize,
    pub proxy_rotations: usize,
}

pub const SUPPORTED_PLATFORMS: &[(&str, &str, &str)] = &[
    ("xiaohongshu", "小红书", "https://www.xiaohongshu.com"),
    ("douyin", "抖音", "https://www.douyin.com"),
    ("bilibili", "B站", "https://www.bilibili.com"),
    ("weibo", "微博", "https://weibo.com"),
    ("kuaishou", "快手", "https://www.kuaishou.com"),
    ("tieba", "百度贴吧", "https://tieba.baidu.com"),
    ("zhihu", "知乎", "https://www.zhihu.com"),
];

pub fn detect_ip_block(status_code: u16, body: &str, config: &IpBlockDetection) -> bool {
    if !config.enabled {
        return false;
    }

    if config.block_status_codes.contains(&status_code) {
        return true;
    }

    let body_lower = body.to_lowercase();
    for keyword in &config.block_keywords {
        if body_lower.contains(&keyword.to_lowercase()) {
            return true;
        }
    }

    false
}

pub fn persist_result(result: &SocialCrawlResult, config: &PersistenceConfig) -> std::result::Result<Option<String>, String> {
    if !config.enabled {
        return Ok(None);
    }

    let save_dir = if config.save_dir.is_empty() {
        std::env::temp_dir().join("biosphere_social_crawler").to_string_lossy().to_string()
    } else {
        config.save_dir.clone()
    };

    std::fs::create_dir_all(&save_dir)
        .map_err(|e| format!("Create dir failed: {}", e))?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    match config.format.as_str() {
        "csv" => {
            let path = format!("{}/{}_{}_{}.csv", save_dir, result.platform, result.target, timestamp);
            let mut csv_content = String::new();
            csv_content.push_str("type,id,title,content,author,likes,url\n");
            for post in &result.posts {
                csv_content.push_str(&format!("post,\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\"\n",
                    post.id, post.title.replace('"', "\"\""), post.content.replace('"', "\"\""),
                    post.author.replace('"', "\"\""), post.likes, post.url));
            }
            for comment in &result.comments {
                csv_content.push_str(&format!("comment,\"{}\",,\"{}\",\"{}\",{},\n",
                    comment.id, comment.content.replace('"', "\"\""),
                    comment.author.replace('"', "\"\""), comment.likes));
            }
            std::fs::write(&path, csv_content).map_err(|e| format!("Write CSV failed: {}", e))?;
            Ok(Some(path))
        }
        "jsonl" => {
            let path = format!("{}/{}_{}_{}.jsonl", save_dir, result.platform, result.target, timestamp);
            let mut lines = Vec::new();
            for post in &result.posts {
                if let Ok(json) = serde_json::to_string(post) {
                    lines.push(json);
                }
            }
            for comment in &result.comments {
                if let Ok(json) = serde_json::to_string(comment) {
                    lines.push(json);
                }
            }
            std::fs::write(&path, lines.join("\n")).map_err(|e| format!("Write JSONL failed: {}", e))?;
            Ok(Some(path))
        }
        _ => {
            let path = format!("{}/{}_{}_{}.json", save_dir, result.platform, result.target, timestamp);
            let json = serde_json::to_string_pretty(result).map_err(|e| format!("Serialize failed: {}", e))?;
            std::fs::write(&path, json).map_err(|e| format!("Write JSON failed: {}", e))?;
            Ok(Some(path))
        }
    }
}
