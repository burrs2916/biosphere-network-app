use crate::core::{Result, ToolError};
use super::config::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use tokio::sync::Semaphore;

struct ProxyManager {
    proxies: Vec<String>,
    current_index: AtomicUsize,
    rotation_mode: String,
    failed_proxies: Arc<tokio::sync::Mutex<HashSet<String>>>,
    max_failures: u32,
}

impl ProxyManager {
    fn new(config: &SocialProxyPool) -> Self {
        Self {
            proxies: config.proxies.iter().filter(|p| !p.is_empty()).cloned().collect(),
            current_index: AtomicUsize::new(0),
            rotation_mode: config.rotation_mode.clone(),
            failed_proxies: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            max_failures: config.max_failures,
        }
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    fn get_next(&self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }
        match self.rotation_mode.as_str() {
            "random" => {
                let idx = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as usize % self.proxies.len();
                Some(self.proxies[idx].clone())
            }
            _ => {
                let idx = self.current_index.fetch_add(1, AtomicOrdering::Relaxed) % self.proxies.len();
                Some(self.proxies[idx].clone())
            }
        }
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

    async fn mark_failed(&self, proxy: &str) {
        let mut failed = self.failed_proxies.lock().await;
        let count = failed.iter().filter(|p| *p == proxy).count() as u32;
        if count >= self.max_failures {
            failed.insert(proxy.to_string());
        }
    }

    async fn mark_success(&self, proxy: &str) {
        let mut failed = self.failed_proxies.lock().await;
        failed.remove(proxy);
    }
}

fn extract_capture(pattern: &str, text: &str) -> String {
    regex::Regex::new(pattern)
        .ok()
        .and_then(|re| re.captures(text))
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

fn extract_all_captures(pattern: &str, text: &str) -> Vec<String> {
    let re = match regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    re.captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn now_timestamp_str() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

pub struct SocialCrawler {
    client: reqwest::Client,
    proxy_manager: Option<ProxyManager>,
}

impl SocialCrawler {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .build()
            .unwrap_or_default();
        Self { client, proxy_manager: None }
    }

    pub fn with_proxy_pool(config: &SocialCrawlConfig) -> Self {
        let ua = &config.login_config.user_agent;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(ua.as_str())
            .build()
            .unwrap_or_default();
        let proxy_manager = if !config.proxy_pool.proxies.is_empty() {
            Some(ProxyManager::new(&config.proxy_pool))
        } else {
            None
        };
        Self { client, proxy_manager }
    }

    pub async fn crawl(&self, config: &SocialCrawlConfig) -> Result<SocialCrawlResult> {
        let start = std::time::Instant::now();
        let mut result = SocialCrawlResult::default();
        result.platform = config.platform.clone();
        result.target = config.target.clone();

        if config.search_mode && !config.search_query.is_empty() {
            self.crawl_search(config, &mut result).await?;
        } else {
            match config.platform.as_str() {
                "xiaohongshu" | "xhs" => self.crawl_xiaohongshu(config, &mut result).await?,
                "douyin" | "tiktok" => self.crawl_douyin(config, &mut result).await?,
                "bilibili" => self.crawl_bilibili(config, &mut result).await?,
                "weibo" => self.crawl_weibo(config, &mut result).await?,
                "kuaishou" => self.crawl_kuaishou(config, &mut result).await?,
                "tieba" => self.crawl_tieba(config, &mut result).await?,
                "zhihu" => self.crawl_zhihu(config, &mut result).await?,
                _ => return Err(ToolError::ExecutionError(format!("Unsupported platform: {}", config.platform))),
            }
        }

        if config.include_comments && !result.posts.is_empty() {
            self.crawl_comments(config, &mut result).await?;
        }

        if config.media_download.enabled || config.include_media {
            self.download_media(config, &mut result).await?;
        }

        if config.persistence.enabled {
            match persist_result(&result, &config.persistence) {
                Ok(path) => result.persistence_path = path,
                Err(e) => result.errors.push(format!("Persistence failed: {}", e)),
            }
        }

        result.total_items = result.posts.len() + result.users.len() + result.comments.len();
        result.duration_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    async fn crawl_search(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let query = urlencoding::encode(&config.search_query);
        match config.platform.as_str() {
            "xiaohongshu" | "xhs" => {
                let url = format!("https://www.xiaohongshu.com/search_result?keyword={}&source=web_search_result_notes", query);
                let html = self.fetch_with_retry(&url, "https://www.xiaohongshu.com/", config).await?;
                let note_ids = extract_all_captures(r#"note_id":"([^"]+)""#, &html);
                for note_id in note_ids.iter().take(config.max_items) {
                    result.search_results.push(SocialPost {
                        id: note_id.clone(),
                        url: format!("https://www.xiaohongshu.com/explore/{}", note_id),
                        crawl_time: now_timestamp_str(),
                        ..Default::default()
                    });
                }
            }
            "douyin" | "tiktok" => {
                let url = format!("https://www.douyin.com/search/{}", query);
                let html = self.fetch_with_retry(&url, "https://www.douyin.com/", config).await?;
                let aweme_ids = extract_all_captures(r#"aweme_id":"([^"]+)""#, &html);
                for aweme_id in aweme_ids.iter().take(config.max_items) {
                    result.search_results.push(SocialPost {
                        id: aweme_id.clone(),
                        url: format!("https://www.douyin.com/video/{}", aweme_id),
                        crawl_time: now_timestamp_str(),
                        ..Default::default()
                    });
                }
            }
            "bilibili" => {
                let api_url = format!("https://api.bilibili.com/x/web-interface/search/type?search_type=video&keyword={}&page=1&page_size={}", query, config.max_items.min(50));
                let text = self.fetch_with_retry(&api_url, "https://www.bilibili.com/", config).await?;
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(results) = json.pointer("/data/result").and_then(|v| v.as_array()) {
                        for item in results.iter().take(config.max_items) {
                            let bvid = item.get("bvid").and_then(|v| v.as_str()).unwrap_or("");
                            result.search_results.push(SocialPost {
                                id: bvid.to_string(),
                                title: item.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                author: item.get("author").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                url: format!("https://www.bilibili.com/video/{}", bvid),
                                crawl_time: now_timestamp_str(),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            "weibo" => {
                let api_url = format!("https://m.weibo.cn/api/container/getIndex?containerid=100103type%3D1%26q%3D{}&page_type=searchall", query);
                let text = self.fetch_with_retry(&api_url, "https://m.weibo.cn/", config).await?;
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(cards) = json.pointer("/data/cards").and_then(|v| v.as_array()) {
                        for card in cards.iter().take(config.max_items) {
                            if let Some(mblog) = card.get("mblog") {
                                let mid = mblog.get("mid").and_then(|v| v.as_str()).unwrap_or("");
                                result.search_results.push(SocialPost {
                                    id: mid.to_string(),
                                    content: mblog.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    author: mblog.get("user").and_then(|u| u.get("screen_name")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    url: format!("https://m.weibo.cn/detail/{}", mid),
                                    crawl_time: now_timestamp_str(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
            "zhihu" => {
                let api_url = format!("https://www.zhihu.com/api/v4/search_v3?t=general&q={}&correction=1&offset=0&limit={}", query, config.max_items.min(20));
                let text = self.fetch_with_retry(&api_url, "https://www.zhihu.com/", config).await?;
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        for item in data.iter().take(config.max_items) {
                            if let Some(obj) = item.get("object") {
                                let id = obj.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                                result.search_results.push(SocialPost {
                                    id: id.to_string(),
                                    title: obj.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    content: obj.get("excerpt").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    url: obj.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    crawl_time: now_timestamp_str(),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
            "tieba" => {
                let url = format!("https://tieba.baidu.com/f?kw={}", query);
                let html = self.fetch_with_retry(&url, "", config).await?;
                let thread_ids = extract_all_captures(r#"/p/(\d+)""#, &html);
                for tid in thread_ids.iter().take(config.max_items) {
                    result.search_results.push(SocialPost {
                        id: tid.clone(),
                        url: format!("https://tieba.baidu.com/p/{}", tid),
                        crawl_time: now_timestamp_str(),
                        ..Default::default()
                    });
                }
            }
            "kuaishou" => {
                let url = format!("https://www.kuaishou.com/search/video?searchKey={}", query);
                let html = self.fetch_with_retry(&url, "https://www.kuaishou.com/", config).await?;
                let video_ids = extract_all_captures(r#"photoId":"([^"]+)""#, &html);
                for vid in video_ids.iter().take(config.max_items) {
                    result.search_results.push(SocialPost {
                        id: vid.clone(),
                        url: format!("https://www.kuaishou.com/short-video/{}", vid),
                        crawl_time: now_timestamp_str(),
                        ..Default::default()
                    });
                }
            }
            _ => return Err(ToolError::ExecutionError(format!("Search not supported for: {}", config.platform))),
        }
        Ok(())
    }

    async fn crawl_comments(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let posts_to_crawl: Vec<SocialPost> = result.posts.iter().take(10).cloned().collect();
        for post in posts_to_crawl {
            let comments = self.fetch_comments_for_post(&post, config).await?;
            result.comments.extend(comments);
            self.rate_limit_delay(config).await;
        }
        Ok(())
    }

    async fn fetch_comments_for_post(&self, post: &SocialPost, config: &SocialCrawlConfig) -> Result<Vec<SocialComment>> {
        let mut comments = Vec::new();
        match config.platform.as_str() {
            "bilibili" => {
                let aid = extract_capture(r"avid|aid", &post.id);
                if !aid.is_empty() || !post.id.is_empty() {
                    let api_url = format!("https://api.bilibili.com/x/v2/reply?type=1&oid={}&pn=1&ps={}", post.id, config.max_items.min(20));
                    if let Ok(text) = self.fetch_with_retry(&api_url, "https://www.bilibili.com/", config).await {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(replies) = json.pointer("/data/replies").and_then(|v| v.as_array()) {
                                for reply in replies.iter().take(config.max_items) {
                                    let rpid = reply.get("rpid").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let mut comment = SocialComment {
                                        id: rpid.to_string(),
                                        post_id: post.id.clone(),
                                        content: reply.get("content").and_then(|c| c.get("message")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        author: reply.get("member").and_then(|m| m.get("uname")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        likes: reply.get("like").and_then(|v| v.as_u64()).unwrap_or(0),
                                        created_at: reply.get("ctime").and_then(|v| v.as_u64()).map(|t| t.to_string()).unwrap_or_default(),
                                        ..Default::default()
                                    };
                                    if let Some(sub_replies) = reply.get("replies").and_then(|v| v.as_array()) {
                                        for sub in sub_replies.iter().take(5) {
                                            let sub_rpid = sub.get("rpid").and_then(|v| v.as_u64()).unwrap_or(0);
                                            comment.sub_comments.push(SocialComment {
                                                id: sub_rpid.to_string(),
                                                post_id: post.id.clone(),
                                                content: sub.get("content").and_then(|c| c.get("message")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                                author: sub.get("member").and_then(|m| m.get("uname")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                                likes: sub.get("like").and_then(|v| v.as_u64()).unwrap_or(0),
                                                reply_to: rpid.to_string(),
                                                ..Default::default()
                                            });
                                        }
                                    }
                                    comments.push(comment);
                                }
                            }
                        }
                    }
                }
            }
            "weibo" => {
                if !post.id.is_empty() {
                    let api_url = format!("https://m.weibo.cn/api/comments/show?id={}&page=1", post.id);
                    if let Ok(text) = self.fetch_with_retry(&api_url, "https://m.weibo.cn/", config).await {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(data) = json.pointer("/data").and_then(|v| v.as_array()) {
                                for item in data.iter().take(config.max_items) {
                                    let cid = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                                    comments.push(SocialComment {
                                        id: cid.to_string(),
                                        post_id: post.id.clone(),
                                        content: item.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        author: item.get("user").and_then(|u| u.get("screen_name")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        likes: item.get("like_count").and_then(|v| v.as_u64()).unwrap_or(0),
                                        created_at: item.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "zhihu" => {
                if !post.id.is_empty() {
                    let api_url = format!("https://www.zhihu.com/api/v4/answers/{}/comments?limit={}&offset=0", post.id, config.max_items.min(20));
                    if let Ok(text) = self.fetch_with_retry(&api_url, "https://www.zhihu.com/", config).await {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                                for item in data.iter().take(config.max_items) {
                                    let cid = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                                    comments.push(SocialComment {
                                        id: cid.to_string(),
                                        post_id: post.id.clone(),
                                        content: item.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        author: item.get("author").and_then(|a| a.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                        likes: item.get("voteup_count").and_then(|v| v.as_u64()).unwrap_or(0),
                                        created_at: item.get("created_time").and_then(|v| v.as_u64()).map(|t| t.to_string()).unwrap_or_default(),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "tieba" => {
                if !post.id.is_empty() {
                    let url = format!("https://tieba.baidu.com/p/{}", post.id);
                    if let Ok(html) = self.fetch_with_retry(&url, "", config).await {
                        let comment_contents = extract_all_captures(r#"class="d_post_content j_d_post_content ">([\s\S]*?)</div>"#, &html);
                        let comment_authors = extract_all_captures(r#"class="p_author_name j_user_card"[^>]*>([^<]+)"#, &html);
                        for (i, content) in comment_contents.iter().enumerate().take(config.max_items) {
                            comments.push(SocialComment {
                                id: format!("{}_{}", post.id, i),
                                post_id: post.id.clone(),
                                content: content.trim().to_string(),
                                author: comment_authors.get(i).cloned().unwrap_or_default(),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(comments)
    }

    async fn download_media(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let save_dir = if config.media_download.save_dir.is_empty() {
            std::env::temp_dir().join("biosphere_social_media").to_string_lossy().to_string()
        } else {
            config.media_download.save_dir.clone()
        };

        std::fs::create_dir_all(&save_dir)
            .map_err(|e| ToolError::ExecutionError(format!("Create media dir failed: {}", e)))?;

        let mut media_urls: Vec<(String, String)> = Vec::new();
        for post in &result.posts {
            for (idx, url) in post.media_urls.iter().enumerate() {
                let lower = url.to_lowercase();
                let media_type = if lower.contains(".mp4") || lower.contains(".webm") || lower.contains("video") {
                    "video"
                } else if lower.contains(".mp3") || lower.contains(".wav") || lower.contains("audio") {
                    "audio"
                } else {
                    "image"
                };
                let should_download = match media_type {
                    "video" => config.media_download.include_videos,
                    "audio" => config.media_download.include_audio,
                    _ => config.media_download.include_images,
                };
                if should_download {
                    let filename = config.media_download.rename_pattern
                        .replace("{platform}", &config.platform)
                        .replace("{id}", &post.id)
                        .replace("{index}", &idx.to_string());
                    media_urls.push((url.clone(), filename));
                }
            }
        }

        if media_urls.is_empty() {
            return Ok(());
        }

        let semaphore = Arc::new(Semaphore::new(config.media_download.max_concurrent));
        let max_size = config.media_download.max_file_size_mb * 1024 * 1024;
        let mut join_set = tokio::task::JoinSet::new();

        for (url, filename) in &media_urls {
            let client = self.client.clone();
            let url = url.clone();
            let filename = filename.clone();
            let save_dir = save_dir.clone();
            let semaphore = semaphore.clone();
            let max_size = max_size;

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                match client.get(&url).header("Referer", &url).send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if !status.is_success() {
                            return MediaDownloadResult {
                                url, file_path: String::new(), file_size: 0,
                                media_type: String::new(), success: false,
                                error: Some(format!("HTTP {}", status)),
                            };
                        }
                        let content_length = resp.headers().get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);
                        if content_length > max_size {
                            return MediaDownloadResult {
                                url, file_path: String::new(), file_size: content_length,
                                media_type: String::new(), success: false,
                                error: Some(format!("File too large: {} bytes", content_length)),
                            };
                        }
                        let content_type = resp.headers().get("content-type")
                            .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        let media_type = if content_type.contains("video") { "video" }
                            else if content_type.contains("audio") { "audio" }
                            else { "image" }.to_string();
                        let ext = match media_type.as_str() {
                            "video" => "mp4",
                            "audio" => "mp3",
                            _ => "jpg",
                        };
                        match resp.bytes().await {
                            Ok(bytes) => {
                                let file_path = format!("{}/{}.{}", save_dir, filename, ext);
                                match std::fs::write(&file_path, &bytes) {
                                    Ok(_) => MediaDownloadResult {
                                        url, file_path, file_size: bytes.len() as u64,
                                        media_type, success: true, error: None,
                                    },
                                    Err(e) => MediaDownloadResult {
                                        url, file_path: String::new(), file_size: 0,
                                        media_type, success: false, error: Some(format!("Write failed: {}", e)),
                                    },
                                }
                            }
                            Err(e) => MediaDownloadResult {
                                url, file_path: String::new(), file_size: 0,
                                media_type, success: false, error: Some(format!("Read body failed: {}", e)),
                            },
                        }
                    }
                    Err(e) => MediaDownloadResult {
                        url, file_path: String::new(), file_size: 0,
                        media_type: String::new(), success: false,
                        error: Some(format!("Request failed: {}", e)),
                    },
                }
            });
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok(dl_result) = res {
                result.media_downloads.push(dl_result);
            }
        }

        Ok(())
    }

    async fn crawl_xiaohongshu(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let url = format!("https://www.xiaohongshu.com/user/profile/{}", config.target);
        let html = self.fetch_with_retry(&url, "https://www.xiaohongshu.com/", config).await?;

        let note_ids = extract_all_captures(r#"note_id":"([^"]+)""#, &html);
        let titles = extract_all_captures(r#"title":"([^"]*)""#, &html);
        let desc_list = extract_all_captures(r#"desc":"([^"]*)""#, &html);
        let liked_counts = extract_all_captures(r#"liked_count":"(\d+)""#, &html);
        let image_urls = extract_all_captures(r#"url":"(https?://sns-webpic-qc\.xhscdn\.com/[^"]+)""#, &html);
        let tags_re = regex::Regex::new("#([^\"]+?)#").unwrap_or_else(|_| regex::Regex::new("NEVER_MATCH").unwrap());
        let tags: Vec<String> = tags_re.captures_iter(&html).filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string())).collect();
        let posts_count = note_ids.len();

        for (i, note_id) in note_ids.iter().take(config.max_items).enumerate() {
            let mut post_media = Vec::new();
            for img_url in &image_urls {
                if !post_media.contains(img_url) {
                    post_media.push(img_url.clone());
                }
            }
            result.posts.push(SocialPost {
                id: note_id.clone(),
                title: titles.get(i).cloned().unwrap_or_default(),
                content: desc_list.get(i).cloned().unwrap_or_default(),
                author: config.target.clone(),
                author_id: config.target.clone(),
                likes: liked_counts.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                url: format!("https://www.xiaohongshu.com/explore/{}", note_id),
                media_urls: post_media,
                tags: if tags.is_empty() { Vec::new() } else { tags.clone() },
                crawl_time: now_timestamp_str(),
                ..Default::default()
            });
        }

        let username = extract_capture(r#"nickname":"([^"]+)""#, &html);
        let bio = extract_capture(r#"desc":"([^"]*)""#, &html);
        let followers = extract_capture(r#"fans":"(\d+)""#, &html).parse::<u64>().unwrap_or(0);
        let following = extract_capture(r#"follows":"(\d+)""#, &html).parse::<u64>().unwrap_or(0);

        result.users.push(SocialUser {
            id: config.target.clone(),
            username: username.clone(),
            display_name: username,
            bio,
            followers,
            following,
            posts_count,
            url,
            ..Default::default()
        });

        Ok(())
    }

    async fn crawl_douyin(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let url = format!("https://www.douyin.com/user/{}", config.target);
        let html = self.fetch_with_retry(&url, "https://www.douyin.com/", config).await?;

        let aweme_ids = extract_all_captures(r#"aweme_id":"([^"]+)""#, &html);
        let desc_list = extract_all_captures(r#"desc":"([^"]*)""#, &html);
        let digg_counts = extract_all_captures(r#"digg_count":(\d+)"#, &html);
        let comment_counts = extract_all_captures(r#"comment_count":(\d+)"#, &html);
        let video_urls = extract_all_captures(r#"play_addr"[^}]*"url_list":\["([^"]+)"#, &html);
        let cover_urls = extract_all_captures(r#"cover"[^}]*"url_list":\["([^"]+)"#, &html);
        let posts_count = aweme_ids.len();

        for (i, aweme_id) in aweme_ids.iter().take(config.max_items).enumerate() {
            let mut post_media = cover_urls.clone();
            if let Some(vid) = video_urls.get(i) {
                post_media.push(vid.clone());
            }
            result.posts.push(SocialPost {
                id: aweme_id.clone(),
                title: desc_list.get(i).cloned().unwrap_or_default(),
                content: desc_list.get(i).cloned().unwrap_or_default(),
                author: config.target.clone(),
                author_id: config.target.clone(),
                likes: digg_counts.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                comments_count: comment_counts.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                url: format!("https://www.douyin.com/video/{}", aweme_id),
                media_urls: post_media,
                crawl_time: now_timestamp_str(),
                ..Default::default()
            });
        }

        let username = extract_capture(r#"nickname":"([^"]+)""#, &html);
        let bio = extract_capture(r#"signature":"([^"]*)""#, &html);
        let followers = extract_capture(r#"follower_count":(\d+)"#, &html).parse::<u64>().unwrap_or(0);
        let following = extract_capture(r#"following_count":(\d+)"#, &html).parse::<u64>().unwrap_or(0);
        let avatar = extract_capture(r#"avatar_larger"[^}]*"url_list":\["([^"]+)"#, &html);

        result.users.push(SocialUser {
            id: config.target.clone(),
            username: username.clone(),
            display_name: username,
            bio,
            avatar_url: avatar,
            followers,
            following,
            posts_count,
            url,
            ..Default::default()
        });

        Ok(())
    }

    async fn crawl_bilibili(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let api_url = format!(
            "https://api.bilibili.com/x/space/wbi/arc/search?mid={}&ps={}&pn=1",
            config.target, config.max_items.min(50)
        );
        let text = self.fetch_with_retry(&api_url, "https://www.bilibili.com/", config).await?;

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(videos) = json.pointer("/data/list/vlist").and_then(|v| v.as_array()) {
                for video in videos.iter().take(config.max_items) {
                    let bvid = video.get("bvid").and_then(|v| v.as_str()).unwrap_or("");
                    let pic = video.get("pic").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    result.posts.push(SocialPost {
                        id: bvid.to_string(),
                        title: video.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        content: video.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        author: video.get("author").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        likes: video.get("play").and_then(|v| v.as_u64()).unwrap_or(0),
                        comments_count: video.get("comment").and_then(|v| v.as_u64()).unwrap_or(0),
                        url: format!("https://www.bilibili.com/video/{}", bvid),
                        created_at: video.get("created").and_then(|v| v.as_u64()).map(|t| t.to_string()).unwrap_or_default(),
                        media_urls: if pic.is_empty() { Vec::new() } else { vec![pic] },
                        crawl_time: now_timestamp_str(),
                        ..Default::default()
                    });
                }
            }
        }

        let info_url = format!("https://api.bilibili.com/x/space/wbi/acc/info?mid={}", config.target);
        if let Ok(info_text) = self.fetch_with_retry(&info_url, "https://www.bilibili.com/", config).await {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&info_text) {
                if let Some(data) = json.get("data") {
                    let name = data.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let sign = data.get("sign").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let face = data.get("face").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let verified = data.get("official").and_then(|o| o.get("role")).and_then(|r| r.as_u64()).unwrap_or(0) > 0;
                    let gender = data.get("sex").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    let stat_url = format!("https://api.bilibili.com/x/relation/stat?vmid={}", config.target);
                    let mut followers: u64 = 0;
                    if let Ok(stat_text) = self.fetch_with_retry(&stat_url, "https://www.bilibili.com/", config).await {
                        if let Ok(stat_json) = serde_json::from_str::<serde_json::Value>(&stat_text) {
                            followers = stat_json.get("data").and_then(|d| d.get("follower")).and_then(|v| v.as_u64()).unwrap_or(0);
                        }
                    }

                    result.users.push(SocialUser {
                        id: config.target.clone(),
                        username: name.clone(),
                        display_name: name,
                        bio: sign,
                        avatar_url: face,
                        followers,
                        posts_count: result.posts.len(),
                        verified,
                        url: format!("https://space.bilibili.com/{}", config.target),
                        gender,
                        ..Default::default()
                    });
                }
            }
        }

        Ok(())
    }

    async fn crawl_weibo(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let api_url = format!(
            "https://m.weibo.cn/api/container/getIndex?containerid=230413{}_-_WEIBO_SECOND_PROFILE_WEIBO&page_type=03&page=1",
            config.target
        );
        let text = self.fetch_with_retry(&api_url, "https://m.weibo.cn/", config).await?;

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(cards) = json.pointer("/data/cards").and_then(|v| v.as_array()) {
                for card in cards.iter().take(config.max_items) {
                    if let Some(mblog) = card.get("mblog") {
                        let mid = mblog.get("mid").and_then(|v| v.as_str()).unwrap_or("");
                        let mut media = Vec::new();
                        if let Some(pics) = mblog.get("pics").and_then(|v| v.as_array()) {
                            for pic in pics {
                                if let Some(url) = pic.get("large").and_then(|l| l.get("url")).and_then(|v| v.as_str()) {
                                    media.push(url.to_string());
                                }
                            }
                        }
                        let video_url = mblog.get("page_info")
                            .and_then(|p| p.get("media_info"))
                            .and_then(|m| m.get("stream_url_hd").or_else(|| m.get("stream_url")))
                            .and_then(|v| v.as_str()).map(|s| s.to_string());
                        if let Some(vu) = video_url {
                            media.push(vu);
                        }
                        let reposts = mblog.get("reposts_count").and_then(|v| v.as_u64()).unwrap_or(0);
                        let attitudes = mblog.get("attitudes_count").and_then(|v| v.as_u64()).unwrap_or(0);
                        let comments_count = mblog.get("comments_count").and_then(|v| v.as_u64()).unwrap_or(0);
                        let author_name = mblog.get("user").and_then(|u| u.get("screen_name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let author_id = mblog.get("user").and_then(|u| u.get("id")).and_then(|v| v.as_u64()).unwrap_or(0);

                        result.posts.push(SocialPost {
                            id: mid.to_string(),
                            content: mblog.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            author: author_name,
                            author_id: author_id.to_string(),
                            likes: attitudes,
                            comments_count,
                            shares: reposts,
                            url: format!("https://m.weibo.cn/detail/{}", mid),
                            created_at: mblog.get("created_at").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            media_urls: media,
                            location: mblog.get("region_name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            is_original: !mblog.get("retweeted_status").is_some(),
                            crawl_time: now_timestamp_str(),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        let profile_url = format!("https://m.weibo.cn/api/container/getIndex?containerid=100505{}", config.target);
        if let Ok(profile_text) = self.fetch_with_retry(&profile_url, "https://m.weibo.cn/", config).await {
            if let Ok(profile_json) = serde_json::from_str::<serde_json::Value>(&profile_text) {
                if let Some(user_info) = profile_json.pointer("/data/userInfo") {
                    let screen_name = user_info.get("screen_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let description = user_info.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let avatar = user_info.get("profile_image_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let followers = user_info.get("followers_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let following = user_info.get("follow_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let verified = user_info.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
                    let verified_type = user_info.get("verified_type").and_then(|v| v.as_i64()).map(|t| t.to_string()).unwrap_or_default();
                    let gender = user_info.get("gender").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let location = user_info.get("location").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    result.users.push(SocialUser {
                        id: config.target.clone(),
                        username: screen_name.clone(),
                        display_name: screen_name,
                        bio: description,
                        avatar_url: avatar,
                        followers,
                        following,
                        posts_count: result.posts.len(),
                        verified,
                        verified_type,
                        url: format!("https://weibo.com/u/{}", config.target),
                        gender,
                        location,
                        ..Default::default()
                    });
                }
            }
        }

        Ok(())
    }

    async fn crawl_kuaishou(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let url = format!("https://www.kuaishou.com/profile/{}", config.target);
        let html = self.fetch_with_retry(&url, "https://www.kuaishou.com/", config).await?;

        let video_ids = extract_all_captures(r#"photoId":"([^"]+)""#, &html);
        let captions = extract_all_captures(r#"caption":"([^"]*)""#, &html);
        let covers = extract_all_captures(r#"coverUrl":"([^"]+)""#, &html);
        let like_counts = extract_all_captures(r#"likeCount":(\d+)"#, &html);
        let comment_counts = extract_all_captures(r#"commentCount":(\d+)"#, &html);

        for (i, vid) in video_ids.iter().take(config.max_items).enumerate() {
            let mut media = Vec::new();
            if let Some(cover) = covers.get(i) {
                media.push(cover.clone());
            }
            result.posts.push(SocialPost {
                id: vid.clone(),
                title: captions.get(i).cloned().unwrap_or_default(),
                content: captions.get(i).cloned().unwrap_or_default(),
                author: config.target.clone(),
                author_id: config.target.clone(),
                likes: like_counts.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                comments_count: comment_counts.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                url: format!("https://www.kuaishou.com/short-video/{}", vid),
                media_urls: media,
                crawl_time: now_timestamp_str(),
                ..Default::default()
            });
        }

        let username = extract_capture(r#"user_name":"([^"]+)""#, &html);
        let bio = extract_capture(r#"user_text":"([^"]*)""#, &html);
        let followers = extract_capture(r#"fan_count":"(\d+)""#, &html).parse::<u64>().unwrap_or(0);
        let following = extract_capture(r#"follow_count":"(\d+)""#, &html).parse::<u64>().unwrap_or(0);

        result.users.push(SocialUser {
            id: config.target.clone(),
            username: username.clone(),
            display_name: username,
            bio,
            followers,
            following,
            posts_count: result.posts.len(),
            url,
            ..Default::default()
        });

        Ok(())
    }

    async fn crawl_tieba(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let url = format!("https://tieba.baidu.com/f?kw={}", urlencoding::encode(&config.target));
        let html = self.fetch_with_retry(&url, "", config).await?;

        let thread_ids = extract_all_captures(r#"/p/(\d+)""#, &html);
        let titles = extract_all_captures(r#"class="j_th_tit ">([^<]+)"#, &html);
        let reply_counts = extract_all_captures(r#"class="threadlist_rep_num center_text"[^>]*>(\d+)"#, &html);

        for (i, tid) in thread_ids.iter().take(config.max_items).enumerate() {
            result.posts.push(SocialPost {
                id: tid.clone(),
                title: titles.get(i).cloned().unwrap_or_default(),
                url: format!("https://tieba.baidu.com/p/{}", tid),
                comments_count: reply_counts.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                crawl_time: now_timestamp_str(),
                ..Default::default()
            });
        }

        Ok(())
    }

    async fn crawl_zhihu(&self, config: &SocialCrawlConfig, result: &mut SocialCrawlResult) -> Result<()> {
        let api_url = format!(
            "https://www.zhihu.com/api/v4/members/{}/answers?limit={}&offset=0",
            config.target, config.max_items.min(20)
        );
        let text = self.fetch_with_retry(&api_url, "https://www.zhihu.com/", config).await?;

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(answers) = json.get("data").and_then(|d| d.as_array()) {
                for answer in answers.iter().take(config.max_items) {
                    let qid = answer.get("question").and_then(|q| q.get("id")).and_then(|v| v.as_u64()).unwrap_or(0);
                    let aid = answer.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let author_name = answer.get("author").and_then(|a| a.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let author_id = answer.get("author").and_then(|a| a.get("url_token")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let voteup = answer.get("voteup_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let comment_count = answer.get("comment_count").and_then(|v| v.as_u64()).unwrap_or(0);
                    let excerpt = answer.get("excerpt").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    result.posts.push(SocialPost {
                        id: aid.to_string(),
                        title: answer.get("question").and_then(|q| q.get("title")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        content: excerpt,
                        author: author_name,
                        author_id: author_id,
                        likes: voteup,
                        comments_count: comment_count,
                        url: format!("https://www.zhihu.com/question/{}/answer/{}", qid, aid),
                        created_at: answer.get("created_time").and_then(|v| v.as_u64()).map(|t| t.to_string()).unwrap_or_default(),
                        crawl_time: now_timestamp_str(),
                        ..Default::default()
                    });
                }
            }
        }

        let profile_url = format!("https://www.zhihu.com/api/v4/members/{}", config.target);
        if let Ok(profile_text) = self.fetch_with_retry(&profile_url, "https://www.zhihu.com/", config).await {
            if let Ok(profile_json) = serde_json::from_str::<serde_json::Value>(&profile_text) {
                let name = profile_json.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let headline = profile_json.get("headline").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let avatar = profile_json.get("avatar_url").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let follower_count = profile_json.get("follower_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let following_count = profile_json.get("following_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let answer_count = profile_json.get("answer_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let gender = profile_json.get("gender").and_then(|v| v.as_i64()).map(|g| if g == 1 { "male" } else if g == 0 { "female" } else { "unknown" }).unwrap_or("unknown").to_string();
                let location = profile_json.get("location").and_then(|l| l.get("name")).and_then(|v| v.as_str()).unwrap_or("").to_string();

                result.users.push(SocialUser {
                    id: config.target.clone(),
                    username: name.clone(),
                    display_name: name,
                    bio: headline,
                    avatar_url: avatar,
                    followers: follower_count,
                    following: following_count,
                    posts_count: answer_count,
                    url: format!("https://www.zhihu.com/people/{}", config.target),
                    gender,
                    location,
                    ..Default::default()
                });
            }
        }

        Ok(())
    }

    async fn fetch_with_retry(&self, url: &str, referer: &str, config: &SocialCrawlConfig) -> Result<String> {
        let max_retries = config.ip_block_detection.max_retries.max(1);
        let retry_delay = config.ip_block_detection.retry_delay_ms;
        let mut last_error = String::new();
        let mut current_proxy = String::new();

        for attempt in 0..=max_retries {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(retry_delay * attempt as u64)).await;
            }

            let use_proxy = if !current_proxy.is_empty() {
                Some(current_proxy.clone())
            } else if let Some(ref pm) = self.proxy_manager {
                pm.get_next_healthy().await
            } else if !config.proxy_url.is_empty() {
                Some(config.proxy_url.clone())
            } else {
                None
            };

            let client = if let Some(ref proxy_url) = use_proxy {
                match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .user_agent(&config.login_config.user_agent)
                    .proxy(reqwest::Proxy::all(proxy_url.as_str()).unwrap_or_else(|_| reqwest::Proxy::all("http://127.0.0.1:1").unwrap()))
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        last_error = format!("Proxy client build failed: {}", e);
                        if let Some(ref pm) = self.proxy_manager {
                            pm.mark_failed(proxy_url).await;
                        }
                        continue;
                    }
                }
            } else {
                self.client.clone()
            };

            let mut req = client.get(url);
            if !referer.is_empty() {
                req = req.header("Referer", referer);
            }
            if !config.cookie.is_empty() {
                req = req.header("Cookie", &config.cookie);
            } else if !config.login_config.cookie_string.is_empty() {
                req = req.header("Cookie", &config.login_config.cookie_string);
            }
            req = req.header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            req = req.header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();

                    if detect_ip_block(status, &body, &config.ip_block_detection) {
                        result_proxy_stats(config, true, !use_proxy.is_none(), use_proxy.is_some());

                        if let Some(ref pm) = self.proxy_manager {
                            if let Some(ref proxy) = use_proxy {
                                pm.mark_failed(proxy).await;
                            }
                        }

                        if config.ip_block_detection.auto_switch_proxy {
                            if let Some(ref pm) = self.proxy_manager {
                                current_proxy = pm.get_next_healthy().await.unwrap_or_default();
                            }
                        }

                        last_error = format!("IP blocked (HTTP {}), attempt {}/{}", status, attempt + 1, max_retries);
                        continue;
                    }

                    if let Some(ref pm) = self.proxy_manager {
                        if let Some(ref proxy) = use_proxy {
                            pm.mark_success(proxy).await;
                        }
                    }

                    result_proxy_stats(config, false, !use_proxy.is_none(), use_proxy.is_some());
                    return Ok(body);
                }
                Err(e) => {
                    last_error = format!("Request failed: {}", e);
                    if let Some(ref pm) = self.proxy_manager {
                        if let Some(ref proxy) = use_proxy {
                            pm.mark_failed(proxy).await;
                        }
                    }
                }
            }
        }

        Err(ToolError::ExecutionError(format!("All retries exhausted: {}", last_error)))
    }

    async fn rate_limit_delay(&self, config: &SocialCrawlConfig) {
        let base_delay = config.rate_limit.delay_between_requests_ms;
        let jitter = config.rate_limit.jitter_ms;
        if base_delay > 0 {
            let actual_jitter = if jitter > 0 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64 % (jitter * 2)
            } else {
                0
            };
            tokio::time::sleep(std::time::Duration::from_millis(base_delay + actual_jitter)).await;
        }
    }
}

fn result_proxy_stats(_config: &SocialCrawlConfig, _is_blocked: bool, _is_proxy: bool, _is_proxy_request: bool) {
}
