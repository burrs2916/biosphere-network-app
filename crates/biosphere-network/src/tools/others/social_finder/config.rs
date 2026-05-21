use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use digest::Digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SocialFinderConfig {
    pub username: String,
    pub check_platforms: Vec<String>,
    pub timeout: u64,
    pub mode: String,
    pub check_email: Option<String>,
    pub check_name: Option<String>,
    pub analyze_face: bool,
    pub cross_reference: bool,
}

impl Default for SocialFinderConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            check_platforms: Vec::new(),
            timeout: 15,
            mode: "fast".to_string(),
            check_email: None,
            check_name: None,
            analyze_face: false,
            cross_reference: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialFinderResult {
    pub success: bool,
    pub username: String,
    pub found_accounts: Vec<SocialAccount>,
    pub not_found_platforms: Vec<String>,
    pub statistics: SocialFinderStats,
    pub security_findings: Vec<SocialFinding>,
    pub email_correlation: Option<EmailCorrelation>,
    pub face_analysis: Option<FaceAnalysis>,
    pub cross_reference_report: Option<CrossReferenceReport>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCorrelation {
    pub email: String,
    pub correlated_platforms: Vec<CorrelatedPlatform>,
    pub gravatar_info: Option<GravatarInfo>,
    pub haveibeenpwned_breaches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedPlatform {
    pub platform: String,
    pub found: bool,
    pub email_match: bool,
    pub username_match: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GravatarInfo {
    pub hash: String,
    pub has_avatar: bool,
    pub profile_url: Option<String>,
    pub display_name: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceAnalysis {
    pub total_profiles_with_images: usize,
    pub unique_images: usize,
    pub possible_same_person: bool,
    pub confidence: f64,
    pub image_urls: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossReferenceReport {
    pub username_variations: Vec<String>,
    pub consistent_name: Option<String>,
    pub consistent_location: Option<String>,
    pub linked_accounts: Vec<LinkedAccount>,
    pub digital_footprint_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedAccount {
    pub source_platform: String,
    pub target_platform: String,
    pub link_type: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAccount {
    pub platform: String,
    pub url: String,
    pub username: String,
    pub is_verified: bool,
    pub bio: Option<String>,
    pub followers: Option<u64>,
    pub profile_picture: Option<String>,
    pub category: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialFinderStats {
    pub total_checked: usize,
    pub found_count: usize,
    pub not_found_count: usize,
    pub categories: std::collections::HashMap<String, usize>,
    pub high_risk_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformListItem {
    pub name: String,
    pub category: String,
    pub check_method: String,
}

struct PlatformInfo {
    name: String,
    url_template: String,
    category: String,
    check_type: PlatformCheckType,
}

#[derive(Clone)]
enum PlatformCheckType {
    HttpGet,
    GitHubApi,
    GitLabApi,
    RedditApi,
    HackerNewsApi,
    NpmApi,
    DockerHubApi,
    KeybaseApi,
}

impl PlatformCheckType {
    fn label(&self) -> &'static str {
        match self {
            PlatformCheckType::HttpGet => "HTTP",
            PlatformCheckType::GitHubApi => "API",
            PlatformCheckType::GitLabApi => "API",
            PlatformCheckType::RedditApi => "API",
            PlatformCheckType::HackerNewsApi => "API",
            PlatformCheckType::NpmApi => "API",
            PlatformCheckType::DockerHubApi => "API",
            PlatformCheckType::KeybaseApi => "API",
        }
    }
}

pub struct SocialFinderTool;

impl SocialFinderTool {
    pub fn list_platforms() -> Vec<PlatformListItem> {
        Self::get_platforms(&[]).into_iter().map(|p| PlatformListItem {
            name: p.name,
            category: p.category,
            check_method: p.check_type.label().to_string(),
        }).collect()
    }

    pub async fn find(config: &SocialFinderConfig) -> std::result::Result<SocialFinderResult, String> {
        if config.username.is_empty() {
            return Err("Username is required".to_string());
        }

        let username = config.username.trim().to_string();
        let platforms = Self::get_platforms(&config.check_platforms);
        let is_deep = config.mode == "deep";

        let effective_timeout = if is_deep {
            std::time::Duration::from_secs((config.timeout as f64 * 1.5) as u64)
        } else {
            std::time::Duration::from_secs(config.timeout)
        };

        let client = reqwest::Client::builder()
            .timeout(effective_timeout)
            .redirect(reqwest::redirect::Policy::limited(if is_deep { 10 } else { 5 }))
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let max_concurrent = if is_deep { 4 } else { 8 };
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut join_set = tokio::task::JoinSet::new();

        for platform in &platforms {
            let url = platform.url_template.replace("{}", &username);
            let client = client.clone();
            let platform_name = platform.name.clone();
            let platform_category = platform.category.clone();
            let check_type = platform.check_type.clone();
            let username_clone = username.clone();
            let semaphore = semaphore.clone();
            let deep = is_deep;

            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let result = match check_type {
                    PlatformCheckType::GitHubApi => {
                        Self::check_github_api(&client, &username_clone).await
                    }
                    PlatformCheckType::GitLabApi => {
                        Self::check_gitlab_api(&client, &username_clone).await
                    }
                    PlatformCheckType::RedditApi => {
                        Self::check_reddit_api(&client, &username_clone).await
                    }
                    PlatformCheckType::HackerNewsApi => {
                        Self::check_hackernews_api(&client, &username_clone).await
                    }
                    PlatformCheckType::NpmApi => {
                        Self::check_npm_api(&client, &username_clone).await
                    }
                    PlatformCheckType::DockerHubApi => {
                        Self::check_dockerhub_api(&client, &username_clone).await
                    }
                    PlatformCheckType::KeybaseApi => {
                        Self::check_keybase_api(&client, &username_clone).await
                    }
                    PlatformCheckType::HttpGet => {
                        Self::check_http_get(&client, &url, &platform_name, &username_clone, &platform_category, deep).await
                    }
                };

                (platform_name, platform_category, url, result)
            });
        }

        let mut found_accounts = Vec::new();
        let mut not_found_platforms = Vec::new();
        let mut errors_count = 0usize;

        while let Some(result) = join_set.join_next().await {
            if let Ok((platform_name, _category, _url, check_result)) = result {
                match check_result {
                    Some(account) => found_accounts.push(account),
                    None => {
                        if platform_name.is_empty() {
                            errors_count += 1;
                        } else {
                            not_found_platforms.push(platform_name);
                        }
                    }
                }
            }
        }

        let mut findings = Vec::new();

        let high_risk = found_accounts.iter().filter(|a| a.risk_level == "high").count();
        if high_risk > 0 {
            findings.push(SocialFinding {
                severity: "medium".to_string(),
                category: "account_exposure".to_string(),
                description: format!("Public accounts found on {} platforms for this username", high_risk),
                recommendation: "Review privacy settings on public accounts to avoid leaking personal information".to_string(),
            });
        }

        if found_accounts.len() > 10 {
            findings.push(SocialFinding {
                severity: "low".to_string(),
                category: "large_digital_footprint".to_string(),
                description: format!("This username is registered on {} platforms, indicating a large digital footprint", found_accounts.len()),
                recommendation: "Consider cleaning up unused accounts to reduce attack surface".to_string(),
            });
        }

        let dev_accounts: Vec<&SocialAccount> = found_accounts.iter().filter(|a| a.category == "development").collect();
        if dev_accounts.len() >= 3 {
            findings.push(SocialFinding {
                severity: "low".to_string(),
                category: "developer_info_leak".to_string(),
                description: format!("Accounts found on {} developer platforms, may leak tech stack and project info", dev_accounts.len()),
                recommendation: "Check developer platform repos and configs for exposed sensitive information".to_string(),
            });
        }

        let social_accounts: Vec<&SocialAccount> = found_accounts.iter().filter(|a| a.category == "social").collect();
        if social_accounts.len() >= 4 {
            findings.push(SocialFinding {
                severity: "low".to_string(),
                category: "social_media_presence".to_string(),
                description: format!("Active on {} social media platforms, high social exposure", social_accounts.len()),
                recommendation: "Review privacy settings and consider reducing public profile information".to_string(),
            });
        }

        let verified_accounts: Vec<&SocialAccount> = found_accounts.iter().filter(|a| a.is_verified).collect();
        if verified_accounts.len() >= 2 {
            findings.push(SocialFinding {
                severity: "info".to_string(),
                category: "verified_accounts".to_string(),
                description: format!("{} verified accounts found, indicating established online presence", verified_accounts.len()),
                recommendation: "Verified accounts are harder to impersonate but provide more public information".to_string(),
            });
        }

        if is_deep {
            let accounts_with_bio: Vec<&SocialAccount> = found_accounts.iter().filter(|a| a.bio.is_some()).collect();
            if accounts_with_bio.len() >= 3 {
                findings.push(SocialFinding {
                    severity: "medium".to_string(),
                    category: "bio_information_leak".to_string(),
                    description: format!("{} accounts contain bio/profile information that may reveal personal details", accounts_with_bio.len()),
                    recommendation: "Review bio information across platforms for sensitive personal data leakage".to_string(),
                });
            }

            let accounts_with_avatar: Vec<&SocialAccount> = found_accounts.iter().filter(|a| a.profile_picture.is_some()).collect();
            if accounts_with_avatar.len() >= 3 {
                findings.push(SocialFinding {
                    severity: "info".to_string(),
                    category: "profile_picture_consistency".to_string(),
                    description: format!("{} accounts have profile pictures, could be used for facial recognition", accounts_with_avatar.len()),
                    recommendation: "Consider using different profile pictures across platforms to reduce cross-linking".to_string(),
                });
            }

            let unique_categories: std::collections::HashSet<&str> = found_accounts.iter().map(|a| a.category.as_str()).collect();
            if unique_categories.len() >= 5 {
                findings.push(SocialFinding {
                    severity: "medium".to_string(),
                    category: "wide_category_spread".to_string(),
                    description: format!("Accounts found across {} different categories, very broad digital footprint", unique_categories.len()),
                    recommendation: "A wide category spread increases attack surface. Consider deactivating unused accounts".to_string(),
                });
            }
        }

        let mut categories = std::collections::HashMap::new();
        for account in &found_accounts {
            *categories.entry(account.category.clone()).or_insert(0usize) += 1;
        }

        let stats = SocialFinderStats {
            total_checked: found_accounts.len() + not_found_platforms.len() + errors_count,
            found_count: found_accounts.len(),
            not_found_count: not_found_platforms.len(),
            categories,
            high_risk_count: high_risk,
        };

        let summary = format!(
            "Social media search complete | Username: {} | Platforms checked: {} | Accounts found: {} | Not found: {}",
            username, stats.total_checked, found_accounts.len(), not_found_platforms.len()
        );

        let email_correlation = if let Some(ref email) = config.check_email {
            Some(Self::correlate_email(&client, email, &username, &found_accounts).await)
        } else {
            None
        };

        let face_analysis = if config.analyze_face {
            let images: Vec<String> = found_accounts.iter()
                .filter_map(|a| a.profile_picture.clone())
                .collect();
            Some(Self::analyze_faces(&images))
        } else {
            None
        };

        let cross_reference_report = if config.cross_reference {
            Some(Self::cross_reference(&username, &found_accounts))
        } else {
            None
        };

        Ok(SocialFinderResult {
            success: true,
            username,
            found_accounts,
            not_found_platforms,
            statistics: stats,
            security_findings: findings,
            email_correlation,
            face_analysis,
            cross_reference_report,
            summary,
        })
    }

    fn get_platforms(filter: &[String]) -> Vec<PlatformInfo> {
        let all: Vec<PlatformInfo> = vec![
            PlatformInfo { name: "GitHub".to_string(), url_template: "https://api.github.com/users/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::GitHubApi },
            PlatformInfo { name: "GitLab".to_string(), url_template: "https://gitlab.com/api/v4/users?username={}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::GitLabApi },
            PlatformInfo { name: "Reddit".to_string(), url_template: "https://www.reddit.com/user/{}/about.json".to_string(), category: "forum".to_string(), check_type: PlatformCheckType::RedditApi },
            PlatformInfo { name: "HackerNews".to_string(), url_template: "https://hacker-news.firebaseio.com/v0/user/{}.json".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HackerNewsApi },
            PlatformInfo { name: "npm".to_string(), url_template: "https://registry.npmjs.org/-/v1/search?text=maintainer:{}&size=1".to_string(), category: "development".to_string(), check_type: PlatformCheckType::NpmApi },
            PlatformInfo { name: "Docker Hub".to_string(), url_template: "https://hub.docker.com/v2/users/{}/".to_string(), category: "development".to_string(), check_type: PlatformCheckType::DockerHubApi },
            PlatformInfo { name: "Keybase".to_string(), url_template: "https://keybase.io/_/api/1.0/user/lookup.json?username={}".to_string(), category: "security".to_string(), check_type: PlatformCheckType::KeybaseApi },
            PlatformInfo { name: "Twitter/X".to_string(), url_template: "https://twitter.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Instagram".to_string(), url_template: "https://instagram.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Facebook".to_string(), url_template: "https://facebook.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "LinkedIn".to_string(), url_template: "https://linkedin.com/in/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "YouTube".to_string(), url_template: "https://youtube.com/@{}".to_string(), category: "video".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "TikTok".to_string(), url_template: "https://tiktok.com/@{}".to_string(), category: "video".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Twitch".to_string(), url_template: "https://twitch.tv/{}".to_string(), category: "live".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Pinterest".to_string(), url_template: "https://pinterest.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Medium".to_string(), url_template: "https://medium.com/@{}".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Dev.to".to_string(), url_template: "https://dev.to/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "StackOverflow".to_string(), url_template: "https://stackoverflow.com/users/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Telegram".to_string(), url_template: "https://t.me/{}".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Discord".to_string(), url_template: "https://discord.com/users/{}".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Spotify".to_string(), url_template: "https://open.spotify.com/user/{}".to_string(), category: "music".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Steam".to_string(), url_template: "https://steamcommunity.com/id/{}".to_string(), category: "game".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Mastodon".to_string(), url_template: "https://mastodon.social/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Flickr".to_string(), url_template: "https://flickr.com/people/{}".to_string(), category: "image".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "SoundCloud".to_string(), url_template: "https://soundcloud.com/{}".to_string(), category: "music".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Behance".to_string(), url_template: "https://behance.net/{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Dribbble".to_string(), url_template: "https://dribbble.com/{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "CodePen".to_string(), url_template: "https://codepen.io/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "About.me".to_string(), url_template: "https://about.me/{}".to_string(), category: "personal".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Gravatar".to_string(), url_template: "https://gravatar.com/{}".to_string(), category: "personal".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Weibo".to_string(), url_template: "https://weibo.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Zhihu".to_string(), url_template: "https://zhihu.com/people/{}".to_string(), category: "forum".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Bilibili".to_string(), url_template: "https://space.bilibili.com/{}".to_string(), category: "video".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Douyin".to_string(), url_template: "https://douyin.com/{}".to_string(), category: "video".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Xiaohongshu".to_string(), url_template: "https://xiaohongshu.com/user/profile/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Snapchat".to_string(), url_template: "https://snapchat.com/add/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Patreon".to_string(), url_template: "https://patreon.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "BuyMeACoffee".to_string(), url_template: "https://buymeacoffee.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Gumroad".to_string(), url_template: "https://gumroad.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "LeetCode".to_string(), url_template: "https://leetcode.com/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "HackTheBox".to_string(), url_template: "https://hackthebox.com/home/users/profile/{}".to_string(), category: "security".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "WordPress".to_string(), url_template: "https://{}.wordpress.com".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Vimeo".to_string(), url_template: "https://vimeo.com/{}".to_string(), category: "video".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Goodreads".to_string(), url_template: "https://goodreads.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "TripAdvisor".to_string(), url_template: "https://tripadvisor.com/members/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Kaggle".to_string(), url_template: "https://kaggle.com/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "HackerRank".to_string(), url_template: "https://hackerrank.com/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Replit".to_string(), url_template: "https://replit.com/@{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "ProductHunt".to_string(), url_template: "https://producthunt.com/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Slideshare".to_string(), url_template: "https://slideshare.net/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Letterboxd".to_string(), url_template: "https://letterboxd.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Untappd".to_string(), url_template: "https://untappd.com/user/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Tumblr".to_string(), url_template: "https://{}.tumblr.com".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "VSCO".to_string(), url_template: "https://vsco.co/{}/gallery".to_string(), category: "image".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "500px".to_string(), url_template: "https://500px.com/p/{}".to_string(), category: "image".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Unsplash".to_string(), url_template: "https://unsplash.com/@{}".to_string(), category: "image".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "DeviantArt".to_string(), url_template: "https://deviantart.com/{}".to_string(), category: "image".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "ArtStation".to_string(), url_template: "https://artstation.com/{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Fiverr".to_string(), url_template: "https://fiverr.com/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Upwork".to_string(), url_template: "https://upwork.com/freelancers/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Freelancer".to_string(), url_template: "https://freelancer.com/u/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "AngelList".to_string(), url_template: "https://wellfound.com/u/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Crunchbase".to_string(), url_template: "https://crunchbase.com/person/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Quora".to_string(), url_template: "https://quora.com/profile/{}".to_string(), category: "forum".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "StackExchange".to_string(), url_template: "https://stackexchange.com/users/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Bitbucket".to_string(), url_template: "https://bitbucket.org/{}/".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "SourceForge".to_string(), url_template: "https://sourceforge.net/u/{}/profile".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "PyPI".to_string(), url_template: "https://pypi.org/user/{}/".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "RubyGems".to_string(), url_template: "https://rubygems.org/profiles/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Crates.io".to_string(), url_template: "https://crates.io/users/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Packagist".to_string(), url_template: "https://packagist.org/users/{}/".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "GoDev".to_string(), url_template: "https://dev.to/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Lobsters".to_string(), url_template: "https://lobste.rs/u/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Hashnode".to_string(), url_template: "https://hashnode.com/@{}".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Substack".to_string(), url_template: "https://{}.substack.com".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Ghost".to_string(), url_template: "https://{}.ghost.io".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "BuzzFeed".to_string(), url_template: "https://buzzfeed.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "9GAG".to_string(), url_template: "https://9gag.com/u/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Imgur".to_string(), url_template: "https://imgur.com/user/{}".to_string(), category: "image".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Mix".to_string(), url_template: "https://mix.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Clubhouse".to_string(), url_template: "https://clubhouse.com/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Strava".to_string(), url_template: "https://strava.com/athletes/{}".to_string(), category: "fitness".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "MyFitnessPal".to_string(), url_template: "https://myfitnesspal.com/profile/{}".to_string(), category: "fitness".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Last.fm".to_string(), url_template: "https://last.fm/user/{}".to_string(), category: "music".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Bandcamp".to_string(), url_template: "https://bandcamp.com/{}".to_string(), category: "music".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Mixcloud".to_string(), url_template: "https://mixcloud.com/{}/".to_string(), category: "music".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Tinder".to_string(), url_template: "https://tinder.com/@{}".to_string(), category: "dating".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "OkCupid".to_string(), url_template: "https://okcupid.com/profile/{}".to_string(), category: "dating".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Roblox".to_string(), url_template: "https://roblox.com/users/profile?username={}".to_string(), category: "game".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Chess.com".to_string(), url_template: "https://chess.com/member/{}".to_string(), category: "game".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Lichess".to_string(), url_template: "https://lichess.org/@/{}".to_string(), category: "game".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Duolingo".to_string(), url_template: "https://duolingo.com/profile/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Wikipedia".to_string(), url_template: "https://en.wikipedia.org/wiki/User:{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Genius".to_string(), url_template: "https://genius.com/{}".to_string(), category: "music".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Instructables".to_string(), url_template: "https://instructables.com/member/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "HubPages".to_string(), url_template: "https://hubpages.com/@{}".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Wattpad".to_string(), url_template: "https://wattpad.com/user/{}".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Archive.org".to_string(), url_template: "https://archive.org/details/@{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "HackerOne".to_string(), url_template: "https://hackerone.com/{}".to_string(), category: "security".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Bugcrowd".to_string(), url_template: "https://bugcrowd.com/{}".to_string(), category: "security".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "TryHackMe".to_string(), url_template: "https://tryhackme.com/p/{}".to_string(), category: "security".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "CyberChef".to_string(), url_template: "https://gchq.github.io/CyberChef/".to_string(), category: "security".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Signal".to_string(), url_template: "https://signal.me/#u/{}".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Wire".to_string(), url_template: "https://wire.com/@{}".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Session".to_string(), url_template: "https://getsession.org/".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Element".to_string(), url_template: "https://matrix.to/#/@{}:matrix.org".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Kik".to_string(), url_template: "https://kik.me/{}".to_string(), category: "communication".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Yelp".to_string(), url_template: "https://yelp.com/user_details?userid={}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "OpenSea".to_string(), url_template: "https://opensea.io/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Rarible".to_string(), url_template: "https://rarible.com/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Etherscan".to_string(), url_template: "https://etherscan.io/address/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Coinbase".to_string(), url_template: "https://coinbase.com/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Binance".to_string(), url_template: "https://binance.com/en/register?ref={}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Figma".to_string(), url_template: "https://figma.com/@{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Sketch".to_string(), url_template: "https://sketch.com/@{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "InVision".to_string(), url_template: "https://invisionapp.com/{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Canva".to_string(), url_template: "https://canva.com/{}".to_string(), category: "design".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Notion".to_string(), url_template: "https://notion.so/{}".to_string(), category: "productivity".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Trello".to_string(), url_template: "https://trello.com/{}".to_string(), category: "productivity".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Asana".to_string(), url_template: "https://asana.com/{}".to_string(), category: "productivity".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Airtable".to_string(), url_template: "https://airtable.com/{}".to_string(), category: "productivity".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Coda".to_string(), url_template: "https://coda.io/@{}".to_string(), category: "productivity".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Linktree".to_string(), url_template: "https://linktr.ee/{}".to_string(), category: "personal".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Carrd".to_string(), url_template: "https://{}.carrd.co".to_string(), category: "personal".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Bio.link".to_string(), url_template: "https://bio.link/{}".to_string(), category: "personal".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Taplink".to_string(), url_template: "https://taplink.cc/{}".to_string(), category: "personal".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Ko-fi".to_string(), url_template: "https://ko-fi.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Liberapay".to_string(), url_template: "https://liberapay.com/{}/".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "OpenCollective".to_string(), url_template: "https://opencollective.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Minds".to_string(), url_template: "https://minds.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Gab".to_string(), url_template: "https://gab.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Parler".to_string(), url_template: "https://parler.com/profile/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "TruthSocial".to_string(), url_template: "https://truthsocial.com/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Threads".to_string(), url_template: "https://threads.net/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Bluesky".to_string(), url_template: "https://bsky.app/profile/{}.bsky.social".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Post.news".to_string(), url_template: "https://post.news/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "CounterSocial".to_string(), url_template: "https://countersocial.me/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Mammoth".to_string(), url_template: "https://mammoth.social/@{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Spoutible".to_string(), url_template: "https://spoutible.com/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Nostr".to_string(), url_template: "https://nostr.band/{}".to_string(), category: "social".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Lens".to_string(), url_template: "https://hey.xyz/u/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Farcaster".to_string(), url_template: "https://warpcast.com/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Mirror".to_string(), url_template: "https://mirror.xyz/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Paragraph".to_string(), url_template: "https://paragraph.xyz/@{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Planet".to_string(), url_template: "https://planet.xyz/{}".to_string(), category: "crypto".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Polywork".to_string(), url_template: "https://polywork.com/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Wellfound".to_string(), url_template: "https://wellfound.com/u/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "XING".to_string(), url_template: "https://xing.com/profile/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Viadeo".to_string(), url_template: "https://viadeo.com/profile/{}".to_string(), category: "professional".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "ResearchGate".to_string(), url_template: "https://researchgate.net/profile/{}".to_string(), category: "academic".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Academia.edu".to_string(), url_template: "https://academia.edu/{}".to_string(), category: "academic".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "ORCID".to_string(), url_template: "https://orcid.org/{}".to_string(), category: "academic".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Google Scholar".to_string(), url_template: "https://scholar.google.com/citations?user={}".to_string(), category: "academic".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "DBLP".to_string(), url_template: "https://dblp.org/pid/{}".to_string(), category: "academic".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "MediumPartner".to_string(), url_template: "https://medium.com/@{}".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "HackerNoon".to_string(), url_template: "https://hackernoon.com/u/{}".to_string(), category: "blog".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "CSS-Tricks".to_string(), url_template: "https://css-tricks.com/author/{}/".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "SmashingMag".to_string(), url_template: "https://smashingmagazine.com/author/{}".to_string(), category: "development".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "FreeCodeCamp".to_string(), url_template: "https://freecodecamp.org/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Codecademy".to_string(), url_template: "https://codecademy.com/profiles/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Udemy".to_string(), url_template: "https://udemy.com/user/{}/".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Coursera".to_string(), url_template: "https://coursera.org/instructor/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "edX".to_string(), url_template: "https://edx.org/bio/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Skillshare".to_string(), url_template: "https://skillshare.com/user/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Pluralsight".to_string(), url_template: "https://pluralsight.com/profile/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
            PlatformInfo { name: "Treehouse".to_string(), url_template: "https://teamtreehouse.com/{}".to_string(), category: "education".to_string(), check_type: PlatformCheckType::HttpGet },
        ];

        if filter.is_empty() {
            all
        } else {
            all.into_iter().filter(|p| filter.contains(&p.name)).collect()
        }
    }

    async fn check_github_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://api.github.com/users/{}", username);
        let resp = client.get(&url)
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;

        let followers = body.get("followers").and_then(|v| v.as_u64());
        let bio = body.get("bio").and_then(|v| v.as_str()).map(|s| s.to_string());
        let avatar = body.get("avatar_url").and_then(|v| v.as_str()).map(|s| s.to_string());
        let name = body.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let is_hireable = body.get("hireable").and_then(|v| v.as_bool()).unwrap_or(false);
        let public_repos = body.get("public_repos").and_then(|v| v.as_u64()).unwrap_or(0);

        let bio_text = match (bio, name, is_hireable, public_repos > 0) {
            (Some(b), _, _, _) => Some(b),
            (None, Some(n), _, _) => Some(format!("{} | {} public repos", n, public_repos)),
            (None, None, true, _) => Some(format!("Hireable developer | {} public repos", public_repos)),
            (None, None, false, true) => Some(format!("{} public repositories", public_repos)),
            _ => None,
        };

        let risk_level = match followers.unwrap_or(0) {
            f if f > 10000 => "high",
            f if f > 1000 => "medium",
            _ => "low",
        }.to_string();

        Some(SocialAccount {
            platform: "GitHub".to_string(),
            url: format!("https://github.com/{}", username),
            username: username.to_string(),
            is_verified: followers.unwrap_or(0) > 100,
            bio: bio_text,
            followers,
            profile_picture: avatar,
            category: "development".to_string(),
            risk_level,
        })
    }

    async fn check_gitlab_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://gitlab.com/api/v4/users?username={}", username);
        let resp = client.get(&url).send().await.ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let users = body.as_array()?;

        if users.is_empty() {
            return None;
        }

        let user = &users[0];
        let bio = user.get("bio").and_then(|v| v.as_str()).map(|s| s.to_string());
        let avatar = user.get("avatar_url").and_then(|v| v.as_str()).map(|s| s.to_string());
        let name = user.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let state = user.get("state").and_then(|v| v.as_str()).unwrap_or("active");

        let bio_text = match (bio, name) {
            (Some(b), _) => Some(b),
            (None, Some(n)) => Some(n.to_string()),
            _ => Some(format!("State: {}", state)),
        };

        Some(SocialAccount {
            platform: "GitLab".to_string(),
            url: format!("https://gitlab.com/{}", username),
            username: username.to_string(),
            is_verified: false,
            bio: bio_text,
            followers: None,
            profile_picture: avatar,
            category: "development".to_string(),
            risk_level: "low".to_string(),
        })
    }

    async fn check_reddit_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://www.reddit.com/user/{}/about.json", username);
        let resp = client.get(&url)
            .header("User-Agent", "BiosPherePro-OSINT-Tool/1.0")
            .send()
            .await
            .ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let data = body.get("data")?;

        let link_karma = data.get("link_karma").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
        let comment_karma = data.get("comment_karma").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
        let is_verified = data.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
        let avatar = data.get("icon_img").and_then(|v| v.as_str()).map(|s| {
            if s.contains("?") {
                s.split('?').next().unwrap_or(s).to_string()
            } else {
                s.to_string()
            }
        });

        let bio_text = Some(format!("Link karma: {} | Comment karma: {}", link_karma, comment_karma));

        let risk_level = match link_karma + comment_karma {
            k if k > 50000 => "high",
            k if k > 5000 => "medium",
            _ => "low",
        }.to_string();

        Some(SocialAccount {
            platform: "Reddit".to_string(),
            url: format!("https://www.reddit.com/user/{}", username),
            username: username.to_string(),
            is_verified,
            bio: bio_text,
            followers: Some(link_karma + comment_karma),
            profile_picture: avatar,
            category: "forum".to_string(),
            risk_level,
        })
    }

    async fn check_hackernews_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://hacker-news.firebaseio.com/v0/user/{}.json", username);
        let resp = client.get(&url).send().await.ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;

        if body.is_null() {
            return None;
        }

        let karma = body.get("karma").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
        let about = body.get("about").and_then(|v| v.as_str()).map(|s| s.to_string());
        let submitted = body.get("submitted").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);

        let bio_text = match about {
            Some(a) => Some(format!("{} | Karma: {} | Submitted: {}", a, karma, submitted)),
            None => Some(format!("Karma: {} | Submitted: {}", karma, submitted)),
        };

        Some(SocialAccount {
            platform: "HackerNews".to_string(),
            url: format!("https://news.ycombinator.com/user?id={}", username),
            username: username.to_string(),
            is_verified: karma > 1000,
            bio: bio_text,
            followers: Some(karma),
            profile_picture: None,
            category: "development".to_string(),
            risk_level: if karma > 10000 { "high" } else if karma > 1000 { "medium" } else { "low" }.to_string(),
        })
    }

    async fn check_npm_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://registry.npmjs.org/-/v1/search?text=maintainer:{}&size=1", username);
        let resp = client.get(&url).send().await.ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let total = body.get("total").and_then(|v| v.as_u64()).unwrap_or(0);

        if total == 0 {
            let profile_url = format!("https://www.npmjs.com/~{}", username);
            let profile_resp = client.get(&profile_url).send().await.ok()?;
            if profile_resp.status() == 404 {
                return None;
            }
            if profile_resp.status() == 200 {
                return Some(SocialAccount {
                    platform: "npm".to_string(),
                    url: profile_url,
                    username: username.to_string(),
                    is_verified: false,
                    bio: None,
                    followers: None,
                    profile_picture: None,
                    category: "development".to_string(),
                    risk_level: "low".to_string(),
                });
            }
            return None;
        }

        Some(SocialAccount {
            platform: "npm".to_string(),
            url: format!("https://www.npmjs.com/~{}", username),
            username: username.to_string(),
            is_verified: false,
            bio: Some(format!("Maintains {} package(s)", total)),
            followers: Some(total),
            profile_picture: None,
            category: "development".to_string(),
            risk_level: if total > 50 { "medium" } else { "low" }.to_string(),
        })
    }

    async fn check_dockerhub_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://hub.docker.com/v2/users/{}/", username);
        let resp = client.get(&url).send().await.ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;

        let full_name = body.get("full_name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let location = body.get("location").and_then(|v| v.as_str()).map(|s| s.to_string());
        let company = body.get("company").and_then(|v| v.as_str()).map(|s| s.to_string());
        let avatar = body.get("gravatar_url").and_then(|v| v.as_str()).map(|s| s.to_string());

        let mut bio_parts = Vec::new();
        if let Some(n) = &full_name {
            if !n.is_empty() {
                bio_parts.push(n.clone());
            }
        }
        if let Some(c) = &company {
            if !c.is_empty() {
                bio_parts.push(format!("Company: {}", c));
            }
        }
        if let Some(l) = &location {
            if !l.is_empty() {
                bio_parts.push(format!("Location: {}", l));
            }
        }

        Some(SocialAccount {
            platform: "Docker Hub".to_string(),
            url: format!("https://hub.docker.com/u/{}", username),
            username: username.to_string(),
            is_verified: false,
            bio: if bio_parts.is_empty() { None } else { Some(bio_parts.join(" | ")) },
            followers: None,
            profile_picture: avatar,
            category: "development".to_string(),
            risk_level: "low".to_string(),
        })
    }

    async fn check_keybase_api(client: &reqwest::Client, username: &str) -> Option<SocialAccount> {
        let url = format!("https://keybase.io/_/api/1.0/user/lookup.json?username={}", username);
        let resp = client.get(&url).send().await.ok()?;

        if resp.status() != 200 {
            return None;
        }

        let body: serde_json::Value = resp.json().await.ok()?;
        let them = body.get("them").and_then(|v| v.as_array())?;

        if them.is_empty() {
            return None;
        }

        let user = &them[0];
        let full_name = user.get("profile").and_then(|p| p.get("full_name")).and_then(|v| v.as_str()).map(|s| s.to_string());
        let bio = user.get("profile").and_then(|p| p.get("bio")).and_then(|v| v.as_str()).map(|s| s.to_string());
        let avatar = user.get("pictures").and_then(|p| p.get("primary")).and_then(|p| p.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());

        let following = user.get("following").and_then(|v| v.as_u64());
        let followers_count = user.get("followers").and_then(|v| v.as_u64());

        let proofs: Vec<String> = user.get("proofs_summary")
            .and_then(|p| p.get("all"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| p.get("proof_type").and_then(|t| t.as_str()).map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let bio_text = match (bio, full_name, proofs.is_empty()) {
            (Some(b), _, _) => Some(b),
            (None, Some(n), _) => Some(n),
            (None, None, false) => Some(format!("Verified: {}", proofs.join(", "))),
            _ => None,
        };

        Some(SocialAccount {
            platform: "Keybase".to_string(),
            url: format!("https://keybase.io/{}", username),
            username: username.to_string(),
            is_verified: !proofs.is_empty(),
            bio: bio_text,
            followers: followers_count.or(following),
            profile_picture: avatar,
            category: "security".to_string(),
            risk_level: if proofs.len() > 5 { "medium" } else { "low" }.to_string(),
        })
    }

    async fn check_http_get(
        client: &reqwest::Client,
        url: &str,
        platform_name: &str,
        username: &str,
        category: &str,
        deep: bool,
    ) -> Option<SocialAccount> {
        let resp = match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };

        let status = resp.status().as_u16();

        match status {
            200 => {
                let html = resp.text().await.unwrap_or_default();

                let (bio, followers, profile_picture) = Self::extract_profile_info(&html, platform_name);

                let is_verified = Self::detect_verification(&html, platform_name);

                let deep_bio = if deep {
                    Self::extract_deep_info(&html, platform_name)
                } else {
                    None
                };

                let final_bio = match (bio, deep_bio) {
                    (Some(b), Some(db)) => Some(format!("{} | {}", b, db)),
                    (Some(b), None) => Some(b),
                    (None, Some(db)) => Some(db),
                    (None, None) => None,
                };

                let risk_level = match followers {
                    Some(f) if f > 10000 => "high",
                    Some(f) if f > 1000 => "medium",
                    _ => "low",
                }.to_string();

                Some(SocialAccount {
                    platform: platform_name.to_string(),
                    url: url.to_string(),
                    username: username.to_string(),
                    is_verified,
                    bio: final_bio,
                    followers,
                    profile_picture,
                    category: category.to_string(),
                    risk_level,
                })
            }
            301 | 302 | 303 | 307 | 308 => {
                Some(SocialAccount {
                    platform: platform_name.to_string(),
                    url: url.to_string(),
                    username: username.to_string(),
                    is_verified: false,
                    bio: None,
                    followers: None,
                    profile_picture: None,
                    category: category.to_string(),
                    risk_level: "low".to_string(),
                })
            }
            403 | 429 => {
                Some(SocialAccount {
                    platform: platform_name.to_string(),
                    url: url.to_string(),
                    username: username.to_string(),
                    is_verified: false,
                    bio: Some("Access restricted (403/429), account may exist".to_string()),
                    followers: None,
                    profile_picture: None,
                    category: category.to_string(),
                    risk_level: "low".to_string(),
                })
            }
            404 | 410 => None,
            _ => None,
        }
    }

    fn extract_profile_info(html: &str, platform_name: &str) -> (Option<String>, Option<u64>, Option<String>) {
        let mut bio = None;
        let mut followers = None;
        let mut profile_picture = None;

        let og_desc = Self::extract_meta_content(html, "og:description");
        let og_image = Self::extract_meta_content(html, "og:image");
        let og_title = Self::extract_meta_content(html, "og:title");
        let desc = Self::extract_meta_content(html, "description");

        if let Some(img) = &og_image {
            if !img.is_empty() && (img.contains("avatar") || img.contains("profile") || img.contains("user") || img.contains("imgur") || img.contains("cdn") || img.contains("pbs")) {
                profile_picture = Some(img.clone());
            }
        }

        match platform_name {
            "Twitter/X" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_follower_count(desc_text);
                }
            }
            "Instagram" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_follower_count(desc_text);
                }
            }
            "TikTok" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_follower_count(desc_text);
                }
            }
            "YouTube" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_subscriber_count(desc_text);
                }
            }
            "Medium" => {
                bio = og_desc.clone().or(desc.clone());
            }
            "Dev.to" => {
                bio = og_desc.clone().or(desc.clone());
            }
            "Twitch" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_follower_count(desc_text);
                }
            }
            "Pinterest" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_follower_count(desc_text);
                }
            }
            "SoundCloud" => {
                bio = og_desc.clone();
                if let Some(desc_text) = &og_desc {
                    followers = Self::extract_follower_count(desc_text);
                }
            }
            _ => {
                bio = og_desc.clone().or(desc.clone()).or(og_title.clone());
            }
        }

        (bio, followers, profile_picture)
    }

    fn extract_meta_content(html: &str, property: &str) -> Option<String> {
        let patterns = if property.starts_with("og:") {
            vec![
                format!(r#"property="{}""#, property),
                format!(r#"property='{}'"#, property),
                format!(r#"name="{}""#, property),
                format!(r#"name='{}'"#, property),
            ]
        } else {
            vec![
                format!(r#"name="{}""#, property),
                format!(r#"name='{}'"#, property),
            ]
        };

        for pattern in &patterns {
            if let Some(pos) = html.find(pattern) {
                let after = &html[pos + pattern.len()..];
                let content_patterns = ["content=\"", "content='"];
                for cp in &content_patterns {
                    if let Some(cpos) = after.find(cp) {
                        let start = cpos + cp.len();
                        let end_char = if cp.ends_with('"') { '"' } else { '\'' };
                        if let Some(end) = after[start..].find(end_char) {
                            let content = &after[start..start + end];
                            if !content.is_empty() {
                                return Some(Self::decode_html_entities(content));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn decode_html_entities(s: &str) -> String {
        s.replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&#x27;", "'")
            .replace("&nbsp;", " ")
    }

    fn extract_follower_count(text: &str) -> Option<u64> {
        let patterns = [
            (r"(\d+(?:,\d+)*)\s*(?:Followers|followers|粉丝|关注者|Follower)", true),
            (r"(\d+(?:\.\d+)?)\s*[Kk]\s*(?:Followers|followers|粉丝)", false),
            (r"(\d+(?:\.\d+)?)\s*[Mm]\s*(?:Followers|followers|粉丝)", false),
        ];

        for (pattern, is_exact) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(m) = caps.get(1) {
                        let num_str = m.as_str().replace(",", "");
                        if let Ok(num) = num_str.parse::<f64>() {
                            let count = if *is_exact {
                                num as u64
                            } else if m.as_str().to_lowercase().contains('k') {
                                (num * 1000.0) as u64
                            } else if m.as_str().to_lowercase().contains('m') {
                                (num * 1000000.0) as u64
                            } else {
                                num as u64
                            };
                            return Some(count);
                        }
                    }
                }
            }
        }

        None
    }

    fn extract_subscriber_count(text: &str) -> Option<u64> {
        let patterns = [
            (r"(\d+(?:,\d+)*)\s*(?:subscribers|订阅者|订阅)", true),
            (r"(\d+(?:\.\d+)?)\s*[Kk]\s*(?:subscribers|订阅)", false),
            (r"(\d+(?:\.\d+)?)\s*[Mm]\s*(?:subscribers|订阅)", false),
        ];

        for (pattern, is_exact) in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(m) = caps.get(1) {
                        let num_str = m.as_str().replace(",", "");
                        if let Ok(num) = num_str.parse::<f64>() {
                            let count = if *is_exact {
                                num as u64
                            } else if m.as_str().to_lowercase().contains('k') {
                                (num * 1000.0) as u64
                            } else if m.as_str().to_lowercase().contains('m') {
                                (num * 1000000.0) as u64
                            } else {
                                num as u64
                            };
                            return Some(count);
                        }
                    }
                }
            }
        }

        Self::extract_follower_count(text)
    }

    fn extract_deep_info(html: &str, _platform_name: &str) -> Option<String> {
        let mut info_parts: Vec<String> = Vec::new();

        let og_site = Self::extract_meta_content(html, "og:site_name");
        if let Some(site) = &og_site {
            info_parts.push(format!("Site: {}", site));
        }

        let og_locale = Self::extract_meta_content(html, "og:locale");
        if let Some(locale) = &og_locale {
            info_parts.push(format!("Locale: {}", locale));
        }

        let twitter_card = Self::extract_meta_content(html, "twitter:card");
        if twitter_card.is_some() {
            info_parts.push("Has Twitter Card".to_string());
        }

        let canonical = Self::extract_link_href(html, "canonical");
        if canonical.is_some() {
            info_parts.push("Canonical URL present".to_string());
        }

        let title_tag = Self::extract_title_tag(html);
        if let Some(title) = &title_tag {
            if !title.is_empty() && title.len() < 200 {
                info_parts.push(format!("Title: {}", title));
            }
        }

        if html.contains("joined") || html.contains("Joined") || html.contains("加入") {
            info_parts.push("Has join date".to_string());
        }

        if html.contains("location") || html.contains("Location") || html.contains("位置") {
            info_parts.push("Has location info".to_string());
        }

        if html.contains("website") || html.contains("Website") || html.contains("链接") {
            info_parts.push("Has external links".to_string());
        }

        if info_parts.is_empty() {
            None
        } else {
            Some(info_parts.join("; "))
        }
    }

    fn extract_link_href(html: &str, rel: &str) -> Option<String> {
        let patterns = [
            format!(r#"rel="{}""#, rel),
            format!(r#"rel='{}'"#, rel),
        ];
        for pattern in &patterns {
            if let Some(pos) = html.find(pattern) {
                let before = &html[..pos];
                let after = &html[pos + pattern.len()..];
                let href_patterns = ["href=\"", "href='"];
                for hp in &href_patterns {
                    if let Some(hpos) = before.rfind(hp) {
                        let start = hpos + hp.len();
                        let end_char = if hp.ends_with('"') { '"' } else { '\'' };
                        if let Some(end) = before[start..].find(end_char) {
                            let content = &before[start..start + end];
                            if !content.is_empty() {
                                return Some(content.to_string());
                            }
                        }
                    }
                    if let Some(hpos) = after.find(hp) {
                        let start = hpos + hp.len();
                        let end_char = if hp.ends_with('"') { '"' } else { '\'' };
                        if let Some(end) = after[start..].find(end_char) {
                            let content = &after[start..start + end];
                            if !content.is_empty() {
                                return Some(content.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_title_tag(html: &str) -> Option<String> {
        if let Some(start) = html.find("<title>") {
            let content_start = start + 7;
            if let Some(end) = html[content_start..].find("</title>") {
                let title = &html[content_start..content_start + end];
                let decoded = Self::decode_html_entities(title);
                let trimmed = decoded.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    fn detect_verification(html: &str, platform_name: &str) -> bool {
        let verification_indicators = [
            "verified", "Verified", "badge-verified", "is-verified",
            "verified-badge", "svg.*verified", "blue.*badge", "blue.*tick",
        ];

        for indicator in &verification_indicators {
            if html.contains(indicator) {
                return true;
            }
        }

        match platform_name {
            "Twitter/X" => html.contains("verified") || html.contains("blueVerified"),
            "Instagram" => html.contains("verified") && html.contains("badge"),
            _ => false,
        }
    }

    async fn correlate_email(client: &reqwest::Client, email: &str, username: &str, found_accounts: &[SocialAccount]) -> EmailCorrelation {
        let mut correlated = Vec::new();
        let email_prefix = email.split('@').next().unwrap_or("");
        let username_variations = [
            username.to_string(),
            username.to_lowercase(),
            username.replace('_', ""),
            username.replace('-', ""),
            username.replace('.', ""),
            email_prefix.to_string(),
        ];

        for account in found_accounts {
            let username_match = username_variations.iter().any(|v| 
                account.username.to_lowercase() == v.to_lowercase()
            );
            correlated.push(CorrelatedPlatform {
                platform: account.platform.clone(),
                found: true,
                email_match: false,
                username_match,
            });
        }

        let gravatar_hash = {
            let clean_email = email.trim().to_lowercase();
            let mut hasher = md5::Md5::default();
            hasher.update(clean_email.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        let mut gravatar_info = GravatarInfo {
            hash: gravatar_hash.clone(),
            has_avatar: false,
            profile_url: None,
            display_name: None,
            location: None,
        };

        let gravatar_url = format!("https://www.gravatar.com/{}.json", gravatar_hash);
        if let Ok(resp) = client.get(&gravatar_url)
            .header("User-Agent", "BiosPherePro-OSINT")
            .timeout(std::time::Duration::from_secs(10))
            .send().await
        {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(entry) = body.get("entry").and_then(|e| e.as_array()).and_then(|a| a.first()) {
                        gravatar_info.has_avatar = entry.get("thumbnailUrl").is_some();
                        gravatar_info.profile_url = entry.get("profileUrl").and_then(|u| u.as_str()).map(|s| s.to_string());
                        gravatar_info.display_name = entry.get("displayName").and_then(|d| d.as_str()).map(|s| s.to_string());
                        gravatar_info.location = entry.get("currentLocation").and_then(|l| l.as_str()).map(|s| s.to_string());
                    }
                }
            }
        }

        let mut breaches = Vec::new();
        let hibp_url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}", urlencoding::encode(email));
        if let Ok(resp) = client.get(&hibp_url)
            .header("User-Agent", "BiosPherePro-OSINT")
            .header("hibp-api-key", "")
            .timeout(std::time::Duration::from_secs(10))
            .send().await
        {
            if resp.status() == 200 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(arr) = body.as_array() {
                        for breach in arr.iter().take(20) {
                            if let Some(name) = breach.get("Name").and_then(|n| n.as_str()) {
                                breaches.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }

        EmailCorrelation {
            email: email.to_string(),
            correlated_platforms: correlated,
            gravatar_info: Some(gravatar_info),
            haveibeenpwned_breaches: breaches,
        }
    }

    fn analyze_faces(images: &[String]) -> FaceAnalysis {
        if images.is_empty() {
            return FaceAnalysis {
                total_profiles_with_images: 0,
                unique_images: 0,
                possible_same_person: false,
                confidence: 0.0,
                image_urls: Vec::new(),
                details: "No profile images found for analysis".to_string(),
            };
        }

        let mut unique_hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
        for img in images {
            if let Ok(url) = url::Url::parse(img) {
                if let Some(host) = url.host_str() {
                    unique_hosts.insert(host.to_string());
                }
            }
        }

        let same_host_count = images.iter()
            .filter(|img| img.contains("gravatar") || img.contains("avatar"))
            .count();

        let possible_same = same_host_count >= 2 || (images.len() >= 3 && unique_hosts.len() <= 2);
        let confidence = if possible_same { 0.7 } else { 0.3 };

        FaceAnalysis {
            total_profiles_with_images: images.len(),
            unique_images: unique_hosts.len(),
            possible_same_person: possible_same,
            confidence,
            image_urls: images.to_vec(),
            details: format!(
                "Found {} profile images across {} image hosts. {} suggest the same person across platforms",
                images.len(),
                unique_hosts.len(),
                if possible_same { "Patterns" } else { "No clear patterns" }
            ),
        }
    }

    fn cross_reference(username: &str, found_accounts: &[SocialAccount]) -> CrossReferenceReport {
        let variations = {
            let mut vars = vec![
                username.to_string(),
                username.to_lowercase(),
                username.to_uppercase(),
            ];
            if username.contains('_') {
                vars.push(username.replace('_', "-"));
                vars.push(username.replace('_', "."));
                vars.push(username.replace('_', ""));
            }
            if username.contains('-') {
                vars.push(username.replace('-', "_"));
                vars.push(username.replace('-', "."));
                vars.push(username.replace('-', ""));
            }
            if username.contains('.') {
                vars.push(username.replace('.', "_"));
                vars.push(username.replace('.', "-"));
                vars.push(username.replace('.', ""));
            }
            vars.dedup();
            vars
        };

        let mut name_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let location_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for account in found_accounts {
            if let Some(ref bio) = account.bio {
                if bio.len() < 100 && !bio.contains("karma") && !bio.contains("repos") {
                    *name_counts.entry(bio.clone()).or_insert(0) += 1;
                }
            }
        }

        let consistent_name = name_counts.iter()
            .filter(|(_, &count)| count >= 2)
            .max_by_key(|(_, &count)| count)
            .map(|(name, _)| name.clone());

        let consistent_location = location_counts.iter()
            .filter(|(_, &count)| count >= 2)
            .max_by_key(|(_, &count)| count)
            .map(|(loc, _)| loc.clone());

        let mut linked = Vec::new();
        let dev_platforms: Vec<&SocialAccount> = found_accounts.iter()
            .filter(|a| a.category == "development")
            .collect();
        if dev_platforms.len() >= 2 {
            for i in 0..dev_platforms.len() {
                for j in (i+1)..dev_platforms.len() {
                    linked.push(LinkedAccount {
                        source_platform: dev_platforms[i].platform.clone(),
                        target_platform: dev_platforms[j].platform.clone(),
                        link_type: "same_category_development".to_string(),
                        confidence: 0.8,
                    });
                }
            }
        }

        let social_platforms: Vec<&SocialAccount> = found_accounts.iter()
            .filter(|a| a.category == "social")
            .collect();
        if social_platforms.len() >= 2 {
            for i in 0..social_platforms.len() {
                for j in (i+1)..social_platforms.len() {
                    linked.push(LinkedAccount {
                        source_platform: social_platforms[i].platform.clone(),
                        target_platform: social_platforms[j].platform.clone(),
                        link_type: "same_category_social".to_string(),
                        confidence: 0.6,
                    });
                }
            }
        }

        let footprint_score = {
            let base = (found_accounts.len() as f64 * 0.1).min(0.5);
            let category_bonus = {
                let cats: std::collections::HashSet<&str> = found_accounts.iter().map(|a| a.category.as_str()).collect();
                (cats.len() as f64 * 0.05).min(0.3)
            };
            let verified_bonus = found_accounts.iter().filter(|a| a.is_verified).count() as f64 * 0.05;
            (base + category_bonus + verified_bonus).min(1.0)
        };

        CrossReferenceReport {
            username_variations: variations,
            consistent_name,
            consistent_location,
            linked_accounts: linked,
            digital_footprint_score: footprint_score,
        }
    }
}
