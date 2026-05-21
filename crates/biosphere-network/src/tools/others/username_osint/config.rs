use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UsernameOsintConfig {
    pub username: String,
    pub timeout: u64,
    pub platforms: Vec<String>,
    pub categories: Vec<String>,
    pub check_all: bool,
    pub retries: u32,
    pub concurrent_limit: usize,
    pub generate_permutations: bool,
    pub usernames: Vec<String>,
    pub recursive_search: bool,
    pub max_recursive_depth: u32,
    pub tags: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub top_sites: usize,
    pub use_disabled_sites: bool,
    pub id_type: String,
    pub cookie_jar: Option<String>,
    pub proxy_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameOsintResult {
    pub username: String,
    pub found_on: Vec<PlatformResult>,
    pub not_found_on: Vec<PlatformResult>,
    pub errors: Vec<PlatformResult>,
    pub total_found: usize,
    pub total_checked: usize,
    pub total_errors: usize,
    pub digital_footprint_score: f64,
    pub risk_level: String,
    pub category_summary: Vec<CategorySummary>,
    pub summary: String,
    pub permutations: Vec<String>,
    pub batch_results: Vec<BatchUsernameResult>,
    pub error_analysis: Option<ErrorAnalysis>,
    pub recursive_results: Vec<RecursiveSearchResult>,
    pub extracted_ids: Vec<super::id_types::ExtractedId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchUsernameResult {
    pub username: String,
    pub found_count: usize,
    pub total_checked: usize,
    pub digital_footprint_score: f64,
    pub risk_level: String,
    pub found_on: Vec<PlatformResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformResult {
    pub platform: String,
    pub url: String,
    pub found: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub error_type: Option<String>,
    pub category: String,
    pub response_time_ms: Option<u64>,
    pub page_title: Option<String>,
    pub is_captcha: bool,
    pub is_censored: bool,
    pub retry_count: u32,
    pub detection_method: Option<String>,
    pub protection_type: Option<String>,
    pub suggested_action: Option<String>,
    pub extracted_info: Option<ExtractedUserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedUserInfo {
    pub full_name: Option<String>,
    pub location: Option<String>,
    pub bio: Option<String>,
    pub profile_image_url: Option<String>,
    pub external_links: Vec<String>,
    pub id_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorAnalysis {
    pub error_categories: Vec<ErrorCategory>,
    pub captcha_count: usize,
    pub censored_count: usize,
    pub network_error_count: usize,
    pub total_error_count: usize,
    pub error_rate: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCategory {
    pub category: String,
    pub count: usize,
    pub platforms: Vec<String>,
    pub severity: String,
    pub description: String,
    pub suggested_fix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category: String,
    pub total: usize,
    pub found: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveSearchResult {
    pub id_value: String,
    pub id_type: String,
    pub source_platform: String,
    pub found_count: usize,
    pub total_checked: usize,
    pub found_on: Vec<PlatformResult>,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintProgress {
    pub checked: usize,
    pub total: usize,
    pub found: usize,
    pub errors: usize,
    pub current_platform: String,
    pub username: String,
    pub latest_result: Option<PlatformResult>,
}

impl Default for UsernameOsintConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            timeout: 10,
            platforms: Vec::new(),
            categories: Vec::new(),
            check_all: true,
            retries: 1,
            concurrent_limit: 15,
            generate_permutations: false,
            usernames: Vec::new(),
            recursive_search: true,
            max_recursive_depth: 2,
            tags: Vec::new(),
            exclude_tags: Vec::new(),
            top_sites: 500,
            use_disabled_sites: false,
            id_type: "username".to_string(),
            cookie_jar: None,
            proxy_url: None,
        }
    }
}

pub const PLATFORM_CATEGORIES: &[(&str, &str)] = &[
    ("social", "Social Media"),
    ("developer", "Developer & Tech"),
    ("gaming", "Gaming"),
    ("creative", "Creative & Design"),
    ("music", "Music"),
    ("security", "Security & Privacy"),
    ("finance", "Finance"),
    ("dating", "Dating"),
    ("forum", "Forum & Community"),
    ("other", "Other"),
];

pub fn generate_username_permutations(usernames: &[String]) -> Vec<String> {
    if usernames.is_empty() {
        return Vec::new();
    }
    let mut permutations = usernames.to_vec();

    if usernames.len() >= 2 {
        let separators = ["", "_", "-", "."];
        for i in 0..usernames.len() {
            for j in 0..usernames.len() {
                if i == j { continue; }
                for sep in &separators {
                    let combined = format!("{}{}{}", usernames[i], sep, usernames[j]);
                    if !permutations.contains(&combined) {
                        permutations.push(combined);
                    }
                }
            }
        }
    }

    let common_suffixes = ["123", "1234", "1", "2", "0", "99", "00", "x", "xx", "_1", "_2", "official", "real", "the", "im"];
    let base: Vec<String> = permutations.clone();
    for name in &base {
        for suffix in &common_suffixes {
            let variant = format!("{}{}", name, suffix);
            if !permutations.contains(&variant) {
                permutations.push(variant);
            }
        }
        let lower = name.to_lowercase();
        if lower != *name && !permutations.contains(&lower) {
            permutations.push(lower);
        }
        let upper_first = {
            let mut c = name.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        };
        if upper_first != *name && !permutations.contains(&upper_first) {
            permutations.push(upper_first);
        }
    }

    permutations
}
