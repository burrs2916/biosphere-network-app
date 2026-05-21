use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringConfig {
    pub target_url: Option<String>,
    pub email_content: Option<String>,
    pub domain: Option<String>,
    pub analysis_type: String,
    pub check_typosquatting: bool,
    pub check_homograph: bool,
    pub check_brand_impersonation: bool,
}

impl Default for SocialEngineeringConfig {
    fn default() -> Self {
        Self {
            target_url: None,
            email_content: None,
            domain: None,
            analysis_type: "comprehensive".to_string(),
            check_typosquatting: true,
            check_homograph: true,
            check_brand_impersonation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingResult {
    pub original_domain: String,
    pub typosquatted_domains: Vec<TyposquattedDomain>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattedDomain {
    pub domain: String,
    pub technique: String,
    pub is_registered: bool,
    pub similarity_score: f64,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandImpersonation {
    pub brand: String,
    pub impersonation_type: String,
    pub indicators: Vec<String>,
    pub confidence: f64,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailPhishingIndicator {
    pub indicator_type: String,
    pub description: String,
    pub value: String,
    pub risk_level: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialEngineeringResult {
    pub success: bool,
    pub analysis_type: String,
    pub typosquatting: Option<TyposquattingResult>,
    pub brand_impersonations: Vec<BrandImpersonation>,
    pub email_indicators: Vec<EmailPhishingIndicator>,
    pub security_findings: Vec<SocialEngineeringFinding>,
    pub summary: String,
}

pub struct SocialEngineeringTool;

impl SocialEngineeringTool {
    pub async fn analyze(config: &SocialEngineeringConfig) -> std::result::Result<SocialEngineeringResult, String> {
        if config.target_url.is_none() && config.email_content.is_none() && config.domain.is_none() {
            return Err("At least one analysis target (URL, email content, or domain) is required".to_string());
        }

        let mut typosquatting = None;
        let mut brand_impersonations = Vec::new();
        let mut email_indicators = Vec::new();
        let mut security_findings = Vec::new();

        if let Some(domain) = &config.domain {
            if !domain.trim().is_empty() {
                if config.check_typosquatting {
                    typosquatting = Some(Self::check_typosquatting(domain.trim(), &mut security_findings));
                }
                if config.check_brand_impersonation {
                    Self::check_brand_impersonation(domain.trim(), &mut brand_impersonations, &mut security_findings);
                }
                if config.check_homograph {
                    Self::check_homograph(domain.trim(), &mut security_findings);
                }
            }
        }

        if let Some(email) = &config.email_content {
            if !email.trim().is_empty() {
                Self::analyze_email(email.trim(), &mut email_indicators, &mut security_findings);
            }
        }

        if let Some(url) = &config.target_url {
            if !url.trim().is_empty() {
                Self::analyze_url(url.trim(), &mut email_indicators, &mut security_findings);
            }
        }

        let summary = Self::build_summary(&typosquatting, &brand_impersonations, &email_indicators, &security_findings);

        Ok(SocialEngineeringResult {
            success: true,
            analysis_type: config.analysis_type.clone(),
            typosquatting,
            brand_impersonations,
            email_indicators,
            security_findings,
            summary,
        })
    }

    fn check_typosquatting(domain: &str, findings: &mut Vec<SocialEngineeringFinding>) -> TyposquattingResult {
        let mut typosquatted = Vec::new();

        let omitted = Self::generate_omitted_chars(domain);
        for variant in omitted {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "character_omission".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        let hyphenated = Self::generate_hyphenated(domain);
        for variant in hyphenated {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "hyphen_insertion".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        let replaced = Self::generate_adjacent_replacements(domain);
        for variant in replaced {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "adjacent_replacement".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        let doubled = Self::generate_doubled_chars(domain);
        for variant in doubled {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "character_doubling".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        let tld_swapped = Self::generate_tld_swaps(domain);
        for variant in tld_swapped {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "tld_swap".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        let subdomain_swapped = Self::generate_subdomain_swaps(domain);
        for variant in subdomain_swapped {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "subdomain_swap".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        let vowel_swapped = Self::generate_vowel_swaps(domain);
        for variant in vowel_swapped {
            let score = Self::calculate_similarity(domain, &variant);
            typosquatted.push(TyposquattedDomain {
                domain: variant,
                technique: "vowel_swap".to_string(),
                is_registered: false,
                similarity_score: score,
                risk_level: Self::score_to_risk(score),
            });
        }

        typosquatted.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap_or(std::cmp::Ordering::Equal));
        typosquatted.truncate(30);

        let overall_risk = if typosquatted.iter().any(|t| t.risk_level == "critical") {
            "critical"
        } else if typosquatted.iter().any(|t| t.risk_level == "high") {
            "high"
        } else {
            "medium"
        }.to_string();

        findings.push(SocialEngineeringFinding {
            severity: if overall_risk == "critical" { "critical" } else { "high" }.to_string(),
            category: "typosquatting".to_string(),
            description: format!("Domain {} has {} potential typosquatted variants", domain, typosquatted.len()),
            recommendation: "Register key typosquatted domain variants and set up domain monitoring alerts".to_string(),
            mitre_technique: Some("T1583.001".to_string()),
        });

        TyposquattingResult {
            original_domain: domain.to_string(),
            typosquatted_domains: typosquatted,
            risk_level: overall_risk,
        }
    }

    fn check_homograph(domain: &str, findings: &mut Vec<SocialEngineeringFinding>) {
        let homograph_map: [(char, char); 14] = [
            ('a', 'а'), ('c', 'с'), ('e', 'е'), ('o', 'о'),
            ('p', 'р'), ('x', 'х'), ('y', 'у'), ('i', 'і'),
            ('j', 'ј'), ('s', 'ѕ'), ('d', 'ԁ'), ('g', 'ɡ'),
            ('h', 'һ'), ('n', 'ո'),
        ];

        let domain_lower: Vec<char> = domain.to_lowercase().chars().collect();
        let mut homograph_count = 0;

        for c in &domain_lower {
            for (latin, _cyrillic) in &homograph_map {
                if c == latin {
                    homograph_count += 1;
                    break;
                }
            }
        }

        if homograph_count > 0 {
            let risk = if homograph_count >= 4 { "critical" } else if homograph_count >= 2 { "high" } else { "medium" };
            findings.push(SocialEngineeringFinding {
                severity: risk.to_string(),
                category: "homograph_attack".to_string(),
                description: format!("Domain contains {} characters that could be replaced with visually similar Unicode characters", homograph_count),
                recommendation: "Use Punycode display in browsers and verify domain encoding before visiting".to_string(),
                mitre_technique: Some("T1583.001".to_string()),
            });
        }
    }

    fn check_brand_impersonation(
        domain: &str,
        impersonations: &mut Vec<BrandImpersonation>,
        findings: &mut Vec<SocialEngineeringFinding>,
    ) {
        let known_brands: [(&str, &[&str]); 10] = [
            ("google", &["google-login", "google-verify", "google-security", "google-account", "google-drive", "google-docs"]),
            ("microsoft", &["microsoft-login", "office365-verify", "ms-security", "azure-login", "microsoft-team", "outlook-login"]),
            ("apple", &["apple-id", "icloud-verify", "apple-security", "apple-support", "apple-store"]),
            ("amazon", &["amazon-login", "aws-verify", "amazon-security", "prime-verify", "amazon-delivery"]),
            ("paypal", &["paypal-login", "paypal-verify", "paypal-security", "paypal-payment"]),
            ("facebook", &["fb-login", "facebook-verify", "meta-security", "facebook-update"]),
            ("netflix", &["netflix-login", "netflix-verify", "netflix-billing", "netflix-update"]),
            ("twitter", &["twitter-login", "twitter-verify", "x-security", "twitter-reset"]),
            ("linkedin", &["linkedin-login", "linkedin-verify", "linkedin-security"]),
            ("bank", &["bank-login", "bank-verify", "banking-security", "online-banking"]),
        ];

        let domain_lower = domain.to_lowercase();
        for (brand, indicators) in &known_brands {
            if domain_lower.contains(brand) {
                let matched_indicators: Vec<String> = indicators
                    .iter()
                    .filter(|ind| {
                        let prefix = ind.split('-').next().unwrap_or("");
                        domain_lower.contains(prefix)
                    })
                    .map(|s| s.to_string())
                    .collect();

                let confidence = if !matched_indicators.is_empty() {
                    0.85 + (matched_indicators.len() as f64 * 0.03).min(0.15)
                } else {
                    0.6
                };

                impersonations.push(BrandImpersonation {
                    brand: brand.to_string(),
                    impersonation_type: "domain_impersonation".to_string(),
                    indicators: if matched_indicators.is_empty() { vec![format!("contains brand name: {}", brand)] } else { matched_indicators },
                    confidence,
                    risk_level: if confidence > 0.85 { "critical" } else if confidence > 0.7 { "high" } else { "medium" }.to_string(),
                });
            }
        }

        if !impersonations.is_empty() {
            let critical_count = impersonations.iter().filter(|i| i.risk_level == "critical").count();
            findings.push(SocialEngineeringFinding {
                severity: if critical_count > 0 { "critical" } else { "high" }.to_string(),
                category: "brand_impersonation".to_string(),
                description: format!("Detected {} brand impersonation attempts", impersonations.len()),
                recommendation: "Report impersonation domains to brand owners and relevant authorities".to_string(),
                mitre_technique: Some("T1583.001".to_string()),
            });
        }
    }

    fn analyze_email(
        email: &str,
        indicators: &mut Vec<EmailPhishingIndicator>,
        findings: &mut Vec<SocialEngineeringFinding>,
    ) {
        let email_lower = email.to_lowercase();

        let urgency_keywords = [
            ("urgent", "high"), ("immediately", "high"), ("expire", "medium"),
            ("suspend", "high"), ("verify your account", "high"), ("action required", "high"),
            ("final notice", "high"), ("account locked", "critical"), ("unauthorized access", "critical"),
            ("security alert", "medium"), ("limited time", "medium"), ("act now", "high"),
        ];

        for (keyword, risk) in &urgency_keywords {
            if email_lower.contains(keyword) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "urgency_language".to_string(),
                    description: format!("Detected urgency keyword: '{}'", keyword),
                    value: keyword.to_string(),
                    risk_level: risk.to_string(),
                    recommendation: "Verify email sender, do not rush into action due to urgency".to_string(),
                });
            }
        }

        let action_keywords = [
            ("click here", "high"), ("download now", "high"), ("confirm your", "high"),
            ("update your", "medium"), ("reset your password", "high"), ("verify your identity", "high"),
            ("enable access", "high"), ("validate your", "high"),
        ];

        for (keyword, risk) in &action_keywords {
            if email_lower.contains(keyword) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "action_inducing".to_string(),
                    description: format!("Detected action-inducing keyword: '{}'", keyword),
                    value: keyword.to_string(),
                    risk_level: risk.to_string(),
                    recommendation: "Do not click links directly in emails, manually visit the official website".to_string(),
                });
            }
        }

        if email.contains("http://") {
            indicators.push(EmailPhishingIndicator {
                indicator_type: "insecure_link".to_string(),
                description: "Email contains HTTP (non-HTTPS) links".to_string(),
                value: "http://".to_string(),
                risk_level: "high".to_string(),
                recommendation: "Do not click insecure HTTP links".to_string(),
            });
        }

        let ip_url_pattern = regex::Regex::new(r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").ok();
        if let Some(pattern) = &ip_url_pattern {
            if pattern.is_match(email) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "ip_address_url".to_string(),
                    description: "Email contains IP address URL instead of domain name".to_string(),
                    value: "IP address URL".to_string(),
                    risk_level: "critical".to_string(),
                    recommendation: "Legitimate services never use raw IP addresses in links".to_string(),
                });
            }
        }

        if email.contains("@") && email.contains("Reply-To:") {
            let reply_to_match = regex::Regex::new(r"Reply-To:\s*\S+@\S+").ok();
            let from_match = regex::Regex::new(r"From:\s*\S+@\S+").ok();
            if let (Some(rt), Some(fm)) = (reply_to_match, from_match) {
                if let (Some(rt_match), Some(fm_match)) = (rt.find(email), fm.find(email)) {
                    let rt_str = rt_match.as_str();
                    let rt_domain: Option<String> = rt_str.split('@').next_back().map(|d: &str| d.trim().to_lowercase());
                    let fm_str = fm_match.as_str();
                    let fm_domain: Option<String> = fm_str.split('@').next_back().map(|d: &str| d.trim().to_lowercase());
                    if let (Some(rt_d), Some(fm_d)) = (rt_domain, fm_domain) {
                        if rt_d != fm_d {
                            indicators.push(EmailPhishingIndicator {
                                indicator_type: "mismatched_reply_to".to_string(),
                                description: "Reply-To domain differs from From domain".to_string(),
                                value: format!("From: {} / Reply-To: {}", fm_d, rt_d),
                                risk_level: "critical".to_string(),
                                recommendation: "Reply-To mismatch is a strong phishing indicator, do not reply".to_string(),
                            });
                        }
                    }
                }
            }
        }

        let url_count = email_lower.matches("http://").count() + email_lower.matches("https://").count();
        if url_count > 3 {
            indicators.push(EmailPhishingIndicator {
                indicator_type: "excessive_links".to_string(),
                description: format!("Email contains {} URLs, which is unusually high", url_count),
                value: url_count.to_string(),
                risk_level: "medium".to_string(),
                recommendation: "Legitimate emails typically have few links, verify each one carefully".to_string(),
            });
        }

        let attachment_patterns = [".exe", ".scr", ".zip", ".rar", ".js", ".vbs", ".bat", ".cmd", ".ps1"];
        for pattern in &attachment_patterns {
            if email_lower.contains(pattern) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "suspicious_attachment".to_string(),
                    description: format!("Email references potentially dangerous file type: {}", pattern),
                    value: pattern.to_string(),
                    risk_level: "critical".to_string(),
                    recommendation: "Do not download or open suspicious attachments, scan with antivirus first".to_string(),
                });
                break;
            }
        }

        if !indicators.is_empty() {
            let critical_count = indicators.iter().filter(|i| i.risk_level == "critical").count();
            findings.push(SocialEngineeringFinding {
                severity: if critical_count > 0 { "critical" } else { "high" }.to_string(),
                category: "email_phishing".to_string(),
                description: format!("Detected {} phishing indicators in email content", indicators.len()),
                recommendation: "Verify sender email address, do not click suspicious links or open attachments".to_string(),
                mitre_technique: Some("T1566.001".to_string()),
            });
        }
    }

    fn analyze_url(
        url: &str,
        indicators: &mut Vec<EmailPhishingIndicator>,
        findings: &mut Vec<SocialEngineeringFinding>,
    ) {
        if url.contains('@') {
            indicators.push(EmailPhishingIndicator {
                indicator_type: "url_deception".to_string(),
                description: "URL contains @ symbol, which may be used for URL deception".to_string(),
                value: "@".to_string(),
                risk_level: "high".to_string(),
                recommendation: "Do not visit URLs containing @ symbols, they can mask the real destination".to_string(),
            });
        }

        let url_lower = url.to_lowercase();
        let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".bid"];
        for tld in &suspicious_tlds {
            if url_lower.contains(tld) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "suspicious_tld".to_string(),
                    description: format!("URL uses suspicious top-level domain: {}", tld),
                    value: tld.to_string(),
                    risk_level: "medium".to_string(),
                    recommendation: "Be cautious when visiting sites with free or suspicious TLDs".to_string(),
                });
            }
        }

        if url.len() > 75 {
            indicators.push(EmailPhishingIndicator {
                indicator_type: "excessive_url_length".to_string(),
                description: format!("URL length is abnormal: {} characters", url.len()),
                value: url.len().to_string(),
                risk_level: "low".to_string(),
                recommendation: "Excessively long URLs may be used to hide the real destination".to_string(),
            });
        }

        let ip_url_pattern = regex::Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").ok();
        if let Some(pattern) = &ip_url_pattern {
            if pattern.is_match(url) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "ip_address_url".to_string(),
                    description: "URL uses IP address instead of domain name".to_string(),
                    value: "IP address URL".to_string(),
                    risk_level: "high".to_string(),
                    recommendation: "Legitimate websites rarely use raw IP addresses".to_string(),
                });
            }
        }

        let encoded_patterns = ["%40", "%3A", "%2F", "%00"];
        for enc in &encoded_patterns {
            if url_lower.contains(enc) {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "url_encoding".to_string(),
                    description: format!("URL contains encoded characters: {}", enc),
                    value: enc.to_string(),
                    risk_level: "medium".to_string(),
                    recommendation: "URL encoding may be used to hide the real destination".to_string(),
                });
                break;
            }
        }

        let redirect_patterns = ["//", "redirect", "url=", "next=", "target=", "redir="];
        for pattern in &redirect_patterns {
            if url_lower.contains(pattern) && url_lower.matches("http").count() > 1 {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "open_redirect".to_string(),
                    description: format!("URL may contain open redirect pattern: {}", pattern),
                    value: pattern.to_string(),
                    risk_level: "high".to_string(),
                    recommendation: "Open redirects can lead to phishing sites, verify the final destination".to_string(),
                });
                break;
            }
        }

        if (url_lower.contains("login") || url_lower.contains("signin") || url_lower.contains("account"))
            && url_lower.starts_with("http://") {
                indicators.push(EmailPhishingIndicator {
                    indicator_type: "insecure_login_page".to_string(),
                    description: "Login-related URL uses insecure HTTP instead of HTTPS".to_string(),
                    value: "http:// + login".to_string(),
                    risk_level: "critical".to_string(),
                    recommendation: "Legitimate login pages always use HTTPS, do not enter credentials on HTTP pages".to_string(),
                });
            }

        if !indicators.is_empty() {
            let critical_count = indicators.iter().filter(|i| i.risk_level == "critical").count();
            findings.push(SocialEngineeringFinding {
                severity: if critical_count > 0 { "critical" } else { "medium" }.to_string(),
                category: "url_analysis".to_string(),
                description: format!("URL analysis found {} suspicious indicators", indicators.len()),
                recommendation: "Carefully verify the real destination of the URL".to_string(),
                mitre_technique: Some("T1204".to_string()),
            });
        }
    }

    fn calculate_similarity(original: &str, variant: &str) -> f64 {
        let orig_len = original.len() as f64;
        let var_len = variant.len() as f64;
        if orig_len == 0.0 { return 0.0; }

        let len_diff = (orig_len - var_len).abs() / orig_len;

        let matching_chars = original.chars().zip(variant.chars()).filter(|(a, b)| a == b).count() as f64;
        let char_similarity = matching_chars / orig_len.max(var_len);

        let similarity = char_similarity * (1.0 - len_diff * 0.5);
        (similarity * 100.0).round() / 100.0
    }

    fn score_to_risk(score: f64) -> String {
        if score >= 0.9 { "critical" }
        else if score >= 0.8 { "high" }
        else if score >= 0.6 { "medium" }
        else { "low" }.to_string()
    }

    fn build_summary(
        typosquatting: &Option<TyposquattingResult>,
        impersonations: &[BrandImpersonation],
        email_indicators: &[EmailPhishingIndicator],
        findings: &[SocialEngineeringFinding],
    ) -> String {
        let mut parts = Vec::new();

        if let Some(ts) = typosquatting {
            parts.push(format!("Typosquatted domains: {}", ts.typosquatted_domains.len()));
        }
        if !impersonations.is_empty() {
            parts.push(format!("Brand impersonations: {}", impersonations.len()));
        }
        if !email_indicators.is_empty() {
            parts.push(format!("Phishing indicators: {}", email_indicators.len()));
        }

        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let high = findings.iter().filter(|f| f.severity == "high").count();

        if critical > 0 || high > 0 {
            parts.insert(0, format!("Social engineering risk detected: {} critical, {} high", critical, high));
        } else {
            parts.insert(0, "Social engineering analysis complete".to_string());
        }

        parts.join(" | ")
    }

    fn generate_omitted_chars(domain: &str) -> Vec<String> {
        let mut results = Vec::new();
        let chars: Vec<char> = domain.chars().collect();
        for i in 0..chars.len() {
            let mut modified: Vec<char> = chars.clone();
            modified.remove(i);
            results.push(modified.into_iter().collect());
        }
        results
    }

    fn generate_hyphenated(domain: &str) -> Vec<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            let name = parts[0];
            let suffix = parts[1..].join(".");
            let mut results = Vec::new();
            let chars: Vec<char> = name.chars().collect();
            for i in 1..chars.len() {
                let hyphenated: String = format!("{}-{}", &name[..i], &name[i..]);
                results.push(format!("{}.{}", hyphenated, suffix));
            }
            results
        } else {
            vec![]
        }
    }

    fn generate_adjacent_replacements(domain: &str) -> Vec<String> {
        let adjacent_keys: std::collections::HashMap<char, &str> = [
            ('a', "qwsz"), ('b', "vghn"), ('c', "xdfv"), ('d', "serfcx"),
            ('e', "wrsdf3"), ('f', "drtgvc"), ('g', "ftyhbv"), ('h', "gyujnb"),
            ('i', "ujko8"), ('j', "huikmn"), ('k', "jiolm"), ('l', "kop"),
            ('m', "njk"), ('n', "bhjm"), ('o', "iklp9"), ('p', "ol0"),
            ('q', "wa"), ('r', "edft4"), ('s', "awedxz"), ('t', "rfgy5"),
            ('u', "yhji7"), ('v', "cfgb"), ('w', "qase"), ('x', "zsdc"),
            ('y', "tghu6"), ('z', "asx"),
        ].iter().cloned().collect();

        let mut results = Vec::new();
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 { return results; }
        let name = parts[0];
        let suffix = parts[1..].join(".");

        for (i, c) in name.chars().enumerate() {
            let lower = c.to_ascii_lowercase();
            if let Some(adj) = adjacent_keys.get(&lower) {
                for replacement in adj.chars().take(2) {
                    let mut modified: Vec<char> = name.chars().collect();
                    modified[i] = replacement;
                    results.push(format!("{}.{}", modified.into_iter().collect::<String>(), suffix));
                }
            }
        }

        results.truncate(10);
        results
    }

    fn generate_doubled_chars(domain: &str) -> Vec<String> {
        let mut results = Vec::new();
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 { return results; }
        let name = parts[0];
        let suffix = parts[1..].join(".");

        let chars: Vec<char> = name.chars().collect();
        for i in 0..chars.len() {
            if results.len() >= 8 { break; }
            let doubled: String = format!("{}{}{}", &name[..i], chars[i], &name[i..]);
            results.push(format!("{}.{}", doubled, suffix));
        }

        results
    }

    fn generate_tld_swaps(domain: &str) -> Vec<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 { return vec![]; }

        let name = parts[0];
        let alternative_tlds = ["com", "net", "org", "io", "co", "xyz", "cc", "info", "biz", "dev"];

        alternative_tlds.iter()
            .filter(|tld| !domain.to_lowercase().ends_with(&format!(".{}", tld)))
            .take(5)
            .map(|tld| format!("{}.{}", name, tld))
            .collect()
    }

    fn generate_subdomain_swaps(domain: &str) -> Vec<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 { return vec![]; }
        let name = parts[0];
        let suffix = parts[1..].join(".");
        let prefixes = ["www", "mail", "login", "secure", "account"];

        prefixes.iter()
            .map(|prefix| format!("{}.{}.{}", prefix, name, suffix))
            .collect()
    }

    fn generate_vowel_swaps(domain: &str) -> Vec<String> {
        let mut results = Vec::new();
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 { return results; }
        let name = parts[0];
        let suffix = parts[1..].join(".");
        let vowels = [('a', 'e'), ('e', 'a'), ('i', 'e'), ('o', 'a'), ('u', 'o')];

        for (v1, v2) in &vowels {
            if name.to_lowercase().contains(*v1) {
                let swapped: String = name.chars().map(|c| {
                    if c.to_ascii_lowercase() == *v1 { *v2 } else { c }
                }).collect();
                if swapped != name {
                    results.push(format!("{}.{}", swapped, suffix));
                }
            }
        }

        results.truncate(5);
        results
    }
}
