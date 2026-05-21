use std::collections::HashMap;

use crate::core::{Result, ToolError};
use super::config::{
    IdnCheckConfig, IdnCheckResult, SuspiciousChar, SimilarDomain, DomainVariant,
    CharSubstitution, ScriptAnalysis, ScriptInfo, BrandMatch, BatchIdnCheckResult,
    CONFUSABLE_CHARS, BRAND_DOMAINS,
};

pub struct IdnCheckerTool;

impl IdnCheckerTool {
    pub async fn check(config: &IdnCheckConfig) -> Result<IdnCheckResult> {
        let domain = config.domain.trim().to_string();
        if domain.is_empty() {
            return Err(ToolError::ExecutionError("Domain is empty".to_string()));
        }

        let domain = Self::clean_domain(&domain);

        let is_idn = domain.chars().any(|c| !c.is_ascii());
        let punycode_domain = if is_idn {
            Some(idna::domain_to_ascii(&domain).unwrap_or_else(|_| domain.clone()))
        } else {
            None
        };

        let mut suspicious_chars = Vec::new();
        for (i, c) in domain.chars().enumerate() {
            for &(confusable, resembles, category, unicode_name) in CONFUSABLE_CHARS {
                if c == confusable {
                    let risk = Self::char_risk_level(category);
                    suspicious_chars.push(SuspiciousChar {
                        position: i,
                        char: c.to_string(),
                        unicode_codepoint: format!("U+{:04X}", c as u32),
                        unicode_name: unicode_name.to_string(),
                        resembles: resembles.to_string(),
                        category: category.to_string(),
                        risk,
                    });
                    break;
                }
            }
        }

        let script_analysis = Self::analyze_scripts(&domain, &suspicious_chars);

        let brand_match = if config.check_brand {
            Self::check_brand_match(&domain)
        } else {
            None
        };

        let is_suspicious = !suspicious_chars.is_empty()
            || is_idn
            || script_analysis.is_mixed_script
            || brand_match.is_some();

        let risk_score = Self::calculate_risk_score(
            &suspicious_chars,
            &script_analysis,
            &brand_match,
            is_idn,
        );

        let risk_level = Self::risk_level_from_score(risk_score);

        let mut similar_domains = Vec::new();
        if is_suspicious {
            Self::generate_similar_domains(&domain, &punycode_domain, &mut similar_domains);
        }

        let mut generated_variants = Vec::new();
        if config.generate_variants {
            generated_variants = Self::generate_domain_variants(&domain, config.max_variants);
            if config.check_dns {
                Self::check_dns_registration(&mut generated_variants).await;
            }
        }

        let summary = Self::generate_summary(
            &domain,
            is_suspicious,
            &risk_level,
            risk_score,
            &suspicious_chars,
            &script_analysis,
            &brand_match,
            &generated_variants,
        );

        Ok(IdnCheckResult {
            original_domain: domain,
            punycode_domain,
            is_idn,
            is_suspicious,
            risk_level,
            risk_score,
            suspicious_chars,
            similar_domains,
            generated_variants,
            script_analysis,
            brand_match,
            summary,
        })
    }

    pub async fn batch_check(domains: &[String], config: &IdnCheckConfig) -> Result<BatchIdnCheckResult> {
        let mut results = Vec::new();
        let mut suspicious_count = 0;
        let mut safe_count = 0;
        let mut error_count = 0;

        for domain in domains {
            let domain = domain.trim().to_string();
            if domain.is_empty() {
                continue;
            }

            let check_config = IdnCheckConfig {
                domain: domain.clone(),
                generate_variants: config.generate_variants,
                check_dns: config.check_dns,
                check_brand: config.check_brand,
                max_variants: config.max_variants,
            };

            match Self::check(&check_config).await {
                Ok(result) => {
                    if result.is_suspicious {
                        suspicious_count += 1;
                    } else {
                        safe_count += 1;
                    }
                    results.push(result);
                }
                Err(_) => {
                    error_count += 1;
                }
            }
        }

        let total = results.len();
        let summary = format!(
            "Batch check: {} domains total, {} suspicious, {} safe, {} errors",
            total, suspicious_count, safe_count, error_count
        );

        Ok(BatchIdnCheckResult {
            total,
            suspicious_count,
            safe_count,
            error_count,
            results,
            summary,
        })
    }

    fn clean_domain(domain: &str) -> String {
        let d = domain.trim();
        let d = d.strip_prefix("http://").unwrap_or(d);
        let d = d.strip_prefix("https://").unwrap_or(d);
        let d = d.strip_prefix("www.").unwrap_or(d);
        let d = d.split('/').next().unwrap_or(d);
        let d = d.split(':').next().unwrap_or(d);
        d.to_string()
    }

    fn char_risk_level(category: &str) -> String {
        match category {
            "Cyrillic" => "high".to_string(),
            "Greek" => "high".to_string(),
            "Armenian" => "high".to_string(),
            "Coptic" => "medium".to_string(),
            "Cherokee" => "medium".to_string(),
            "Latin Extended" => "medium".to_string(),
            "Enclosed" => "low".to_string(),
            "CJK" => "low".to_string(),
            _ => "low".to_string(),
        }
    }

    fn analyze_scripts(domain: &str, suspicious_chars: &[SuspiciousChar]) -> ScriptAnalysis {
        let mut script_map: HashMap<String, usize> = HashMap::new();
        let mut confusable_scripts: HashMap<String, bool> = HashMap::new();

        for c in domain.chars() {
            let script = Self::detect_script(c);
            *script_map.entry(script.clone()).or_insert(0) += 1;
        }

        for sc in suspicious_chars {
            confusable_scripts.insert(sc.category.clone(), true);
        }

        let scripts: Vec<ScriptInfo> = script_map
            .iter()
            .map(|(name, count)| ScriptInfo {
                script: name.clone(),
                char_count: *count,
                has_confusable: confusable_scripts.get(name).copied().unwrap_or(false),
            })
            .collect();

        let script_count = scripts.len();
        let is_mixed_script = script_count > 1;
        let has_confusable = !suspicious_chars.is_empty();

        let detail = if is_mixed_script {
            let script_names: Vec<String> = scripts.iter().map(|s| {
                format!("{}({})", s.script, s.char_count)
            }).collect();
            format!("Mixed-script domain detected: {} - HIGH RISK for homograph attack", script_names.join(", "))
        } else if has_confusable {
            format!("Single script but contains confusable characters from {} categories",
                suspicious_chars.iter().map(|s| s.category.clone()).collect::<std::collections::HashSet<_>>().len())
        } else {
            "Single script domain with no confusable characters detected".to_string()
        };

        ScriptAnalysis {
            scripts,
            is_mixed_script,
            is_single_script: !is_mixed_script,
            has_confusable,
            script_count,
            detail,
        }
    }

    fn detect_script(c: char) -> String {
        if c.is_ascii() {
            if c.is_ascii_alphabetic() {
                return "Latin".to_string();
            }
            if c.is_ascii_digit() {
                return "Common".to_string();
            }
            return "Common".to_string();
        }

        let cp = c as u32;
        if (0x0400..=0x04FF).contains(&cp) || (0x0500..=0x052F).contains(&cp) {
            return "Cyrillic".to_string();
        }
        if (0x0370..=0x03FF).contains(&cp) || (0x1F00..=0x1FFF).contains(&cp) {
            return "Greek".to_string();
        }
        if (0x2C80..=0x2CFF).contains(&cp) {
            return "Coptic".to_string();
        }
        if (0x0530..=0x058F).contains(&cp) {
            return "Armenian".to_string();
        }
        if (0x13A0..=0x13FF).contains(&cp) {
            return "Cherokee".to_string();
        }
        if (0x4E00..=0x9FFF).contains(&cp) || (0x3400..=0x4DBF).contains(&cp) || (0x3000..=0x303F).contains(&cp) {
            return "CJK".to_string();
        }
        if (0x0080..=0x024F).contains(&cp) {
            return "Latin Extended".to_string();
        }
        if (0x2460..=0x24FF).contains(&cp) {
            return "Enclosed".to_string();
        }

        "Other".to_string()
    }

    fn normalize_confusables(s: &str) -> String {
        s.chars().map(|c| {
            for &(confusable, resembles, _, _) in CONFUSABLE_CHARS {
                if c == confusable {
                    return resembles;
                }
            }
            c
        }).collect()
    }

    fn check_brand_match(domain: &str) -> Option<BrandMatch> {
        let domain_lower = domain.to_lowercase();
        let domain_part = domain_lower.split('.').next().unwrap_or(&domain_lower);
        let normalized = Self::normalize_confusables(domain_part);

        for &(brand, category) in BRAND_DOMAINS {
            if normalized.contains(brand) {
                let mut positions = Vec::new();
                if let Some(start) = normalized.find(brand) {
                    for i in start..start + brand.len() {
                        positions.push(i);
                    }
                }

                let confidence = if normalized == brand {
                    0.95
                } else if normalized.starts_with(brand) || normalized.ends_with(brand) {
                    0.85
                } else {
                    0.7
                };

                let has_confusable = domain_part.chars().any(|c| {
                    CONFUSABLE_CHARS.iter().any(|&(conf, _, _, _)| c == conf)
                });

                let final_confidence = if has_confusable && confidence < 0.95 {
                    (confidence + 0.1_f64).min(1.0_f64)
                } else {
                    confidence
                };

                return Some(BrandMatch {
                    brand: brand.to_string(),
                    category: category.to_string(),
                    confidence: final_confidence,
                    matched_positions: positions,
                });
            }
        }

        None
    }

    fn calculate_risk_score(
        suspicious_chars: &[SuspiciousChar],
        script_analysis: &ScriptAnalysis,
        brand_match: &Option<BrandMatch>,
        is_idn: bool,
    ) -> f64 {
        let mut score = 0.0;

        let high_count = suspicious_chars.iter().filter(|c| c.risk == "high").count() as f64;
        let medium_count = suspicious_chars.iter().filter(|c| c.risk == "medium").count() as f64;
        let low_count = suspicious_chars.iter().filter(|c| c.risk == "low").count() as f64;

        score += high_count * 0.25;
        score += medium_count * 0.15;
        score += low_count * 0.08;

        if script_analysis.is_mixed_script {
            score += 0.20;
        }

        if is_idn {
            score += 0.10;
        }

        if let Some(ref brand) = brand_match {
            score += 0.25 * brand.confidence;
        }

        score.min(1.0)
    }

    fn risk_level_from_score(score: f64) -> String {
        if score >= 0.8 {
            "critical".to_string()
        } else if score >= 0.6 {
            "high".to_string()
        } else if score >= 0.4 {
            "medium".to_string()
        } else if score >= 0.2 {
            "low".to_string()
        } else {
            "safe".to_string()
        }
    }

    fn generate_similar_domains(
        domain: &str,
        punycode_domain: &Option<String>,
        similar_domains: &mut Vec<SimilarDomain>,
    ) {
        let ascii_version: String = domain.chars().map(|c| {
            for &(confusable, resembles, _, _) in CONFUSABLE_CHARS {
                if c == confusable {
                    return resembles;
                }
            }
            c
        }).collect();

        if ascii_version != domain {
            similar_domains.push(SimilarDomain {
                domain: ascii_version.clone(),
                similarity_type: "ASCII homograph".to_string(),
                punycode: None,
                risk_level: "high".to_string(),
            });
        }

        if let Some(ref puny) = punycode_domain {
            similar_domains.push(SimilarDomain {
                domain: puny.clone(),
                similarity_type: "Punycode representation".to_string(),
                punycode: Some(puny.clone()),
                risk_level: "medium".to_string(),
            });
        }

        let tld_variants = [
            (".com", ".net"), (".com", ".org"), (".com", ".io"),
            (".com", ".co"), (".com", ".cc"), (".com", ".xyz"),
        ];

        for (from_tld, to_tld) in &tld_variants {
            if domain.ends_with(from_tld) {
                let variant = domain.replace(from_tld, to_tld);
                similar_domains.push(SimilarDomain {
                    domain: variant,
                    similarity_type: format!("TLD variation ({}→{})", from_tld, to_tld),
                    punycode: None,
                    risk_level: "low".to_string(),
                });
            }
        }

        let hyphen_variants = Self::generate_hyphen_variants(domain);
        for variant in hyphen_variants {
            similar_domains.push(SimilarDomain {
                domain: variant,
                similarity_type: "Hyphen insertion".to_string(),
                punycode: None,
                risk_level: "low".to_string(),
            });
        }
    }

    fn generate_hyphen_variants(domain: &str) -> Vec<String> {
        let mut variants = Vec::new();
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return variants;
        }

        let name = parts[0];
        let tld = parts[1..].join(".");

        if name.len() >= 4 {
            let mid = name.len() / 2;
            let hyphenated = format!("{}-{}.{}", &name[..mid], &name[mid..], tld);
            variants.push(hyphenated);
        }

        variants
    }

    fn generate_domain_variants(domain: &str, max_variants: usize) -> Vec<DomainVariant> {
        let mut variants = Vec::new();
        let mut seen = std::collections::HashSet::new();
        seen.insert(domain.to_string());

        let parts: Vec<&str> = domain.split('.').collect();
        if parts.is_empty() {
            return variants;
        }

        let name = parts[0].to_string();
        let tld = if parts.len() > 1 {
            parts[1..].join(".")
        } else {
            String::new()
        };

        Self::generate_substitution_variants(&name, &tld, &mut variants, &mut seen, max_variants);

        Self::generate_combination_variants(&name, &tld, &mut variants, &mut seen, max_variants);

        variants.truncate(max_variants);
        variants
    }

    fn generate_substitution_variants(
        name: &str,
        tld: &str,
        variants: &mut Vec<DomainVariant>,
        seen: &mut std::collections::HashSet<String>,
        max_variants: usize,
    ) {
        let chars: Vec<char> = name.chars().collect();

        for (i, c) in chars.iter().enumerate() {
            if variants.len() >= max_variants {
                break;
            }

            for &(confusable, resembles, category, _) in CONFUSABLE_CHARS {
                if variants.len() >= max_variants {
                    break;
                }

                if *c == resembles && c.is_ascii() {
                    let mut new_chars = chars.clone();
                    new_chars[i] = confusable;
                    let new_name: String = new_chars.into_iter().collect();
                    let full_domain = if tld.is_empty() {
                        new_name.clone()
                    } else {
                        format!("{}.{}", new_name, tld)
                    };

                    if !seen.contains(&full_domain) {
                        seen.insert(full_domain.clone());
                        let punycode = idna::domain_to_ascii(&full_domain)
                            .unwrap_or_else(|_| full_domain.clone());

                        variants.push(DomainVariant {
                            domain: full_domain,
                            punycode,
                            variant_type: "Single substitution".to_string(),
                            substitutions: vec![CharSubstitution {
                                original: resembles.to_string(),
                                replaced: confusable.to_string(),
                                position: i,
                                category: category.to_string(),
                            }],
                            is_registered: None,
                            risk_level: "high".to_string(),
                        });
                    }
                }
            }
        }
    }

    fn generate_combination_variants(
        name: &str,
        tld: &str,
        variants: &mut Vec<DomainVariant>,
        seen: &mut std::collections::HashSet<String>,
        _max_variants: usize,
    ) {
        let chars: Vec<char> = name.chars().collect();
        let mut substitutable_positions: Vec<(usize, char, Vec<(char, &str)>)> = Vec::new();

        for (i, c) in chars.iter().enumerate() {
            if c.is_ascii_alphabetic() {
                let mut subs = Vec::new();
                for &(confusable, resembles, category, _) in CONFUSABLE_CHARS {
                    if *c == resembles {
                        subs.push((confusable, category));
                    }
                }
                if !subs.is_empty() {
                    substitutable_positions.push((i, *c, subs));
                }
            }
        }

        if substitutable_positions.len() < 2 {
            return;
        }

        let max_combo = std::cmp::min(substitutable_positions.len(), 3);
        let combo_positions = &substitutable_positions[..max_combo];

        let mut new_chars = chars.clone();
        let mut substitutions = Vec::new();

        for &(pos, original, ref subs) in combo_positions {
            if let Some(&(confusable, category)) = subs.first() {
                new_chars[pos] = confusable;
                substitutions.push(CharSubstitution {
                    original: original.to_string(),
                    replaced: confusable.to_string(),
                    position: pos,
                    category: category.to_string(),
                });
            }
        }

        if substitutions.len() >= 2 {
            let new_name: String = new_chars.into_iter().collect();
            let full_domain = if tld.is_empty() {
                new_name.clone()
            } else {
                format!("{}.{}", new_name, tld)
            };

            if !seen.contains(&full_domain) {
                seen.insert(full_domain.clone());
                let punycode = idna::domain_to_ascii(&full_domain)
                    .unwrap_or_else(|_| full_domain.clone());

                variants.push(DomainVariant {
                    domain: full_domain,
                    punycode,
                    variant_type: format!("Multi-substitution ({} chars)", substitutions.len()),
                    substitutions,
                    is_registered: None,
                    risk_level: "critical".to_string(),
                });
            }
        }
    }

    async fn check_dns_registration(variants: &mut [DomainVariant]) {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::error::ResolveErrorKind;
        use std::net::IpAddr;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let parking_ips: &[&str] = &[
            "0.0.0.0",
            "127.0.0.1",
            "::1",
        ];

        for variant in variants.iter_mut() {
            let lookup_domain = variant.domain.trim_end_matches('.').to_string();

            match resolver.lookup_ip(&lookup_domain).await {
                Ok(lookup) => {
                    let ips: Vec<IpAddr> = lookup.iter().collect();
                    if ips.is_empty() {
                        variant.is_registered = Some(false);
                    } else {
                        let is_parking = ips.iter().any(|ip| {
                            parking_ips.contains(&ip.to_string().as_str())
                        });
                        variant.is_registered = Some(!is_parking);
                    }
                }
                Err(e) => {
                    match e.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => {
                            variant.is_registered = Some(false);
                        }
                        _ => {
                            variant.is_registered = None;
                        }
                    }
                }
            }
        }
    }

    fn generate_summary(
        domain: &str,
        is_suspicious: bool,
        risk_level: &str,
        risk_score: f64,
        suspicious_chars: &[SuspiciousChar],
        script_analysis: &ScriptAnalysis,
        brand_match: &Option<BrandMatch>,
        generated_variants: &[DomainVariant],
    ) -> String {
        if !is_suspicious {
            return format!("✅ Domain '{}' appears safe - no IDN homograph issues detected", domain);
        }

        let risk_emoji = match risk_level {
            "critical" => "🔴",
            "high" => "🟠",
            "medium" => "🟡",
            "low" => "🟢",
            _ => "⚪",
        };

        let mut parts = vec![format!(
            "{} Domain '{}' is {} (risk score: {:.0}%)",
            risk_emoji, domain, risk_level.to_uppercase(), risk_score * 100.0
        )];

        if !suspicious_chars.is_empty() {
            let categories: std::collections::HashSet<&str> = suspicious_chars.iter().map(|c| c.category.as_str()).collect();
            parts.push(format!("Contains {} confusable character(s) from {} script(s)",
                suspicious_chars.len(), categories.len()));
        }

        if script_analysis.is_mixed_script {
            parts.push("Mixed-script domain detected - classic homograph attack indicator".to_string());
        }

        if let Some(ref brand) = brand_match {
            parts.push(format!("Matches known brand '{}' ({}) - likely phishing target", brand.brand, brand.category));
        }

        let registered_count = generated_variants.iter()
            .filter(|v| v.is_registered == Some(true))
            .count();
        if registered_count > 0 {
            parts.push(format!("{} of {} generated variants appear to be registered domains",
                registered_count, generated_variants.len()));
        }

        parts.join(". ")
    }
}
