use crate::core::{Result, ToolError};
use super::config::{CveQueryConfig, CveQueryResult, CveEntry, CveReference, AffectedProduct, ExploitabilityInfo, PatchInfo, SeverityStats, CvssDistribution};
use std::time::Instant;

pub struct CveLookupTool;

impl CveLookupTool {
    pub async fn query(config: &CveQueryConfig) -> Result<CveQueryResult> {
        let start = Instant::now();
        let query = config.query.trim().to_string();
        
        if query.is_empty() {
            return Err(ToolError::ExecutionError("Query is empty".to_string()));
        }

        let result = if query.to_uppercase().starts_with("CVE-") {
            Self::query_by_cve_id(&query, config).await
        } else {
            Self::search_by_keyword(&query, config).await
        }?;

        let vulnerabilities = Self::apply_filters(result.vulnerabilities, config);
        let (severity_stats, cvss_distribution) = Self::compute_stats(&vulnerabilities);
        
        let scan_duration_ms = start.elapsed().as_millis() as u64;
        let summary = Self::generate_summary(&query, &vulnerabilities, result.total_results);

        Ok(CveQueryResult {
            query,
            vulnerabilities,
            total_results: result.total_results,
            summary,
            scan_duration_ms,
            severity_stats,
            cvss_distribution,
        })
    }

    async fn query_by_cve_id(cve_id: &str, _config: &CveQueryConfig) -> Result<CveQueryResult> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("BiosPherePro/1.0 CVE Lookup Tool")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);

        let resp = Self::send_with_retry(&client, &url).await?;

        if resp.status().as_u16() == 403 {
            return Err(ToolError::ExecutionError("NVD API rate limit exceeded. Please wait a moment and try again.".to_string()));
        }

        if !resp.status().is_success() {
            return Err(ToolError::ExecutionError(format!("NVD API returned status: {}", resp.status())));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| ToolError::ExecutionError(format!("Failed to parse NVD response: {}", e)))?;

        let mut vulnerabilities = Vec::new();

        if let Some(vulnerabilities_arr) = body.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulnerabilities_arr {
                if let Some(cve) = vuln.get("cve") {
                    let entry = Self::parse_cve_entry(cve);
                    vulnerabilities.push(entry);
                }
            }
        }

        let total_results = vulnerabilities.len();

        Ok(CveQueryResult {
            query: cve_id.to_string(),
            vulnerabilities,
            total_results,
            summary: String::new(),
            scan_duration_ms: 0,
            severity_stats: SeverityStats::default(),
            cvss_distribution: CvssDistribution::default(),
        })
    }

    async fn search_by_keyword(keyword: &str, config: &CveQueryConfig) -> Result<CveQueryResult> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("BiosPherePro/1.0 CVE Lookup Tool")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let mut url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage={}",
            urlencoding::encode(keyword),
            config.limit.min(100)
        );

        if let Some(ref severity) = config.severity_filter {
            let sev = match severity.to_uppercase().as_str() {
                "CRITICAL" => "CRITICAL",
                "HIGH" => "HIGH",
                "MEDIUM" => "MEDIUM",
                "LOW" => "LOW",
                _ => severity,
            };
            url.push_str(&format!("&cvssV3Severity={}", sev));
        }

        if let Some(cvss_min) = config.cvss_min {
            url.push_str(&format!("&cvssScoreMin={}", cvss_min));
        }

        if let Some(cvss_max) = config.cvss_max {
            url.push_str(&format!("&cvssScoreMax={}", cvss_max));
        }

        if let Some(ref cpe) = config.cpe_name {
            url.push_str(&format!("&cpeName={}", urlencoding::encode(cpe)));
        }

        if let Some(ref cwe) = config.cwe_id {
            url.push_str(&format!("&cweId={}", cwe));
        }

        if let Some(ref start_date) = config.pub_date_start {
            url.push_str(&format!("&pubStartDate={}", start_date));
        }

        if let Some(ref end_date) = config.pub_date_end {
            url.push_str(&format!("&pubEndDate={}", end_date));
        }

        let resp = Self::send_with_retry(&client, &url).await?;

        if resp.status().as_u16() == 403 {
            return Err(ToolError::ExecutionError("NVD API rate limit exceeded. Please wait a moment and try again.".to_string()));
        }

        if !resp.status().is_success() {
            return Err(ToolError::ExecutionError(format!("NVD API returned status: {}", resp.status())));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| ToolError::ExecutionError(format!("Failed to parse NVD response: {}", e)))?;

        let mut vulnerabilities = Vec::new();

        if let Some(vulnerabilities_arr) = body.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulnerabilities_arr {
                if let Some(cve) = vuln.get("cve") {
                    let entry = Self::parse_cve_entry(cve);
                    vulnerabilities.push(entry);
                }
            }
        }

        let total_results = body.get("totalResults")
            .and_then(|v| v.as_i64())
            .unwrap_or(vulnerabilities.len() as i64) as usize;

        Ok(CveQueryResult {
            query: keyword.to_string(),
            vulnerabilities,
            total_results,
            summary: String::new(),
            scan_duration_ms: 0,
            severity_stats: SeverityStats::default(),
            cvss_distribution: CvssDistribution::default(),
        })
    }

    fn parse_cve_entry(cve: &serde_json::Value) -> CveEntry {
        let cve_id = cve.get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let description = cve.get("descriptions")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.iter().find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en")))
            .and_then(|d| d.get("value").and_then(|v| v.as_str()))
            .unwrap_or("No description available")
            .to_string();

        let (severity, cvss_score, cvss_version, cvss_vector) = Self::extract_cvss_info(cve);

        let published_date = cve.get("published")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let last_modified = cve.get("lastModified")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let url = format!("https://nvd.nist.gov/vuln/detail/{}", cve_id);

        let cwe_ids = Self::extract_cwe_ids(cve);

        let references = Self::extract_references(cve);

        let affected_products = Self::extract_affected_products(cve);

        let exploitability = Self::extract_exploitability(cve, &references);

        let patches = Self::extract_patches(&references);

        CveEntry {
            cve_id,
            description,
            severity,
            cvss_score,
            cvss_version,
            cvss_vector,
            published_date,
            last_modified,
            url,
            cwe_ids,
            references,
            affected_products,
            exploitability,
            patches,
            source: "NVD".to_string(),
        }
    }

    fn extract_cvss_info(cve: &serde_json::Value) -> (Option<String>, Option<f64>, Option<String>, Option<String>) {
        let metrics = match cve.get("metrics") {
            Some(m) => m,
            None => return (None, None, None, None),
        };

        let metric = if let Some(cvss_v31) = metrics.get("cvssMetricV31").and_then(|v| v.as_array()) {
            cvss_v31.first()
        } else if let Some(cvss_v30) = metrics.get("cvssMetricV30").and_then(|v| v.as_array()) {
            cvss_v30.first()
        } else if let Some(cvss_v2) = metrics.get("cvssMetricV2").and_then(|v| v.as_array()) {
            cvss_v2.first()
        } else {
            None
        };

        match metric {
            Some(m) => {
                let cvss_data = m.get("cvssData");
                let severity = cvss_data
                    .and_then(|d| d.get("baseSeverity"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| m.get("baseSeverity").and_then(|v| v.as_str()).map(|s| s.to_string()));
                
                let score = cvss_data
                    .and_then(|d| d.get("baseScore"))
                    .and_then(|v| v.as_f64())
                    .or_else(|| m.get("baseScore").and_then(|v| v.as_f64()));
                
                let version = cvss_data
                    .and_then(|d| d.get("version"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                
                let vector = cvss_data
                    .and_then(|d| d.get("vectorString"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                (severity, score, version, vector)
            }
            None => (None, None, None, None),
        }
    }

    fn extract_cwe_ids(cve: &serde_json::Value) -> Vec<String> {
        let mut cwe_ids = Vec::new();
        
        if let Some(weaknesses) = cve.get("weaknesses").and_then(|w| w.as_array()) {
            for weakness in weaknesses {
                if let Some(descriptions) = weakness.get("description").and_then(|d| d.as_array()) {
                    for desc in descriptions {
                        if let Some(cwe_id) = desc.get("value").and_then(|v| v.as_str()) {
                            if cwe_id.starts_with("CWE-") {
                                cwe_ids.push(cwe_id.to_string());
                            }
                        }
                    }
                }
            }
        }

        cwe_ids.sort();
        cwe_ids.dedup();
        cwe_ids
    }

    fn extract_references(cve: &serde_json::Value) -> Vec<CveReference> {
        let mut references = Vec::new();
        
        if let Some(refs) = cve.get("references").and_then(|r| r.as_array()) {
            for r in refs {
                let url = r.get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                
                if url.is_empty() {
                    continue;
                }

                let source = r.get("source")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let tags = r.get("tags")
                    .and_then(|t| t.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();

                references.push(CveReference { url, source, tags });
            }
        }

        references
    }

    fn extract_affected_products(cve: &serde_json::Value) -> Vec<AffectedProduct> {
        let mut products = Vec::new();
        
        if let Some(configurations) = cve.get("configurations").and_then(|c| c.as_array()) {
            for config in configurations {
                if let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) {
                    for node in nodes {
                        if let Some(cpe_matches) = node.get("cpeMatch").and_then(|c| c.as_array()) {
                            for cpe in cpe_matches {
                                if let Some(cpe_str) = cpe.get("criteria").and_then(|v| v.as_str()) {
                                    let parts: Vec<&str> = cpe_str.split(':').collect();
                                    let vendor = parts.get(2).unwrap_or(&"unknown").to_string();
                                    let product = parts.get(3).unwrap_or(&"unknown").to_string();
                                    
                                    let version = parts.get(4).unwrap_or(&"*").to_string();
                                    let versions = if version == "*" || version.is_empty() {
                                        vec!["All versions".to_string()]
                                    } else {
                                        vec![version]
                                    };

                                    products.push(AffectedProduct {
                                        vendor,
                                        product,
                                        versions,
                                        cpe: cpe_str.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        products.sort_by(|a, b| a.product.cmp(&b.product));
        products.dedup_by(|a, b| a.cpe == b.cpe);
        products
    }

    fn extract_exploitability(_cve: &serde_json::Value, references: &[CveReference]) -> Option<ExploitabilityInfo> {
        let exploit_tags = ["Exploit", "Third Party Advisory", "Exploited"];
        let exploit_sources = ["exploit-db.com", "exploitdb.com", "packetstormsecurity.com", 
                               "seclists.org", "github.com", "metasploit", "rapid7"];
        
        let mut has_exploit = false;
        let mut exploit_available = false;
        let mut found_sources = Vec::new();

        for reference in references {
            let url_lower = reference.url.to_lowercase();
            let tags_lower: Vec<String> = reference.tags.iter().map(|t| t.to_lowercase()).collect();
            
            for tag in &exploit_tags {
                if tags_lower.iter().any(|t| t.contains(&tag.to_lowercase())) {
                    has_exploit = true;
                }
            }

            for source in &exploit_sources {
                if url_lower.contains(source) {
                    has_exploit = true;
                    exploit_available = true;
                    found_sources.push(source.to_string());
                }
            }
        }

        if has_exploit || exploit_available {
            Some(ExploitabilityInfo {
                has_exploit,
                exploit_available,
                exploit_sources: found_sources,
                epss_score: None,
                epss_percentile: None,
            })
        } else {
            None
        }
    }

    fn extract_patches(references: &[CveReference]) -> Vec<PatchInfo> {
        let patch_keywords = ["patch", "fix", "update", "security update", "hotfix", "security advisory"];
        let patch_sources = ["github.com", "gitlab.com", "bitbucket.org", "microsoft.com", 
                            "oracle.com", "adobe.com", "apple.com", "linux"];
        
        let mut patches = Vec::new();

        for reference in references {
            let url_lower = reference.url.to_lowercase();
            let tags_lower: Vec<String> = reference.tags.iter().map(|t| t.to_lowercase()).collect();
            
            let is_patch = patch_keywords.iter().any(|kw| {
                tags_lower.iter().any(|t| t.contains(kw)) || url_lower.contains(kw)
            }) || patch_sources.iter().any(|src| url_lower.contains(src) && 
                (url_lower.contains("patch") || url_lower.contains("fix") || url_lower.contains("commit")));

            if is_patch {
                patches.push(PatchInfo {
                    url: reference.url.clone(),
                    source: reference.source.clone(),
                    description: None,
                });
            }
        }

        patches
    }

    fn apply_filters(vulnerabilities: Vec<CveEntry>, config: &CveQueryConfig) -> Vec<CveEntry> {
        vulnerabilities.into_iter().filter(|v| {
            if let Some(ref severity) = config.severity_filter {
                if let Some(ref sev) = v.severity {
                    if !sev.eq_ignore_ascii_case(severity) {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            if let Some(min) = config.cvss_min {
                if let Some(score) = v.cvss_score {
                    if score < min {
                        return false;
                    }
                }
            }

            if let Some(max) = config.cvss_max {
                if let Some(score) = v.cvss_score {
                    if score > max {
                        return false;
                    }
                }
            }

            if let Some(has_exploit) = config.has_exploit {
                if has_exploit {
                    if v.exploitability.is_none() || !v.exploitability.as_ref().unwrap().has_exploit {
                        return false;
                    }
                }
            }

            true
        }).collect()
    }

    fn compute_stats(vulnerabilities: &[CveEntry]) -> (SeverityStats, CvssDistribution) {
        let mut severity_stats = SeverityStats::default();
        let mut cvss_distribution = CvssDistribution::default();

        for v in vulnerabilities {
            match v.severity.as_deref() {
                Some("CRITICAL") => severity_stats.critical += 1,
                Some("HIGH") => severity_stats.high += 1,
                Some("MEDIUM") => severity_stats.medium += 1,
                Some("LOW") => severity_stats.low += 1,
                _ => severity_stats.none += 1,
            }

            match v.cvss_score {
                Some(score) if score >= 9.0 => cvss_distribution.range_9_10 += 1,
                Some(score) if score >= 7.0 => cvss_distribution.range_7_9 += 1,
                Some(score) if score >= 4.0 => cvss_distribution.range_4_7 += 1,
                Some(_) => cvss_distribution.range_0_4 += 1,
                None => cvss_distribution.unknown += 1,
            }
        }

        (severity_stats, cvss_distribution)
    }

    fn generate_summary(query: &str, vulnerabilities: &[CveEntry], total_results: usize) -> String {
        if vulnerabilities.is_empty() {
            format!("No CVE entries found for: {}", query)
        } else if vulnerabilities.len() == 1 && query.to_uppercase().starts_with("CVE-") {
            format!("Found CVE entry: {}", query)
        } else {
            let critical = vulnerabilities.iter().filter(|v| v.severity.as_deref() == Some("CRITICAL")).count();
            let high = vulnerabilities.iter().filter(|v| v.severity.as_deref() == Some("HIGH")).count();
            
            if critical > 0 || high > 0 {
                format!(
                    "Found {} CVE entries for '{}' ({} critical, {} high severity)",
                    total_results, query, critical, high
                )
            } else {
                format!(
                    "Found {} CVE entries for '{}'",
                    total_results, query
                )
            }
        }
    }

    async fn send_with_retry(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
        let mut last_error = None;
        for attempt in 0..3 {
            match client.get(url).send().await {
                Ok(resp) => {
                    if resp.status().as_u16() == 429 {
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt as u32 + 1))).await;
                            continue;
                        }
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < 2 {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(ToolError::ExecutionError(format!(
            "NVD API request failed after retries: {}",
            last_error.map(|e| e.to_string()).unwrap_or_default()
        )))
    }
}
