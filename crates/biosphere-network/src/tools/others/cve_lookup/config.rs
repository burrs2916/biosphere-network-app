use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveQueryConfig {
    pub query: String,
    pub limit: usize,
    pub severity_filter: Option<String>,
    pub cvss_min: Option<f64>,
    pub cvss_max: Option<f64>,
    pub pub_date_start: Option<String>,
    pub pub_date_end: Option<String>,
    pub mod_date_start: Option<String>,
    pub mod_date_end: Option<String>,
    pub cpe_name: Option<String>,
    pub cwe_id: Option<String>,
    pub has_exploit: Option<bool>,
    pub is_vulnerable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveQueryResult {
    pub query: String,
    pub vulnerabilities: Vec<CveEntry>,
    pub total_results: usize,
    pub summary: String,
    pub scan_duration_ms: u64,
    pub severity_stats: SeverityStats,
    pub cvss_distribution: CvssDistribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub description: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
    pub url: String,
    pub cwe_ids: Vec<String>,
    pub references: Vec<CveReference>,
    pub affected_products: Vec<AffectedProduct>,
    pub exploitability: Option<ExploitabilityInfo>,
    pub patches: Vec<PatchInfo>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveReference {
    pub url: String,
    pub source: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub versions: Vec<String>,
    pub cpe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityInfo {
    pub has_exploit: bool,
    pub exploit_available: bool,
    pub exploit_sources: Vec<String>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchInfo {
    pub url: String,
    pub source: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct SeverityStats {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub none: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct CvssDistribution {
    pub range_9_10: usize,
    pub range_7_9: usize,
    pub range_4_7: usize,
    pub range_0_4: usize,
    pub unknown: usize,
}

impl Default for CveQueryConfig {
    fn default() -> Self {
        Self {
            query: String::new(),
            limit: 20,
            severity_filter: None,
            cvss_min: None,
            cvss_max: None,
            pub_date_start: None,
            pub_date_end: None,
            mod_date_start: None,
            mod_date_end: None,
            cpe_name: None,
            cwe_id: None,
            has_exploit: None,
            is_vulnerable: None,
        }
    }
}



impl SeverityStats {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.none
    }
}

impl CvssDistribution {
    pub fn total(&self) -> usize {
        self.range_9_10 + self.range_7_9 + self.range_4_7 + self.range_0_4 + self.unknown
    }
}
