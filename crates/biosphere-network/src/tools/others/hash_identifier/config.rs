use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashIdentification {
    pub hash_value: String,
    pub possible_types: Vec<HashTypeMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashTypeMatch {
    pub hash_type: String,
    pub description: String,
    pub confidence: f64,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeoInfo {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub isp: String,
    pub org: String,
    pub timezone: String,
}
