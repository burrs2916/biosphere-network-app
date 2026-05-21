use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCheckResult {
    pub host: String,
    pub port: u16,
    pub is_secure: bool,
    pub protocol_version: String,
    pub cipher_name: String,
    pub cipher_bits: u16,
    pub certificate: CertificateInfo,
    pub protocol_issues: Vec<String>,
    pub cipher_issues: Vec<String>,
    pub overall_grade: String,
    pub score: i32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub is_expired: bool,
    pub days_remaining: i64,
    pub signature_algorithm: String,
    pub key_type: String,
    pub key_bits: u32,
    pub san_domains: Vec<String>,
    pub is_self_signed: bool,
    pub subject_cn: String,
    pub issuer_cn: String,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSslCheckResult {
    pub host: String,
    pub result: Option<SslCheckResult>,
    pub error: Option<String>,
}
