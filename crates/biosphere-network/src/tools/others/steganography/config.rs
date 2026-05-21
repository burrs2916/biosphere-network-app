use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteganographyConfig {
    pub operation: String,
    pub cover_file_path: String,
    pub secret_file_path: Option<String>,
    pub secret_text: Option<String>,
    pub output_file_path: Option<String>,
    pub passphrase: Option<String>,
}

impl Default for SteganographyConfig {
    fn default() -> Self {
        Self {
            operation: "hide".to_string(),
            cover_file_path: String::new(),
            secret_file_path: None,
            secret_text: None,
            output_file_path: None,
            passphrase: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteganographyResult {
    pub success: bool,
    pub operation: String,
    pub message: String,
    pub output_path: Option<String>,
    pub extracted_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegCrackConfig {
    pub file_path: String,
    pub wordlist_path: Option<String>,
    pub max_threads: usize,
    pub extract_on_crack: bool,
    pub verbose: bool,
    pub timeout_secs: u64,
}

impl Default for StegCrackConfig {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            wordlist_path: None,
            max_threads: 4,
            extract_on_crack: true,
            verbose: false,
            timeout_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegCrackResult {
    pub success: bool,
    pub file_path: String,
    pub passphrase_found: Option<String>,
    pub attempts: u64,
    pub duration_secs: f64,
    pub extracted_data: Option<String>,
    pub method: String,
}

pub const STEG_COMMON_PASSWORDS: &[&str] = &[
    "", "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "master", "dragon", "login", "princess", "hello",
    "charlie", "donald", "shadow", "sunshine", "trustno1",
    "iloveyou", "batman", "access", "hello123", "pass",
    "test", "guest", "root", "admin", "letmein", "welcome",
    "secret", "steganography", "stego", "hidden", "hide",
    "encrypt", "decrypt", "private", "confidential", "covert",
    "invisible", "concealed", "embedded", "payload", "cover",
    "image", "photo", "picture", "file", "data", "info",
    "pass123", "passw0rd", "p@ssw0rd", "password1", "password123",
    "changeme", "default", "1234", "12345", "123456789",
    "1234567890", "0987654321", "abcdef", "abcdefg",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegDetectResult {
    pub file_path: String,
    pub suspicious: bool,
    pub detected_tools: Vec<String>,
    pub confidence: f64,
    pub findings: Vec<StegFinding>,
    pub file_size: u64,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegFinding {
    pub finding_type: String,
    pub severity: String,
    pub detail: String,
    pub offset: Option<u64>,
}

pub fn detect_steganography(file_data: &[u8], file_path: &str) -> StegDetectResult {
    let mut findings = Vec::new();
    let mut detected_tools = Vec::new();
    let mut confidence: f64 = 0.0;

    if file_data.len() > 2 && file_data[0] == 0xFF && file_data[1] == 0xD8 {
        let mut comment_count = 0;
        let mut i = 2;
        while i < file_data.len() - 1 {
            if file_data[i] == 0xFF {
                let marker = file_data[i + 1];
                if marker == 0xFE {
                    comment_count += 1;
                    if i + 3 < file_data.len() {
                        let len = ((file_data[i + 2] as usize) << 8) | file_data[i + 3] as usize;
                        if len > 100 {
                            findings.push(StegFinding {
                                finding_type: "jpeg_comment".to_string(),
                                severity: "medium".to_string(),
                                detail: format!("Large JPEG comment block ({} bytes) at offset {}", len, i),
                                offset: Some(i as u64),
                            });
                            confidence += 0.15;
                        }
                    }
                }
                if marker == 0xDA { break; }
                if (0xD0..=0xD7).contains(&marker) { i += 2; continue; }
                if i + 3 < file_data.len() {
                    let seg_len = ((file_data[i + 2] as usize) << 8) | file_data[i + 3] as usize;
                    i += 2 + seg_len;
                } else { break; }
            } else { i += 1; }
        }
        if comment_count > 3 {
            findings.push(StegFinding {
                finding_type: "excessive_comments".to_string(),
                severity: "low".to_string(),
                detail: format!("{} JPEG comment markers found", comment_count),
                offset: None,
            });
            confidence += 0.1;
        }
    }

    if file_data.len() > 8 && &file_data[0..8] == b"\x89PNG\r\n\x1a\n" {
        let mut i = 8;
        while i + 11 < file_data.len() {
            let chunk_len = ((file_data[i] as u32) << 24) | ((file_data[i+1] as u32) << 16) | ((file_data[i+2] as u32) << 8) | file_data[i+3] as u32;
            let chunk_type = &file_data[i+4..i+8];
            let chunk_name = std::str::from_utf8(chunk_type).unwrap_or("????");
            
            if chunk_name == "tEXt" || chunk_name == "iTXt" || chunk_name == "zTXt" {
                if chunk_len > 1000 {
                    findings.push(StegFinding {
                        finding_type: "png_text_chunk".to_string(),
                        severity: "medium".to_string(),
                        detail: format!("Large PNG text chunk '{}' ({} bytes)", chunk_name, chunk_len),
                        offset: Some(i as u64),
                    });
                    confidence += 0.15;
                }
            }
            if chunk_name == "stEG" || chunk_name == "steg" {
                detected_tools.push("Custom steganography tool".to_string());
                confidence += 0.5;
            }
            if chunk_name == "IEND" { break; }
            i += 12 + chunk_len as usize;
            if chunk_len > file_data.len() as u32 { break; }
        }
    }

    let file_size = file_data.len() as u64;
    let sample_size = std::cmp::min(file_data.len(), 10240);
    let sample = &file_data[file_data.len() - sample_size..];
    let mut freq = [0usize; 256];
    for &byte in sample { freq[byte as usize] += 1; }
    let total = sample.len() as f64;
    let entropy = freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| { let p = f as f64 / total; -p * p.log2() })
        .sum::<f64>();

    if entropy > 7.9 {
        findings.push(StegFinding {
            finding_type: "high_entropy".to_string(),
            severity: "medium".to_string(),
            detail: format!("High entropy ({:.2}) in file tail suggests encrypted/hidden data", entropy),
            offset: None,
        });
        confidence += 0.2;
    }

    let trailing = &file_data[file_data.len().saturating_sub(32)..];
    let zero_count = trailing.iter().filter(|&&b| b == 0).count();
    if zero_count < 5 && file_data.len() > 1000 {
        findings.push(StegFinding {
            finding_type: "nonzero_trailing".to_string(),
            severity: "low".to_string(),
            detail: "File has non-zero trailing data".to_string(),
            offset: Some(file_data.len() as u64 - 32),
        });
        confidence += 0.1;
    }

    if file_path.to_lowercase().contains("steg") {
        detected_tools.push("Filename suggests steganography".to_string());
        confidence += 0.1;
    }

    StegDetectResult {
        file_path: file_path.to_string(),
        suspicious: confidence > 0.3,
        detected_tools,
        confidence: confidence.min(1.0_f64),
        findings,
        file_size,
        entropy,
    }
}
