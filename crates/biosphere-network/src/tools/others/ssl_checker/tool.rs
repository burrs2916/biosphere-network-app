use crate::core::{Result, ToolError};
use super::config::{SslCheckResult, CertificateInfo};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::time::Duration;

pub struct SslCheckerTool;

impl SslCheckerTool {
    pub fn new() -> Self {
        Self
    }

    pub async fn check(host: &str, port: Option<u16>) -> Result<SslCheckResult> {
        let trimmed = host.trim();
        let target_host = if trimmed.starts_with("https://") {
            trimmed.trim_start_matches("https://").to_string()
        } else if trimmed.starts_with("http://") {
            trimmed.trim_start_matches("http://").to_string()
        } else {
            trimmed.to_string()
        };

        let target_host = if target_host.contains('/') {
            target_host.split('/').next().unwrap_or(&target_host).to_string()
        } else {
            target_host
        };

        let target_port = port.unwrap_or(443);

        if target_host.is_empty() {
            return Err(ToolError::ExecutionError("Empty host".to_string()));
        }

        let addr = format!("{}:{}", target_host, target_port);

        let tcp_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ToolError::ExecutionError("Connection timeout".to_string()))?
        .map_err(|e| ToolError::ExecutionError(format!("Connection failed: {}", e)))?;

        let tcp_stream = tcp_stream.into_std()
            .map_err(|e| ToolError::ExecutionError(format!("Stream conversion error: {}", e)))?;

        tcp_stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        tcp_stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| ToolError::ExecutionError(format!("SSL builder error: {}", e)))?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        let ssl_stream = connector.connect(&target_host, tcp_stream)
            .map_err(|e| ToolError::ExecutionError(format!("TLS handshake failed: {}", e)))?;

        let ssl = ssl_stream.ssl();

        let protocol_version = Self::get_protocol_version(ssl);
        let cipher_name = ssl.current_cipher()
            .map(|c| c.name().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let cipher_bits = ssl.current_cipher()
            .map(|c| c.bits().algorithm as u16)
            .unwrap_or(0);

        let cert_der = ssl.peer_certificate()
            .ok_or_else(|| ToolError::ExecutionError("No certificate found".to_string()))?
            .to_der()
            .map_err(|e| ToolError::ExecutionError(format!("Failed to encode certificate: {}", e)))?;

        let cert_info = Self::parse_certificate(&cert_der)?;

        let mut protocol_issues = Vec::new();
        let mut cipher_issues = Vec::new();

        Self::evaluate_protocol(&protocol_version, &mut protocol_issues);
        Self::evaluate_cipher(&cipher_name, &mut cipher_issues);

        let is_secure = protocol_issues.is_empty() && cipher_issues.is_empty() && !cert_info.is_expired && cert_info.days_remaining > 0;

        let score = Self::calculate_score(&cert_info, &protocol_issues, &cipher_issues);
        let overall_grade = Self::score_to_grade(score);

        let summary = format!(
            "SSL/TLS Grade: {} ({}/100) - Protocol: {} - Cipher: {} ({} bits) - Cert expires in {} days",
            overall_grade, score, protocol_version, cipher_name, cipher_bits, cert_info.days_remaining
        );

        Ok(SslCheckResult {
            host: target_host,
            port: target_port,
            is_secure,
            protocol_version,
            cipher_name,
            cipher_bits,
            certificate: cert_info,
            protocol_issues,
            cipher_issues,
            overall_grade,
            score,
            summary,
        })
    }

    fn get_protocol_version(ssl: &openssl::ssl::SslRef) -> String {
        let version = ssl.version_str();
        match version {
            "TLSv1.3" => "TLS 1.3".to_string(),
            "TLSv1.2" => "TLS 1.2".to_string(),
            "TLSv1.1" => "TLS 1.1".to_string(),
            "TLSv1.0" => "TLS 1.0".to_string(),
            "SSLv3" => "SSL 3.0".to_string(),
            "SSLv2" => "SSL 2.0".to_string(),
            _ => version.to_string(),
        }
    }

    fn parse_certificate(der: &[u8]) -> Result<CertificateInfo> {
        let cert = X509::from_der(der)
            .map_err(|e| ToolError::ExecutionError(format!("Certificate parse error: {}", e)))?;

        let subject = format!("{:?}", cert.subject_name());
        let issuer = format!("{:?}", cert.issuer_name());

        let subject_cn = cert.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let issuer_cn = cert.issuer_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let serial_number = cert.serial_number()
            .to_bn()
            .map(|bn| bn.to_hex_str().map(|s| s.to_string()).unwrap_or_else(|_| "Unknown".to_string()))
            .unwrap_or_else(|_| "Unknown".to_string());

        let not_before_str = cert.not_before().to_string();
        let not_after_str = cert.not_after().to_string();

        let now = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|e| ToolError::ExecutionError(format!("Time error: {}", e)))?;

        let is_expired = cert.not_after() < &now;
        let days_remaining = cert.not_after()
            .diff(&now)
            .map(|diff| diff.days)
            .unwrap_or(0);

        let signature_algorithm = cert.signature_algorithm()
            .object()
            .to_string();

        let public_key = cert.public_key()
            .map_err(|e| ToolError::ExecutionError(format!("Public key error: {}", e)))?;

        let key_bits = public_key.bits();
        let key_type = if public_key.rsa().is_ok() {
            "RSA".to_string()
        } else if public_key.dsa().is_ok() {
            "DSA".to_string()
        } else if public_key.ec_key().is_ok() {
            "EC".to_string()
        } else {
            "Unknown".to_string()
        };

        let is_self_signed = cert.subject_name().try_cmp(cert.issuer_name())
            .map(|o| o == std::cmp::Ordering::Equal)
            .unwrap_or(false);

        let mut san_domains = Vec::new();
        if let Some(san) = cert.subject_alt_names() {
            for name in san.iter() {
                if let Some(dns) = name.dnsname() {
                    san_domains.push(dns.to_string());
                }
            }
        }

        let fingerprint = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(der);
            let result = hasher.finalize();
            result.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
        };

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            not_before: not_before_str,
            not_after: not_after_str,
            is_expired,
            days_remaining: days_remaining as i64,
            signature_algorithm,
            key_type,
            key_bits,
            san_domains,
            is_self_signed,
            subject_cn,
            issuer_cn,
            fingerprint_sha256: fingerprint,
        })
    }

    fn evaluate_protocol(protocol: &str, issues: &mut Vec<String>) {
        match protocol {
            "TLS 1.3" => {},
            "TLS 1.2" => {},
            "TLS 1.1" => {
                issues.push("TLS 1.1 is deprecated and should not be used (RFC 8996)".to_string());
            },
            "TLS 1.0" => {
                issues.push("TLS 1.0 is deprecated and insecure (RFC 8996)".to_string());
            },
            p if p.starts_with("SSL") => {
                issues.push(format!("{} is completely insecure and must not be used", p));
            },
            _ => {
                issues.push("Unknown protocol version".to_string());
            }
        }
    }

    fn evaluate_cipher(cipher_name: &str, issues: &mut Vec<String>) {
        let lower = cipher_name.to_lowercase();

        if lower.contains("null") {
            issues.push("Null cipher provides no encryption".to_string());
        }
        if lower.contains("export") {
            issues.push("Export-grade cipher is intentionally weak (40-bit)".to_string());
        }
        if lower.contains("anon") {
            issues.push("Anonymous cipher provides no authentication".to_string());
        }
        if lower.contains("rc4") {
            issues.push("RC4 cipher is broken and insecure (RFC 7465)".to_string());
        }
        if lower.contains("des") && !lower.contains("3des") {
            issues.push("DES cipher is insecure (56-bit key)".to_string());
        }
        if lower.contains("3des") {
            issues.push("3DES is deprecated and slow".to_string());
        }
        if lower.contains("cbc") && !lower.contains("aes_256") && !lower.contains("aes_128") {
            issues.push("CBC mode ciphers may be vulnerable to padding oracle attacks".to_string());
        }
    }

    fn calculate_score(cert: &CertificateInfo, protocol_issues: &[String], cipher_issues: &[String]) -> i32 {
        let mut score = 100;

        if cert.is_expired {
            score -= 30;
        } else if cert.days_remaining < 30 {
            score -= 10;
        } else if cert.days_remaining < 90 {
            score -= 5;
        }

        if cert.is_self_signed {
            score -= 15;
        }

        if cert.key_bits < 2048 {
            score -= 20;
        } else if cert.key_bits < 3072 {
            score -= 5;
        }

        if cert.signature_algorithm.to_lowercase().contains("sha1") {
            score -= 15;
        }

        for issue in protocol_issues {
            if issue.contains("completely insecure") || issue.contains("SSL") {
                score -= 25;
            } else if issue.contains("deprecated") {
                score -= 15;
            }
        }

        for issue in cipher_issues {
            if issue.contains("Null") || issue.contains("no encryption") {
                score -= 25;
            } else if issue.contains("broken") || issue.contains("insecure") {
                score -= 20;
            } else if issue.contains("weak") || issue.contains("deprecated") {
                score -= 15;
            } else {
                score -= 10;
            }
        }

        score.clamp(0, 100)
    }

    fn score_to_grade(score: i32) -> String {
        match score {
            s if s >= 90 => "A".to_string(),
            s if s >= 75 => "B".to_string(),
            s if s >= 60 => "C".to_string(),
            s if s >= 40 => "D".to_string(),
            _ => "F".to_string(),
        }
    }
}
