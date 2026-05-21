use std::net::IpAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

use crate::tools::info_gathering::port_scanner::well_known_ports::{WellKnownPort, RiskLevel};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceVersion {
    pub service: String,
    pub version: String,
    pub banner: Option<String>,
    pub port_info: Option<PortInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub service: String,
    pub protocol: String,
    pub description: String,
    pub category: String,
    pub category_icon: String,
    pub risk_level: String,
    pub risk_color: String,
    pub risk_score: u8,
}

pub struct ServiceDetector;

impl ServiceDetector {
    pub fn identify_service(port: u16) -> Option<&'static str> {
        WellKnownPort::get_service_name(port)
    }

    pub fn identify_service_string(port: u16) -> Option<String> {
        Self::identify_service(port).map(|s| s.to_string())
    }

    pub fn get_port_info(port: u16) -> Option<PortInfo> {
        WellKnownPort::get_port_info(port).map(|p| {
            PortInfo {
                port: p.port,
                service: p.service.clone(),
                protocol: p.protocol.clone(),
                description: p.description.clone(),
                category: p.category.as_str().to_string(),
                category_icon: p.category.icon().to_string(),
                risk_level: p.risk_level.as_str().to_string(),
                risk_color: p.risk_level.color().to_string(),
                risk_score: p.risk_level.score(),
            }
        })
    }

    pub fn get_risk_level(port: u16) -> Option<RiskLevel> {
        WellKnownPort::get_risk_level(port).cloned()
    }

    pub async fn grab_banner(target: IpAddr, port: u16, timeout_ms: u64) -> Option<String> {
        if !Self::should_grab_banner(port) {
            return None;
        }
        
        let banner_timeout = Duration::from_millis((timeout_ms / 3).min(200));
        
        let addr = std::net::SocketAddr::new(target, port);
        
        let mut stream = tokio::time::timeout(banner_timeout, TcpStream::connect(&addr))
            .await
            .ok()?
            .ok()?;

        let banner = Self::probe_service(&mut stream, port, banner_timeout).await;
        
        Some(banner)
    }

    fn should_grab_banner(port: u16) -> bool {
        matches!(port,
            21 | 22 | 23 | 25 | 80 | 110 | 143 | 443 | 993 | 995 |
            3306 | 3389 | 5432 | 5900 | 6379 | 8080 | 8443 | 27017
        )
    }

    async fn probe_service(stream: &mut TcpStream, port: u16, timeout: Duration) -> String {
        let probe = Self::get_probe_message(port);
        
        if let Err(_) = tokio::time::timeout(timeout, stream.write_all(probe.as_bytes())).await {
            return String::new();
        }

        let mut buffer = vec![0u8; 1024];
        let n = match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => return String::new(),
        };

        let banner = String::from_utf8_lossy(&buffer[..n])
            .trim()
            .to_string();

        Self::clean_banner(&banner)
    }

    fn get_probe_message(port: u16) -> String {
        match port {
            21 | 22 | 23 | 25 | 110 | 143 => String::new(),
            80 | 8080 | 8443 => format!("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
            443 => format!("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
            3306 => String::new(),
            _ => String::new(),
        }
    }

    fn clean_banner(banner: &str) -> String {
        banner
            .lines()
            .take(3)
            .collect::<Vec<&str>>()
            .join(" | ")
            .chars()
            .take(200)
            .collect()
    }

    pub fn parse_version(banner: &str, port: u16) -> Option<ServiceVersion> {
        if banner.is_empty() {
            return None;
        }

        let service_name = Self::identify_service(port)?;
        let port_info = Self::get_port_info(port);

        let version = match service_name {
            "ssh" => Self::parse_ssh_version(banner),
            "http" | "https" | "http-proxy" | "https-alt" => Self::parse_http_version(banner),
            "ftp" => Self::parse_ftp_version(banner),
            "mysql" => Self::parse_mysql_version(banner),
            "smtp" => Self::parse_smtp_version(banner),
            _ => None,
        };

        version.map(|v| ServiceVersion {
            service: service_name.to_string(),
            version: v,
            banner: Some(banner.to_string()),
            port_info,
        })
    }

    fn parse_ssh_version(banner: &str) -> Option<String> {
        if banner.starts_with("SSH-") {
            Some(banner.split_whitespace().next()?.to_string())
        } else {
            None
        }
    }

    fn parse_http_version(banner: &str) -> Option<String> {
        for line in banner.lines() {
            if line.starts_with("Server:") {
                return Some(line["Server:".len()..].trim().to_string());
            }
        }
        None
    }

    fn parse_ftp_version(banner: &str) -> Option<String> {
        if banner.contains("vsftpd") || banner.contains("ProFTPD") || banner.contains("FileZilla") {
            Some(banner.to_string())
        } else {
            None
        }
    }

    fn parse_mysql_version(banner: &str) -> Option<String> {
        if banner.contains("mysql") {
            Some(banner.to_string())
        } else {
            None
        }
    }

    fn parse_smtp_version(banner: &str) -> Option<String> {
        if banner.contains("Postfix") || banner.contains("Sendmail") || banner.contains("Exim") {
            Some(banner.to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_service() {
        assert_eq!(ServiceDetector::identify_service(22), Some("ssh"));
        assert_eq!(ServiceDetector::identify_service(80), Some("http"));
        assert_eq!(ServiceDetector::identify_service(443), Some("https"));
        assert_eq!(ServiceDetector::identify_service(3306), Some("mysql"));
        assert_eq!(ServiceDetector::identify_service(9999), None);
    }

    #[test]
    fn test_parse_ssh_version() {
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3";
        let version = ServiceDetector::parse_ssh_version(banner);
        assert_eq!(version, Some("SSH-2.0-OpenSSH_8.9p1".to_string()));
    }

    #[test]
    fn test_parse_http_version() {
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n";
        let version = ServiceDetector::parse_http_version(banner);
        assert_eq!(version, Some("Apache/2.4.52 (Ubuntu)".to_string()));
    }
}
