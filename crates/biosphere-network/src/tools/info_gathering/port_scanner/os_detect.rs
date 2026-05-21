use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSDetection {
    pub os_type: String,
    pub os_family: String,
    pub confidence: u8,
    pub ttl: Option<u8>,
    pub details: Vec<String>,
}

impl OSDetection {
    pub fn new() -> Self {
        Self {
            os_type: "Unknown".to_string(),
            os_family: "Unknown".to_string(),
            confidence: 0,
            ttl: None,
            details: Vec::new(),
        }
    }

    pub async fn detect(target: IpAddr, timeout_ms: u64) -> Self {
        let mut detection = Self::new();
        
        if let Some(ttl) = Self::detect_ttl(target, timeout_ms).await {
            detection.ttl = Some(ttl);
            let (os_type, os_family, confidence) = Self::identify_os_by_ttl(ttl);
            detection.os_type = os_type;
            detection.os_family = os_family;
            detection.confidence = confidence;
            detection.details.push(format!("TTL: {}", ttl));
        }
        
        detection
    }

    async fn detect_ttl(target: IpAddr, timeout_ms: u64) -> Option<u8> {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};
        
        let target_str = target.to_string();
        
        let ping_result = timeout(
            Duration::from_millis(timeout_ms),
            Command::new("ping")
                .arg("-c")
                .arg("1")
                .arg("-W")
                .arg((timeout_ms / 1000).max(1).to_string())
                .arg(&target_str)
                .output()
        ).await;
        
        match ping_result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(ttl) = Self::extract_ttl_from_ping_output(&stdout) {
                    return Some(ttl);
                }
            }
            _ => {}
        }
        
        None
    }

    fn extract_ttl_from_ping_output(output: &str) -> Option<u8> {
        for line in output.lines() {
            if line.contains("ttl=") || line.contains("TTL=") {
                if let Some(ttl_start) = line.find("ttl=").or_else(|| line.find("TTL=")) {
                    let ttl_part = &line[ttl_start..];
                    if let Some(eq_pos) = ttl_part.find('=') {
                        let ttl_str = &ttl_part[eq_pos + 1..];
                        if let Some(space_pos) = ttl_str.find(' ') {
                            if let Ok(ttl) = ttl_str[..space_pos].parse::<u8>() {
                                return Some(ttl);
                            }
                        } else if let Ok(ttl) = ttl_str.parse::<u8>() {
                            return Some(ttl);
                        }
                    }
                }
            }
        }
        None
    }

    fn identify_os_by_ttl(ttl: u8) -> (String, String, u8) {
        if ttl <= 64 {
            if ttl >= 60 && ttl <= 64 {
                ("Linux/Unix".to_string(), "Unix-like".to_string(), 90)
            } else if ttl >= 50 && ttl < 60 {
                ("Linux/Unix".to_string(), "Unix-like".to_string(), 70)
            } else if ttl >= 40 && ttl < 50 {
                ("Linux/Unix (distant)".to_string(), "Unix-like".to_string(), 50)
            } else {
                ("Unknown".to_string(), "Unknown".to_string(), 30)
            }
        } else if ttl >= 100 && ttl <= 128 {
            if ttl >= 120 && ttl <= 128 {
                ("Windows".to_string(), "Windows".to_string(), 90)
            } else if ttl >= 110 && ttl < 120 {
                ("Windows".to_string(), "Windows".to_string(), 70)
            } else {
                ("Windows (distant)".to_string(), "Windows".to_string(), 50)
            }
        } else if ttl >= 200 {
            if ttl >= 250 {
                ("Cisco/Network Device".to_string(), "Network".to_string(), 85)
            } else {
                ("Network Device".to_string(), "Network".to_string(), 60)
            }
        } else {
            ("Unknown".to_string(), "Unknown".to_string(), 20)
        }
    }

    pub fn get_display(&self) -> String {
        if self.confidence >= 80 {
            format!("{} ({}% confidence)", self.os_type, self.confidence)
        } else if self.confidence >= 50 {
            format!("{} ({}% confidence)", self.os_type, self.confidence)
        } else {
            format!("Possibly {} ({}% confidence)", self.os_type, self.confidence)
        }
    }
}

impl Default for OSDetection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_os_by_ttl_linux() {
        let (os_type, os_family, confidence) = OSDetection::identify_os_by_ttl(64);
        assert_eq!(os_type, "Linux/Unix");
        assert_eq!(os_family, "Unix-like");
        assert_eq!(confidence, 90);
    }

    #[test]
    fn test_identify_os_by_ttl_windows() {
        let (os_type, os_family, confidence) = OSDetection::identify_os_by_ttl(128);
        assert_eq!(os_type, "Windows");
        assert_eq!(os_family, "Windows");
        assert_eq!(confidence, 90);
    }

    #[test]
    fn test_identify_os_by_ttl_cisco() {
        let (os_type, os_family, confidence) = OSDetection::identify_os_by_ttl(255);
        assert_eq!(os_type, "Cisco/Network Device");
        assert_eq!(os_family, "Network");
        assert_eq!(confidence, 85);
    }
}
