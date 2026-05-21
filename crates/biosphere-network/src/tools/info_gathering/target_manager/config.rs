use serde::{Deserialize, Serialize};
use crate::infrastructure::database::models::TargetType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub name: String,
    pub target_type: TargetType,
    pub target_value: String,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub location: Option<String>,
    pub organization: Option<String>,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub priority: Option<String>,
    pub auto_scan: Option<bool>,
    pub scan_interval: Option<i64>,
    pub metadata: Option<String>,
}

impl TargetConfig {
    pub fn new(name: String, target_type: TargetType, target_value: String) -> Self {
        Self {
            name,
            target_type,
            target_value,
            description: None,
            tags: None,
            location: None,
            organization: None,
            owner: None,
            contact: None,
            priority: None,
            auto_scan: None,
            scan_interval: None,
            metadata: None,
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_organization(mut self, organization: String) -> Self {
        self.organization = Some(organization);
        self
    }

    pub fn with_owner(mut self, owner: String) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn with_contact(mut self, contact: String) -> Self {
        self.contact = Some(contact);
        self
    }

    pub fn with_priority(mut self, priority: String) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn with_auto_scan(mut self, auto_scan: bool) -> Self {
        self.auto_scan = Some(auto_scan);
        self
    }

    pub fn with_scan_interval(mut self, scan_interval: i64) -> Self {
        self.scan_interval = Some(scan_interval);
        self
    }

    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Target name cannot be empty".to_string());
        }

        if self.target_value.is_empty() {
            return Err("Target value cannot be empty".to_string());
        }

        match self.target_type {
            TargetType::IP => {
                if !self.is_valid_ip(&self.target_value) {
                    return Err("Invalid IP address".to_string());
                }
            }
            TargetType::Domain | TargetType::Hostname => {
                if !self.is_valid_domain(&self.target_value) {
                    return Err("Invalid domain name".to_string());
                }
            }
            TargetType::URL => {
                if !self.is_valid_url(&self.target_value) {
                    return Err("Invalid URL".to_string());
                }
            }
            TargetType::Subnet => {
                if !self.is_valid_subnet(&self.target_value) {
                    return Err("Invalid subnet".to_string());
                }
            }
            TargetType::Range => {
                if !self.is_valid_range(&self.target_value) {
                    return Err("Invalid IP range".to_string());
                }
            }
            TargetType::Email => {
                if !self.is_valid_email(&self.target_value) {
                    return Err("Invalid email address".to_string());
                }
            }
            TargetType::Phone => {
                if self.target_value.trim().is_empty() {
                    return Err("Phone number cannot be empty".to_string());
                }
            }
            TargetType::Username | TargetType::SocialMedia => {
                if self.target_value.trim().is_empty() {
                    return Err("Value cannot be empty".to_string());
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn is_valid_ip(&self, value: &str) -> bool {
        value.parse::<std::net::IpAddr>().is_ok()
    }

    fn is_valid_domain(&self, value: &str) -> bool {
        if value.is_empty() || value.len() > 253 {
            return false;
        }

        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() < 2 {
            return false;
        }

        parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 63 && part.chars().all(|c| {
                c.is_alphanumeric() || c == '-'
            })
        })
    }

    fn is_valid_url(&self, value: &str) -> bool {
        value.starts_with("http://") || value.starts_with("https://")
    }

    fn is_valid_subnet(&self, value: &str) -> bool {
        if let Some((ip, mask)) = value.split_once('/') {
            if let Ok(mask_num) = mask.parse::<u8>() {
                if mask_num <= 32 {
                    return ip.parse::<std::net::IpAddr>().is_ok();
                }
            }
        }
        false
    }

    fn is_valid_range(&self, value: &str) -> bool {
        if let Some((start, end)) = value.split_once('-') {
            let start_ip = start.parse::<std::net::IpAddr>().is_ok();
            let end_ip = end.parse::<std::net::IpAddr>().is_ok();
            return start_ip && end_ip;
        }
        false
    }

    fn is_valid_email(&self, value: &str) -> bool {
        value.contains('@') && value.contains('.') && value.len() > 5
    }
}
