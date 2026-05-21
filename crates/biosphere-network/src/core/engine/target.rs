use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::fmt;

use ipnet::IpNet;

use super::event_type::BiosEventType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAlias {
    pub alias_type: BiosEventType,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiosTarget {
    pub target_type: BiosEventType,
    pub target_value: String,
    pub aliases: Vec<TargetAlias>,
}

impl BiosTarget {
    pub fn new(target_value: String, target_type: BiosEventType) -> Self {
        Self {
            target_type,
            target_value,
            aliases: Vec::new(),
        }
    }

    pub fn from_auto(target_value: &str) -> Self {
        let target_type = Self::detect_type(target_value);
        let mut target = Self {
            target_type: target_type.clone(),
            target_value: target_value.to_string(),
            aliases: Vec::new(),
        };

        if target_type == BiosEventType::InternetName && Self::is_domain_name(target_value) {
            target.set_alias(target_value, BiosEventType::DomainName);
        }

        target
    }

    fn is_domain_name(hostname: &str) -> bool {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        for part in &parts {
            if part.is_empty() {
                return false;
            }
            if part.starts_with('-') || part.ends_with('-') {
                return false;
            }
            if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }
        let tld = parts.last().unwrap();
        tld.chars().all(|c| c.is_ascii_alphabetic()) && tld.len() >= 2
    }

    pub fn detect_type(value: &str) -> BiosEventType {
        let trimmed = value.trim();

        if trimmed.parse::<IpAddr>().is_ok() {
            if trimmed.contains(':') {
                return BiosEventType::Ipv6Address;
            }
            return BiosEventType::IpAddress;
        }

        if trimmed.contains('/') {
            let parts: Vec<&str> = trimmed.split('/').collect();
            if parts.len() == 2 {
                if parts[0].parse::<IpAddr>().is_ok() {
                    if parts[0].contains(':') {
                        return BiosEventType::NetblockV6Owner;
                    }
                    return BiosEventType::NetblockOwner;
                }
            }
        }

        if trimmed.contains('@') && !trimmed.contains(' ') {
            return BiosEventType::EmailAddr;
        }

        if trimmed.starts_with('+') && trimmed[1..].chars().all(|c| c.is_ascii_digit()) {
            return BiosEventType::PhoneNumber;
        }

        if trimmed.starts_with('"') && trimmed.ends_with('"') {
            let inner = &trimmed[1..trimmed.len() - 1];
            if inner.contains(' ') {
                return BiosEventType::HumanName;
            }
            return BiosEventType::Username;
        }

        if trimmed.chars().all(|c| c.is_ascii_digit()) {
            return BiosEventType::BgpAsOwner;
        }

        if trimmed.contains('.') && !trimmed.contains(' ') {
            return BiosEventType::InternetName;
        }

        BiosEventType::Custom("UNKNOWN".to_string())
    }

    pub fn set_alias(&mut self, value: &str, alias_type: BiosEventType) {
        if value.is_empty() {
            return;
        }
        let lower = value.to_lowercase();
        if self.aliases.iter().any(|a| a.value.to_lowercase() == lower && a.alias_type == alias_type) {
            return;
        }
        self.aliases.push(TargetAlias {
            alias_type,
            value: value.to_string(),
        });
    }

    pub fn get_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .aliases
            .iter()
            .filter(|a| matches!(a.alias_type, BiosEventType::InternetName | BiosEventType::DomainName))
            .map(|a| a.value.to_lowercase())
            .collect();

        if matches!(self.target_type, BiosEventType::InternetName | BiosEventType::DomainName | BiosEventType::EmailAddr) {
            let lower = self.target_value.to_lowercase();
            if !names.contains(&lower) {
                names.push(lower);
            }
        }

        names
    }

    pub fn get_addresses(&self) -> Vec<String> {
        let mut addrs: Vec<String> = self
            .aliases
            .iter()
            .filter(|a| matches!(a.alias_type, BiosEventType::IpAddress | BiosEventType::Ipv6Address))
            .map(|a| a.value.clone())
            .collect();

        if matches!(self.target_type, BiosEventType::IpAddress) {
            if !addrs.contains(&self.target_value) {
                addrs.push(self.target_value.clone());
            }
        }

        addrs
    }

    pub fn matches(&self, value: &str, include_parents: bool, include_children: bool) -> bool {
        if value.is_empty() {
            return false;
        }

        if matches!(
            self.target_type,
            BiosEventType::HumanName
                | BiosEventType::PhoneNumber
                | BiosEventType::Username
                | BiosEventType::BitcoinAddress
                | BiosEventType::Custom(_)
        ) {
            return true;
        }

        let lower = value.to_lowercase();

        if value.parse::<IpAddr>().is_ok() {
            if self.get_addresses().iter().any(|a| a.to_lowercase() == lower) {
                return true;
            }

            if matches!(
                self.target_type,
                BiosEventType::IpAddress
                    | BiosEventType::Ipv6Address
                    | BiosEventType::NetblockOwner
                    | BiosEventType::NetblockV6Owner
            ) {
                if let Ok(target_net) = self.target_value.parse::<IpNet>() {
                    if let Ok(ip) = value.parse::<IpAddr>() {
                        if target_net.contains(&ip) {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        let names = self.get_names();
        for name in &names {
            if name.to_lowercase() == lower {
                return true;
            }
            if include_children && lower.ends_with(&format!(".{}", name)) {
                return true;
            }
            if include_parents && name.ends_with(&format!(".{}", lower)) {
                return true;
            }
        }

        false
    }
}

impl fmt::Display for BiosTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.target_value, self.target_type)
    }
}
