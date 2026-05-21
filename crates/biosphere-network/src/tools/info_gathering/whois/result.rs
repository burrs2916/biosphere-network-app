use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResult {
    pub domain: String,
    pub registrar: Option<String>,
    pub created_date: Option<String>,
    pub updated_date: Option<String>,
    pub expiry_date: Option<String>,
    pub status: Vec<String>,
    pub name_servers: Vec<String>,
    pub registrant_name: Option<String>,
    pub registrant_organization: Option<String>,
    pub registrant_country: Option<String>,
    pub registrant_email: Option<String>,
    pub admin_name: Option<String>,
    pub admin_email: Option<String>,
    pub tech_name: Option<String>,
    pub tech_email: Option<String>,
    pub dnssec: Option<String>,
    pub raw_response: String,
    pub query_time: u64,
    pub queried_at: DateTime<Utc>,
}

impl WhoisResult {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            registrar: None,
            created_date: None,
            updated_date: None,
            expiry_date: None,
            status: Vec::new(),
            name_servers: Vec::new(),
            registrant_name: None,
            registrant_organization: None,
            registrant_country: None,
            registrant_email: None,
            admin_name: None,
            admin_email: None,
            tech_name: None,
            tech_email: None,
            dnssec: None,
            raw_response: String::new(),
            query_time: 0,
            queried_at: Utc::now(),
        }
    }

    pub fn is_available(&self) -> bool {
        self.registrar.is_none() && self.raw_response.contains("No match for")
    }
}
