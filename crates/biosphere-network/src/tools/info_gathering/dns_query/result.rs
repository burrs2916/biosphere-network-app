use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryResult {
    pub domain: String,
    pub query_type: String,
    pub records: Vec<DnsRecord>,
    pub query_time: i32,
    pub dns_server: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub r#type: String,
    pub class: String,
    pub ttl: i32,
    pub data: String,
}

impl DnsQueryResult {
    pub fn new(domain: String, query_type: String) -> Self {
        Self {
            domain,
            query_type,
            records: Vec::new(),
            query_time: 0,
            dns_server: None,
            error: None,
        }
    }

    pub fn with_records(mut self, records: Vec<DnsRecord>) -> Self {
        self.records = records;
        self
    }

    pub fn with_query_time(mut self, query_time: i32) -> Self {
        self.query_time = query_time;
        self
    }

    pub fn with_dns_server(mut self, dns_server: String) -> Self {
        self.dns_server = Some(dns_server);
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    pub fn is_success(&self) -> bool {
        self.error.is_none() && !self.records.is_empty()
    }

    pub fn get_record_data(&self) -> Vec<String> {
        self.records.iter().map(|r| r.data.clone()).collect()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn to_summary(&self) -> String {
        if let Some(error) = &self.error {
            return format!("Error: {}", error);
        }

        if self.records.is_empty() {
            return "No records found".to_string();
        }

        let mut summary = format!("Found {} {} record(s):\n", self.records.len(), self.query_type);
        for record in &self.records {
            summary.push_str(&format!("  - {}\n", record.data));
        }

        summary
    }
}

impl DnsRecord {
    pub fn new(name: String, r#type: String, class: String, ttl: i32, data: String) -> Self {
        Self {
            name,
            r#type,
            class,
            ttl,
            data,
        }
    }
}
