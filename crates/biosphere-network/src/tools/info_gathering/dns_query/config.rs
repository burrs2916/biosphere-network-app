use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryConfig {
    pub domain: String,
    pub query_type: DnsQueryType,
    pub dns_server: Option<String>,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    AAAA,
    MX,
    NS,
    CNAME,
    TXT,
    SOA,
    PTR,
    ANY,
}

impl DnsQueryType {
    pub fn as_str(&self) -> &str {
        match self {
            DnsQueryType::A => "A",
            DnsQueryType::AAAA => "AAAA",
            DnsQueryType::MX => "MX",
            DnsQueryType::NS => "NS",
            DnsQueryType::CNAME => "CNAME",
            DnsQueryType::TXT => "TXT",
            DnsQueryType::SOA => "SOA",
            DnsQueryType::PTR => "PTR",
            DnsQueryType::ANY => "ANY",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(DnsQueryType::A),
            "AAAA" => Some(DnsQueryType::AAAA),
            "MX" => Some(DnsQueryType::MX),
            "NS" => Some(DnsQueryType::NS),
            "CNAME" => Some(DnsQueryType::CNAME),
            "TXT" => Some(DnsQueryType::TXT),
            "SOA" => Some(DnsQueryType::SOA),
            "PTR" => Some(DnsQueryType::PTR),
            "ANY" => Some(DnsQueryType::ANY),
            _ => None,
        }
    }
}

impl DnsQueryConfig {
    pub fn new(domain: String, query_type: DnsQueryType) -> Self {
        Self {
            domain,
            query_type,
            dns_server: None,
            timeout: 5,
        }
    }

    pub fn with_dns_server(mut self, dns_server: String) -> Self {
        self.dns_server = Some(dns_server);
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }
}
