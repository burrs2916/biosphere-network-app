use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisConfig {
    pub domain: String,
    pub timeout_ms: u64,
}

impl WhoisConfig {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            timeout_ms: 5000,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}
