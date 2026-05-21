use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub max_concurrent_tasks: usize,
    pub default_timeout_ms: u64,
    pub log_level: String,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 100,
            default_timeout_ms: 5000,
            log_level: "info".to_string(),
        }
    }
}

impl GlobalConfig {
    pub fn new() -> Self {
        Self::default()
    }
}
