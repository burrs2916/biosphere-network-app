use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingConfig {
    pub target: String,
    pub count: u32,
    pub timeout: u64,
    pub interval: u64,
    pub packet_size: usize,
}

impl PingConfig {
    pub fn new(target: String) -> Self {
        Self {
            target,
            count: 4,
            timeout: 2,
            interval: 1,
            packet_size: 64,
        }
    }

    pub fn with_count(mut self, count: u32) -> Self {
        self.count = count;
        self
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_interval(mut self, interval: u64) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_packet_size(mut self, packet_size: usize) -> Self {
        self.packet_size = packet_size;
        self
    }
}
