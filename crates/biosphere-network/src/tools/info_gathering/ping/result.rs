use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub target: String,
    pub packet_sent: u32,
    pub packet_received: u32,
    pub packet_loss: f64,
    pub min_rtt: Option<f64>,
    pub max_rtt: Option<f64>,
    pub avg_rtt: Option<f64>,
    pub std_dev_rtt: Option<f64>,
    pub status: String,
    pub error_message: Option<String>,
    pub ping_responses: Vec<PingResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    pub sequence: u32,
    pub rtt: Option<f64>,
    pub bytes: usize,
    pub status: String,
    pub error_message: Option<String>,
}

impl PingResult {
    pub fn new(target: String) -> Self {
        Self {
            target,
            packet_sent: 0,
            packet_received: 0,
            packet_loss: 0.0,
            min_rtt: None,
            max_rtt: None,
            avg_rtt: None,
            std_dev_rtt: None,
            status: "pending".to_string(),
            error_message: None,
            ping_responses: Vec::new(),
        }
    }

    pub fn with_responses(mut self, responses: Vec<PingResponse>) -> Self {
        self.packet_sent = responses.len() as u32;
        self.packet_received = responses.iter().filter(|r| r.rtt.is_some()).count() as u32;
        
        if self.packet_sent > 0 {
            self.packet_loss = ((self.packet_sent - self.packet_received) as f64 / self.packet_sent as f64) * 100.0;
        }

        let rtts: Vec<f64> = responses.iter()
            .filter_map(|r| r.rtt)
            .collect();

        if !rtts.is_empty() {
            self.min_rtt = Some(rtts.iter().cloned().fold(f64::INFINITY, f64::min));
            self.max_rtt = Some(rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max));
            self.avg_rtt = Some(rtts.iter().sum::<f64>() / rtts.len() as f64);
            
            if rtts.len() > 1 {
                let mean = self.avg_rtt.unwrap();
                let variance = rtts.iter()
                    .map(|&x| (x - mean).powi(2))
                    .sum::<f64>() / (rtts.len() - 1) as f64;
                self.std_dev_rtt = Some(variance.sqrt());
            }
        }

        self.status = if self.packet_received > 0 {
            "success".to_string()
        } else {
            "failed".to_string()
        };

        self.ping_responses = responses;
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.status = "failed".to_string();
        self
    }

    pub fn is_success(&self) -> bool {
        self.status == "success"
    }

    pub fn to_summary(&self) -> String {
        if let Some(error) = &self.error_message {
            return format!("Error: {}", error);
        }

        format!(
            "PING {}: {} packets transmitted, {} received, {:.1}% packet loss\nRTT: min={:.2}ms max={:.2}ms avg={:.2}ms",
            self.target,
            self.packet_sent,
            self.packet_received,
            self.packet_loss,
            self.min_rtt.unwrap_or(0.0),
            self.max_rtt.unwrap_or(0.0),
            self.avg_rtt.unwrap_or(0.0)
        )
    }
}

impl PingResponse {
    pub fn new(sequence: u32, bytes: usize) -> Self {
        Self {
            sequence,
            rtt: None,
            bytes,
            status: "pending".to_string(),
            error_message: None,
        }
    }

    pub fn with_rtt(mut self, rtt: f64) -> Self {
        self.rtt = Some(rtt);
        self.status = "success".to_string();
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.status = "failed".to_string();
        self
    }
}
