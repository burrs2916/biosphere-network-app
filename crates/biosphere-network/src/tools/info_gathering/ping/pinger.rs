use super::{PingConfig, PingResult, PingResponse};
use crate::core::{ToolError, Result};
use std::process::Command;
use regex::Regex;

pub struct Pinger;

impl Pinger {
    pub fn new() -> Self {
        Self
    }

    pub fn ping(config: PingConfig) -> Result<PingResult> {
        let mut responses = Vec::new();

        let output = Command::new("ping")
            .arg("-c")
            .arg(config.count.to_string())
            .arg("-W")
            .arg((config.timeout * 1000).to_string())
            .arg("-i")
            .arg(config.interval.to_string())
            .arg("-s")
            .arg(config.packet_size.to_string())
            .arg(&config.target)
            .output()
            .map_err(|e| ToolError::ExecutionError(format!("Failed to execute ping: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        eprintln!("DEBUG: Ping stdout:\n{}", stdout);
        eprintln!("DEBUG: Ping stderr:\n{}", stderr);
        eprintln!("DEBUG: Exit code: {}", output.status);

        if !output.status.success() && stdout.is_empty() {
            return Err(ToolError::ExecutionError(format!("Ping failed: {}", stderr)));
        }

        Self::parse_ping_output(&stdout, config.count, config.packet_size, &mut responses);

        Ok(PingResult::new(config.target.clone()).with_responses(responses))
    }

    fn parse_ping_output(output: &str, count: u32, packet_size: usize, responses: &mut Vec<PingResponse>) {
        let time_regex = Regex::new(r"time=(\d+\.?\d*)\s*ms").unwrap();
        
        let lines: Vec<&str> = output.lines().collect();
        let mut rtts = Vec::new();

        for line in &lines {
            if line.contains("bytes from") && line.contains("time=") {
                if let Some(caps) = time_regex.captures(line) {
                    if let Ok(rtt) = caps[1].parse::<f64>() {
                        rtts.push(rtt);
                    }
                }
            }
        }

        for i in 0..count {
            if (i as usize) < rtts.len() {
                responses.push(
                    PingResponse::new(i, packet_size)
                        .with_rtt(rtts[i as usize])
                );
            } else {
                responses.push(
                    PingResponse::new(i, packet_size)
                        .with_error("Request timeout".to_string())
                );
            }
        }
    }
}