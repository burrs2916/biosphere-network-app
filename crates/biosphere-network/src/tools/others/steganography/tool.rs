use crate::core::{Result, ToolError};
use super::config::*;
use std::fs;

pub struct SteganographyTool;

impl SteganographyTool {
    pub async fn process(config: &SteganographyConfig) -> Result<SteganographyResult> {
        match config.operation.as_str() {
            "hide" => Self::hide(config).await,
            "extract" => Self::extract(config).await,
            _ => Err(ToolError::ExecutionError("Invalid operation".to_string())),
        }
    }

    async fn hide(config: &SteganographyConfig) -> Result<SteganographyResult> {
        if config.cover_file_path.is_empty() {
            return Err(ToolError::ExecutionError("Cover file path is required".to_string()));
        }
        if config.secret_file_path.is_none() && config.secret_text.is_none() {
            return Err(ToolError::ExecutionError("Secret file or text is required".to_string()));
        }
        if config.output_file_path.is_none() {
            return Err(ToolError::ExecutionError("Output file path is required".to_string()));
        }

        let cover_data = fs::read(&config.cover_file_path)
            .map_err(|e| ToolError::ExecutionError(format!("Failed to read cover file: {}", e)))?;

        let secret_data = if let Some(ref text) = config.secret_text {
            text.as_bytes().to_vec()
        } else {
            fs::read(config.secret_file_path.as_ref().unwrap())
                .map_err(|e| ToolError::ExecutionError(format!("Failed to read secret file: {}", e)))?
        };

        let mut output_data = Vec::new();
        output_data.extend_from_slice(&cover_data);
        output_data.extend_from_slice(&secret_data);
        output_data.extend_from_slice(&secret_data.len().to_le_bytes());

        if let Some(ref passphrase) = config.passphrase {
            let marker = b"STEG_PASS:";
            output_data.extend_from_slice(marker);
            output_data.extend_from_slice(&passphrase.len().to_le_bytes());
            output_data.extend_from_slice(passphrase.as_bytes());
        }

        fs::write(config.output_file_path.as_ref().unwrap(), &output_data)
            .map_err(|e| ToolError::ExecutionError(format!("Failed to write output file: {}", e)))?;

        Ok(SteganographyResult {
            success: true,
            operation: "hide".to_string(),
            message: format!("Successfully hidden {} bytes of data", secret_data.len()),
            output_path: config.output_file_path.clone(),
            extracted_data: None,
        })
    }

    async fn extract(config: &SteganographyConfig) -> Result<SteganographyResult> {
        if config.cover_file_path.is_empty() {
            return Err(ToolError::ExecutionError("Cover file path is required".to_string()));
        }

        let data = fs::read(&config.cover_file_path)
            .map_err(|e| ToolError::ExecutionError(format!("Failed to read file: {}", e)))?;

        if data.len() < 8 {
            return Ok(SteganographyResult {
                success: false,
                operation: "extract".to_string(),
                message: "No hidden data found".to_string(),
                output_path: None,
                extracted_data: None,
            });
        }

        let has_passphrase = Self::check_passphrase(&data);
        if has_passphrase {
            if config.passphrase.is_none() {
                return Ok(SteganographyResult {
                    success: false,
                    operation: "extract".to_string(),
                    message: "This file is password protected, please provide a passphrase".to_string(),
                    output_path: None,
                    extracted_data: None,
                });
            }
            if !Self::verify_passphrase(&data, config.passphrase.as_ref().unwrap()) {
                return Ok(SteganographyResult {
                    success: false,
                    operation: "extract".to_string(),
                    message: "Incorrect passphrase".to_string(),
                    output_path: None,
                    extracted_data: None,
                });
            }
        }

        let len_bytes = &data[data.len() - 8..];
        let secret_len = u64::from_le_bytes(len_bytes.try_into().unwrap_or([0; 8])) as usize;

        if secret_len == 0 || secret_len > data.len() - 8 {
            return Ok(SteganographyResult {
                success: false,
                operation: "extract".to_string(),
                message: "No valid hidden data found".to_string(),
                output_path: None,
                extracted_data: None,
            });
        }

        let secret_data = &data[data.len() - 8 - secret_len..data.len() - 8];
        let extracted_str = String::from_utf8_lossy(secret_data).to_string();

        Ok(SteganographyResult {
            success: true,
            operation: "extract".to_string(),
            message: format!("Successfully extracted {} bytes of data", secret_len),
            output_path: None,
            extracted_data: Some(extracted_str),
        })
    }

    fn check_passphrase(data: &[u8]) -> bool {
        let marker = b"STEG_PASS:";
        if data.len() < marker.len() + 8 {
            return false;
        }
        let search_start = data.len().saturating_sub(256);
        let tail = &data[search_start..];
        tail.windows(marker.len()).any(|w| w == marker)
    }

    fn verify_passphrase(data: &[u8], passphrase: &str) -> bool {
        let marker = b"STEG_PASS:";
        if data.len() < marker.len() + 8 + passphrase.len() {
            return false;
        }
        let search_start = data.len().saturating_sub(512);
        let tail = &data[search_start..];
        if let Some(pos) = tail.windows(marker.len()).position(|w| w == marker) {
            let after_marker = &tail[pos + marker.len()..];
            if after_marker.len() < 8 {
                return false;
            }
            let pass_len = u64::from_le_bytes(
                after_marker[..8].try_into().unwrap_or([0; 8])
            ) as usize;
            if after_marker.len() < 8 + pass_len {
                return false;
            }
            let stored_pass = &after_marker[8..8 + pass_len];
            return stored_pass == passphrase.as_bytes();
        }
        false
    }
}
