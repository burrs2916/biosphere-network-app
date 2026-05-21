use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncoderResult {
    pub success: bool,
    pub input: String,
    pub output: String,
    pub encoding_type: String,
    pub operation: String,
    pub error: Option<String>,
}

impl EncoderResult {
    pub fn success(
        input: String,
        output: String,
        encoding_type: String,
        operation: String,
    ) -> Self {
        Self {
            success: true,
            input,
            output,
            encoding_type,
            operation,
            error: None,
        }
    }

    pub fn error(input: String, encoding_type: String, operation: String, error: String) -> Self {
        Self {
            success: false,
            input,
            output: String::new(),
            encoding_type,
            operation,
            error: Some(error),
        }
    }
}
