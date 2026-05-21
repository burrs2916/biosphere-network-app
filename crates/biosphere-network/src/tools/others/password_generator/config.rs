use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CharacterSet {
    Lowercase,
    Uppercase,
    Numbers,
    Symbols,
    All,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    pub length: u32,
    pub include_lowercase: bool,
    pub include_uppercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
    pub exclude_ambiguous: bool,
    pub exclude_similar: bool,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResult {
    pub success: bool,
    pub passwords: Vec<String>,
    pub config: PasswordConfig,
    pub error: Option<String>,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_numbers: true,
            include_symbols: true,
            exclude_ambiguous: false,
            exclude_similar: false,
            count: 1,
        }
    }
}

impl PasswordResult {
    pub fn success(passwords: Vec<String>, config: PasswordConfig) -> Self {
        Self {
            success: true,
            passwords,
            config,
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            passwords: vec![],
            config: PasswordConfig::default(),
            error: Some(message),
        }
    }
}