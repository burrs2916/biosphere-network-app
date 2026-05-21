use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::error::{Result, ToolError};
use super::progress::ProgressReporter;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ToolCategory {
    InformationGathering,
    WebAttack,
    PasswordAttack,
    WirelessAttack,
    Forensics,
    PostExploitation,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ToolCategory,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolArgs {
    pub target: Option<String>,
    pub options: HashMap<String, String>,
}

impl ToolArgs {
    pub fn new(target: Option<String>) -> Self {
        Self {
            target,
            options: HashMap::new(),
        }
    }

    pub fn with_option(mut self, key: String, value: String) -> Self {
        self.options.insert(key, value);
        self
    }

    pub fn get_option(&self, key: &str) -> Option<&String> {
        self.options.get(key)
    }

    pub fn get_target(&self) -> Result<&String> {
        self.target.as_ref()
            .ok_or_else(|| ToolError::MissingArgument("target".to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub success: bool,
    pub data: String,
    pub error: Option<String>,
}

impl ToolOutput {
    pub fn success(data: String) -> Self {
        Self {
            success: true,
            data,
            error: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: String::new(),
            error: Some(error),
        }
    }
}

pub trait Tool: Send + Sync {
    fn info(&self) -> ToolInfo;

    fn check_installed(&self) -> bool {
        true
    }

    fn run(&self, args: ToolArgs, progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput>;
}
