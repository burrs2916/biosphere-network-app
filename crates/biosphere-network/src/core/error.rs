use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("Invalid configuration: {0}")]
    ConfigError(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Tool not found: {0}")]
    NotFoundError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Execution error: {0}")]
    ExecutionError(String),
    
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    
    #[error("Missing required argument: {0}")]
    MissingArgument(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, ToolError>;
