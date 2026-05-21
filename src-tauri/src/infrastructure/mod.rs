pub mod logging;
pub mod config;

pub use logging::{init_logger, log};
pub use config::LogConfig;
