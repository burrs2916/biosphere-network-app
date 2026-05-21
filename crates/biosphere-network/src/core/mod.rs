mod error;
mod progress;
mod tool;
mod registry;
mod config;
pub mod engine;

pub use error::{ToolError, Result};
pub use progress::{ProgressReporter, NoOpProgressReporter};
pub use tool::{Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput};
pub use registry::ToolRegistry;
pub use config::GlobalConfig;
pub use engine::{
    BiosEventType, EventCategory, BiosEvent, BiosEventRef, BiosTarget,
    BiosModule, ModuleMeta, ModuleConfig, ModuleRegistry,
    EventBus, EventBusConfig, EventStats,
    Correlator, CorrelationRule, CorrelationResult, CorrelationRuleMeta,
    CorrelationMatchRule, CorrelationCollection, CorrelationAggregation,
    CorrelationAnalysis, default_correlation_rules,
    ScanOrchestrator, ScanState, ScanResult, ScanConfig, ScanConfigSnapshot,
    EngineDatabase,
};
