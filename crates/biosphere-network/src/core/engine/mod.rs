pub mod event_type;
pub mod event;
pub mod target;
pub mod module;
pub mod event_bus;
pub mod correlator;
pub mod scan;
pub mod database;
pub mod security;

pub use event_type::{BiosEventType, EventCategory};
pub use event::{BiosEvent, BiosEventRef};
pub use target::BiosTarget;
pub use module::{BiosModule, ModuleMeta, ModuleConfig, ModuleRegistry};
pub use event_bus::{EventBus, EventBusConfig, EventStats};
pub use correlator::{Correlator, CorrelationRule, CorrelationResult, CorrelationRuleMeta, CorrelationMatchRule, CorrelationCollection, CorrelationAggregation, CorrelationAnalysis, default_correlation_rules};
pub use scan::{ScanOrchestrator, ScanState, ScanResult, ScanConfig, ScanConfigSnapshot};
pub use database::EngineDatabase;
pub use security::{CsrfTokenManager, SecurityHeaders};
