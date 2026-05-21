use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use uuid::Uuid;

use super::correlator::{Correlator, CorrelationResult, default_correlation_rules};
use super::database::EngineDatabase;
use super::event::BiosEvent;
use super::event_bus::{EventBus, EventBusConfig};
use super::event_type::BiosEventType;
use super::module::ModuleRegistry;
use super::target::BiosTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScanState {
    Initializing,
    Starting,
    Running,
    Paused,
    AbortRequested,
    Aborting,
    Aborted,
    Finished,
    ErrorFailed,
}

impl ScanState {
    pub fn can_transition_to(&self, target: &ScanState) -> bool {
        match self {
            ScanState::Initializing => matches!(target, ScanState::Starting | ScanState::ErrorFailed),
            ScanState::Starting => matches!(target, ScanState::Running | ScanState::AbortRequested | ScanState::ErrorFailed),
            ScanState::Running => matches!(target, ScanState::AbortRequested | ScanState::Paused | ScanState::Finished | ScanState::ErrorFailed),
            ScanState::Paused => matches!(target, ScanState::Running | ScanState::AbortRequested | ScanState::ErrorFailed),
            ScanState::AbortRequested => matches!(target, ScanState::Aborting | ScanState::Aborted | ScanState::ErrorFailed),
            ScanState::Aborting => matches!(target, ScanState::Aborted | ScanState::ErrorFailed),
            ScanState::Aborted | ScanState::Finished | ScanState::ErrorFailed => false,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, ScanState::Aborted | ScanState::Finished | ScanState::ErrorFailed)
    }

    pub fn is_active(&self) -> bool {
        matches!(self, ScanState::Starting | ScanState::Running)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ScanState::Initializing => "initializing",
            ScanState::Starting => "starting",
            ScanState::Running => "running",
            ScanState::Paused => "paused",
            ScanState::AbortRequested => "abort_requested",
            ScanState::Aborting => "aborting",
            ScanState::Aborted => "aborted",
            ScanState::Finished => "finished",
            ScanState::ErrorFailed => "error_failed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "initializing" => Some(ScanState::Initializing),
            "starting" => Some(ScanState::Starting),
            "running" => Some(ScanState::Running),
            "paused" => Some(ScanState::Paused),
            "abort_requested" => Some(ScanState::AbortRequested),
            "aborting" => Some(ScanState::Aborting),
            "aborted" => Some(ScanState::Aborted),
            "finished" => Some(ScanState::Finished),
            "error_failed" => Some(ScanState::ErrorFailed),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub target: String,
    pub state: ScanState,
    pub total_events: usize,
    pub correlation_results: Vec<CorrelationResult>,
    pub event_type_counts: HashMap<String, usize>,
    pub module_counts: HashMap<String, usize>,
    pub suppressed_events: usize,
    pub error_modules: usize,
    pub config_snapshot: Option<ScanConfigSnapshot>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanConfig {
    pub output_filters: HashMap<String, Vec<BiosEventType>>,
    pub max_event_data_size: Option<usize>,
    pub config_file_path: Option<String>,
    pub auto_reload_interval_secs: Option<u64>,
}

impl ScanConfig {
    pub fn load_from_file(path: &str) -> std::result::Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path, e))?;
        let config: ScanConfig = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse config file {}: {}", path, e))?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &str) -> std::result::Result<(), String> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        std::fs::write(path, content)
            .map_err(|e| format!("Failed to write config file {}: {}", path, e))?;
        Ok(())
    }

    pub fn resolve_value(&self, value: &str) -> String {
        if value.starts_with("file://") {
            let path = &value[7..];
            std::fs::read_to_string(path).unwrap_or_else(|_| value.to_string())
        } else if value.starts_with("env://") {
            let env_var = &value[6..];
            std::env::var(env_var).unwrap_or_else(|_| value.to_string())
        } else {
            value.to_string()
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanConfigSnapshot {
    pub scan_id: String,
    pub scan_name: String,
    pub target_value: String,
    pub target_type: String,
    pub modules_enabled: Vec<String>,
    pub global_options: HashMap<String, String>,
    pub module_options: HashMap<String, HashMap<String, String>>,
    pub created_at: i64,
}

pub struct ScanOrchestrator {
    registry: Arc<RwLock<ModuleRegistry>>,
    correlator: Arc<RwLock<Correlator>>,
    database: Option<Arc<EngineDatabase>>,
    config: EventBusConfig,
    scan_config: ScanConfig,
    scans: Arc<RwLock<HashMap<String, Arc<RwLock<ScanInternalState>>>>>,
}

struct ScanInternalState {
    target: BiosTarget,
    event_bus: Option<EventBus>,
    state: ScanState,
    config_snapshot: Option<ScanConfigSnapshot>,
    started_at: Option<i64>,
    finished_at: Option<i64>,
}

impl ScanOrchestrator {
    pub fn new(registry: Arc<RwLock<ModuleRegistry>>) -> Self {
        let mut correlator = Correlator::new();
        for rule in default_correlation_rules() {
            correlator.add_rule(rule);
        }

        Self {
            registry,
            correlator: Arc::new(RwLock::new(correlator)),
            database: None,
            config: EventBusConfig::default(),
            scan_config: ScanConfig::default(),
            scans: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_config(mut self, config: EventBusConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_scan_config(mut self, scan_config: ScanConfig) -> Self {
        self.scan_config = scan_config;
        self
    }

    pub fn with_database(mut self, database: EngineDatabase) -> Self {
        self.database = Some(Arc::new(database));
        self
    }

    pub fn with_correlation_rules(mut self, yaml_rules: Vec<String>) -> std::result::Result<Self, String> {
        let mut correlator = Correlator::new();
        for rule in default_correlation_rules() {
            correlator.add_rule(rule);
        }
        for yaml in yaml_rules {
            correlator.load_rules_from_yaml(&yaml)?;
        }
        self.correlator = Arc::new(RwLock::new(correlator));
        Ok(self)
    }

    async fn transition_state(state: &Arc<RwLock<ScanInternalState>>, target: ScanState) -> std::result::Result<ScanState, String> {
        let mut internal = state.write().await;
        if !internal.state.can_transition_to(&target) {
            return Err(format!("Invalid state transition: {} -> {}", internal.state, target));
        }
        info!("Scan state transition: {} -> {}", internal.state, target);
        internal.state = target;
        Ok(target)
    }

    pub async fn start_scan(&self, target_value: &str, scan_name: Option<&str>, scan_id: Option<String>) -> std::result::Result<String, String> {
        let scan_id = scan_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let name = scan_name.unwrap_or("Unnamed Scan").to_string();
        let mut target = BiosTarget::from_auto(target_value);

        info!("Starting scan {} for target: {} (type: {})", scan_id, target.target_value, target.target_type);

        let config_snapshot = self.build_config_snapshot(&scan_id, &name, &target).await;

        {
            let reg = self.registry.read().await;
            for module in reg.all_modules() {
                if let Err(e) = module.enrich_target(&mut target).await {
                    debug!("Module {} enrich_target failed: {}", module.name(), e);
                }
            }
        }

        if !self.scan_config.output_filters.is_empty() {
            let mut reg = self.registry.write().await;
            reg.set_output_filter_from_config(&self.scan_config.output_filters);
        }

        if let Some(ref db) = self.database {
            if let Err(e) = db.create_scan(&scan_id, &target.target_value, target.target_type.as_str()) {
                warn!("Failed to create scan in database: {}", e);
            }

            if let Err(e) = db.store_config_snapshot(&config_snapshot) {
                warn!("Failed to store config snapshot: {}", e);
            }

            let types_to_register: Vec<(String, String, bool, String)> = BiosEventType::all_standard_types()
                .into_iter()
                .map(|et| {
                    let meta = crate::core::engine::event_type::EventTypeMeta::from(&et);
                    (meta.event, meta.description, meta.is_raw, meta.category)
                })
                .collect();
            if let Err(e) = db.batch_register_event_types(&types_to_register) {
                warn!("Failed to register event types in database: {}", e);
            }
        }

        let internal_state = Arc::new(RwLock::new(ScanInternalState {
            target: target.clone(),
            event_bus: None,
            state: ScanState::Initializing,
            config_snapshot: Some(config_snapshot),
            started_at: None,
            finished_at: None,
        }));

        self.scans.write().await.insert(scan_id.clone(), internal_state.clone());

        {
            let mut internal = internal_state.write().await;
            internal.state = ScanState::Starting;
            internal.started_at = Some(chrono::Utc::now().timestamp());
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(&scan_id, ScanState::Starting.as_str());
        }

        let mut event_bus = EventBus::new(
            self.config.clone(),
            self.registry.clone(),
            target.clone(),
            scan_id.clone(),
            self.database.clone(),
        );

        event_bus.start_processing().await;

        let root_event = BiosEvent::root(scan_id.clone(), target.target_value.clone());
        event_bus.publish(root_event).await;

        let target_event = BiosEvent::new(
            target.target_type.clone(),
            target.target_value.clone(),
            "BiosPhere".to_string(),
            None,
            scan_id.clone(),
        );
        event_bus.publish(target_event).await;

        {
            let reg = self.registry.read().await;
            for module in reg.all_modules() {
                let watched = module.watched_events();
                if watched.contains(&BiosEventType::Root) {
                    let target_guard = event_bus.get_target().await;
                    let root = BiosEvent::root(scan_id.clone(), target.target_value.clone());
                    let events = module.handle_event(&root, &target_guard).await;
                    for event in events {
                        event_bus.publish(event).await;
                    }
                }
            }
        }

        {
            let mut internal = internal_state.write().await;
            internal.event_bus = Some(event_bus);
            internal.state = ScanState::Running;
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(&scan_id, ScanState::Running.as_str());
        }

        Ok(scan_id)
    }

    pub async fn start_scan_with_config(&self, target_value: &str, scan_name: Option<&str>, scan_id: Option<String>, config: ScanConfig) -> std::result::Result<String, String> {
        let scan_id = scan_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let name = scan_name.unwrap_or("Unnamed Scan").to_string();
        let mut target = BiosTarget::from_auto(target_value);

        info!("Starting scan {} for target: {} (type: {}) with custom config", scan_id, target.target_value, target.target_type);

        let config_snapshot = self.build_config_snapshot(&scan_id, &name, &target).await;

        {
            let reg = self.registry.read().await;
            for module in reg.all_modules() {
                if let Err(e) = module.enrich_target(&mut target).await {
                    debug!("Module {} enrich_target failed: {}", module.name(), e);
                }
            }
        }

        if !config.output_filters.is_empty() {
            let mut reg = self.registry.write().await;
            reg.set_output_filter_from_config(&config.output_filters);
        }

        if let Some(ref db) = self.database {
            if let Err(e) = db.create_scan(&scan_id, &target.target_value, target.target_type.as_str()) {
                warn!("Failed to create scan in database: {}", e);
            }
            if let Err(e) = db.store_config_snapshot(&config_snapshot) {
                warn!("Failed to store config snapshot: {}", e);
            }
        }

        let internal_state = Arc::new(RwLock::new(ScanInternalState {
            target: target.clone(),
            event_bus: None,
            state: ScanState::Initializing,
            config_snapshot: Some(config_snapshot),
            started_at: None,
            finished_at: None,
        }));

        self.scans.write().await.insert(scan_id.clone(), internal_state.clone());

        {
            let mut internal = internal_state.write().await;
            internal.state = ScanState::Starting;
            internal.started_at = Some(chrono::Utc::now().timestamp());
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(&scan_id, ScanState::Starting.as_str());
        }

        let event_bus_config = self.config.clone();

        let mut event_bus = EventBus::new(
            event_bus_config,
            self.registry.clone(),
            target.clone(),
            scan_id.clone(),
            self.database.clone(),
        );

        event_bus.start_processing().await;

        let root_event = BiosEvent::root(scan_id.clone(), target.target_value.clone());
        event_bus.publish(root_event).await;

        let target_event = BiosEvent::new(
            target.target_type.clone(),
            target.target_value.clone(),
            "BiosPhere".to_string(),
            None,
            scan_id.clone(),
        );
        event_bus.publish(target_event).await;

        {
            let reg = self.registry.read().await;
            for module in reg.all_modules() {
                let watched = module.watched_events();
                if watched.contains(&BiosEventType::Root) {
                    let target_guard = event_bus.get_target().await;
                    let root = BiosEvent::root(scan_id.clone(), target.target_value.clone());
                    let events = module.handle_event(&root, &target_guard).await;
                    for event in events {
                        event_bus.publish(event).await;
                    }
                }
            }
        }

        {
            let mut internal = internal_state.write().await;
            internal.event_bus = Some(event_bus);
            internal.state = ScanState::Running;
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(&scan_id, ScanState::Running.as_str());
        }

        Ok(scan_id)
    }

    async fn build_config_snapshot(&self, scan_id: &str, scan_name: &str, target: &BiosTarget) -> ScanConfigSnapshot {
        let reg = self.registry.read().await;
        let modules_enabled = reg.module_names();
        let mut module_options = HashMap::new();
        for name in &modules_enabled {
            module_options.insert(name.clone(), HashMap::new());
        }

        ScanConfigSnapshot {
            scan_id: scan_id.to_string(),
            scan_name: scan_name.to_string(),
            target_value: target.target_value.clone(),
            target_type: target.target_type.as_str().to_string(),
            modules_enabled,
            global_options: HashMap::new(),
            module_options,
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    pub async fn stop_scan(&self, scan_id: &str) -> std::result::Result<(), String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        drop(scans);

        {
            let mut internal = state_arc.write().await;
            if !internal.state.can_transition_to(&ScanState::AbortRequested) {
                return Err(format!("Cannot stop scan in state {}", internal.state));
            }
            internal.state = ScanState::AbortRequested;
        }

        {
            let internal = state_arc.read().await;
            if let Some(ref bus) = internal.event_bus {
                bus.stop().await;
            }
        }

        {
            let mut internal = state_arc.write().await;
            internal.state = ScanState::Aborting;
        }

        {
            let reg = self.registry.read().await;
            reg.request_stop_all();
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(scan_id, ScanState::AbortRequested.as_str());
        }

        Ok(())
    }

    pub async fn pause_scan(&self, scan_id: &str) -> std::result::Result<(), String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        drop(scans);

        {
            let mut internal = state_arc.write().await;
            if internal.state != ScanState::Running {
                return Err(format!("Cannot pause scan in state {}", internal.state));
            }
            internal.state = ScanState::Paused;
        }

        {
            let reg = self.registry.read().await;
            reg.request_stop_all();
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(scan_id, ScanState::Paused.as_str());
            let reg = self.registry.read().await;
            for name in reg.module_names() {
                let _ = db.save_module_state(scan_id, &name, "paused", 0, None, false);
            }
        }

        Ok(())
    }

    pub async fn resume_scan(&self, scan_id: &str) -> std::result::Result<(), String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        drop(scans);

        {
            let mut internal = state_arc.write().await;
            if internal.state != ScanState::Paused {
                return Err(format!("Cannot resume scan in state {}", internal.state));
            }
            internal.state = ScanState::Running;
        }

        if let Some(ref db) = self.database {
            let _ = db.update_scan_status(scan_id, ScanState::Running.as_str());
            let reg = self.registry.read().await;
            for name in reg.module_names() {
                if let Ok(Some(entry)) = db.get_module_state(scan_id, &name) {
                    if entry.disabled {
                        let _ = db.reset_module_state(scan_id, &name);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn check_scan_completion(&self, scan_id: &str) -> std::result::Result<ScanState, String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        drop(scans);

        let should_complete = {
            let internal = state_arc.read().await;
            if let Some(ref bus) = internal.event_bus {
                bus.is_completed().await && !internal.state.is_terminal()
            } else {
                false
            }
        };

        if should_complete {
            {
                let internal = state_arc.read().await;
                if let Some(ref bus) = internal.event_bus {
                    bus.flush_batch().await;
                }
            }

            let events = {
                let internal = state_arc.read().await;
                match &internal.event_bus {
                    Some(bus) => bus.get_events().await,
                    None => Vec::new(),
                }
            };

            let final_state = {
                let internal = state_arc.read().await;
                if internal.state == ScanState::Aborting || internal.state == ScanState::AbortRequested {
                    ScanState::Aborted
                } else {
                    ScanState::Finished
                }
            };

            {
                let mut internal = state_arc.write().await;
                internal.state = final_state;
                internal.finished_at = Some(chrono::Utc::now().timestamp());
            }

            if let Some(ref db) = self.database {
                let _ = db.update_scan_status(scan_id, final_state.as_str());

                {
                    let internal = state_arc.read().await;
                    if let Some(ref bus) = internal.event_bus {
                        bus.flush_batch().await;
                    }
                }

                let mut correlator = self.correlator.write().await;
                let correlation_results = correlator.run_correlations(&events);
                if let Err(e) = db.store_correlations(&correlation_results, scan_id) {
                    warn!("Failed to store correlations in database: {}", e);
                }
            }
        }

        let internal = state_arc.read().await;
        Ok(internal.state)
    }

    pub async fn get_scan_result(&self, scan_id: &str) -> std::result::Result<ScanResult, String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        let internal = state_arc.read().await;

        let (stats, events) = if let Some(ref bus) = internal.event_bus {
            (bus.get_stats().await, bus.get_events().await)
        } else {
            return Err("Event bus not available".to_string());
        };

        let correlation_results = {
            let mut correlator = self.correlator.write().await;
            correlator.run_correlations(&events)
        };

        Ok(ScanResult {
            scan_id: scan_id.to_string(),
            target: internal.target.target_value.clone(),
            state: internal.state,
            total_events: stats.total_events,
            correlation_results,
            event_type_counts: stats.events_by_type,
            module_counts: stats.events_by_module,
            suppressed_events: stats.suppressed_events,
            error_modules: stats.error_modules,
            config_snapshot: internal.config_snapshot.clone(),
        })
    }

    pub async fn run_correlations(&self, scan_id: &str) -> std::result::Result<Vec<CorrelationResult>, String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        let internal = state_arc.read().await;

        let events = if let Some(ref bus) = internal.event_bus {
            bus.get_events().await
        } else {
            Vec::new()
        };

        let mut correlator = self.correlator.write().await;
        Ok(correlator.run_correlations(&events))
    }

    pub async fn list_scans(&self) -> Vec<(String, ScanState, String)> {
        let scans = self.scans.read().await;
        let mut result = Vec::new();
        for (id, state_arc) in scans.iter() {
            let internal = state_arc.read().await;
            result.push((id.clone(), internal.state, internal.target.target_value.clone()));
        }
        result
    }

    pub async fn delete_scan(&self, scan_id: &str) -> std::result::Result<(), String> {
        {
            let scans = self.scans.read().await;
            if let Some(state_arc) = scans.get(scan_id) {
                let internal = state_arc.read().await;
                if internal.state.is_active() {
                    return Err("Cannot delete an active scan. Stop it first.".to_string());
                }
            }
        }

        if let Some(ref db) = self.database {
            if let Err(e) = db.delete_scan(scan_id) {
                warn!("Failed to delete scan from database: {}", e);
            }
        }
        let mut scans = self.scans.write().await;
        scans.remove(scan_id).ok_or("Scan not found")?;
        Ok(())
    }

    pub async fn get_config_snapshot(&self, scan_id: &str) -> std::result::Result<Option<ScanConfigSnapshot>, String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        let internal = state_arc.read().await;
        Ok(internal.config_snapshot.clone())
    }

    pub async fn rerun_scan(&self, original_scan_id: &str) -> std::result::Result<String, String> {
        let snapshot = {
            let scans = self.scans.read().await;
            if let Some(state_arc) = scans.get(original_scan_id) {
                let internal = state_arc.read().await;
                internal.config_snapshot.clone()
            } else if let Some(ref db) = self.database {
                db.get_config_snapshot(original_scan_id).map_err(|e| e.to_string())?
            } else {
                return Err("Original scan not found and no database available".to_string());
            }
        };

        let snapshot = snapshot.ok_or("No config snapshot available for scan")?;

        let new_scan_id = self.start_scan(&snapshot.target_value, Some(&snapshot.scan_name), None).await?;

        if !snapshot.module_options.is_empty() {
            let mut reg = self.registry.write().await;
            for (module_name, options) in &snapshot.module_options {
                let config = crate::core::engine::module::ModuleConfig {
                    options: options.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect(),
                    descriptions: HashMap::new(),
                };
                if let Err(e) = reg.setup_module(module_name, &config) {
                    warn!("Failed to setup module {} for rescan: {}", module_name, e);
                }
            }
        }

        Ok(new_scan_id)
    }

    pub async fn rerun_scan_with_config(&self, original_scan_id: &str, overrides: ScanConfig) -> std::result::Result<String, String> {
        let snapshot = {
            let scans = self.scans.read().await;
            if let Some(state_arc) = scans.get(original_scan_id) {
                let internal = state_arc.read().await;
                internal.config_snapshot.clone()
            } else if let Some(ref db) = self.database {
                db.get_config_snapshot(original_scan_id).map_err(|e| e.to_string())?
            } else {
                return Err("Original scan not found and no database available".to_string());
            }
        };

        let snapshot = snapshot.ok_or("No config snapshot available for scan")?;
        let new_scan_id = self.start_scan_with_config(&snapshot.target_value, Some(&snapshot.scan_name), None, overrides).await?;
        Ok(new_scan_id)
    }

    pub async fn clone_scan_config(&self, scan_id: &str) -> std::result::Result<ScanConfigSnapshot, String> {
        let scans = self.scans.read().await;
        let state_arc = scans.get(scan_id).ok_or("Scan not found")?.clone();
        let internal = state_arc.read().await;
        internal.config_snapshot.clone().ok_or("No config snapshot available".to_string())
    }
}
