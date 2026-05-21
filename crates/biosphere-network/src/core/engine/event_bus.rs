use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{debug, info, warn, error};

use super::event::{BiosEvent, BiosEventRef};
use super::event_type::BiosEventType;
use super::module::ModuleRegistry;
use super::target::BiosTarget;
use super::database::EngineDatabase;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModuleErrorState {
    pub module_name: String,
    pub error_count: usize,
    pub last_error_time: i64,
    pub last_error_message: String,
    pub is_disabled: bool,
}

pub struct ModuleErrorTracker {
    errors: RwLock<HashMap<String, ModuleErrorState>>,
    max_errors: usize,
    cooldown_secs: i64,
    auto_recover: bool,
}

impl ModuleErrorTracker {
    pub fn new(max_errors: usize, cooldown_secs: i64, auto_recover: bool) -> Self {
        Self {
            errors: RwLock::new(HashMap::new()),
            max_errors,
            cooldown_secs,
            auto_recover,
        }
    }

    pub async fn record_error(&self, module_name: &str, error_message: &str) {
        let now = chrono::Utc::now().timestamp();
        let mut errors = self.errors.write().await;
        let state = errors.entry(module_name.to_string()).or_insert_with(|| ModuleErrorState {
            module_name: module_name.to_string(),
            error_count: 0,
            last_error_time: 0,
            last_error_message: String::new(),
            is_disabled: false,
        });
        state.error_count += 1;
        state.last_error_time = now;
        state.last_error_message = error_message.to_string();

        if state.error_count >= self.max_errors {
            state.is_disabled = true;
            warn!(
                "Module {} disabled after {} errors (last: {})",
                module_name, state.error_count, error_message
            );
        }
    }

    pub async fn is_module_disabled(&self, module_name: &str) -> bool {
        let mut errors = self.errors.write().await;
        if let Some(state) = errors.get_mut(module_name) {
            if state.is_disabled && self.auto_recover {
                let now = chrono::Utc::now().timestamp();
                if now - state.last_error_time >= self.cooldown_secs {
                    state.is_disabled = false;
                    state.error_count = 0;
                    info!("Module {} auto-recovered after cooldown", module_name);
                    return false;
                }
            }
            return state.is_disabled;
        }
        false
    }

    pub async fn get_error_states(&self) -> Vec<ModuleErrorState> {
        let errors = self.errors.read().await;
        errors.values().cloned().collect()
    }

    pub async fn reset_module(&self, module_name: &str) {
        let mut errors = self.errors.write().await;
        errors.remove(module_name);
    }

    pub async fn clear_module_queue(
        &self,
        module_name: &str,
        module_pending: &Arc<RwLock<HashMap<String, usize>>>,
        module_rate_tokens: &Arc<RwLock<HashMap<String, (usize, std::time::Instant)>>>,
    ) {
        {
            let mut pending = module_pending.write().await;
            pending.remove(module_name);
        }
        {
            let mut tokens = module_rate_tokens.write().await;
            tokens.remove(module_name);
        }
        info!("Cleared queue state for module {}", module_name);
    }

    pub async fn recover_module(
        &self,
        module_name: &str,
        module_pending: &Arc<RwLock<HashMap<String, usize>>>,
        module_rate_tokens: &Arc<RwLock<HashMap<String, (usize, std::time::Instant)>>>,
    ) {
        self.reset_module(module_name).await;
        self.clear_module_queue(module_name, module_pending, module_rate_tokens).await;
        info!("Fully recovered module {} with queue cleanup", module_name);
    }

    pub async fn get_disabled_modules(&self) -> Vec<String> {
        let errors = self.errors.read().await;
        errors.iter()
            .filter(|(_, state)| state.is_disabled)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct EventBusConfig {
    pub max_concurrent_modules: usize,
    pub event_buffer_size: usize,
    pub max_events_per_scan: usize,
    pub idle_check_interval_ms: u64,
    pub finished_confirmation_passes: usize,
    pub max_event_depth: usize,
    pub max_same_data_per_module: usize,
    pub cycle_detection_window: usize,
    pub module_timeout_secs: u64,
    pub global_semaphore_permits: usize,
    pub module_max_errors: usize,
    pub module_error_cooldown_secs: i64,
    pub module_auto_recover: bool,
    pub backpressure_threshold: usize,
    pub module_rate_limit_per_sec: usize,
    pub module_pending_limit: usize,
    pub batch_store_size: usize,
    pub batch_store_interval_ms: u64,
    pub max_event_data_size: usize,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            max_concurrent_modules: 5,
            event_buffer_size: 10000,
            max_events_per_scan: 100000,
            idle_check_interval_ms: 1000,
            finished_confirmation_passes: 3,
            max_event_depth: 20,
            max_same_data_per_module: 50,
            cycle_detection_window: 100,
            module_timeout_secs: 300,
            global_semaphore_permits: 10,
            module_max_errors: 5,
            module_error_cooldown_secs: 300,
            module_auto_recover: true,
            backpressure_threshold: 5000,
            module_rate_limit_per_sec: 100,
            module_pending_limit: 200,
            batch_store_size: 50,
            batch_store_interval_ms: 500,
            max_event_data_size: 1048576,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackpressureStatus {
    pub total_events: usize,
    pub threshold: usize,
    pub is_backpressured: bool,
    pub total_pending: usize,
    pub overloaded_modules: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventStats {
    pub total_events: usize,
    pub events_by_type: HashMap<String, usize>,
    pub events_by_module: HashMap<String, usize>,
    pub scan_id: String,
    pub suppressed_events: usize,
    pub rate_limited_events: usize,
    pub error_modules: usize,
}

enum EventBusCommand {
    Event(BiosEvent),
    StoreOnly(BiosEvent),
    Shutdown,
}

pub struct EventBus {
    config: EventBusConfig,
    registry: Arc<RwLock<ModuleRegistry>>,
    database: Option<Arc<EngineDatabase>>,
    command_tx: mpsc::UnboundedSender<EventBusCommand>,
    command_rx: Option<mpsc::UnboundedReceiver<EventBusCommand>>,
    processed_events: Arc<RwLock<HashMap<String, BiosEventRef>>>,
    notified_signatures: Arc<RwLock<HashSet<String>>>,
    event_hashes: Arc<RwLock<HashSet<String>>>,
    event_depths: Arc<RwLock<HashMap<String, usize>>>,
    module_event_counts: Arc<RwLock<HashMap<String, HashMap<String, usize>>>>,
    stats: Arc<RwLock<EventStats>>,
    target: Arc<RwLock<BiosTarget>>,
    running: Arc<RwLock<bool>>,
    scan_completed: Arc<RwLock<bool>>,
    active_tasks: Arc<RwLock<usize>>,
    error_tracker: Arc<ModuleErrorTracker>,
    module_pending: Arc<RwLock<HashMap<String, usize>>>,
    module_rate_tokens: Arc<RwLock<HashMap<String, (usize, std::time::Instant)>>>,
    batch_buffer: Arc<RwLock<Vec<BiosEventRef>>>,
}

fn event_signature(event: &BiosEvent) -> String {
    format!("{}:{}", event.event_type.as_str(), event.data.to_lowercase())
}

impl EventBus {
    pub fn new(
        config: EventBusConfig,
        registry: Arc<RwLock<ModuleRegistry>>,
        target: BiosTarget,
        scan_id: String,
        database: Option<Arc<EngineDatabase>>,
    ) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let error_tracker = Arc::new(ModuleErrorTracker::new(
            config.module_max_errors,
            config.module_error_cooldown_secs,
            config.module_auto_recover,
        ));

        Self {
            config,
            registry,
            database,
            command_tx,
            command_rx: Some(command_rx),
            processed_events: Arc::new(RwLock::new(HashMap::new())),
            notified_signatures: Arc::new(RwLock::new(HashSet::new())),
            event_hashes: Arc::new(RwLock::new(HashSet::new())),
            event_depths: Arc::new(RwLock::new(HashMap::new())),
            module_event_counts: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EventStats {
                total_events: 0,
                events_by_type: HashMap::new(),
                events_by_module: HashMap::new(),
                scan_id,
                suppressed_events: 0,
                rate_limited_events: 0,
                error_modules: 0,
            })),
            target: Arc::new(RwLock::new(target)),
            running: Arc::new(RwLock::new(false)),
            scan_completed: Arc::new(RwLock::new(false)),
            active_tasks: Arc::new(RwLock::new(0)),
            error_tracker,
            module_pending: Arc::new(RwLock::new(HashMap::new())),
            module_rate_tokens: Arc::new(RwLock::new(HashMap::new())),
            batch_buffer: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn publish(&self, event: BiosEvent) -> bool {
        if event.store_only {
            return self.publish_store_only(event).await;
        }

        if self.check_backpressure().await {
            debug!("Backpressure active, dropping event: {} from {}", event.event_type, event.module);
            let mut stats = self.stats.write().await;
            stats.suppressed_events += 1;
            return false;
        }

        let sig = event_signature(&event);

        if event.hash != "ROOT" {
            let is_hash_dup = {
                let hashes = self.event_hashes.read().await;
                hashes.contains(&event.hash)
            };
            if is_hash_dup {
                debug!("Hash-duplicate event: {} from {}", event.event_type, event.module);
                let mut stats = self.stats.write().await;
                stats.suppressed_events += 1;
                return false;
            }
        }

        let depth = self.compute_event_depth(&event).await;
        if depth > self.config.max_event_depth {
            debug!("Event depth {} exceeds max {}: {} from {}",
                depth, self.config.max_event_depth, event.event_type, event.module);
            let mut stats = self.stats.write().await;
            stats.suppressed_events += 1;
            return false;
        }

        if !self.check_module_frequency(&event).await {
            debug!("Module frequency limit reached for {} on data pattern", event.module);
            let mut stats = self.stats.write().await;
            stats.suppressed_events += 1;
            return false;
        }

        if !self.check_module_rate_limit(&event.module).await {
            debug!("Module rate limit reached for {}", event.module);
            let mut stats = self.stats.write().await;
            stats.rate_limited_events += 1;
            return false;
        }

        {
            let mut hashes = self.event_hashes.write().await;
            hashes.insert(event.hash.clone());
        }

        {
            let mut depths = self.event_depths.write().await;
            depths.insert(event.hash.clone(), depth);
        }

        let event_ref = BiosEventRef::from(&event);
        {
            let mut processed = self.processed_events.write().await;
            processed.insert(event.hash.clone(), event_ref.clone());
        }

        self.batch_store_event(event_ref).await;

        {
            let mut stats = self.stats.write().await;
            stats.total_events += 1;
            *stats.events_by_type.entry(event.event_type.to_string()).or_insert(0) += 1;
            *stats.events_by_module.entry(event.module.clone()).or_insert(0) += 1;
        }

        let is_duplicate = {
            let notified = self.notified_signatures.read().await;
            notified.contains(&sig)
        };

        let has_provenance_cycle = self.check_provenance_cycle(&event).await;
        let has_source_type_data_cycle = self.check_source_type_data_cycle(&event).await;

        let should_notify = if is_duplicate || has_provenance_cycle || has_source_type_data_cycle {
            false
        } else {
            let processed = self.processed_events.read().await;
            !event.should_suppress_notification(&processed)
        };

        if !should_notify {
            let reason = if is_duplicate {
                "duplicate"
            } else if has_provenance_cycle {
                "provenance_cycle"
            } else if has_source_type_data_cycle {
                "source_type_data_cycle"
            } else {
                "circular"
            };
            debug!("Event stored but not notified ({}): {} from {}", reason, event.event_type, event.module);
            let mut stats = self.stats.write().await;
            stats.suppressed_events += 1;
            return true;
        }

        {
            let mut notified = self.notified_signatures.write().await;
            notified.insert(sig);
        }

        if let Err(e) = self.command_tx.send(EventBusCommand::Event(event)) {
            warn!("Failed to send event to channel: {}", e);
            return false;
        }

        true
    }

    async fn compute_event_depth(&self, event: &BiosEvent) -> usize {
        let depths = self.event_depths.read().await;
        match &event.source_event_hash {
            Some(src_hash) if src_hash != "ROOT" => {
                depths.get(src_hash).map(|d| d + 1).unwrap_or(1)
            }
            _ => 0,
        }
    }

    async fn check_provenance_cycle(&self, event: &BiosEvent) -> bool {
        if event.source_event_hash.is_none() || event.source_event_hash.as_deref() == Some("ROOT") {
            return false;
        }

        let processed = self.processed_events.read().await;
        let event_type = &event.event_type;
        let event_data_lower = event.data.to_lowercase();

        let mut current_hash = event.source_event_hash.clone();
        let mut depth = 0;
        const MAX_PROVENANCE_DEPTH: usize = 50;

        while let Some(ref hash) = current_hash {
            if depth >= MAX_PROVENANCE_DEPTH {
                return true;
            }

            if hash == "ROOT" {
                return false;
            }

            if let Some(parent) = processed.get(hash) {
                if parent.event_type == *event_type && parent.data.to_lowercase() == event_data_lower {
                    return true;
                }
                current_hash = parent.source_event_hash.clone();
            } else {
                break;
            }
            depth += 1;
        }

        false
    }

    async fn check_source_type_data_cycle(&self, event: &BiosEvent) -> bool {
        if event.source_event_hash.is_none() || event.source_event_hash.as_deref() == Some("ROOT") {
            return false;
        }

        let processed = self.processed_events.read().await;
        let event_type = &event.event_type;
        let event_data_lower = event.data.to_lowercase();

        let mut current_hash = event.source_event_hash.clone();
        let mut depth = 0;
        const MAX_DEPTH: usize = 50;

        while let Some(ref hash) = current_hash {
            if depth >= MAX_DEPTH {
                return true;
            }
            if hash == "ROOT" {
                return false;
            }

            if let Some(parent) = processed.get(hash) {
                if parent.event_type == *event_type && parent.data.to_lowercase() == event_data_lower {
                    return true;
                }
                if let Some(ref src_type) = parent.source_event_type {
                    if src_type == event_type && parent.source_event_data.as_ref().map_or(false, |d| d.to_lowercase() == event_data_lower) {
                        return true;
                    }
                }
                current_hash = parent.source_event_hash.clone();
            } else {
                break;
            }
            depth += 1;
        }

        false
    }

    async fn check_module_frequency(&self, event: &BiosEvent) -> bool {
        let data_key = if event.data.len() > 64 {
            super::database::truncate_to_byte_limit(&event.data, 64)
        } else {
            event.data.clone()
        };
        let freq_key = format!("{}:{}", event.module, data_key);

        let mut counts = self.module_event_counts.write().await;
        let module_counts = counts.entry(event.module.clone()).or_default();
        let count = module_counts.entry(freq_key).or_insert(0);
        *count += 1;

        *count <= self.config.max_same_data_per_module
    }

    pub async fn publish_store_only(&self, event: BiosEvent) -> bool {
        if let Err(e) = self.command_tx.send(EventBusCommand::StoreOnly(event)) {
            warn!("Failed to send store-only event to channel: {}", e);
            return false;
        }
        true
    }

    async fn check_backpressure(&self) -> bool {
        let stats = self.stats.read().await;
        stats.total_events >= self.config.backpressure_threshold
    }

    async fn check_module_rate_limit(&self, module_name: &str) -> bool {
        let mut tokens = self.module_rate_tokens.write().await;
        let now = std::time::Instant::now();
        let limit = self.config.module_rate_limit_per_sec;

        let entry = tokens.entry(module_name.to_string()).or_insert((limit, now));
        let elapsed = now.duration_since(entry.1);

        if elapsed >= std::time::Duration::from_secs(1) {
            entry.0 = limit.saturating_sub(1);
            entry.1 = now;
            return true;
        }

        if entry.0 > 0 {
            entry.0 -= 1;
            return true;
        }

        false
    }

    async fn check_module_pending_limit(&self, module_name: &str) -> bool {
        let pending = self.module_pending.read().await;
        let count = pending.get(module_name).copied().unwrap_or(0);
        count < self.config.module_pending_limit
    }

    async fn increment_module_pending(&self, module_name: &str) {
        let mut pending = self.module_pending.write().await;
        *pending.entry(module_name.to_string()).or_insert(0) += 1;
    }

    async fn decrement_module_pending(&self, module_name: &str) {
        let mut pending = self.module_pending.write().await;
        if let Some(count) = pending.get_mut(module_name) {
            *count = count.saturating_sub(1);
        }
    }

    pub async fn get_backpressure_status(&self) -> BackpressureStatus {
        let stats = self.stats.read().await;
        let pending = self.module_pending.read().await;
        let total_pending: usize = pending.values().sum();
        let overloaded_modules: Vec<String> = pending.iter()
            .filter(|(_, &count)| count > self.config.module_pending_limit / 2)
            .map(|(name, _)| name.clone())
            .collect();

        BackpressureStatus {
            total_events: stats.total_events,
            threshold: self.config.backpressure_threshold,
            is_backpressured: stats.total_events >= self.config.backpressure_threshold,
            total_pending,
            overloaded_modules,
        }
    }

    pub async fn batch_store_event(&self, mut event: BiosEventRef) {
        let max_size = self.config.max_event_data_size;
        if event.data.len() > max_size {
            event.data = super::database::truncate_to_byte_limit(&event.data, max_size);
            event.data.push_str("...[TRUNCATED]");
        }
        let batch_size = self.config.batch_store_size;
        let mut buffer = self.batch_buffer.write().await;
        buffer.push(event);

        if buffer.len() >= batch_size {
            self.flush_batch_buffer(&mut buffer).await;
        }
    }

    async fn flush_batch_buffer(&self, buffer: &mut Vec<BiosEventRef>) {
        if buffer.is_empty() {
            return;
        }

        if let Some(ref db) = self.database {
            let scan_id = self.stats.read().await.scan_id.clone();
            let events: Vec<BiosEventRef> = buffer.drain(..).collect();
            if let Err(e) = db.store_events_batch(&events, &scan_id) {
                warn!("Failed to batch store {} events: {}", events.len(), e);
            }
        } else {
            buffer.clear();
        }
    }

    pub async fn flush_batch(&self) {
        let mut buffer = self.batch_buffer.write().await;
        self.flush_batch_buffer(&mut buffer).await;
    }

    pub async fn start_processing(&mut self) {
        let mut running = self.running.write().await;
        if *running {
            return;
        }
        *running = true;
        drop(running);

        let command_rx = self.command_rx.take();
        if command_rx.is_none() {
            error!("Command receiver already taken; cannot start processing");
            return;
        }
        let mut command_rx = command_rx.unwrap();

        let semaphore = Arc::new(Semaphore::new(self.config.global_semaphore_permits));
        let registry = self.registry.clone();
        let target = self.target.clone();
        let processed_events = self.processed_events.clone();
        let notified_signatures = self.notified_signatures.clone();
        let stats = self.stats.clone();
        let config = self.config.clone();
        let running_flag = self.running.clone();
        let scan_completed = self.scan_completed.clone();
        let active_tasks = self.active_tasks.clone();

        let command_tx = self.command_tx.clone();
        let database = self.database.clone();
        let scan_id = self.stats.read().await.scan_id.clone();
        let error_tracker = self.error_tracker.clone();
        let module_pending = self.module_pending.clone();
        let module_rate_tokens = self.module_rate_tokens.clone();
        let batch_buffer = self.batch_buffer.clone();
        let _batch_store_size = self.config.batch_store_size;
        let _batch_store_interval_ms = self.config.batch_store_interval_ms;
        let event_hashes = self.event_hashes.clone();

        tokio::spawn(async move {
            let mut idle_rounds: usize = 0;
            let mut finished_pass: usize = 0;
            let confirmation_passes = config.finished_confirmation_passes;
            let mut finished_triggered = false;

            loop {
                let is_running = *running_flag.read().await;
                if !is_running {
                    break;
                }

                if let Some(ref db) = database {
                    if db.is_scan_abort_requested(&scan_id) {
                        info!("Abort requested for scan {} via database, stopping", scan_id);
                        {
                            let reg = registry.read().await;
                            reg.request_stop_all();
                        }
                        break;
                    }
                }

                {
                    let stats_guard = stats.read().await;
                    if stats_guard.total_events > config.max_events_per_scan {
                        warn!("Max events per scan reached, stopping");
                        break;
                    }
                }

                match tokio::time::timeout(
                    std::time::Duration::from_millis(config.idle_check_interval_ms),
                    command_rx.recv(),
                ).await {
                    Ok(Some(EventBusCommand::Event(event))) => {
                        idle_rounds = 0;
                        Self::dispatch_event(
                            &event,
                            &registry,
                            &target,
                            &command_tx,
                            &semaphore,
                            &processed_events,
                            &notified_signatures,
                            &stats,
                            &active_tasks,
                            &running_flag,
                            &error_tracker,
                            &module_pending,
                            &module_rate_tokens,
                            config.module_pending_limit,
                            config.module_rate_limit_per_sec,
                        ).await;
                    }
                    Ok(Some(EventBusCommand::StoreOnly(event))) => {
                        let sig = event_signature(&event);
                        {
                            let mut hashes = event_hashes.write().await;
                            hashes.insert(event.hash.clone());
                        }
                        {
                            let mut event_ref = BiosEventRef::from(&event);
                            let max_size = config.max_event_data_size;
                            if event_ref.data.len() > max_size {
                                event_ref.data = super::database::truncate_to_byte_limit(&event_ref.data, max_size);
                                event_ref.data.push_str("...[TRUNCATED]");
                            }
                            let hash = event_ref.hash.clone();
                            {
                                let mut processed = processed_events.write().await;
                                processed.insert(hash, event_ref.clone());
                            }
                            if let Some(ref db) = database {
                                if let Err(e) = db.store_event(&event_ref, &scan_id) {
                                    warn!("Failed to store store-only event: {}", e);
                                }
                            }
                        }
                        {
                            let mut st = stats.write().await;
                            st.total_events += 1;
                            *st.events_by_type.entry(event.event_type.to_string()).or_insert(0) += 1;
                            *st.events_by_module.entry(event.module.clone()).or_insert(0) += 1;
                            st.suppressed_events += 1;
                        }
                        debug!("Store-only (external): {} from {}", event.event_type, event.module);
                        let _ = sig;
                    }
                    Ok(Some(EventBusCommand::Shutdown)) => {
                        info!("Shutdown command received");
                        break;
                    }
                    Ok(None) => {
                        info!("Command channel closed");
                        break;
                    }
                    Err(_) => {
                        let current_active = *active_tasks.read().await;
                        if current_active == 0 {
                            idle_rounds += 1;

                            {
                                let mut buffer = batch_buffer.write().await;
                                if !buffer.is_empty() {
                                    if let Some(ref db) = database {
                                        let sid = scan_id.clone();
                                        let events: Vec<BiosEventRef> = buffer.drain(..).collect();
                                        if let Err(e) = db.store_events_batch(&events, &sid) {
                                            warn!("Failed to batch store {} events: {}", events.len(), e);
                                        }
                                    } else {
                                        buffer.clear();
                                    }
                                }
                            }

                            if !finished_triggered && idle_rounds >= 2 {
                                info!("All modules idle, triggering finished() callbacks");
                                finished_triggered = true;
                                finished_pass = 0;

                                let reg = registry.read().await;
                                for module in reg.active_modules() {
                                    let events = module.finished().await;
                                    for event in events {
                                        let sig = event_signature(&event);
                                        {
                                            let notified = notified_signatures.read().await;
                                            if notified.contains(&sig) {
                                                continue;
                                            }
                                        }
                                        if let Err(e) = command_tx.send(EventBusCommand::Event(event)) {
                                            warn!("Failed to forward finished event: {}", e);
                                        }
                                    }
                                }
                            }

                            if finished_triggered {
                                let current_active_now = *active_tasks.read().await;
                                let total_pending: usize = module_pending.read().await.values().sum();
                                if current_active_now == 0 && total_pending == 0 {
                                    finished_pass += 1;

                                    if finished_pass < confirmation_passes {
                                        info!("Finished confirmation pass {}/{} — re-triggering finished()", finished_pass, confirmation_passes);
                                        let reg = registry.read().await;
                                        for module in reg.active_modules() {
                                            let events = module.finished().await;
                                            for event in events {
                                                let sig = event_signature(&event);
                                                {
                                                    let notified = notified_signatures.read().await;
                                                    if notified.contains(&sig) {
                                                        continue;
                                                    }
                                                }
                                                if let Err(e) = command_tx.send(EventBusCommand::Event(event)) {
                                                    warn!("Failed to forward finished event: {}", e);
                                                }
                                            }
                                        }
                                    } else {
                                        info!("Scan completed after {} confirmation passes", confirmation_passes);
                                        *scan_completed.write().await = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            {
                let mut running = running_flag.write().await;
                *running = false;
            }

            info!("Event processing loop ended");
        });
    }

    async fn dispatch_event(
        event: &BiosEvent,
        registry: &Arc<RwLock<ModuleRegistry>>,
        target: &Arc<RwLock<BiosTarget>>,
        command_tx: &mpsc::UnboundedSender<EventBusCommand>,
        global_semaphore: &Arc<Semaphore>,
        processed_events: &Arc<RwLock<HashMap<String, BiosEventRef>>>,
        notified_signatures: &Arc<RwLock<HashSet<String>>>,
        stats: &Arc<RwLock<EventStats>>,
        active_tasks: &Arc<RwLock<usize>>,
        running_flag: &Arc<RwLock<bool>>,
        error_tracker: &Arc<ModuleErrorTracker>,
        module_pending: &Arc<RwLock<HashMap<String, usize>>>,
        module_rate_tokens: &Arc<RwLock<HashMap<String, (usize, std::time::Instant)>>>,
        module_pending_limit: usize,
        module_rate_limit_per_sec: usize,
    ) {
        let subscriber_names = {
            let reg = registry.read().await;
            reg.subscribers_for(&event.event_type)
        };

        if subscriber_names.is_empty() {
            return;
        }

        for module_name in subscriber_names {
            if error_tracker.is_module_disabled(&module_name).await {
                debug!("Module {} is disabled due to errors, skipping", module_name);
                continue;
            }

            {
                let tokens = module_rate_tokens.read().await;
                let now = std::time::Instant::now();
                let entry = tokens.get(&module_name);
                let allowed = match entry {
                    Some((remaining, window_start)) => {
                        let elapsed = now.duration_since(*window_start);
                        if elapsed >= std::time::Duration::from_secs(1) {
                            true
                        } else {
                            *remaining > 0
                        }
                    }
                    None => true,
                };
                drop(tokens);

                if !allowed {
                    debug!("Module {} rate limit reached, skipping event", module_name);
                    continue;
                }

                let mut tokens = module_rate_tokens.write().await;
                let entry = tokens.entry(module_name.clone()).or_insert((module_rate_limit_per_sec, std::time::Instant::now()));
                let now = std::time::Instant::now();
                if now.duration_since(entry.1) >= std::time::Duration::from_secs(1) {
                    entry.0 = module_rate_limit_per_sec.saturating_sub(1);
                    entry.1 = now;
                } else if entry.0 > 0 {
                    entry.0 -= 1;
                }
            }

            {
                let pending = module_pending.read().await;
                let count = pending.get(&module_name).copied().unwrap_or(0);
                if count >= module_pending_limit {
                    debug!("Module {} pending limit reached ({}), skipping event", module_name, count);
                    continue;
                }
            }

            {
                let mut pending = module_pending.write().await;
                *pending.entry(module_name.clone()).or_insert(0) += 1;
            }

            {
                let reg = registry.read().await;
                if reg.is_queue_full(&module_name) {
                    debug!("Module {} queue is full, skipping event", module_name);
                    continue;
                }
                reg.increment_queue_depth(&module_name);
            }

            let global_permit = global_semaphore.clone().acquire_owned().await;
            if global_permit.is_err() {
                {
                    let reg = registry.read().await;
                    reg.decrement_queue_depth(&module_name);
                }
                break;
            }

            let module_semaphore = {
                let reg = registry.read().await;
                reg.get_semaphore(&module_name)
            };

            let module_semaphore = match module_semaphore {
                Some(sem) => sem,
                None => {
                    {
                        let reg = registry.read().await;
                        reg.decrement_queue_depth(&module_name);
                    }
                    continue;
                }
            };

            let module_permit = module_semaphore.clone().acquire_owned().await;
            if module_permit.is_err() {
                drop(global_permit);
                {
                    let reg = registry.read().await;
                    reg.decrement_queue_depth(&module_name);
                }
                continue;
            }

            let is_running = *running_flag.read().await;
            if !is_running {
                {
                    let reg = registry.read().await;
                    reg.decrement_queue_depth(&module_name);
                }
                break;
            }

            {
                let mut at = active_tasks.write().await;
                *at += 1;
            }

            let registry = registry.clone();
            let target = target.clone();
            let command_tx = command_tx.clone();
            let event_clone = event.clone();
            let _processed_events = processed_events.clone();
            let _notified_signatures = notified_signatures.clone();
            let _stats = stats.clone();
            let active_tasks = active_tasks.clone();
            let error_tracker = error_tracker.clone();
            let queue_depth_tracker = registry.clone();
            let module_pending_tracker = module_pending.clone();

            tokio::spawn(async move {
                let _global_permit = global_permit.unwrap();
                let _module_permit = module_permit.unwrap();

                let new_events: Vec<BiosEvent> = {
                    let reg = registry.read().await;
                    if let Some(module) = reg.get(&module_name) {
                        let module_state = reg.get_state(&module_name);
                        if let Some(state) = module_state {
                            if state.is_error() || state.is_stop_requested() {
                                let mut at = active_tasks.write().await;
                                *at -= 1;
                                queue_depth_tracker.read().await.decrement_queue_depth(&module_name);
                                {
                                    let mut pending = module_pending_tracker.write().await;
                                    if let Some(count) = pending.get_mut(&module_name) {
                                        *count = count.saturating_sub(1);
                                    }
                                }
                                return;
                            }
                        }

                        let target_guard = target.read().await;
                        let result = tokio::time::timeout(
                            std::time::Duration::from_secs(300),
                            module.handle_event(&event_clone, &target_guard),
                        ).await;

                        match result {
                            Ok(events) => events,
                            Err(_) => {
                                error!("Module {} timed out processing event", module_name);
                                error_tracker.record_error(&module_name, "Module execution timed out").await;
                                let mut at = active_tasks.write().await;
                                *at -= 1;
                                queue_depth_tracker.read().await.decrement_queue_depth(&module_name);
                                {
                                    let mut pending = module_pending_tracker.write().await;
                                    if let Some(count) = pending.get_mut(&module_name) {
                                        *count = count.saturating_sub(1);
                                    }
                                }
                                return;
                            }
                        }
                    } else {
                        let mut at = active_tasks.write().await;
                        *at -= 1;
                        queue_depth_tracker.read().await.decrement_queue_depth(&module_name);
                        {
                            let mut pending = module_pending_tracker.write().await;
                            if let Some(count) = pending.get_mut(&module_name) {
                                *count = count.saturating_sub(1);
                            }
                        }
                        return;
                    }
                };

                {
                    let mut at = active_tasks.write().await;
                    *at -= 1;
                }

                queue_depth_tracker.read().await.decrement_queue_depth(&module_name);

                let reg = registry.read().await;
                let module_state = reg.get_state(&module_name);

                for new_event in new_events {
                    if let Some(state) = module_state {
                        if !state.should_output_event(&new_event.event_type) {
                            debug!(
                                "Module {} output filter suppressed: {}",
                                module_name, new_event.event_type
                            );
                            continue;
                        }
                    }

                    if let Err(e) = command_tx.send(EventBusCommand::Event(new_event)) {
                        warn!("Failed to forward event: {}", e);
                    }
                }

                {
                    let mut pending = module_pending_tracker.write().await;
                    if let Some(count) = pending.get_mut(&module_name) {
                        *count = count.saturating_sub(1);
                    }
                }
            });
        }
    }

    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        let _ = self.command_tx.send(EventBusCommand::Shutdown);
    }

    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    pub async fn is_completed(&self) -> bool {
        *self.scan_completed.read().await
    }

    pub async fn get_stats(&self) -> EventStats {
        let mut stats = self.stats.read().await.clone();
        let error_states = self.error_tracker.get_error_states().await;
        stats.error_modules = error_states.iter().filter(|s| s.is_disabled).count();
        stats
    }

    pub async fn get_module_error_states(&self) -> Vec<ModuleErrorState> {
        self.error_tracker.get_error_states().await
    }

    pub async fn reset_module_errors(&self, module_name: &str) {
        self.error_tracker.reset_module(module_name).await;
    }

    pub async fn get_events(&self) -> Vec<BiosEventRef> {
        self.processed_events.read().await.values().cloned().collect()
    }

    pub async fn get_events_by_type(&self, event_type: &BiosEventType) -> Vec<BiosEventRef> {
        self.processed_events
            .read()
            .await
            .values()
            .filter(|e| &e.event_type == event_type)
            .cloned()
            .collect()
    }

    pub async fn get_target(&self) -> BiosTarget {
        self.target.read().await.clone()
    }

    pub async fn update_target(&self, f: impl FnOnce(&mut BiosTarget)) {
        let mut target = self.target.write().await;
        f(&mut target);
    }

    pub async fn active_task_count(&self) -> usize {
        *self.active_tasks.read().await
    }
}
