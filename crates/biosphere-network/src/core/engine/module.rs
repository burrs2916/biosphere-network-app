use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::event::BiosEvent;
use super::event_type::BiosEventType;
use super::target::BiosTarget;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct ModuleMeta {
    pub name: String,
    pub summary: String,
    pub flags: Vec<String>,
    pub use_cases: Vec<String>,
    pub categories: Vec<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleConfig {
    pub options: HashMap<String, serde_json::Value>,
    pub descriptions: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct OutputFilter {
    pub allowed: HashSet<BiosEventType>,
    pub excluded: HashSet<BiosEventType>,
    pub allow_wildcard: bool,
    pub exclude_raw: bool,
    pub exclude_categories: HashSet<String>,
}

impl OutputFilter {
    pub fn new(allowed: HashSet<BiosEventType>) -> Self {
        Self {
            allowed,
            excluded: HashSet::new(),
            allow_wildcard: false,
            exclude_raw: false,
            exclude_categories: HashSet::new(),
        }
    }

    pub fn with_exclusions(mut self, excluded: HashSet<BiosEventType>) -> Self {
        self.excluded = excluded;
        self
    }

    pub fn with_wildcard(mut self) -> Self {
        self.allow_wildcard = true;
        self
    }

    pub fn with_raw_excluded(mut self) -> Self {
        self.exclude_raw = true;
        self
    }

    pub fn with_category_excluded(mut self, category: &str) -> Self {
        self.exclude_categories.insert(category.to_string());
        self
    }

    pub fn should_output(&self, event_type: &BiosEventType) -> bool {
        if event_type == &BiosEventType::Root {
            return true;
        }

        if self.excluded.contains(event_type) {
            return false;
        }

        if self.exclude_raw && event_type.is_raw() {
            return false;
        }

        if !self.exclude_categories.is_empty() {
            let cat = event_type.category().to_string();
            if self.exclude_categories.contains(&cat) {
                return false;
            }
        }

        if self.allow_wildcard {
            return !self.excluded.contains(event_type);
        }

        if self.allowed.is_empty() {
            return true;
        }

        self.allowed.contains(event_type)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleState {
    pub error_state: Arc<AtomicBool>,
    pub stop_requested: Arc<AtomicBool>,
    pub output_filter: Option<OutputFilter>,
    pub temp_storage: HashMap<String, serde_json::Value>,
    pub max_threads: usize,
}

impl ModuleState {
    pub fn new() -> Self {
        Self {
            error_state: Arc::new(AtomicBool::new(false)),
            stop_requested: Arc::new(AtomicBool::new(false)),
            output_filter: None,
            temp_storage: HashMap::new(),
            max_threads: 1,
        }
    }

    pub fn set_temp(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.temp_storage.insert(key.into(), value);
    }

    pub fn get_temp(&self, key: &str) -> Option<&serde_json::Value> {
        self.temp_storage.get(key)
    }

    pub fn remove_temp(&mut self, key: &str) -> Option<serde_json::Value> {
        self.temp_storage.remove(key)
    }

    pub fn clear_temp(&mut self) {
        self.temp_storage.clear();
    }

    pub fn set_error(&self) {
        self.error_state.store(true, Ordering::SeqCst);
    }

    pub fn is_error(&self) -> bool {
        self.error_state.load(Ordering::SeqCst)
    }

    pub fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::SeqCst);
    }

    pub fn is_stop_requested(&self) -> bool {
        self.stop_requested.load(Ordering::SeqCst)
    }

    pub fn set_output_filter(&mut self, filter: HashSet<BiosEventType>) {
        self.output_filter = Some(OutputFilter::new(filter));
    }

    pub fn set_output_filter_advanced(&mut self, filter: OutputFilter) {
        self.output_filter = Some(filter);
    }

    pub fn should_output_event(&self, event_type: &BiosEventType) -> bool {
        match &self.output_filter {
            Some(filter) => filter.should_output(event_type),
            None => true,
        }
    }
}

#[async_trait]
pub trait BiosModule: Send + Sync {
    fn name(&self) -> &str;
    fn meta(&self) -> ModuleMeta;
    fn watched_events(&self) -> &[BiosEventType];
    fn produced_events(&self) -> &[BiosEventType];
    fn priority(&self) -> u8 {
        1
    }

    fn max_threads(&self) -> usize {
        1
    }

    async fn setup(&mut self, _config: &ModuleConfig) -> std::result::Result<(), String> {
        Ok(())
    }

    async fn handle_event(&self, event: &BiosEvent, target: &BiosTarget) -> Vec<BiosEvent>;

    async fn enrich_target(&self, _target: &mut BiosTarget) -> std::result::Result<(), String> {
        Ok(())
    }

    async fn finished(&self) -> Vec<BiosEvent> {
        Vec::new()
    }

    fn init_temp_storage(&self, _state: &mut ModuleState) {
        // Default implementation does nothing; modules can override to initialize temp storage.
    }
}

pub struct ModuleRegistry {
    modules: HashMap<String, Box<dyn BiosModule>>,
    module_states: HashMap<String, ModuleState>,
    event_subscriptions: HashMap<BiosEventType, Vec<String>>,
    module_semaphores: HashMap<String, Arc<Semaphore>>,
    module_queue_depths: HashMap<String, Arc<std::sync::atomic::AtomicUsize>>,
    module_max_queue_depths: HashMap<String, usize>,
}

use tokio::sync::Semaphore;

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            module_states: HashMap::new(),
            event_subscriptions: HashMap::new(),
            module_semaphores: HashMap::new(),
            module_queue_depths: HashMap::new(),
            module_max_queue_depths: HashMap::new(),
        }
    }

    pub fn register(&mut self, module: Box<dyn BiosModule>) {
        let name = module.name().to_string();
        let watched = module.watched_events().to_vec();
        let max_threads = module.max_threads();
        let priority = module.priority();

        for event_type in &watched {
            let subs = self.event_subscriptions
                .entry(event_type.clone())
                .or_default();
            subs.push(name.clone());
            subs.sort_by_key(|sub_name| {
                if sub_name == &name {
                    priority
                } else {
                    self.modules.get(sub_name).map(|m| m.priority()).unwrap_or(255)
                }
            });
        }

        let mut state = ModuleState::new();
        state.max_threads = max_threads;
        module.init_temp_storage(&mut state);
        self.module_semaphores.insert(name.clone(), Arc::new(Semaphore::new(max_threads)));
        self.module_queue_depths.insert(name.clone(), Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        self.module_max_queue_depths.insert(name.clone(), max_threads * 10);
        self.module_states.insert(name.clone(), state);
        self.modules.insert(name, module);
    }

    pub fn get(&self, name: &str) -> Option<&dyn BiosModule> {
        self.modules.get(name).map(|m| m.as_ref())
    }

    pub fn get_state(&self, name: &str) -> Option<&ModuleState> {
        self.module_states.get(name)
    }

    pub fn get_state_mut(&mut self, name: &str) -> Option<&mut ModuleState> {
        self.module_states.get_mut(name)
    }

    pub fn get_semaphore(&self, name: &str) -> Option<Arc<Semaphore>> {
        self.module_semaphores.get(name).cloned()
    }

    pub fn get_queue_depth(&self, name: &str) -> usize {
        self.module_queue_depths
            .get(name)
            .map(|d| d.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn increment_queue_depth(&self, name: &str) {
        if let Some(depth) = self.module_queue_depths.get(name) {
            depth.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn decrement_queue_depth(&self, name: &str) {
        if let Some(depth) = self.module_queue_depths.get(name) {
            depth.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn is_queue_full(&self, name: &str) -> bool {
        let current = self.get_queue_depth(name);
        let max = self.module_max_queue_depths.get(name).copied().unwrap_or(100);
        current >= max
    }

    pub fn set_max_queue_depth(&mut self, name: &str, max_depth: usize) {
        self.module_max_queue_depths.insert(name.to_string(), max_depth);
    }

    pub fn setup_module(&mut self, name: &str, config: &ModuleConfig) -> std::result::Result<(), String> {
        let module = self.modules.get_mut(name).ok_or("Module not found")?;
        let rt = tokio::runtime::Handle::current();
        rt.block_on(module.setup(config))
    }

    pub fn subscribers_for(&self, event_type: &BiosEventType) -> Vec<String> {
        let mut result = Vec::new();

        if let Some(subs) = self.event_subscriptions.get(event_type) {
            for sub in subs {
                if let Some(state) = self.module_states.get(sub) {
                    if !state.is_error() && !state.is_stop_requested() {
                        result.push(sub.clone());
                    }
                }
            }
        }

        if let Some(wildcard_subs) = self.event_subscriptions.get(&BiosEventType::Custom("*".to_string())) {
            for sub in wildcard_subs {
                if let Some(state) = self.module_states.get(sub) {
                    if !state.is_error() && !state.is_stop_requested() {
                        result.push(sub.clone());
                    }
                }
            }
        }

        result.sort_by_key(|name| {
            self.modules.get(name).map(|m| m.priority()).unwrap_or(255)
        });

        result
    }

    pub fn all_modules(&self) -> Vec<&dyn BiosModule> {
        let mut modules: Vec<&dyn BiosModule> = self.modules.values().map(|m| m.as_ref()).collect();
        modules.sort_by_key(|m| m.priority());
        modules
    }

    pub fn active_modules(&self) -> Vec<&dyn BiosModule> {
        let mut modules: Vec<&dyn BiosModule> = self
            .modules
            .iter()
            .filter(|(name, _)| {
                if let Some(state) = self.module_states.get(*name) {
                    !state.is_error() && !state.is_stop_requested()
                } else {
                    true
                }
            })
            .map(|(_, m)| m.as_ref())
            .collect();
        modules.sort_by_key(|m| m.priority());
        modules
    }

    pub fn module_names(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.modules.len()
    }

    pub fn request_stop_all(&self) {
        for state in self.module_states.values() {
            state.request_stop();
        }
    }

    pub fn set_output_filter(&mut self, module_name: &str, filter: HashSet<BiosEventType>) {
        if let Some(state) = self.module_states.get_mut(module_name) {
            state.set_output_filter(filter);
        }
    }

    pub fn set_output_filter_from_config(&mut self, config: &std::collections::HashMap<String, Vec<BiosEventType>>) {
        for (module_name, filter) in config {
            if let Some(state) = self.module_states.get_mut(module_name) {
                state.set_output_filter(filter.iter().cloned().collect());
            }
        }
    }

    pub fn all_modules_idle(&self) -> bool {
        self.module_queue_depths.values().all(|depth| {
            depth.load(std::sync::atomic::Ordering::Relaxed) == 0
        })
    }

    pub fn modules_producing(&self, event_types: &[BiosEventType]) -> Vec<String> {
        let mut result = Vec::new();
        for (name, module) in &self.modules {
            let produced = module.produced_events();
            for et in event_types {
                if produced.contains(et) {
                    result.push(name.clone());
                    break;
                }
            }
        }
        result
    }

    pub fn modules_consuming(&self, event_types: &[BiosEventType]) -> Vec<String> {
        let mut result = Vec::new();
        for (name, module) in &self.modules {
            let watched = module.watched_events();
            for et in event_types {
                if watched.contains(et) {
                    result.push(name.clone());
                    break;
                }
            }
        }
        result
    }

    pub fn events_produced_by(&self, module_name: &str) -> Vec<BiosEventType> {
        self.modules.get(module_name)
            .map(|m| m.produced_events().to_vec())
            .unwrap_or_default()
    }

    pub fn events_consumed_by(&self, module_name: &str) -> Vec<BiosEventType> {
        self.modules.get(module_name)
            .map(|m| m.watched_events().to_vec())
            .unwrap_or_default()
    }

    pub fn resolve_dependencies(&self, module_names: &[String]) -> std::result::Result<Vec<String>, String> {
        let mut resolved = Vec::new();
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        for name in module_names {
            if !self.modules.contains_key(name) {
                return Err(format!("Module not found: {}", name));
            }
            self.resolve_dfs(name, &mut resolved, &mut visited, &mut in_stack)?;
        }

        Ok(resolved)
    }

    fn resolve_dfs(
        &self,
        name: &str,
        resolved: &mut Vec<String>,
        visited: &mut HashSet<String>,
        in_stack: &mut HashSet<String>,
    ) -> std::result::Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if in_stack.contains(name) {
            return Err(format!("Circular dependency detected involving module: {}", name));
        }

        in_stack.insert(name.to_string());

        if let Some(module) = self.modules.get(name) {
            let produced = module.produced_events();
            for event_type in produced {
                if let Some(subs) = self.event_subscriptions.get(event_type) {
                    for sub in subs {
                        if sub != name && !visited.contains(sub) {
                            self.resolve_dfs(sub, resolved, visited, in_stack)?;
                        }
                    }
                }
            }
        }

        in_stack.remove(name);
        visited.insert(name.to_string());
        resolved.push(name.to_string());
        Ok(())
    }

    pub fn resolve_modules_for_event_types(&self, event_types: &[BiosEventType]) -> Vec<String> {
        let mut required = HashSet::new();
        let mut to_process: Vec<BiosEventType> = event_types.to_vec();

        while let Some(et) = to_process.pop() {
            let producers = self.modules_producing(std::slice::from_ref(&et));
            for producer in &producers {
                if required.contains(producer) {
                    continue;
                }
                required.insert(producer.clone());

                if let Some(module) = self.modules.get(producer) {
                    for watched in module.watched_events() {
                        if !to_process.iter().any(|e| e == watched) {
                            to_process.push(watched.clone());
                        }
                    }
                }
            }
        }

        let mut result: Vec<String> = required.into_iter().collect();
        result.sort_by_key(|name| {
            self.modules.get(name).map(|m| m.priority()).unwrap_or(255)
        });
        result
    }

    pub fn get_module_dependency_graph(&self) -> HashMap<String, Vec<String>> {
        let mut graph = HashMap::new();

        for (name, module) in &self.modules {
            let mut deps = HashSet::new();
            for event_type in module.watched_events() {
                if let Some(subs) = self.event_subscriptions.get(event_type) {
                    for sub in subs {
                        if sub != name {
                            deps.insert(sub.clone());
                        }
                    }
                }
            }
            graph.insert(name.clone(), deps.into_iter().collect());
        }

        graph
    }

    pub fn validate_module_compatibility(&self, module_names: &[String]) -> std::result::Result<Vec<String>, String> {
        let mut warnings = Vec::new();
        let available: HashSet<&String> = module_names.iter().collect();

        for name in module_names {
            if let Some(module) = self.modules.get(name) {
                for event_type in module.watched_events() {
                    let producers: Vec<String> = self.modules_producing(std::slice::from_ref(event_type));
                    let has_producer = producers.iter().any(|p| available.contains(p));
                    if !has_producer && *event_type != BiosEventType::Root {
                        warnings.push(format!(
                            "Module '{}' watches '{}' but no selected module produces it",
                            name, event_type
                        ));
                    }
                }
            }
        }

        Ok(warnings)
    }
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
