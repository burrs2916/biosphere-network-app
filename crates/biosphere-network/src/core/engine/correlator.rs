use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

use super::event::BiosEventRef;
use super::event_type::EventCategory;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRuleMeta {
    pub name: String,
    pub description: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatchRule {
    pub method: String,
    pub field: String,
    pub value: serde_yaml::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCollection {
    pub collect: Vec<CorrelationMatchRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationAggregation {
    pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationAnalysis {
    pub method: String,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub minimum: Option<usize>,
    #[serde(default)]
    pub maximum: Option<usize>,
    #[serde(default)]
    pub maximum_percent: Option<f64>,
    #[serde(default)]
    pub minimum_percent: Option<f64>,
    #[serde(default)]
    pub noisy_percent: Option<f64>,
    #[serde(default)]
    pub count_unique_only: Option<bool>,
    #[serde(default)]
    pub match_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub version: u32,
    pub meta: CorrelationRuleMeta,
    #[serde(default)]
    pub collections: Vec<CorrelationCollection>,
    #[serde(default)]
    pub aggregation: Option<CorrelationAggregation>,
    #[serde(default)]
    pub analysis: Vec<CorrelationAnalysis>,
    pub headline: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip)]
    pub raw_yaml: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub rule_id: String,
    pub rule_name: String,
    pub rule_risk: String,
    pub headline: String,
    pub matched_events: Vec<BiosEventRef>,
    pub source_events: Vec<BiosEventRef>,
    pub child_events: Vec<BiosEventRef>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct EnrichedEvent {
    event: BiosEventRef,
    source_events: Vec<BiosEventRef>,
    child_events: Vec<BiosEventRef>,
    entity_events: Vec<BiosEventRef>,
    collection_index: usize,
}

struct CompiledMatchRule {
    method: String,
    field: String,
    values: Vec<String>,
    negative_values: Vec<String>,
    compiled_positive_regex: Option<Regex>,
    compiled_negative_regex: Option<Regex>,
}

impl CompiledMatchRule {
    fn from_rule(rule: &CorrelationMatchRule) -> Self {
        let (values, negative_values): (Vec<String>, Vec<String>) = match &rule.value {
            serde_yaml::Value::String(s) => {
                if s.starts_with("not ") {
                    (Vec::new(), vec![s[4..].to_string()])
                } else {
                    (vec![s.clone()], Vec::new())
                }
            }
            serde_yaml::Value::Sequence(seq) => {
                let mut pos = Vec::new();
                let mut neg = Vec::new();
                for v in seq {
                    if let Some(s) = v.as_str() {
                        if s.starts_with("not ") {
                            neg.push(s[4..].to_string());
                        } else {
                            pos.push(s.to_string());
                        }
                    }
                }
                (pos, neg)
            }
            _ => (Vec::new(), Vec::new()),
        };

        let compiled_positive_regex = if rule.method == "regex" && !values.is_empty() {
            let combined = values.join("|");
            Regex::new(&combined).ok()
        } else {
            None
        };

        let compiled_negative_regex = if rule.method == "regex" && !negative_values.is_empty() {
            let combined = negative_values.join("|");
            Regex::new(&combined).ok()
        } else {
            None
        };

        Self {
            method: rule.method.clone(),
            field: rule.field.clone(),
            values,
            negative_values,
            compiled_positive_regex,
            compiled_negative_regex,
        }
    }

    fn matches_enriched(&self, enriched: &EnrichedEvent) -> bool {
        let field_values = get_enriched_field_values(&self.field, enriched);

        let positive_match = if self.values.is_empty() {
            true
        } else {
            self.values.iter().any(|pattern| {
                field_values.iter().any(|v| self.match_single(pattern, Some(v), true))
            })
        };

        let negative_match = self.negative_values.iter().any(|pattern| {
            field_values.iter().any(|v| self.match_single(pattern, Some(v), false))
        });

        positive_match && !negative_match
    }

    fn match_single(&self, pattern: &str, field_value: Option<&str>, is_positive: bool) -> bool {
        let value = field_value.unwrap_or("");
        match self.method.as_str() {
            "exact" => value == pattern,
            "regex" => {
                let regex = if is_positive {
                    &self.compiled_positive_regex
                } else {
                    &self.compiled_negative_regex
                };
                if let Some(ref re) = regex {
                    re.is_match(value)
                } else {
                    Regex::new(pattern)
                        .map(|re| re.is_match(value))
                        .unwrap_or(false)
                }
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RuleScope {
    needs_sources: bool,
    needs_children: bool,
    needs_entities: bool,
}

impl RuleScope {
    fn analyze(rule: &CorrelationRule) -> Self {
        let mut scope = RuleScope::default();

        for collection in &rule.collections {
            for match_rule in &collection.collect {
                if match_rule.field.starts_with("source.") {
                    scope.needs_sources = true;
                }
                if match_rule.field.starts_with("child.") {
                    scope.needs_children = true;
                }
                if match_rule.field.starts_with("entity.") {
                    scope.needs_entities = true;
                }
            }
        }

        if let Some(ref agg) = rule.aggregation {
            if agg.field.starts_with("source.") {
                scope.needs_sources = true;
            }
            if agg.field.starts_with("child.") {
                scope.needs_children = true;
            }
            if agg.field.starts_with("entity.") {
                scope.needs_entities = true;
            }
        }

        for analysis in &rule.analysis {
            if let Some(ref field) = analysis.field {
                if field.starts_with("source.") {
                    scope.needs_sources = true;
                }
                if field.starts_with("child.") {
                    scope.needs_children = true;
                }
                if field.starts_with("entity.") {
                    scope.needs_entities = true;
                }
            }
        }

        if rule.headline.contains("source.") {
            scope.needs_sources = true;
        }
        if rule.headline.contains("child.") {
            scope.needs_children = true;
        }
        if rule.headline.contains("entity.") {
            scope.needs_entities = true;
        }

        scope
    }
}

struct CompiledRule {
    id: String,
    meta: CorrelationRuleMeta,
    compiled_collections: Vec<Vec<CompiledMatchRule>>,
    aggregation: Option<CorrelationAggregation>,
    analysis: Vec<CorrelationAnalysis>,
    headline: String,
    scope: RuleScope,
}

impl CompiledRule {
    fn from_rule(rule: &CorrelationRule) -> Self {
        let compiled_collections = rule.collections.iter().map(|collection| {
            collection.collect.iter().map(CompiledMatchRule::from_rule).collect()
        }).collect();
        let scope = RuleScope::analyze(rule);

        Self {
            id: rule.id.clone(),
            meta: rule.meta.clone(),
            compiled_collections,
            aggregation: rule.aggregation.clone(),
            analysis: rule.analysis.clone(),
            headline: rule.headline.clone(),
            scope,
        }
    }
}

pub struct Correlator {
    rules: Vec<CorrelationRule>,
    compiled_rules: Vec<CompiledRule>,
    needs_recompile: bool,
    pipeline_stats: RefCell<CorrelationPipelineStats>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CorrelationPipelineStats {
    pub total_input_events: usize,
    pub collection_phase_matched: usize,
    pub aggregation_phase_groups: usize,
    pub analysis_phase_passed: usize,
    pub analysis_phase_rejected: usize,
    pub total_results: usize,
}

#[derive(Debug, Clone)]
pub struct CollectionResult {
    pub rule_id: String,
    pub collection_index: usize,
    pub matched_events: Vec<EnrichedEvent>,
}

#[derive(Debug, Clone)]
pub struct AggregationResult {
    pub rule_id: String,
    pub groups: HashMap<String, Vec<EnrichedEvent>>,
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_rules: Vec::new(),
            needs_recompile: false,
            pipeline_stats: RefCell::new(CorrelationPipelineStats::default()),
        }
    }

    pub fn load_rules_from_yaml(&mut self, yaml_content: &str) -> std::result::Result<(), String> {
        let mut rule: CorrelationRule = serde_yaml::from_str(yaml_content)
            .map_err(|e| format!("Failed to parse YAML rule: {}", e))?;
        rule.raw_yaml = Some(yaml_content.to_string());
        self.validate_rule(&rule)?;
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(format!("Rule with ID '{}' already exists", rule.id));
        }
        self.rules.push(rule);
        self.needs_recompile = true;
        Ok(())
    }

    pub fn update_rule(&mut self, rule_id: &str, yaml_content: &str) -> std::result::Result<(), String> {
        let mut new_rule: CorrelationRule = serde_yaml::from_str(yaml_content)
            .map_err(|e| format!("Failed to parse YAML rule: {}", e))?;
        new_rule.raw_yaml = Some(yaml_content.to_string());
        self.validate_rule(&new_rule)?;
        if new_rule.id != rule_id {
            return Err(format!("Rule ID mismatch: expected '{}', got '{}'", rule_id, new_rule.id));
        }
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            self.rules[pos] = new_rule;
            self.needs_recompile = true;
            Ok(())
        } else {
            Err(format!("Rule '{}' not found", rule_id))
        }
    }

    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = enabled;
            self.needs_recompile = true;
            true
        } else {
            false
        }
    }

    pub fn get_rule_yaml(&self, rule_id: &str) -> Option<&str> {
        self.rules.iter()
            .find(|r| r.id == rule_id)
            .and_then(|r| r.raw_yaml.as_deref())
    }

    pub fn load_rules_from_yaml_file(&mut self, path: &str) -> std::result::Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read rule file {}: {}", path, e))?;

        let mut count = 0;
        for doc in content.split("\n---") {
            let doc = doc.trim();
            if doc.is_empty() {
                continue;
            }
            match self.load_rules_from_yaml(doc) {
                Ok(_) => count += 1,
                Err(e) => {
                    return Err(format!("Error in file {} at rule #{}: {}", path, count + 1, e));
                }
            }
        }
        Ok(count)
    }

    pub fn load_rules_from_directory(&mut self, dir_path: &str) -> std::result::Result<usize, String> {
        let dir = std::fs::read_dir(dir_path)
            .map_err(|e| format!("Failed to read directory {}: {}", dir_path, e))?;

        let mut total = 0;
        let mut errors = Vec::new();

        for entry in dir {
            let entry = entry.map_err(|e| format!("Failed to read dir entry: {}", e))?;
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    match self.load_rules_from_yaml_file(path.to_str().unwrap_or("")) {
                        Ok(count) => total += count,
                        Err(e) => errors.push(e),
                    }
                }
            }
        }

        if !errors.is_empty() {
            return Err(format!("Errors loading rules: {}", errors.join("; ")));
        }
        Ok(total)
    }

    pub fn reload_rules_from_yaml_file(&mut self, path: &str) -> std::result::Result<usize, String> {
        let old_rules = self.rules.clone();
        self.rules.clear();
        self.needs_recompile = true;

        match self.load_rules_from_yaml_file(path) {
            Ok(count) => Ok(count),
            Err(e) => {
                self.rules = old_rules;
                self.needs_recompile = true;
                Err(e)
            }
        }
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        if self.rules.len() != before {
            self.needs_recompile = true;
            true
        } else {
            false
        }
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
        self.needs_recompile = true;
    }

    pub fn rules(&self) -> &[CorrelationRule] {
        &self.rules
    }

    fn validate_rule(&self, rule: &CorrelationRule) -> std::result::Result<(), String> {
        if rule.id.is_empty() {
            return Err("Rule has no ID".to_string());
        }
        if rule.id.contains(' ') {
            return Err(format!("Rule ID '{}' contains spaces", rule.id));
        }
        if rule.meta.name.is_empty() {
            return Err(format!("Rule {} has no name", rule.id));
        }
        if rule.meta.description.is_empty() {
            return Err(format!("Rule {} has no description", rule.id));
        }
        if rule.headline.is_empty() {
            return Err(format!("Rule {} has no headline", rule.id));
        }
        if rule.collections.is_empty() {
            return Err(format!("Rule {} has no collections", rule.id));
        }

        let valid_risks = ["info", "low", "medium", "high", "critical"];
        if !valid_risks.contains(&rule.meta.risk.to_lowercase().as_str()) {
            return Err(format!(
                "Rule {} has invalid risk level '{}'. Must be one of: {}",
                rule.id, rule.meta.risk, valid_risks.join(", ")
            ));
        }

        if rule.version == 0 {
            return Err(format!("Rule {} has version 0, must be >= 1", rule.id));
        }

        let valid_fields = [
            "type", "data", "module",
            "source.type", "source.data", "source.module",
            "entity.type", "entity.data", "entity.module",
            "child.type", "child.data", "child.module",
        ];

        for (ci, collection) in rule.collections.iter().enumerate() {
            if collection.collect.is_empty() {
                return Err(format!("Rule {} collection {} has no match rules", rule.id, ci));
            }

            for (mi, match_rule) in collection.collect.iter().enumerate() {
                if !valid_fields.contains(&match_rule.field.as_str()) {
                    return Err(format!(
                        "Rule {} collection {} match {}: invalid field '{}'",
                        rule.id, ci, mi, match_rule.field
                    ));
                }
                if match_rule.method != "exact" && match_rule.method != "regex" {
                    return Err(format!(
                        "Rule {} collection {} match {}: invalid method '{}'",
                        rule.id, ci, mi, match_rule.method
                    ));
                }

                if mi == 0 {
                    if match_rule.field.contains('.') {
                        return Err(format!(
                            "Rule {} collection {} match {}: first match rule field cannot use dot notation (source/child/entity)",
                            rule.id, ci, mi
                        ));
                    }
                    if match_rule.field == "data" && match_rule.method == "regex" {
                        return Err(format!(
                            "Rule {} collection {} match {}: first match rule cannot use regex on data field",
                            rule.id, ci, mi
                        ));
                    }
                    if match_rule.field == "module" && match_rule.method != "exact" {
                        return Err(format!(
                            "Rule {} collection {} match {}: module field only supports exact matching",
                            rule.id, ci, mi
                        ));
                    }
                }

                if let serde_yaml::Value::Sequence(seq) = &match_rule.value {
                    for v in seq {
                        if let Some(s) = v.as_str() {
                            if s.starts_with("not ") && s[4..].trim().is_empty() {
                                return Err(format!(
                                    "Rule {} collection {} match {}: negation pattern 'not ' must be followed by a value",
                                    rule.id, ci, mi
                                ));
                            }
                        }
                    }
                }
            }
        }

        if let Some(ref agg) = rule.aggregation {
            if agg.field.is_empty() {
                return Err(format!("Rule {} aggregation has empty field", rule.id));
            }
        }

        let valid_analysis_methods = [
            "threshold", "outlier",
            "first_collection_only", "match_all_to_first_collection",
        ];
        for (ai, analysis) in rule.analysis.iter().enumerate() {
            if !valid_analysis_methods.contains(&analysis.method.as_str()) {
                return Err(format!(
                    "Rule {} analysis {}: unknown method '{}'",
                    rule.id, ai, analysis.method
                ));
            }

            match analysis.method.as_str() {
                "threshold" => {
                    if analysis.field.is_none() && analysis.count_unique_only.unwrap_or(false) {
                        return Err(format!(
                            "Rule {} analysis {}: count_unique_only requires a field",
                            rule.id, ai
                        ));
                    }
                }
                "outlier" => {
                    if analysis.maximum_percent.is_none() {
                        return Err(format!(
                            "Rule {} analysis {}: outlier method requires maximum_percent",
                            rule.id, ai
                        ));
                    }
                }
                "match_all_to_first_collection" => {
                    if analysis.match_method.is_none() {
                        return Err(format!(
                            "Rule {} analysis {}: match_all_to_first_collection requires match_method (exact/contains/subnet)",
                            rule.id, ai
                        ));
                    }
                    if let Some(ref mm) = analysis.match_method {
                        if !["exact", "contains", "subnet"].contains(&mm.as_str()) {
                            return Err(format!(
                                "Rule {} analysis {}: invalid match_method '{}', must be exact/contains/subnet",
                                rule.id, ai, mm
                            ));
                        }
                    }
                }
                "first_collection_only" => {
                    if rule.collections.len() < 2 {
                        return Err(format!(
                            "Rule {} analysis {}: first_collection_only requires at least 2 collections",
                            rule.id, ai
                        ));
                    }
                }
                _ => {}
            }
        }

        let headline_fields = extract_headline_fields(&rule.headline);
        for hf in &headline_fields {
            if !valid_fields.contains(&hf.as_str()) && hf != "count" && hf != "confidence" && hf != "risk" {
                if !hf.starts_with("unique_count:") {
                    return Err(format!(
                        "Rule {} headline references unknown field '{}'",
                        rule.id, hf
                    ));
                }
            }
        }

        Ok(())
    }

    fn ensure_compiled(&mut self) {
        if self.needs_recompile {
            self.compiled_rules = self.rules.iter()
                .filter(|r| r.enabled)
                .map(CompiledRule::from_rule)
                .collect();
            self.needs_recompile = false;
        }
    }

    pub fn run_correlations(&mut self, events: &[BiosEventRef]) -> Vec<CorrelationResult> {
        self.ensure_compiled();
        {
            let mut stats = self.pipeline_stats.borrow_mut();
            *stats = CorrelationPipelineStats::default();
            stats.total_input_events = events.len();
        }

        let mut results = Vec::new();

        let event_index = build_event_index(events);

        for rule in &self.compiled_rules {
            if let Some(result) = self.process_rule(rule, events, &event_index) {
                results.extend(result);
            }
        }

        self.pipeline_stats.borrow_mut().total_results = results.len();
        results
    }

    pub fn run_pipeline_phases(&mut self, events: &[BiosEventRef]) -> (Vec<CollectionResult>, Vec<AggregationResult>, Vec<CorrelationResult>) {
        self.ensure_compiled();
        {
            let mut stats = self.pipeline_stats.borrow_mut();
            *stats = CorrelationPipelineStats::default();
            stats.total_input_events = events.len();
        }

        let event_index = build_event_index(events);

        let mut all_collections = Vec::new();
        let mut all_aggregations = Vec::new();
        let mut all_results = Vec::new();

        for rule in &self.compiled_rules {
            let (collections, aggregations, results) = self.process_rule_phases(rule, events, &event_index);
            all_collections.extend(collections);
            all_aggregations.extend(aggregations);
            if let Some(r) = results {
                all_results.extend(r);
            }
        }

        self.pipeline_stats.borrow_mut().total_results = all_results.len();
        (all_collections, all_aggregations, all_results)
    }

    fn process_rule_phases(
        &self,
        rule: &CompiledRule,
        events: &[BiosEventRef],
        event_index: &HashMap<String, usize>,
    ) -> (Vec<CollectionResult>, Vec<AggregationResult>, Option<Vec<CorrelationResult>>) {
        let mut collection_results = Vec::new();
        let mut all_enriched: Vec<EnrichedEvent> = Vec::new();

        for (ci, collection_matchers) in rule.compiled_collections.iter().enumerate() {
            let mut enriched = enrich_events(events, event_index, ci, &rule.scope);

            for matcher in collection_matchers {
                enriched = enriched
                    .into_iter()
                    .filter(|e| matcher.matches_enriched(e))
                    .collect();
            }

            self.pipeline_stats.borrow_mut().collection_phase_matched += enriched.len();
            collection_results.push(CollectionResult {
                rule_id: rule.id.clone(),
                collection_index: ci,
                matched_events: enriched.clone(),
            });

            all_enriched.extend(enriched);
        }

        if all_enriched.is_empty() {
            return (collection_results, Vec::new(), None);
        }

        let (groups, aggregation_results) = if let Some(agg) = &rule.aggregation {
            let groups = aggregate_enriched(&agg.field, &all_enriched);
            self.pipeline_stats.borrow_mut().aggregation_phase_groups += groups.len();
            let agg_result = AggregationResult {
                rule_id: rule.id.clone(),
                groups: groups.clone(),
            };
            (groups, vec![agg_result])
        } else {
            let mut map = HashMap::new();
            map.insert("__all__".to_string(), all_enriched);
            self.pipeline_stats.borrow_mut().aggregation_phase_groups += 1;
            (map, vec![AggregationResult {
                rule_id: rule.id.clone(),
                groups: HashMap::new(),
            }])
        };

        let total_events_count = events.len();
        let mut final_results = Vec::new();

        for (key, group_events) in &groups {
            let mut filtered_events = group_events.clone();
            let mut passes_analysis = true;

            for analysis in &rule.analysis {
                match apply_analysis_enriched(analysis, &filtered_events, total_events_count, key) {
                    AnalysisResult::Pass => {}
                    AnalysisResult::Fail => {
                        passes_analysis = false;
                        break;
                    }
                    AnalysisResult::Filtered(events) => {
                        filtered_events = events;
                    }
                }
            }

            if passes_analysis && !filtered_events.is_empty() {
                self.pipeline_stats.borrow_mut().analysis_phase_passed += 1;
                let headline = render_headline(&rule.headline, &filtered_events, key);

                final_results.push(CorrelationResult {
                    rule_id: rule.id.clone(),
                    rule_name: rule.meta.name.clone(),
                    rule_risk: rule.meta.risk.clone(),
                    headline,
                    matched_events: filtered_events.iter().map(|e| e.event.clone()).collect(),
                    source_events: filtered_events.iter()
                        .flat_map(|e| e.source_events.iter().cloned())
                        .collect(),
                    child_events: filtered_events.iter()
                        .flat_map(|e| e.child_events.iter().cloned())
                        .collect(),
                    description: rule.meta.description.clone(),
                });
            } else {
                self.pipeline_stats.borrow_mut().analysis_phase_rejected += 1;
            }
        }

        let result = if final_results.is_empty() {
            None
        } else {
            Some(final_results)
        };

        (collection_results, aggregation_results, result)
    }

    pub fn pipeline_stats(&self) -> CorrelationPipelineStats {
        self.pipeline_stats.borrow().clone()
    }

    pub fn reset_pipeline_stats(&self) {
        *self.pipeline_stats.borrow_mut() = CorrelationPipelineStats::default();
    }

    fn process_rule(&self, rule: &CompiledRule, events: &[BiosEventRef], event_index: &HashMap<String, usize>) -> Option<Vec<CorrelationResult>> {
        let mut all_enriched: Vec<EnrichedEvent> = Vec::new();

        for (ci, collection_matchers) in rule.compiled_collections.iter().enumerate() {
            let mut enriched = enrich_events(events, event_index, ci, &rule.scope);

            for matcher in collection_matchers {
                enriched = enriched
                    .into_iter()
                    .filter(|e| matcher.matches_enriched(e))
                    .collect();
            }

            all_enriched.extend(enriched);
        }

        if all_enriched.is_empty() {
            return None;
        }

        let grouped = if let Some(agg) = &rule.aggregation {
            aggregate_enriched(&agg.field, &all_enriched)
        } else {
            let mut map = HashMap::new();
            map.insert("__all__".to_string(), all_enriched);
            map
        };

        let total_events_count = events.len();
        let mut final_results = Vec::new();

        for (key, group_events) in grouped {
            let mut filtered_events = group_events.clone();
            let mut passes_analysis = true;

            for analysis in &rule.analysis {
                match apply_analysis_enriched(analysis, &filtered_events, total_events_count, &key) {
                    AnalysisResult::Pass => {}
                    AnalysisResult::Fail => {
                        passes_analysis = false;
                        break;
                    }
                    AnalysisResult::Filtered(events) => {
                        filtered_events = events;
                    }
                }
            }

            if passes_analysis && !filtered_events.is_empty() {
                let headline = render_headline(&rule.headline, &filtered_events, &key);

                final_results.push(CorrelationResult {
                    rule_id: rule.id.clone(),
                    rule_name: rule.meta.name.clone(),
                    rule_risk: rule.meta.risk.clone(),
                    headline,
                    matched_events: filtered_events.iter().map(|e| e.event.clone()).collect(),
                    source_events: filtered_events.iter()
                        .flat_map(|e| e.source_events.iter().cloned())
                        .collect(),
                    child_events: filtered_events.iter()
                        .flat_map(|e| e.child_events.iter().cloned())
                        .collect(),
                    description: rule.meta.description.clone(),
                });
            }
        }

        if final_results.is_empty() {
            None
        } else {
            Some(final_results)
        }
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

fn build_event_index(events: &[BiosEventRef]) -> HashMap<String, usize> {
    events.iter().enumerate().map(|(i, e)| (e.hash.clone(), i)).collect()
}

fn enrich_events(events: &[BiosEventRef], event_index: &HashMap<String, usize>, collection_index: usize, scope: &RuleScope) -> Vec<EnrichedEvent> {
    events.iter().map(|event| {
        let source_events = if scope.needs_sources {
            find_source_events(event, events, event_index)
        } else {
            Vec::new()
        };
        let child_events = if scope.needs_children {
            find_child_events(event, events)
        } else {
            Vec::new()
        };
        let entity_events = if scope.needs_entities {
            find_entity_events(event, events, event_index)
        } else {
            Vec::new()
        };

        EnrichedEvent {
            event: event.clone(),
            source_events,
            child_events,
            entity_events,
            collection_index,
        }
    }).collect()
}

fn find_source_events(event: &BiosEventRef, events: &[BiosEventRef], event_index: &HashMap<String, usize>) -> Vec<BiosEventRef> {
    let mut sources = Vec::new();
    let mut current_hash = event.source_event_hash.clone();
    let mut visited = std::collections::HashSet::new();
    let max_depth = 50;

    for _ in 0..max_depth {
        let hash = match current_hash {
            Some(ref h) if h != "ROOT" => h.clone(),
            _ => break,
        };
        if visited.contains(&hash) {
            break;
        }
        visited.insert(hash.clone());

        if let Some(&idx) = event_index.get(&hash) {
            let parent = &events[idx];
            sources.push(parent.clone());
            current_hash = parent.source_event_hash.clone();
        } else {
            break;
        }
    }

    sources
}

fn find_child_events(event: &BiosEventRef, events: &[BiosEventRef]) -> Vec<BiosEventRef> {
    events.iter()
        .filter(|e| e.source_event_hash.as_deref() == Some(&event.hash))
        .cloned()
        .collect()
}

fn find_entity_events(event: &BiosEventRef, events: &[BiosEventRef], event_index: &HashMap<String, usize>) -> Vec<BiosEventRef> {
    if event.event_type.category() == EventCategory::Entity || event.event_type.category() == EventCategory::Internal {
        return vec![event.clone()];
    }

    let mut current_hash = event.source_event_hash.clone();
    let mut visited = std::collections::HashSet::new();
    let max_depth = 50;

    for _ in 0..max_depth {
        let hash = match current_hash {
            Some(ref h) if h != "ROOT" => h.clone(),
            _ => break,
        };
        if visited.contains(&hash) {
            break;
        }
        visited.insert(hash.clone());

        if let Some(&idx) = event_index.get(&hash) {
            let parent = &events[idx];
            if parent.event_type.category() == EventCategory::Entity || parent.event_type.category() == EventCategory::Internal {
                return vec![parent.clone()];
            }
            current_hash = parent.source_event_hash.clone();
        } else {
            break;
        }
    }

    Vec::new()
}

fn get_enriched_field_values(field: &str, enriched: &EnrichedEvent) -> Vec<String> {
    if field.contains('.') {
        let parts: Vec<&str> = field.splitn(2, '.').collect();
        if parts.len() != 2 {
            return vec![enriched.event.data.clone()];
        }
        let prefix = parts[0];
        let sub_field = parts[1];

        let target_events = match prefix {
            "source" => &enriched.source_events,
            "child" => &enriched.child_events,
            "entity" => &enriched.entity_events,
            _ => return vec![],
        };

        target_events.iter().filter_map(|e| {
            match sub_field {
                "type" => Some(e.event_type.as_str().to_string()),
                "data" => Some(e.data.clone()),
                "module" => Some(e.module.clone()),
                _ => None,
            }
        }).collect()
    } else {
        match field {
            "type" => vec![enriched.event.event_type.as_str().to_string()],
            "data" => vec![enriched.event.data.clone()],
            "module" => vec![enriched.event.module.clone()],
            _ => vec![],
        }
    }
}

fn aggregate_enriched(field: &str, events: &[EnrichedEvent]) -> HashMap<String, Vec<EnrichedEvent>> {
    let mut groups: HashMap<String, Vec<EnrichedEvent>> = HashMap::new();

    for event in events {
        let keys = get_enriched_field_values(field, event);
        let key = keys.into_iter().next().unwrap_or_else(|| "unknown".to_string());
        groups.entry(key).or_default().push(event.clone());
    }

    groups
}

fn render_headline(template: &str, group_events: &[EnrichedEvent], agg_key: &str) -> String {
    let mut result = template.to_string();

    result = result.replace("{data}", agg_key);
    result = result.replace("{count}", &group_events.len().to_string());

    if let Some(first) = group_events.first() {
        result = result.replace("{type}", first.event.event_type.as_str());
        result = result.replace("{module}", &first.event.module);

        if !first.source_events.is_empty() {
            if let Some(src) = first.source_events.first() {
                result = result.replace("{source.data}", &src.data);
                result = result.replace("{source.type}", src.event_type.as_str());
                result = result.replace("{source.module}", &src.module);
            }
        }

        if !first.entity_events.is_empty() {
            if let Some(entity) = first.entity_events.first() {
                result = result.replace("{entity.data}", &entity.data);
                result = result.replace("{entity.type}", entity.event_type.as_str());
                result = result.replace("{entity.module}", &entity.module);
            }
        }

        result = result.replace("{confidence}", &first.event.confidence.to_string());
        result = result.replace("{risk}", &first.event.risk.to_string());
    }

    let re = Regex::new(r"\{unique_count:([^}]+)\}").unwrap();
    if let Some(captures) = re.captures(&template) {
        if let Some(field_match) = captures.get(1) {
            let field: &str = field_match.as_str();
            let unique_values: std::collections::HashSet<String> = group_events.iter()
                .flat_map(|e| get_enriched_field_values(field, e))
                .collect();
            result = re.replace_all(&result, &unique_values.len().to_string()).to_string();
        }
    }

    result
}

enum AnalysisResult {
    Pass,
    Fail,
    Filtered(Vec<EnrichedEvent>),
}

fn apply_analysis_enriched(analysis: &CorrelationAnalysis, events: &[EnrichedEvent], total_events_count: usize, _key: &str) -> AnalysisResult {
    match analysis.method.as_str() {
        "threshold" => {
            let count = if analysis.count_unique_only.unwrap_or(false) {
                if let Some(field) = &analysis.field {
                    let unique: std::collections::HashSet<String> = events
                        .iter()
                        .flat_map(|e| get_enriched_field_values(field, e))
                        .collect();
                    unique.len()
                } else {
                    events.len()
                }
            } else {
                events.len()
            };

            if let Some(min) = analysis.minimum {
                if count < min {
                    return AnalysisResult::Fail;
                }
            }
            if let Some(max) = analysis.maximum {
                if count > max {
                    return AnalysisResult::Fail;
                }
            }
            AnalysisResult::Pass
        }
        "outlier" => {
            let max_pct = analysis.maximum_percent.unwrap_or(10.0);
            let noisy_pct = analysis.noisy_percent.unwrap_or(10.0);
            if total_events_count == 0 {
                return AnalysisResult::Pass;
            }
            let total: f64 = total_events_count as f64;
            let bucket_count = events.len() as f64;
            let avg_pct = if total > 0.0 {
                let num_buckets = (total / bucket_count.max(1.0)).max(1.0);
                (bucket_count / total) * 100.0 * num_buckets
            } else {
                0.0
            };

            if avg_pct < noisy_pct {
                return AnalysisResult::Fail;
            }

            let pct = (bucket_count / total) * 100.0;
            if pct <= max_pct {
                AnalysisResult::Pass
            } else {
                AnalysisResult::Fail
            }
        }
        "first_collection_only" => {
            let col0_keys: std::collections::HashSet<String> = events.iter()
                .filter(|e| e.collection_index == 0)
                .flat_map(|e| {
                    if let Some(ref field) = analysis.field {
                        get_enriched_field_values(field, e)
                    } else {
                        vec![e.event.data.clone()]
                    }
                })
                .collect();

            if col0_keys.is_empty() {
                return AnalysisResult::Fail;
            }

            let filtered: Vec<EnrichedEvent> = events.iter()
                .filter(|e| {
                    if e.collection_index == 0 {
                        return true;
                    }
                    if let Some(ref field) = analysis.field {
                        let vals = get_enriched_field_values(field, e);
                        vals.iter().any(|v| col0_keys.contains(v))
                    } else {
                        col0_keys.contains(&e.event.data)
                    }
                })
                .cloned()
                .collect();

            if filtered.iter().any(|e| e.collection_index != 0) {
                AnalysisResult::Filtered(filtered)
            } else if filtered.is_empty() {
                AnalysisResult::Fail
            } else {
                AnalysisResult::Pass
            }
        }
        "match_all_to_first_collection" => {
            let reference: std::collections::HashSet<String> = events.iter()
                .filter(|e| e.collection_index == 0)
                .flat_map(|e| {
                    if let Some(ref field) = analysis.field {
                        get_enriched_field_values(field, e)
                    } else {
                        vec![e.event.data.clone()]
                    }
                })
                .collect();

            if reference.is_empty() {
                return AnalysisResult::Fail;
            }

            let match_method = analysis.match_method.as_deref().unwrap_or("exact");

            let filtered: Vec<EnrichedEvent> = events.iter()
                .filter(|e| {
                    if e.collection_index == 0 {
                        return true;
                    }
                    let vals = if let Some(ref field) = analysis.field {
                        get_enriched_field_values(field, e)
                    } else {
                        vec![e.event.data.clone()]
                    };
                    vals.iter().any(|v| {
                        match match_method {
                            "exact" => reference.contains(v),
                            "contains" => reference.iter().any(|r| r.contains(v.as_str())),
                            _ => reference.contains(v),
                        }
                    })
                })
                .cloned()
                .collect();

            if filtered.iter().any(|e| e.collection_index != 0) {
                AnalysisResult::Filtered(filtered)
            } else if filtered.is_empty() {
                AnalysisResult::Fail
            } else {
                AnalysisResult::Pass
            }
        }
        "subnet" => {
            let cidr_prefix = analysis.match_method.as_deref()
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(24);

            let subnets: std::collections::HashSet<String> = events.iter()
                .flat_map(|e| {
                    let data = if let Some(ref field) = analysis.field {
                        get_enriched_field_values(field, e)
                    } else {
                        vec![e.event.data.clone()]
                    };
                    data.into_iter().filter_map(|d| {
                        let ip_str = d.split(':').next().unwrap_or(&d).trim();
                        ip_str.parse::<std::net::IpAddr>().ok().map(|ip| {
                            match ip {
                                std::net::IpAddr::V4(v4) => {
                                    let mask: u32 = if cidr_prefix >= 32 { u32::MAX } else { !0u32 << (32 - cidr_prefix) };
                                    let network = u32::from(v4) & mask;
                                    std::net::Ipv4Addr::from(network).to_string()
                                }
                                std::net::IpAddr::V6(v6) => {
                                    format!("{}/{}", v6, cidr_prefix)
                                }
                            }
                        })
                    }).collect::<Vec<_>>()
                })
                .collect();

            if subnets.len() > 1 {
                AnalysisResult::Pass
            } else {
                AnalysisResult::Fail
            }
        }
        "frequency" => {
            let min_pct = analysis.minimum_percent.unwrap_or(1.0);
            let max_pct = analysis.maximum_percent.unwrap_or(100.0);
            if total_events_count == 0 {
                return AnalysisResult::Fail;
            }
            let pct = (events.len() as f64 / total_events_count as f64) * 100.0;
            if pct >= min_pct && pct <= max_pct {
                AnalysisResult::Pass
            } else {
                AnalysisResult::Fail
            }
        }
        _ => AnalysisResult::Pass,
    }
}

fn extract_headline_fields(headline: &str) -> Vec<String> {
    let re = Regex::new(r"\{([a-zA-Z_.:]+)\}").unwrap();
    re.captures_iter(headline)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

pub fn default_correlation_rules() -> Vec<CorrelationRule> {
    let mut rules = Vec::new();

    rules.push(CorrelationRule {
        id: "multiple_malicious".to_string(),
        version: 1,
        meta: CorrelationRuleMeta {
            name: "Entity considered malicious by multiple sources".to_string(),
            description: "An IP, host or email was considered malicious by multiple sources.".to_string(),
            risk: "HIGH".to_string(),
        },
        collections: vec![CorrelationCollection {
            collect: vec![
                CorrelationMatchRule {
                    method: "regex".to_string(),
                    field: "type".to_string(),
                    value: serde_yaml::Value::Sequence(vec![
                        serde_yaml::Value::String("MALICIOUS_*".to_string()),
                        serde_yaml::Value::String("BLACKLISTED_*".to_string()),
                    ]),
                },
            ],
        }],
        aggregation: Some(CorrelationAggregation {
            field: "data".to_string(),
        }),
        analysis: vec![CorrelationAnalysis {
            method: "threshold".to_string(),
            field: Some("data".to_string()),
            minimum: Some(2),
            maximum: None,
            maximum_percent: None,
            minimum_percent: None,
            noisy_percent: None,
            count_unique_only: Some(false),
            match_method: None,
        }],
        headline: "Entity considered malicious by multiple sources: {data}".to_string(),
        enabled: true,
        raw_yaml: None,
    });

    rules.push(CorrelationRule {
        id: "vulnerability_critical".to_string(),
        version: 1,
        meta: CorrelationRuleMeta {
            name: "At least one CRITICAL-rated vulnerability was found".to_string(),
            description: "A vulnerability rated as CRITICAL was found on a host.".to_string(),
            risk: "HIGH".to_string(),
        },
        collections: vec![CorrelationCollection {
            collect: vec![CorrelationMatchRule {
                method: "exact".to_string(),
                field: "type".to_string(),
                value: serde_yaml::Value::String("VULNERABILITY_CVE_CRITICAL".to_string()),
            }],
        }],
        aggregation: Some(CorrelationAggregation {
            field: "data".to_string(),
        }),
        analysis: vec![],
        headline: "Critical-rated vulnerability found on {data}".to_string(),
        enabled: true,
        raw_yaml: None,
    });

    rules.push(CorrelationRule {
        id: "database_exposed".to_string(),
        version: 1,
        meta: CorrelationRuleMeta {
            name: "Database exposed on the Internet".to_string(),
            description: "A database service appears to be exposed on the Internet.".to_string(),
            risk: "HIGH".to_string(),
        },
        collections: vec![CorrelationCollection {
            collect: vec![CorrelationMatchRule {
                method: "exact".to_string(),
                field: "type".to_string(),
                value: serde_yaml::Value::String("DATABASE_EXPOSED".to_string()),
            }],
        }],
        aggregation: Some(CorrelationAggregation {
            field: "data".to_string(),
        }),
        analysis: vec![],
        headline: "Database exposed: {data}".to_string(),
        enabled: true,
        raw_yaml: None,
    });

    rules.push(CorrelationRule {
        id: "outlier_country".to_string(),
        version: 1,
        meta: CorrelationRuleMeta {
            name: "Outlier country".to_string(),
            description: "A country that appeared in 10% or less of the total countries found.".to_string(),
            risk: "INFO".to_string(),
        },
        collections: vec![CorrelationCollection {
            collect: vec![CorrelationMatchRule {
                method: "exact".to_string(),
                field: "type".to_string(),
                value: serde_yaml::Value::String("COUNTRY_NAME".to_string()),
            }],
        }],
        aggregation: Some(CorrelationAggregation {
            field: "data".to_string(),
        }),
        analysis: vec![CorrelationAnalysis {
            method: "outlier".to_string(),
            field: None,
            minimum: None,
            maximum: None,
            maximum_percent: Some(10.0),
            minimum_percent: None,
            noisy_percent: Some(10.0),
            count_unique_only: None,
            match_method: None,
        }],
        headline: "Outlier country found: {data}".to_string(),
        enabled: true,
        raw_yaml: None,
    });

    rules.push(CorrelationRule {
        id: "remote_desktop_exposed".to_string(),
        version: 1,
        meta: CorrelationRuleMeta {
            name: "Remote desktop service exposed".to_string(),
            description: "A remote desktop service appears to be exposed on the Internet.".to_string(),
            risk: "HIGH".to_string(),
        },
        collections: vec![CorrelationCollection {
            collect: vec![CorrelationMatchRule {
                method: "exact".to_string(),
                field: "type".to_string(),
                value: serde_yaml::Value::String("REMOTE_DESKTOP_EXPOSED".to_string()),
            }],
        }],
        aggregation: Some(CorrelationAggregation {
            field: "data".to_string(),
        }),
        analysis: vec![],
        headline: "Remote desktop exposed: {data}".to_string(),
        enabled: true,
        raw_yaml: None,
    });

    rules.push(CorrelationRule {
        id: "cloud_bucket_open".to_string(),
        version: 1,
        meta: CorrelationRuleMeta {
            name: "Cloud storage bucket is open".to_string(),
            description: "A cloud storage bucket was found to be publicly accessible.".to_string(),
            risk: "MEDIUM".to_string(),
        },
        collections: vec![CorrelationCollection {
            collect: vec![CorrelationMatchRule {
                method: "exact".to_string(),
                field: "type".to_string(),
                value: serde_yaml::Value::String("CLOUD_STORAGE_BUCKET_OPEN".to_string()),
            }],
        }],
        aggregation: Some(CorrelationAggregation {
            field: "data".to_string(),
        }),
        analysis: vec![],
        headline: "Open cloud storage bucket: {data}".to_string(),
        enabled: true,
        raw_yaml: None,
    });

    rules
}
