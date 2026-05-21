use rusqlite::{Connection, Result as SqliteResult, params};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};
use regex::Regex;

use crate::core::engine::event::BiosEventRef;
use crate::core::engine::event_type::BiosEventType;
use crate::core::engine::correlator::CorrelationResult;

pub fn truncate_to_byte_limit(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s[..boundary].to_string()
}

pub struct EngineDatabase {
    conn: Arc<RwLock<Connection>>,
}

unsafe impl Send for EngineDatabase {}
unsafe impl Sync for EngineDatabase {}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DuplicateEventEntry {
    pub event_type: String,
    pub data: String,
    pub module_a: String,
    pub hash_a: String,
    pub source_hash_a: Option<String>,
    pub module_b: String,
    pub hash_b: String,
}

#[derive(Debug, Clone, Default)]
pub struct EventSearchQuery {
    pub scan_id: String,
    pub event_types: Vec<String>,
    pub module_filter: Option<String>,
    pub data_pattern: Option<String>,
    pub min_confidence: Option<i32>,
    pub min_risk: Option<i32>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PaginatedResult {
    pub events: Vec<BiosEventRef>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone)]
pub struct ModuleStateEntry {
    pub status: String,
    pub error_count: i32,
    pub last_error_message: Option<String>,
    pub last_error_time: Option<i64>,
    pub disabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypedConfigValue {
    pub val: String,
    pub val_type: String,
}

impl TypedConfigValue {
    pub fn as_str(&self) -> &str {
        &self.val
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self.val_type.as_str() {
            "bool" => Some(self.val != "0" && self.val.to_lowercase() != "false"),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self.val_type.as_str() {
            "int" => self.val.parse().ok(),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<Vec<String>> {
        match self.val_type.as_str() {
            "list" => Some(self.val.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
            _ => None,
        }
    }
}

impl EngineDatabase {
    pub fn new<P: AsRef<Path>>(path: P) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            #[allow(clippy::arc_with_non_send_sync)]
            conn: Arc::new(RwLock::new(conn)),
        };
        db.initialize()?;
        Ok(db)
    }

    pub fn in_memory() -> SqliteResult<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            #[allow(clippy::arc_with_non_send_sync)]
            conn: Arc::new(RwLock::new(conn)),
        };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();

        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA wal_autocheckpoint=1000;
             PRAGMA cache_size=-64000;
             PRAGMA temp_store=MEMORY;
             PRAGMA mmap_size=268435456;
             PRAGMA busy_timeout=5000;"
        )?;

        conn.create_scalar_function(
            "regexp",
            2,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8 | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                let pattern = ctx.get::<String>(0)?;
                let text = ctx.get::<String>(1)?;
                let re = Regex::new(&pattern).map_err(|e| {
                    rusqlite::Error::UserFunctionError(e.into())
                })?;
                Ok(re.is_match(&text))
            },
        )?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS engine_event_types (
                event       VARCHAR NOT NULL PRIMARY KEY,
                event_descr VARCHAR NOT NULL,
                event_raw   INT NOT NULL DEFAULT 0,
                event_type  VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS engine_scans (
                scan_id TEXT PRIMARY KEY,
                target_value TEXT NOT NULL,
                target_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'not_started',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS engine_scan_config (
                scan_id TEXT NOT NULL,
                component TEXT NOT NULL,
                opt TEXT NOT NULL,
                val TEXT NOT NULL,
                val_type TEXT NOT NULL DEFAULT 'str',
                PRIMARY KEY (scan_id, component, opt),
                FOREIGN KEY (scan_id) REFERENCES engine_scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS engine_scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                generated INTEGER NOT NULL,
                component TEXT NOT NULL,
                classification TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES engine_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_engine_scan_log_scan_id ON engine_scan_log(scan_id);

            CREATE TABLE IF NOT EXISTS engine_module_state (
                scan_id TEXT NOT NULL,
                module_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'idle',
                error_count INTEGER NOT NULL DEFAULT 0,
                last_error_message TEXT,
                last_error_time INTEGER,
                disabled INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (scan_id, module_name),
                FOREIGN KEY (scan_id) REFERENCES engine_scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS engine_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data TEXT NOT NULL,
                module TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE,
                source_event_hash TEXT,
                source_event_type TEXT,
                source_event_data TEXT,
                confidence INTEGER NOT NULL DEFAULT 100,
                visibility INTEGER NOT NULL DEFAULT 100,
                risk INTEGER NOT NULL DEFAULT 0,
                false_positive INTEGER NOT NULL DEFAULT 0,
                store_only INTEGER NOT NULL DEFAULT 0,
                generated INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES engine_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_engine_events_scan_id ON engine_events(scan_id);
            CREATE INDEX IF NOT EXISTS idx_engine_events_type ON engine_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_engine_events_hash ON engine_events(hash);
            CREATE INDEX IF NOT EXISTS idx_engine_events_source_hash ON engine_events(scan_id, source_event_hash);

            CREATE TABLE IF NOT EXISTS engine_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                rule_risk TEXT NOT NULL,
                headline TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES engine_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_engine_correlations_scan_id ON engine_correlations(scan_id);

            CREATE TABLE IF NOT EXISTS engine_correlation_events (
                correlation_id INTEGER NOT NULL,
                event_hash TEXT NOT NULL,
                FOREIGN KEY (correlation_id) REFERENCES engine_correlations(id),
                FOREIGN KEY (event_hash) REFERENCES engine_events(hash)
            );

            CREATE INDEX IF NOT EXISTS idx_engine_correlation_events_corr ON engine_correlation_events(correlation_id);

            CREATE TABLE IF NOT EXISTS engine_target_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                alias_type TEXT NOT NULL,
                alias_value TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES engine_scans(scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_engine_target_aliases_scan_id ON engine_target_aliases(scan_id);

            CREATE TABLE IF NOT EXISTS engine_cache (
                label TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_engine_cache_expires ON engine_cache(expires_at);"
        )?;

        Ok(())
    }

    pub fn create_scan(&self, scan_id: &str, target_value: &str, target_type: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT OR REPLACE INTO engine_scans (scan_id, target_value, target_type, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![scan_id, target_value, target_type, "running", now, now],
        )?;
        Ok(())
    }

    pub fn update_scan_status(&self, scan_id: &str, status: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE engine_scans SET status = ?1, updated_at = ?2 WHERE scan_id = ?3",
            params![status, now, scan_id],
        )?;
        Ok(())
    }

    pub fn get_scan_status(&self, scan_id: &str) -> SqliteResult<Option<String>> {
        let conn = self.conn.read().unwrap();
        let result = conn.query_row(
            "SELECT status FROM engine_scans WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(status) => Ok(Some(status)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn is_scan_abort_requested(&self, scan_id: &str) -> bool {
        match self.get_scan_status(scan_id) {
            Ok(Some(status)) => status == "abort_requested" || status == "aborting",
            _ => false,
        }
    }

    pub fn event_exists(&self, scan_id: &str, hash: &str) -> SqliteResult<bool> {
        let conn = self.conn.read().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_events WHERE scan_id = ?1 AND hash = ?2",
            params![scan_id, hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn get_duplicate_events(&self, scan_id: &str) -> SqliteResult<Vec<DuplicateEventEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT e1.event_type, e1.data, e1.module, e1.hash, e1.source_event_hash, \
             e2.module AS other_module, e2.hash AS other_hash \
             FROM engine_events e1 \
             JOIN engine_events e2 ON e1.scan_id = e2.scan_id \
             AND e1.data = e2.data AND e1.event_type = e2.event_type \
             AND e1.hash < e2.hash \
             WHERE e1.scan_id = ?1 \
             ORDER BY e1.data, e1.event_type"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok(DuplicateEventEntry {
                event_type: row.get(0)?,
                data: row.get(1)?,
                module_a: row.get(2)?,
                hash_a: row.get(3)?,
                source_hash_a: row.get(4)?,
                module_b: row.get(5)?,
                hash_b: row.get(6)?,
            })
        })?;
        results.collect()
    }

    pub fn store_event(&self, event: &BiosEventRef, scan_id: &str) -> SqliteResult<()> {
        self.store_event_with_truncate(event, scan_id, None)
    }

    pub fn store_event_with_truncate(&self, event: &BiosEventRef, scan_id: &str, max_data_size: Option<usize>) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let source_event_type = event.source_event_type.as_ref().map(|t| t.as_str());
        let data = match max_data_size {
            Some(size) => truncate_to_byte_limit(&event.data, size),
            None => event.data.clone(),
        };
        let source_data = match max_data_size {
            Some(size) => event.source_event_data.as_ref().map(|d| truncate_to_byte_limit(d, size)),
            None => event.source_event_data.clone(),
        };
        conn.execute(
            "INSERT OR IGNORE INTO engine_events (scan_id, event_type, data, module, hash, source_event_hash, source_event_type, source_event_data, confidence, visibility, risk, store_only, generated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                scan_id,
                event.event_type.as_str(),
                data,
                event.module,
                event.hash,
                event.source_event_hash,
                source_event_type,
                source_data,
                event.confidence,
                event.visibility,
                event.risk,
                event.store_only as i32,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn store_events(&self, events: &[BiosEventRef], scan_id: &str) -> SqliteResult<()> {
        for event in events {
            self.store_event(event, scan_id)?;
        }
        Ok(())
    }

    pub fn store_events_batch(&self, events: &[BiosEventRef], scan_id: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;
        let now = chrono::Utc::now().timestamp_millis();
        for event in events {
            let source_event_type = event.source_event_type.as_ref().map(|t| t.as_str());
            let result = tx.execute(
                "INSERT OR IGNORE INTO engine_events (scan_id, event_type, data, module, hash, source_event_hash, source_event_type, source_event_data, confidence, visibility, risk, store_only, generated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    scan_id,
                    event.event_type.as_str(),
                    event.data,
                    event.module,
                    event.hash,
                    event.source_event_hash,
                    source_event_type,
                    event.source_event_data,
                    event.confidence,
                    event.visibility,
                    event.risk,
                    event.store_only as i32,
                    now,
                ],
            );
            if let Err(e) = result {
                tx.rollback()?;
                return Err(e);
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_events_by_scan(&self, scan_id: &str) -> SqliteResult<Vec<BiosEventRef>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, data, module, hash, confidence, visibility, risk, source_event_hash, source_event_type, source_event_data, store_only FROM engine_events WHERE scan_id = ?1 ORDER BY generated ASC"
        )?;

        let events = stmt.query_map(params![scan_id], |row| {
            let event_type_str: String = row.get(0)?;
            let event_type = BiosEventType::from_str(&event_type_str)
                .unwrap_or(BiosEventType::Custom(event_type_str));
            let source_event_type_str: Option<String> = row.get(8)?;
            let source_event_type = source_event_type_str
                .as_deref()
                .and_then(BiosEventType::from_str);
            let store_only: i32 = row.get(10).unwrap_or(0);
            Ok(BiosEventRef {
                event_type,
                data: row.get(1)?,
                module: row.get(2)?,
                hash: row.get(3)?,
                confidence: row.get(4)?,
                visibility: row.get(5)?,
                risk: row.get(6)?,
                source_event_hash: row.get(7)?,
                source_event_type,
                source_event_data: row.get(9)?,
                store_only: store_only != 0,
            })
        })?;

        events.collect()
    }

    pub fn get_events_by_type(&self, scan_id: &str, event_type: &BiosEventType) -> SqliteResult<Vec<BiosEventRef>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, data, module, hash, confidence, visibility, risk, source_event_hash, source_event_type, source_event_data, store_only FROM engine_events WHERE scan_id = ?1 AND event_type = ?2 ORDER BY generated ASC"
        )?;

        let events = stmt.query_map(params![scan_id, event_type.as_str()], |row| {
            let event_type_str: String = row.get(0)?;
            let et = BiosEventType::from_str(&event_type_str)
                .unwrap_or(BiosEventType::Custom(event_type_str));
            let source_event_type_str: Option<String> = row.get(8)?;
            let source_event_type = source_event_type_str
                .as_deref()
                .and_then(BiosEventType::from_str);
            let store_only: i32 = row.get(10).unwrap_or(0);
            Ok(BiosEventRef {
                event_type: et,
                data: row.get(1)?,
                module: row.get(2)?,
                hash: row.get(3)?,
                confidence: row.get(4)?,
                visibility: row.get(5)?,
                risk: row.get(6)?,
                source_event_hash: row.get(7)?,
                source_event_type,
                source_event_data: row.get(9)?,
                store_only: store_only != 0,
            })
        })?;

        events.collect()
    }

    pub fn get_event_count(&self, scan_id: &str) -> SqliteResult<usize> {
        let conn = self.conn.read().unwrap();
        let count: usize = conn.query_row(
            "SELECT COUNT(*) FROM engine_events WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn get_event_type_counts(&self, scan_id: &str) -> SqliteResult<Vec<(String, usize)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) as cnt FROM engine_events WHERE scan_id = ?1 GROUP BY event_type ORDER BY cnt DESC"
        )?;

        let counts = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
        })?;

        counts.collect()
    }

    pub fn get_event_summary_by_module(&self, scan_id: &str) -> SqliteResult<Vec<(String, usize, usize)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT module, COUNT(*) as total, COUNT(DISTINCT data) as unique_count \
             FROM engine_events WHERE scan_id = ?1 \
             GROUP BY module ORDER BY total DESC"
        )?;

        let results = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?, row.get::<_, usize>(2)?))
        })?;

        results.collect()
    }

    pub fn get_event_summary_by_entity(&self, scan_id: &str, limit: Option<usize>) -> SqliteResult<Vec<(String, String, usize, usize)>> {
        let conn = self.conn.read().unwrap();
        let limit_val = limit.unwrap_or(50);
        let mut stmt = conn.prepare(
            "SELECT e.data, t.event_descr, COUNT(*) as total, COUNT(DISTINCT e.data) as unique_count \
             FROM engine_events e, engine_event_types t \
             WHERE e.scan_id = ?1 AND t.event = e.event_type AND t.event_type = 'ENTITY' \
             GROUP BY e.data, e.event_type ORDER BY total DESC LIMIT ?2"
        )?;

        let results = stmt.query_map(params![scan_id, limit_val], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, usize>(2)?, row.get::<_, usize>(3)?))
        })?;

        results.collect()
    }

    pub fn get_unique_events(&self, scan_id: &str, event_type: Option<&str>, filter_fp: bool) -> SqliteResult<Vec<(String, String, usize)>> {
        let conn = self.conn.read().unwrap();
        let mut sql = String::from(
            "SELECT DISTINCT data, event_type, COUNT(*) as cnt FROM engine_events WHERE scan_id = ?1"
        );
        if let Some(_et) = event_type {
            sql.push_str(" AND event_type = ?2");
        }
        if filter_fp {
            sql.push_str(" AND false_positive = 0");
        }
        sql.push_str(" GROUP BY event_type, data ORDER BY cnt DESC");

        let mut stmt = conn.prepare(&sql)?;
        let results: SqliteResult<Vec<(String, String, usize)>> = if let Some(et) = event_type {
            stmt.query_map(params![scan_id, et], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, usize>(2)?))
            })?.collect()
        } else {
            stmt.query_map(params![scan_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, usize>(2)?))
            })?.collect()
        };
        results
    }

    pub fn search_events_paginated(&self, query: &EventSearchQuery) -> SqliteResult<PaginatedResult> {
        let conn = self.conn.read().unwrap();

        let mut where_clauses = vec!["scan_id = ?1".to_string()];
        let mut param_index = 2u32;
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(query.scan_id.clone())];

        if !query.event_types.is_empty() {
            let placeholders: Vec<String> = query.event_types.iter().map(|_| {
                let p = format!("?{}", param_index);
                param_index += 1;
                p
            }).collect();
            where_clauses.push(format!("event_type IN ({})", placeholders.join(", ")));
            for et in &query.event_types {
                param_values.push(Box::new(et.clone()));
            }
        }

        if let Some(ref module) = query.module_filter {
            where_clauses.push(format!("module = ?{}", param_index));
            param_values.push(Box::new(module.clone()));
            param_index += 1;
        }

        if let Some(ref pattern) = query.data_pattern {
            where_clauses.push(format!("data LIKE ?{}", param_index));
            param_values.push(Box::new(format!("%{}%", pattern)));
            param_index += 1;
        }

        if let Some(min_conf) = query.min_confidence {
            where_clauses.push(format!("confidence >= ?{}", param_index));
            param_values.push(Box::new(min_conf));
            param_index += 1;
        }

        if let Some(min_risk) = query.min_risk {
            where_clauses.push(format!("risk >= ?{}", param_index));
            param_values.push(Box::new(min_risk));
            param_index += 1;
        }

        let where_sql = where_clauses.join(" AND ");

        let count_sql = format!("SELECT COUNT(*) FROM engine_events WHERE {}", where_sql);
        let total: usize = conn.query_row(&count_sql, rusqlite::params_from_iter(param_values.iter().map(|p| p.as_ref())), |row| row.get(0))?;

        let limit = query.limit.unwrap_or(100);
        let offset = query.offset.unwrap_or(0);

        let search_sql = format!(
            "SELECT event_type, data, module, hash, confidence, visibility, risk, source_event_hash, source_event_type, source_event_data, store_only FROM engine_events WHERE {} ORDER BY generated ASC LIMIT ?{} OFFSET ?{}",
            where_sql, param_index, param_index + 1
        );
        param_values.push(Box::new(limit as i64));
        param_values.push(Box::new(offset as i64));

        let mut stmt = conn.prepare(&search_sql)?;
        let events: Vec<BiosEventRef> = stmt.query_map(
            rusqlite::params_from_iter(param_values.iter().map(|p| p.as_ref())),
            |row| {
                let event_type_str: String = row.get(0)?;
                let event_type = BiosEventType::from_str(&event_type_str)
                    .unwrap_or(BiosEventType::Custom(event_type_str));
                let source_event_type_str: Option<String> = row.get(8)?;
                let source_event_type = source_event_type_str
                    .as_deref()
                    .and_then(BiosEventType::from_str);
                let store_only: i32 = row.get(10).unwrap_or(0);
                Ok(BiosEventRef {
                    event_type,
                    data: row.get(1)?,
                    module: row.get(2)?,
                    hash: row.get(3)?,
                    confidence: row.get(4)?,
                    visibility: row.get(5)?,
                    risk: row.get(6)?,
                    source_event_hash: row.get(7)?,
                    source_event_type,
                    source_event_data: row.get(9)?,
                    store_only: store_only != 0,
                })
            },
        )?.collect::<SqliteResult<Vec<_>>>()?;

        Ok(PaginatedResult {
            events,
            total,
            offset,
            limit,
        })
    }

    pub fn store_correlation(&self, result: &CorrelationResult, scan_id: &str) -> SqliteResult<i64> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();

        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO engine_correlations (scan_id, rule_id, rule_name, rule_risk, headline, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan_id,
                result.rule_id,
                result.rule_name,
                result.rule_risk,
                result.headline,
                result.description,
                now,
            ],
        )?;
        let correlation_id = tx.last_insert_rowid();
        for event in &result.matched_events {
            tx.execute(
                "INSERT INTO engine_correlation_events (correlation_id, event_hash) VALUES (?1, ?2)",
                params![correlation_id, event.hash],
            )?;
        }
        tx.commit()?;
        Ok(correlation_id)
    }

    pub fn store_correlations(&self, results: &[CorrelationResult], scan_id: &str) -> SqliteResult<()> {
        for result in results {
            self.store_correlation(result, scan_id)?;
        }
        Ok(())
    }

    pub fn store_correlations_batch(&self, results: &[CorrelationResult], scan_id: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;
        let now = chrono::Utc::now().timestamp_millis();

        for result in results {
            let desc = &result.description;
            let res = tx.execute(
                "INSERT INTO engine_correlations (scan_id, rule_id, rule_name, rule_risk, headline, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![scan_id, result.rule_id, result.rule_name, result.rule_risk, result.headline, desc, now],
            );
            if let Err(e) = res {
                tx.rollback()?;
                return Err(e);
            }
            let correlation_id = tx.last_insert_rowid();
            for event in &result.matched_events {
                let res = tx.execute(
                    "INSERT INTO engine_correlation_events (correlation_id, event_hash) VALUES (?1, ?2)",
                    params![correlation_id, event.hash],
                );
                if let Err(e) = res {
                    tx.rollback()?;
                    return Err(e);
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_correlations_by_risk(&self, scan_id: &str, min_risk: &str) -> SqliteResult<Vec<CorrelationResult>> {
        let risk_order = [("critical", 4), ("high", 3), ("medium", 2), ("low", 1), ("info", 0)];
        let min_level = risk_order.iter()
            .find(|(name, _)| name == &min_risk.to_lowercase())
            .map(|(_, level)| *level)
            .unwrap_or(0);

        let all = self.get_correlations(scan_id)?;
        Ok(all.into_iter().filter(|c| {
            let level = risk_order.iter()
                .find(|(name, _)| name == &c.rule_risk.to_lowercase())
                .map(|(_, level)| *level)
                .unwrap_or(0);
            level >= min_level
        }).collect())
    }

    pub fn get_correlation_count_by_scan(&self, scan_id: &str) -> SqliteResult<usize> {
        let conn = self.conn.read().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_correlations WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    pub fn get_correlations(&self, scan_id: &str) -> SqliteResult<Vec<CorrelationResult>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.rule_id, c.rule_name, c.rule_risk, c.headline, c.description \
             FROM engine_correlations c WHERE c.scan_id = ?1 ORDER BY c.created_at ASC"
        )?;

        let results = stmt.query_map(params![scan_id], |row| {
            Ok(CorrelationResult {
                rule_id: row.get(1)?,
                rule_name: row.get(2)?,
                rule_risk: row.get(3)?,
                headline: row.get(4)?,
                description: row.get(5)?,
                matched_events: Vec::new(),
                source_events: Vec::new(),
                child_events: Vec::new(),
            })
        })?;

        let mut correlations: Vec<CorrelationResult> = results.collect::<SqliteResult<Vec<_>>>()?;

        for corr in &mut correlations {
            let event_hashes: Vec<String> = {
                let mut hash_stmt = conn.prepare(
                    "SELECT ce.event_hash FROM engine_correlation_events ce \
                     JOIN engine_correlations c ON ce.correlation_id = c.id \
                     WHERE c.scan_id = ?1 AND c.rule_id = ?2"
                )?;
                let hashes = hash_stmt.query_map(params![scan_id, corr.rule_id], |row| {
                    row.get::<_, String>(0)
                })?;
                hashes.collect::<SqliteResult<Vec<_>>>().unwrap_or_default()
            };

            for hash in &event_hashes {
                if let Ok(event) = self.get_event_by_hash(scan_id, hash) {
                    corr.matched_events.push(event);
                }
            }
        }

        Ok(correlations)
    }

    fn get_event_by_hash(&self, scan_id: &str, hash: &str) -> SqliteResult<BiosEventRef> {
        let conn = self.conn.read().unwrap();
        conn.query_row(
            "SELECT event_type, data, module, hash, confidence, visibility, risk, source_event_hash, source_event_type, source_event_data, store_only FROM engine_events WHERE scan_id = ?1 AND hash = ?2",
            params![scan_id, hash],
            |row| {
                let event_type_str: String = row.get(0)?;
                let event_type = BiosEventType::from_str(&event_type_str)
                    .unwrap_or(BiosEventType::Custom(event_type_str));
                let source_event_type_str: Option<String> = row.get(8)?;
                let source_event_type = source_event_type_str
                    .as_deref()
                    .and_then(BiosEventType::from_str);
                let store_only: i32 = row.get(10).unwrap_or(0);
                Ok(BiosEventRef {
                    event_type,
                    data: row.get(1)?,
                    module: row.get(2)?,
                    hash: row.get(3)?,
                    confidence: row.get(4)?,
                    visibility: row.get(5)?,
                    risk: row.get(6)?,
                    source_event_hash: row.get(7)?,
                    source_event_type,
                    source_event_data: row.get(9)?,
                    store_only: store_only != 0,
                })
            },
        )
    }

    pub fn store_target_alias(&self, scan_id: &str, alias_type: &str, alias_value: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute(
            "INSERT INTO engine_target_aliases (scan_id, alias_type, alias_value) VALUES (?1, ?2, ?3)",
            params![scan_id, alias_type, alias_value],
        )?;
        Ok(())
    }

    pub fn store_target_aliases_batch(&self, scan_id: &str, aliases: &[(String, String)]) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;
        for (alias_type, alias_value) in aliases {
            tx.execute(
                "INSERT INTO engine_target_aliases (scan_id, alias_type, alias_value) VALUES (?1, ?2, ?3)",
                params![scan_id, alias_type, alias_value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_target_aliases(&self, scan_id: &str) -> SqliteResult<Vec<(String, String)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT alias_type, alias_value FROM engine_target_aliases WHERE scan_id = ?1"
        )?;

        let aliases = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        aliases.collect()
    }

    pub fn resolve_alias_across_scans(&self, alias_value: &str) -> SqliteResult<Vec<String>> {
        let conn = self.conn.write().unwrap();
        let lower = alias_value.to_lowercase();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT s.scan_id FROM engine_scans s \
             LEFT JOIN engine_target_aliases a ON a.scan_id = s.scan_id \
             WHERE LOWER(s.target_value) = ?1 OR LOWER(a.alias_value) = ?1"
        )?;
        let results = stmt.query_map(params![lower], |row| {
            row.get::<_, String>(0)
        })?;
        results.collect()
    }

    pub fn delete_scan(&self, scan_id: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute("DELETE FROM engine_correlation_events WHERE correlation_id IN (SELECT id FROM engine_correlations WHERE scan_id = ?1)", params![scan_id])?;
        conn.execute("DELETE FROM engine_events WHERE scan_id = ?1", params![scan_id])?;
        conn.execute("DELETE FROM engine_correlations WHERE scan_id = ?1", params![scan_id])?;
        conn.execute("DELETE FROM engine_target_aliases WHERE scan_id = ?1", params![scan_id])?;
        conn.execute("DELETE FROM engine_scan_log WHERE scan_id = ?1", params![scan_id])?;
        conn.execute("DELETE FROM engine_scan_config WHERE scan_id = ?1", params![scan_id])?;
        conn.execute("DELETE FROM engine_scans WHERE scan_id = ?1", params![scan_id])?;
        Ok(())
    }

    pub fn store_config_snapshot(&self, snapshot: &crate::core::engine::scan::ScanConfigSnapshot) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "DELETE FROM engine_scan_config WHERE scan_id = ?1",
            params![snapshot.scan_id],
        )?;

        for (key, value) in &snapshot.global_options {
            tx.execute(
                "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![snapshot.scan_id, "global", key, value, "str"],
            )?;
        }

        for (module_name, options) in &snapshot.module_options {
            for (key, value) in options {
                tx.execute(
                    "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![snapshot.scan_id, format!("module:{}", module_name), key, value, "str"],
                )?;
            }
        }

        let modules_json = serde_json::to_string(&snapshot.modules_enabled).unwrap_or_else(|_| "[]".to_string());
        tx.execute(
            "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![snapshot.scan_id, "_meta", "modules_enabled", modules_json, "list"],
        )?;
        tx.execute(
            "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![snapshot.scan_id, "_meta", "scan_name", snapshot.scan_name, "str"],
        )?;
        tx.execute(
            "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![snapshot.scan_id, "_meta", "target_value", snapshot.target_value, "str"],
        )?;
        tx.execute(
            "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![snapshot.scan_id, "_meta", "target_type", snapshot.target_type, "str"],
        )?;
        tx.execute(
            "INSERT INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![snapshot.scan_id, "_meta", "created_at", snapshot.created_at.to_string(), "int"],
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn get_config_snapshot(&self, scan_id: &str) -> SqliteResult<Option<crate::core::engine::scan::ScanConfigSnapshot>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT component, opt, val FROM engine_scan_config WHERE scan_id = ?1"
        )?;

        let rows: Vec<(String, String, String)> = stmt.query_map(params![scan_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?.collect::<SqliteResult<Vec<_>>>()?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut meta = HashMap::new();
        let mut global_options = HashMap::new();
        let mut module_options = HashMap::new();

        for (component, opt, val) in &rows {
            if component == "_meta" {
                meta.insert(opt.clone(), val.clone());
            } else if component == "global" {
                global_options.insert(opt.clone(), val.clone());
            } else if component.starts_with("module:") {
                let module_name = component.strip_prefix("module:").unwrap().to_string();
                module_options.entry(module_name).or_insert_with(HashMap::new).insert(opt.clone(), val.clone());
            }
        }

        let modules_enabled: Vec<String> = meta.get("modules_enabled")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or_default();
        let scan_name = meta.get("scan_name").cloned().unwrap_or_default();
        let target_value = meta.get("target_value").cloned().unwrap_or_default();
        let target_type = meta.get("target_type").cloned().unwrap_or_default();
        let created_at = meta.get("created_at").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);

        Ok(Some(crate::core::engine::scan::ScanConfigSnapshot {
            scan_id: scan_id.to_string(),
            scan_name,
            target_value,
            target_type,
            modules_enabled,
            global_options,
            module_options,
            created_at,
        }))
    }

    pub fn register_event_type(&self, event_name: &str, description: &str, is_raw: bool, category: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO engine_event_types (event, event_descr, event_raw, event_type) VALUES (?1, ?2, ?3, ?4)",
            params![event_name, description, is_raw as i32, category],
        )?;
        Ok(())
    }

    pub fn get_event_type_meta(&self, event_name: &str) -> SqliteResult<Option<EventTypeMeta>> {
        let conn = self.conn.read().unwrap();
        let result = conn.query_row(
            "SELECT event, event_descr, event_raw, event_type FROM engine_event_types WHERE event = ?1",
            params![event_name],
            |row| {
                Ok(EventTypeMeta {
                    event: row.get(0)?,
                    description: row.get(1)?,
                    is_raw: row.get::<_, i32>(2)? != 0,
                    category: row.get(3)?,
                })
            },
        );

        match result {
            Ok(meta) => Ok(Some(meta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_all_event_types(&self) -> SqliteResult<Vec<EventTypeMeta>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event, event_descr, event_raw, event_type FROM engine_event_types ORDER BY event"
        )?;

        let results = stmt.query_map([], |row| {
            Ok(EventTypeMeta {
                event: row.get(0)?,
                description: row.get(1)?,
                is_raw: row.get::<_, i32>(2)? != 0,
                category: row.get(3)?,
            })
        })?;

        results.collect()
    }

    pub fn batch_register_event_types(&self, types: &[(String, String, bool, String)]) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;
        for (event, descr, is_raw, category) in types {
            tx.execute(
                "INSERT OR REPLACE INTO engine_event_types (event, event_descr, event_raw, event_type) VALUES (?1, ?2, ?3, ?4)",
                params![event, descr, *is_raw as i32, category],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // P5-13: Module State Persistence

    pub fn save_module_state(&self, scan_id: &str, module_name: &str, status: &str, error_count: i32, last_error: Option<&str>, disabled: bool) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT OR REPLACE INTO engine_module_state (scan_id, module_name, status, error_count, last_error_message, last_error_time, disabled, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![scan_id, module_name, status, error_count, last_error, if last_error.is_some() { Some(now) } else { None }, disabled as i32, now],
        )?;
        Ok(())
    }

    pub fn get_module_state(&self, scan_id: &str, module_name: &str) -> SqliteResult<Option<ModuleStateEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT status, error_count, last_error_message, last_error_time, disabled FROM engine_module_state WHERE scan_id = ?1 AND module_name = ?2"
        )?;
        let result = stmt.query_row(params![scan_id, module_name], |row| {
            Ok(ModuleStateEntry {
                status: row.get(0)?,
                error_count: row.get(1)?,
                last_error_message: row.get(2)?,
                last_error_time: row.get(3)?,
                disabled: row.get::<_, i32>(4)? != 0,
            })
        });
        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn get_all_module_states(&self, scan_id: &str) -> SqliteResult<Vec<(String, ModuleStateEntry)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT module_name, status, error_count, last_error_message, last_error_time, disabled FROM engine_module_state WHERE scan_id = ?1"
        )?;
        let entries = stmt.query_map(params![scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                ModuleStateEntry {
                    status: row.get(1)?,
                    error_count: row.get(2)?,
                    last_error_message: row.get(3)?,
                    last_error_time: row.get(4)?,
                    disabled: row.get::<_, i32>(5)? != 0,
                },
            ))
        })?;
        entries.collect()
    }

    pub fn reset_module_state(&self, scan_id: &str, module_name: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "UPDATE engine_module_state SET status = 'idle', error_count = 0, last_error_message = NULL, last_error_time = NULL, disabled = 0, updated_at = ?3 WHERE scan_id = ?1 AND module_name = ?2",
            params![scan_id, module_name, now],
        )?;
        Ok(())
    }

    // P2-1: Scan Log

    pub fn scan_log_event(&self, scan_id: &str, classification: &str, message: &str, component: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        conn.execute(
            "INSERT INTO engine_scan_log (scan_id, generated, component, classification, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![scan_id, now, component, classification, message],
        )?;
        Ok(())
    }

    pub fn scan_log_events_batch(&self, batch: &[(String, String, String, String, i64)]) -> SqliteResult<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;

        let chunk_size = 100;
        for chunk in batch.chunks(chunk_size) {
            let placeholders: Vec<String> = chunk.iter()
                .map(|_| "(?, ?, ?, ?, ?)".to_string())
                .collect();
            let sql = format!(
                "INSERT INTO engine_scan_log (scan_id, generated, component, classification, message) VALUES {}",
                placeholders.join(", ")
            );
            let mut stmt = tx.prepare(&sql)?;
            let params: Vec<Box<dyn rusqlite::types::ToSql>> = chunk.iter()
                .flat_map(|(scan_id, classification, message, component, generated)| {
                    vec![
                        Box::new(scan_id.clone()) as Box<dyn rusqlite::types::ToSql>,
                        Box::new(*generated) as Box<dyn rusqlite::types::ToSql>,
                        Box::new(component.clone()) as Box<dyn rusqlite::types::ToSql>,
                        Box::new(classification.clone()) as Box<dyn rusqlite::types::ToSql>,
                        Box::new(message.clone()) as Box<dyn rusqlite::types::ToSql>,
                    ]
                })
                .collect();
            let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            stmt.execute(param_refs.as_slice())?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_scan_logs(&self, scan_id: &str, limit: Option<usize>) -> SqliteResult<Vec<ScanLogEntry>> {
        let conn = self.conn.read().unwrap();
        let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();
        let query = format!(
            "SELECT generated, component, classification, message FROM engine_scan_log WHERE scan_id = ?1 ORDER BY generated DESC {}",
            limit_clause
        );
        let mut stmt = conn.prepare(&query)?;
        let entries = stmt.query_map(params![scan_id], |row| {
            Ok(ScanLogEntry {
                generated: row.get(0)?,
                component: row.get(1)?,
                classification: row.get(2)?,
                message: row.get(3)?,
            })
        })?;
        entries.collect()
    }

    pub fn get_scan_errors(&self, scan_id: &str, limit: Option<usize>) -> SqliteResult<Vec<ScanLogEntry>> {
        let conn = self.conn.read().unwrap();
        let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();
        let query = format!(
            "SELECT generated, component, classification, message FROM engine_scan_log WHERE scan_id = ?1 AND classification = 'ERROR' ORDER BY generated DESC {}",
            limit_clause
        );
        let mut stmt = conn.prepare(&query)?;
        let entries = stmt.query_map(params![scan_id], |row| {
            Ok(ScanLogEntry {
                generated: row.get(0)?,
                component: row.get(1)?,
                classification: row.get(2)?,
                message: row.get(3)?,
            })
        })?;
        entries.collect()
    }

    pub fn get_scan_logs_by_level(&self, scan_id: &str, levels: &[&str], limit: Option<usize>) -> SqliteResult<Vec<ScanLogEntry>> {
        let conn = self.conn.read().unwrap();
        let placeholders: Vec<String> = levels.iter().enumerate().map(|(i, _)| format!("?{}", i + 2)).collect();
        let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();
        let query = format!(
            "SELECT generated, component, classification, message FROM engine_scan_log WHERE scan_id = ?1 AND classification IN ({}) ORDER BY generated DESC {}",
            placeholders.join(", "),
            limit_clause
        );
        let mut stmt = conn.prepare(&query)?;
        let params: Vec<&dyn rusqlite::types::ToSql> = std::iter::once(&scan_id as &dyn rusqlite::types::ToSql)
            .chain(levels.iter().map(|l| l as &dyn rusqlite::types::ToSql))
            .collect();
        let entries = stmt.query_map(params.as_slice(), |row| {
            Ok(ScanLogEntry {
                generated: row.get(0)?,
                component: row.get(1)?,
                classification: row.get(2)?,
                message: row.get(3)?,
            })
        })?;
        entries.collect()
    }

    pub fn purge_scan_logs_before(&self, scan_id: &str, before_timestamp: i64) -> SqliteResult<usize> {
        let conn = self.conn.write().unwrap();
        conn.execute(
            "DELETE FROM engine_scan_log WHERE scan_id = ?1 AND generated < ?2",
            params![scan_id, before_timestamp],
        )
    }

    pub fn purge_logs_by_level(&self, scan_id: &str, levels: &[&str]) -> SqliteResult<usize> {
        let conn = self.conn.write().unwrap();
        let placeholders: Vec<String> = levels.iter().enumerate().map(|(i, _)| format!("?{}", i + 2)).collect();
        let query = format!(
            "DELETE FROM engine_scan_log WHERE scan_id = ?1 AND classification IN ({})",
            placeholders.join(", ")
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = std::iter::once(&scan_id as &dyn rusqlite::types::ToSql)
            .chain(levels.iter().map(|l| l as &dyn rusqlite::types::ToSql))
            .collect();
        conn.execute(&query, params.as_slice())
    }

    pub fn rotate_scan_logs(&self, scan_id: &str, keep_count: usize) -> SqliteResult<usize> {
        let conn = self.conn.write().unwrap();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_scan_log WHERE scan_id = ?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        if (total as usize) <= keep_count {
            return Ok(0);
        }
        let cutoff: i64 = conn.query_row(
            "SELECT generated FROM engine_scan_log WHERE scan_id = ?1 ORDER BY generated DESC LIMIT 1 OFFSET ?2",
            params![scan_id, keep_count as i64],
            |row| row.get(0),
        )?;
        conn.execute(
            "DELETE FROM engine_scan_log WHERE scan_id = ?1 AND generated <= ?2",
            params![scan_id, cutoff],
        )
    }

    // P2-2: Scan Config

    pub fn scan_config_set(&self, scan_id: &str, component: &str, opt: &str, val: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![scan_id, component, opt, val, "str"],
        )?;
        Ok(())
    }

    pub fn scan_config_set_typed(&self, scan_id: &str, component: &str, opt: &str, val: &str, val_type: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![scan_id, component, opt, val, val_type],
        )?;
        Ok(())
    }

    pub fn scan_config_set_bool(&self, scan_id: &str, component: &str, opt: &str, val: bool) -> SqliteResult<()> {
        self.scan_config_set_typed(scan_id, component, opt, if val { "1" } else { "0" }, "bool")
    }

    pub fn scan_config_set_int(&self, scan_id: &str, component: &str, opt: &str, val: i64) -> SqliteResult<()> {
        self.scan_config_set_typed(scan_id, component, opt, &val.to_string(), "int")
    }

    pub fn scan_config_set_list(&self, scan_id: &str, component: &str, opt: &str, val: &[String]) -> SqliteResult<()> {
        self.scan_config_set_typed(scan_id, component, opt, &val.join(","), "list")
    }

    pub fn scan_config_set_batch(&self, scan_id: &str, config: &[(&str, &str, &str)]) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;
        for (component, opt, val) in config {
            tx.execute(
                "INSERT OR REPLACE INTO engine_scan_config (scan_id, component, opt, val, val_type) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![scan_id, component, opt, val, "str"],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn scan_config_get(&self, scan_id: &str) -> SqliteResult<Vec<(String, String, String, String)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT component, opt, val, val_type FROM engine_scan_config WHERE scan_id = ?1 ORDER BY component, opt"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))
        })?;
        results.collect()
    }

    pub fn scan_config_get_typed(&self, scan_id: &str, component: &str, opt: &str) -> SqliteResult<Option<TypedConfigValue>> {
        let conn = self.conn.read().unwrap();
        let result = conn.query_row(
            "SELECT val, val_type FROM engine_scan_config WHERE scan_id = ?1 AND component = ?2 AND opt = ?3",
            params![scan_id, component, opt],
            |row| {
                let val: String = row.get(0)?;
                let val_type: String = row.get(1)?;
                Ok((val, val_type))
            },
        );
        match result {
            Ok((val, val_type)) => Ok(Some(TypedConfigValue { val, val_type })),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // P2-4: False Positive

    pub fn update_false_positive(&self, scan_id: &str, event_hashes: &[String], fp_flag: bool) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;
        for hash in event_hashes {
            tx.execute(
                "UPDATE engine_events SET false_positive = ?1 WHERE scan_id = ?2 AND hash = ?3",
                params![fp_flag as i32, scan_id, hash],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn update_false_positive_cascade(&self, scan_id: &str, event_hashes: &[String], fp_flag: bool) -> SqliteResult<usize> {
        let conn = self.conn.write().unwrap();
        let tx = conn.unchecked_transaction()?;

        let mut to_process: Vec<String> = event_hashes.to_vec();
        let mut visited: HashSet<String> = HashSet::new();
        let mut total_updated: usize = 0;

        while let Some(hash) = to_process.pop() {
            if visited.contains(&hash) {
                continue;
            }
            visited.insert(hash.clone());

            let updated = tx.execute(
                "UPDATE engine_events SET false_positive = ?1 WHERE scan_id = ?2 AND hash = ?3",
                params![fp_flag as i32, scan_id, hash],
            )?;
            total_updated += updated;

            let mut child_stmt = tx.prepare(
                "SELECT hash FROM engine_events WHERE scan_id = ?1 AND source_event_hash = ?2"
            )?;
            let children: Vec<String> = child_stmt.query_map(params![scan_id, hash], |row| {
                row.get::<_, String>(0)
            })?.collect::<SqliteResult<Vec<_>>>()?;
            drop(child_stmt);

            for child in children {
                if !visited.contains(&child) {
                    to_process.push(child);
                }
            }
        }

        tx.commit()?;
        Ok(total_updated)
    }

    pub fn get_false_positive_stats(&self, scan_id: &str) -> SqliteResult<HashMap<String, usize>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) FROM engine_events WHERE scan_id = ?1 AND false_positive = 1 GROUP BY event_type"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
        })?;
        results.collect()
    }

    // P2-5: Sources/Children Direct

    pub fn scan_element_sources_direct(&self, scan_id: &str, element_hashes: &[String]) -> SqliteResult<Vec<BiosEventRef>> {
        if element_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.read().unwrap();
        let placeholders: Vec<String> = element_hashes.iter().map(|_| "?".to_string()).collect();
        let query = format!(
            "SELECT c.event_type, c.data, c.module, c.hash, c.confidence, c.visibility, c.risk, \
             c.source_event_hash, c.source_event_type, c.source_event_data, c.store_only \
             FROM engine_events c, engine_events s \
             WHERE c.scan_id = ?1 AND c.source_event_hash = s.hash AND s.scan_id = c.scan_id \
             AND c.hash IN ({})",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&query)?;
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(scan_id.to_string())];
        for h in element_hashes {
            param_values.push(Box::new(h.clone()));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let events = stmt.query_map(param_refs.as_slice(), |row| {
            Self::row_to_event_ref(row)
        })?;
        events.collect()
    }

    pub fn scan_element_children_direct(&self, scan_id: &str, element_hashes: &[String]) -> SqliteResult<Vec<BiosEventRef>> {
        if element_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.read().unwrap();
        let placeholders: Vec<String> = element_hashes.iter().map(|_| "?".to_string()).collect();
        let query = format!(
            "SELECT c.event_type, c.data, c.module, c.hash, c.confidence, c.visibility, c.risk, \
             c.source_event_hash, c.source_event_type, c.source_event_data, c.store_only \
             FROM engine_events c, engine_events s \
             WHERE c.scan_id = ?1 AND c.source_event_hash = s.hash AND s.scan_id = c.scan_id \
             AND s.hash IN ({})",
            placeholders.join(",")
        );
        let mut stmt = conn.prepare(&query)?;
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(scan_id.to_string())];
        for h in element_hashes {
            param_values.push(Box::new(h.clone()));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let events = stmt.query_map(param_refs.as_slice(), |row| {
            Self::row_to_event_ref(row)
        })?;
        events.collect()
    }

    pub fn scan_element_sources_all(&self, scan_id: &str, child_hashes: &[String]) -> SqliteResult<Vec<BiosEventRef>> {
        let mut all_sources = Vec::new();
        let mut next_hashes: Vec<String> = child_hashes.to_vec();
        let mut visited: HashSet<String> = child_hashes.iter().cloned().collect();

        while !next_hashes.is_empty() {
            let sources = self.scan_element_sources_direct(scan_id, &next_hashes)?;
            next_hashes.clear();
            for src in &sources {
                if let Some(ref parent_hash) = src.source_event_hash {
                    if parent_hash != "ROOT" && !visited.contains(parent_hash) {
                        visited.insert(parent_hash.clone());
                        next_hashes.push(parent_hash.clone());
                    }
                }
            }
            all_sources.extend(sources);
        }

        Ok(all_sources)
    }

    pub fn scan_element_children_all(&self, scan_id: &str, parent_hashes: &[String]) -> SqliteResult<Vec<BiosEventRef>> {
        let mut all_children = Vec::new();
        let mut next_hashes: Vec<String> = parent_hashes.to_vec();
        let mut visited: HashSet<String> = parent_hashes.iter().cloned().collect();

        while !next_hashes.is_empty() {
            let children = self.scan_element_children_direct(scan_id, &next_hashes)?;
            next_hashes.clear();
            for child in &children {
                if !visited.contains(&child.hash) {
                    visited.insert(child.hash.clone());
                    next_hashes.push(child.hash.clone());
                    all_children.push(child.clone());
                }
            }
        }

        Ok(all_children)
    }

    pub fn get_event_provenance_path(&self, scan_id: &str, event_hash: &str) -> SqliteResult<Vec<BiosEventRef>> {
        let mut path = Vec::new();
        let mut current_hash = Some(event_hash.to_string());
        let mut visited = HashSet::new();

        while let Some(hash) = current_hash {
            if hash == "ROOT" || visited.contains(&hash) {
                break;
            }
            visited.insert(hash.clone());

            let conn = self.conn.read().unwrap();
            let result = conn.query_row(
                "SELECT event_type, data, module, hash, confidence, visibility, risk, \
                 source_event_hash, source_event_type, source_event_data, store_only \
                 FROM engine_events WHERE scan_id = ?1 AND hash = ?2",
                params![scan_id, hash],
                Self::row_to_event_ref,
            );

            match result {
                Ok(event) => {
                    current_hash = event.source_event_hash.clone();
                    path.push(event);
                }
                Err(_) => break,
            }
        }

        path.reverse();
        Ok(path)
    }

    pub fn resolve_entity_for_event(&self, scan_id: &str, event_hash: &str) -> SqliteResult<Option<BiosEventRef>> {
        let mut current_hash = Some(event_hash.to_string());
        let mut visited = HashSet::new();
        const MAX_DEPTH: usize = 50;

        for _ in 0..MAX_DEPTH {
            let hash = match &current_hash {
                Some(h) if h != "ROOT" => h.clone(),
                _ => return Ok(None),
            };

            if visited.contains(&hash) {
                return Ok(None);
            }
            visited.insert(hash.clone());

            let conn = self.conn.read().unwrap();
            let result = conn.query_row(
                "SELECT event_type, data, module, hash, confidence, visibility, risk, \
                 source_event_hash, source_event_type, source_event_data, store_only \
                 FROM engine_events WHERE scan_id = ?1 AND hash = ?2",
                params![scan_id, hash],
                Self::row_to_event_ref,
            );

            match result {
                Ok(event) => {
                    if event.event_type.category() == crate::core::engine::event_type::EventCategory::Entity
                        || event.event_type.category() == crate::core::engine::event_type::EventCategory::Internal
                    {
                        return Ok(Some(event));
                    }
                    current_hash = event.source_event_hash.clone();
                }
                Err(_) => return Ok(None),
            }
        }

        Ok(None)
    }

    pub fn batch_resolve_entities(&self, scan_id: &str, event_hashes: &[String]) -> SqliteResult<HashMap<String, Option<BiosEventRef>>> {
        let mut results = HashMap::new();
        for hash in event_hashes {
            results.insert(hash.clone(), self.resolve_entity_for_event(scan_id, hash)?);
        }
        Ok(results)
    }

    pub fn get_event_provenance_tree(&self, scan_id: &str, event_hash: &str, max_depth: usize) -> SqliteResult<ProvenanceNode> {
        let conn = self.conn.read().unwrap();
        let root_event = conn.query_row(
            "SELECT event_type, data, module, hash, confidence, visibility, risk, \
             source_event_hash, source_event_type, source_event_data, store_only \
             FROM engine_events WHERE scan_id = ?1 AND hash = ?2",
            params![scan_id, event_hash],
            Self::row_to_event_ref,
        )?;
        drop(conn);

        let children = self.scan_element_children_direct(scan_id, &[event_hash.to_string()])?;

        let child_nodes: Vec<ProvenanceNode> = if max_depth > 0 {
            children.iter()
                .filter_map(|c| self.get_event_provenance_tree(scan_id, &c.hash, max_depth - 1).ok())
                .collect()
        } else {
            Vec::new()
        };

        Ok(ProvenanceNode {
            event: root_event,
            children: child_nodes,
        })
    }

    // P2-6: Correlation with mapping table

    pub fn store_correlation_v2(&self, scan_id: &str, rule_id: &str, rule_name: &str, rule_risk: &str, headline: &str, description: &str, event_hashes: &[String]) -> SqliteResult<i64> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO engine_correlations (scan_id, rule_id, rule_name, rule_risk, headline, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![scan_id, rule_id, rule_name, rule_risk, headline, description, now],
        )?;
        let correlation_id = tx.last_insert_rowid();
        for hash in event_hashes {
            tx.execute(
                "INSERT INTO engine_correlation_events (correlation_id, event_hash) VALUES (?1, ?2)",
                params![correlation_id, hash],
            )?;
        }
        tx.commit()?;
        Ok(correlation_id)
    }

    pub fn get_correlations_v2(&self, scan_id: &str) -> SqliteResult<Vec<CorrelationResult>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.rule_id, c.rule_name, c.rule_risk, c.headline, c.description \
             FROM engine_correlations c WHERE c.scan_id = ?1 ORDER BY c.created_at ASC"
        )?;

        let results = stmt.query_map(params![scan_id], |row| {
            Ok(CorrelationResult {
                rule_id: row.get(1)?,
                rule_name: row.get(2)?,
                rule_risk: row.get(3)?,
                headline: row.get(4)?,
                description: row.get(5)?,
                matched_events: Vec::new(),
                source_events: Vec::new(),
                child_events: Vec::new(),
            })
        })?;

        let mut correlations: Vec<CorrelationResult> = results.collect::<SqliteResult<Vec<_>>>()?;

        for corr in &mut correlations {
            let event_hashes: Vec<String> = {
                let mut hash_stmt = conn.prepare(
                    "SELECT ce.event_hash FROM engine_correlation_events ce \
                     JOIN engine_correlations c ON ce.correlation_id = c.id \
                     WHERE c.scan_id = ?1 AND c.rule_id = ?2"
                )?;
                let hashes = hash_stmt.query_map(params![scan_id, corr.rule_id], |row| {
                    row.get::<_, String>(0)
                })?;
                hashes.collect::<SqliteResult<Vec<_>>>().unwrap_or_default()
            };

            for hash in &event_hashes {
                if let Ok(event) = self.get_event_by_hash(scan_id, hash) {
                    corr.matched_events.push(event);
                }
            }
        }

        Ok(correlations)
    }

    pub fn get_events_by_correlation(&self, scan_id: &str, correlation_id: i64) -> SqliteResult<Vec<BiosEventRef>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT e.event_type, e.data, e.module, e.hash, e.confidence, e.visibility, e.risk, \
             e.source_event_hash, e.source_event_type, e.source_event_data, e.store_only \
             FROM engine_events e \
             JOIN engine_correlation_events ce ON ce.event_hash = e.hash \
             JOIN engine_correlations c ON ce.correlation_id = c.id \
             WHERE c.scan_id = ?1 AND c.id = ?2"
        )?;

        let results = stmt.query_map(params![scan_id, correlation_id], |row| {
            Self::row_to_event_ref(row)
        })?;

        let mut events = Vec::new();
        for e in results.flatten() {
            events.push(e);
        }
        Ok(events)
    }

    pub fn get_events_by_correlation_rule(&self, scan_id: &str, rule_id: &str) -> SqliteResult<Vec<BiosEventRef>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT e.event_type, e.data, e.module, e.hash, e.confidence, e.visibility, e.risk, \
             e.source_event_hash, e.source_event_type, e.source_event_data, e.store_only \
             FROM engine_events e \
             JOIN engine_correlation_events ce ON ce.event_hash = e.hash \
             JOIN engine_correlations c ON ce.correlation_id = c.id \
             WHERE c.scan_id = ?1 AND c.rule_id = ?2"
        )?;

        let results = stmt.query_map(params![scan_id, rule_id], |row| {
            Self::row_to_event_ref(row)
        })?;

        let mut events = Vec::new();
        for e in results.flatten() {
            events.push(e);
        }
        Ok(events)
    }

    // P2-7: Unique event data

    pub fn get_unique_event_data(&self, scan_id: &str, event_type: Option<&BiosEventType>, filter_fp: bool) -> SqliteResult<Vec<String>> {
        let conn = self.conn.read().unwrap();
        let mut query = "SELECT DISTINCT data FROM engine_events WHERE scan_id = ?1".to_string();
        if let Some(_et) = event_type {
            query.push_str(" AND event_type = ?2");
        }
        if filter_fp {
            query.push_str(" AND false_positive = 0");
        }
        let mut stmt = conn.prepare(&query)?;
        if let Some(et) = event_type {
            let results = stmt.query_map(params![scan_id, et.as_str()], |row| {
                row.get::<_, String>(0)
            })?;
            results.collect()
        } else {
            let results = stmt.query_map(params![scan_id], |row| {
                row.get::<_, String>(0)
            })?;
            results.collect()
        }
    }

    // P2-8: Result history

    pub fn get_result_history(&self, scan_id: &str) -> SqliteResult<Vec<(i64, usize)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT (generated / 60000) * 60000 as minute_bucket, COUNT(*) as cnt \
             FROM engine_events WHERE scan_id = ?1 \
             GROUP BY minute_bucket ORDER BY minute_bucket ASC"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, usize>(1)?))
        })?;
        results.collect()
    }

    pub fn get_scan_trend_by_target(&self, target_value: &str) -> SqliteResult<Vec<ScanTrendEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT s.scan_id, s.status, s.created_at, \
             COUNT(e.hash) AS total_events, \
             COUNT(DISTINCT e.event_type) AS event_type_count, \
             SUM(CASE WHEN e.false_positive = 1 THEN 1 ELSE 0 END) AS fp_count \
             FROM engine_scans s \
             LEFT JOIN engine_events e ON e.scan_id = s.scan_id \
             WHERE s.target_value = ?1 \
             GROUP BY s.scan_id \
             ORDER BY s.created_at ASC"
        )?;
        let results = stmt.query_map(params![target_value], |row| {
            Ok(ScanTrendEntry {
                scan_id: row.get(0)?,
                status: row.get(1)?,
                created_at: row.get(2)?,
                total_events: row.get(3)?,
                event_type_count: row.get(4)?,
                false_positive_count: row.get::<_, usize>(5)?,
            })
        })?;
        results.collect()
    }

    pub fn get_event_type_trend(&self, scan_id: &str) -> SqliteResult<Vec<(String, i64, usize)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT event_type, (generated / 60000) * 60000 as minute_bucket, COUNT(*) as cnt \
             FROM engine_events WHERE scan_id = ?1 \
             GROUP BY event_type, minute_bucket \
             ORDER BY event_type, minute_bucket ASC"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, usize>(2)?))
        })?;
        results.collect()
    }

    pub fn get_risk_trend(&self, scan_id: &str) -> SqliteResult<Vec<(i64, f64)>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT (generated / 60000) * 60000 as minute_bucket, AVG(risk) as avg_risk \
             FROM engine_events WHERE scan_id = ?1 AND risk > 0 \
             GROUP BY minute_bucket ORDER BY minute_bucket ASC"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })?;
        results.collect()
    }

    // P2-3: Store event with truncation

    // P3-4: Result Summary Queries

    pub fn get_result_summary_by_type(&self, scan_id: &str) -> SqliteResult<Vec<ResultSummaryEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.event_type, e.event_descr, MAX(r.generated) AS last_in, \
             COUNT(*) AS total, COUNT(DISTINCT r.data) AS utotal \
             FROM engine_events r \
             LEFT JOIN engine_event_types e ON e.event = r.event_type \
             WHERE r.scan_id = ?1 \
             GROUP BY r.event_type ORDER BY e.event_descr"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok(ResultSummaryEntry {
                key: row.get(0)?,
                description: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                last_seen: row.get(2)?,
                total: row.get(3)?,
                unique_total: row.get(4)?,
            })
        })?;
        results.collect()
    }

    pub fn get_result_summary_by_module(&self, scan_id: &str) -> SqliteResult<Vec<ResultSummaryEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.module, '' AS descr, MAX(r.generated) AS last_in, \
             COUNT(*) AS total, COUNT(DISTINCT r.data) AS utotal \
             FROM engine_events r \
             WHERE r.scan_id = ?1 \
             GROUP BY r.module ORDER BY total DESC"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok(ResultSummaryEntry {
                key: row.get(0)?,
                description: row.get(1)?,
                last_seen: row.get(2)?,
                total: row.get(3)?,
                unique_total: row.get(4)?,
            })
        })?;
        results.collect()
    }

    pub fn get_result_summary_by_entity(&self, scan_id: &str, limit: usize) -> SqliteResult<Vec<ResultSummaryEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.data, e.event_descr, MAX(r.generated) AS last_in, \
             COUNT(*) AS total, COUNT(DISTINCT r.data) AS utotal \
             FROM engine_events r \
             LEFT JOIN engine_event_types e ON e.event = r.event_type \
             WHERE r.scan_id = ?1 \
             AND e.event_type = 'ENTITY' \
             GROUP BY r.data, e.event_descr ORDER BY total DESC LIMIT ?2"
        )?;
        let results = stmt.query_map(params![scan_id, limit], |row| {
            Ok(ResultSummaryEntry {
                key: row.get(0)?,
                description: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                last_seen: row.get(2)?,
                total: row.get(3)?,
                unique_total: row.get(4)?,
            })
        })?;
        results.collect()
    }

    pub fn get_result_summary_by_entity_category(&self, scan_id: &str, category: &str, limit: usize) -> SqliteResult<Vec<ResultSummaryEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.data, e.event_descr, MAX(r.generated) AS last_in, \
             COUNT(*) AS total, COUNT(DISTINCT r.data) AS utotal \
             FROM engine_events r \
             LEFT JOIN engine_event_types e ON e.event = r.event_type \
             WHERE r.scan_id = ?1 \
             AND e.event_type = ?2 \
             GROUP BY r.data, e.event_descr ORDER BY total DESC LIMIT ?3"
        )?;
        let results = stmt.query_map(params![scan_id, category, limit], |row| {
            Ok(ResultSummaryEntry {
                key: row.get(0)?,
                description: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                last_seen: row.get(2)?,
                total: row.get(3)?,
                unique_total: row.get(4)?,
            })
        })?;
        results.collect()
    }

    pub fn get_entity_trend_across_scans(&self, target_value: &str) -> SqliteResult<Vec<EntityTrendEntry>> {
        let conn = self.conn.read().unwrap();
        let lower = target_value.to_lowercase();
        let mut stmt = conn.prepare(
            "SELECT s.scan_id, s.created_at, r.event_type, r.data, COUNT(*) as cnt \
             FROM engine_scans s \
             JOIN engine_events r ON r.scan_id = s.scan_id \
             JOIN engine_event_types e ON e.event = r.event_type \
             WHERE LOWER(s.target_value) = ?1 AND e.event_type IN ('ENTITY', 'SUBENTITY') \
             GROUP BY s.scan_id, r.event_type, r.data \
             ORDER BY s.created_at ASC, r.event_type, r.data"
        )?;
        let results = stmt.query_map(params![lower], |row| {
            Ok(EntityTrendEntry {
                scan_id: row.get(0)?,
                created_at: row.get(1)?,
                event_type: row.get(2)?,
                data: row.get(3)?,
                count: row.get(4)?,
            })
        })?;
        results.collect()
    }

    // P3-10: Correlation Summary Queries

    pub fn get_correlation_summary_by_rule(&self, scan_id: &str) -> SqliteResult<Vec<CorrelationSummaryEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.rule_id, c.rule_name, COUNT(ce.event_hash) AS total \
             FROM engine_correlations c \
             LEFT JOIN engine_correlation_events ce ON ce.correlation_id = c.id \
             WHERE c.scan_id = ?1 \
             GROUP BY c.rule_id ORDER BY c.rule_id"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok(CorrelationSummaryEntry {
                key: row.get(0)?,
                description: row.get(1)?,
                total: row.get(2)?,
            })
        })?;
        results.collect()
    }

    pub fn get_correlation_summary_by_risk(&self, scan_id: &str) -> SqliteResult<Vec<CorrelationSummaryEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.rule_risk, '', COUNT(*) AS total \
             FROM engine_correlations c \
             WHERE c.scan_id = ?1 \
             GROUP BY c.rule_risk ORDER BY c.rule_risk"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok(CorrelationSummaryEntry {
                key: row.get(0)?,
                description: row.get(1)?,
                total: row.get(2)?,
            })
        })?;
        results.collect()
    }

    pub fn get_correlation_list_with_count(&self, scan_id: &str) -> SqliteResult<Vec<CorrelationListEntry>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT c.id, c.rule_id, c.rule_name, c.rule_risk, c.headline, c.description, c.created_at, \
             COUNT(ce.event_hash) AS event_count \
             FROM engine_correlations c \
             LEFT JOIN engine_correlation_events ce ON ce.correlation_id = c.id \
             WHERE c.scan_id = ?1 \
             GROUP BY c.id ORDER BY c.created_at ASC"
        )?;
        let results = stmt.query_map(params![scan_id], |row| {
            Ok(CorrelationListEntry {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                rule_name: row.get(2)?,
                rule_risk: row.get(3)?,
                headline: row.get(4)?,
                description: row.get(5)?,
                created_at: row.get(6)?,
                event_count: row.get(7)?,
            })
        })?;
        results.collect()
    }

    // P3-5: Enhanced Search

    pub fn search_events(&self, criteria: &SearchCriteria) -> SqliteResult<Vec<BiosEventRef>> {
        let conn = self.conn.read().unwrap();
        let mut query = String::from(
            "SELECT c.event_type, c.data, c.module, c.hash, c.confidence, c.visibility, c.risk, \
             c.source_event_hash, c.source_event_type, c.source_event_data, c.store_only \
             FROM engine_events c \
             LEFT JOIN engine_events s ON s.scan_id = c.scan_id AND s.hash = c.source_event_hash \
             WHERE 1=1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref scan_id) = criteria.scan_id {
            query.push_str(" AND c.scan_id = ?");
            param_values.push(Box::new(scan_id.clone() as String));
        }

        if let Some(ref event_type) = criteria.event_type {
            query.push_str(" AND c.event_type = ?");
            param_values.push(Box::new(event_type.clone() as String));
        }

        if criteria.filter_fp {
            query.push_str(" AND c.false_positive = 0");
        }

        if let Some(ref value) = criteria.value {
            let like_value: String = value.replace('*', "%");
            query.push_str(" AND (c.data LIKE ? OR s.data LIKE ?)");
            param_values.push(Box::new(like_value.clone() as String));
            param_values.push(Box::new(like_value as String));
        }

        if let Some(ref regex_pattern) = criteria.regex {
            query.push_str(" AND (regexp(?, c.data) OR (c.source_event_data IS NOT NULL AND regexp(?, c.source_event_data)))");
            param_values.push(Box::new(regex_pattern.clone() as String));
            param_values.push(Box::new(regex_pattern.clone() as String));
        }

        query.push_str(" ORDER BY c.data");

        let mut stmt = conn.prepare(&query)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let events: Vec<BiosEventRef> = stmt.query_map(param_refs.as_slice(), |row| {
            Self::row_to_event_ref(row)
        })?.collect::<SqliteResult<Vec<_>>>()?;

        Ok(events)
    }

    // P3-6: Export

    pub fn export_scan_csv(&self, scan_id: &str) -> SqliteResult<String> {
        let events = self.get_events_by_scan(scan_id)?;
        let mut csv = String::from("Generated,Type,Module,Source,Confidence,Visibility,Risk,F/P,Data\n");
        for e in &events {
            let src = e.source_event_data.as_deref().unwrap_or("");
            let fp = "0";
            let data_escaped = e.data.replace('"', "\"\"");
            csv.push_str(&format!(
                "\"\",\"{}\",\"{}\",\"{}\",{},{},{},{},\"{}\"\n",
                e.event_type.as_str(),
                e.module,
                src.replace('"', "\"\""),
                e.confidence,
                e.visibility,
                e.risk,
                fp,
                data_escaped,
            ));
        }
        Ok(csv)
    }

    pub fn export_scan_json(&self, scan_id: &str) -> SqliteResult<String> {
        let events = self.get_events_by_scan(scan_id)?;
        Ok(serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".to_string()))
    }

    pub fn export_scan_gexf(&self, scan_id: &str) -> SqliteResult<String> {
        let events = self.get_events_by_scan(scan_id)?;
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<gexf xmlns=\"http://www.gexf.net/1.2draft\" version=\"1.2\">\n");
        xml.push_str("  <graph mode=\"static\" defaultedgetype=\"directed\">\n");

        xml.push_str("    <attributes class=\"node\" mode=\"static\">\n");
        xml.push_str("      <attribute id=\"0\" title=\"type\" type=\"string\"/>\n");
        xml.push_str("      <attribute id=\"1\" title=\"module\" type=\"string\"/>\n");
        xml.push_str("    </attributes>\n");

        xml.push_str("    <nodes>\n");
        for e in &events {
            let label = xml_escape(&e.data);
            xml.push_str(&format!(
                "      <node id=\"{}\" label=\"{}\">\n",
                xml_escape(&e.hash),
                label
            ));
            xml.push_str("        <attvalues>\n");
            xml.push_str(&format!(
                "          <attvalue for=\"0\" value=\"{}\"/>\n",
                xml_escape(e.event_type.as_str())
            ));
            xml.push_str(&format!(
                "          <attvalue for=\"1\" value=\"{}\"/>\n",
                xml_escape(&e.module)
            ));
            xml.push_str("        </attvalues>\n");
            xml.push_str("      </node>\n");
        }
        xml.push_str("    </nodes>\n");

        xml.push_str("    <edges>\n");
        let mut edge_id = 0u64;
        for e in &events {
            if let Some(ref src_hash) = e.source_event_hash {
                if src_hash != "ROOT" {
                    xml.push_str(&format!(
                        "      <edge id=\"{}\" source=\"{}\" target=\"{}\"/>\n",
                        edge_id,
                        xml_escape(src_hash),
                        xml_escape(&e.hash)
                    ));
                    edge_id += 1;
                }
            }
        }
        xml.push_str("    </edges>\n");

        xml.push_str("  </graph>\n");
        xml.push_str("</gexf>\n");
        Ok(xml)
    }

    pub fn export_scan_sigma_json(&self, scan_id: &str) -> SqliteResult<String> {
        let events = self.get_events_by_scan(scan_id)?;

        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        for e in &events {
            let label = if e.data.len() > 80 {
                let truncated = truncate_to_byte_limit(&e.data, 77);
                format!("{}...", truncated)
            } else {
                e.data.clone()
            };
            let category = e.event_type.category().to_string();
            let color = match e.event_type.risk_level() {
                "critical" => "#dc3545",
                "high" => "#e74c3c",
                "medium" => "#f39c12",
                "low" => "#3498db",
                _ => "#95a5a6",
            };
            let size = if e.source_event_hash.as_deref() == Some("ROOT") {
                20.0
            } else {
                10.0
            };

            nodes.push(serde_json::json!({
                "id": e.hash,
                "label": label,
                "x": 0,
                "y": 0,
                "size": size,
                "color": color,
                "attributes": {
                    "type": e.event_type.as_str(),
                    "module": e.module,
                    "category": category,
                    "risk": e.event_type.risk_level(),
                    "confidence": e.confidence,
                }
            }));

            if let Some(ref src_hash) = e.source_event_hash {
                if src_hash != "ROOT" {
                    edges.push(serde_json::json!({
                        "id": format!("e_{}_{}", src_hash, e.hash),
                        "source": src_hash,
                        "target": e.hash,
                        "color": "#ccc",
                    }));
                }
            }
        }

        let graph = serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        });

        serde_json::to_string_pretty(&graph).map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    }

    pub fn export_scan_cytoscape_json(&self, scan_id: &str) -> SqliteResult<String> {
        let events = self.get_events_by_scan(scan_id)?;

        let mut elements = Vec::new();

        for e in &events {
            let label = if e.data.len() > 80 {
                let truncated = truncate_to_byte_limit(&e.data, 77);
                format!("{}...", truncated)
            } else {
                e.data.clone()
            };

            elements.push(serde_json::json!({
                "data": {
                    "id": e.hash,
                    "label": label,
                    "type": e.event_type.as_str(),
                    "module": e.module,
                    "category": e.event_type.category().to_string(),
                    "risk": e.event_type.risk_level(),
                    "confidence": e.confidence,
                },
                "group": "nodes",
            }));

            if let Some(ref src_hash) = e.source_event_hash {
                if src_hash != "ROOT" {
                    elements.push(serde_json::json!({
                        "data": {
                            "id": format!("e_{}_{}", src_hash, e.hash),
                            "source": src_hash,
                            "target": e.hash,
                        },
                        "group": "edges",
                    }));
                }
            }
        }

        let result = serde_json::json!({
            "elements": elements,
        });

        serde_json::to_string_pretty(&result).map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    }

    pub fn export_multi_scan_csv(&self, scan_ids: &[String]) -> SqliteResult<String> {
        let mut csv = String::from("ScanID,Generated,Type,Module,Source,Confidence,Visibility,Risk,F/P,Data\n");
        for scan_id in scan_ids {
            let events = self.get_events_by_scan(scan_id)?;
            for e in &events {
                let src = e.source_event_data.as_deref().unwrap_or("");
                let data_escaped = e.data.replace('"', "\"\"");
                csv.push_str(&format!(
                    "\"{}\",\"\",\"{}\",\"{}\",\"{}\",{},{},{},0,\"{}\"\n",
                    scan_id,
                    e.event_type.as_str(),
                    e.module,
                    src.replace('"', "\"\""),
                    e.confidence,
                    e.visibility,
                    e.risk,
                    data_escaped,
                ));
            }
        }
        Ok(csv)
    }

    pub fn export_multi_scan_json(&self, scan_ids: &[String]) -> SqliteResult<String> {
        let mut all_events: Vec<serde_json::Value> = Vec::new();
        for scan_id in scan_ids {
            let events = self.get_events_by_scan(scan_id)?;
            for e in &events {
                let mut obj = serde_json::to_value(e).unwrap_or_default();
                if let Some(map) = obj.as_object_mut() {
                    map.insert("scan_id".to_string(), serde_json::Value::String(scan_id.clone()));
                }
                all_events.push(obj);
            }
        }
        Ok(serde_json::to_string_pretty(&all_events).unwrap_or_else(|_| "[]".to_string()))
    }

    pub fn export_multi_scan_gexf(&self, scan_ids: &[String]) -> SqliteResult<String> {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<gexf xmlns=\"http://www.gexf.net/1.2draft\" version=\"1.2\">\n");
        xml.push_str("  <graph mode=\"static\" defaultedgetype=\"directed\">\n");
        xml.push_str("    <attributes class=\"node\" mode=\"static\">\n");
        xml.push_str("      <attribute id=\"0\" title=\"type\" type=\"string\"/>\n");
        xml.push_str("      <attribute id=\"1\" title=\"module\" type=\"string\"/>\n");
        xml.push_str("      <attribute id=\"2\" title=\"scan_id\" type=\"string\"/>\n");
        xml.push_str("    </attributes>\n");

        xml.push_str("    <nodes>\n");
        for scan_id in scan_ids {
            let events = self.get_events_by_scan(scan_id)?;
            for e in &events {
                let label = xml_escape(&e.data);
                xml.push_str(&format!(
                    "      <node id=\"{}\" label=\"{}\">\n",
                    xml_escape(&format!("{}_{}", scan_id, e.hash)),
                    label
                ));
                xml.push_str("        <attvalues>\n");
                xml.push_str(&format!(
                    "          <attvalue for=\"0\" value=\"{}\"/>\n",
                    xml_escape(e.event_type.as_str())
                ));
                xml.push_str(&format!(
                    "          <attvalue for=\"1\" value=\"{}\"/>\n",
                    xml_escape(&e.module)
                ));
                xml.push_str(&format!(
                    "          <attvalue for=\"2\" value=\"{}\"/>\n",
                    xml_escape(scan_id)
                ));
                xml.push_str("        </attvalues>\n");
                xml.push_str("      </node>\n");
            }
        }
        xml.push_str("    </nodes>\n");

        xml.push_str("    <edges>\n");
        let mut edge_id = 0u64;
        for scan_id in scan_ids {
            let events = self.get_events_by_scan(scan_id)?;
            for e in &events {
                if let Some(ref src_hash) = e.source_event_hash {
                    if src_hash != "ROOT" {
                        xml.push_str(&format!(
                            "      <edge id=\"{}\" source=\"{}\" target=\"{}\"/>\n",
                            edge_id,
                            xml_escape(&format!("{}_{}", scan_id, src_hash)),
                            xml_escape(&format!("{}_{}", scan_id, e.hash))
                        ));
                        edge_id += 1;
                    }
                }
            }
        }
        xml.push_str("    </edges>\n");

        xml.push_str("  </graph>\n");
        xml.push_str("</gexf>\n");
        Ok(xml)
    }

    pub fn export_scan_xlsx(&self, scan_id: &str) -> SqliteResult<Vec<u8>> {
        use rust_xlsxwriter::*;

        let events = self.get_events_by_scan(scan_id)?;
        let mut workbook = Workbook::new();
        let worksheet = workbook.add_worksheet();

        let header_format = Format::new()
            .set_bold()
            .set_background_color(Color::RGB(0x4472C4))
            .set_font_color(Color::White)
            .set_border(FormatBorder::Thin);

        let headers = ["Type", "Data", "Module", "Confidence", "Visibility", "Risk", "Source Hash", "Source Data"];
        for (col, header) in headers.iter().enumerate() {
            worksheet.write_string_with_format(0, col as u16, *header, &header_format)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
        }

        let sensitive_format = Format::new()
            .set_font_color(Color::Red)
            .set_bold();

        for (row_idx, e) in events.iter().enumerate() {
            let row = (row_idx + 1) as u32;
            worksheet.write_string(row, 0, e.event_type.as_str())
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

            if e.event_type.is_sensitive() {
                worksheet.write_string_with_format(row, 1, &e.data, &sensitive_format)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            } else {
                worksheet.write_string(row, 1, &e.data)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            }

            worksheet.write_string(row, 2, &e.module)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            worksheet.write_number(row, 3, e.confidence as f64)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            worksheet.write_number(row, 4, e.visibility as f64)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            worksheet.write_number(row, 5, e.risk as f64)
                .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;

            if let Some(ref src_hash) = e.source_event_hash {
                worksheet.write_string(row, 6, src_hash)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            }
            if let Some(ref src_data) = e.source_event_data {
                worksheet.write_string(row, 7, src_data)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))?;
            }
        }

        worksheet.set_column_width(0, 25).ok();
        worksheet.set_column_width(1, 60).ok();
        worksheet.set_column_width(2, 20).ok();
        worksheet.set_column_width(7, 40).ok();

        workbook.save_to_buffer()
            .map_err(|e| rusqlite::Error::InvalidParameterName(e.to_string()))
    }

    // P3-7: Cache System

    pub fn cache_put(&self, label: &str, data: &str, ttl_secs: i64) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        let expires_at = now + ttl_secs;
        conn.execute(
            "INSERT OR REPLACE INTO engine_cache (label, data, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![label, data, now, expires_at],
        )?;
        Ok(())
    }

    pub fn cache_get(&self, label: &str) -> SqliteResult<Option<String>> {
        let conn = self.conn.read().unwrap();
        let now = chrono::Utc::now().timestamp();
        let result = conn.query_row(
            "SELECT data FROM engine_cache WHERE label = ?1 AND expires_at > ?2",
            params![label, now],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn cache_get_or_put<F>(&self, label: &str, ttl_secs: i64, compute: F) -> SqliteResult<String>
    where
        F: FnOnce() -> String,
    {
        if let Some(data) = self.cache_get(label)? {
            return Ok(data);
        }
        let data = compute();
        self.cache_put(label, &data, ttl_secs)?;
        Ok(data)
    }

    pub fn cache_stats(&self) -> SqliteResult<CacheStats> {
        let conn = self.conn.read().unwrap();
        let now = chrono::Utc::now().timestamp();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_cache", [], |row| row.get(0)
        )?;
        let expired: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_cache WHERE expires_at <= ?1", params![now], |row| row.get(0)
        )?;
        let active = total - expired;
        let oldest: Option<i64> = conn.query_row(
            "SELECT MIN(created_at) FROM engine_cache WHERE expires_at > ?1", params![now], |row| row.get(0)
        ).ok();
        let newest: Option<i64> = conn.query_row(
            "SELECT MAX(created_at) FROM engine_cache WHERE expires_at > ?1", params![now], |row| row.get(0)
        ).ok();
        Ok(CacheStats {
            total_entries: total as usize,
            active_entries: active as usize,
            expired_entries: expired as usize,
            oldest_created: oldest,
            newest_created: newest,
        })
    }

    pub fn cache_remove(&self, label: &str) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute("DELETE FROM engine_cache WHERE label = ?1", params![label])?;
        Ok(())
    }

    pub fn cache_cleanup(&self) -> SqliteResult<usize> {
        let conn = self.conn.write().unwrap();
        let now = chrono::Utc::now().timestamp();
        let count = conn.execute("DELETE FROM engine_cache WHERE expires_at <= ?1", params![now])?;
        Ok(count)
    }

    pub fn vacuum(&self) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute_batch("VACUUM;")?;
        Ok(())
    }

    pub fn analyze(&self) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute_batch("ANALYZE;")?;
        Ok(())
    }

    pub fn integrity_check(&self) -> SqliteResult<Vec<String>> {
        let conn = self.conn.write().unwrap();
        let mut stmt = conn.prepare("PRAGMA integrity_check")?;
        let results = stmt.query_map([], |row| {
            row.get::<_, String>(0)
        })?;
        results.collect()
    }

    pub fn get_database_stats(&self) -> SqliteResult<DatabaseStats> {
        let conn = self.conn.read().unwrap();

        let page_count: i64 = conn.query_row(
            "PRAGMA page_count", [], |row| row.get(0)
        )?;

        let page_size: i64 = conn.query_row(
            "PRAGMA page_size", [], |row| row.get(0)
        )?;

        let free_pages: i64 = conn.query_row(
            "PRAGMA freelist_count", [], |row| row.get(0)
        )?;

        let scan_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_scans", [], |row| row.get(0)
        )?;

        let event_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_events", [], |row| row.get(0)
        )?;

        let correlation_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_correlations", [], |row| row.get(0)
        )?;

        let cache_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_cache", [], |row| row.get(0)
        )?;

        let log_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM engine_scan_log", [], |row| row.get(0)
        )?;

        Ok(DatabaseStats {
            total_size_bytes: page_count * page_size,
            page_size,
            page_count,
            free_pages,
            scan_count: scan_count as usize,
            event_count: event_count as usize,
            correlation_count: correlation_count as usize,
            cache_count: cache_count as usize,
            log_count: log_count as usize,
        })
    }

    pub fn cleanup_old_scans(&self, max_age_days: i64) -> SqliteResult<usize> {
        let conn = self.conn.write().unwrap();
        let cutoff = chrono::Utc::now().timestamp() - (max_age_days * 86400);

        let old_scans: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT scan_id FROM engine_scans WHERE updated_at < ?1 AND status NOT IN ('running', 'starting', 'initializing')"
            )?;
            let results = stmt.query_map(params![cutoff], |row| {
                row.get::<_, String>(0)
            })?;
            results.collect::<SqliteResult<Vec<_>>>()?
        };

        let count = old_scans.len();
        drop(conn);

        for scan_id in &old_scans {
            self.delete_scan(scan_id)?;
        }

        Ok(count)
    }

    pub fn reindex(&self) -> SqliteResult<()> {
        let conn = self.conn.write().unwrap();
        conn.execute_batch("REINDEX;")?;
        Ok(())
    }

    // P3-9: Scan Instance List with Stats

    pub fn list_scans(&self) -> SqliteResult<Vec<ScanInstanceInfo>> {
        let conn = self.conn.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT s.scan_id, s.target_value, s.target_type, s.status, s.created_at, \
             COUNT(e.hash) AS total_events, \
             COUNT(DISTINCT e.data) AS unique_events, \
             COUNT(DISTINCT e.event_type) AS event_type_count, \
             COUNT(DISTINCT e.module) AS module_count, \
             (SELECT COUNT(*) FROM engine_correlations c WHERE c.scan_id = s.scan_id) AS correlation_count \
             FROM engine_scans s \
             LEFT JOIN engine_events e ON e.scan_id = s.scan_id \
             GROUP BY s.scan_id \
             ORDER BY s.created_at DESC"
        )?;
        let results = stmt.query_map([], |row| {
            Ok(ScanInstanceInfo {
                scan_id: row.get(0)?,
                target: row.get(1)?,
                target_type: row.get(2)?,
                status: row.get(3)?,
                started_at: row.get(4)?,
                total_events: row.get(5)?,
                unique_events: row.get(6)?,
                event_type_count: row.get(7)?,
                module_count: row.get(8)?,
                correlation_count: row.get(9)?,
            })
        })?;
        results.collect()
    }

    pub fn list_scans_paginated(&self, offset: usize, limit: usize, status_filter: Option<&str>) -> SqliteResult<PaginatedScanList> {
        let conn = self.conn.read().unwrap();

        let count_sql = match status_filter {
            Some(_) => "SELECT COUNT(*) FROM engine_scans WHERE status = ?1",
            None => "SELECT COUNT(*) FROM engine_scans",
        };

        let total: usize = if status_filter.is_some() {
            conn.query_row(count_sql, params![status_filter], |row| row.get(0))?
        } else {
            conn.query_row(count_sql, [], |row| row.get(0))?
        };

        let list_sql = match status_filter {
            Some(_) => {
                "SELECT s.scan_id, s.target_value, s.target_type, s.status, s.created_at, \
                 COALESCE(evs.total, 0) AS total_events, \
                 COALESCE(evs.unique_events, 0) AS unique_events, \
                 COALESCE(evs.type_count, 0) AS event_type_count, \
                 COALESCE(evs.module_count, 0) AS module_count, \
                 COALESCE(corr.cnt, 0) AS correlation_count \
                 FROM engine_scans s \
                 LEFT JOIN (SELECT scan_id, COUNT(*) as total, COUNT(DISTINCT data) as unique_events, COUNT(DISTINCT event_type) as type_count, COUNT(DISTINCT module) as module_count FROM engine_events GROUP BY scan_id) evs ON evs.scan_id = s.scan_id \
                 LEFT JOIN (SELECT scan_id, COUNT(*) as cnt FROM engine_correlations GROUP BY scan_id) corr ON corr.scan_id = s.scan_id \
                 WHERE s.status = ?1 \
                 ORDER BY s.created_at DESC LIMIT ?2 OFFSET ?3"
            }
            None => {
                "SELECT s.scan_id, s.target_value, s.target_type, s.status, s.created_at, \
                 COALESCE(evs.total, 0) AS total_events, \
                 COALESCE(evs.unique_events, 0) AS unique_events, \
                 COALESCE(evs.type_count, 0) AS event_type_count, \
                 COALESCE(evs.module_count, 0) AS module_count, \
                 COALESCE(corr.cnt, 0) AS correlation_count \
                 FROM engine_scans s \
                 LEFT JOIN (SELECT scan_id, COUNT(*) as total, COUNT(DISTINCT data) as unique_events, COUNT(DISTINCT event_type) as type_count, COUNT(DISTINCT module) as module_count FROM engine_events GROUP BY scan_id) evs ON evs.scan_id = s.scan_id \
                 LEFT JOIN (SELECT scan_id, COUNT(*) as cnt FROM engine_correlations GROUP BY scan_id) corr ON corr.scan_id = s.scan_id \
                 ORDER BY s.created_at DESC LIMIT ?1 OFFSET ?2"
            }
        };

        let mut stmt = conn.prepare(list_sql)?;
        let results: Vec<ScanInstanceInfo> = if let Some(sf) = status_filter {
            stmt.query_map(params![sf, limit as i64, offset as i64], |row| {
                Ok(ScanInstanceInfo {
                    scan_id: row.get(0)?,
                    target: row.get(1)?,
                    target_type: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    total_events: row.get(5)?,
                    unique_events: row.get(6)?,
                    event_type_count: row.get(7)?,
                    module_count: row.get(8)?,
                    correlation_count: row.get(9)?,
                })
            })?.collect::<SqliteResult<Vec<_>>>()?
        } else {
            stmt.query_map(params![limit as i64, offset as i64], |row| {
                Ok(ScanInstanceInfo {
                    scan_id: row.get(0)?,
                    target: row.get(1)?,
                    target_type: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    total_events: row.get(5)?,
                    unique_events: row.get(6)?,
                    event_type_count: row.get(7)?,
                    module_count: row.get(8)?,
                    correlation_count: row.get(9)?,
                })
            })?.collect::<SqliteResult<Vec<_>>>()?
        };

        Ok(PaginatedScanList {
            scans: results,
            total,
            offset,
            limit,
        })
    }

    fn row_to_event_ref(row: &rusqlite::Row) -> SqliteResult<BiosEventRef> {
        let event_type_str: String = row.get(0)?;
        let event_type = BiosEventType::from_str(&event_type_str)
            .unwrap_or(BiosEventType::Custom(event_type_str));
        let source_event_type_str: Option<String> = row.get(8)?;
        let source_event_type = source_event_type_str
            .as_deref()
            .and_then(BiosEventType::from_str);
        let store_only: i32 = row.get(10).unwrap_or(0);
        Ok(BiosEventRef {
            event_type,
            data: row.get(1)?,
            module: row.get(2)?,
            hash: row.get(3)?,
            confidence: row.get(4)?,
            visibility: row.get(5)?,
            risk: row.get(6)?,
            source_event_hash: row.get(7)?,
            source_event_type,
            source_event_data: row.get(9)?,
            store_only: store_only != 0,
        })
    }
}

pub struct EventTypeMeta {
    pub event: String,
    pub description: String,
    pub is_raw: bool,
    pub category: String,
}

pub struct ScanLogEntry {
    pub generated: i64,
    pub component: String,
    pub classification: String,
    pub message: String,
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResultSummaryEntry {
    pub key: String,
    pub description: String,
    pub last_seen: i64,
    pub total: usize,
    pub unique_total: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationSummaryEntry {
    pub key: String,
    pub description: String,
    pub total: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationListEntry {
    pub id: i64,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_risk: String,
    pub headline: String,
    pub description: String,
    pub created_at: i64,
    pub event_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SearchCriteria {
    pub scan_id: Option<String>,
    pub event_type: Option<String>,
    pub value: Option<String>,
    pub regex: Option<String>,
    pub filter_fp: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanInstanceInfo {
    pub scan_id: String,
    pub target: String,
    pub target_type: String,
    pub status: String,
    pub started_at: i64,
    pub total_events: usize,
    pub unique_events: usize,
    pub event_type_count: usize,
    pub module_count: usize,
    pub correlation_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaginatedScanList {
    pub scans: Vec<ScanInstanceInfo>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanTrendEntry {
    pub scan_id: String,
    pub status: String,
    pub created_at: i64,
    pub total_events: usize,
    pub event_type_count: usize,
    pub false_positive_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntityTrendEntry {
    pub scan_id: String,
    pub created_at: i64,
    pub event_type: String,
    pub data: String,
    pub count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceNode {
    pub event: BiosEventRef,
    pub children: Vec<ProvenanceNode>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseStats {
    pub total_size_bytes: i64,
    pub page_size: i64,
    pub page_count: i64,
    pub free_pages: i64,
    pub scan_count: usize,
    pub event_count: usize,
    pub correlation_count: usize,
    pub cache_count: usize,
    pub log_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub active_entries: usize,
    pub expired_entries: usize,
    pub oldest_created: Option<i64>,
    pub newest_created: Option<i64>,
}
