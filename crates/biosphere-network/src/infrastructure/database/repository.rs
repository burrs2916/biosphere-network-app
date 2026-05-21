use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use super::models::{ScanTask, ScanResultRecord, ScanTaskWithResults, Target, DnsQuery, PingRecord, TracerouteRecord, TracerouteHop, WhoisRecord, Task, TargetGroup, SecHeaderRecord, HashIdentifierRecord, IpGeoRecord, SslCheckRecord, SiteCheckRecord, WafDetectionRecord, ToolHistoryRecord, NetworkDiscoveryRecord, OsintPlatform, OsintScanResult};
use super::migrations::{get_all_migrations, get_version_migrations, SCHEMA_VERSION};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize()?;
        Ok(db)
    }

    pub fn in_memory() -> SqliteResult<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        
        for migration in get_all_migrations() {
            for stmt in migration.split(';') {
                let stmt = stmt.trim();
                if stmt.is_empty() { continue; }
                if let Err(e) = conn.execute(stmt, []) {
                    eprintln!("Init migration warning (may already exist): {}", e);
                }
            }
        }
        
        let version: i32 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        
        if version < SCHEMA_VERSION {
            let migrations = get_version_migrations(version, SCHEMA_VERSION);
            for migration in migrations {
                for stmt in migration.split(';') {
                    let stmt = stmt.trim();
                    if stmt.is_empty() { continue; }
                    if let Err(e) = conn.execute(stmt, []) {
                        eprintln!("Migration warning (column/table may already exist): {}", e);
                    }
                }
            }
            
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [SCHEMA_VERSION],
            )?;
        }
        
        Ok(())
    }

    pub fn create_scan_task(&self, task: &ScanTask) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO scan_tasks (target, scan_mode, start_time, end_time, status, total_ports, open_ports, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &task.target,
                &task.scan_mode,
                &task.start_time.to_rfc3339(),
                &task.end_time.map(|t| t.to_rfc3339()),
                &task.status,
                &task.total_ports,
                &task.open_ports,
                &task.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn update_scan_task(&self, task: &ScanTask) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "UPDATE scan_tasks 
             SET end_time = ?1, status = ?2, total_ports = ?3, open_ports = ?4
             WHERE id = ?5",
            rusqlite::params![
                &task.end_time.map(|t| t.to_rfc3339()),
                &task.status,
                &task.total_ports,
                &task.open_ports,
                &task.id,
            ],
        )?;
        
        Ok(())
    }

    pub fn create_scan_result(&self, result: &ScanResultRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO scan_results (task_id, target, port, status, service, version, banner, os_detection, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &result.task_id,
                &result.target,
                &result.port,
                &result.status,
                &result.service,
                &result.version,
                &result.banner,
                &result.os_detection,
                &result.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn create_scan_results_batch(&self, results: &[ScanResultRecord]) -> SqliteResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        
        for result in results {
            tx.execute(
                "INSERT INTO scan_results (task_id, target, port, status, service, version, banner, os_detection, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    &result.task_id,
                    &result.target,
                    &result.port,
                    &result.status,
                    &result.service,
                    &result.version,
                    &result.banner,
                    &result.os_detection,
                    &result.created_at.to_rfc3339(),
                ],
            )?;
        }
        
        tx.commit()?;
        Ok(())
    }

    pub fn get_scan_tasks(&self, limit: i32, offset: i32) -> SqliteResult<Vec<ScanTask>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, target, scan_mode, start_time, end_time, status, total_ports, open_ports, created_at
             FROM scan_tasks
             ORDER BY start_time DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let tasks = stmt.query_map([limit, offset], |row| {
            Ok(ScanTask {
                id: Some(row.get(0)?),
                target: row.get(1)?,
                scan_mode: row.get(2)?,
                start_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                end_time: row.get::<_, Option<String>>(4)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                status: row.get(5)?,
                total_ports: row.get(6)?,
                open_ports: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        tasks
    }

    pub fn get_scan_task_by_id(&self, id: i64) -> SqliteResult<Option<ScanTask>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, target, scan_mode, start_time, end_time, status, total_ports, open_ports, created_at
             FROM scan_tasks
             WHERE id = ?1"
        )?;
        
        let task = stmt.query_row([id], |row| {
            Ok(ScanTask {
                id: Some(row.get(0)?),
                target: row.get(1)?,
                scan_mode: row.get(2)?,
                start_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                end_time: row.get::<_, Option<String>>(4)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                status: row.get(5)?,
                total_ports: row.get(6)?,
                open_ports: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        }).ok();
        
        Ok(task)
    }

    pub fn get_scan_results_by_task_id(&self, task_id: i64) -> SqliteResult<Vec<ScanResultRecord>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, task_id, target, port, status, service, version, banner, os_detection, created_at
             FROM scan_results
             WHERE task_id = ?1
             ORDER BY port"
        )?;
        
        let results = stmt.query_map([task_id], |row| {
            Ok(ScanResultRecord {
                id: Some(row.get(0)?),
                task_id: row.get(1)?,
                target: row.get(2)?,
                port: row.get(3)?,
                status: row.get(4)?,
                service: row.get(5)?,
                version: row.get(6)?,
                banner: row.get(7)?,
                os_detection: row.get(8)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        results
    }

    pub fn get_scan_task_with_results(&self, id: i64) -> SqliteResult<Option<ScanTaskWithResults>> {
        let task = self.get_scan_task_by_id(id)?;
        
        if let Some(task) = task {
            let results = self.get_scan_results_by_task_id(id)?;
            Ok(Some(ScanTaskWithResults { task, results }))
        } else {
            Ok(None)
        }
    }

    pub fn delete_scan_task(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM scan_tasks WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn count_scan_tasks(&self) -> SqliteResult<i32> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn.query_row("SELECT COUNT(*) FROM scan_tasks", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn count_targets(&self) -> SqliteResult<i32> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn.query_row("SELECT COUNT(*) FROM targets WHERE is_active = 1", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn search_scan_tasks(&self, query: &str, limit: i32, offset: i32) -> SqliteResult<Vec<ScanTask>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, target, scan_mode, start_time, end_time, status, total_ports, open_ports, created_at
             FROM scan_tasks
             WHERE target LIKE ?1 OR scan_mode LIKE ?1
             ORDER BY start_time DESC
             LIMIT ?2 OFFSET ?3"
        )?;
        
        let search_pattern = format!("%{}%", query);
        
        let tasks = stmt.query_map([&search_pattern, &limit.to_string(), &offset.to_string()], |row| {
            Ok(ScanTask {
                id: Some(row.get(0)?),
                target: row.get(1)?,
                scan_mode: row.get(2)?,
                start_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                end_time: row.get::<_, Option<String>>(4)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                status: row.get(5)?,
                total_ports: row.get(6)?,
                open_ports: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        tasks
    }

    pub fn create_target(&self, target: &Target) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO targets (name, target_type, target_value, description, tags, location, organization, created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level, priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans, open_ports_count, vulnerabilities_count, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
            rusqlite::params![
                &target.name,
                &target.target_type,
                &target.target_value,
                &target.description,
                &target.tags,
                &target.location,
                &target.organization,
                &target.created_at.to_rfc3339(),
                &target.updated_at.to_rfc3339(),
                &target.last_scanned_at.map(|t| t.to_rfc3339()),
                target.is_active as i32,
                &target.group_id,
                &target.status,
                &target.risk_level,
                &target.priority,
                &target.owner,
                &target.contact,
                target.auto_scan as i32,
                &target.scan_interval,
                &target.next_scan_at.map(|t| t.to_rfc3339()),
                target.total_scans,
                target.open_ports_count,
                target.vulnerabilities_count,
                &target.metadata,
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn update_target(&self, target: &Target) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "UPDATE targets 
             SET name = ?1, target_type = ?2, target_value = ?3, description = ?4, tags = ?5, 
                 location = ?6, organization = ?7, updated_at = ?8, last_scanned_at = ?9, is_active = ?10,
                 group_id = ?11, status = ?12, risk_level = ?13, priority = ?14, owner = ?15, 
                 contact = ?16, auto_scan = ?17, scan_interval = ?18, next_scan_at = ?19, 
                 total_scans = ?20, open_ports_count = ?21, vulnerabilities_count = ?22, metadata = ?23
             WHERE id = ?24",
            rusqlite::params![
                &target.name,
                &target.target_type,
                &target.target_value,
                &target.description,
                &target.tags,
                &target.location,
                &target.organization,
                &target.updated_at.to_rfc3339(),
                &target.last_scanned_at.map(|t| t.to_rfc3339()),
                target.is_active as i32,
                &target.group_id,
                &target.status,
                &target.risk_level,
                &target.priority,
                &target.owner,
                &target.contact,
                target.auto_scan as i32,
                &target.scan_interval,
                &target.next_scan_at.map(|t| t.to_rfc3339()),
                target.total_scans,
                target.open_ports_count,
                target.vulnerabilities_count,
                &target.metadata,
                &target.id,
            ],
        )?;
        
        Ok(())
    }

    pub fn get_targets(&self, limit: i32, offset: i32) -> SqliteResult<Vec<Target>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, name, target_type, target_value, description, tags, location, organization, 
                    created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level,
                    priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans,
                    open_ports_count, vulnerabilities_count, metadata
             FROM targets
             WHERE is_active = 1
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let targets = stmt.query_map([limit, offset], |row| {
            Ok(Target {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                target_type: row.get(2)?,
                target_value: row.get(3)?,
                description: row.get(4)?,
                tags: row.get(5)?,
                location: row.get(6)?,
                organization: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_scanned_at: row.get::<_, Option<String>>(10)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                is_active: row.get::<_, i32>(11)? == 1,
                group_id: row.get(12)?,
                status: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "new".to_string()),
                risk_level: row.get::<_, Option<String>>(14)?.unwrap_or_else(|| "none".to_string()),
                priority: row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "normal".to_string()),
                owner: row.get(16)?,
                contact: row.get(17)?,
                auto_scan: row.get::<_, Option<i32>>(18)?.unwrap_or(0) == 1,
                scan_interval: row.get(19)?,
                next_scan_at: row.get::<_, Option<String>>(20)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                total_scans: row.get::<_, Option<i32>>(21)?.unwrap_or(0),
                open_ports_count: row.get::<_, Option<i32>>(22)?.unwrap_or(0),
                vulnerabilities_count: row.get::<_, Option<i32>>(23)?.unwrap_or(0),
                metadata: row.get(24)?,
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        targets
    }

    pub fn get_targets_by_group(&self, group_id: i64, limit: i32, offset: i32) -> SqliteResult<Vec<Target>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, name, target_type, target_value, description, tags, location, organization, 
                    created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level,
                    priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans,
                    open_ports_count, vulnerabilities_count, metadata
             FROM targets
             WHERE is_active = 1 AND group_id = ?1
             ORDER BY created_at DESC
             LIMIT ?2 OFFSET ?3"
        )?;
        
        let targets = stmt.query_map(rusqlite::params![group_id, limit, offset], |row| {
            Ok(Target {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                target_type: row.get(2)?,
                target_value: row.get(3)?,
                description: row.get(4)?,
                tags: row.get(5)?,
                location: row.get(6)?,
                organization: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_scanned_at: row.get::<_, Option<String>>(10)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                is_active: row.get::<_, i32>(11)? == 1,
                group_id: row.get(12)?,
                status: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "new".to_string()),
                risk_level: row.get::<_, Option<String>>(14)?.unwrap_or_else(|| "none".to_string()),
                priority: row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "normal".to_string()),
                owner: row.get(16)?,
                contact: row.get(17)?,
                auto_scan: row.get::<_, Option<i32>>(18)?.unwrap_or(0) == 1,
                scan_interval: row.get(19)?,
                next_scan_at: row.get::<_, Option<String>>(20)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                total_scans: row.get::<_, Option<i32>>(21)?.unwrap_or(0),
                open_ports_count: row.get::<_, Option<i32>>(22)?.unwrap_or(0),
                vulnerabilities_count: row.get::<_, Option<i32>>(23)?.unwrap_or(0),
                metadata: row.get(24)?,
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        targets
    }

    pub fn get_targets_count(&self) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM targets WHERE is_active = 1",
            [],
            |row| row.get(0)
        )?;
        
        Ok(count)
    }

    pub fn get_targets_count_by_group(&self, group_id: i64) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM targets WHERE is_active = 1 AND group_id = ?1",
            [group_id],
            |row| row.get(0)
        )?;
        
        Ok(count)
    }

    pub fn get_targets_filtered(
        &self,
        target_type: Option<&str>,
        status: Option<&str>,
        risk_level: Option<&str>,
        priority: Option<&str>,
        tag: Option<&str>,
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> SqliteResult<Vec<Target>> {
        let conn = self.conn.lock().unwrap();

        let mut conditions = vec!["is_active = 1".to_string()];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(tt) = target_type {
            if !tt.is_empty() {
                conditions.push(format!("target_type = ?{}", conditions.len() + 1));
                params.push(Box::new(tt.to_string()));
            }
        }
        if let Some(s) = status {
            if !s.is_empty() {
                conditions.push(format!("status = ?{}", conditions.len() + 1));
                params.push(Box::new(s.to_string()));
            }
        }
        if let Some(rl) = risk_level {
            if !rl.is_empty() {
                conditions.push(format!("risk_level = ?{}", conditions.len() + 1));
                params.push(Box::new(rl.to_string()));
            }
        }
        if let Some(p) = priority {
            if !p.is_empty() {
                conditions.push(format!("priority = ?{}", conditions.len() + 1));
                params.push(Box::new(p.to_string()));
            }
        }
        if let Some(t) = tag {
            if !t.is_empty() {
                conditions.push(format!("tags LIKE ?{}", conditions.len() + 1));
                params.push(Box::new(format!("%{}%", t)));
            }
        }

        let where_clause = conditions.join(" AND ");

        let order_col = match sort_by.unwrap_or("created_at") {
            "name" => "name",
            "last_scanned_at" => "last_scanned_at",
            "risk_level" => "risk_level",
            "priority" => "priority",
            "total_scans" => "total_scans",
            _ => "created_at",
        };
        let order_dir = match sort_order.unwrap_or("DESC") {
            "ASC" | "asc" => "ASC",
            _ => "DESC",
        };

        let sql = format!(
            "SELECT id, name, target_type, target_value, description, tags, location, organization, 
                    created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level,
                    priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans,
                    open_ports_count, vulnerabilities_count, metadata
             FROM targets
             WHERE {}
             ORDER BY {} {}
             LIMIT ?{} OFFSET ?{}",
            where_clause, order_col, order_dir,
            conditions.len() + 1,
            conditions.len() + 2,
        );

        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let targets = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(Target {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                target_type: row.get(2)?,
                target_value: row.get(3)?,
                description: row.get(4)?,
                tags: row.get(5)?,
                location: row.get(6)?,
                organization: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_scanned_at: row.get::<_, Option<String>>(10)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                is_active: row.get::<_, i32>(11)? == 1,
                group_id: row.get(12)?,
                status: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "new".to_string()),
                risk_level: row.get::<_, Option<String>>(14)?.unwrap_or_else(|| "none".to_string()),
                priority: row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "normal".to_string()),
                owner: row.get(16)?,
                contact: row.get(17)?,
                auto_scan: row.get::<_, Option<i32>>(18)?.unwrap_or(0) == 1,
                scan_interval: row.get(19)?,
                next_scan_at: row.get::<_, Option<String>>(20)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                total_scans: row.get::<_, Option<i32>>(21)?.unwrap_or(0),
                open_ports_count: row.get::<_, Option<i32>>(22)?.unwrap_or(0),
                vulnerabilities_count: row.get::<_, Option<i32>>(23)?.unwrap_or(0),
                metadata: row.get(24)?,
            })
        })?.collect::<SqliteResult<Vec<_>>>();

        targets
    }

    pub fn get_targets_filtered_count(
        &self,
        target_type: Option<&str>,
        status: Option<&str>,
        risk_level: Option<&str>,
        priority: Option<&str>,
        tag: Option<&str>,
    ) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();

        let mut conditions = vec!["is_active = 1".to_string()];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(tt) = target_type {
            if !tt.is_empty() {
                conditions.push(format!("target_type = ?{}", conditions.len() + 1));
                params.push(Box::new(tt.to_string()));
            }
        }
        if let Some(s) = status {
            if !s.is_empty() {
                conditions.push(format!("status = ?{}", conditions.len() + 1));
                params.push(Box::new(s.to_string()));
            }
        }
        if let Some(rl) = risk_level {
            if !rl.is_empty() {
                conditions.push(format!("risk_level = ?{}", conditions.len() + 1));
                params.push(Box::new(rl.to_string()));
            }
        }
        if let Some(p) = priority {
            if !p.is_empty() {
                conditions.push(format!("priority = ?{}", conditions.len() + 1));
                params.push(Box::new(p.to_string()));
            }
        }
        if let Some(t) = tag {
            if !t.is_empty() {
                conditions.push(format!("tags LIKE ?{}", conditions.len() + 1));
                params.push(Box::new(format!("%{}%", t)));
            }
        }

        let where_clause = conditions.join(" AND ");
        let sql = format!("SELECT COUNT(*) FROM targets WHERE {}", where_clause);

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let count: i64 = conn.query_row(&sql, param_refs.as_slice(), |row| row.get(0))?;
        Ok(count)
    }

    pub fn batch_update_target_group(&self, target_ids: &[i64], group_id: Option<i64>) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        for id in target_ids {
            conn.execute(
                "UPDATE targets SET group_id = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![group_id, &now, id],
            )?;
        }
        Ok(())
    }

    pub fn batch_update_target_tags(&self, target_ids: &[i64], tags: &str, append: bool) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();

        for id in target_ids {
            if append {
                conn.execute(
                    "UPDATE targets SET tags = CASE WHEN tags IS NULL OR tags = '' THEN ?1 ELSE tags || ',' || ?1 END, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![tags, &now, id],
                )?;
            } else {
                conn.execute(
                    "UPDATE targets SET tags = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![tags, &now, id],
                )?;
            }
        }
        Ok(())
    }

    pub fn get_scan_tasks_by_target(&self, target_value: &str, limit: i32, offset: i32) -> SqliteResult<Vec<ScanTask>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, target, scan_mode, start_time, end_time, status, total_ports, open_ports, created_at
             FROM scan_tasks
             WHERE target = ?1
             ORDER BY created_at DESC
             LIMIT ?2 OFFSET ?3"
        )?;

        let tasks = stmt.query_map(rusqlite::params![target_value, limit, offset], |row| {
            Ok(ScanTask {
                id: Some(row.get(0)?),
                target: row.get(1)?,
                scan_mode: row.get(2)?,
                start_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                end_time: row.get::<_, Option<String>>(4)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                status: row.get(5)?,
                total_ports: row.get(6)?,
                open_ports: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();

        tasks
    }

    pub fn get_target_statistics(&self) -> SqliteResult<serde_json::Value> {
        let conn = self.conn.lock().unwrap();

        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM targets WHERE is_active = 1", [], |row| row.get(0)
        )?;

        let by_type: Vec<serde_json::Value> = {
            let mut stmt = conn.prepare(
                "SELECT target_type, COUNT(*) as cnt FROM targets WHERE is_active = 1 GROUP BY target_type ORDER BY cnt DESC"
            )?;
            let rows: Vec<(String, i64)> = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?.filter_map(|r| r.ok()).collect();
            rows.into_iter().map(|(t, c)| serde_json::json!({"type": t, "count": c})).collect()
        };

        let by_risk: Vec<serde_json::Value> = {
            let mut stmt = conn.prepare(
                "SELECT risk_level, COUNT(*) as cnt FROM targets WHERE is_active = 1 GROUP BY risk_level ORDER BY cnt DESC"
            )?;
            let rows: Vec<(String, i64)> = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?.filter_map(|r| r.ok()).collect();
            rows.into_iter().map(|(l, c)| serde_json::json!({"level": l, "count": c})).collect()
        };

        let by_status: Vec<serde_json::Value> = {
            let mut stmt = conn.prepare(
                "SELECT status, COUNT(*) as cnt FROM targets WHERE is_active = 1 GROUP BY status ORDER BY cnt DESC"
            )?;
            let rows: Vec<(String, i64)> = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?.filter_map(|r| r.ok()).collect();
            rows.into_iter().map(|(s, c)| serde_json::json!({"status": s, "count": c})).collect()
        };

        Ok(serde_json::json!({
            "total": total,
            "by_type": by_type,
            "by_risk": by_risk,
            "by_status": by_status
        }))
    }

    pub fn get_target_by_value(&self, target_value: &str) -> SqliteResult<Option<Target>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, name, target_type, target_value, description, tags, location, organization, 
                    created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level,
                    priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans,
                    open_ports_count, vulnerabilities_count, metadata
             FROM targets
             WHERE target_value = ?1"
        )?;
        
        let target = stmt.query_row([target_value], |row| {
            Ok(Target {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                target_type: row.get(2)?,
                target_value: row.get(3)?,
                description: row.get(4)?,
                tags: row.get(5)?,
                location: row.get(6)?,
                organization: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_scanned_at: row.get::<_, Option<String>>(10)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                is_active: row.get::<_, i32>(11)? == 1,
                group_id: row.get(12)?,
                status: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "new".to_string()),
                risk_level: row.get::<_, Option<String>>(14)?.unwrap_or_else(|| "none".to_string()),
                priority: row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "normal".to_string()),
                owner: row.get(16)?,
                contact: row.get(17)?,
                auto_scan: row.get::<_, Option<i32>>(18)?.unwrap_or(0) == 1,
                scan_interval: row.get(19)?,
                next_scan_at: row.get::<_, Option<String>>(20)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                total_scans: row.get::<_, Option<i32>>(21)?.unwrap_or(0),
                open_ports_count: row.get::<_, Option<i32>>(22)?.unwrap_or(0),
                vulnerabilities_count: row.get::<_, Option<i32>>(23)?.unwrap_or(0),
                metadata: row.get(24)?,
            })
        }).ok();
        
        Ok(target)
    }

    pub fn get_target_by_id(&self, id: i64) -> SqliteResult<Option<Target>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, name, target_type, target_value, description, tags, location, organization, 
                    created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level,
                    priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans,
                    open_ports_count, vulnerabilities_count, metadata
             FROM targets
             WHERE id = ?1"
        )?;
        
        let target = stmt.query_row([id], |row| {
            Ok(Target {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                target_type: row.get(2)?,
                target_value: row.get(3)?,
                description: row.get(4)?,
                tags: row.get(5)?,
                location: row.get(6)?,
                organization: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_scanned_at: row.get::<_, Option<String>>(10)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                is_active: row.get::<_, i32>(11)? == 1,
                group_id: row.get(12)?,
                status: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "new".to_string()),
                risk_level: row.get::<_, Option<String>>(14)?.unwrap_or_else(|| "none".to_string()),
                priority: row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "normal".to_string()),
                owner: row.get(16)?,
                contact: row.get(17)?,
                auto_scan: row.get::<_, Option<i32>>(18)?.unwrap_or(0) == 1,
                scan_interval: row.get(19)?,
                next_scan_at: row.get::<_, Option<String>>(20)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                total_scans: row.get::<_, Option<i32>>(21)?.unwrap_or(0),
                open_ports_count: row.get::<_, Option<i32>>(22)?.unwrap_or(0),
                vulnerabilities_count: row.get::<_, Option<i32>>(23)?.unwrap_or(0),
                metadata: row.get(24)?,
            })
        }).ok();
        
        Ok(target)
    }

    pub fn delete_target(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM targets WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn search_targets(&self, query: &str, limit: i32, offset: i32) -> SqliteResult<Vec<Target>> {
        let conn = self.conn.lock().unwrap();
        
        let search_pattern = format!("%{}%", query);
        
        let mut stmt = conn.prepare(
            "SELECT id, name, target_type, target_value, description, tags, location, organization, 
                    created_at, updated_at, last_scanned_at, is_active, group_id, status, risk_level,
                    priority, owner, contact, auto_scan, scan_interval, next_scan_at, total_scans,
                    open_ports_count, vulnerabilities_count, metadata
             FROM targets
             WHERE is_active = 1 AND (
                 name LIKE ?1 OR 
                 target_value LIKE ?1 OR 
                 description LIKE ?1 OR 
                 tags LIKE ?1 OR 
                 location LIKE ?1 OR 
                 organization LIKE ?1
             )
             ORDER BY created_at DESC
             LIMIT ?2 OFFSET ?3"
        )?;
        
        let targets = stmt.query_map(rusqlite::params![&search_pattern, limit, offset], |row| {
            Ok(Target {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                target_type: row.get(2)?,
                target_value: row.get(3)?,
                description: row.get(4)?,
                tags: row.get(5)?,
                location: row.get(6)?,
                organization: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                last_scanned_at: row.get::<_, Option<String>>(10)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                is_active: row.get::<_, i32>(11)? == 1,
                group_id: row.get(12)?,
                status: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "new".to_string()),
                risk_level: row.get::<_, Option<String>>(14)?.unwrap_or_else(|| "none".to_string()),
                priority: row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "normal".to_string()),
                owner: row.get(16)?,
                contact: row.get(17)?,
                auto_scan: row.get::<_, Option<i32>>(18)?.unwrap_or(0) == 1,
                scan_interval: row.get(19)?,
                next_scan_at: row.get::<_, Option<String>>(20)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                total_scans: row.get::<_, Option<i32>>(21)?.unwrap_or(0),
                open_ports_count: row.get::<_, Option<i32>>(22)?.unwrap_or(0),
                vulnerabilities_count: row.get::<_, Option<i32>>(23)?.unwrap_or(0),
                metadata: row.get(24)?,
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        targets
    }

    pub fn create_dns_query(&self, query: &DnsQuery) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO dns_queries (target_id, query_domain, query_type, dns_server, query_time, ttl, result, raw_response, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &query.target_id,
                &query.query_domain,
                &query.query_type,
                &query.dns_server,
                &query.query_time,
                &query.ttl,
                &query.result,
                &query.raw_response,
                &query.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn get_dns_queries(&self, limit: i32, offset: i32) -> SqliteResult<Vec<DnsQuery>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, target_id, query_domain, query_type, dns_server, query_time, ttl, result, raw_response, created_at
             FROM dns_queries
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let queries = stmt.query_map([limit, offset], |row| {
            Ok(DnsQuery {
                id: Some(row.get(0)?),
                target_id: row.get(1)?,
                query_domain: row.get(2)?,
                query_type: row.get(3)?,
                dns_server: row.get(4)?,
                query_time: row.get(5)?,
                ttl: row.get(6)?,
                result: row.get(7)?,
                raw_response: row.get(8)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        queries
    }

    pub fn delete_dns_query(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM dns_queries WHERE id = ?1",
            [id],
        )?;
        Ok(())
    }

    pub fn clear_dns_queries(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM dns_queries",
            [],
        )?;
        Ok(())
    }

    pub fn create_ping_record(&self, record: &PingRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO ping_records (target_id, target_host, packet_sent, packet_received, packet_loss, min_rtt, max_rtt, avg_rtt, std_dev_rtt, status, error_message, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                &record.target_id,
                &record.target_host,
                &record.packet_sent,
                &record.packet_received,
                &record.packet_loss,
                &record.min_rtt,
                &record.max_rtt,
                &record.avg_rtt,
                &record.std_dev_rtt,
                &record.status,
                &record.error_message,
                &record.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn get_ping_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<PingRecord>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, target_id, target_host, packet_sent, packet_received, packet_loss, min_rtt, max_rtt, avg_rtt, std_dev_rtt, status, error_message, created_at
             FROM ping_records
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let records = stmt.query_map([limit, offset], |row| {
            Ok(PingRecord {
                id: Some(row.get(0)?),
                target_id: row.get(1)?,
                target_host: row.get(2)?,
                packet_sent: row.get(3)?,
                packet_received: row.get(4)?,
                packet_loss: row.get(5)?,
                min_rtt: row.get(6)?,
                max_rtt: row.get(7)?,
                avg_rtt: row.get(8)?,
                std_dev_rtt: row.get(9)?,
                status: row.get(10)?,
                error_message: row.get(11)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(12)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        records
    }

    pub fn delete_ping_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM ping_records WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn clear_ping_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM ping_records", [])?;
        Ok(())
    }

    pub fn create_traceroute_record(&self, record: &TracerouteRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO traceroute_records (target_id, target_host, max_hops, total_hops, destination_reached, result, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &record.target_id,
                &record.target_host,
                &record.max_hops,
                &record.total_hops,
                record.destination_reached as i32,
                &record.result,
                &record.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn create_traceroute_hop(&self, hop: &TracerouteHop) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO traceroute_hops (traceroute_id, hop_number, ip_address, hostname, rtt1, rtt2, rtt3, avg_rtt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &hop.traceroute_id,
                &hop.hop_number,
                &hop.ip_address,
                &hop.hostname,
                &hop.rtt1,
                &hop.rtt2,
                &hop.rtt3,
                &hop.avg_rtt,
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn create_whois_record(&self, record: &WhoisRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO whois_records (target_id, query_target, query_type, registrar, registrant_name, registrant_email, registrant_org, created_date, expiration_date, updated_date, name_servers, raw_data, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                &record.target_id,
                &record.query_target,
                &record.query_type,
                &record.registrar,
                &record.registrant_name,
                &record.registrant_email,
                &record.registrant_org,
                &record.created_date,
                &record.expiration_date,
                &record.updated_date,
                &record.name_servers,
                &record.raw_data,
                &record.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn get_whois_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<WhoisRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target_id, query_target, query_type, registrar, registrant_name, registrant_email, registrant_org, created_date, expiration_date, updated_date, name_servers, raw_data, created_at FROM whois_records ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        )?;
        let records = stmt.query_map(rusqlite::params![limit, offset], |row| {
            let created_at_str: String = row.get(13)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(WhoisRecord {
                id: row.get(0)?,
                target_id: row.get(1)?,
                query_target: row.get(2)?,
                query_type: row.get(3)?,
                registrar: row.get(4)?,
                registrant_name: row.get(5)?,
                registrant_email: row.get(6)?,
                registrant_org: row.get(7)?,
                created_date: row.get(8)?,
                expiration_date: row.get(9)?,
                updated_date: row.get(10)?,
                name_servers: row.get(11)?,
                raw_data: row.get(12)?,
                created_at,
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn delete_whois_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM whois_records WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn clear_whois_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM whois_records", [])?;
        Ok(())
    }

    pub fn create_task(&self, task: &Task) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO tasks (task_type, target_id, status, progress, result_summary, error_message, start_time, end_time, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                &task.task_type,
                &task.target_id,
                &task.status,
                &task.progress,
                &task.result_summary,
                &task.error_message,
                &task.start_time.to_rfc3339(),
                &task.end_time.map(|t| t.to_rfc3339()),
                &task.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn update_task(&self, task: &Task) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "UPDATE tasks 
             SET status = ?1, progress = ?2, result_summary = ?3, error_message = ?4, end_time = ?5
             WHERE id = ?6",
            rusqlite::params![
                &task.status,
                &task.progress,
                &task.result_summary,
                &task.error_message,
                &task.end_time.map(|t| t.to_rfc3339()),
                &task.id,
            ],
        )?;
        
        Ok(())
    }

    pub fn get_tasks(&self, limit: i32, offset: i32) -> SqliteResult<Vec<Task>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, task_type, target_id, status, progress, result_summary, error_message, start_time, end_time, created_at
             FROM tasks
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let tasks = stmt.query_map([limit, offset], |row| {
            Ok(Task {
                id: Some(row.get(0)?),
                task_type: row.get(1)?,
                target_id: row.get(2)?,
                status: row.get(3)?,
                progress: row.get(4)?,
                result_summary: row.get(5)?,
                error_message: row.get(6)?,
                start_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                end_time: row.get::<_, Option<String>>(8)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        tasks
    }

    pub fn create_target_group(&self, group: &TargetGroup) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO target_groups (name, description, target_ids, tags, color, created_at, updated_at, parent_id, icon, target_count, active_count, risk_count, default_scan_config, auto_scan, scan_interval, owner, is_public, shared_with)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            rusqlite::params![
                &group.name,
                &group.description,
                &group.target_ids,
                &group.tags,
                &group.color,
                &group.created_at.to_rfc3339(),
                &group.updated_at.map(|t: chrono::DateTime<chrono::Utc>| t.to_rfc3339()),
                &group.parent_id,
                &group.icon,
                group.target_count,
                group.active_count,
                group.risk_count,
                &group.default_scan_config,
                group.auto_scan as i32,
                &group.scan_interval,
                &group.owner,
                group.is_public as i32,
                &group.shared_with,
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn get_target_groups(&self, limit: i32, offset: i32) -> SqliteResult<Vec<TargetGroup>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, name, description, target_ids, tags, color, created_at, updated_at, icon,
                    (SELECT COUNT(*) FROM targets WHERE group_id = target_groups.id AND is_active = 1) as target_count
             FROM target_groups
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let groups = stmt.query_map([limit, offset], |row| {
            Ok(TargetGroup {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                description: row.get(2)?,
                target_ids: row.get(3)?,
                tags: row.get(4)?,
                color: row.get(5)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                updated_at: row.get::<_, Option<String>>(7)?.and_then(|t| {
                    DateTime::parse_from_rfc3339(&t)
                        .map(|dt| dt.with_timezone(&Utc))
                        .ok()
                }),
                parent_id: None,
                icon: row.get(8)?,
                target_count: row.get(9)?,
                active_count: 0,
                risk_count: 0,
                default_scan_config: None,
                auto_scan: false,
                scan_interval: None,
                owner: None,
                is_public: true,
                shared_with: None,
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        groups
    }

    pub fn update_target_group(&self, group: &TargetGroup) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "UPDATE target_groups 
             SET name = ?1, description = ?2, target_ids = ?3, tags = ?4, color = ?5, updated_at = ?6,
                 parent_id = ?7, icon = ?8, target_count = ?9, active_count = ?10, risk_count = ?11,
                 default_scan_config = ?12, auto_scan = ?13, scan_interval = ?14, owner = ?15,
                 is_public = ?16, shared_with = ?17
             WHERE id = ?18",
            rusqlite::params![
                &group.name,
                &group.description,
                &group.target_ids,
                &group.tags,
                &group.color,
                &Utc::now().to_rfc3339(),
                &group.parent_id,
                &group.icon,
                group.target_count,
                group.active_count,
                group.risk_count,
                &group.default_scan_config,
                group.auto_scan as i32,
                &group.scan_interval,
                &group.owner,
                group.is_public as i32,
                &group.shared_with,
                &group.id,
            ],
        )?;
        
        Ok(())
    }

    pub fn delete_target_group(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM target_groups WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn create_sec_header_record(&self, record: &SecHeaderRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO sec_header_records (url, score, grade, present_count, missing_count, summary, result, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &record.url,
                &record.score,
                &record.grade,
                &record.present_count,
                &record.missing_count,
                &record.summary,
                &record.result,
                &record.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn get_sec_header_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<SecHeaderRecord>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, url, score, grade, present_count, missing_count, summary, result, created_at
             FROM sec_header_records
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let records = stmt.query_map([limit, offset], |row| {
            Ok(SecHeaderRecord {
                id: Some(row.get(0)?),
                url: row.get(1)?,
                score: row.get(2)?,
                grade: row.get(3)?,
                present_count: row.get(4)?,
                missing_count: row.get(5)?,
                summary: row.get(6)?,
                result: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        records
    }

    pub fn delete_sec_header_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sec_header_records WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn clear_sec_header_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sec_header_records", [])?;
        Ok(())
    }

    pub fn create_hash_identifier_record(&self, record: &HashIdentifierRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        
        conn.execute(
            "INSERT INTO hash_identifier_records (hash_value, possible_types, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                &record.hash_value,
                &record.possible_types,
                &record.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(conn.last_insert_rowid())
    }

    pub fn get_hash_identifier_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<HashIdentifierRecord>> {
        let conn = self.conn.lock().unwrap();
        
        let mut stmt = conn.prepare(
            "SELECT id, hash_value, possible_types, created_at
             FROM hash_identifier_records
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        
        let records = stmt.query_map([limit, offset], |row| {
            Ok(HashIdentifierRecord {
                id: Some(row.get(0)?),
                hash_value: row.get(1)?,
                possible_types: row.get(2)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();
        
        records
    }

    pub fn delete_hash_identifier_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM hash_identifier_records WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn clear_hash_identifier_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM hash_identifier_records", [])?;
        Ok(())
    }

    pub fn create_ip_geo_record(&self, record: &IpGeoRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO ip_geo_records (ip, country, country_code, region, city, latitude, longitude, isp, org, timezone, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &record.ip,
                &record.country,
                &record.country_code,
                &record.region,
                &record.city,
                &record.latitude,
                &record.longitude,
                &record.isp,
                &record.org,
                &record.timezone,
                &record.created_at.to_rfc3339(),
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn get_ip_geo_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<IpGeoRecord>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, ip, country, country_code, region, city, latitude, longitude, isp, org, timezone, created_at
             FROM ip_geo_records
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;

        let records = stmt.query_map([limit, offset], |row| {
            Ok(IpGeoRecord {
                id: Some(row.get(0)?),
                ip: row.get(1)?,
                country: row.get(2)?,
                country_code: row.get(3)?,
                region: row.get(4)?,
                city: row.get(5)?,
                latitude: row.get(6)?,
                longitude: row.get(7)?,
                isp: row.get(8)?,
                org: row.get(9)?,
                timezone: row.get(10)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(11)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>();

        records
    }

    pub fn delete_ip_geo_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM ip_geo_records WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn clear_ip_geo_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM ip_geo_records", [])?;
        Ok(())
    }

    pub fn save_ssl_check_record(&self, record: &SslCheckRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO ssl_check_records (host, port, is_secure, protocol_version, cipher_name, cipher_bits, score, grade, subject_cn, issuer_cn, is_expired, days_remaining, is_self_signed, key_type, key_bits, summary, result, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            rusqlite::params![
                record.host, record.port, record.is_secure, record.protocol_version,
                record.cipher_name, record.cipher_bits, record.score, record.grade,
                record.subject_cn, record.issuer_cn, record.is_expired, record.days_remaining,
                record.is_self_signed, record.key_type, record.key_bits, record.summary,
                record.result, record.created_at.to_rfc3339()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_ssl_check_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<SslCheckRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, host, port, is_secure, protocol_version, cipher_name, cipher_bits, score, grade, subject_cn, issuer_cn, is_expired, days_remaining, is_self_signed, key_type, key_bits, summary, result, created_at FROM ssl_check_records ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        )?;
        let records = stmt.query_map(rusqlite::params![limit, offset], |row| {
            let created_at_str: String = row.get(18)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(SslCheckRecord {
                id: row.get(0)?,
                host: row.get(1)?,
                port: row.get(2)?,
                is_secure: row.get(3)?,
                protocol_version: row.get(4)?,
                cipher_name: row.get(5)?,
                cipher_bits: row.get(6)?,
                score: row.get(7)?,
                grade: row.get(8)?,
                subject_cn: row.get(9)?,
                issuer_cn: row.get(10)?,
                is_expired: row.get(11)?,
                days_remaining: row.get(12)?,
                is_self_signed: row.get(13)?,
                key_type: row.get(14)?,
                key_bits: row.get(15)?,
                summary: row.get(16)?,
                result: row.get(17)?,
                created_at,
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn delete_ssl_check_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM ssl_check_records WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn clear_ssl_check_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM ssl_check_records", [])?;
        Ok(())
    }

    pub fn save_site_check_record(&self, record: &SiteCheckRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO site_check_records (url, is_online, status_code, response_time_ms, title, server, dns_resolved, ssl_valid, is_redirect, summary, result, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                record.url, record.is_online, record.status_code, record.response_time_ms,
                record.title, record.server, record.dns_resolved, record.ssl_valid,
                record.is_redirect, record.summary, record.result, record.created_at.to_rfc3339()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_site_check_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<SiteCheckRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, url, is_online, status_code, response_time_ms, title, server, dns_resolved, ssl_valid, is_redirect, summary, result, created_at FROM site_check_records ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        )?;
        let records = stmt.query_map(rusqlite::params![limit, offset], |row| {
            let created_at_str: String = row.get(12)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(SiteCheckRecord {
                id: row.get(0)?,
                url: row.get(1)?,
                is_online: row.get(2)?,
                status_code: row.get(3)?,
                response_time_ms: row.get(4)?,
                title: row.get(5)?,
                server: row.get(6)?,
                dns_resolved: row.get(7)?,
                ssl_valid: row.get(8)?,
                is_redirect: row.get(9)?,
                summary: row.get(10)?,
                result: row.get(11)?,
                created_at,
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn delete_site_check_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM site_check_records WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn clear_site_check_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM site_check_records", [])?;
        Ok(())
    }

    pub fn save_waf_detection_record(&self, record: &WafDetectionRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO waf_detection_records (url, waf_detected, waf_name, confidence, summary, result, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                record.url, record.waf_detected, record.waf_name, record.confidence,
                record.summary, record.result, record.created_at.to_rfc3339()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_waf_detection_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<WafDetectionRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, url, waf_detected, waf_name, confidence, summary, result, created_at FROM waf_detection_records ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        )?;
        let records = stmt.query_map(rusqlite::params![limit, offset], |row| {
            let created_at_str: String = row.get(7)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(WafDetectionRecord {
                id: row.get(0)?,
                url: row.get(1)?,
                waf_detected: row.get(2)?,
                waf_name: row.get(3)?,
                confidence: row.get(4)?,
                summary: row.get(5)?,
                result: row.get(6)?,
                created_at,
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn delete_waf_detection_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM waf_detection_records WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn clear_waf_detection_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM waf_detection_records", [])?;
        Ok(())
    }

    pub fn create_tool_history(&self, record: &ToolHistoryRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tool_history (tool_type, tool_name, input_summary, result_summary, result_json, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &record.tool_type,
                &record.tool_name,
                &record.input_summary,
                &record.result_summary,
                &record.result_json,
                &record.status,
                &record.created_at.to_rfc3339(),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_tool_history(&self, tool_type: &str, limit: i32, offset: i32) -> SqliteResult<Vec<ToolHistoryRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, tool_type, tool_name, input_summary, result_summary, result_json, status, created_at
             FROM tool_history
             WHERE tool_type = ?1
             ORDER BY created_at DESC
             LIMIT ?2 OFFSET ?3"
        )?;
        let records = stmt.query_map(rusqlite::params![tool_type, limit, offset], |row| {
            Ok(ToolHistoryRecord {
                id: Some(row.get(0)?),
                tool_type: row.get(1)?,
                tool_name: row.get(2)?,
                input_summary: row.get(3)?,
                result_summary: row.get(4)?,
                result_json: row.get(5)?,
                status: row.get(6)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn get_all_tool_history(&self, limit: i32, offset: i32) -> SqliteResult<Vec<ToolHistoryRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, tool_type, tool_name, input_summary, result_summary, result_json, status, created_at
             FROM tool_history
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2"
        )?;
        let records = stmt.query_map(rusqlite::params![limit, offset], |row| {
            Ok(ToolHistoryRecord {
                id: Some(row.get(0)?),
                tool_type: row.get(1)?,
                tool_name: row.get(2)?,
                input_summary: row.get(3)?,
                result_summary: row.get(4)?,
                result_json: row.get(5)?,
                status: row.get(6)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn delete_tool_history(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM tool_history WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn clear_tool_history(&self, tool_type: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM tool_history WHERE tool_type = ?1", rusqlite::params![tool_type])?;
        Ok(())
    }

    pub fn clear_all_tool_history(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM tool_history", [])?;
        Ok(())
    }

    pub fn get_tool_history_count(&self, tool_type: &str) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM tool_history WHERE tool_type = ?1",
            rusqlite::params![tool_type],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn save_network_discovery_record(&self, record: &NetworkDiscoveryRecord) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO network_discovery_records (network_range, active_hosts, total_scanned, summary, result, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                record.network_range, record.active_hosts, record.total_scanned,
                record.summary, record.result, record.created_at.to_rfc3339()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_network_discovery_records(&self, limit: i32, offset: i32) -> SqliteResult<Vec<NetworkDiscoveryRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, network_range, active_hosts, total_scanned, summary, result, created_at FROM network_discovery_records ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        )?;
        let records = stmt.query_map(rusqlite::params![limit, offset], |row| {
            let created_at_str: String = row.get(6)?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(NetworkDiscoveryRecord {
                id: row.get(0)?,
                network_range: row.get(1)?,
                active_hosts: row.get(2)?,
                total_scanned: row.get(3)?,
                summary: row.get(4)?,
                result: row.get(5)?,
                created_at,
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(records)
    }

    pub fn delete_network_discovery_record(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM network_discovery_records WHERE id = ?1", rusqlite::params![id])?;
        Ok(())
    }

    pub fn clear_network_discovery_records(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM network_discovery_records", [])?;
        Ok(())
    }

    // ===== OsintPlatform CRUD =====

    pub fn get_osint_platforms(&self, category: Option<&str>, active_only: bool) -> SqliteResult<Vec<OsintPlatform>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = "SELECT id, name, display_name, category, url_template, url_main, url_probe, url_subpath, check_type, error_type, error_codes, error_messages, error_url, presence_strs, absence_strs, regex_check, request_method, request_head_only, headers, payload, get_params, activation, errors, tags, id_type, similar_search, ignore403, disabled, protection, engine, engine_data, username_claimed, username_unclaimed, alexa_rank, is_active, is_built_in, priority, notes, source, created_at, updated_at FROM osint_platforms".to_string();
        let mut conditions = Vec::new();
        if active_only { conditions.push("is_active = 1".to_string()); conditions.push("disabled = 0".to_string()); }
        if category.is_some() { conditions.push("category = ?".to_string()); }
        if !conditions.is_empty() { sql.push_str(" WHERE "); sql.push_str(&conditions.join(" AND ")); }
        sql.push_str(" ORDER BY alexa_rank ASC NULLS LAST, priority DESC, name ASC");

        let mut stmt = conn.prepare(&sql)?;
        let platforms: Vec<OsintPlatform> = if category.is_some() {
            stmt.query_map(rusqlite::params![category.unwrap()], |row| self::row_to_osint_platform(row))?.collect::<SqliteResult<Vec<_>>>()?
        } else {
            stmt.query_map([], |row| self::row_to_osint_platform(row))?.collect::<SqliteResult<Vec<_>>>()?
        };
        Ok(platforms)
    }

    pub fn get_osint_platform_by_name(&self, name: &str) -> SqliteResult<Option<OsintPlatform>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, display_name, category, url_template, url_main, url_probe, url_subpath, check_type, error_type, error_codes, error_messages, error_url, presence_strs, absence_strs, regex_check, request_method, request_head_only, headers, payload, get_params, activation, errors, tags, id_type, similar_search, ignore403, disabled, protection, engine, engine_data, username_claimed, username_unclaimed, alexa_rank, is_active, is_built_in, priority, notes, source, created_at, updated_at FROM osint_platforms WHERE name = ?1"
        )?;
        let result = stmt.query_row([name], |row| self::row_to_osint_platform(row)).ok();
        Ok(result)
    }

    pub fn create_osint_platform(&self, platform: &OsintPlatform) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO osint_platforms (name, display_name, category, url_template, url_main, url_probe, url_subpath, check_type, error_type, error_codes, error_messages, error_url, presence_strs, absence_strs, regex_check, request_method, request_head_only, headers, payload, get_params, activation, errors, tags, id_type, similar_search, ignore403, disabled, protection, engine, engine_data, username_claimed, username_unclaimed, alexa_rank, is_active, is_built_in, priority, notes, source, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41)",
            rusqlite::params![
                platform.name, platform.display_name, platform.category, platform.url_template,
                platform.url_main, platform.url_probe, platform.url_subpath, platform.check_type,
                platform.error_type, platform.error_codes, platform.error_messages, platform.error_url,
                platform.presence_strs, platform.absence_strs, platform.regex_check,
                platform.request_method, platform.request_head_only as i32, platform.headers, platform.payload,
                platform.get_params, platform.activation, platform.errors, platform.tags,
                platform.id_type, platform.similar_search as i32, platform.ignore403 as i32,
                platform.disabled as i32, platform.protection, platform.engine, platform.engine_data,
                platform.username_claimed, platform.username_unclaimed, platform.alexa_rank,
                platform.is_active as i32, platform.is_built_in as i32, platform.priority,
                platform.notes, platform.source, platform.created_at.to_rfc3339(), platform.updated_at.to_rfc3339()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_osint_platform(&self, platform: &OsintPlatform) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE osint_platforms SET display_name=?1, category=?2, url_template=?3, url_main=?4, url_probe=?5, url_subpath=?6, check_type=?7, error_type=?8, error_codes=?9, error_messages=?10, error_url=?11, presence_strs=?12, absence_strs=?13, regex_check=?14, request_method=?15, request_head_only=?16, headers=?17, payload=?18, get_params=?19, activation=?20, errors=?21, tags=?22, id_type=?23, similar_search=?24, ignore403=?25, disabled=?26, protection=?27, engine=?28, engine_data=?29, username_claimed=?30, username_unclaimed=?31, alexa_rank=?32, is_active=?33, priority=?34, notes=?35, updated_at=?36 WHERE name=?37",
            rusqlite::params![
                platform.display_name, platform.category, platform.url_template,
                platform.url_main, platform.url_probe, platform.url_subpath, platform.check_type,
                platform.error_type, platform.error_codes, platform.error_messages, platform.error_url,
                platform.presence_strs, platform.absence_strs, platform.regex_check,
                platform.request_method, platform.request_head_only as i32, platform.headers, platform.payload,
                platform.get_params, platform.activation, platform.errors, platform.tags,
                platform.id_type, platform.similar_search as i32, platform.ignore403 as i32,
                platform.disabled as i32, platform.protection, platform.engine, platform.engine_data,
                platform.username_claimed, platform.username_unclaimed, platform.alexa_rank,
                platform.is_active as i32, platform.priority, platform.notes,
                Utc::now().to_rfc3339(), platform.name
            ],
        )?;
        Ok(())
    }

    pub fn delete_osint_platform(&self, name: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM osint_platforms WHERE name = ?1 AND is_built_in = 0", [name])?;
        Ok(())
    }

    pub fn get_osint_platform_categories(&self) -> SqliteResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT DISTINCT category FROM osint_platforms ORDER BY category")?;
        let cats = stmt.query_map([], |row| row.get(0))?.collect::<SqliteResult<Vec<String>>>()?;
        Ok(cats)
    }

    pub fn count_osint_platforms(&self) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM osint_platforms WHERE is_active = 1", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn batch_create_osint_platforms(&self, platforms: &[OsintPlatform]) -> SqliteResult<usize> {
        let conn = self.conn.lock().unwrap();
        let mut count = 0;
        for p in platforms {
            let result = conn.execute(
                "INSERT OR IGNORE INTO osint_platforms (name, display_name, category, url_template, url_main, url_probe, url_subpath, check_type, error_type, error_codes, error_messages, error_url, presence_strs, absence_strs, regex_check, request_method, request_head_only, headers, payload, get_params, activation, errors, tags, id_type, similar_search, ignore403, disabled, protection, engine, engine_data, username_claimed, username_unclaimed, alexa_rank, is_active, is_built_in, priority, notes, source, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41)",
                rusqlite::params![
                    p.name, p.display_name, p.category, p.url_template,
                    p.url_main, p.url_probe, p.url_subpath, p.check_type,
                    p.error_type, p.error_codes, p.error_messages, p.error_url,
                    p.presence_strs, p.absence_strs, p.regex_check,
                    p.request_method, p.request_head_only as i32, p.headers, p.payload,
                    p.get_params, p.activation, p.errors, p.tags,
                    p.id_type, p.similar_search as i32, p.ignore403 as i32,
                    p.disabled as i32, p.protection, p.engine, p.engine_data,
                    p.username_claimed, p.username_unclaimed, p.alexa_rank,
                    p.is_active as i32, p.is_built_in as i32, p.priority,
                    p.notes, p.source, p.created_at.to_rfc3339(), p.updated_at.to_rfc3339()
                ],
            );
            if let Ok(n) = result { count += n; }
        }
        Ok(count)
    }

    // ===== OsintScanResult CRUD =====

    pub fn create_osint_scan_result(&self, result: &OsintScanResult) -> SqliteResult<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO osint_scan_results (target_id, username, platform_name, platform_url, found, status_code, error_message, category, response_time_ms, scanned_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            rusqlite::params![
                result.target_id, result.username, result.platform_name, result.platform_url,
                result.found as i32, result.status_code, result.error_message, result.category,
                result.response_time_ms, result.scanned_at.to_rfc3339()
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn batch_create_osint_scan_results(&self, results: &[OsintScanResult]) -> SqliteResult<usize> {
        let conn = self.conn.lock().unwrap();
        let mut count = 0;
        for r in results {
            let result = conn.execute(
                "INSERT INTO osint_scan_results (target_id, username, platform_name, platform_url, found, status_code, error_message, category, response_time_ms, scanned_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    r.target_id, r.username, r.platform_name, r.platform_url,
                    r.found as i32, r.status_code, r.error_message, r.category,
                    r.response_time_ms, r.scanned_at.to_rfc3339()
                ],
            );
            if let Ok(n) = result { count += n; }
        }
        Ok(count)
    }

    pub fn get_osint_scan_results(&self, username: &str) -> SqliteResult<Vec<OsintScanResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target_id, username, platform_name, platform_url, found, status_code, error_message, category, response_time_ms, scanned_at FROM osint_scan_results WHERE username = ?1 ORDER BY scanned_at DESC"
        )?;
        let results = stmt.query_map([username], |row| {
            let scanned_at_str: String = row.get(10)?;
            let scanned_at = DateTime::parse_from_rfc3339(&scanned_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            Ok(OsintScanResult {
                id: row.get(0)?,
                target_id: row.get(1)?,
                username: row.get(2)?,
                platform_name: row.get(3)?,
                platform_url: row.get(4)?,
                found: row.get::<_, i32>(5)? == 1,
                status_code: row.get(6)?,
                error_message: row.get(7)?,
                category: row.get(8)?,
                response_time_ms: row.get(9)?,
                scanned_at,
            })
        })?.collect::<SqliteResult<Vec<_>>>()?;
        Ok(results)
    }

    pub fn get_latest_osint_scan_by_username(&self, username: &str) -> SqliteResult<Option<DateTime<Utc>>> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT MAX(scanned_at) FROM osint_scan_results WHERE username = ?1",
            [username],
            |row| row.get::<_, Option<String>>(0),
        ).ok().flatten();
        Ok(result.and_then(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)).ok()))
    }
}

fn row_to_osint_platform(row: &rusqlite::Row) -> SqliteResult<OsintPlatform> {
    let created_at_str: String = row.get(39)?;
    let updated_at_str: String = row.get(40)?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    Ok(OsintPlatform {
        id: row.get(0)?,
        name: row.get(1)?,
        display_name: row.get(2)?,
        category: row.get(3)?,
        url_template: row.get(4)?,
        url_main: row.get(5)?,
        url_probe: row.get(6)?,
        url_subpath: row.get(7)?,
        check_type: row.get(8)?,
        error_type: row.get(9)?,
        error_codes: row.get(10)?,
        error_messages: row.get(11)?,
        error_url: row.get(12)?,
        presence_strs: row.get(13)?,
        absence_strs: row.get(14)?,
        regex_check: row.get(15)?,
        request_method: row.get(16)?,
        request_head_only: row.get::<_, i32>(17)? == 1,
        headers: row.get(18)?,
        payload: row.get(19)?,
        get_params: row.get(20)?,
        activation: row.get(21)?,
        errors: row.get(22)?,
        tags: row.get(23)?,
        id_type: row.get(24)?,
        similar_search: row.get::<_, i32>(25)? == 1,
        ignore403: row.get::<_, i32>(26)? == 1,
        disabled: row.get::<_, i32>(27)? == 1,
        protection: row.get(28)?,
        engine: row.get(29)?,
        engine_data: row.get(30)?,
        username_claimed: row.get(31)?,
        username_unclaimed: row.get(32)?,
        alexa_rank: row.get(33)?,
        is_active: row.get::<_, i32>(34)? == 1,
        is_built_in: row.get::<_, i32>(35)? == 1,
        priority: row.get(36)?,
        notes: row.get(37)?,
        source: row.get(38)?,
        created_at,
        updated_at,
    })
}
