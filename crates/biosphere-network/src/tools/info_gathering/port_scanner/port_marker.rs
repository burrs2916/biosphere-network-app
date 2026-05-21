use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use rusqlite::{Connection, params};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MarkType {
    Favorite,
    Important,
    Dangerous,
    Custom(String),
}

impl MarkType {
    pub fn as_str(&self) -> &str {
        match self {
            MarkType::Favorite => "favorite",
            MarkType::Important => "important",
            MarkType::Dangerous => "dangerous",
            MarkType::Custom(name) => name.as_str(),
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "favorite" => MarkType::Favorite,
            "important" => MarkType::Important,
            "dangerous" => MarkType::Dangerous,
            custom => MarkType::Custom(custom.to_string()),
        }
    }

    pub fn icon(&self) -> &str {
        match self {
            MarkType::Favorite => "⭐",
            MarkType::Important => "🔴",
            MarkType::Dangerous => "⚠️",
            MarkType::Custom(_) => "📌",
        }
    }

    pub fn color(&self) -> &str {
        match self {
            MarkType::Favorite => "#fbbf24",  // Gold
            MarkType::Important => "#ef4444",   // Red
            MarkType::Dangerous => "#f97316",  // Orange
            MarkType::Custom(_) => "#8b5cf6",  // Purple
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMarking {
    pub port: u16,
    pub mark_type: MarkType,
    pub note: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

pub struct PortMarker {
    db_path: String,
    cache: Mutex<HashMap<u16, PortMarking>>,
}

impl PortMarker {
    pub fn new(db_path: &str) -> Self {
        let mut marker = Self {
            db_path: db_path.to_string(),
            cache: Mutex::new(HashMap::new()),
        };
        
        // Ensure table exists
        if let Err(e) = marker.ensure_table_exists() {
            eprintln!("Warning: Failed to ensure port_markings table exists: {}", e);
        }
        
        marker.load_from_db().ok();
        marker
    }

    fn ensure_table_exists(&self) -> Result<(), String> {
        let conn = self.get_connection()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS port_markings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER NOT NULL UNIQUE,
                mark_type TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT
            )",
            [],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_connection(&self) -> Result<Connection, String> {
        Connection::open(&self.db_path).map_err(|e| e.to_string())
    }

    fn load_from_db(&mut self) -> Result<(), String> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT port, mark_type, note, created_at, updated_at FROM port_markings"
        ).map_err(|e| e.to_string())?;

        let markings = stmt.query_map([], |row| {
            Ok(PortMarking {
                port: row.get(0)?,
                mark_type: MarkType::from_str(&row.get::<_, String>(1)?),
                note: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        }).map_err(|e| e.to_string())?;

        let mut cache = self.cache.lock().map_err(|e| e.to_string())?;
        cache.clear();

        for marking in markings {
            let m = marking.map_err(|e| e.to_string())?;
            cache.insert(m.port, m);
        }

        Ok(())
    }

    pub fn mark_port(&self, port: u16, mark_type: MarkType, note: String) -> Result<(), String> {
        let conn = self.get_connection()?;
        
        let now = chrono::Utc::now().to_rfc3339();
        
        // Check if marking exists
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM port_markings WHERE port = ?1",
            params![port],
            |row| Ok(row.get::<_, i32>(0)? > 0)
        ).map_err(|e| e.to_string())?;

        if exists {
            conn.execute(
                "UPDATE port_markings SET mark_type = ?1, note = ?2, updated_at = ?3 WHERE port = ?4",
                params![mark_type.as_str(), note, now, port]
            ).map_err(|e| e.to_string())?;
        } else {
            conn.execute(
                "INSERT INTO port_markings (port, mark_type, note, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![port, mark_type.as_str(), note, now]
            ).map_err(|e| e.to_string())?;
        }

        // Update cache
        let mut cache = self.cache.lock().map_err(|e| e.to_string())?;
        cache.insert(port, PortMarking {
            port,
            mark_type,
            note,
            created_at: now.clone(),
            updated_at: if exists { Some(now) } else { None },
        });

        Ok(())
    }

    pub fn unmark_port(&self, port: u16) -> Result<bool, String> {
        let conn = self.get_connection()?;
        
        let rows_affected = conn.execute(
            "DELETE FROM port_markings WHERE port = ?1",
            params![port]
        ).map_err(|e| e.to_string())?;

        // Update cache
        let mut cache = self.cache.lock().map_err(|e| e.to_string())?;
        cache.remove(&port);

        Ok(rows_affected > 0)
    }

    pub fn get_marking(&self, port: u16) -> Option<PortMarking> {
        let cache = self.cache.lock().ok()?;
        cache.get(&port).cloned()
    }

    pub fn get_all_markings(&self) -> Vec<PortMarking> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.values().cloned().collect()
    }

    pub fn get_markings_by_type(&self, mark_type: &MarkType) -> Vec<PortMarking> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.values()
            .filter(|m| &m.mark_type == mark_type)
            .cloned()
            .collect()
    }

    pub fn clear_all(&self) -> Result<(), String> {
        let conn = self.get_connection()?;
        conn.execute("DELETE FROM port_markings", [])
            .map_err(|e| e.to_string())?;

        let mut cache = self.cache.lock().map_err(|e| e.to_string())?;
        cache.clear();

        Ok(())
    }

    pub fn is_marked(&self, port: u16) -> bool {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.contains_key(&port)
    }

    pub fn export_markings(&self) -> String {
        let markings = self.get_all_markings();
        serde_json::to_string_pretty(&markings).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn import_markings(&self, json_data: &str) -> Result<usize, String> {
        let imported: Vec<PortMarking> = serde_json::from_str(json_data)
            .map_err(|e| format!("Invalid JSON: {}", e))?;
        
        let mut count = 0;
        for marking in imported {
            self.mark_port(marking.port, marking.mark_type, marking.note)?;
            count += 1;
        }

        Ok(count)
    }
}

use std::sync::OnceLock;

static PORT_MARKER: OnceLock<PortMarker> = OnceLock::new();

pub fn init_port_marker(db_path: &str) {
    PORT_MARKER.get_or_init(|| PortMarker::new(db_path));
}

pub fn get_port_marker() -> &'static PortMarker {
    PORT_MARKER.get_or_init(|| PortMarker::new("biosphere.db"))
}
