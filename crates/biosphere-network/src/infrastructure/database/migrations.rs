pub const SCHEMA_VERSION: i32 = 17;

pub const CREATE_SCAN_TASKS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_mode TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL,
    total_ports INTEGER,
    open_ports INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const CREATE_SCAN_RESULTS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    service TEXT,
    version TEXT,
    banner TEXT,
    os_detection TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE
);
"#;

pub const CREATE_TARGETS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    description TEXT,
    tags TEXT,
    location TEXT,
    organization TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at TEXT,
    is_active INTEGER DEFAULT 1,
    UNIQUE(target_value)
);
"#;

pub const CREATE_DNS_QUERIES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    query_domain TEXT NOT NULL,
    query_type TEXT NOT NULL,
    dns_server TEXT,
    query_time INTEGER NOT NULL,
    ttl INTEGER,
    result TEXT NOT NULL,
    raw_response TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"#;

pub const CREATE_PING_RECORDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS ping_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    target_host TEXT NOT NULL,
    packet_sent INTEGER NOT NULL,
    packet_received INTEGER NOT NULL,
    packet_loss REAL NOT NULL,
    min_rtt REAL,
    max_rtt REAL,
    avg_rtt REAL,
    std_dev_rtt REAL,
    status TEXT NOT NULL,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"#;

pub const CREATE_TRACEROUTE_RECORDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS traceroute_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    target_host TEXT NOT NULL,
    max_hops INTEGER NOT NULL,
    total_hops INTEGER NOT NULL,
    destination_reached INTEGER NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"#;

pub const CREATE_TRACEROUTE_HOPS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS traceroute_hops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    traceroute_id INTEGER NOT NULL,
    hop_number INTEGER NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    rtt1 REAL,
    rtt2 REAL,
    rtt3 REAL,
    avg_rtt REAL,
    FOREIGN KEY (traceroute_id) REFERENCES traceroute_records(id) ON DELETE CASCADE
);
"#;

pub const CREATE_PORT_MARKINGS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS port_markings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port INTEGER NOT NULL UNIQUE,
    mark_type TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
);
"#;

pub const CREATE_SEC_HEADER_RECORDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS sec_header_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    present_count INTEGER NOT NULL,
    missing_count INTEGER NOT NULL,
    summary TEXT,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const CREATE_HASH_IDENTIFIER_RECORDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS hash_identifier_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_value TEXT NOT NULL,
    possible_types TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const CREATE_IP_GEO_RECORDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS ip_geo_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    country TEXT NOT NULL,
    country_code TEXT NOT NULL,
    region TEXT NOT NULL,
    city TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    isp TEXT NOT NULL,
    org TEXT NOT NULL,
    timezone TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;


pub const CREATE_WHOIS_RECORDS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS whois_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    query_target TEXT NOT NULL,
    query_type TEXT NOT NULL,
    registrar TEXT,
    registrant_name TEXT,
    registrant_email TEXT,
    registrant_org TEXT,
    created_date TEXT,
    expiration_date TEXT,
    updated_date TEXT,
    name_servers TEXT,
    raw_data TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"#;

pub const CREATE_TASKS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type TEXT NOT NULL,
    target_id INTEGER,
    status TEXT NOT NULL,
    progress REAL DEFAULT 0,
    result_summary TEXT,
    error_message TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"#;

pub const CREATE_TARGET_GROUPS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS target_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    target_ids TEXT,
    tags TEXT,
    color TEXT NOT NULL DEFAULT '#667eea',
    icon TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT,
    parent_id INTEGER,
    target_count INTEGER DEFAULT 0,
    active_count INTEGER DEFAULT 0,
    risk_count INTEGER DEFAULT 0,
    default_scan_config TEXT,
    auto_scan INTEGER DEFAULT 0,
    scan_interval INTEGER,
    owner TEXT,
    is_public INTEGER DEFAULT 1,
    shared_with TEXT
);
"#;

pub const CREATE_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_scan_tasks_target ON scan_tasks(target);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_start_time ON scan_tasks(start_time);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_task_id ON scan_results(task_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_target_port ON scan_results(target, port);
CREATE INDEX IF NOT EXISTS idx_targets_target_value ON targets(target_value);
CREATE INDEX IF NOT EXISTS idx_targets_target_type ON targets(target_type);
CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(query_domain);
CREATE INDEX IF NOT EXISTS idx_dns_queries_type ON dns_queries(query_type);
CREATE INDEX IF NOT EXISTS idx_ping_records_host ON ping_records(target_host);
CREATE INDEX IF NOT EXISTS idx_traceroute_records_host ON traceroute_records(target_host);
CREATE INDEX IF NOT EXISTS idx_whois_records_target ON whois_records(query_target);
CREATE INDEX IF NOT EXISTS idx_tasks_type ON tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_sec_header_records_url ON sec_header_records(url);
CREATE INDEX IF NOT EXISTS idx_sec_header_records_grade ON sec_header_records(grade);
CREATE INDEX IF NOT EXISTS idx_hash_identifier_records_hash ON hash_identifier_records(hash_value);
"#;

pub const CREATE_VERSION_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
"#;

pub fn get_all_migrations() -> Vec<&'static str> {
    vec![
        CREATE_VERSION_TABLE,
        CREATE_SCAN_TASKS_TABLE,
        CREATE_SCAN_RESULTS_TABLE,
        CREATE_TARGETS_TABLE,
        CREATE_DNS_QUERIES_TABLE,
        CREATE_PING_RECORDS_TABLE,
        CREATE_TRACEROUTE_RECORDS_TABLE,
        CREATE_TRACEROUTE_HOPS_TABLE,
        CREATE_WHOIS_RECORDS_TABLE,
        CREATE_TASKS_TABLE,
        CREATE_TARGET_GROUPS_TABLE,
        CREATE_PORT_MARKINGS_TABLE,
        CREATE_SEC_HEADER_RECORDS_TABLE,
        CREATE_HASH_IDENTIFIER_RECORDS_TABLE,
        CREATE_IP_GEO_RECORDS_TABLE,
        CREATE_INDEXES,
        MIGRATE_V6_TO_V7_SEC_HEADERS,
        MIGRATE_V6_TO_V7_HASH_IDENTIFIER,
        MIGRATE_V6_TO_V7_INDEXES,
        MIGRATE_V7_TO_V8_IP_GEO,
        MIGRATE_V7_TO_V8_INDEXES,
        MIGRATE_V8_TO_V9_SSL_CHECK,
        MIGRATE_V8_TO_V9_INDEXES,
        MIGRATE_V9_TO_V10_SITE_CHECK,
        MIGRATE_V9_TO_V10_INDEXES,
        MIGRATE_V10_TO_V11_WAF_DETECTION,
        MIGRATE_V10_TO_V11_INDEXES,
        MIGRATE_V11_TO_V12_TOOL_HISTORY,
        MIGRATE_V11_TO_V12_TOOL_HISTORY_INDEXES,
    ]
}

pub const MIGRATE_V3_TO_V4_TARGETS: &str = r#"
ALTER TABLE targets ADD COLUMN group_id INTEGER;
ALTER TABLE targets ADD COLUMN status TEXT DEFAULT 'new';
ALTER TABLE targets ADD COLUMN risk_level TEXT DEFAULT 'none';
ALTER TABLE targets ADD COLUMN priority TEXT DEFAULT 'normal';
ALTER TABLE targets ADD COLUMN owner TEXT;
ALTER TABLE targets ADD COLUMN contact TEXT;
ALTER TABLE targets ADD COLUMN auto_scan INTEGER DEFAULT 0;
ALTER TABLE targets ADD COLUMN scan_interval INTEGER;
ALTER TABLE targets ADD COLUMN next_scan_at TEXT;
ALTER TABLE targets ADD COLUMN total_scans INTEGER DEFAULT 0;
ALTER TABLE targets ADD COLUMN open_ports_count INTEGER DEFAULT 0;
ALTER TABLE targets ADD COLUMN vulnerabilities_count INTEGER DEFAULT 0;
ALTER TABLE targets ADD COLUMN metadata TEXT;
"#;

pub const MIGRATE_V3_TO_V4_TARGET_GROUPS: &str = r#"
ALTER TABLE target_groups ADD COLUMN parent_id INTEGER;
ALTER TABLE target_groups ADD COLUMN target_count INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN active_count INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN risk_count INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN default_scan_config TEXT;
ALTER TABLE target_groups ADD COLUMN auto_scan INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN scan_interval INTEGER;
ALTER TABLE target_groups ADD COLUMN owner TEXT;
ALTER TABLE target_groups ADD COLUMN is_public INTEGER DEFAULT 1;
ALTER TABLE target_groups ADD COLUMN shared_with TEXT;
"#;

pub const MIGRATE_V4_TO_V5_PORT_MARKINGS: &str = r#"
CREATE TABLE IF NOT EXISTS port_markings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port INTEGER NOT NULL UNIQUE,
    mark_type TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
);
"#;

pub const MIGRATE_V6_TO_V7_SEC_HEADERS: &str = r#"
CREATE TABLE IF NOT EXISTS sec_header_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    present_count INTEGER NOT NULL,
    missing_count INTEGER NOT NULL,
    summary TEXT,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V6_TO_V7_HASH_IDENTIFIER: &str = r#"
CREATE TABLE IF NOT EXISTS hash_identifier_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash_value TEXT NOT NULL,
    possible_types TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V6_TO_V7_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_sec_header_records_url ON sec_header_records(url);
CREATE INDEX IF NOT EXISTS idx_sec_header_records_grade ON sec_header_records(grade);
CREATE INDEX IF NOT EXISTS idx_hash_identifier_records_hash ON hash_identifier_records(hash_value);
"#;

pub const MIGRATE_V7_TO_V8_IP_GEO: &str = r#"
CREATE TABLE IF NOT EXISTS ip_geo_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    country TEXT NOT NULL,
    country_code TEXT NOT NULL,
    region TEXT NOT NULL,
    city TEXT NOT NULL,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    isp TEXT NOT NULL,
    org TEXT NOT NULL,
    timezone TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V7_TO_V8_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_ip_geo_records_ip ON ip_geo_records(ip);
"#;

pub const MIGRATE_V8_TO_V9_SSL_CHECK: &str = r#"
CREATE TABLE IF NOT EXISTS ssl_check_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    protocol_version TEXT NOT NULL,
    cipher_name TEXT NOT NULL,
    cipher_bits INTEGER NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    subject_cn TEXT NOT NULL,
    issuer_cn TEXT NOT NULL,
    is_expired INTEGER NOT NULL,
    days_remaining INTEGER NOT NULL,
    is_self_signed INTEGER NOT NULL,
    key_type TEXT NOT NULL,
    key_bits INTEGER NOT NULL,
    summary TEXT,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V8_TO_V9_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_ssl_check_records_host ON ssl_check_records(host);
CREATE INDEX IF NOT EXISTS idx_ssl_check_records_grade ON ssl_check_records(grade);
"#;

pub const MIGRATE_V9_TO_V10_SITE_CHECK: &str = r#"
CREATE TABLE IF NOT EXISTS site_check_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    is_online INTEGER NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    title TEXT,
    server TEXT,
    dns_resolved INTEGER NOT NULL,
    ssl_valid INTEGER,
    is_redirect INTEGER NOT NULL,
    summary TEXT,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V9_TO_V10_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_site_check_records_url ON site_check_records(url);
CREATE INDEX IF NOT EXISTS idx_site_check_records_is_online ON site_check_records(is_online);
"#;

pub const MIGRATE_V10_TO_V11_WAF_DETECTION: &str = r#"
CREATE TABLE IF NOT EXISTS waf_detection_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    waf_detected INTEGER NOT NULL,
    waf_name TEXT,
    confidence REAL NOT NULL,
    summary TEXT,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V10_TO_V11_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_waf_detection_records_url ON waf_detection_records(url);
CREATE INDEX IF NOT EXISTS idx_waf_detection_records_waf_detected ON waf_detection_records(waf_detected);
"#;

pub const MIGRATE_V11_TO_V12_TOOL_HISTORY: &str = r#"
CREATE TABLE IF NOT EXISTS tool_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    input_summary TEXT NOT NULL,
    result_summary TEXT,
    result_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V11_TO_V12_TOOL_HISTORY_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_tool_history_tool_type ON tool_history(tool_type);
CREATE INDEX IF NOT EXISTS idx_tool_history_created_at ON tool_history(created_at);
CREATE INDEX IF NOT EXISTS idx_tool_history_status ON tool_history(status);
"#;

pub const MIGRATE_V12_TO_V13_TARGET_GROUPS_FIX: &str = r#"
ALTER TABLE target_groups ADD COLUMN parent_id INTEGER;
ALTER TABLE target_groups ADD COLUMN target_count INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN active_count INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN risk_count INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN default_scan_config TEXT;
ALTER TABLE target_groups ADD COLUMN auto_scan INTEGER DEFAULT 0;
ALTER TABLE target_groups ADD COLUMN scan_interval INTEGER;
ALTER TABLE target_groups ADD COLUMN owner TEXT;
ALTER TABLE target_groups ADD COLUMN is_public INTEGER DEFAULT 1;
ALTER TABLE target_groups ADD COLUMN shared_with TEXT;
"#;

pub const MIGRATE_V13_TO_V14_NETWORK_DISCOVERY: &str = r#"
CREATE TABLE IF NOT EXISTS network_discovery_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_range TEXT NOT NULL,
    active_hosts INTEGER NOT NULL,
    total_scanned INTEGER NOT NULL,
    summary TEXT,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V13_TO_V14_NETWORK_DISCOVERY_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_network_discovery_records_range ON network_discovery_records(network_range);
CREATE INDEX IF NOT EXISTS idx_network_discovery_records_created_at ON network_discovery_records(created_at);
"#;

pub const MIGRATE_V14_TO_V15_OSINT_PLATFORMS: &str = r#"
CREATE TABLE IF NOT EXISTS osint_platforms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT,
    category TEXT NOT NULL DEFAULT 'other',
    url_template TEXT NOT NULL,
    error_type TEXT NOT NULL DEFAULT 'status_code',
    error_codes TEXT,
    error_messages TEXT,
    error_url TEXT,
    regex_check TEXT,
    request_method TEXT DEFAULT 'GET',
    headers TEXT,
    payload TEXT,
    is_active INTEGER DEFAULT 1,
    is_built_in INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0,
    notes TEXT,
    source TEXT DEFAULT 'builtin',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"#;

pub const MIGRATE_V14_TO_V15_OSINT_PLATFORMS_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_osint_platforms_name ON osint_platforms(name);
CREATE INDEX IF NOT EXISTS idx_osint_platforms_category ON osint_platforms(category);
CREATE INDEX IF NOT EXISTS idx_osint_platforms_is_active ON osint_platforms(is_active);
CREATE INDEX IF NOT EXISTS idx_osint_platforms_source ON osint_platforms(source);
"#;

pub const MIGRATE_V14_TO_V15_OSINT_SEED_PLATFORMS: &str = r#"
INSERT OR IGNORE INTO osint_platforms (name, display_name, category, url_template, error_type, error_codes, regex_check, request_method, is_built_in, priority, source) VALUES
('github', 'GitHub', 'developer', 'https://github.com/{}', 'status_code', '[404]', '^[a-zA-Z0-9]{0,38}$', 'GET', 1, 100, 'builtin'),
('gitlab', 'GitLab', 'developer', 'https://gitlab.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 99, 'builtin'),
('twitter', 'Twitter/X', 'social', 'https://twitter.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 98, 'builtin'),
('reddit', 'Reddit', 'social', 'https://www.reddit.com/user/{}', 'status_code', '[404]', NULL, 'GET', 1, 97, 'builtin'),
('instagram', 'Instagram', 'social', 'https://www.instagram.com/{}/', 'status_code', '[404]', NULL, 'GET', 1, 96, 'builtin'),
('pinterest', 'Pinterest', 'social', 'https://www.pinterest.com/{}/', 'status_code', '[404]', NULL, 'GET', 1, 95, 'builtin'),
('tiktok', 'TikTok', 'social', 'https://www.tiktok.com/@{}', 'status_code', '[404]', NULL, 'GET', 1, 94, 'builtin'),
('twitch', 'Twitch', 'social', 'https://www.twitch.tv/{}', 'status_code', '[404]', NULL, 'GET', 1, 93, 'builtin'),
('youtube', 'YouTube', 'social', 'https://www.youtube.com/@{}', 'status_code', '[404]', NULL, 'GET', 1, 92, 'builtin'),
('medium', 'Medium', 'social', 'https://medium.com/@{}', 'status_code', '[404]', NULL, 'GET', 1, 91, 'builtin'),
('linkedin', 'LinkedIn', 'social', 'https://www.linkedin.com/in/{}', 'status_code', '[404]', NULL, 'GET', 1, 90, 'builtin'),
('facebook', 'Facebook', 'social', 'https://www.facebook.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 89, 'builtin'),
('devto', 'Dev.to', 'developer', 'https://dev.to/{}', 'status_code', '[404]', NULL, 'GET', 1, 88, 'builtin'),
('hackernews', 'Hacker News', 'developer', 'https://news.ycombinator.com/user?id={}', 'message', '["No such user."]', NULL, 'GET', 1, 87, 'builtin'),
('keybase', 'Keybase', 'security', 'https://keybase.io/{}', 'status_code', '[404]', NULL, 'GET', 1, 86, 'builtin'),
('aboutme', 'About.me', 'social', 'https://about.me/{}', 'status_code', '[404]', NULL, 'GET', 1, 85, 'builtin'),
('patreon', 'Patreon', 'social', 'https://www.patreon.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 84, 'builtin'),
('steam', 'Steam', 'gaming', 'https://steamcommunity.com/id/{}', 'status_code', '[404]', NULL, 'GET', 1, 83, 'builtin'),
('soundcloud', 'SoundCloud', 'music', 'https://soundcloud.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 82, 'builtin'),
('spotify', 'Spotify', 'music', 'https://open.spotify.com/user/{}', 'status_code', '[404]', NULL, 'GET', 1, 81, 'builtin'),
('behance', 'Behance', 'creative', 'https://www.behance.net/{}', 'status_code', '[404]', NULL, 'GET', 1, 80, 'builtin'),
('dribbble', 'Dribbble', 'creative', 'https://dribbble.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 79, 'builtin'),
('codepen', 'CodePen', 'developer', 'https://codepen.io/{}', 'status_code', '[404]', NULL, 'GET', 1, 78, 'builtin'),
('npm', 'npm', 'developer', 'https://www.npmjs.com/~{}', 'status_code', '[404]', NULL, 'GET', 1, 77, 'builtin'),
('pypi', 'PyPI', 'developer', 'https://pypi.org/user/{}/', 'status_code', '[404]', NULL, 'GET', 1, 76, 'builtin'),
('rubygems', 'RubyGems', 'developer', 'https://rubygems.org/profiles/{}', 'status_code', '[404]', NULL, 'GET', 1, 75, 'builtin'),
('dockerhub', 'Docker Hub', 'developer', 'https://hub.docker.com/u/{}', 'status_code', '[404]', NULL, 'GET', 1, 74, 'builtin'),
('kaggle', 'Kaggle', 'developer', 'https://www.kaggle.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 73, 'builtin'),
('leetcode', 'LeetCode', 'developer', 'https://leetcode.com/{}/', 'status_code', '[404]', NULL, 'GET', 1, 72, 'builtin'),
('hackerrank', 'HackerRank', 'developer', 'https://www.hackerrank.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 71, 'builtin'),
('replit', 'Replit', 'developer', 'https://replit.com/@{}', 'status_code', '[404]', NULL, 'GET', 1, 70, 'builtin'),
('gitbook', 'GitBook', 'developer', 'https://app.gitbook.com/u/{}', 'status_code', '[404]', NULL, 'GET', 1, 69, 'builtin'),
('stackoverflow', 'Stack Overflow', 'developer', 'https://stackoverflow.com/users/{}', 'status_code', '[404]', NULL, 'GET', 1, 68, 'builtin'),
('stackexchange', 'Stack Exchange', 'developer', 'https://stackexchange.com/users/{}?tab=profiles', 'status_code', '[404]', NULL, 'GET', 1, 67, 'builtin'),
('bitbucket', 'Bitbucket', 'developer', 'https://bitbucket.org/{}/', 'status_code', '[404]', NULL, 'GET', 1, 66, 'builtin'),
('cratesio', 'crates.io', 'developer', 'https://crates.io/users/{}', 'status_code', '[404]', NULL, 'GET', 1, 65, 'builtin'),
('sourceforge', 'SourceForge', 'developer', 'https://sourceforge.net/u/{}/profile/', 'status_code', '[404]', NULL, 'GET', 1, 64, 'builtin'),
('gravatar', 'Gravatar', 'developer', 'https://en.gravatar.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 63, 'builtin'),
('pastebin', 'Pastebin', 'developer', 'https://pastebin.com/u/{}', 'status_code', '[404]', NULL, 'GET', 1, 62, 'builtin'),
('opencollective', 'Open Collective', 'developer', 'https://opencollective.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 61, 'builtin'),
('liberapay', 'Liberapay', 'developer', 'https://liberapay.com/{}/', 'status_code', '[404]', NULL, 'GET', 1, 60, 'builtin'),
('tumblr', 'Tumblr', 'social', 'https://{}.tumblr.com/', 'status_code', '[404]', NULL, 'GET', 1, 59, 'builtin'),
('flickr', 'Flickr', 'creative', 'https://www.flickr.com/people/{}/', 'status_code', '[404]', NULL, 'GET', 1, 58, 'builtin'),
('vimeo', 'Vimeo', 'creative', 'https://vimeo.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 57, 'builtin'),
('slideshare', 'SlideShare', 'social', 'https://www.slideshare.net/{}', 'status_code', '[404]', NULL, 'GET', 1, 56, 'builtin'),
('goodreads', 'Goodreads', 'social', 'https://www.goodreads.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 55, 'builtin'),
('letterboxd', 'Letterboxd', 'social', 'https://letterboxd.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 54, 'builtin'),
('mastodon_social', 'Mastodon (social)', 'social', 'https://mastodon.social/@{}', 'status_code', '[404]', NULL, 'GET', 1, 53, 'builtin'),
('buymeacoffee', 'Buy Me a Coffee', 'social', 'https://www.buymeacoffee.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 52, 'builtin'),
('giphy', 'Giphy', 'social', 'https://giphy.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 51, 'builtin'),
('imgur', 'Imgur', 'social', 'https://imgur.com/user/{}', 'status_code', '[404]', NULL, 'GET', 1, 50, 'builtin'),
('flipboard', 'Flipboard', 'social', 'https://flipboard.com/@{}', 'status_code', '[404]', NULL, 'GET', 1, 49, 'builtin'),
('tripadvisor', 'TripAdvisor', 'social', 'https://www.tripadvisor.com/Profile/{}', 'status_code', '[404]', NULL, 'GET', 1, 48, 'builtin'),
('strava', 'Strava', 'social', 'https://www.strava.com/athletes/{}', 'status_code', '[404]', NULL, 'GET', 1, 47, 'builtin'),
('gofundme', 'GoFundMe', 'social', 'https://www.gofundme.com/f/{}', 'status_code', '[404]', NULL, 'GET', 1, 46, 'builtin'),
('discord', 'Discord', 'gaming', 'https://discord.com/users/{}', 'status_code', '[404]', NULL, 'GET', 1, 45, 'builtin'),
('roblox', 'Roblox', 'gaming', 'https://www.roblox.com/users/profile?username={}', 'status_code', '[404]', NULL, 'GET', 1, 44, 'builtin'),
('chess', 'Chess.com', 'gaming', 'https://www.chess.com/member/{}', 'status_code', '[404]', '^[a-z1-9]{3,25}$', 'GET', 1, 43, 'builtin'),
('lichess', 'Lichess', 'gaming', 'https://lichess.org/@/{}', 'status_code', '[404]', NULL, 'GET', 1, 42, 'builtin'),
('xbox_gamertag', 'Xbox Gamertag', 'gaming', 'https://xboxgamertag.com/search/{}', 'status_code', '[404]', NULL, 'GET', 1, 41, 'builtin'),
('fortnite_tracker', 'Fortnite Tracker', 'gaming', 'https://fortnitetracker.com/profile/all/{}', 'status_code', '[404]', NULL, 'GET', 1, 40, 'builtin'),
('bandcamp', 'Bandcamp', 'music', 'https://{}.bandcamp.com/', 'status_code', '[404]', NULL, 'GET', 1, 39, 'builtin'),
('mixcloud', 'Mixcloud', 'music', 'https://www.mixcloud.com/{}/', 'status_code', '[404]', NULL, 'GET', 1, 38, 'builtin'),
('deezer', 'Deezer', 'music', 'https://www.deezer.com/en/profile/{}', 'status_code', '[404]', NULL, 'GET', 1, 37, 'builtin'),
('lastfm', 'Last.fm', 'music', 'https://www.last.fm/user/{}', 'status_code', '[404]', NULL, 'GET', 1, 36, 'builtin'),
('genius', 'Genius', 'music', 'https://genius.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 35, 'builtin'),
('kickstarter', 'Kickstarter', 'creative', 'https://www.kickstarter.com/profile/{}', 'status_code', '[404]', NULL, 'GET', 1, 34, 'builtin'),
('etsy', 'Etsy', 'creative', 'https://www.etsy.com/shop/{}', 'status_code', '[404]', NULL, 'GET', 1, 33, 'builtin'),
('redbubble', 'Redbubble', 'creative', 'https://www.redbubble.com/people/{}?ref=artist_title_name', 'status_code', '[404]', NULL, 'GET', 1, 32, 'builtin'),
('fiverr', 'Fiverr', 'creative', 'https://www.fiverr.com/{}', 'status_code', '[404]', NULL, 'GET', 1, 31, 'builtin'),
('upwork', 'Upwork', 'creative', 'https://www.upwork.com/freelancers/{}', 'status_code', '[404]', NULL, 'GET', 1, 30, 'builtin');
"#;

pub const MIGRATE_V15_TO_V16_OSINT_SCAN_RESULTS: &str = r#"
CREATE TABLE IF NOT EXISTS osint_scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    username TEXT NOT NULL,
    platform_name TEXT NOT NULL,
    platform_url TEXT NOT NULL,
    found INTEGER NOT NULL,
    status_code INTEGER,
    error_message TEXT,
    category TEXT,
    response_time_ms INTEGER,
    scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"#;

pub const MIGRATE_V15_TO_V16_OSINT_SCAN_RESULTS_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_osint_scan_results_username ON osint_scan_results(username);
CREATE INDEX IF NOT EXISTS idx_osint_scan_results_platform ON osint_scan_results(platform_name);
CREATE INDEX IF NOT EXISTS idx_osint_scan_results_found ON osint_scan_results(found);
CREATE INDEX IF NOT EXISTS idx_osint_scan_results_target_id ON osint_scan_results(target_id);
"#;

pub const MIGRATE_V16_TO_V17_OSINT_PLATFORMS_EXPAND: &str = r#"
ALTER TABLE osint_platforms ADD COLUMN url_main TEXT;
ALTER TABLE osint_platforms ADD COLUMN url_probe TEXT;
ALTER TABLE osint_platforms ADD COLUMN url_subpath TEXT;
ALTER TABLE osint_platforms ADD COLUMN check_type TEXT NOT NULL DEFAULT 'status_code';
ALTER TABLE osint_platforms ADD COLUMN presence_strs TEXT;
ALTER TABLE osint_platforms ADD COLUMN absence_strs TEXT;
ALTER TABLE osint_platforms ADD COLUMN request_head_only INTEGER DEFAULT 0;
ALTER TABLE osint_platforms ADD COLUMN get_params TEXT;
ALTER TABLE osint_platforms ADD COLUMN activation TEXT;
ALTER TABLE osint_platforms ADD COLUMN errors TEXT;
ALTER TABLE osint_platforms ADD COLUMN tags TEXT;
ALTER TABLE osint_platforms ADD COLUMN id_type TEXT NOT NULL DEFAULT 'username';
ALTER TABLE osint_platforms ADD COLUMN similar_search INTEGER DEFAULT 0;
ALTER TABLE osint_platforms ADD COLUMN ignore403 INTEGER DEFAULT 0;
ALTER TABLE osint_platforms ADD COLUMN disabled INTEGER DEFAULT 0;
ALTER TABLE osint_platforms ADD COLUMN protection TEXT;
ALTER TABLE osint_platforms ADD COLUMN engine TEXT;
ALTER TABLE osint_platforms ADD COLUMN engine_data TEXT;
ALTER TABLE osint_platforms ADD COLUMN username_claimed TEXT;
ALTER TABLE osint_platforms ADD COLUMN username_unclaimed TEXT;
ALTER TABLE osint_platforms ADD COLUMN alexa_rank INTEGER;
"#;

pub const MIGRATE_V16_TO_V17_OSINT_PLATFORMS_MIGRATE_URL: &str = r#"
UPDATE osint_platforms SET url_main = CASE
    WHEN url_template LIKE 'https://%' THEN SUBSTR(url_template, 1, INSTR(SUBSTR(url_template, 9), '/') + 8)
    WHEN url_template LIKE 'http://%' THEN SUBSTR(url_template, 1, INSTR(SUBSTR(url_template, 8), '/') + 7)
    ELSE url_template
END
WHERE url_main IS NULL;
UPDATE osint_platforms SET check_type = error_type;
UPDATE osint_platforms SET url_template = REPLACE(url_template, '{}', '{username}') WHERE url_template LIKE '%{}%';
UPDATE osint_platforms SET source = 'builtin' WHERE source IS NULL;
"#;

pub const MIGRATE_V16_TO_V17_OSINT_PLATFORMS_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_osint_platforms_engine ON osint_platforms(engine);
CREATE INDEX IF NOT EXISTS idx_osint_platforms_id_type ON osint_platforms(id_type);
CREATE INDEX IF NOT EXISTS idx_osint_platforms_disabled ON osint_platforms(disabled);
CREATE INDEX IF NOT EXISTS idx_osint_platforms_tags ON osint_platforms(tags);
"#;

pub fn get_version_migrations(from_version: i32, to_version: i32) -> Vec<&'static str> {
    let mut migrations = Vec::new();
    
    if from_version < 4 && to_version >= 4 {
        migrations.push(MIGRATE_V3_TO_V4_TARGETS);
        migrations.push(MIGRATE_V3_TO_V4_TARGET_GROUPS);
    }
    
    if from_version < 5 && to_version >= 5 {
        migrations.push(MIGRATE_V4_TO_V5_PORT_MARKINGS);
    }
    
    if from_version < 7 && to_version >= 7 {
        migrations.push(MIGRATE_V6_TO_V7_SEC_HEADERS);
        migrations.push(MIGRATE_V6_TO_V7_HASH_IDENTIFIER);
        migrations.push(MIGRATE_V6_TO_V7_INDEXES);
    }
    
    if from_version < 8 && to_version >= 8 {
        migrations.push(MIGRATE_V7_TO_V8_IP_GEO);
        migrations.push(MIGRATE_V7_TO_V8_INDEXES);
    }
    
    if from_version < 9 && to_version >= 9 {
        migrations.push(MIGRATE_V8_TO_V9_SSL_CHECK);
        migrations.push(MIGRATE_V8_TO_V9_INDEXES);
    }
    
    if from_version < 10 && to_version >= 10 {
        migrations.push(MIGRATE_V9_TO_V10_SITE_CHECK);
        migrations.push(MIGRATE_V9_TO_V10_INDEXES);
    }
    
    if from_version < 11 && to_version >= 11 {
        migrations.push(MIGRATE_V10_TO_V11_WAF_DETECTION);
        migrations.push(MIGRATE_V10_TO_V11_INDEXES);
    }
    
    if from_version < 12 && to_version >= 12 {
        migrations.push(MIGRATE_V11_TO_V12_TOOL_HISTORY);
        migrations.push(MIGRATE_V11_TO_V12_TOOL_HISTORY_INDEXES);
    }
    
    if from_version < 13 && to_version >= 13 {
        migrations.push(MIGRATE_V12_TO_V13_TARGET_GROUPS_FIX);
    }
    
    if from_version < 14 && to_version >= 14 {
        migrations.push(MIGRATE_V13_TO_V14_NETWORK_DISCOVERY);
        migrations.push(MIGRATE_V13_TO_V14_NETWORK_DISCOVERY_INDEXES);
    }
    
    if from_version < 15 && to_version >= 15 {
        migrations.push(MIGRATE_V14_TO_V15_OSINT_PLATFORMS);
        migrations.push(MIGRATE_V14_TO_V15_OSINT_PLATFORMS_INDEXES);
        migrations.push(MIGRATE_V14_TO_V15_OSINT_SEED_PLATFORMS);
    }
    
    if from_version < 16 && to_version >= 16 {
        migrations.push(MIGRATE_V15_TO_V16_OSINT_SCAN_RESULTS);
        migrations.push(MIGRATE_V15_TO_V16_OSINT_SCAN_RESULTS_INDEXES);
    }
    
    if from_version < 17 && to_version >= 17 {
        migrations.push(MIGRATE_V16_TO_V17_OSINT_PLATFORMS_EXPAND);
        migrations.push(MIGRATE_V16_TO_V17_OSINT_PLATFORMS_MIGRATE_URL);
        migrations.push(MIGRATE_V16_TO_V17_OSINT_PLATFORMS_INDEXES);
    }
    
    migrations
}
