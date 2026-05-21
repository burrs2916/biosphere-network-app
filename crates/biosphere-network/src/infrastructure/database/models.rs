use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    IP,
    Domain,
    URL,
    Subnet,
    Range,
    Hostname,
    Network,
    Service,
    Username,
    Email,
    Phone,
    SocialMedia,
}

impl Default for TargetType {
    fn default() -> Self {
        TargetType::IP
    }
}

impl TargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetType::IP => "IP",
            TargetType::Domain => "Domain",
            TargetType::URL => "URL",
            TargetType::Subnet => "Subnet",
            TargetType::Range => "Range",
            TargetType::Hostname => "Hostname",
            TargetType::Network => "Network",
            TargetType::Service => "Service",
            TargetType::Username => "Username",
            TargetType::Email => "Email",
            TargetType::Phone => "Phone",
            TargetType::SocialMedia => "SocialMedia",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "IP" => Some(TargetType::IP),
            "Domain" => Some(TargetType::Domain),
            "URL" => Some(TargetType::URL),
            "Subnet" => Some(TargetType::Subnet),
            "Range" => Some(TargetType::Range),
            "Hostname" => Some(TargetType::Hostname),
            "Network" => Some(TargetType::Network),
            "Service" => Some(TargetType::Service),
            "Username" => Some(TargetType::Username),
            "Email" => Some(TargetType::Email),
            "Phone" => Some(TargetType::Phone),
            "SocialMedia" => Some(TargetType::SocialMedia),
            _ => None,
        }
    }

    pub fn category(&self) -> TargetCategory {
        match self {
            TargetType::IP | TargetType::Subnet | TargetType::Range => TargetCategory::Network,
            TargetType::Domain | TargetType::Hostname | TargetType::URL => TargetCategory::Web,
            TargetType::Network | TargetType::Service => TargetCategory::Infrastructure,
            TargetType::Username | TargetType::Email | TargetType::Phone | TargetType::SocialMedia => TargetCategory::OSINT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetCategory {
    Network,
    Web,
    Infrastructure,
    OSINT,
}

impl TargetCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetCategory::Network => "network",
            TargetCategory::Web => "web",
            TargetCategory::Infrastructure => "infrastructure",
            TargetCategory::OSINT => "osint",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetStatus {
    New,
    Pending,
    Scanning,
    Completed,
    HasRisk,
    Offline,
    Error,
}

impl Default for TargetStatus {
    fn default() -> Self {
        TargetStatus::New
    }
}

impl TargetStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetStatus::New => "new",
            TargetStatus::Pending => "pending",
            TargetStatus::Scanning => "scanning",
            TargetStatus::Completed => "completed",
            TargetStatus::HasRisk => "has_risk",
            TargetStatus::Offline => "offline",
            TargetStatus::Error => "error",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "new" => Some(TargetStatus::New),
            "pending" => Some(TargetStatus::Pending),
            "scanning" => Some(TargetStatus::Scanning),
            "completed" => Some(TargetStatus::Completed),
            "has_risk" => Some(TargetStatus::HasRisk),
            "offline" => Some(TargetStatus::Offline),
            "error" => Some(TargetStatus::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
    None,
}

impl Default for RiskLevel {
    fn default() -> Self {
        RiskLevel::None
    }
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "critical",
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
            RiskLevel::Info => "info",
            RiskLevel::None => "none",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(RiskLevel::Critical),
            "high" => Some(RiskLevel::High),
            "medium" => Some(RiskLevel::Medium),
            "low" => Some(RiskLevel::Low),
            "info" => Some(RiskLevel::Info),
            "none" => Some(RiskLevel::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
    Normal,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::Critical => "critical",
            Priority::High => "high",
            Priority::Medium => "medium",
            Priority::Low => "low",
            Priority::Normal => "normal",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(Priority::Critical),
            "high" => Some(Priority::High),
            "medium" => Some(Priority::Medium),
            "low" => Some(Priority::Low),
            "normal" => Some(Priority::Normal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    PortScan,
    PingTest,
    DnsQuery,
    ServiceDetect,
    VulnScan,
    FullAudit,
}

impl ScanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanType::PortScan => "port_scan",
            ScanType::PingTest => "ping_test",
            ScanType::DnsQuery => "dns_query",
            ScanType::ServiceDetect => "service_detect",
            ScanType::VulnScan => "vuln_scan",
            ScanType::FullAudit => "full_audit",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "port_scan" => Some(ScanType::PortScan),
            "ping_test" => Some(ScanType::PingTest),
            "dns_query" => Some(ScanType::DnsQuery),
            "service_detect" => Some(ScanType::ServiceDetect),
            "vuln_scan" => Some(ScanType::VulnScan),
            "full_audit" => Some(ScanType::FullAudit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Pending => "pending",
            ScanStatus::Running => "running",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
            ScanStatus::Cancelled => "cancelled",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(ScanStatus::Pending),
            "running" => Some(ScanStatus::Running),
            "completed" => Some(ScanStatus::Completed),
            "failed" => Some(ScanStatus::Failed),
            "cancelled" => Some(ScanStatus::Cancelled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub id: Option<i64>,
    pub target: String,
    pub scan_mode: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status: String,
    pub total_ports: Option<i32>,
    pub open_ports: Option<i32>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultRecord {
    pub id: Option<i64>,
    pub task_id: i64,
    pub target: String,
    pub port: i32,
    pub status: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub os_detection: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTaskWithResults {
    pub task: ScanTask,
    pub results: Vec<ScanResultRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: Option<i64>,
    pub name: String,
    pub target_type: String,
    pub target_value: String,
    pub description: Option<String>,
    pub tags: Option<String>,
    pub location: Option<String>,
    pub organization: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_scanned_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    
    pub group_id: Option<i64>,
    pub status: String,
    pub risk_level: String,
    pub priority: String,
    pub owner: Option<String>,
    pub contact: Option<String>,
    pub auto_scan: bool,
    pub scan_interval: Option<i64>,
    pub next_scan_at: Option<DateTime<Utc>>,
    pub total_scans: i32,
    pub open_ports_count: i32,
    pub vulnerabilities_count: i32,
    pub metadata: Option<String>,
}

impl Target {
    pub fn new(name: String, target_type: String, target_value: String) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            name,
            target_type,
            target_value,
            description: None,
            tags: None,
            location: None,
            organization: None,
            created_at: now,
            updated_at: now,
            last_scanned_at: None,
            is_active: true,
            group_id: None,
            status: TargetStatus::New.as_str().to_string(),
            risk_level: RiskLevel::None.as_str().to_string(),
            priority: Priority::Normal.as_str().to_string(),
            owner: None,
            contact: None,
            auto_scan: false,
            scan_interval: None,
            next_scan_at: None,
            total_scans: 0,
            open_ports_count: 0,
            vulnerabilities_count: 0,
            metadata: None,
        }
    }
    
    pub fn parse_tags(&self) -> Vec<String> {
        match &self.tags {
            Some(tags) => tags.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => Vec::new(),
        }
    }
    
    pub fn set_tags(&mut self, tags: &[String]) {
        self.tags = Some(tags.join(","));
    }
    
    pub fn get_status(&self) -> TargetStatus {
        TargetStatus::from_str(&self.status).unwrap_or_default()
    }
    
    pub fn set_status(&mut self, status: TargetStatus) {
        self.status = status.as_str().to_string();
    }
    
    pub fn get_risk_level(&self) -> RiskLevel {
        RiskLevel::from_str(&self.risk_level).unwrap_or_default()
    }
    
    pub fn set_risk_level(&mut self, risk: RiskLevel) {
        self.risk_level = risk.as_str().to_string();
    }
    
    pub fn get_priority(&self) -> Priority {
        Priority::from_str(&self.priority).unwrap_or_default()
    }
    
    pub fn set_priority(&mut self, priority: Priority) {
        self.priority = priority.as_str().to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: Option<i64>,
    pub target_id: Option<i64>,
    pub query_domain: String,
    pub query_type: String,
    pub dns_server: Option<String>,
    pub query_time: i32,
    pub ttl: Option<i32>,
    pub result: String,
    pub raw_response: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRecord {
    pub id: Option<i64>,
    pub target_id: Option<i64>,
    pub target_host: String,
    pub packet_sent: i32,
    pub packet_received: i32,
    pub packet_loss: f64,
    pub min_rtt: Option<f64>,
    pub max_rtt: Option<f64>,
    pub avg_rtt: Option<f64>,
    pub std_dev_rtt: Option<f64>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteRecord {
    pub id: Option<i64>,
    pub target_id: Option<i64>,
    pub target_host: String,
    pub max_hops: i32,
    pub total_hops: i32,
    pub destination_reached: bool,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub id: Option<i64>,
    pub traceroute_id: i64,
    pub hop_number: i32,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub rtt1: Option<f64>,
    pub rtt2: Option<f64>,
    pub rtt3: Option<f64>,
    pub avg_rtt: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisRecord {
    pub id: Option<i64>,
    pub target_id: Option<i64>,
    pub query_target: String,
    pub query_type: String,
    pub registrar: Option<String>,
    pub registrant_name: Option<String>,
    pub registrant_email: Option<String>,
    pub registrant_org: Option<String>,
    pub created_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub name_servers: Option<String>,
    pub raw_data: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Option<i64>,
    pub task_type: String,
    pub target_id: Option<i64>,
    pub status: String,
    pub progress: f64,
    pub result_summary: Option<String>,
    pub error_message: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ScanTask {
    pub fn new(target: String, scan_mode: String) -> Self {
        Self {
            id: None,
            target,
            scan_mode,
            start_time: Utc::now(),
            end_time: None,
            status: "running".to_string(),
            total_ports: None,
            open_ports: None,
            created_at: Utc::now(),
        }
    }

    pub fn complete(&mut self, total_ports: i32, open_ports: i32) {
        self.end_time = Some(Utc::now());
        self.status = "completed".to_string();
        self.total_ports = Some(total_ports);
        self.open_ports = Some(open_ports);
    }

    pub fn fail(&mut self) {
        self.end_time = Some(Utc::now());
        self.status = "failed".to_string();
    }
}

impl ScanResultRecord {
    pub fn new(
        task_id: i64,
        target: String,
        port: u16,
        status: String,
        service: Option<String>,
        version: Option<String>,
        banner: Option<String>,
        os_detection: Option<String>,
    ) -> Self {
        Self {
            id: None,
            task_id,
            target,
            port: port as i32,
            status,
            service,
            version,
            banner,
            os_detection,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteCheckRecord {
    pub id: Option<i64>,
    pub url: String,
    pub is_online: bool,
    pub status_code: Option<i32>,
    pub response_time_ms: Option<i64>,
    pub title: Option<String>,
    pub server: Option<String>,
    pub dns_resolved: bool,
    pub ssl_valid: Option<bool>,
    pub is_redirect: bool,
    pub summary: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

impl SiteCheckRecord {
    pub fn new(
        url: String,
        is_online: bool,
        status_code: Option<i32>,
        response_time_ms: Option<i64>,
        title: Option<String>,
        server: Option<String>,
        dns_resolved: bool,
        ssl_valid: Option<bool>,
        is_redirect: bool,
        summary: String,
        result: String,
    ) -> Self {
        Self {
            id: None,
            url,
            is_online,
            status_code,
            response_time_ms,
            title,
            server,
            dns_resolved,
            ssl_valid,
            is_redirect,
            summary,
            result,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetectionRecord {
    pub id: Option<i64>,
    pub url: String,
    pub waf_detected: bool,
    pub waf_name: Option<String>,
    pub confidence: f64,
    pub summary: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

impl WafDetectionRecord {
    pub fn new(
        url: String,
        waf_detected: bool,
        waf_name: Option<String>,
        confidence: f64,
        summary: String,
        result: String,
    ) -> Self {
        Self {
            id: None,
            url,
            waf_detected,
            waf_name,
            confidence,
            summary,
            result,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiscoveryRecord {
    pub id: Option<i64>,
    pub network_range: String,
    pub active_hosts: i32,
    pub total_scanned: i32,
    pub summary: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

impl NetworkDiscoveryRecord {
    pub fn new(
        network_range: String,
        active_hosts: i32,
        total_scanned: i32,
        summary: String,
        result: String,
    ) -> Self {
        Self {
            id: None,
            network_range,
            active_hosts,
            total_scanned,
            summary,
            result,
            created_at: Utc::now(),
        }
    }
}

impl DnsQuery {
    pub fn new(
        query_domain: String,
        query_type: String,
        query_time: i32,
        result: String,
    ) -> Self {
        Self {
            id: None,
            target_id: None,
            query_domain,
            query_type,
            dns_server: None,
            query_time,
            ttl: None,
            result,
            raw_response: None,
            created_at: Utc::now(),
        }
    }
}

impl PingRecord {
    pub fn new(target_host: String, packet_sent: i32, packet_received: i32) -> Self {
        let packet_loss = if packet_sent > 0 {
            ((packet_sent - packet_received) as f64 / packet_sent as f64) * 100.0
        } else {
            0.0
        };
        
        Self {
            id: None,
            target_id: None,
            target_host,
            packet_sent,
            packet_received,
            packet_loss,
            min_rtt: None,
            max_rtt: None,
            avg_rtt: None,
            std_dev_rtt: None,
            status: if packet_received > 0 { "success".to_string() } else { "failed".to_string() },
            error_message: None,
            created_at: Utc::now(),
        }
    }
}

impl TracerouteRecord {
    pub fn new(target_host: String, max_hops: i32) -> Self {
        Self {
            id: None,
            target_id: None,
            target_host,
            max_hops,
            total_hops: 0,
            destination_reached: false,
            result: String::new(),
            created_at: Utc::now(),
        }
    }
}

impl WhoisRecord {
    pub fn new(query_target: String, query_type: String) -> Self {
        Self {
            id: None,
            target_id: None,
            query_target,
            query_type,
            registrar: None,
            registrant_name: None,
            registrant_email: None,
            registrant_org: None,
            created_date: None,
            expiration_date: None,
            updated_date: None,
            name_servers: None,
            raw_data: None,
            created_at: Utc::now(),
        }
    }
}

impl Task {
    pub fn new(task_type: String) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            task_type,
            target_id: None,
            status: "pending".to_string(),
            progress: 0.0,
            result_summary: None,
            error_message: None,
            start_time: now,
            end_time: None,
            created_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecHeaderRecord {
    pub id: Option<i64>,
    pub url: String,
    pub score: i32,
    pub grade: String,
    pub present_count: i32,
    pub missing_count: i32,
    pub summary: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

impl SecHeaderRecord {
    pub fn new(
        url: String,
        score: i32,
        grade: String,
        present_count: i32,
        missing_count: i32,
        summary: String,
        result: String,
    ) -> Self {
        Self {
            id: None,
            url,
            score,
            grade,
            present_count,
            missing_count,
            summary,
            result,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashIdentifierRecord {
    pub id: Option<i64>,
    pub hash_value: String,
    pub possible_types: String,
    pub created_at: DateTime<Utc>,
}

impl HashIdentifierRecord {
    pub fn new(hash_value: String, possible_types: String) -> Self {
        Self {
            id: None,
            hash_value,
            possible_types,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeoRecord {
    pub id: Option<i64>,
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub isp: String,
    pub org: String,
    pub timezone: String,
    pub created_at: DateTime<Utc>,
}

impl IpGeoRecord {
    pub fn new(
        ip: String,
        country: String,
        country_code: String,
        region: String,
        city: String,
        latitude: f64,
        longitude: f64,
        isp: String,
        org: String,
        timezone: String,
    ) -> Self {
        Self {
            id: None,
            ip,
            country,
            country_code,
            region,
            city,
            latitude,
            longitude,
            isp,
            org,
            timezone,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetGroup {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub target_ids: Option<String>,
    pub tags: Option<String>,
    pub color: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    
    pub parent_id: Option<i64>,
    pub icon: Option<String>,
    pub target_count: i32,
    pub active_count: i32,
    pub risk_count: i32,
    pub default_scan_config: Option<String>,
    pub auto_scan: bool,
    pub scan_interval: Option<i64>,
    pub owner: Option<String>,
    pub is_public: bool,
    pub shared_with: Option<String>,
}

impl TargetGroup {
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            name,
            description: None,
            target_ids: None,
            tags: None,
            color: Self::generate_random_color(),
            created_at: now,
            updated_at: None,
            parent_id: None,
            icon: None,
            target_count: 0,
            active_count: 0,
            risk_count: 0,
            default_scan_config: None,
            auto_scan: false,
            scan_interval: None,
            owner: None,
            is_public: true,
            shared_with: None,
        }
    }

    fn generate_random_color() -> String {
        let colors = [
            "#667eea", "#764ba2", "#f093fb", "#f5576c",
            "#4facfe", "#00f2fe", "#43e97b", "#38f9d7",
            "#fa709a", "#fee140", "#a8edea", "#fed6e3",
            "#ff9a9e", "#fecfef", "#ffecd2", "#fcb69f",
        ];
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        if let Some(nanos) = chrono::Utc::now().timestamp_nanos_opt() {
            nanos.hash(&mut hasher);
        } else {
            chrono::Utc::now().timestamp().hash(&mut hasher);
        }
        let index = hasher.finish() as usize % colors.len();
        
        colors[index].to_string()
    }

    pub fn parse_target_ids(&self) -> Vec<i64> {
        match &self.target_ids {
            Some(ids) => ids.split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn set_target_ids(&mut self, ids: &[i64]) {
        self.target_ids = Some(ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(","));
    }

    pub fn parse_tags(&self) -> Vec<String> {
        match &self.tags {
            Some(tags) => tags.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn set_tags(&mut self, tags: &[String]) {
        self.tags = Some(tags.join(","));
    }
    
    pub fn parse_shared_with(&self) -> Vec<String> {
        match &self.shared_with {
            Some(users) => users.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => Vec::new(),
        }
    }
    
    pub fn set_shared_with(&mut self, users: &[String]) {
        self.shared_with = Some(users.join(","));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCheckRecord {
    pub id: Option<i64>,
    pub host: String,
    pub port: i32,
    pub is_secure: bool,
    pub protocol_version: String,
    pub cipher_name: String,
    pub cipher_bits: i32,
    pub score: i32,
    pub grade: String,
    pub subject_cn: String,
    pub issuer_cn: String,
    pub is_expired: bool,
    pub days_remaining: i64,
    pub is_self_signed: bool,
    pub key_type: String,
    pub key_bits: i32,
    pub summary: String,
    pub result: String,
    pub created_at: DateTime<Utc>,
}

impl SslCheckRecord {
    pub fn new(
        host: String,
        port: i32,
        is_secure: bool,
        protocol_version: String,
        cipher_name: String,
        cipher_bits: i32,
        score: i32,
        grade: String,
        subject_cn: String,
        issuer_cn: String,
        is_expired: bool,
        days_remaining: i64,
        is_self_signed: bool,
        key_type: String,
        key_bits: i32,
        summary: String,
        result: String,
    ) -> Self {
        Self {
            id: None,
            host,
            port,
            is_secure,
            protocol_version,
            cipher_name,
            cipher_bits,
            score,
            grade,
            subject_cn,
            issuer_cn,
            is_expired,
            days_remaining,
            is_self_signed,
            key_type,
            key_bits,
            summary,
            result,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolHistoryRecord {
    pub id: Option<i64>,
    pub tool_type: String,
    pub tool_name: String,
    pub input_summary: String,
    pub result_summary: Option<String>,
    pub result_json: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

impl ToolHistoryRecord {
    pub fn new(
        tool_type: String,
        tool_name: String,
        input_summary: String,
        result_summary: Option<String>,
        result_json: String,
        status: String,
    ) -> Self {
        Self {
            id: None,
            tool_type,
            tool_name,
            input_summary,
            result_summary,
            result_json,
            status,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintPlatform {
    pub id: Option<i64>,
    pub name: String,
    pub display_name: Option<String>,
    pub category: String,
    pub url_template: String,
    pub url_main: Option<String>,
    pub url_probe: Option<String>,
    pub url_subpath: Option<String>,
    pub check_type: String,
    pub error_type: String,
    pub error_codes: Option<String>,
    pub error_messages: Option<String>,
    pub error_url: Option<String>,
    pub presence_strs: Option<String>,
    pub absence_strs: Option<String>,
    pub regex_check: Option<String>,
    pub request_method: String,
    pub request_head_only: bool,
    pub headers: Option<String>,
    pub payload: Option<String>,
    pub get_params: Option<String>,
    pub activation: Option<String>,
    pub errors: Option<String>,
    pub tags: Option<String>,
    pub id_type: String,
    pub similar_search: bool,
    pub ignore403: bool,
    pub disabled: bool,
    pub protection: Option<String>,
    pub engine: Option<String>,
    pub engine_data: Option<String>,
    pub username_claimed: Option<String>,
    pub username_unclaimed: Option<String>,
    pub alexa_rank: Option<i64>,
    pub is_active: bool,
    pub is_built_in: bool,
    pub priority: i32,
    pub notes: Option<String>,
    pub source: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OsintPlatform {
    pub fn new(name: String, category: String, url_template: String) -> Self {
        let now = Utc::now();
        Self {
            id: None,
            name,
            display_name: None,
            category,
            url_template,
            url_main: None,
            url_probe: None,
            url_subpath: None,
            check_type: "status_code".to_string(),
            error_type: "status_code".to_string(),
            error_codes: Some("[404]".to_string()),
            error_messages: None,
            error_url: None,
            presence_strs: None,
            absence_strs: None,
            regex_check: None,
            request_method: "GET".to_string(),
            request_head_only: false,
            headers: None,
            payload: None,
            get_params: None,
            activation: None,
            errors: None,
            tags: None,
            id_type: "username".to_string(),
            similar_search: false,
            ignore403: false,
            disabled: false,
            protection: None,
            engine: None,
            engine_data: None,
            username_claimed: None,
            username_unclaimed: None,
            alexa_rank: None,
            is_active: true,
            is_built_in: false,
            priority: 0,
            notes: None,
            source: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn parse_error_codes(&self) -> Vec<u16> {
        self.error_codes
            .as_ref()
            .and_then(|s| serde_json::from_str::<Vec<u16>>(s).ok())
            .unwrap_or_else(|| vec![404])
    }

    pub fn parse_error_messages(&self) -> Vec<String> {
        self.error_messages
            .as_ref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_presence_strs(&self) -> Vec<String> {
        self.presence_strs
            .as_ref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_absence_strs(&self) -> Vec<String> {
        self.absence_strs
            .as_ref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_headers(&self) -> std::collections::HashMap<String, String> {
        self.headers
            .as_ref()
            .and_then(|s| serde_json::from_str::<std::collections::HashMap<String, String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_get_params(&self) -> std::collections::HashMap<String, String> {
        self.get_params
            .as_ref()
            .and_then(|s| serde_json::from_str::<std::collections::HashMap<String, String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_payload(&self) -> std::collections::HashMap<String, serde_json::Value> {
        self.payload
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_errors(&self) -> std::collections::HashMap<String, String> {
        self.errors
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_tags(&self) -> Vec<String> {
        self.tags
            .as_ref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn parse_activation(&self) -> Option<serde_json::Value> {
        self.activation
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
    }

    pub fn parse_protection(&self) -> Vec<String> {
        self.protection
            .as_ref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn build_url(&self, username: &str) -> String {
        let url = self.url_template.replace("{username}", username);
        let url = if let Some(ref subpath) = self.url_subpath {
            url.replace("{urlSubpath}", subpath)
        } else {
            url
        };
        let url = if let Some(ref main) = self.url_main {
            url.replace("{urlMain}", main)
        } else {
            url
        };
        let re = regex::Regex::new(r"(?<!:)/+").unwrap();
        re.replace_all(&url, "/").to_string()
    }

    pub fn build_probe_url(&self, username: &str) -> String {
        if let Some(ref probe) = self.url_probe {
            let url = probe
                .replace("{username}", username)
                .replace("{urlSubpath}", self.url_subpath.as_deref().unwrap_or(""))
                .replace("{urlMain}", self.url_main.as_deref().unwrap_or(""));
            let mut url = url;
            let params = self.parse_get_params();
            if !params.is_empty() {
                let separator = if url.contains('?') { "&" } else { "?" };
                let query: Vec<String> = params.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect();
                url.push_str(separator);
                url.push_str(&query.join("&"));
            }
            let re = regex::Regex::new(r"(?<!:)/+").unwrap();
            re.replace_all(&url, "/").to_string()
        } else {
            self.build_url(username)
        }
    }

    pub fn should_allow_redirects(&self) -> bool {
        self.check_type != "response_url"
    }

    pub fn effective_request_method(&self) -> &str {
        if self.request_method.is_empty() {
            if self.check_type == "status_code" && self.request_head_only {
                return "HEAD";
            }
            return "GET";
        }
        &self.request_method
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintScanResult {
    pub id: Option<i64>,
    pub target_id: Option<i64>,
    pub username: String,
    pub platform_name: String,
    pub platform_url: String,
    pub found: bool,
    pub status_code: Option<i32>,
    pub error_message: Option<String>,
    pub category: Option<String>,
    pub response_time_ms: Option<i64>,
    pub scanned_at: DateTime<Utc>,
}
