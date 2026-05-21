use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WellKnownPort {
    pub port: u16,
    pub service: String,
    pub protocol: String,
    pub description: String,
    #[serde(serialize_with = "serialize_category")]
    pub category: PortCategory,
    #[serde(serialize_with = "serialize_risk")]
    pub risk_level: RiskLevel,
}

fn serialize_category<S>(category: &PortCategory, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(category.as_str())
}

fn serialize_risk<S>(risk: &RiskLevel, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(risk.as_str())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortCategory {
    Web,
    Database,
    RemoteAccess,
    Mail,
    FileTransfer,
    Administration,
    IoT,
    Development,
    Messaging,
    Streaming,
    VPN,
    Proxy,
    Printing,
    Gaming,
    Other,
}

impl PortCategory {
    pub fn as_str(&self) -> &str {
        match self {
            PortCategory::Web => "Web",
            PortCategory::Database => "Database",
            PortCategory::RemoteAccess => "RemoteAccess",
            PortCategory::Mail => "Mail",
            PortCategory::FileTransfer => "FileTransfer",
            PortCategory::Administration => "Administration",
            PortCategory::IoT => "IoT",
            PortCategory::Development => "Development",
            PortCategory::Messaging => "Messaging",
            PortCategory::Streaming => "Streaming",
            PortCategory::VPN => "VPN",
            PortCategory::Proxy => "Proxy",
            PortCategory::Printing => "Printing",
            PortCategory::Gaming => "Gaming",
            PortCategory::Other => "Other",
        }
    }
    
    pub fn icon(&self) -> &str {
        match self {
            PortCategory::Web => "🌐",
            PortCategory::Database => "🗄️",
            PortCategory::RemoteAccess => "🖥️",
            PortCategory::Mail => "📧",
            PortCategory::FileTransfer => "📁",
            PortCategory::Administration => "⚙️",
            PortCategory::IoT => "🔌",
            PortCategory::Development => "💻",
            PortCategory::Messaging => "💬",
            PortCategory::Streaming => "🎬",
            PortCategory::VPN => "🔒",
            PortCategory::Proxy => "🔄",
            PortCategory::Printing => "🖨️",
            PortCategory::Gaming => "🎮",
            PortCategory::Other => "❓",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn as_str(&self) -> &str {
        match self {
            RiskLevel::Critical => "Critical",
            RiskLevel::High => "High",
            RiskLevel::Medium => "Medium",
            RiskLevel::Low => "Low",
            RiskLevel::Info => "Info",
        }
    }
    
    pub fn color(&self) -> &str {
        match self {
            RiskLevel::Critical => "#dc2626",  // Red
            RiskLevel::High => "#ea580c",      // Orange
            RiskLevel::Medium => "#ca8a04",    // Yellow
            RiskLevel::Low => "#16a34a",       // Green
            RiskLevel::Info => "#6b7280",      // Gray
        }
    }
    
    pub fn score(&self) -> u8 {
        match self {
            RiskLevel::Critical => 5,
            RiskLevel::High => 4,
            RiskLevel::Medium => 3,
            RiskLevel::Low => 2,
            RiskLevel::Info => 1,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref WELL_KNOWN_PORTS: Vec<WellKnownPort> = vec![
        // ===== Web Services (HTTP/HTTPS) =====
        WellKnownPort { port: 80, service: "http".to_string(), protocol: "TCP".to_string(), description: "Hypertext Transfer Protocol (HTTP)".to_string(), category: PortCategory::Web, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 443, service: "https".to_string(), protocol: "TCP".to_string(), description: "HTTP Secure (HTTPS)".to_string(), category: PortCategory::Web, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 8080, service: "http-proxy".to_string(), protocol: "TCP".to_string(), description: "HTTP Alternate/Proxy".to_string(), category: PortCategory::Web, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 8443, service: "https-alt".to_string(), protocol: "TCP".to_string(), description: "HTTPS Alternate".to_string(), category: PortCategory::Web, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 8000, service: "http-dev".to_string(), protocol: "TCP".to_string(), description: "HTTP Dev Server (Django/Express)".to_string(), category: PortCategory::Development, risk_level: RiskLevel::Low },
        WellKnownPort { port: 8888, service: "http-alt2".to_string(), protocol: "TCP".to_string(), description: "HTTP Alternate 2".to_string(), category: PortCategory::Development, risk_level: RiskLevel::Low },
        WellKnownPort { port: 3000, service: "node-dev".to_string(), protocol: "TCP".to_string(), description: "Node.js Development Server".to_string(), category: PortCategory::Development, risk_level: RiskLevel::Low },
        WellKnownPort { port: 5000, service: "flask-dev".to_string(), protocol: "TCP".to_string(), description: "Flask/Django Dev Server".to_string(), category: PortCategory::Development, risk_level: RiskLevel::Low },
        WellKnownPort { port: 4000, service: "graphql".to_string(), protocol: "TCP".to_string(), description: "GraphQL IDE/Server".to_string(), category: PortCategory::Development, risk_level: RiskLevel::Low },
        WellKnownPort { port: 9090, service: "prometheus".to_string(), protocol: "TCP".to_string(), description: "Prometheus Monitoring".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },

        // ===== Remote Access / Administration =====
        WellKnownPort { port: 22, service: "ssh".to_string(), protocol: "TCP".to_string(), description: "Secure Shell (SSH)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::High },
        WellKnownPort { port: 23, service: "telnet".to_string(), protocol: "TCP".to_string(), description: "Telnet (Unencrypted)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 3389, service: "rdp".to_string(), protocol: "TCP".to_string(), description: "Remote Desktop Protocol (RDP)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 5900, service: "vnc".to_string(), protocol: "TCP".to_string(), description: "Virtual Network Computing (VNC)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::High },
        WellKnownPort { port: 5901, service: "vnc-display1".to_string(), protocol: "TCP".to_string(), description: "VNC Display :1".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::High },
        WellKnownPort { port: 1723, service: "pptp".to_string(), protocol: "TCP".to_string(), description: "Point-to-Point Tunneling Protocol".to_string(), category: PortCategory::VPN, risk_level: RiskLevel::Medium },
        
        // ===== Database Services =====
        WellKnownPort { port: 3306, service: "mysql".to_string(), protocol: "TCP".to_string(), description: "MySQL/MariaDB Database".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 5432, service: "postgresql".to_string(), protocol: "TCP".to_string(), description: "PostgreSQL Database".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 27017, service: "mongodb".to_string(), protocol: "TCP".to_string(), description: "MongoDB Database".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 6379, service: "redis".to_string(), protocol: "TCP".to_string(), description: "Redis Key-Value Store".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 11211, service: "memcached".to_string(), protocol: "TCP".to_string(), description: "Memcached Cache".to_string(), category: PortCategory::Database, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 1433, service: "mssql".to_string(), protocol: "TCP".to_string(), description: "Microsoft SQL Server".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 1521, service: "oracle-db".to_string(), protocol: "TCP".to_string(), description: "Oracle Database".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 27018, service: "mongodb-config".to_string(), protocol: "TCP".to_string(), description: "MongoDB Config Server".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 9200, service: "elasticsearch".to_string(), protocol: "TCP".to_string(), description: "Elasticsearch Search Engine".to_string(), category: PortCategory::Database, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 5672, service: "rabbitmq".to_string(), protocol: "TCP".to_string(), description: "RabbitMQ Message Broker".to_string(), category: PortCategory::Database, risk_level: RiskLevel::Medium },

        // ===== Mail Services =====
        WellKnownPort { port: 25, service: "smtp".to_string(), protocol: "TCP".to_string(), description: "Simple Mail Transfer Protocol".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::High },
        WellKnownPort { port: 110, service: "pop3".to_string(), protocol: "TCP".to_string(), description: "Post Office Protocol v3".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 143, service: "imap".to_string(), protocol: "TCP".to_string(), description: "Internet Message Access Protocol".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 465, service: "smtps".to_string(), protocol: "TCP".to_string(), description: "SMTP over SSL/TLS".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 587, service: "smtp-submission".to_string(), protocol: "TCP".to_string(), description: "SMTP Submission".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 993, service: "imaps".to_string(), protocol: "TCP".to_string(), description: "IMAP over SSL".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 995, service: "pop3s".to_string(), protocol: "TCP".to_string(), description: "POP3 over SSL".to_string(), category: PortCategory::Mail, risk_level: RiskLevel::Medium },

        // ===== File Transfer =====
        WellKnownPort { port: 20, service: "ftp-data".to_string(), protocol: "TCP".to_string(), description: "FTP Data Transfer".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 21, service: "ftp".to_string(), protocol: "TCP".to_string(), description: "File Transfer Protocol (Control)".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::High },
        WellKnownPort { port: 69, service: "tftp".to_string(), protocol: "UDP".to_string(), description: "Trivial File Transfer Protocol".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::High },
        WellKnownPort { port: 445, service: "smb".to_string(), protocol: "TCP".to_string(), description: "SMB/CIFS File Sharing".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 2049, service: "nfs".to_string(), protocol: "TCP".to_string(), description: "Network File System".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::High },
        WellKnownPort { port: 1099, service: "rmiregistry".to_string(), protocol: "TCP".to_string(), description: "Java RMI Registry".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::High },

        // ===== DNS Services =====
        WellKnownPort { port: 53, service: "dns".to_string(), protocol: "TCP/UDP".to_string(), description: "Domain Name System".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::High },

        // ===== Directory Services =====
        WellKnownPort { port: 389, service: "ldap".to_string(), protocol: "TCP".to_string(), description: "Lightweight Directory Access Protocol".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::High },
        WellKnownPort { port: 636, service: "ldaps".to_string(), protocol: "TCP".to_string(), description: "LDAP over SSL".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 3268, service: "ldap-gc".to_string(), protocol: "TCP".to_string(), description: "LDAP Global Catalog".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },

        // ===== Authentication =====
        WellKnownPort { port: 88, service: "kerberos".to_string(), protocol: "TCP/UDP".to_string(), description: "Kerberos Authentication".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::High },
        WellKnownPort { port: 135, service: "rpc".to_string(), protocol: "TCP".to_string(), description: "Microsoft RPC Endpoint Mapper".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 139, service: "netbios-ssn".to_string(), protocol: "TCP".to_string(), description: "NetBIOS Session Service".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::High },

        // ===== Messaging / Chat =====
        WellKnownPort { port: 5222, service: "xmpp-client".to_string(), protocol: "TCP".to_string(), description: "XMPP/Jabber Client".to_string(), category: PortCategory::Messaging, risk_level: RiskLevel::Low },
        WellKnownPort { port: 5269, service: "xmpp-server".to_string(), protocol: "TCP".to_string(), description: "XMPP Server-to-Server".to_string(), category: PortCategory::Messaging, risk_level: RiskLevel::Low },

        // ===== VPN / Tunneling =====
        WellKnownPort { port: 1194, service: "openvpn".to_string(), protocol: "UDP".to_string(), description: "OpenVPN".to_string(), category: PortCategory::VPN, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 500, service: "isakmp".to_string(), protocol: "UDP".to_string(), description: "IKE/IPsec VPN".to_string(), category: PortCategory::VPN, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 4500, service: "ipsec-nat-t".to_string(), protocol: "UDP".to_string(), description: "IPsec NAT Traversal".to_string(), category: PortCategory::VPN, risk_level: RiskLevel::Medium },

        // ===== Proxy Services =====
        WellKnownPort { port: 1080, service: "socks".to_string(), protocol: "TCP".to_string(), description: "SOCKS Proxy".to_string(), category: PortCategory::Proxy, risk_level: RiskLevel::High },
        WellKnownPort { port: 3128, service: "squid-http".to_string(), protocol: "TCP".to_string(), description: "Squid HTTP Proxy".to_string(), category: PortCategory::Proxy, risk_level: RiskLevel::Medium },

        // ===== IoT / Embedded Devices =====
        WellKnownPort { port: 1883, service: "mqtt".to_string(), protocol: "TCP".to_string(), description: "MQTT Message Queue".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 502, service: "modbus".to_string(), protocol: "TCP".to_string(), description: "Modbus SCADA/ICS".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 161, service: "snmp".to_string(), protocol: "UDP".to_string(), description: "Simple Network Management Protocol".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 162, service: "snmp-trap".to_string(), protocol: "UDP".to_string(), description: "SNMP Trap".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 554, service: "rtsp".to_string(), protocol: "TCP".to_string(), description: "Real Time Streaming Protocol (CCTV)".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 2323, service: "telnet-alt".to_string(), protocol: "TCP".to_string(), description: "Telnet Alternate (IoT devices)".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Critical },

        // ===== Printing =====
        WellKnownPort { port: 631, service: "ipp".to_string(), protocol: "TCP".to_string(), description: "Internet Printing Protocol".to_string(), category: PortCategory::Printing, risk_level: RiskLevel::Low },
        WellKnownPort { port: 9100, service: "raw-printer".to_string(), protocol: "TCP".to_string(), description: "Raw Printer Port (JetDirect)".to_string(), category: PortCategory::Printing, risk_level: RiskLevel::Low },

        // ===== Gaming =====
        WellKnownPort { port: 25565, service: "minecraft".to_string(), protocol: "TCP".to_string(), description: "Minecraft Server".to_string(), category: PortCategory::Gaming, risk_level: RiskLevel::Info },
        WellKnownPort { port: 27015, service: "srcds".to_string(), protocol: "UDP".to_string(), description: "Source Dedicated Server (CSGO/TF2)".to_string(), category: PortCategory::Gaming, risk_level: RiskLevel::Info },
        WellKnownPort { port: 7777, service: "unreal-tournament".to_string(), protocol: "UDP".to_string(), description: "Unreal Tournament Server".to_string(), category: PortCategory::Gaming, risk_level: RiskLevel::Info },

        // ===== Other Common Ports =====
        WellKnownPort { port: 123, service: "ntp".to_string(), protocol: "UDP".to_string(), description: "Network Time Protocol".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Info },
        WellKnownPort { port: 512, service: "exec".to_string(), protocol: "TCP".to_string(), description: "Remote Process Execution (rexec)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 513, service: "login".to_string(), protocol: "TCP".to_string(), description: "Remote Login (rlogin)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 514, service: "syslog".to_string(), protocol: "UDP".to_string(), description: "System Logging".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Low },
        WellKnownPort { port: 520, service: "rip".to_string(), protocol: "UDP".to_string(), description: "Routing Information Protocol".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 873, service: "rsync".to_string(), protocol: "TCP".to_string(), description: "Rsync File Synchronization".to_string(), category: PortCategory::FileTransfer, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 1900, service: "ssdp".to_string(), protocol: "UDP".to_string(), description: "Simple Service Discovery Protocol".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Low },
        WellKnownPort { port: 2000, service: "cisco-sccp".to_string(), protocol: "TCP".to_string(), description: "Cisco SCCP VoIP".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 3300, service: "sybase".to_string(), protocol: "TCP".to_string(), description: "Sybase SQL Server".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 3690, service: "svn".to_string(), protocol: "TCP".to_string(), description: "Subversion Version Control".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Low },
        WellKnownPort { port: 5009, service: "airport-admin".to_string(), protocol: "TCP".to_string(), description: "Apple Airport Admin".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 5060, service: "sip".to_string(), protocol: "TCP/UDP".to_string(), description: "Session Initiation Protocol (VoIP)".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 5061, service: "sips".to_string(), protocol: "TCP".to_string(), description: "SIP over TLS".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 5902, service: "vnc-display2".to_string(), protocol: "TCP".to_string(), description: "VNC Display :2".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::High },
        WellKnownPort { port: 5985, service: "winrm".to_string(), protocol: "TCP".to_string(), description: "Windows Remote Management (HTTP)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 5986, service: "winrms".to_string(), protocol: "TCP".to_string(), description: "Windows Remote Management (HTTPS)".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 6000, service: "x11".to_string(), protocol: "TCP".to_string(), description: "X Window System".to_string(), category: PortCategory::RemoteAccess, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 6443, service: "kubernetes-api".to_string(), protocol: "TCP".to_string(), description: "Kubernetes API Server".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::High },
        WellKnownPort { port: 6666, service: "irc".to_string(), protocol: "TCP".to_string(), description: "Internet Relay Chat".to_string(), category: PortCategory::Messaging, risk_level: RiskLevel::Low },
        WellKnownPort { port: 7070, service: "kibana".to_string(), protocol: "TCP".to_string(), description: "Kibana Web Interface".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 8001, service: "vcm-tun".to_string(), protocol: "TCP".to_string(), description: "VCOM Tunnel".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 8008, service: "http-alt3".to_string(), protocol: "TCP".to_string(), description: "HTTP Alternate 3".to_string(), category: PortCategory::Web, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 8333, service: "bitcoin-rpc".to_string(), protocol: "TCP".to_string(), description: "Bitcoin RPC".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Low },
        WellKnownPort { port: 8500, service: "consul".to_string(), protocol: "TCP".to_string(), description: "Consul Service Discovery".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 9000, service: "sonarqube".to_string(), protocol: "TCP".to_string(), description: "SonarQube Code Quality".to_string(), category: PortCategory::Development, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 9001, service: "tor-or-control".to_string(), protocol: "TCP".to_string(), description: "Tor OR Control Port".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 9300, service: "elastic-comm".to_string(), protocol: "TCP".to_string(), description: "Elasticsearch Node Communication".to_string(), category: PortCategory::Database, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 10000, service: "webmin".to_string(), protocol: "TCP".to_string(), description: "Webmin Admin Panel".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::High },
        WellKnownPort { port: 13337, service: "ethereum-rpc".to_string(), protocol: "TCP".to_string(), description: "Ethereum JSON-RPC".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Low },
        WellKnownPort { port: 15672, service: "rabbitmq-mgmt".to_string(), protocol: "TCP".to_string(), description: "RabbitMQ Management UI".to_string(), category: PortCategory::Database, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 18092, service: "grafana".to_string(), protocol: "TCP".to_string(), description: "Grafana Dashboard".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 20000, service: "dnp3".to_string(), protocol: "TCP".to_string(), description: "DNP3 SCADA Protocol".to_string(), category: PortCategory::IoT, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 2375, service: "docker-api".to_string(), protocol: "TCP".to_string(), description: "Docker API (Unauthenticated)".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Critical },
        WellKnownPort { port: 28017, service: "mongodb-web".to_string(), protocol: "TCP".to_string(), description: "MongoDB Web UI".to_string(), category: PortCategory::Database, risk_level: RiskLevel::High },
        WellKnownPort { port: 37777, service: "veeam-vbr".to_string(), protocol: "TCP".to_string(), description: "Veeam Backup & Replication".to_string(), category: PortCategory::Administration, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 40400, service: "couchbase-web".to_string(), protocol: "TCP".to_string(), description: "Couchbase Web Console".to_string(), category: PortCategory::Database, risk_level: RiskLevel::Medium },
        WellKnownPort { port: 49152, service: "apple-ios-sync".to_string(), protocol: "TCP".to_string(), description: "iOS Device Sync".to_string(), category: PortCategory::Other, risk_level: RiskLevel::Low },
    ];
}

impl WellKnownPort {
    pub fn get_port_info(port: u16) -> Option<&'static WellKnownPort> {
        WELL_KNOWN_PORTS.iter().find(|p| p.port == port)
    }

    pub fn get_service_name(port: u16) -> Option<&'static str> {
        Self::get_port_info(port).map(|p| p.service.as_str())
    }

    pub fn get_risk_level(port: u16) -> Option<&'static RiskLevel> {
        Self::get_port_info(port).map(|p| &p.risk_level)
    }

    pub fn get_category(port: u16) -> Option<&'static PortCategory> {
        Self::get_port_info(port).map(|p| &p.category)
    }

    pub fn get_ports_by_category(category: &PortCategory) -> Vec<u16> {
        WELL_KNOWN_PORTS.iter()
            .filter(|p| p.category == *category)
            .map(|p| p.port)
            .collect()
    }

    pub fn get_ports_by_risk(level: &RiskLevel) -> Vec<u16> {
        WELL_KNOWN_PORTS.iter()
            .filter(|p| p.risk_level == *level)
            .map(|p| p.port)
            .collect()
    }

    pub fn get_all_ports() -> Vec<u16> {
        WELL_KNOWN_PORTS.iter().map(|p| p.port).collect()
    }
}
