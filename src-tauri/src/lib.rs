#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]

mod infrastructure;

use tauri::{Manager, Emitter, State};
use infrastructure::{init_logger, log};
use biosphere_network::{
    ToolRegistry, 
    HostToIp, ResolveConfig, Resolver,
    PortScanner, PortScanConfig, ScanMode, Scanner, OSDetection,
    infrastructure::system::SystemResources,
    infrastructure::network::resolve_hostname,
    infrastructure::{Database, ScanTask, ScanResultRecord, ScanTaskWithResults},
    infrastructure::database::{DnsQuery, PingRecord},
    SecHeaderRecord, HashIdentifierRecord, IpGeoRecord, SslCheckRecord, SiteCheckRecord, WafDetectionRecord, ToolHistoryRecord, NetworkDiscoveryRecord,
    query_whois,
    encode_decode, encode_bytes, decode_bytes,
    compute_hash, timestamp_to_datetime, datetime_to_timestamp, get_current_timestamp,
    generate_passwords, generate_passphrase, check_password_strength,
    PasswordConfig, PasswordResult, PasswordStrength,
    list_zip_files, extract_zip, check_zip_encryption, brute_force_zip, ZipFileInfo, ZipExtractResult, ZipBruteForceResult,
    HashIdentification, IpGeoInfo, SecurityHeaderReport, SecurityHeaderConfig, SecurityHeaderAnalyzer,
    identify_hash, lookup_ip_geo,
    SslCheckResult, SslCheckerTool,
    SiteCheckResult, SiteCheckerTool,
    WafDetectionResult, WafDetectorTool, WafConfig,
    WordlistGeneratorTool, WordlistConfig, WordlistResult,
    SubdomainEnumTool, SubdomainConfig, SubdomainResult,
    DirScannerTool, DirScanConfig, DirScanResult,
    CveLookupTool, CveQueryConfig, CveQueryResult,
    EmailVerifierTool, EmailVerifyConfig, EmailVerifyResult,
    UsernameOsintTool, UsernameOsintConfig, UsernameOsintResult,
    IdnCheckerTool, IdnCheckConfig, IdnCheckResult, BatchIdnCheckResult,
    ReverseEngineerTool, ReverseEngineerConfig, ReverseEngineerResult,
    WifiDeauthDetectorTool, WifiDeauthConfig, WifiDeauthResult, WifiInterface,
    ParamDiscoveryTool, ParamDiscoveryConfig, ParamDiscoveryResult,
    SubdomainTakeoverTool, TakeoverConfig, TakeoverResult,
    WebCrawlerTool, WebCrawlerConfig, WebCrawlerResult, DownloadResult, BatchDownloadResult, SiteDownloadConfig, ExportConfig,
    TechDetectorTool, TechDetectConfig, TechDetectResult,
    SecretScannerTool, SecretScanConfig, SecretScanResult,
    SqliScannerTool, SqliScanConfig, SqliScanResult,
    XssScannerTool, XssScanConfig, XssScanResult,
    HashCrackerTool, HashCrackConfig, HashCrackResult,
    SteganographyTool, SteganographyConfig, SteganographyResult,
    BruteForceTool, BruteForceConfig, BruteForceResult,
    MetadataExtractorTool, MetadataExtractConfig, MetadataExtractResult,
    CorsCheckerTool, CorsCheckConfig, CorsCheckResult,
    OpenRedirectTool, OpenRedirectConfig, OpenRedirectResult,
    CookieAnalyzerTool, CookieAnalyzerConfig, CookieAnalyzerResult,
    AdminFinderTool, AdminFinderConfig, AdminFinderResult,
    CommandInjectionTool, CommandInjectionConfig, CommandInjectionResult,
    NetworkDiscoveryTool, NetworkDiscoveryConfig, NetworkDiscoveryResult,
    WifiScannerTool, WifiScanConfig, WifiScanResult, WifiNetwork, WifiConnectorTool, WifiConnectConfig, WifiConnectResult, WifiCrackDiscoveryTool, CrackResult, WifiInterfaceTool, NetworkInterface, WifiAutoCrackTool, AutoCrackResult,
    CloudAuditTool, CloudAuditConfig, CloudAuditResult,
    ApkAnalysisTool, ApkAnalysisConfig, ApkAnalysisResult,
    DnsAnalyzerTool, DnsAnalyzerConfig, DnsAnalyzerResult,
    DdosTesterTool, DdosTesterConfig, DdosTesterResult,
    PrivilegeEscCheckTool, PrivilegeEscConfig, PrivilegeEscResult,
    BinaryAnalyzerTool, BinaryAnalyzerConfig, BinaryAnalyzerResult, DirectoryScanResult,
    ExploitFrameworkTool, ExploitFrameworkConfig, ExploitFrameworkResult,
    PostExploitationTool, PostExploitationConfig, PostExploitationResult,
    PhishingDetectorTool, PhishingDetectorConfig, PhishingDetectorResult,
    PayloadInjectorTool, PayloadInjectorConfig, PayloadInjectorResult,
    AnonymityCheckerTool, AnonymityCheckerConfig, AnonymityCheckerResult,
    ForensicsAnalyzerTool, ForensicsAnalyzerConfig, ForensicsAnalyzerResult,
    AdAuditTool, AdAuditConfig, AdAuditResult,
    MobileSecurityTool, MobileSecurityConfig, MobileSecurityResult,
    AssetSearchTool, AssetSearchConfig, AssetSearchResult,
    ReverseIpTool, ReverseIpConfig, ReverseIpResult,
    CfBypassTool, CfBypassConfig, CfBypassResult,
    SocialFinderTool, SocialFinderConfig, SocialFinderResult, PlatformListItem,
    OsintGatherTool, OsintGatherConfig, OsintGatherResult,
    RatTool, RatToolConfig, RatToolResult,
    BluetoothScannerTool, BluetoothScanConfig, BluetoothScanResult,
    MemoryForensicsTool, MemoryForensicsConfig, MemoryForensicsResult,
    FirmwareAnalyzerTool, FirmwareAnalyzerConfig, FirmwareAnalyzerResult,
    SocialEngineeringTool, SocialEngineeringConfig, SocialEngineeringResult,
    request_cancel, reset_cancel,
    infrastructure::database::models::{OsintPlatform, OsintScanResult},
    MaigretImporter, ImportStats,
};
use std::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut registry = ToolRegistry::new();
    registry.register(HostToIp::new());
    registry.register(PortScanner::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(Mutex::new(registry))
        .setup(|app| {
            let data_dir = app.path().app_data_dir()
                .expect("Failed to get app data directory");
            
            std::fs::create_dir_all(&data_dir)
                .expect("Failed to create data directory");
            
            let mut log_config = infrastructure::LogConfig {
                console_output: true,
                clear_on_start: false,
                ..Default::default()
            };
            
            #[cfg(debug_assertions)]
            {
                log_config.log_dir = std::path::PathBuf::from("/dev/null");
            }
            
            init_logger(&data_dir, &log_config);
            
            log("SYSTEM", "Biosphere Network Tools Platform 启动", None);
            
            let db_path = data_dir.join("scan_history.db");
            let db = Database::new(&db_path)
                .expect("Failed to initialize database");
            app.manage(Mutex::new(db));
            
            log("SYSTEM", &format!("数据库初始化成功: {:?}", db_path), None);
            
            if let Some(db_path_str) = db_path.to_str() {
                biosphere_network::init_port_marker(db_path_str);
                log("SYSTEM", "端口标记器初始化成功", None);
            } else {
                log("SYSTEM", "警告：端口标记器初始化失败，数据库路径无效", None);
            }
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            resolve_host,
            scan_ports,
            detect_os,
            cancel_scan,
            reset_scan_state,
            list_network_tools,
            get_system_info,
            save_scan_task,
            update_scan_task,
            save_scan_results,
            get_scan_history,
            get_scan_task_detail,
            clear_scan_history,
            delete_scan_task,
            search_scan_history,
            dns_query,
            get_dns_query_history,
            delete_dns_query,
            clear_dns_query_history,
            ping,
            save_ping_result,
            get_ping_history,
            delete_ping_record,
            clear_ping_history,
            target_manager,
            mark_port,
            unmark_port,
            get_port_marking,
            get_all_port_markings,
            get_well_known_ports,
            get_port_info,
            export_port_markings,
            import_port_markings,
            batch_scan_ports,
            whois_query,
            save_whois_record,
            get_whois_history,
            delete_whois_record,
            clear_whois_history,
            encode_decode_command,
            encode_file_command,
            decode_file_command,
            compute_hash_command,
            detect_encoding_command,
            timestamp_to_datetime_command,
            datetime_to_timestamp_command,
            get_current_timestamp_command,
            generate_passwords_command,
            generate_passphrase_command,
            check_password_strength_command,
            list_zip_files_command,
            check_zip_encryption_command,
            extract_zip_command,
            brute_force_zip_command,
            identify_hash_command,
            lookup_ip_geo_command,
            analyze_security_headers_command,
            save_sec_header_record,
            get_sec_header_history,
            delete_sec_header_record,
            clear_sec_header_history,
            save_hash_identifier_record,
            get_hash_identifier_history,
            delete_hash_identifier_record,
            clear_hash_identifier_history,
            save_ip_geo_record,
            get_ip_geo_history,
            delete_ip_geo_record,
            clear_ip_geo_history,
            check_ssl_command,
            save_ssl_check_record,
            get_ssl_check_history,
            delete_ssl_check_record,
            clear_ssl_check_history,
            check_site_command,
            save_site_check_record,
            get_site_check_history,
            delete_site_check_record,
            clear_site_check_history,
            detect_waf_command,
            save_waf_detection_record,
            get_waf_detection_history,
            delete_waf_detection_record,
            clear_waf_detection_history,
            generate_wordlist_command,
            enumerate_subdomains_command,
            scan_dirs_command,
            lookup_cve_command,
            verify_email_command,
            check_username_osint_command,
            get_osint_platforms_command,
            get_osint_platform_by_name_command,
            create_osint_platform_command,
            update_osint_platform_command,
            delete_osint_platform_command,
            get_osint_platform_categories_command,
            count_osint_platforms_command,
            batch_import_osint_platforms_command,
            import_maigret_data_command,
            save_osint_scan_results_command,
            get_osint_scan_results_command,
            discover_params_command,
            check_subdomain_takeover_command,
            crawl_web_command,
            download_resource_command,
            download_resources_batch_command,
            download_resources_batch_with_config_command,
            download_site_command,
            download_full_site_command,
            export_crawl_result_command,
            detect_tech_command,
            scan_secrets_command,
            scan_sqli_command,
            scan_xss_command,
            crack_hash_command,
            steganography_command,
            brute_force_command,
            extract_metadata_command,
            check_cors_command,
            check_open_redirect_command,
            analyze_cookies_command,
            find_admin_command,
            scan_command_injection_command,
            discover_network_command,
            save_network_discovery_record,
            get_network_discovery_history,
            delete_network_discovery_record,
            clear_network_discovery_history,
            scan_wifi_command,
            connect_wifi_command,
            wifi_crack_discovery_command,
            list_wifi_interfaces_command,
            wifi_auto_crack_command,
            audit_cloud_command,
            analyze_apk_command,
            select_apk_file,
            analyze_dns_command,
            test_ddos_command,
            check_privilege_esc_command,
            analyze_binary_command,
            select_binary_file,
            select_directory_for_scan,
            scan_directory_for_binaries,
            scan_exploit_command,
            analyze_post_exploitation_command,
            detect_phishing_command,
            inject_payload_command,
            check_anonymity_command,
            analyze_forensics_command,
            audit_ad_command,
            analyze_mobile_security_command,
            search_assets_command,
            reverse_ip_lookup_command,
            cf_bypass_command,
            find_social_command,
            list_social_platforms_command,
            gather_osint_command,
            idn_check_command,
            idn_batch_check_command,
            reverse_engineer_command,
             wifi_deauth_detect_command,
             list_wifi_deauth_interfaces_command,
            analyze_rat_command,
            scan_bluetooth_command,
            analyze_memory_command,
            analyze_firmware_command,
            analyze_social_engineering_command,
            get_dashboard_data,
            save_tool_history,
            get_tool_history,
            get_all_tool_history,
            delete_tool_history,
            clear_tool_history,
            get_tool_help,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to Biosphere Network Tools Platform.", name)
}

#[tauri::command]
fn resolve_host(
    _registry: tauri::State<Mutex<ToolRegistry>>,
    host: String,
) -> Result<biosphere_network::ResolveResult, String> {
    let config = ResolveConfig::new(host);
    
    match Resolver::resolve(config) {
        Ok(result) => Ok(result),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
async fn scan_ports(
    _registry: tauri::State<'_, Mutex<ToolRegistry>>,
    app: tauri::AppHandle,
    db: tauri::State<'_, Mutex<Database>>,
    target: String,
    start_port: Option<u16>,
    end_port: Option<u16>,
    timeout_ms: Option<u64>,
    scan_mode: Option<String>,
    target_id: Option<i64>,
) -> Result<biosphere_network::ToolOutput, String> {
    reset_cancel();
    
    let start = start_port.unwrap_or(1);
    let end = end_port.unwrap_or(1024);
    let timeout = timeout_ms.unwrap_or(1000);
    let mode = scan_mode.as_deref().and_then(|s| match s {
        "quick" => Some(ScanMode::Quick),
        "standard" => Some(ScanMode::Standard),
        "full" => Some(ScanMode::Full),
        "custom" => Some(ScanMode::Custom),
        _ => None,
    }).unwrap_or(ScanMode::Standard);

    let config = PortScanConfig {
        target: target.clone(),
        start_port: start,
        end_port: end,
        timeout_ms: timeout,
        concurrent_limit: 100,
        scan_mode: mode,
    };

    let scanner = Scanner::new(config);
    
    let app_handle = app.clone();
    let results = scanner.scan_with_progress(move |scanned, total, open| {
        let _ = app_handle.emit("scan-progress", serde_json::json!({
            "scanned": scanned,
            "total": total,
            "open": open
        }));
    }).await.map_err(|e| e.to_string())?;

    let open_ports: Vec<&biosphere_network::PortScanResult> = 
        results.iter()
            .filter(|r| r.is_open())
            .collect();

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "port_scan".to_string(),
            open_ports_count: Some(open_ports.len() as i32),
            vulnerabilities_count: None,
            risk_level: if open_ports.len() > 10 {
                Some("high".to_string())
            } else if open_ports.len() > 3 {
                Some("medium".to_string())
            } else if !open_ports.is_empty() {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    let output = if open_ports.is_empty() {
        format!("No open ports found on {}", target)
    } else {
        let json_results: Vec<serde_json::Value> = open_ports.iter().map(|r| {
            serde_json::json!({
                "target": r.target,
                "resolved_ip": r.resolved_ip,
                "port": r.port,
                "status": format!("{:?}", r.status),
                "service": r.service,
                "version": r.version.as_ref().map(|v| v.version.clone()),
                "banner": r.banner,
            })
        }).collect();
        serde_json::to_string(&json_results).unwrap_or_default()
    };

    Ok(biosphere_network::ToolOutput::success(output))
}

#[tauri::command]
async fn detect_os(target: String, timeout_ms: Option<u64>) -> Result<OSDetectionResponse, String> {
    use std::net::IpAddr;
    
    let timeout = timeout_ms.unwrap_or(3000);
    
    let ip: IpAddr = if let Ok(ip) = target.parse() {
        ip
    } else {
        resolve_hostname(&target).await
            .map_err(|e| format!("Failed to resolve hostname '{}': {}", target, e))?
    };
    
    let detection = OSDetection::detect(ip, timeout).await;
    
    Ok(OSDetectionResponse {
        os_type: detection.os_type.clone(),
        os_family: detection.os_family.clone(),
        confidence: detection.confidence,
        ttl: detection.ttl,
        details: detection.details.clone(),
        display: detection.get_display(),
    })
}

#[tauri::command]
fn cancel_scan() {
    request_cancel();
}

#[tauri::command]
fn reset_scan_state() {
    reset_cancel();
}

#[tauri::command]
fn list_network_tools(
    registry: tauri::State<Mutex<ToolRegistry>>,
) -> Vec<biosphere_network::ToolInfo> {
    registry.lock().unwrap().list_tools()
}

#[tauri::command]
fn get_system_info() -> SystemInfoResponse {
    let resources = SystemResources::detect_cached();
    
    SystemInfoResponse {
        cpu_cores: resources.cpu_cores,
        total_memory_mb: resources.total_memory_mb,
        available_memory_mb: resources.available_memory_mb,
        cpu_usage_percent: resources.cpu_usage_percent,
        load_average: resources.load_average,
        optimal_concurrency: resources.calculate_optimal_concurrency(),
        recommended_timeout: resources.get_recommended_timeout(),
        summary: resources.summary(),
    }
}

#[tauri::command]
fn save_scan_task(
    db: State<Mutex<Database>>,
    target: String,
    scan_mode: String,
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    let task = ScanTask::new(target, scan_mode);
    db.create_scan_task(&task).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_scan_task(
    db: State<Mutex<Database>>,
    task_id: i64,
    total_ports: i32,
    open_ports: i32,
    status: String,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    let mut task = db.get_scan_task_by_id(task_id)
        .map_err(|e| e.to_string())?
        .ok_or("Task not found")?;
    
    task.total_ports = Some(total_ports);
    task.open_ports = Some(open_ports);
    task.status = status;
    task.end_time = Some(chrono::Utc::now());
    
    db.update_scan_task(&task).map_err(|e| e.to_string())
}

#[tauri::command]
fn save_scan_results(
    db: State<Mutex<Database>>,
    _task_id: i64,
    results: Vec<ScanResultRecord>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.create_scan_results_batch(&results).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_scan_history(
    db: State<Mutex<Database>>,
    limit: i32,
    offset: i32,
) -> Result<Vec<ScanTask>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_scan_tasks(limit, offset).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_scan_task_detail(
    db: State<Mutex<Database>>,
    task_id: i64,
) -> Result<Option<ScanTaskWithResults>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_scan_task_with_results(task_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_scan_task(
    db: State<Mutex<Database>>,
    task_id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_scan_task(task_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_scan_history(
    db: State<Mutex<Database>>,
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_all_scan_tasks().map(|c| c as i64).map_err(|e| e.to_string())
}

#[tauri::command]
fn search_scan_history(
    db: State<Mutex<Database>>,
    query: String,
    limit: i32,
    offset: i32,
) -> Result<Vec<ScanTask>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.search_scan_tasks(&query, limit, offset).map_err(|e| e.to_string())
}

#[derive(Debug, serde::Serialize)]
pub struct SystemInfoResponse {
    pub cpu_cores: usize,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub cpu_usage_percent: f32,
    pub load_average: f32,
    pub optimal_concurrency: usize,
    pub recommended_timeout: u64,
    pub summary: String,
}

#[derive(Debug, serde::Serialize)]
pub struct OSDetectionResponse {
    pub os_type: String,
    pub os_family: String,
    pub confidence: u8,
    pub ttl: Option<u8>,
    pub details: Vec<String>,
    pub display: String,
}

#[tauri::command]
async fn dns_query(
    domain: String,
    query_type: String,
    dns_server: Option<String>,
    timeout: Option<u64>,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<serde_json::Value, String> {
    use biosphere_network::{DnsQueryConfig, DnsQueryType, DnsResolver};
    use chrono::Utc;
    
    let qtype = match query_type.to_uppercase().as_str() {
        "A" => DnsQueryType::A,
        "AAAA" => DnsQueryType::AAAA,
        "MX" => DnsQueryType::MX,
        "NS" => DnsQueryType::NS,
        "CNAME" => DnsQueryType::CNAME,
        "TXT" => DnsQueryType::TXT,
        "SOA" => DnsQueryType::SOA,
        "PTR" => DnsQueryType::PTR,
        "ANY" => DnsQueryType::ANY,
        _ => return Err(format!("Invalid query type: {}", query_type)),
    };
    
    let mut config = DnsQueryConfig::new(domain.clone(), qtype);
    
    if let Some(server) = dns_server.clone() {
        if !server.trim().is_empty() {
            config = config.with_dns_server(server);
        }
    }
    
    config = config.with_timeout(timeout.unwrap_or(5));
    
    let result = DnsResolver::query(config).await
        .map_err(|e| e.to_string())?;
    
    let query_time = result.query_time;
    let result_json = serde_json::to_value(&result).unwrap_or_default();
    
    let dns_server_value = dns_server.clone().unwrap_or_else(|| "System DNS".to_string());
    
    let dns_query_record = DnsQuery {
        id: None,
        target_id: None,
        query_domain: domain.clone(),
        query_type: query_type.clone(),
        dns_server: Some(dns_server_value),
        query_time,
        ttl: result.records.first().map(|r| r.ttl),
        result: serde_json::to_string(&result).unwrap_or_default(),
        raw_response: Some(serde_json::to_string(&result).unwrap_or_default()),
        created_at: Utc::now(),
    };
    
    let db_guard = db.lock().unwrap();
    let _ = db_guard.create_dns_query(&dns_query_record);

    if let Some(tid) = target_id {
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "dns_query".to_string(),
            open_ports_count: None,
            vulnerabilities_count: None,
            risk_level: None,
            status: Some("completed".to_string()),
        });
    }

    Ok(result_json)
}

#[tauri::command]
fn get_dns_query_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<DnsQuery>, String> {
    let db_guard = db.lock().unwrap();
    let queries = db_guard.get_dns_queries(
        limit.unwrap_or(50),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())?;
    
    Ok(queries)
}

#[tauri::command]
fn delete_dns_query(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db_guard = db.lock().unwrap();
    db_guard.delete_dns_query(id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn clear_dns_query_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db_guard = db.lock().unwrap();
    db_guard.clear_dns_queries()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn ping(
    target: String,
    count: Option<u32>,
    timeout: Option<u64>,
    interval: Option<u64>,
    packet_size: Option<usize>,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<serde_json::Value, String> {
    use biosphere_network::{PingConfig, Pinger};
    
    let config = PingConfig::new(target.clone())
        .with_count(count.unwrap_or(4))
        .with_timeout(timeout.unwrap_or(2))
        .with_interval(interval.unwrap_or(1))
        .with_packet_size(packet_size.unwrap_or(64));
    
    let result = Pinger::ping(config)
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "ping".to_string(),
            open_ports_count: None,
            vulnerabilities_count: None,
            risk_level: None,
            status: Some("completed".to_string()),
        });
    }
    
    Ok(serde_json::to_value(result).unwrap_or_default())
}

#[tauri::command]
async fn whois_query(
    domain: String,
    timeout_ms: Option<u64>,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<serde_json::Value, String> {
    log("WHOIS", &format!("Starting query for domain: {}", domain), None);
    
    let timeout = timeout_ms.unwrap_or(10000);
    log("WHOIS", &format!("Using timeout: {}ms", timeout), None);
    
    match query_whois(domain.clone(), Some(timeout)).await {
        Ok(result) => {
            log("WHOIS", &format!("Query successful for {}", domain), None);

            if let Some(tid) = target_id {
                let db_guard = db.lock().map_err(|e| e.to_string())?;
                let service = biosphere_network::TargetService::new(db_guard.clone());
                let _ = service.record_scan(biosphere_network::ScanRecord {
                    target_id: tid,
                    scan_type: "whois".to_string(),
                    open_ports_count: None,
                    vulnerabilities_count: None,
                    risk_level: None,
                    status: Some("completed".to_string()),
                });
            }

            Ok(serde_json::to_value(result).unwrap_or_default())
        }
        Err(e) => {
            log("WHOIS", &format!("Query failed for {}: {}", domain, e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn save_whois_record(
    db: State<Mutex<Database>>,
    record: biosphere_network::infrastructure::database::WhoisRecord,
) -> Result<i64, String> {
    let db_guard = db.lock().unwrap();
    db_guard.create_whois_record(&record)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_whois_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<biosphere_network::infrastructure::database::WhoisRecord>, String> {
    let db_guard = db.lock().unwrap();
    db_guard.get_whois_records(
        limit.unwrap_or(50),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_whois_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db_guard = db.lock().unwrap();
    db_guard.delete_whois_record(id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_whois_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db_guard = db.lock().unwrap();
    db_guard.clear_whois_records()
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn encode_decode_command(
    encoding_type: String,
    operation: String,
    input: String,
) -> Result<serde_json::Value, String> {
    log("ENCODER", &format!("Processing {} {} operation", encoding_type, operation), None);
    
    match encode_decode(encoding_type, operation, input).await {
        Ok(result) => {
            log("ENCODER", "Processing successful", None);
            Ok(serde_json::to_value(result).unwrap_or_default())
        }
        Err(e) => {
            log("ENCODER", &format!("Processing failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn encode_file_command(
    encoding_type: String,
    file_data: Vec<u8>,
) -> Result<String, String> {
    log("ENCODER", &format!("Encoding file with {}, size: {} bytes", encoding_type, file_data.len()), None);
    
    match encode_bytes(encoding_type, file_data) {
        Ok(result) => {
            log("ENCODER", &format!("File encoding successful, output size: {} chars", result.len()), None);
            Ok(result)
        }
        Err(e) => {
            log("ENCODER", &format!("File encoding failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn decode_file_command(
    encoding_type: String,
    encoded_data: String,
) -> Result<Vec<u8>, String> {
    log("ENCODER", &format!("Decoding file with {}, input size: {} chars", encoding_type, encoded_data.len()), None);
    
    match decode_bytes(encoding_type, encoded_data) {
        Ok(result) => {
            log("ENCODER", &format!("File decoding successful, output size: {} bytes", result.len()), None);
            Ok(result)
        }
        Err(e) => {
            log("ENCODER", &format!("File decoding failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn compute_hash_command(
    hash_type: String,
    input: String,
) -> Result<String, String> {
    log("HASH", &format!("Computing {} hash, input length: {}", hash_type, input.len()), None);
    
    match compute_hash(hash_type, input) {
        Ok(result) => {
            log("HASH", &format!("Hash computed successfully, result: {}", result), None);
            Ok(result)
        }
        Err(e) => {
            log("HASH", &format!("Hash computation failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn detect_encoding_command(
    input: String,
) -> Result<serde_json::Value, String> {
    log("ENCODER", &format!("Detecting encoding for input length: {}", input.len()), None);
    
    use biosphere_network::tools::others::encoder_decoder::EncoderDecoderTool;
    
    match EncoderDecoderTool::detect_encoding(&input) {
        Ok((encoding_type, confidence)) => {
            let encoding_name = match encoding_type {
                biosphere_network::tools::others::encoder_decoder::EncodingType::Base64 => "base64",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Base64Url => "base64url",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Url => "url",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Html => "html",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Hex => "hex",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Base32 => "base32",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Base58 => "base58",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Jwt => "jwt",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Rot13 => "rot13",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Rot47 => "rot47",
                biosphere_network::tools::others::encoder_decoder::EncodingType::Unicode => "unicode",
            };
            
            log("ENCODER", &format!("Detected encoding: {} (confidence: {})", encoding_name, confidence), None);
            
            Ok(serde_json::json!({
                "encoding_type": encoding_name,
                "confidence": confidence
            }))
        }
        Err(e) => {
            log("ENCODER", &format!("Encoding detection failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn timestamp_to_datetime_command(
    timestamp: i64,
) -> Result<String, String> {
    match timestamp_to_datetime(timestamp) {
        Ok(result) => Ok(result),
        Err(e) => Err(e.to_string())
    }
}

#[tauri::command]
fn datetime_to_timestamp_command(
    datetime_str: String,
) -> Result<i64, String> {
    match datetime_to_timestamp(datetime_str) {
        Ok(result) => Ok(result),
        Err(e) => Err(e.to_string())
    }
}

#[tauri::command]
fn get_current_timestamp_command() -> String {
    get_current_timestamp()
}

#[tauri::command]
fn generate_passwords_command(config: PasswordConfig) -> Result<PasswordResult, String> {
    log("PASSWORD", &format!("Generating {} password(s) with length {}", config.count, config.length), None);

    match generate_passwords(config) {
        Ok(result) => {
            if result.success {
                log("PASSWORD", &format!("Successfully generated {} password(s)", result.passwords.len()), None);
            }
            Ok(result)
        }
        Err(e) => {
            log("PASSWORD", &format!("Password generation failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn generate_passphrase_command(word_count: u32, separator: String) -> Result<String, String> {
    match generate_passphrase(word_count, separator) {
        Ok(passphrase) => Ok(passphrase),
        Err(e) => Err(e.to_string())
    }
}

#[tauri::command]
fn check_password_strength_command(password: String) -> PasswordStrength {
    check_password_strength(password)
}

#[tauri::command]
fn list_zip_files_command(zip_path: String) -> Result<Vec<ZipFileInfo>, String> {
    log("ZIP", &format!("Listing files in ZIP: {}", zip_path), None);
    
    match list_zip_files(zip_path) {
        Ok(files) => {
            log("ZIP", &format!("Found {} files", files.len()), None);
            Ok(files)
        }
        Err(e) => {
            log("ZIP", &format!("Failed to list files: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn check_zip_encryption_command(zip_path: String) -> Result<bool, String> {
    log("ZIP", &format!("Checking encryption for: {}", zip_path), None);
    
    match check_zip_encryption(zip_path) {
        Ok(is_encrypted) => {
            log("ZIP", &format!("Encrypted: {}", is_encrypted), None);
            Ok(is_encrypted)
        }
        Err(e) => {
            log("ZIP", &format!("Failed to check encryption: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn extract_zip_command(
    zip_path: String,
    output_dir: String,
    password: Option<String>,
) -> Result<ZipExtractResult, String> {
    log("ZIP", &format!("Extracting ZIP: {} to {}", zip_path, output_dir), None);
    
    match extract_zip(zip_path, output_dir, password) {
        Ok(result) => {
            if result.success {
                log("ZIP", &format!("Successfully extracted {} files", result.files_extracted), None);
            }
            Ok(result)
        }
        Err(e) => {
            log("ZIP", &format!("Failed to extract ZIP: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn brute_force_zip_command(
    zip_path: String,
    mode: String,
    dictionary_path: Option<String>,
) -> Result<ZipBruteForceResult, String> {
    log("ZIP", &format!("Brute forcing ZIP: {} with mode {}", zip_path, mode), None);

    match brute_force_zip(zip_path, mode, dictionary_path) {
        Ok(result) => {
            if result.success {
                log("ZIP", &format!("Password found after {} attempts", result.attempts), None);
            } else {
                log("ZIP", &format!("Password not found after {} attempts", result.attempts), None);
            }
            Ok(result)
        }
        Err(e) => {
            log("ZIP", &format!("Brute force failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn save_ping_result(
    db: State<Mutex<Database>>,
    result: PingRecord,
) -> Result<i64, String> {
    let db_guard = db.lock().map_err(|e| e.to_string())?;
    db_guard.create_ping_record(&result)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_ping_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<PingRecord>, String> {
    let db_guard = db.lock().map_err(|e| e.to_string())?;
    let records = db_guard.get_ping_records(
        limit.unwrap_or(100),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())?;
    
    Ok(records)
}

#[tauri::command]
fn delete_ping_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db_guard = db.lock().map_err(|e| e.to_string())?;
    db_guard.delete_ping_record(id)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn clear_ping_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db_guard = db.lock().map_err(|e| e.to_string())?;
    db_guard.clear_ping_records()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn target_manager(
    db: State<Mutex<Database>>,
    action: String,
    id: Option<i64>,
    name: Option<String>,
    target_type: Option<String>,
    target_value: Option<String>,
    description: Option<String>,
    tags: Option<String>,
    location: Option<String>,
    organization: Option<String>,
    query: Option<String>,
    page: Option<i32>,
    page_size: Option<i32>,
    group_id: Option<i64>,
    color: Option<String>,
    icon: Option<String>,
    owner: Option<String>,
    contact: Option<String>,
    priority: Option<String>,
    auto_scan: Option<bool>,
    scan_interval: Option<i64>,
    metadata: Option<String>,
) -> Result<serde_json::Value, String> {
    use biosphere_network::{TargetService, TargetType};

    match action.as_str() {
        "list" => {
            let p = page.unwrap_or(1);
            let ps = page_size.unwrap_or(10);

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());

            let result = if let Some(gid) = group_id {
                service.get_targets_by_group(gid, p, ps).map_err(|e| e.to_string())?
            } else {
                service.get_targets(p, ps).map_err(|e| e.to_string())?
            };

            Ok(serde_json::json!({
                "success": true,
                "targets": result.targets,
                "total": result.total,
                "page": result.page,
                "page_size": result.page_size
            }))
        }

        "search" => {
            let q = query.ok_or("Query parameter required")?;
            let p = page.unwrap_or(1);
            let ps = page_size.unwrap_or(10);

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            let result = service.search_targets(&q, p, ps).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "targets": result.targets,
                "total": result.total,
                "page": result.page,
                "page_size": result.page_size
            }))
        }

        "create" => {
            let n = name.ok_or("Name parameter required")?;
            let tt = target_type.ok_or("Target type parameter required")?;
            let tv = target_value.ok_or("Target value parameter required")?;

            let target_type_enum = TargetType::from_str(&tt)
                .ok_or_else(|| format!("Invalid target type: {}", tt))?;

            let mut config = biosphere_network::TargetConfig::new(n.clone(), target_type_enum, tv);
            config.description = description;
            config.tags = tags.map(|t| t.split(',').map(|s| s.trim().to_string()).collect());
            config.location = location;
            config.organization = organization;
            config.owner = owner;
            config.contact = contact;
            config.priority = priority;
            config.auto_scan = auto_scan;
            config.scan_interval = scan_interval;
            config.metadata = metadata;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());

            let result = service.create_target(config).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": result.success,
                "message": result.message,
                "target_id": result.target_id
            }))
        }

        "update" => {
            let target_id = id.ok_or("ID parameter required for update")?;
            let n = name.ok_or("Name parameter required")?;
            let tt = target_type.ok_or("Target type parameter required")?;
            let tv = target_value.ok_or("Target value parameter required")?;

            let target_type_enum = TargetType::from_str(&tt)
                .ok_or_else(|| format!("Invalid target type: {}", tt))?;

            let mut config = biosphere_network::TargetConfig::new(n, target_type_enum, tv);
            config.description = description;
            config.tags = tags.map(|t| t.split(',').map(|s| s.trim().to_string()).collect());
            config.location = location;
            config.organization = organization;
            config.owner = owner;
            config.contact = contact;
            config.priority = priority;
            config.auto_scan = auto_scan;
            config.scan_interval = scan_interval;
            config.metadata = metadata;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());

            let result = service.update_target(target_id, config).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": result.success,
                "message": result.message,
                "target_id": result.target_id
            }))
        }

        "delete" => {
            let target_id = id.ok_or("ID parameter required for delete")?;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());

            let result = service.delete_target(target_id).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": result.success,
                "message": result.message,
                "target_id": result.target_id
            }))
        }

        "get_groups" => {
            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            let groups = service.get_target_groups().map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "groups": groups
            }))
        }

        "create_group" => {
            let n = name.ok_or("Name parameter required")?;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            let group_id = service.create_target_group(n.clone(), description, color, icon)
                .map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "message": format!("Group '{}' created successfully", n),
                "group_id": group_id
            }))
        }

        "update_group" => {
            let group_id = id.ok_or("ID parameter required for update")?;
            let n = name.ok_or("Name parameter required")?;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            service.update_target_group(group_id, n, description, color, icon)
                .map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "message": format!("Group {} updated successfully", group_id),
                "group_id": group_id
            }))
        }

        "delete_group" => {
            let group_id = id.ok_or("ID parameter required for delete")?;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            service.delete_target_group(group_id).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "message": format!("Group {} deleted successfully", group_id),
                "group_id": group_id
            }))
        }

        "resolve" => {
            let target_id = id.ok_or("ID parameter required for resolve")?;

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            let target = service.get_target_by_id(target_id).map_err(|e| e.to_string())?;

            match target {
                Some(t) => Ok(serde_json::json!({
                    "success": true,
                    "target": {
                        "id": t.id,
                        "name": t.name,
                        "target_type": t.target_type,
                        "target_value": t.target_value,
                        "description": t.description,
                        "tags": t.tags,
                        "location": t.location,
                        "organization": t.organization,
                        "group_id": t.group_id,
                        "status": t.status,
                        "risk_level": t.risk_level,
                        "priority": t.priority,
                        "owner": t.owner,
                        "contact": t.contact,
                        "auto_scan": t.auto_scan,
                        "scan_interval": t.scan_interval,
                        "metadata": t.metadata,
                        "created_at": t.created_at,
                        "updated_at": t.updated_at,
                        "last_scanned_at": t.last_scanned_at,
                        "is_active": t.is_active,
                        "total_scans": t.total_scans,
                        "open_ports_count": t.open_ports_count,
                        "vulnerabilities_count": t.vulnerabilities_count,
                        "next_scan_at": t.next_scan_at,
                    }
                })),
                None => Ok(serde_json::json!({
                    "success": false,
                    "message": format!("Target with id {} not found", target_id)
                }))
            }
        }

        "filtered_list" => {
            let p = page.unwrap_or(1);
            let ps = page_size.unwrap_or(10);

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());

            let result = service.get_targets_filtered(
                target_type.as_deref(),
                None, // status filter from query param
                None, // risk_level filter
                priority.as_deref(),
                tags.as_deref(),
                None, // sort_by
                None, // sort_order
                p, ps,
            ).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "targets": result.targets,
                "total": result.total,
                "page": result.page,
                "page_size": result.page_size
            }))
        }

        "batch_group" => {
            let target_ids_str = query.ok_or("target_ids parameter required")?;
            let target_ids: Vec<i64> = target_ids_str.split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            if target_ids.is_empty() {
                return Err("No valid target IDs provided".to_string());
            }

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            service.batch_update_target_group(&target_ids, group_id)
                .map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "message": format!("Updated group for {} targets", target_ids.len())
            }))
        }

        "batch_tags" => {
            let target_ids_str = query.ok_or("target_ids parameter required")?;
            let target_ids: Vec<i64> = target_ids_str.split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();

            if target_ids.is_empty() {
                return Err("No valid target IDs provided".to_string());
            }

            let tag_value = tags.ok_or("tags parameter required")?;
            let append_mode = description.as_deref() == Some("append");

            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            service.batch_update_target_tags(&target_ids, &tag_value, append_mode)
                .map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "message": format!("Updated tags for {} targets", target_ids.len())
            }))
        }

        "statistics" => {
            let db_guard = db.lock().map_err(|e| e.to_string())?;
            let service = TargetService::new(db_guard.clone());
            let stats = service.get_target_statistics()
                .map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "statistics": stats
            }))
        }

        _ => Err(format!("Unknown action: {}", action))
    }
}

#[tauri::command]
fn mark_port(port: u16, mark_type: String, note: String) -> Result<(), String> {
    use biosphere_network::{get_port_marker, MarkType};
    
    let marker = get_port_marker();
    
    let mark = match mark_type.as_str() {
        "favorite" => MarkType::Favorite,
        "important" => MarkType::Important,
        "dangerous" => MarkType::Dangerous,
        custom => MarkType::Custom(custom.to_string()),
    };
    
    marker.mark_port(port, mark, note)
}

#[tauri::command]
fn unmark_port(port: u16) -> Result<bool, String> {
    use biosphere_network::get_port_marker;
    
    let marker = get_port_marker();
    marker.unmark_port(port)
}

#[tauri::command]
fn get_port_marking(port: u16) -> Result<Option<serde_json::Value>, String> {
    use biosphere_network::get_port_marker;
    
    let marker = get_port_marker();
    let marking = marker.get_marking(port);
    
    match marking {
        Some(m) => Ok(Some(serde_json::to_value(m).map_err(|e| e.to_string())?)),
        None => Ok(None),
    }
}

#[tauri::command]
fn get_all_port_markings() -> Result<Vec<serde_json::Value>, String> {
    use biosphere_network::get_port_marker;
    
    let marker = get_port_marker();
    let markings = marker.get_all_markings();
    
    markings.into_iter()
        .map(|m| serde_json::to_value(m).map_err(|e| e.to_string()))
        .collect()
}

#[tauri::command]
fn get_well_known_ports() -> Result<Vec<serde_json::Value>, String> {
    use biosphere_network::WellKnownPort;
    
    WellKnownPort::get_all_ports()
        .into_iter()
        .filter_map(|port| WellKnownPort::get_port_info(port))
        .map(|info| serde_json::to_value(info).map_err(|e| e.to_string()))
        .collect()
}

#[tauri::command]
fn get_port_info(port: u16) -> Result<serde_json::Value, String> {
    use biosphere_network::WellKnownPort;
    
    match WellKnownPort::get_port_info(port) {
        Some(info) => serde_json::to_value(info).map_err(|e| e.to_string()),
        None => Err(format!("Port {} not found in knowledge base", port)),
    }
}

#[tauri::command]
fn export_port_markings() -> Result<String, String> {
    use biosphere_network::get_port_marker;
    
    let marker = get_port_marker();
    Ok(marker.export_markings())
}

#[tauri::command]
fn import_port_markings(json_data: String) -> Result<usize, String> {
    use biosphere_network::get_port_marker;
    
    let marker = get_port_marker();
    marker.import_markings(&json_data)
}

#[tauri::command]
async fn batch_scan_ports(
    targets: Vec<String>,
    port_range_start: Option<u16>,
    port_range_end: Option<u16>,
    timeout_ms: Option<u64>,
) -> Result<Vec<serde_json::Value>, String> {
    use biosphere_network::{PortScanConfig, ScanMode, Scanner};
    
    let mut join_set = tokio::task::JoinSet::new();
    
    for target in targets {
        let start = port_range_start.unwrap_or(1);
        let end = port_range_end.unwrap_or(1024);
        let timeout = timeout_ms.unwrap_or(1000);
        
        join_set.spawn(async move {
            let config = PortScanConfig {
                target: target.clone(),
                start_port: start,
                end_port: end,
                timeout_ms: timeout,
                concurrent_limit: 100,
                scan_mode: ScanMode::Custom,
            };
            
            let scanner = Scanner::new(config);
            
            match scanner.scan().await {
                Ok(scan_results) => {
                    let open_ports: Vec<serde_json::Value> = scan_results.iter()
                        .filter(|r| r.is_open())
                        .map(|r| serde_json::json!({
                            "port": r.port,
                            "status": format!("{:?}", r.status),
                            "service": r.service,
                            "version": r.version
                        }))
                        .collect();
                    
                    serde_json::json!({
                        "target": target,
                        "open_ports": open_ports,
                        "total_open": open_ports.len(),
                        "status": "completed"
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "target": target,
                        "error": e.to_string(),
                        "status": "failed"
                    })
                }
            }
        });
    }
    
    let mut results = Vec::new();
    while let Some(result) = join_set.join_next().await {
        if let Ok(value) = result {
            results.push(value);
        }
    }

    Ok(results)
}

#[tauri::command]
async fn identify_hash_command(
    input: String,
) -> Result<HashIdentification, String> {
    log("HASH_ID", &format!("Identifying hash type for input length: {}", input.len()), None);

    match identify_hash(&input) {
        Ok(result) => {
            log("HASH_ID", &format!("Identified {} possible types", result.possible_types.len()), None);
            Ok(result)
        }
        Err(e) => {
            log("HASH_ID", &format!("Hash identification failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn lookup_ip_geo_command(
    ip: String,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<IpGeoInfo, String> {
    log("IP_GEO", &format!("Looking up IP geolocation: {}", ip), None);

    match lookup_ip_geo(&ip).await {
        Ok(result) => {
            log("IP_GEO", &format!("Found location: {}, {}", result.city, result.country), None);

            if let Some(tid) = target_id {
                let db_guard = db.lock().map_err(|e| e.to_string())?;
                let service = biosphere_network::TargetService::new(db_guard.clone());
                let _ = service.record_scan(biosphere_network::ScanRecord {
                    target_id: tid,
                    scan_type: "ip_geo".to_string(),
                    open_ports_count: None,
                    vulnerabilities_count: None,
                    risk_level: None,
                    status: Some("completed".to_string()),
                });
            }

            Ok(result)
        }
        Err(e) => {
            log("IP_GEO", &format!("IP geolocation failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn analyze_security_headers_command(
    url: String,
    config: Option<SecurityHeaderConfig>,
) -> Result<SecurityHeaderReport, String> {
    log("SEC_HEADERS", &format!("Analyzing security headers for: {}", url), None);

    let mut analysis_config = config.unwrap_or_default();
    analysis_config.url = url;

    match SecurityHeaderAnalyzer::analyze(&analysis_config).await {
        Ok(result) => {
            log("SEC_HEADERS", &format!("Analysis complete - Score: {}/100 ({})", result.score, result.grade), None);
            Ok(result)
        }
        Err(e) => {
            log("SEC_HEADERS", &format!("Security header analysis failed: {}", e), None);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn save_sec_header_record(
    db: State<Mutex<Database>>,
    url: String,
    score: i32,
    grade: String,
    present_count: i32,
    missing_count: i32,
    summary: String,
    result: String,
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    let record = SecHeaderRecord::new(url, score, grade, present_count, missing_count, summary, result);
    db.create_sec_header_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_sec_header_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<SecHeaderRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_sec_header_records(
        limit.unwrap_or(50),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_sec_header_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_sec_header_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_sec_header_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_sec_header_records().map_err(|e| e.to_string())
}

#[tauri::command]
fn save_hash_identifier_record(
    db: State<Mutex<Database>>,
    hash_value: String,
    possible_types: String,
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    let record = HashIdentifierRecord::new(hash_value, possible_types);
    db.create_hash_identifier_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_hash_identifier_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<HashIdentifierRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_hash_identifier_records(
        limit.unwrap_or(50),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_hash_identifier_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_hash_identifier_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_hash_identifier_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_hash_identifier_records().map_err(|e| e.to_string())
}

#[tauri::command]
fn save_ip_geo_record(
    db: State<Mutex<Database>>,
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
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    let record = IpGeoRecord::new(ip, country, country_code, region, city, latitude, longitude, isp, org, timezone);
    db.create_ip_geo_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_ip_geo_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<IpGeoRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_ip_geo_records(
        limit.unwrap_or(50),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_ip_geo_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_ip_geo_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_ip_geo_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_ip_geo_records().map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_ssl_command(
    host: String,
    port: Option<u16>,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<SslCheckResult, String> {
    let result = SslCheckerTool::check(&host, port)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "ssl_check".to_string(),
            open_ports_count: None,
            vulnerabilities_count: None,
            risk_level: if result.score < 50 {
                Some("high".to_string())
            } else if result.score < 80 {
                Some("medium".to_string())
            } else {
                Some("low".to_string())
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
fn save_ssl_check_record(
    db: State<Mutex<Database>>,
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
) -> Result<i64, String> {
    let record = SslCheckRecord::new(
        host, port, is_secure, protocol_version, cipher_name, cipher_bits,
        score, grade, subject_cn, issuer_cn, is_expired, days_remaining,
        is_self_signed, key_type, key_bits, summary, result,
    );
    let db = db.lock().map_err(|e| e.to_string())?;
    db.save_ssl_check_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_ssl_check_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<SslCheckRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_ssl_check_records(
        limit.unwrap_or(100),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_ssl_check_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_ssl_check_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_ssl_check_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_ssl_check_records().map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_site_command(
    url: String,
    timeout: Option<u64>,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<SiteCheckResult, String> {
    let result = SiteCheckerTool::check(&url, timeout)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "site_check".to_string(),
            open_ports_count: None,
            vulnerabilities_count: None,
            risk_level: if !result.is_online { Some("high".to_string()) } else { None },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
fn save_site_check_record(
    db: State<Mutex<Database>>,
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
) -> Result<i64, String> {
    let record = SiteCheckRecord::new(
        url, is_online, status_code, response_time_ms, title, server,
        dns_resolved, ssl_valid, is_redirect, summary, result,
    );
    let db = db.lock().map_err(|e| e.to_string())?;
    db.save_site_check_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_site_check_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<SiteCheckRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_site_check_records(
        limit.unwrap_or(100),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_site_check_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_site_check_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_site_check_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_site_check_records().map_err(|e| e.to_string())
}

#[tauri::command]
async fn detect_waf_command(
    config: WafConfig,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<WafDetectionResult, String> {
    let result = WafDetectorTool::detect(&config)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "waf_detect".to_string(),
            open_ports_count: None,
            vulnerabilities_count: None,
            risk_level: if result.waf_detected { Some("medium".to_string()) } else { None },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
fn save_waf_detection_record(
    db: State<Mutex<Database>>,
    url: String,
    waf_detected: bool,
    waf_name: Option<String>,
    confidence: f64,
    summary: String,
    result: String,
) -> Result<i64, String> {
    let record = WafDetectionRecord::new(
        url, waf_detected, waf_name, confidence, summary, result,
    );
    let db = db.lock().map_err(|e| e.to_string())?;
    db.save_waf_detection_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_waf_detection_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<WafDetectionRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_waf_detection_records(
        limit.unwrap_or(100),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_waf_detection_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_waf_detection_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_waf_detection_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_waf_detection_records().map_err(|e| e.to_string())
}

#[tauri::command]
fn generate_wordlist_command(
    config: WordlistConfig,
) -> Result<WordlistResult, String> {
    WordlistGeneratorTool::generate(&config)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn enumerate_subdomains_command(
    db: tauri::State<'_, Mutex<Database>>,
    config: SubdomainConfig,
    target_id: Option<i64>,
) -> Result<SubdomainResult, String> {
    let result = SubdomainEnumTool::enumerate(&config)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "subdomain_enum".to_string(),
            open_ports_count: Some(result.alive_count as i32),
            vulnerabilities_count: Some(result.total_found as i32),
            risk_level: if result.total_found > 100 {
                Some("high".to_string())
            } else if result.total_found > 20 {
                Some("medium".to_string())
            } else if result.total_found > 0 {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
async fn scan_dirs_command(
    db: tauri::State<'_, Mutex<Database>>,
    config: DirScanConfig,
    target_id: Option<i64>,
) -> Result<DirScanResult, String> {
    let result = DirScannerTool::scan(&config)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let sensitive_count = result.sensitive_paths.len() as i32;
        let critical_count = result.sensitive_paths.iter().filter(|p| p.severity == "critical").count();
        let high_count = result.sensitive_paths.iter().filter(|p| p.severity == "high").count();
        let medium_count = result.sensitive_paths.iter().filter(|p| p.severity == "medium").count();
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "dir_scan".to_string(),
            open_ports_count: None,
            vulnerabilities_count: Some(sensitive_count),
            risk_level: if critical_count > 0 {
                Some("critical".to_string())
            } else if high_count > 0 {
                Some("high".to_string())
            } else if medium_count > 0 {
                Some("medium".to_string())
            } else if sensitive_count > 0 {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
async fn lookup_cve_command(
    config: CveQueryConfig,
) -> Result<CveQueryResult, String> {
    CveLookupTool::query(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_email_command(
    config: EmailVerifyConfig,
) -> Result<EmailVerifyResult, String> {
    EmailVerifierTool::verify(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_username_osint_command(
    db: State<'_, Mutex<Database>>,
    app: tauri::AppHandle,
    config: UsernameOsintConfig,
) -> Result<UsernameOsintResult, String> {
    let platforms = {
        let db = db.lock().map_err(|e| e.to_string())?;
        UsernameOsintTool::resolve_platforms(&db, &config)
            .map_err(|e| e.to_string())?
    };
    let app_handle = app.clone();
    UsernameOsintTool::check_with_platforms(&config, platforms, move |progress| {
        let _ = app_handle.emit("osint-progress", serde_json::json!({
            "checked": progress.checked,
            "total": progress.total,
            "found": progress.found,
            "errors": progress.errors,
            "current_platform": progress.current_platform,
            "username": progress.username,
        }));
        if let Some(ref result) = progress.latest_result {
            let _ = app_handle.emit("osint-platform-result", serde_json::json!({
                "platform": result.platform,
                "url": result.url,
                "found": result.found,
                "status_code": result.status_code,
                "error": result.error,
                "error_type": result.error_type,
                "category": result.category,
                "response_time_ms": result.response_time_ms,
                "page_title": result.page_title,
                "is_captcha": result.is_captcha,
                "is_censored": result.is_censored,
                "retry_count": result.retry_count,
                "detection_method": result.detection_method,
                "protection_type": result.protection_type,
                "suggested_action": result.suggested_action,
            }));
        }
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_osint_platforms_command(
    db: State<'_, Mutex<Database>>,
    category: Option<String>,
    active_only: Option<bool>,
) -> Result<Vec<OsintPlatform>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_osint_platforms(category.as_deref(), active_only.unwrap_or(true))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_osint_platform_by_name_command(
    db: State<'_, Mutex<Database>>,
    name: String,
) -> Result<Option<OsintPlatform>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_osint_platform_by_name(&name)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn create_osint_platform_command(
    db: State<'_, Mutex<Database>>,
    platform: OsintPlatform,
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.create_osint_platform(&platform)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn update_osint_platform_command(
    db: State<'_, Mutex<Database>>,
    platform: OsintPlatform,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.update_osint_platform(&platform)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_osint_platform_command(
    db: State<'_, Mutex<Database>>,
    name: String,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_osint_platform(&name)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_osint_platform_categories_command(
    db: State<'_, Mutex<Database>>,
) -> Result<Vec<String>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_osint_platform_categories()
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn count_osint_platforms_command(
    db: State<'_, Mutex<Database>>,
) -> Result<i64, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.count_osint_platforms()
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn batch_import_osint_platforms_command(
    db: State<'_, Mutex<Database>>,
    platforms: Vec<OsintPlatform>,
) -> Result<usize, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.batch_create_osint_platforms(&platforms)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn import_maigret_data_command(
    db: State<'_, Mutex<Database>>,
) -> Result<ImportStats, String> {
    let data_json = include_str!("../maigret_data.json");
    let db = db.lock().map_err(|e| e.to_string())?;
    MaigretImporter::import_from_json(&db, data_json)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn save_osint_scan_results_command(
    db: State<'_, Mutex<Database>>,
    results: Vec<OsintScanResult>,
) -> Result<usize, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.batch_create_osint_scan_results(&results)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_osint_scan_results_command(
    db: State<'_, Mutex<Database>>,
    username: String,
) -> Result<Vec<OsintScanResult>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_osint_scan_results(&username)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn discover_params_command(
    config: ParamDiscoveryConfig,
) -> Result<ParamDiscoveryResult, String> {
    ParamDiscoveryTool::discover(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_subdomain_takeover_command(
    config: TakeoverConfig,
) -> Result<TakeoverResult, String> {
    SubdomainTakeoverTool::check(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn crawl_web_command(
    config: WebCrawlerConfig,
) -> Result<WebCrawlerResult, String> {
    WebCrawlerTool::crawl(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn download_resource_command(
    url: String,
    save_dir: String,
) -> Result<DownloadResult, String> {
    WebCrawlerTool::download_resource(&url, &save_dir)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn download_resources_batch_command(
    urls: Vec<String>,
    save_dir: String,
) -> Result<BatchDownloadResult, String> {
    WebCrawlerTool::download_resources_batch(&urls, &save_dir)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn download_resources_batch_with_config_command(
    urls: Vec<String>,
    save_dir: String,
    download_mode: String,
    max_concurrent: usize,
    max_retries: usize,
    retry_delay_ms: u64,
    mirror_mode: bool,
    cookies: Option<String>,
    custom_headers: Option<String>,
    max_download_count: Option<usize>,
) -> Result<BatchDownloadResult, String> {
    WebCrawlerTool::download_resources_batch_with_auth(
        &urls, &save_dir, &download_mode, max_concurrent, max_retries, retry_delay_ms, mirror_mode,
        cookies.as_deref().unwrap_or(""),
        custom_headers.as_deref().unwrap_or(""),
        max_download_count.unwrap_or(0),
    )
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn download_site_command(
    config: SiteDownloadConfig,
    crawl_result: WebCrawlerResult,
) -> Result<BatchDownloadResult, String> {
    WebCrawlerTool::download_site(&config, &crawl_result)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn download_full_site_command(
    start_url: String,
    save_dir: String,
    max_depth: usize,
    max_pages: usize,
    max_concurrent: usize,
    follow_external: bool,
) -> Result<BatchDownloadResult, String> {
    WebCrawlerTool::download_full_site(
        &start_url, &save_dir, max_depth, max_pages, max_concurrent, follow_external,
    )
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn export_crawl_result_command(
    result: WebCrawlerResult,
    config: ExportConfig,
) -> Result<String, String> {
    WebCrawlerTool::export_result(&result, &config)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn detect_tech_command(
    config: TechDetectConfig,
) -> Result<TechDetectResult, String> {
    TechDetectorTool::detect(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_secrets_command(
    config: SecretScanConfig,
) -> Result<SecretScanResult, String> {
    SecretScannerTool::scan(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_sqli_command(
    db: tauri::State<'_, Mutex<Database>>,
    config: SqliScanConfig,
    target_id: Option<i64>,
) -> Result<SqliScanResult, String> {
    let result = SqliScannerTool::scan(&config)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let vuln_count = result.vulnerabilities.len() as i32;
        let critical_count = result.vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high_count = result.vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = result.vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = result.vulnerabilities.iter().filter(|v| v.severity == "low").count();
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "sqli_scan".to_string(),
            open_ports_count: None,
            vulnerabilities_count: Some(vuln_count),
            risk_level: if critical_count > 0 {
                Some("critical".to_string())
            } else if high_count > 0 {
                Some("high".to_string())
            } else if medium_count > 0 {
                Some("medium".to_string())
            } else if low_count > 0 {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
async fn scan_xss_command(
    db: tauri::State<'_, Mutex<Database>>,
    config: XssScanConfig,
    target_id: Option<i64>,
) -> Result<XssScanResult, String> {
    let result = XssScannerTool::scan(&config)
        .await
        .map_err(|e: biosphere_network::core::ToolError| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let vuln_count = result.vulnerabilities.len() as i32;
        let critical_count = result.vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high_count = result.vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = result.vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = result.vulnerabilities.iter().filter(|v| v.severity == "low").count();
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "xss_scan".to_string(),
            open_ports_count: None,
            vulnerabilities_count: Some(vuln_count),
            risk_level: if critical_count > 0 {
                Some("critical".to_string())
            } else if high_count > 0 {
                Some("high".to_string())
            } else if medium_count > 0 {
                Some("medium".to_string())
            } else if low_count > 0 {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
async fn crack_hash_command(
    config: HashCrackConfig,
) -> Result<HashCrackResult, String> {
    HashCrackerTool::crack(&config)
        .await
        .map_err(|e: biosphere_network::core::ToolError| e.to_string())
}

#[tauri::command]
async fn steganography_command(
    config: SteganographyConfig,
) -> Result<SteganographyResult, String> {
    SteganographyTool::process(&config)
        .await
        .map_err(|e: biosphere_network::core::ToolError| e.to_string())
}

#[tauri::command]
async fn brute_force_command(
    config: BruteForceConfig,
) -> Result<BruteForceResult, String> {
    BruteForceTool::brute_force(&config)
        .await
}

#[tauri::command]
async fn extract_metadata_command(
    config: MetadataExtractConfig,
) -> Result<MetadataExtractResult, String> {
    MetadataExtractorTool::extract(&config)
        .await
}

#[tauri::command]
async fn check_cors_command(
    config: CorsCheckConfig,
) -> Result<CorsCheckResult, String> {
    CorsCheckerTool::check(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_open_redirect_command(
    config: OpenRedirectConfig,
) -> Result<OpenRedirectResult, String> {
    OpenRedirectTool::check(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn analyze_cookies_command(
    config: CookieAnalyzerConfig,
) -> Result<CookieAnalyzerResult, String> {
    CookieAnalyzerTool::analyze(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn find_admin_command(
    config: AdminFinderConfig,
) -> Result<AdminFinderResult, String> {
    AdminFinderTool::find(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_command_injection_command(
    db: tauri::State<'_, Mutex<Database>>,
    config: CommandInjectionConfig,
    target_id: Option<i64>,
) -> Result<CommandInjectionResult, String> {
    let result = CommandInjectionTool::scan(&config)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let vuln_count = result.vulnerabilities.len() as i32;
        let critical_count = result.vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high_count = result.vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium_count = result.vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low_count = result.vulnerabilities.iter().filter(|v| v.severity == "low").count();
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "command_injection_scan".to_string(),
            open_ports_count: None,
            vulnerabilities_count: Some(vuln_count),
            risk_level: if critical_count > 0 {
                Some("critical".to_string())
            } else if high_count > 0 {
                Some("high".to_string())
            } else if medium_count > 0 {
                Some("medium".to_string())
            } else if low_count > 0 {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
async fn discover_network_command(
    config: NetworkDiscoveryConfig,
) -> Result<NetworkDiscoveryResult, String> {
    NetworkDiscoveryTool::discover(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn save_network_discovery_record(
    db: State<Mutex<Database>>,
    network_range: String,
    active_hosts: i32,
    total_scanned: i32,
    summary: String,
    result: String,
) -> Result<i64, String> {
    let record = NetworkDiscoveryRecord::new(
        network_range, active_hosts, total_scanned, summary, result,
    );
    let db = db.lock().map_err(|e| e.to_string())?;
    db.save_network_discovery_record(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_network_discovery_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<NetworkDiscoveryRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_network_discovery_records(
        limit.unwrap_or(100),
        offset.unwrap_or(0),
    ).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_network_discovery_record(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_network_discovery_record(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_network_discovery_history(
    db: State<Mutex<Database>>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.clear_network_discovery_records().map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_wifi_command(
    config: WifiScanConfig,
) -> Result<WifiScanResult, String> {
    WifiScannerTool::scan(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect_wifi_command(
    config: WifiConnectConfig,
) -> Result<WifiConnectResult, String> {
    WifiConnectorTool::connect(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wifi_crack_discovery_command(
    networks: Vec<WifiNetwork>,
) -> Vec<CrackResult> {
    WifiCrackDiscoveryTool::analyze(&networks)
}

#[tauri::command]
fn list_wifi_interfaces_command() -> Vec<NetworkInterface> {
    WifiInterfaceTool::list()
}

#[tauri::command]
fn wifi_auto_crack_command(
    networks: Vec<WifiNetwork>,
) -> Vec<AutoCrackResult> {
    WifiAutoCrackTool::auto_crack(&networks)
}

#[tauri::command]
async fn audit_cloud_command(
    config: CloudAuditConfig,
) -> Result<CloudAuditResult, String> {
    CloudAuditTool::audit(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn analyze_apk_command(
    config: ApkAnalysisConfig,
) -> Result<ApkAnalysisResult, String> {
    ApkAnalysisTool::analyze(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn select_apk_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    use tauri_plugin_dialog::FileDialogBuilder;
    use tauri_plugin_dialog::FilePath;
    let (tx, rx) = std::sync::mpsc::channel();
    FileDialogBuilder::new(app.dialog().clone())
        .set_title("Select APK File")
        .add_filter("APK", &["apk"])
        .pick_file(move |path: Option<FilePath>| {
            let _ = tx.send(path.map(|p: FilePath| {
                match p {
                    FilePath::Path(pb) => pb.to_string_lossy().to_string(),
                    FilePath::Url(url) => url.to_string(),
                }
            }));
        });
    rx.recv().map_err(|e: std::sync::mpsc::RecvError| e.to_string())
}

#[tauri::command]
async fn analyze_dns_command(
    config: DnsAnalyzerConfig,
) -> Result<DnsAnalyzerResult, String> {
    DnsAnalyzerTool::analyze(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn test_ddos_command(
    config: DdosTesterConfig,
) -> Result<DdosTesterResult, String> {
    DdosTesterTool::test(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_privilege_esc_command(
    config: PrivilegeEscConfig,
) -> Result<PrivilegeEscResult, String> {
    PrivilegeEscCheckTool::check(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn analyze_binary_command(
    config: BinaryAnalyzerConfig,
) -> Result<BinaryAnalyzerResult, String> {
    BinaryAnalyzerTool::analyze(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn select_binary_file(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    use tauri_plugin_dialog::FileDialogBuilder;
    use tauri_plugin_dialog::FilePath;
    let (tx, rx) = std::sync::mpsc::channel();
    FileDialogBuilder::new(app.dialog().clone())
        .set_title("Select Binary File")
        .add_filter("Binary Files", &["exe", "dll", "so", "dylib", "bin", "elf", "o", "ko", "sys", "apk", "ipa", "app", "rom", "fw", "img"])
        .add_filter("All Files", &["*"])
        .pick_file(move |path: Option<FilePath>| {
            let _ = tx.send(path.map(|p: FilePath| {
                match p {
                    FilePath::Path(pb) => pb.to_string_lossy().to_string(),
                    FilePath::Url(url) => url.to_string(),
                }
            }));
        });
    rx.recv().map_err(|e: std::sync::mpsc::RecvError| e.to_string())
}

#[tauri::command]
async fn select_directory_for_scan(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    use tauri_plugin_dialog::FileDialogBuilder;
    use tauri_plugin_dialog::FilePath;
    let (tx, rx) = std::sync::mpsc::channel();
    FileDialogBuilder::new(app.dialog().clone())
        .set_title("Select Directory to Scan for Binaries")
        .pick_folder(move |path: Option<FilePath>| {
            let _ = tx.send(path.map(|p: FilePath| {
                match p {
                    FilePath::Path(pb) => pb.to_string_lossy().to_string(),
                    FilePath::Url(url) => url.to_string(),
                }
            }));
        });
    rx.recv().map_err(|e: std::sync::mpsc::RecvError| e.to_string())
}

#[tauri::command]
async fn scan_directory_for_binaries(
    directory: String,
    max_depth: u32,
) -> Result<DirectoryScanResult, String> {
    BinaryAnalyzerTool::scan_directory(&directory, max_depth)
}

#[tauri::command]
async fn scan_exploit_command(
    app: tauri::AppHandle,
    db: tauri::State<'_, Mutex<Database>>,
    config: ExploitFrameworkConfig,
) -> Result<ExploitFrameworkResult, String> {
    let app_handle = app.clone();
    let result = ExploitFrameworkTool::scan_with_progress(&config, move |event| {
        let _ = app_handle.emit("exploit-scan-progress", serde_json::json!({
            "phase": event.phase,
            "current": event.current,
            "total": event.total,
            "message": event.message,
            "target": event.target,
            "services_found": event.services_found,
            "vulns_found": event.vulns_found,
        }));
    }).await?;

    if let Some(tid) = config.target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "exploit_scan".to_string(),
            open_ports_count: None,
            vulnerabilities_count: Some(result.total_exploits as i32),
            risk_level: if result.critical_exploits > 0 {
                Some("critical".to_string())
            } else if result.high_exploits > 0 {
                Some("high".to_string())
            } else if result.medium_exploits > 0 {
                Some("medium".to_string())
            } else if result.low_exploits > 0 {
                Some("low".to_string())
            } else {
                None
            },
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
async fn analyze_post_exploitation_command(
    config: PostExploitationConfig,
) -> Result<PostExploitationResult, String> {
    PostExploitationTool::analyze(&config).await
}

#[tauri::command]
async fn detect_phishing_command(
    config: PhishingDetectorConfig,
) -> Result<PhishingDetectorResult, String> {
    PhishingDetectorTool::detect(&config).await
}

#[tauri::command]
async fn inject_payload_command(
    config: PayloadInjectorConfig,
) -> Result<PayloadInjectorResult, String> {
    PayloadInjectorTool::inject(&config).await
}

#[tauri::command]
async fn check_anonymity_command(
    config: AnonymityCheckerConfig,
) -> Result<AnonymityCheckerResult, String> {
    AnonymityCheckerTool::check(&config).await
}

#[tauri::command]
async fn analyze_forensics_command(
    config: ForensicsAnalyzerConfig,
) -> Result<ForensicsAnalyzerResult, String> {
    ForensicsAnalyzerTool::analyze(&config).await
}

#[tauri::command]
async fn audit_ad_command(
    config: AdAuditConfig,
) -> Result<AdAuditResult, String> {
    AdAuditTool::audit(&config).await
}

#[tauri::command]
async fn analyze_mobile_security_command(
    config: MobileSecurityConfig,
) -> Result<MobileSecurityResult, String> {
    MobileSecurityTool::analyze(&config).await
}

#[tauri::command]
async fn search_assets_command(
    config: AssetSearchConfig,
) -> Result<AssetSearchResult, String> {
    AssetSearchTool::search(&config).await
}

#[tauri::command]
async fn reverse_ip_lookup_command(
    config: ReverseIpConfig,
) -> Result<ReverseIpResult, String> {
    ReverseIpTool::lookup(&config).await
}

#[tauri::command]
async fn cf_bypass_command(
    config: CfBypassConfig,
) -> Result<CfBypassResult, String> {
    CfBypassTool::bypass(&config).await
}

#[tauri::command]
async fn find_social_command(
    config: SocialFinderConfig,
    db: tauri::State<'_, Mutex<Database>>,
    target_id: Option<i64>,
) -> Result<SocialFinderResult, String> {
    let result = SocialFinderTool::find(&config).await?;

    if let Some(tid) = target_id {
        let db_guard = db.lock().map_err(|e| e.to_string())?;
        let service = biosphere_network::TargetService::new(db_guard.clone());
        let _ = service.record_scan(biosphere_network::ScanRecord {
            target_id: tid,
            scan_type: "social_find".to_string(),
            open_ports_count: None,
            vulnerabilities_count: None,
            risk_level: None,
            status: Some("completed".to_string()),
        });
    }

    Ok(result)
}

#[tauri::command]
fn list_social_platforms_command() -> Vec<PlatformListItem> {
    SocialFinderTool::list_platforms()
}

#[tauri::command]
async fn gather_osint_command(
    config: OsintGatherConfig,
) -> Result<OsintGatherResult, String> {
    OsintGatherTool::gather(&config).await
}

#[tauri::command]
async fn idn_check_command(
    config: IdnCheckConfig,
) -> Result<IdnCheckResult, String> {
    IdnCheckerTool::check(&config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn idn_batch_check_command(
    domains: Vec<String>,
    config: IdnCheckConfig,
) -> Result<BatchIdnCheckResult, String> {
    IdnCheckerTool::batch_check(&domains, &config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn reverse_engineer_command(
    config: ReverseEngineerConfig,
) -> Result<ReverseEngineerResult, String> {
    ReverseEngineerTool::analyze(&config).await
}

#[tauri::command]
async fn wifi_deauth_detect_command(
    config: WifiDeauthConfig,
) -> Result<WifiDeauthResult, String> {
    WifiDeauthDetectorTool::detect(&config).await
}

#[tauri::command]
fn list_wifi_deauth_interfaces_command() -> Vec<WifiInterface> {
    WifiDeauthDetectorTool::list_interfaces()
}

#[tauri::command]
fn save_tool_history(
    db: State<Mutex<Database>>,
    tool_type: String,
    tool_name: String,
    input_summary: String,
    result_summary: Option<String>,
    result_json: String,
    status: String,
) -> Result<i64, String> {
    let record = ToolHistoryRecord::new(
        tool_type, tool_name, input_summary, result_summary, result_json, status,
    );
    let db = db.lock().map_err(|e| e.to_string())?;
    db.create_tool_history(&record).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_tool_history(
    db: State<Mutex<Database>>,
    tool_type: String,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<ToolHistoryRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_tool_history(&tool_type, limit.unwrap_or(50), offset.unwrap_or(0))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_all_tool_history(
    db: State<Mutex<Database>>,
    limit: Option<i32>,
    offset: Option<i32>,
) -> Result<Vec<ToolHistoryRecord>, String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.get_all_tool_history(limit.unwrap_or(50), offset.unwrap_or(0))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_tool_history(
    db: State<Mutex<Database>>,
    id: i64,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    db.delete_tool_history(id).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_tool_history(
    db: State<Mutex<Database>>,
    tool_type: Option<String>,
) -> Result<(), String> {
    let db = db.lock().map_err(|e| e.to_string())?;
    match tool_type {
        Some(t) => db.clear_tool_history(&t).map_err(|e| e.to_string()),
        None => db.clear_all_tool_history().map_err(|e| e.to_string()),
    }
}

#[derive(Debug, serde::Serialize)]
struct ToolHelpSection {
    title: String,
    content: String,
}

#[derive(Debug, serde::Serialize)]
struct ToolHelpInfo {
    tool_type: String,
    tool_name: String,
    description: String,
    usage: String,
    sections: Vec<ToolHelpSection>,
}

#[tauri::command]
fn get_tool_help(tool_type: String) -> Result<ToolHelpInfo, String> {
    let helps: std::collections::HashMap<&str, (&str, &str, &str, Vec<(&str, &str)>)> = std::collections::HashMap::from([
        ("tech_detector", (
            "技术栈检测",
            "识别网站使用的技术框架、服务器、CMS、JavaScript库等",
            "输入目标URL，选择检测方式后点击开始检测",
            vec![
                ("检测方式", "支持HTTP头检测、Cookie检测、HTML内容检测和JavaScript检测四种方式，建议全部开启以获得最全面的结果"),
                ("置信度", "每项检测结果都有置信度百分比，越高表示越确定该技术被使用"),
                ("超时设置", "默认15秒，对于响应较慢的网站可以适当增加超时时间"),
                ("结果解读", "检测结果按技术分类展示，包括Web服务器、框架、CMS、JS库、CDN等"),
            ]
        )),
        ("secret_scanner", (
            "敏感信息扫描",
            "扫描网页源代码中的敏感信息泄露，如API密钥、令牌、密码等",
            "输入目标URL，配置扫描选项后点击开始扫描",
            vec![
                ("扫描范围", "支持扫描HTML源码、JavaScript文件、CSS文件和注释内容"),
                ("检测规则", "内置50+种敏感信息检测规则，覆盖AWS、GitHub、Slack等常见服务的密钥和令牌"),
                ("严重等级", "检测结果按严重程度分为Critical、High、Medium、Low四个等级"),
                ("注意事项", "仅用于授权的安全审计，扫描结果可能包含误报，请人工确认"),
            ]
        )),
        ("sqli_scanner", (
            "SQL注入检测",
            "检测目标URL是否存在SQL注入漏洞",
            "输入目标URL（可包含参数），选择检测级别后点击开始检测",
            vec![
                ("URL格式", "输入完整URL，如 https://example.com/page?id=1，参数会自动提取"),
                ("检测级别", "Basic：基础检测，速度快；Moderate：中等深度检测；Aggressive：深度检测，耗时较长"),
                ("注入类型", "支持检测Boolean盲注、Error注入、Time盲注、UNION注入和Stacked查询"),
                ("安全提示", "仅在授权范围内使用，过度激进的检测可能对目标造成影响"),
            ]
        )),
        ("cors_checker", (
            "CORS检测",
            "检测目标网站的跨域资源共享(CORS)配置是否安全",
            "输入目标URL后点击开始检测",
            vec![
                ("检测原理", "通过发送不同Origin头的请求，检查服务器返回的CORS响应头配置"),
                ("安全等级", "✅ 安全：正确配置的CORS；⚠️ 警告：宽松但非危险；❌ 不安全：允许任意来源访问"),
                ("常见问题", "最常见的问题是 Access-Control-Allow-Origin 设置为 * 或反射请求的 Origin"),
                ("修复建议", "检测结果会提供具体的修复建议，请根据实际情况调整CORS策略"),
            ]
        )),
        ("open_redirect", (
            "开放重定向检测",
            "检测目标URL是否存在开放重定向漏洞",
            "输入目标URL后点击开始检测",
            vec![
                ("检测原理", "通过在URL参数中注入外部域名，检查是否发生未验证的重定向"),
                ("测试载荷", "自动测试多种常见重定向参数名，如url、redirect、next、return等"),
                ("漏洞危害", "开放重定向可被用于钓鱼攻击，利用用户对原始域名的信任"),
                ("检测模式", "支持Basic和Aggressive两种模式，Aggressive会测试更多参数和编码方式"),
            ]
        )),
        ("cookie_analyzer", (
            "Cookie分析",
            "分析目标网站Cookie的安全属性配置",
            "输入目标URL后点击开始分析",
            vec![
                ("分析内容", "检查每个Cookie的Secure、HttpOnly、SameSite、Path等安全属性"),
                ("安全等级", "✅ 安全：属性配置正确；⚠️ 警告：缺少部分安全属性；❌ 不安全：存在安全隐患"),
                ("常见问题", "缺少Secure标志（允许HTTP传输）、缺少HttpOnly（可被JS读取）、SameSite未设置"),
                ("第三方Cookie", "会区分第一方和第三方Cookie，第三方Cookie需要更严格的安全配置"),
            ]
        )),
        ("admin_finder", (
            "管理后台发现",
            "扫描目标网站的管理后台、登录页面等敏感路径",
            "输入目标URL后点击开始扫描",
            vec![
                ("扫描路径", "内置100+常见管理路径，包括admin、login、dashboard、cpanel等"),
                ("并发设置", "默认并发数为10，可根据目标服务器性能调整，过高可能导致被封锁"),
                ("结果判断", "200状态码的路径会被标记为可能的管理后台，同时会分析页面标题辅助判断"),
                ("超时设置", "建议10-30秒，过短可能遗漏响应慢的页面"),
            ]
        )),
        ("web_crawler", (
            "Web爬虫",
            "爬取目标网站的页面链接、表单、资源等信息",
            "输入目标URL，配置爬取深度和选项后点击开始爬取",
            vec![
                ("爬取深度", "控制爬取的层级深度，建议1-3层，过深会消耗大量时间"),
                ("爬取选项", "可选择是否爬取外部链接、是否跟踪重定向、是否验证SSL证书"),
                ("结果分类", "爬取结果按内部链接、外部链接、表单、资源文件等分类展示"),
                ("Robots.txt", "默认遵守robots.txt规则，可选择忽略"),
            ]
        )),
        ("subdomain_takeover", (
            "子域名接管检测",
            "检测目标子域名是否存在被接管的风险",
            "输入主域名或子域名列表后点击开始检测",
            vec![
                ("检测原理", "检查子域名CNAME指向的服务是否已失效，失效的CNAME可能被攻击者注册接管"),
                ("支持服务", "支持检测GitHub Pages、Heroku、AWS S3、Azure等20+种云服务的接管风险"),
                ("输入格式", "可输入单个域名或每行一个子域名列表"),
                ("风险等级", "Vulnerable：确认可接管；Likely：很可能可接管；Unlikely：不太可能"),
            ]
        )),
        ("param_discovery", (
            "参数发现",
            "发现目标URL的隐藏参数",
            "输入目标URL后点击开始发现",
            vec![
                ("检测原理", "通过向URL添加不同参数并比较响应差异来发现有效参数"),
                ("内置字典", "内置常用参数名字典，也可自定义参数列表"),
                ("判断依据", "通过比较响应状态码、内容长度和响应体的差异来判断参数是否有效"),
                ("并发设置", "默认20线程，可根据目标服务器承受能力调整"),
            ]
        )),
        ("idn_checker", (
            "IDN同形字检测",
            "检测国际化域名(IDN)中的同形字攻击风险",
            "输入域名后点击开始检测",
            vec![
                ("检测原理", "检查域名中是否使用了与其他字符视觉相似的Unicode字符"),
                ("同形字映射", "内置常见同形字映射表，如西里尔字母a与拉丁字母a"),
                ("风险等级", "高风险：使用非拉丁字符模拟知名域名；中风险：包含易混淆字符"),
                ("应用场景", "钓鱼攻击检测、域名安全审计、品牌保护"),
            ]
        )),
        ("username_osint", (
            "用户名OSINT",
            "跨平台检查用户名注册情况，评估数字足迹和安全风险。支持批量查询、用户名变体生成、Sherlock平台导入等功能",
            "输入用户名，选择平台分类和高级选项后点击开始查询",
            vec![
                ("基本查询", "输入用户名后点击开始查询，系统会自动在所有已注册的平台中检查该用户名是否存在。支持按分类筛选平台，不选择分类则检查所有平台"),
                ("批量查询", "在「附加用户名」输入框中输入多个用户名（逗号或空格分隔），系统会同时检查所有用户名，并在「批量结果」标签页中展示每个用户名的扫描结果"),
                ("用户名变体", "开启「生成用户名变体」后，系统会自动组合输入的用户名，生成常见变体（如添加后缀123、official，使用分隔符_、-、.组合等），帮助发现更多关联账户"),
                ("高级设置", "超时：单个平台请求超时时间（默认10秒）；重试次数：网络错误时自动重试次数（默认1次）；并发数：同时检查的平台数量（默认15）"),
                ("错误分类", "系统会自动识别错误类型：🤖 CAPTCHA验证 - 平台要求人机验证；🚫 区域限制 - 平台在当前地区不可用；⏱️ 超时 - 请求超时；🔌 连接失败 - 无法连接到平台；📭 空响应 - 响应体过小可能表示不存在"),
                ("平台管理", "支持添加自定义平台、导入Sherlock data.json批量添加平台、编辑和启停用平台。每个平台需配置URL模板（使用{}表示用户名位置）、检测方式（状态码/页面消息/重定向/正则匹配）等"),
                ("导出结果", "支持三种格式导出：JSON（完整数据）、CSV（表格格式，适合Excel分析）、Markdown（文档格式，适合报告）"),
                ("数字足迹评分", "根据用户名在平台上的注册比例和绝对数量计算评分（0-100），评分越高表示数字足迹越大、隐私风险越高。风险等级：Critical(≥80)、High(≥60)、Medium(≥40)、Low(≥20)、Minimal(<20)"),
            ]
        )),
        ("email_verifier", (
            "邮件验证",
            "验证电子邮件地址的有效性和可达性",
            "输入邮箱地址后点击开始验证",
            vec![
                ("验证步骤", "格式检查 → 域名MX记录检查 → SMTP连接验证 → 邮箱存在性验证"),
                ("验证结果", "✅ 有效：邮箱确认存在；⚠️ 不确定：无法确认；❌ 无效：邮箱不存在"),
                ("超时设置", "SMTP验证可能较慢，建议10-30秒超时"),
                ("隐私提示", "不会发送实际邮件，仅通过SMTP协议验证"),
            ]
        )),
        ("cve_lookup", (
            "CVE查询",
            "查询已知漏洞(CVE)的详细信息",
            "输入CVE编号或关键词后点击查询",
            vec![
                ("查询方式", "支持按CVE编号精确查询和按关键词模糊搜索"),
                ("数据来源", "从NVD(National Vulnerability Database)获取漏洞数据"),
                ("结果内容", "包括漏洞描述、CVSS评分、影响版本、修复建议等"),
                ("CVSS评分", "0-3.9低危；4-6.9中危；7-8.9高危；9-10严重"),
            ]
        )),
        ("dir_scanner", (
            "目录扫描",
            "扫描目标网站的隐藏目录和文件",
            "输入目标URL，配置扫描选项后点击开始扫描",
            vec![
                ("扫描字典", "内置常用目录字典，也可自定义字典文件"),
                ("文件扩展名", "可指定要扫描的文件扩展名，如.php、.html、.txt等"),
                ("并发设置", "默认20线程，过高可能触发目标WAF"),
                ("重定向", "可选择是否跟随重定向"),
            ]
        )),
        ("subdomain_enum", (
            "子域名枚举",
            "枚举目标域名的子域名",
            "输入目标域名后点击开始枚举",
            vec![
                ("枚举方式", "支持字典枚举和DNS解析验证"),
                ("内置字典", "内置常用子域名字典，也可自定义"),
                ("DNS服务器", "默认使用系统DNS，可指定自定义DNS服务器"),
                ("结果内容", "包括子域名、解析IP、CNAME记录等"),
            ]
        )),
        ("wordlist_generator", (
            "密码字典生成",
            "根据目标信息生成定制化密码字典",
            "输入目标相关信息后点击生成",
            vec![
                ("输入信息", "提供目标的姓名、生日、公司名等信息，生成更有针对性的字典"),
                ("生成规则", "支持大小写变换、数字追加、特殊字符追加、Leet替换等规则"),
                ("字典大小", "可通过最小/最大长度和规则组合控制字典大小"),
                ("导出格式", "支持导出为TXT文件，可直接用于其他工具"),
            ]
        )),
        ("whois", (
            "Whois查询",
            "查询域名的注册信息、归属和DNS配置",
            "输入域名后点击查询",
            vec![
                ("查询内容", "包括域名注册商、注册日期、到期日期、DNS服务器、域名状态等"),
                ("批量查询", "支持一次查询多个域名，每行一个"),
                ("结果保存", "查询结果自动保存到历史记录，方便后续查看"),
                ("使用场景", "域名信息收集、归属分析、到期监控"),
            ]
        )),
        ("ssl_checker", (
            "SSL证书检查",
            "检查目标网站的SSL/TLS证书配置和安全性",
            "输入域名或URL后点击检查",
            vec![
                ("检查内容", "证书有效性、颁发机构、到期时间、加密套件、协议版本等"),
                ("安全等级", "根据证书配置评估整体安全等级"),
                ("常见问题", "证书过期、弱加密套件、协议版本过低、证书链不完整"),
                ("协议支持", "检测TLS 1.0/1.1/1.2/1.3的支持情况"),
            ]
        )),
        ("waf_detector", (
            "WAF检测",
            "检测目标网站是否使用Web应用防火墙(WAF)",
            "输入目标URL后点击检测",
            vec![
                ("检测原理", "通过发送特定请求并分析响应头和行为来判断WAF类型"),
                ("支持WAF", "支持检测Cloudflare、ModSecurity、AWS WAF等20+种WAF"),
                ("检测方式", "结合HTTP头分析和行为检测双重验证"),
                ("使用场景", "渗透测试前期侦查、安全评估"),
            ]
        )),
        ("site_checker", (
            "网站检查",
            "检查目标网站的可用性和基本配置",
            "输入URL后点击检查",
            vec![
                ("检查项目", "HTTP状态码、响应时间、重定向链、SSL证书、安全头等"),
                ("响应时间", "测量从请求到收到响应的耗时"),
                ("重定向跟踪", "自动跟踪并显示完整的重定向链"),
                ("使用场景", "网站监控、可用性检查、配置审计"),
            ]
        )),
        ("ip_geo", (
            "IP地理定位",
            "查询IP地址的地理位置和ISP信息",
            "输入IP地址后点击查询",
            vec![
                ("查询内容", "国家、地区、城市、经纬度、ISP、ASN等"),
                ("批量查询", "支持一次查询多个IP地址"),
                ("数据来源", "使用GeoIP数据库进行离线查询"),
                ("使用场景", "威胁分析、访问日志分析、合规检查"),
            ]
        )),
        ("hash_identifier", (
            "哈希识别",
            "识别哈希值的可能算法类型",
            "输入哈希值后点击识别",
            vec![
                ("支持算法", "MD5、SHA1、SHA256、SHA512、bcrypt、NTLM等30+种哈希"),
                ("识别原理", "根据哈希长度、字符集和格式特征判断可能的算法"),
                ("多种可能", "一个哈希可能匹配多种算法，按可能性排序"),
                ("使用场景", "密码审计、数据完整性验证、安全分析"),
            ]
        )),
        ("security_headers", (
            "安全头检查",
            "检查目标网站HTTP安全响应头的配置",
            "输入URL后点击检查",
            vec![
                ("检查头", "Content-Security-Policy、X-Frame-Options、X-Content-Type-Options等"),
                ("安全等级", "根据安全头配置的完整性评估等级：A+到F"),
                ("修复建议", "对缺失或配置不当的安全头提供修复建议"),
                ("重要性", "安全头是防御XSS、点击劫持等攻击的重要手段"),
            ]
        )),
        ("dns_query", (
            "DNS查询",
            "查询域名的DNS记录",
            "输入域名和记录类型后点击查询",
            vec![
                ("记录类型", "支持A、AAAA、CNAME、MX、NS、TXT、SOA、PTR等记录"),
                ("DNS服务器", "可指定自定义DNS服务器，默认使用系统DNS"),
                ("批量查询", "支持同时查询多种记录类型"),
                ("使用场景", "DNS配置验证、邮件服务器分析、子域名发现"),
            ]
        )),
        ("encoder", (
            "编解码器",
            "对文本进行各种编码和解码转换",
            "输入文本，选择编码方式后点击转换",
            vec![
                ("支持编码", "Base64、URL编码、HTML实体编码、Hex编码等"),
                ("双向操作", "支持编码和解码双向操作"),
                ("文件支持", "支持对文件内容进行编解码"),
                ("使用场景", "数据分析、安全测试、开发调试"),
            ]
        )),
        ("zip", (
            "压缩工具",
            "解压和查看ZIP压缩包内容",
            "选择ZIP文件后进行操作",
            vec![
                ("支持格式", "ZIP格式压缩包"),
                ("加密支持", "支持加密ZIP文件的解压（需提供密码）"),
                ("文件列表", "可查看压缩包内的文件列表、大小和压缩率"),
                ("操作说明", "选择ZIP文件→查看内容→选择输出目录→解压"),
            ]
        )),
        ("password", (
            "密码工具",
            "生成安全密码和检查密码强度",
            "配置密码选项后点击生成",
            vec![
                ("密码生成", "支持自定义长度、字符类型、排除规则等"),
                ("密码短语", "生成易记忆的密码短语（多个单词组合）"),
                ("强度检查", "分析密码强度并给出改进建议"),
                ("安全建议", "建议使用16位以上、包含多种字符类型的密码"),
            ]
        )),
        ("port_scanner", (
            "端口扫描",
            "扫描目标主机的开放端口",
            "输入目标IP和端口范围后点击扫描",
            vec![
                ("扫描模式", "Quick：常用端口；Standard：1-1024；Full：1-65535；Custom：自定义范围"),
                ("并发设置", "默认100线程，可根据网络情况调整"),
                ("OS检测", "可根据开放端口特征推测目标操作系统"),
                ("注意事项", "仅扫描授权目标，未经授权的扫描可能违法"),
            ]
        )),
        ("ping", (
            "Ping工具",
            "测试与目标主机的网络连通性",
            "输入目标地址后点击Ping",
            vec![
                ("Ping次数", "可设置发送的Ping包数量"),
                ("超时设置", "单个Ping包的超时时间，默认5秒"),
                ("结果统计", "显示最小/最大/平均延迟和丢包率"),
                ("使用场景", "网络诊断、连通性测试、延迟测量"),
            ]
        )),
        ("target_manager", (
            "目标管理",
            "管理和组织扫描目标，支持分组和批量操作",
            "创建目标并分组管理",
            vec![
                ("目标类型", "支持IP地址、域名、URL、IP段等多种目标类型"),
                ("分组管理", "可创建目标分组，设置颜色和图标便于区分"),
                ("批量操作", "支持批量导入、批量扫描、批量删除"),
                ("端口标记", "可对端口进行标记（收藏/重要/危险）和备注"),
            ]
        )),
        ("rat_tool", (
            "RAT远程管理检测",
            "检测和分析远程管理工具(RAT)活动，识别C2通信和恶意行为，支持端口扫描、Banner分析和能力评估",
            "输入目标主机地址，配置检测参数后点击开始分析",
            vec![
                ("操作类型", "检测：扫描已知RAT端口并识别特征；能力分析：评估已发现RAT的潜在能力；全面审计：同时执行检测和能力分析"),
                ("协议选择", "支持TCP/UDP/HTTP/HTTPS/DNS协议，根据目标服务选择对应协议可提高检测准确性"),
                ("端口配置", "默认扫描端口4444(Metasploit)，也可指定其他可疑端口进行针对性检测"),
                ("结果解读", "检测结果显示RAT家族、置信度、C2服务器、持久化机制等信息，置信度>=90%应视为确认感染"),
            ]
        )),
        ("bluetooth_scanner", (
            "蓝牙安全检测",
            "扫描蓝牙设备并检测安全漏洞，包括BIAS、KNOB、BLESA、BlueBorne等已知攻击",
            "配置扫描参数后点击开始扫描",
            vec![
                ("扫描类型", "经典蓝牙：扫描BR/EDR设备；低功耗蓝牙(BLE)：扫描BLE设备；双模式：同时扫描两种类型"),
                ("漏洞检测", "自动检测BIAS攻击(CVE-2020-10135)、KNOB攻击(CVE-2019-9506)、BLESA攻击(CVE-2020-26559)、BlueBorne(CVE-2017-1000251)等已知漏洞"),
                ("服务枚举", "枚举已连接设备的蓝牙服务和特征，标记不安全的服务"),
                ("安全建议", "检测结果会提供具体的修复建议，如更新固件、关闭可发现模式等"),
            ]
        )),
        ("memory_forensics", (
            "内存取证分析",
            "分析内存转储文件，检测恶意进程、代码注入、持久化机制和C2通信",
            "配置分析参数后点击开始分析",
            vec![
                ("分析类型", "全面分析：同时执行所有检测；进程分析：仅分析可疑进程；网络分析：仅分析网络连接；恶意软件检测：检测恶意软件特征；持久化分析：检测持久化机制"),
                ("进程检测", "自动识别可疑进程名称（如netcat、meterpreter、keylogger等）和可疑命令行模式（如反向Shell、编码执行等）"),
                ("代码注入", "检测RWX（可写可执行）内存区域，识别DLL注入和进程注入（MITRE T1055）"),
                ("持久化机制", "检查macOS LaunchAgent/LaunchDaemon和Linux Cron/Systemd等持久化位置"),
                ("C2通信", "检测已知RAT端口通信和可疑高层端口连接（MITRE T1071）"),
            ]
        )),
        ("host_to_ip", (
            "Host2IP转换",
            "将域名解析为IP地址，支持多种DNS记录查询、反向DNS、CDN检测和安全发现",
            "输入域名后点击开始解析",
            vec![
                ("解析内容", "支持A记录、AAAA记录查询，反向DNS查询和地理位置信息获取"),
                ("配置选项", "查询所有DNS记录：同时查询A、AAAA、MX、NS、TXT等；反向DNS查询；CNAME查询"),
                ("结果说明", "显示IP地址、IP版本、是否私有IP、ASN、国家、组织信息，以及CDN检测和安全发现"),
                ("使用场景", "网络诊断、服务器定位、安全审计、CDN检测"),
            ]
        )),
        ("firmware_analyzer", (
            "固件安全分析",
            "分析固件文件，检测后门、硬编码凭据和二进制安全漏洞",
            "输入固件文件路径，配置分析选项后点击开始分析",
            vec![
                ("分析选项", "支持文件系统提取、硬编码凭据查找、二进制安全分析和后门检测，建议全部开启以获得最全面的结果"),
                ("文件类型", "支持BIN、IMG、FW、TRX、CHK、SquashFS、JFFS2等常见固件格式，自动识别文件类型和架构"),
                ("凭据检测", "自动检测配置文件中的硬编码密码、默认凭据和密钥，按严重程度分级"),
                ("二进制分析", "检测二进制文件的Stack Canary、NX保护等安全机制，识别未加固的可执行文件"),
                ("后门检测", "扫描Telnet守护进程、反向Shell、远程执行命令、Shellshock等已知后门特征"),
                ("安全建议", "检测结果会提供具体的修复建议，如修改默认密码、启用编译保护等"),
            ]
        )),
        ("social_engineering", (
            "社会工程学分析",
            "检测钓鱼攻击、域名仿冒和品牌冒充等社会工程学威胁",
            "输入目标URL、邮件内容或域名，配置检测选项后点击开始分析",
            vec![
                ("分析目标", "支持三种分析目标：目标URL（检测URL安全性）、邮件内容（检测钓鱼指标）、目标域名（检测域名仿冒和品牌冒充）"),
                ("域名仿冒检测", "通过字符遗漏、连字符插入、相邻键替换、字符重复、TLD替换、子域名替换、元音替换等7种技术生成仿冒域名变体"),
                ("同形字攻击", "检测域名中是否使用了与西里尔字母等Unicode字符视觉相似的拉丁字母，评估同形字攻击风险"),
                ("品牌冒充检测", "内置Google、Microsoft、Apple、Amazon等10大品牌的关键词库，检测域名是否冒充知名品牌"),
                ("邮件钓鱼检测", "检测紧急性语言、诱导操作、不安全链接、IP地址URL、回复地址不匹配、可疑附件等13种钓鱼指标"),
                ("URL安全分析", "检测URL欺骗、可疑TLD、URL过长、IP地址URL、URL编码、开放重定向、不安全登录页面等安全风险"),
                ("MITRE ATT&CK", "检测结果关联MITRE ATT&CK技术编号，如T1566.001（钓鱼附件）、T1583.001（域名仿冒）、T1204（用户执行）"),
            ]
        )),
    ]);

    match helps.get(tool_type.as_str()) {
        Some((name, desc, usage, sections)) => Ok(ToolHelpInfo {
            tool_type: tool_type.clone(),
            tool_name: name.to_string(),
            description: desc.to_string(),
            usage: usage.to_string(),
            sections: sections.iter().map(|(t, c)| ToolHelpSection {
                title: t.to_string(),
                content: c.to_string(),
            }).collect(),
        }),
        None => Ok(ToolHelpInfo {
            tool_type: tool_type.clone(),
            tool_name: tool_type.clone(),
            description: "No help information available".to_string(),
            usage: "Please refer to the instructions on the page".to_string(),
            sections: vec![],
        }),
    }
}

#[tauri::command]
async fn analyze_rat_command(
    config: RatToolConfig,
) -> Result<RatToolResult, String> {
    RatTool::analyze(&config).await
}

#[tauri::command]
async fn scan_bluetooth_command(
    config: BluetoothScanConfig,
) -> Result<BluetoothScanResult, String> {
    BluetoothScannerTool::scan(&config).await
}

#[tauri::command]
async fn analyze_memory_command(
    config: MemoryForensicsConfig,
) -> Result<MemoryForensicsResult, String> {
    MemoryForensicsTool::analyze(&config).await
}

#[tauri::command]
async fn analyze_firmware_command(
    config: FirmwareAnalyzerConfig,
) -> Result<FirmwareAnalyzerResult, String> {
    FirmwareAnalyzerTool::analyze(&config).await
}

#[tauri::command]
async fn analyze_social_engineering_command(
    config: SocialEngineeringConfig,
) -> Result<SocialEngineeringResult, String> {
    SocialEngineeringTool::analyze(&config).await
}

#[derive(Debug, serde::Serialize)]
struct DashboardData {
    scan_stats: DashboardScanStats,
    target_stats: DashboardTargetStats,
    risk_distribution: DashboardRiskDistribution,
    recent_activity: Vec<DashboardActivityItem>,
    tool_usage: Vec<DashboardToolUsage>,
    system_info: SystemInfoResponse,
}

#[derive(Debug, serde::Serialize)]
struct DashboardScanStats {
    total_scans: i64,
    completed_scans: i64,
    failed_scans: i64,
    running_scans: i64,
    total_open_ports: i64,
    success_rate: f64,
}

#[derive(Debug, serde::Serialize)]
struct DashboardTargetStats {
    total_targets: i64,
    total_groups: i64,
    total_vulnerabilities: i64,
    active_targets: i64,
    at_risk_targets: i64,
}

#[derive(Debug, serde::Serialize)]
struct DashboardRiskDistribution {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    info: i64,
}

#[derive(Debug, serde::Serialize)]
struct DashboardActivityItem {
    tool_type: String,
    tool_name: String,
    input_summary: String,
    status: String,
    created_at: String,
}

#[derive(Debug, serde::Serialize)]
struct DashboardToolUsage {
    tool_type: String,
    tool_name: String,
    count: i64,
}

#[tauri::command]
fn get_dashboard_data(
    db: State<Mutex<Database>>,
) -> Result<DashboardData, String> {
    let db_guard = db.lock().map_err(|e| format!("Database lock failed: {}", e))?;

    // Scan stats — return zeros on error (fresh database, missing table, etc.)
    let (total_scans, completed_scans, failed_scans, running_scans, total_open_ports, success_rate) =
        db_guard.get_scan_tasks(1000, 0)
            .map(|tasks| {
                let total = tasks.len() as i64;
                let completed = tasks.iter().filter(|t| t.status == "completed").count() as i64;
                let failed = tasks.iter().filter(|t| t.status == "failed" || t.status == "error").count() as i64;
                let running = tasks.iter().filter(|t| t.status == "running").count() as i64;
                let open = tasks.iter().filter_map(|t| t.open_ports).map(|p| p as i64).sum();
                let rate = if total > 0 { (completed as f64 / total as f64) * 100.0 } else { 0.0 };
                (total, completed, failed, running, open, rate)
            })
            .unwrap_or_else(|e| {
                eprintln!("Dashboard: scan_tasks query failed: {}", e);
                (0, 0, 0, 0, 0, 0.0)
            });

    // Target stats — return zeros on error
    let service = biosphere_network::TargetService::new(db_guard.clone());
    let (total_targets, total_vulnerabilities, active_targets, at_risk_targets) =
        service.get_targets(1, 1000)
            .map(|r| {
                let t = r.targets;
                let vuln = t.iter().map(|x| x.vulnerabilities_count as i64).sum();
                let active = t.iter().filter(|x| x.is_active).count() as i64;
                let risk = t.iter().filter(|x| x.risk_level == "critical" || x.risk_level == "high").count() as i64;
                (r.total as i64, vuln, active, risk)
            })
            .unwrap_or_else(|e| {
                eprintln!("Dashboard: target query failed: {}", e);
                (0, 0, 0, 0)
            });

    // Groups — empty on error
    let total_groups = db_guard.get_target_groups(1000, 0)
        .map(|g| g.len() as i64)
        .unwrap_or_else(|e| {
            eprintln!("Dashboard: target_groups query failed: {}", e);
            0
        });

    // Risk distribution
    let risk_distribution = db_guard.get_targets(1000, 0)
        .map(|targets| DashboardRiskDistribution {
            critical: targets.iter().filter(|t| t.risk_level == "critical").count() as i64,
            high: targets.iter().filter(|t| t.risk_level == "high").count() as i64,
            medium: targets.iter().filter(|t| t.risk_level == "medium").count() as i64,
            low: targets.iter().filter(|t| t.risk_level == "low").count() as i64,
            info: targets.iter().filter(|t| t.risk_level == "info" || t.risk_level.is_empty()).count() as i64,
        })
        .unwrap_or_else(|e| {
            eprintln!("Dashboard: risk distribution query failed: {}", e);
            DashboardRiskDistribution { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        });

    // Recent activity — empty on error
    let recent_activity = db_guard.get_all_tool_history(10, 0)
        .map(|history| history.iter().map(|h| DashboardActivityItem {
            tool_type: h.tool_type.clone(),
            tool_name: h.tool_name.clone(),
            input_summary: h.input_summary.clone(),
            status: h.status.clone(),
            created_at: h.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        }).collect())
        .unwrap_or_else(|e| {
            eprintln!("Dashboard: tool_history query failed: {}", e);
            Vec::new()
        });

    // Tool usage — empty on error
    let tool_usage = db_guard.get_all_tool_history(1000, 0)
        .map(|all_history| {
            let mut usage_map: std::collections::HashMap<String, (String, i64)> = std::collections::HashMap::new();
            for h in &all_history {
                let entry = usage_map.entry(h.tool_type.clone()).or_insert((h.tool_name.clone(), 0));
                entry.1 += 1;
            }
            let mut usage: Vec<DashboardToolUsage> = usage_map.into_iter()
                .map(|(tool_type, (tool_name, count))| DashboardToolUsage { tool_type, tool_name, count })
                .collect();
            usage.sort_by(|a, b| b.count.cmp(&a.count));
            usage.truncate(5);
            usage
        })
        .unwrap_or_else(|e| {
            eprintln!("Dashboard: tool_usage query failed: {}", e);
            Vec::new()
        });

    // System info — always available
    let resources = SystemResources::detect_cached();
    let system_info = SystemInfoResponse {
        cpu_cores: resources.cpu_cores,
        total_memory_mb: resources.total_memory_mb,
        available_memory_mb: resources.available_memory_mb,
        cpu_usage_percent: resources.cpu_usage_percent,
        load_average: resources.load_average,
        optimal_concurrency: resources.calculate_optimal_concurrency(),
        recommended_timeout: resources.get_recommended_timeout(),
        summary: resources.summary(),
    };

    Ok(DashboardData {
        scan_stats: DashboardScanStats {
            total_scans,
            completed_scans,
            failed_scans,
            running_scans,
            total_open_ports,
            success_rate,
        },
        target_stats: DashboardTargetStats {
            total_targets,
            total_groups,
            total_vulnerabilities,
            active_targets,
            at_risk_targets,
        },
        risk_distribution,
        recent_activity,
        tool_usage,
        system_info,
    })
}
