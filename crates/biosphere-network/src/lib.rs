pub mod core;
pub mod infrastructure;
pub mod tools;
pub mod plugins;

pub use core::{Tool, ToolArgs, ToolCategory, ToolInfo, ToolOutput, ToolRegistry, ToolError, Result, ProgressReporter};
pub use core::{
    BiosEventType, EventCategory, BiosEvent, BiosEventRef, BiosTarget,
    BiosModule, ModuleMeta, ModuleConfig, ModuleRegistry,
    EventBus, EventBusConfig, EventStats,
    Correlator, CorrelationRule, CorrelationResult, CorrelationRuleMeta,
    CorrelationMatchRule, CorrelationCollection, CorrelationAggregation,
    CorrelationAnalysis, default_correlation_rules,
    ScanOrchestrator, ScanState, ScanResult, ScanConfig, ScanConfigSnapshot,
    EngineDatabase,
};
pub use tools::info_gathering::{
    HostToIp, ResolveConfig, ResolveResult, Resolver, HostDnsRecord, HostInfo, HostSecurityFinding,
    PortScanner, PortScanConfig, PortScanResult, PortStatus, ScanMode, Scanner, ServiceVersion, OSDetection,
    request_cancel, is_cancelled, reset_cancel,
    DnsQueryConfig, DnsQueryType, DnsResolver,
    PingConfig, Pinger,
    WhoisTool, WhoisConfig, WhoisResult, query_whois,
};
pub use tools::info_gathering::port_scanner::{PortMarker, MarkType, WellKnownPort, PortCategory, RiskLevel, PortInfo, get_port_marker, init_port_marker};
pub use tools::others::encoder_decoder::{EncoderDecoderTool, EncoderConfig, EncoderResult, EncodingType, Operation, encode_decode, encode_bytes, decode_bytes, compute_hash, timestamp_to_datetime, datetime_to_timestamp, get_current_timestamp};
pub use tools::others::password_generator::{PasswordGenerator, PasswordConfig, PasswordResult, PasswordStrength, generate_passwords, generate_passphrase, check_password_strength};
pub use tools::others::zip_extractor::{ZipExtractor, ZipFileInfo, ZipExtractResult, ZipBruteForceResult, list_zip_files, extract_zip, check_zip_encryption, brute_force_zip};
pub use tools::others::hash_identifier::{HashIdentification, HashTypeMatch, IpGeoInfo, identify_hash, lookup_ip_geo};
pub use tools::others::security_headers::{SecurityHeaderAnalyzer, SecurityHeaderConfig, SecurityHeaderReport, HeaderDetail, HeaderIssue, CspAnalysis, HstsAnalysis, CspDirective, InformationLeakage, CookieSecurityInfo, SeverityStats, CategoryStat, RedirectEntry, HttpsRedirectCheck};
pub use tools::others::ssl_checker::{SslCheckResult, CertificateInfo, BatchSslCheckResult, SslCheckerTool};
pub use tools::others::site_checker::{SiteCheckResult, BatchSiteCheckResult, SiteCheckerTool};
pub use tools::others::waf_detector::{WafDetectionResult, BatchWafDetectionResult, WafDetectorTool, WafConfig, WafIndicator, BlockedPayload, CookieIndicator, ResponseAnalysis, BypassSuggestion, SeverityStats as WafSeverityStats, CategoryStat as WafCategoryStat};
pub use tools::others::wordlist_generator::{WordlistGeneratorTool, WordlistConfig, WordlistResult};
pub use tools::others::subdomain_enum::{SubdomainEnumTool, SubdomainConfig, SubdomainResult, SubdomainEntry};
pub use tools::others::dir_scanner::{DirScannerTool, DirScanConfig, DirScanResult, DirEntry, SslInfo, WafDetection, SensitivePath};
pub use tools::others::cve_lookup::{CveLookupTool, CveQueryConfig, CveQueryResult, CveEntry};
pub use tools::others::email_verifier::{EmailVerifierTool, EmailVerifyConfig, EmailVerifyResult, EmailVerifyEntry};
pub use tools::others::username_osint::{UsernameOsintTool, UsernameOsintConfig, UsernameOsintResult, PlatformResult, BatchUsernameResult, OsintProgress, MaigretImporter, ImportStats};
pub use tools::others::idn_checker::{IdnCheckerTool, IdnCheckConfig, IdnCheckResult, SuspiciousChar, SimilarDomain, DomainVariant, CharSubstitution, ScriptAnalysis, ScriptInfo, BrandMatch, BatchIdnCheckResult};
pub use tools::others::param_discovery::{ParamDiscoveryTool, ParamDiscoveryConfig, ParamDiscoveryResult, ParamEntry};
pub use tools::others::subdomain_takeover::{SubdomainTakeoverTool, TakeoverConfig, TakeoverResult, TakeoverEntry};
pub use tools::others::web_crawler::{WebCrawlerTool, WebCrawlerConfig, WebCrawlerResult, CrawledLink, ResourceInfo, ApiEndpoint, PageMetadata, DirEntryInfo, DownloadResult, BatchDownloadResult, SiteDownloadConfig, ExportConfig};
pub use tools::others::tech_detector::{TechDetectorTool, TechDetectConfig, TechDetectResult, DetectedTech, TechCategory};
pub use tools::others::secret_scanner::{SecretScannerTool, SecretScanConfig, SecretScanResult, DetectedSecret};
pub use tools::others::sqli_scanner::{SqliScannerTool, SqliScanConfig, SqliScanResult, SqliVulnerability};
pub use tools::others::xss_scanner::{XssScannerTool, XssScanConfig, XssScanResult, XssVulnerability};
pub use tools::others::hash_cracker::{HashCrackerTool, HashCrackConfig, HashCrackResult, HashAttempt};
pub use tools::others::steganography::{SteganographyTool, SteganographyConfig, SteganographyResult};
pub use tools::others::brute_force::{BruteForceTool, BruteForceConfig, BruteForceResult};
pub use tools::others::metadata_extractor::{MetadataExtractorTool, MetadataExtractConfig, MetadataExtractResult, MetadataItem, SensitiveFinding};
pub use tools::others::cors_checker::{CorsCheckerTool, CorsCheckConfig, CorsCheckResult, CorsIssue, CorsOriginResult};
pub use tools::others::open_redirect::{OpenRedirectTool, OpenRedirectConfig, OpenRedirectResult, OpenRedirectVuln};
pub use tools::others::cookie_analyzer::{CookieAnalyzerTool, CookieAnalyzerConfig, CookieAnalyzerResult, CookieInfo, CookieIssue};
pub use tools::others::admin_finder::{AdminFinderTool, AdminFinderConfig, AdminFinderResult, AdminPath};
pub use tools::others::command_injection::{CommandInjectionTool, CommandInjectionConfig, CommandInjectionResult, CommandInjectionVuln};
pub use tools::others::network_discovery::{NetworkDiscoveryTool, NetworkDiscoveryConfig, NetworkDiscoveryResult, DiscoveredHost, DiscoveredPort, DetectedService, NetworkTopology, NetworkSecurityFinding, TopologyNode, TopologyEdge};
pub use tools::others::wifi_scanner::{WifiScannerTool, WifiScanConfig, WifiScanResult, WifiNetwork, WifiSecuritySummary, WifiVulnerability, WifiConnectorTool, WifiConnectConfig, WifiConnectResult, WifiCrackDiscoveryTool, CrackResult, WifiInterfaceTool, NetworkInterface, WifiAutoCrackTool, AutoCrackResult};
pub use tools::others::cloud_audit::{CloudAuditTool, CloudAuditConfig, CloudAuditResult, CloudFinding};
pub use tools::others::apk_analysis::{ApkAnalysisTool, ApkAnalysisConfig, ApkAnalysisResult, ApkCertificateInfo};
pub use tools::others::dns_analyzer::{DnsAnalyzerTool, DnsAnalyzerConfig, DnsAnalyzerResult, DnsRecord, DnssecDetails, ZoneTransferDetails, DnsSecurityIssue};
pub use tools::others::ddos_tester::{DdosTesterTool, DdosTesterConfig, DdosTesterResult, DdosFinding};
pub use tools::others::privilege_esc_check::{PrivilegeEscCheckTool, PrivilegeEscConfig, PrivilegeEscResult, UserInfo, PermissionBinary, CapabilityInfo, CronJobInfo, WritablePath, VulnerableService, KernelExploit, DockerIssue, Misconfiguration};
pub use tools::others::binary_analyzer::{BinaryAnalyzerTool, BinaryAnalyzerConfig, BinaryAnalyzerResult, BinaryHeaders, BinarySection, ImportEntry, ExportEntry, FoundString, SymbolEntry, EntropyAnalysis, PackingDetection, AntiDebugDetection, SecurityFeatures, BinaryVulnerability, DirectoryScanResult, DiscoveredBinary};
pub use tools::others::exploit_framework::{ExploitFrameworkTool, ExploitFrameworkConfig, ExploitFrameworkResult, ExploitInfo, ServiceVulnerability};
pub use tools::others::post_exploitation::{PostExploitationTool, PostExploitationConfig, PostExploitationResult, PersistenceMechanism, LateralMovementPath, DataExfilVector, CredentialInfo, NetworkPivot};
pub use tools::others::phishing_detector::{PhishingDetectorTool, PhishingDetectorConfig, PhishingDetectorResult, DomainAnalysis, SslAnalysis, ContentAnalysis, RedirectAnalysis, ReputationInfo, PhishingIndicator};
pub use tools::others::payload_injector::{PayloadInjectorTool, PayloadInjectorConfig, PayloadInjectorResult, PayloadTemplate, InjectionResult, EncodingResult};
pub use tools::others::anonymity_checker::{AnonymityCheckerTool, AnonymityCheckerConfig, AnonymityCheckerResult, IpLeakInfo, DnsLeakInfo, WebRtcLeakInfo, BrowserFingerprint, ProxyInfo, TorInfo, VpnInfo, AnonymityIssue};
pub use tools::others::forensics_analyzer::{ForensicsAnalyzerTool, ForensicsAnalyzerConfig, ForensicsAnalyzerResult, FilesystemInfo, SuspiciousFile, MemoryAnalysis, ProcessInfo, NetworkConnection, TimelineEntry, AntiForensicsIndicator, RegistryInfo, RegistryEntry};
pub use tools::others::ad_audit::{AdAuditTool, AdAuditConfig, AdAuditResult, KerberosInfo, LdapInfo, SmbInfo, DnsInfo, CertInfo, TrustInfo, GpoInfo, AclInfo, AdIssue};
pub use tools::others::mobile_security::{MobileSecurityTool, MobileSecurityConfig, MobileSecurityResult, PermissionInfo, ApiSecurityIssue, DataStorageIssue, CryptoIssue, NetworkIssue, TamperingProtection, PrivacyIssue};
pub use tools::others::asset_search::{AssetSearchTool, AssetSearchConfig, AssetSearchResult, DiscoveredAsset, SearchStatistics, AssetSecurityFinding};
pub use tools::others::reverse_ip::{ReverseIpTool, ReverseIpConfig, ReverseIpResult, ReverseDomain, DnsHistoryEntry, RelatedIp, ReverseIpFinding};
pub use tools::others::cf_bypass::{CfBypassTool, CfBypassConfig, CfBypassResult, OriginIp, BypassMethod, DnsHistoryRecord, SubdomainRecord, SslCertificateInfo, CfBypassFinding};
pub use tools::others::social_finder::{SocialFinderTool, SocialFinderConfig, SocialFinderResult, SocialAccount, SocialFinderStats, SocialFinding, PlatformListItem};
pub use tools::others::osint_gather::{OsintGatherTool, OsintGatherConfig, OsintGatherResult, OsintEmail, OsintSubdomain, OsintIpInfo, OsintUrl, OsintDnsRecord, OsintMetadata, OsintFinding};
pub use tools::others::reverse_engineer::{ReverseEngineerTool, ReverseEngineerConfig, ReverseEngineerResult, DecompiledClass, DecompiledMethod, ManifestInfo, IntentFilter, ReverseCertificateInfo, HardcodedSecret, SmaliAnalysis, ResourceInfo as ReverseResourceInfo, ReverseSecurityFinding};
pub use tools::others::wifi_deauth_detector::{WifiDeauthDetectorTool, WifiDeauthConfig, WifiDeauthResult, DeauthPacket, AccessPoint, DeauthAlert, ChannelAnalysis, WifiDeauthFinding, WifiInterface};
pub use tools::others::rat_tool::{RatTool, RatToolConfig, RatToolResult, RatConnection, RatCapability, RatDetection, RatSecurityFinding};
pub use tools::others::bluetooth_scanner::{BluetoothScannerTool, BluetoothScanConfig, BluetoothScanResult, BluetoothDevice, BluetoothVulnerability, BluetoothService, BluetoothSecurityFinding};
pub use tools::others::memory_forensics::{MemoryForensicsTool, MemoryForensicsConfig, MemoryForensicsResult, MemoryProcess, MemoryConnection, MemoryArtifact, InjectedCode, RegistryKey, MemorySecurityFinding};
pub use tools::others::firmware_analyzer::{FirmwareAnalyzerTool, FirmwareAnalyzerConfig, FirmwareAnalyzerResult, FirmwareInfo, FirmwarePartition, FirmwareCredential, FirmwareBinary, FirmwareBackdoor, FirmwareSecurityFinding};
pub use tools::others::social_engineering::{SocialEngineeringTool, SocialEngineeringConfig, SocialEngineeringResult, TyposquattingResult, TyposquattedDomain, BrandImpersonation, EmailPhishingIndicator, SocialEngineeringFinding};
pub use infrastructure::database::models::Target;
pub use infrastructure::database::models::{OsintPlatform, OsintScanResult};
pub use infrastructure::database::models::{TargetType, TargetCategory, TargetGroup};
pub use tools::info_gathering::target_manager::TargetService;
pub use tools::info_gathering::target_manager::TargetConfig;
pub use tools::info_gathering::target_manager::ScanRecord;
pub use infrastructure::{SecHeaderRecord, HashIdentifierRecord, IpGeoRecord, SslCheckRecord, SiteCheckRecord, WafDetectionRecord, ToolHistoryRecord, NetworkDiscoveryRecord};
