use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    Entity,
    Descriptor,
    Data,
    SubEntity,
    Internal,
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventCategory::Entity => write!(f, "ENTITY"),
            EventCategory::Descriptor => write!(f, "DESCRIPTOR"),
            EventCategory::Data => write!(f, "DATA"),
            EventCategory::SubEntity => write!(f, "SUBENTITY"),
            EventCategory::Internal => write!(f, "INTERNAL"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BiosEventType {
    Root,
    IpAddress,
    Ipv6Address,
    NetblockOwner,
    NetblockV6Owner,
    InternetName,
    DomainName,
    DomainNameParent,
    DomainRegistrar,
    DomainWhois,
    EmailAddr,
    EmailAddrCompromised,
    EmailAddrDeliverable,
    EmailAddrDisposable,
    EmailAddrGeneric,
    EmailAddrUndeliverable,
    HumanName,
    PhoneNumber,
    PhoneNumberCompromised,
    Username,
    BitcoinAddress,
    EthereumAddress,
    CompanyName,
    PhysicalAddress,
    PhysicalCoordinates,
    CountryName,
    GeoInfo,
    BgpAsOwner,
    BgpAsMember,
    AffiliateEmailAddr,
    AffiliateInternetName,
    AffiliateIpAddress,
    AffiliateDomainName,
    AffiliateCompanyName,
    CoHostedSite,
    CoHostedSiteDomain,
    AccountExternalOwned,
    AccountExternalOwnedCompromised,
    SocialMedia,
    SimilarDomain,
    SimilarAccountExternal,
    PublicCodeRepo,
    AppStoreEntry,
    CloudStorageBucket,
    CloudStorageBucketOpen,
    ProviderDns,
    ProviderMail,
    ProviderHosting,
    ProviderJavascript,
    SslCertificateRaw,
    SslCertificateIssued,
    SslCertificateIssuer,
    SslCertificateExpired,
    SslCertificateMismatch,
    DnsText,
    DnsSrv,
    DnsSpf,
    RawDnsRecords,
    RawRirData,
    RawFileMetaData,
    TcpPortOpen,
    TcpPortOpenBanner,
    UdpPortOpen,
    OperatingSystem,
    DeviceType,
    WebServerBanner,
    WebServerHttpHeaders,
    WebServerStrangeHeader,
    WebServerTechnology,
    WebAnalyticsId,
    LinkedUrlInternal,
    LinkedUrlExternal,
    TargetWebContent,
    TargetWebContentType,
    TargetWebCookie,
    HttpCode,
    DarknetMentionUrl,
    DarknetMentionContent,
    LeakSiteUrl,
    LeakSiteContent,
    MaliciousIpAddress,
    MaliciousInternetName,
    MaliciousEmailAddr,
    MaliciousCoHost,
    MaliciousAffiliateInternetName,
    MaliciousAffiliateIpAddress,
    MaliciousSubnet,
    MaliciousNetblock,
    MaliciousAsn,
    MaliciousBitcoinAddress,
    BlacklistedIpAddress,
    BlacklistedInternetName,
    BlacklistedCoHost,
    BlacklistedSubnet,
    BlacklistedNetblock,
    VulnerabilityCveCritical,
    VulnerabilityCveHigh,
    VulnerabilityCveMedium,
    VulnerabilityCveLow,
    VulnerabilityGeneral,
    VulnerabilityDisclosure,
    DefacedInternetName,
    DefacedIpAddress,
    DatabaseExposed,
    RemoteDesktopExposed,
    DnsZoneTransferPossible,
    InternalIpAddress,
    ProxyHost,
    VpnHost,
    TorExitNode,
    InterestingFile,
    JunkFile,
    PasswordCompromised,
    HashCompromised,
    CreditCardNumber,
    IbanNumber,
    PgpKey,
    JobTitle,
    DateHumanDob,
    SoftwareUsed,
    WifiAccessPoint,
    SearchEngineWebContent,
    Error,
    Base64Data,
    Hash,
    DescriptionCategory,
    DescriptionAbstract,
    UrlForm,
    UrlJavascript,
    UrlFlash,
    UrlWebFramework,
    UrlPassword,
    UrlUpload,
    UrlStatic,
    UrlAdblockedExternal,
    UrlAdblockedInternal,
    Lei,
    NetblockWhois,
    AffiliateDomainWhois,
    CoHostedSiteDomainWhois,
    SimilarDomainWhois,
    SslCertificateExpiring,
    AffiliateInternetNameUnresolved,
    AffiliateInternetNameHijackable,
    AffiliateDescriptionCategory,
    AffiliateDescriptionAbstract,
    DarknetMention,
    PhishingUrl,
    Custom(String),
}

impl BiosEventType {
    pub fn category(&self) -> EventCategory {
        match self {
            BiosEventType::Root => EventCategory::Internal,
            BiosEventType::IpAddress
            | BiosEventType::Ipv6Address
            | BiosEventType::NetblockOwner
            | BiosEventType::NetblockV6Owner
            | BiosEventType::InternetName
            | BiosEventType::DomainName
            | BiosEventType::DomainNameParent
            | BiosEventType::DomainRegistrar
            | BiosEventType::EmailAddr
            | BiosEventType::EmailAddrGeneric
            | BiosEventType::HumanName
            | BiosEventType::PhoneNumber
            | BiosEventType::Username
            | BiosEventType::BitcoinAddress
            | BiosEventType::EthereumAddress
            | BiosEventType::CompanyName
            | BiosEventType::PhysicalAddress
            | BiosEventType::PhysicalCoordinates
            | BiosEventType::CountryName
            | BiosEventType::BgpAsOwner
            | BiosEventType::BgpAsMember
            | BiosEventType::AffiliateEmailAddr
            | BiosEventType::AffiliateInternetName
            | BiosEventType::AffiliateIpAddress
            | BiosEventType::AffiliateDomainName
            | BiosEventType::AffiliateCompanyName
            | BiosEventType::CoHostedSite
            | BiosEventType::CoHostedSiteDomain
            | BiosEventType::AccountExternalOwned
            | BiosEventType::SocialMedia
            | BiosEventType::SimilarDomain
            | BiosEventType::SimilarAccountExternal
            | BiosEventType::PublicCodeRepo
            | BiosEventType::AppStoreEntry
            | BiosEventType::CloudStorageBucket
            | BiosEventType::ProviderDns
            | BiosEventType::ProviderMail
            | BiosEventType::ProviderHosting
            | BiosEventType::ProviderJavascript
            | BiosEventType::SslCertificateIssued
            | BiosEventType::SslCertificateIssuer
            | BiosEventType::Lei
            | BiosEventType::InternalIpAddress
            | BiosEventType::WifiAccessPoint
            | BiosEventType::JobTitle
            | BiosEventType::DateHumanDob
            | BiosEventType::SoftwareUsed
            | BiosEventType::NetblockWhois
            | BiosEventType::AffiliateInternetNameUnresolved
            | BiosEventType::PhishingUrl => EventCategory::Entity,
            BiosEventType::MaliciousIpAddress
            | BiosEventType::MaliciousInternetName
            | BiosEventType::MaliciousEmailAddr
            | BiosEventType::MaliciousCoHost
            | BiosEventType::MaliciousAffiliateInternetName
            | BiosEventType::MaliciousAffiliateIpAddress
            | BiosEventType::MaliciousSubnet
            | BiosEventType::MaliciousNetblock
            | BiosEventType::MaliciousAsn
            | BiosEventType::MaliciousBitcoinAddress
            | BiosEventType::BlacklistedIpAddress
            | BiosEventType::BlacklistedInternetName
            | BiosEventType::BlacklistedCoHost
            | BiosEventType::BlacklistedSubnet
            | BiosEventType::BlacklistedNetblock
            | BiosEventType::EmailAddrCompromised
            | BiosEventType::EmailAddrDeliverable
            | BiosEventType::EmailAddrDisposable
            | BiosEventType::EmailAddrUndeliverable
            | BiosEventType::PhoneNumberCompromised
            | BiosEventType::AccountExternalOwnedCompromised
            | BiosEventType::CloudStorageBucketOpen
            | BiosEventType::SslCertificateExpired
            | BiosEventType::SslCertificateMismatch
            | BiosEventType::SslCertificateExpiring
            | BiosEventType::VulnerabilityCveCritical
            | BiosEventType::VulnerabilityCveHigh
            | BiosEventType::VulnerabilityCveMedium
            | BiosEventType::VulnerabilityCveLow
            | BiosEventType::VulnerabilityGeneral
            | BiosEventType::VulnerabilityDisclosure
            | BiosEventType::DefacedInternetName
            | BiosEventType::DefacedIpAddress
            | BiosEventType::DatabaseExposed
            | BiosEventType::RemoteDesktopExposed
            | BiosEventType::DnsZoneTransferPossible
            | BiosEventType::ProxyHost
            | BiosEventType::VpnHost
            | BiosEventType::TorExitNode
            | BiosEventType::InterestingFile
            | BiosEventType::JunkFile
            | BiosEventType::GeoInfo
            | BiosEventType::OperatingSystem
            | BiosEventType::DeviceType
            | BiosEventType::WebServerTechnology
            | BiosEventType::WebAnalyticsId
            | BiosEventType::DescriptionCategory
            | BiosEventType::DescriptionAbstract
            | BiosEventType::AffiliateDescriptionCategory
            | BiosEventType::AffiliateDescriptionAbstract
            | BiosEventType::AffiliateInternetNameHijackable
            | BiosEventType::DarknetMention
            | BiosEventType::UrlAdblockedExternal
            | BiosEventType::UrlAdblockedInternal => EventCategory::Descriptor,
            BiosEventType::DomainWhois
            | BiosEventType::RawDnsRecords
            | BiosEventType::RawRirData
            | BiosEventType::RawFileMetaData
            | BiosEventType::SslCertificateRaw
            | BiosEventType::TargetWebContent
            | BiosEventType::TargetWebContentType
            | BiosEventType::TargetWebCookie
            | BiosEventType::WebServerBanner
            | BiosEventType::WebServerHttpHeaders
            | BiosEventType::WebServerStrangeHeader
            | BiosEventType::SearchEngineWebContent
            | BiosEventType::DarknetMentionContent
            | BiosEventType::LeakSiteContent
            | BiosEventType::DnsText
            | BiosEventType::DnsSrv
            | BiosEventType::DnsSpf
            | BiosEventType::TcpPortOpenBanner
            | BiosEventType::UdpPortOpen
            | BiosEventType::HttpCode
            | BiosEventType::PasswordCompromised
            | BiosEventType::HashCompromised
            | BiosEventType::PgpKey
            | BiosEventType::CreditCardNumber
            | BiosEventType::IbanNumber
            | BiosEventType::Hash
            | BiosEventType::Base64Data
            | BiosEventType::Error
            | BiosEventType::AffiliateDomainWhois
            | BiosEventType::CoHostedSiteDomainWhois
            | BiosEventType::SimilarDomainWhois => EventCategory::Data,
            BiosEventType::LinkedUrlInternal
            | BiosEventType::LinkedUrlExternal
            | BiosEventType::TcpPortOpen
            | BiosEventType::UrlForm
            | BiosEventType::UrlJavascript
            | BiosEventType::UrlFlash
            | BiosEventType::UrlWebFramework
            | BiosEventType::UrlPassword
            | BiosEventType::UrlUpload
            | BiosEventType::UrlStatic
            | BiosEventType::DarknetMentionUrl
            | BiosEventType::LeakSiteUrl => EventCategory::SubEntity,
            BiosEventType::Custom(_) => EventCategory::Entity,
        }
    }

    pub fn is_entity(&self) -> bool {
        self.category() == EventCategory::Entity
    }

    pub fn as_str(&self) -> &str {
        match self {
            BiosEventType::Root => "ROOT",
            BiosEventType::IpAddress => "IP_ADDRESS",
            BiosEventType::Ipv6Address => "IPV6_ADDRESS",
            BiosEventType::NetblockOwner => "NETBLOCK_OWNER",
            BiosEventType::NetblockV6Owner => "NETBLOCKV6_OWNER",
            BiosEventType::InternetName => "INTERNET_NAME",
            BiosEventType::DomainName => "DOMAIN_NAME",
            BiosEventType::DomainNameParent => "DOMAIN_NAME_PARENT",
            BiosEventType::DomainRegistrar => "DOMAIN_REGISTRAR",
            BiosEventType::DomainWhois => "DOMAIN_WHOIS",
            BiosEventType::EmailAddr => "EMAILADDR",
            BiosEventType::EmailAddrCompromised => "EMAILADDR_COMPROMISED",
            BiosEventType::EmailAddrDeliverable => "EMAILADDR_DELIVERABLE",
            BiosEventType::EmailAddrDisposable => "EMAILADDR_DISPOSABLE",
            BiosEventType::EmailAddrGeneric => "EMAILADDR_GENERIC",
            BiosEventType::EmailAddrUndeliverable => "EMAILADDR_UNDELIVERABLE",
            BiosEventType::HumanName => "HUMAN_NAME",
            BiosEventType::PhoneNumber => "PHONE_NUMBER",
            BiosEventType::PhoneNumberCompromised => "PHONE_NUMBER_COMPROMISED",
            BiosEventType::Username => "USERNAME",
            BiosEventType::BitcoinAddress => "BITCOIN_ADDRESS",
            BiosEventType::EthereumAddress => "ETHEREUM_ADDRESS",
            BiosEventType::CompanyName => "COMPANY_NAME",
            BiosEventType::PhysicalAddress => "PHYSICAL_ADDRESS",
            BiosEventType::PhysicalCoordinates => "PHYSICAL_COORDINATES",
            BiosEventType::CountryName => "COUNTRY_NAME",
            BiosEventType::GeoInfo => "GEOINFO",
            BiosEventType::BgpAsOwner => "BGP_AS_OWNER",
            BiosEventType::BgpAsMember => "BGP_AS_MEMBER",
            BiosEventType::AffiliateEmailAddr => "AFFILIATE_EMAILADDR",
            BiosEventType::AffiliateInternetName => "AFFILIATE_INTERNET_NAME",
            BiosEventType::AffiliateIpAddress => "AFFILIATE_IPADDR",
            BiosEventType::AffiliateDomainName => "AFFILIATE_DOMAIN_NAME",
            BiosEventType::AffiliateCompanyName => "AFFILIATE_COMPANY_NAME",
            BiosEventType::CoHostedSite => "CO_HOSTED_SITE",
            BiosEventType::CoHostedSiteDomain => "CO_HOSTED_SITE_DOMAIN",
            BiosEventType::AccountExternalOwned => "ACCOUNT_EXTERNAL_OWNED",
            BiosEventType::AccountExternalOwnedCompromised => "ACCOUNT_EXTERNAL_OWNED_COMPROMISED",
            BiosEventType::SocialMedia => "SOCIAL_MEDIA",
            BiosEventType::SimilarDomain => "SIMILARDOMAIN",
            BiosEventType::SimilarAccountExternal => "SIMILAR_ACCOUNT_EXTERNAL",
            BiosEventType::PublicCodeRepo => "PUBLIC_CODE_REPO",
            BiosEventType::AppStoreEntry => "APPSTORE_ENTRY",
            BiosEventType::CloudStorageBucket => "CLOUD_STORAGE_BUCKET",
            BiosEventType::CloudStorageBucketOpen => "CLOUD_STORAGE_BUCKET_OPEN",
            BiosEventType::ProviderDns => "PROVIDER_DNS",
            BiosEventType::ProviderMail => "PROVIDER_MAIL",
            BiosEventType::ProviderHosting => "PROVIDER_HOSTING",
            BiosEventType::ProviderJavascript => "PROVIDER_JAVASCRIPT",
            BiosEventType::SslCertificateRaw => "SSL_CERTIFICATE_RAW",
            BiosEventType::SslCertificateIssued => "SSL_CERTIFICATE_ISSUED",
            BiosEventType::SslCertificateIssuer => "SSL_CERTIFICATE_ISSUER",
            BiosEventType::SslCertificateExpired => "SSL_CERTIFICATE_EXPIRED",
            BiosEventType::SslCertificateMismatch => "SSL_CERTIFICATE_MISMATCH",
            BiosEventType::SslCertificateExpiring => "SSL_CERTIFICATE_EXPIRING",
            BiosEventType::DnsText => "DNS_TEXT",
            BiosEventType::DnsSrv => "DNS_SRV",
            BiosEventType::DnsSpf => "DNS_SPF",
            BiosEventType::RawDnsRecords => "RAW_DNS_RECORDS",
            BiosEventType::RawRirData => "RAW_RIR_DATA",
            BiosEventType::RawFileMetaData => "RAW_FILE_META_DATA",
            BiosEventType::TcpPortOpen => "TCP_PORT_OPEN",
            BiosEventType::TcpPortOpenBanner => "TCP_PORT_OPEN_BANNER",
            BiosEventType::UdpPortOpen => "UDP_PORT_OPEN",
            BiosEventType::OperatingSystem => "OPERATING_SYSTEM",
            BiosEventType::DeviceType => "DEVICE_TYPE",
            BiosEventType::WebServerBanner => "WEBSERVER_BANNER",
            BiosEventType::WebServerHttpHeaders => "WEBSERVER_HTTPHEADERS",
            BiosEventType::WebServerStrangeHeader => "WEBSERVER_STRANGEHEADER",
            BiosEventType::WebServerTechnology => "WEBSERVER_TECHNOLOGY",
            BiosEventType::WebAnalyticsId => "WEB_ANALYTICS_ID",
            BiosEventType::LinkedUrlInternal => "LINKED_URL_INTERNAL",
            BiosEventType::LinkedUrlExternal => "LINKED_URL_EXTERNAL",
            BiosEventType::TargetWebContent => "TARGET_WEB_CONTENT",
            BiosEventType::TargetWebContentType => "TARGET_WEB_CONTENT_TYPE",
            BiosEventType::TargetWebCookie => "TARGET_WEB_COOKIE",
            BiosEventType::HttpCode => "HTTP_CODE",
            BiosEventType::DarknetMentionUrl => "DARKNET_MENTION_URL",
            BiosEventType::DarknetMentionContent => "DARKNET_MENTION_CONTENT",
            BiosEventType::LeakSiteUrl => "LEAKSITE_URL",
            BiosEventType::LeakSiteContent => "LEAKSITE_CONTENT",
            BiosEventType::MaliciousIpAddress => "MALICIOUS_IPADDR",
            BiosEventType::MaliciousInternetName => "MALICIOUS_INTERNET_NAME",
            BiosEventType::MaliciousEmailAddr => "MALICIOUS_EMAILADDR",
            BiosEventType::MaliciousCoHost => "MALICIOUS_COHOST",
            BiosEventType::MaliciousAffiliateInternetName => "MALICIOUS_AFFILIATE_INTERNET_NAME",
            BiosEventType::MaliciousAffiliateIpAddress => "MALICIOUS_AFFILIATE_IPADDR",
            BiosEventType::MaliciousSubnet => "MALICIOUS_SUBNET",
            BiosEventType::MaliciousNetblock => "MALICIOUS_NETBLOCK",
            BiosEventType::MaliciousAsn => "MALICIOUS_ASN",
            BiosEventType::MaliciousBitcoinAddress => "MALICIOUS_BITCOIN_ADDRESS",
            BiosEventType::BlacklistedIpAddress => "BLACKLISTED_IPADDR",
            BiosEventType::BlacklistedInternetName => "BLACKLISTED_INTERNET_NAME",
            BiosEventType::BlacklistedCoHost => "BLACKLISTED_COHOST",
            BiosEventType::BlacklistedSubnet => "BLACKLISTED_SUBNET",
            BiosEventType::BlacklistedNetblock => "BLACKLISTED_NETBLOCK",
            BiosEventType::VulnerabilityCveCritical => "VULNERABILITY_CVE_CRITICAL",
            BiosEventType::VulnerabilityCveHigh => "VULNERABILITY_CVE_HIGH",
            BiosEventType::VulnerabilityCveMedium => "VULNERABILITY_CVE_MEDIUM",
            BiosEventType::VulnerabilityCveLow => "VULNERABILITY_CVE_LOW",
            BiosEventType::VulnerabilityGeneral => "VULNERABILITY_GENERAL",
            BiosEventType::VulnerabilityDisclosure => "VULNERABILITY_DISCLOSURE",
            BiosEventType::DefacedInternetName => "DEFACED_INTERNET_NAME",
            BiosEventType::DefacedIpAddress => "DEFACED_IPADDR",
            BiosEventType::DatabaseExposed => "DATABASE_EXPOSED",
            BiosEventType::RemoteDesktopExposed => "REMOTE_DESKTOP_EXPOSED",
            BiosEventType::DnsZoneTransferPossible => "DNS_ZONE_TRANSFER_POSSIBLE",
            BiosEventType::InternalIpAddress => "INTERNAL_IP_ADDRESS",
            BiosEventType::ProxyHost => "PROXY_HOST",
            BiosEventType::VpnHost => "VPN_HOST",
            BiosEventType::TorExitNode => "TOR_EXIT_NODE",
            BiosEventType::InterestingFile => "INTERESTING_FILE",
            BiosEventType::JunkFile => "JUNK_FILE",
            BiosEventType::PasswordCompromised => "PASSWORD_COMPROMISED",
            BiosEventType::HashCompromised => "HASH_COMPROMISED",
            BiosEventType::CreditCardNumber => "CREDIT_CARD_NUMBER",
            BiosEventType::IbanNumber => "IBAN_NUMBER",
            BiosEventType::PgpKey => "PGP_KEY",
            BiosEventType::JobTitle => "JOB_TITLE",
            BiosEventType::DateHumanDob => "DATE_HUMAN_DOB",
            BiosEventType::SoftwareUsed => "SOFTWARE_USED",
            BiosEventType::WifiAccessPoint => "WIFI_ACCESS_POINT",
            BiosEventType::SearchEngineWebContent => "SEARCH_ENGINE_WEB_CONTENT",
            BiosEventType::Error => "ERROR",
            BiosEventType::Base64Data => "BASE64_DATA",
            BiosEventType::Hash => "HASH",
            BiosEventType::DescriptionCategory => "DESCRIPTION_CATEGORY",
            BiosEventType::DescriptionAbstract => "DESCRIPTION_ABSTRACT",
            BiosEventType::UrlForm => "URL_FORM",
            BiosEventType::UrlJavascript => "URL_JAVASCRIPT",
            BiosEventType::UrlFlash => "URL_FLASH",
            BiosEventType::UrlWebFramework => "URL_WEB_FRAMEWORK",
            BiosEventType::UrlPassword => "URL_PASSWORD",
            BiosEventType::UrlUpload => "URL_UPLOAD",
            BiosEventType::UrlStatic => "URL_STATIC",
            BiosEventType::UrlAdblockedExternal => "URL_ADBLOCKED_EXTERNAL",
            BiosEventType::UrlAdblockedInternal => "URL_ADBLOCKED_INTERNAL",
            BiosEventType::Lei => "LEI",
            BiosEventType::NetblockWhois => "NETBLOCK_WHOIS",
            BiosEventType::AffiliateDomainWhois => "AFFILIATE_DOMAIN_WHOIS",
            BiosEventType::CoHostedSiteDomainWhois => "CO_HOSTED_SITE_DOMAIN_WHOIS",
            BiosEventType::SimilarDomainWhois => "SIMILAR_DOMAIN_WHOIS",
            BiosEventType::AffiliateInternetNameUnresolved => "AFFILIATE_INTERNET_NAME_UNRESOLVED",
            BiosEventType::AffiliateInternetNameHijackable => "AFFILIATE_INTERNET_NAME_HIJACKABLE",
            BiosEventType::AffiliateDescriptionCategory => "AFFILIATE_DESCRIPTION_CATEGORY",
            BiosEventType::AffiliateDescriptionAbstract => "AFFILIATE_DESCRIPTION_ABSTRACT",
            BiosEventType::DarknetMention => "DARKNET_MENTION",
            BiosEventType::PhishingUrl => "PHISHING_URL",
            BiosEventType::Custom(name) => name,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ROOT" => Some(BiosEventType::Root),
            "IP_ADDRESS" => Some(BiosEventType::IpAddress),
            "IPV6_ADDRESS" => Some(BiosEventType::Ipv6Address),
            "NETBLOCK_OWNER" => Some(BiosEventType::NetblockOwner),
            "NETBLOCKV6_OWNER" => Some(BiosEventType::NetblockV6Owner),
            "INTERNET_NAME" => Some(BiosEventType::InternetName),
            "DOMAIN_NAME" => Some(BiosEventType::DomainName),
            "DOMAIN_NAME_PARENT" => Some(BiosEventType::DomainNameParent),
            "DOMAIN_REGISTRAR" => Some(BiosEventType::DomainRegistrar),
            "DOMAIN_WHOIS" => Some(BiosEventType::DomainWhois),
            "EMAILADDR" => Some(BiosEventType::EmailAddr),
            "EMAILADDR_COMPROMISED" => Some(BiosEventType::EmailAddrCompromised),
            "EMAILADDR_DELIVERABLE" => Some(BiosEventType::EmailAddrDeliverable),
            "EMAILADDR_DISPOSABLE" => Some(BiosEventType::EmailAddrDisposable),
            "EMAILADDR_GENERIC" => Some(BiosEventType::EmailAddrGeneric),
            "EMAILADDR_UNDELIVERABLE" => Some(BiosEventType::EmailAddrUndeliverable),
            "HUMAN_NAME" => Some(BiosEventType::HumanName),
            "PHONE_NUMBER" => Some(BiosEventType::PhoneNumber),
            "PHONE_NUMBER_COMPROMISED" => Some(BiosEventType::PhoneNumberCompromised),
            "USERNAME" => Some(BiosEventType::Username),
            "BITCOIN_ADDRESS" => Some(BiosEventType::BitcoinAddress),
            "ETHEREUM_ADDRESS" => Some(BiosEventType::EthereumAddress),
            "COMPANY_NAME" => Some(BiosEventType::CompanyName),
            "PHYSICAL_ADDRESS" => Some(BiosEventType::PhysicalAddress),
            "PHYSICAL_COORDINATES" => Some(BiosEventType::PhysicalCoordinates),
            "COUNTRY_NAME" => Some(BiosEventType::CountryName),
            "GEOINFO" => Some(BiosEventType::GeoInfo),
            "BGP_AS_OWNER" => Some(BiosEventType::BgpAsOwner),
            "BGP_AS_MEMBER" => Some(BiosEventType::BgpAsMember),
            "AFFILIATE_EMAILADDR" => Some(BiosEventType::AffiliateEmailAddr),
            "AFFILIATE_INTERNET_NAME" => Some(BiosEventType::AffiliateInternetName),
            "AFFILIATE_IPADDR" => Some(BiosEventType::AffiliateIpAddress),
            "AFFILIATE_DOMAIN_NAME" => Some(BiosEventType::AffiliateDomainName),
            "AFFILIATE_COMPANY_NAME" => Some(BiosEventType::AffiliateCompanyName),
            "CO_HOSTED_SITE" => Some(BiosEventType::CoHostedSite),
            "CO_HOSTED_SITE_DOMAIN" => Some(BiosEventType::CoHostedSiteDomain),
            "ACCOUNT_EXTERNAL_OWNED" => Some(BiosEventType::AccountExternalOwned),
            "ACCOUNT_EXTERNAL_OWNED_COMPROMISED" => Some(BiosEventType::AccountExternalOwnedCompromised),
            "SOCIAL_MEDIA" => Some(BiosEventType::SocialMedia),
            "SIMILARDOMAIN" => Some(BiosEventType::SimilarDomain),
            "SIMILAR_ACCOUNT_EXTERNAL" => Some(BiosEventType::SimilarAccountExternal),
            "PUBLIC_CODE_REPO" => Some(BiosEventType::PublicCodeRepo),
            "APPSTORE_ENTRY" => Some(BiosEventType::AppStoreEntry),
            "CLOUD_STORAGE_BUCKET" => Some(BiosEventType::CloudStorageBucket),
            "CLOUD_STORAGE_BUCKET_OPEN" => Some(BiosEventType::CloudStorageBucketOpen),
            "PROVIDER_DNS" => Some(BiosEventType::ProviderDns),
            "PROVIDER_MAIL" => Some(BiosEventType::ProviderMail),
            "PROVIDER_HOSTING" => Some(BiosEventType::ProviderHosting),
            "PROVIDER_JAVASCRIPT" => Some(BiosEventType::ProviderJavascript),
            "SSL_CERTIFICATE_RAW" => Some(BiosEventType::SslCertificateRaw),
            "SSL_CERTIFICATE_ISSUED" => Some(BiosEventType::SslCertificateIssued),
            "SSL_CERTIFICATE_ISSUER" => Some(BiosEventType::SslCertificateIssuer),
            "SSL_CERTIFICATE_EXPIRED" => Some(BiosEventType::SslCertificateExpired),
            "SSL_CERTIFICATE_MISMATCH" => Some(BiosEventType::SslCertificateMismatch),
            "SSL_CERTIFICATE_EXPIRING" => Some(BiosEventType::SslCertificateExpiring),
            "DNS_TEXT" => Some(BiosEventType::DnsText),
            "DNS_SRV" => Some(BiosEventType::DnsSrv),
            "DNS_SPF" => Some(BiosEventType::DnsSpf),
            "RAW_DNS_RECORDS" => Some(BiosEventType::RawDnsRecords),
            "RAW_RIR_DATA" => Some(BiosEventType::RawRirData),
            "RAW_FILE_META_DATA" => Some(BiosEventType::RawFileMetaData),
            "TCP_PORT_OPEN" => Some(BiosEventType::TcpPortOpen),
            "TCP_PORT_OPEN_BANNER" => Some(BiosEventType::TcpPortOpenBanner),
            "UDP_PORT_OPEN" => Some(BiosEventType::UdpPortOpen),
            "OPERATING_SYSTEM" => Some(BiosEventType::OperatingSystem),
            "DEVICE_TYPE" => Some(BiosEventType::DeviceType),
            "WEBSERVER_BANNER" => Some(BiosEventType::WebServerBanner),
            "WEBSERVER_HTTPHEADERS" => Some(BiosEventType::WebServerHttpHeaders),
            "WEBSERVER_STRANGEHEADER" => Some(BiosEventType::WebServerStrangeHeader),
            "WEBSERVER_TECHNOLOGY" => Some(BiosEventType::WebServerTechnology),
            "WEB_ANALYTICS_ID" => Some(BiosEventType::WebAnalyticsId),
            "LINKED_URL_INTERNAL" => Some(BiosEventType::LinkedUrlInternal),
            "LINKED_URL_EXTERNAL" => Some(BiosEventType::LinkedUrlExternal),
            "TARGET_WEB_CONTENT" => Some(BiosEventType::TargetWebContent),
            "TARGET_WEB_CONTENT_TYPE" => Some(BiosEventType::TargetWebContentType),
            "TARGET_WEB_COOKIE" => Some(BiosEventType::TargetWebCookie),
            "HTTP_CODE" => Some(BiosEventType::HttpCode),
            "DARKNET_MENTION_URL" => Some(BiosEventType::DarknetMentionUrl),
            "DARKNET_MENTION_CONTENT" => Some(BiosEventType::DarknetMentionContent),
            "LEAKSITE_URL" => Some(BiosEventType::LeakSiteUrl),
            "LEAKSITE_CONTENT" => Some(BiosEventType::LeakSiteContent),
            "MALICIOUS_IPADDR" => Some(BiosEventType::MaliciousIpAddress),
            "MALICIOUS_INTERNET_NAME" => Some(BiosEventType::MaliciousInternetName),
            "MALICIOUS_EMAILADDR" => Some(BiosEventType::MaliciousEmailAddr),
            "MALICIOUS_COHOST" => Some(BiosEventType::MaliciousCoHost),
            "MALICIOUS_AFFILIATE_INTERNET_NAME" => Some(BiosEventType::MaliciousAffiliateInternetName),
            "MALICIOUS_AFFILIATE_IPADDR" => Some(BiosEventType::MaliciousAffiliateIpAddress),
            "MALICIOUS_SUBNET" => Some(BiosEventType::MaliciousSubnet),
            "MALICIOUS_NETBLOCK" => Some(BiosEventType::MaliciousNetblock),
            "MALICIOUS_ASN" => Some(BiosEventType::MaliciousAsn),
            "MALICIOUS_BITCOIN_ADDRESS" => Some(BiosEventType::MaliciousBitcoinAddress),
            "BLACKLISTED_IPADDR" => Some(BiosEventType::BlacklistedIpAddress),
            "BLACKLISTED_INTERNET_NAME" => Some(BiosEventType::BlacklistedInternetName),
            "BLACKLISTED_COHOST" => Some(BiosEventType::BlacklistedCoHost),
            "BLACKLISTED_SUBNET" => Some(BiosEventType::BlacklistedSubnet),
            "BLACKLISTED_NETBLOCK" => Some(BiosEventType::BlacklistedNetblock),
            "VULNERABILITY_CVE_CRITICAL" => Some(BiosEventType::VulnerabilityCveCritical),
            "VULNERABILITY_CVE_HIGH" => Some(BiosEventType::VulnerabilityCveHigh),
            "VULNERABILITY_CVE_MEDIUM" => Some(BiosEventType::VulnerabilityCveMedium),
            "VULNERABILITY_CVE_LOW" => Some(BiosEventType::VulnerabilityCveLow),
            "VULNERABILITY_GENERAL" => Some(BiosEventType::VulnerabilityGeneral),
            "VULNERABILITY_DISCLOSURE" => Some(BiosEventType::VulnerabilityDisclosure),
            "DEFACED_INTERNET_NAME" => Some(BiosEventType::DefacedInternetName),
            "DEFACED_IPADDR" => Some(BiosEventType::DefacedIpAddress),
            "DATABASE_EXPOSED" => Some(BiosEventType::DatabaseExposed),
            "REMOTE_DESKTOP_EXPOSED" => Some(BiosEventType::RemoteDesktopExposed),
            "DNS_ZONE_TRANSFER_POSSIBLE" => Some(BiosEventType::DnsZoneTransferPossible),
            "INTERNAL_IP_ADDRESS" => Some(BiosEventType::InternalIpAddress),
            "PROXY_HOST" => Some(BiosEventType::ProxyHost),
            "VPN_HOST" => Some(BiosEventType::VpnHost),
            "TOR_EXIT_NODE" => Some(BiosEventType::TorExitNode),
            "INTERESTING_FILE" => Some(BiosEventType::InterestingFile),
            "JUNK_FILE" => Some(BiosEventType::JunkFile),
            "PASSWORD_COMPROMISED" => Some(BiosEventType::PasswordCompromised),
            "HASH_COMPROMISED" => Some(BiosEventType::HashCompromised),
            "CREDIT_CARD_NUMBER" => Some(BiosEventType::CreditCardNumber),
            "IBAN_NUMBER" => Some(BiosEventType::IbanNumber),
            "PGP_KEY" => Some(BiosEventType::PgpKey),
            "JOB_TITLE" => Some(BiosEventType::JobTitle),
            "DATE_HUMAN_DOB" => Some(BiosEventType::DateHumanDob),
            "SOFTWARE_USED" => Some(BiosEventType::SoftwareUsed),
            "WIFI_ACCESS_POINT" => Some(BiosEventType::WifiAccessPoint),
            "SEARCH_ENGINE_WEB_CONTENT" => Some(BiosEventType::SearchEngineWebContent),
            "ERROR" => Some(BiosEventType::Error),
            "BASE64_DATA" => Some(BiosEventType::Base64Data),
            "HASH" => Some(BiosEventType::Hash),
            "DESCRIPTION_CATEGORY" => Some(BiosEventType::DescriptionCategory),
            "DESCRIPTION_ABSTRACT" => Some(BiosEventType::DescriptionAbstract),
            "URL_FORM" => Some(BiosEventType::UrlForm),
            "URL_JAVASCRIPT" => Some(BiosEventType::UrlJavascript),
            "URL_FLASH" => Some(BiosEventType::UrlFlash),
            "URL_WEB_FRAMEWORK" => Some(BiosEventType::UrlWebFramework),
            "URL_PASSWORD" => Some(BiosEventType::UrlPassword),
            "URL_UPLOAD" => Some(BiosEventType::UrlUpload),
            "URL_STATIC" => Some(BiosEventType::UrlStatic),
            "URL_ADBLOCKED_EXTERNAL" => Some(BiosEventType::UrlAdblockedExternal),
            "URL_ADBLOCKED_INTERNAL" => Some(BiosEventType::UrlAdblockedInternal),
            "LEI" => Some(BiosEventType::Lei),
            "NETBLOCK_WHOIS" => Some(BiosEventType::NetblockWhois),
            "AFFILIATE_DOMAIN_WHOIS" => Some(BiosEventType::AffiliateDomainWhois),
            "CO_HOSTED_SITE_DOMAIN_WHOIS" => Some(BiosEventType::CoHostedSiteDomainWhois),
            "SIMILAR_DOMAIN_WHOIS" => Some(BiosEventType::SimilarDomainWhois),
            "AFFILIATE_INTERNET_NAME_UNRESOLVED" => Some(BiosEventType::AffiliateInternetNameUnresolved),
            "AFFILIATE_INTERNET_NAME_HIJACKABLE" => Some(BiosEventType::AffiliateInternetNameHijackable),
            "AFFILIATE_DESCRIPTION_CATEGORY" => Some(BiosEventType::AffiliateDescriptionCategory),
            "AFFILIATE_DESCRIPTION_ABSTRACT" => Some(BiosEventType::AffiliateDescriptionAbstract),
            "DARKNET_MENTION" => Some(BiosEventType::DarknetMention),
            "PHISHING_URL" => Some(BiosEventType::PhishingUrl),
            _ => Some(BiosEventType::Custom(s.to_string())),
        }
    }

    pub fn matches_pattern(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        let self_str = self.as_str();
        if let Some(prefix) = pattern.strip_suffix('*') {
            self_str.starts_with(prefix)
        } else {
            self_str == pattern
        }
    }
}

impl fmt::Display for BiosEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl BiosEventType {
    pub fn description(&self) -> &'static str {
        match self {
            BiosEventType::Root => "Root event for a scan",
            BiosEventType::IpAddress => "IPv4 Address",
            BiosEventType::Ipv6Address => "IPv6 Address",
            BiosEventType::NetblockOwner => "Netblock Owner (CIDR)",
            BiosEventType::NetblockV6Owner => "IPv6 Netblock Owner (CIDR)",
            BiosEventType::InternetName => "Internet Name (Host/Domain)",
            BiosEventType::DomainName => "Domain Name",
            BiosEventType::DomainNameParent => "Parent Domain Name",
            BiosEventType::DomainRegistrar => "Domain Registrar",
            BiosEventType::DomainWhois => "Domain WHOIS Data",
            BiosEventType::EmailAddr => "Email Address",
            BiosEventType::EmailAddrCompromised => "Compromised Email Address",
            BiosEventType::EmailAddrDeliverable => "Deliverable Email Address",
            BiosEventType::EmailAddrDisposable => "Disposable Email Address",
            BiosEventType::EmailAddrGeneric => "Generic Email Address (role-based)",
            BiosEventType::EmailAddrUndeliverable => "Undeliverable Email Address",
            BiosEventType::HumanName => "Human Name",
            BiosEventType::PhoneNumber => "Phone Number",
            BiosEventType::PhoneNumberCompromised => "Compromised Phone Number",
            BiosEventType::Username => "Username",
            BiosEventType::BitcoinAddress => "Bitcoin Address",
            BiosEventType::EthereumAddress => "Ethereum Address",
            BiosEventType::CompanyName => "Company Name",
            BiosEventType::PhysicalAddress => "Physical Address",
            BiosEventType::PhysicalCoordinates => "Physical Coordinates",
            BiosEventType::CountryName => "Country Name",
            BiosEventType::GeoInfo => "Geolocation Information",
            BiosEventType::BgpAsOwner => "BGP AS Owner",
            BiosEventType::BgpAsMember => "BGP AS Member",
            BiosEventType::AffiliateEmailAddr => "Affiliate Email Address",
            BiosEventType::AffiliateInternetName => "Affiliate Internet Name",
            BiosEventType::AffiliateIpAddress => "Affiliate IP Address",
            BiosEventType::AffiliateDomainName => "Affiliate Domain Name",
            BiosEventType::AffiliateCompanyName => "Affiliate Company Name",
            BiosEventType::CoHostedSite => "Co-Hosted Site",
            BiosEventType::CoHostedSiteDomain => "Co-Hosted Site Domain",
            BiosEventType::AccountExternalOwned => "Externally Owned Account",
            BiosEventType::AccountExternalOwnedCompromised => "Compromised Externally Owned Account",
            BiosEventType::SocialMedia => "Social Media Profile",
            BiosEventType::SimilarDomain => "Similar Domain",
            BiosEventType::SimilarAccountExternal => "Similar External Account",
            BiosEventType::PublicCodeRepo => "Public Code Repository",
            BiosEventType::AppStoreEntry => "App Store Entry",
            BiosEventType::CloudStorageBucket => "Cloud Storage Bucket",
            BiosEventType::CloudStorageBucketOpen => "Open Cloud Storage Bucket",
            BiosEventType::ProviderDns => "DNS Provider",
            BiosEventType::ProviderMail => "Mail Provider",
            BiosEventType::ProviderHosting => "Hosting Provider",
            BiosEventType::ProviderJavascript => "JavaScript Provider",
            BiosEventType::SslCertificateRaw => "Raw SSL Certificate",
            BiosEventType::SslCertificateIssued => "SSL Certificate Issued To",
            BiosEventType::SslCertificateIssuer => "SSL Certificate Issuer",
            BiosEventType::SslCertificateExpired => "Expired SSL Certificate",
            BiosEventType::SslCertificateMismatch => "SSL Certificate Mismatch",
            BiosEventType::SslCertificateExpiring => "Expiring SSL Certificate",
            BiosEventType::DnsText => "DNS TXT Record",
            BiosEventType::DnsSrv => "DNS SRV Record",
            BiosEventType::DnsSpf => "DNS SPF Record",
            BiosEventType::RawDnsRecords => "Raw DNS Records",
            BiosEventType::RawRirData => "Raw RIR Data",
            BiosEventType::RawFileMetaData => "Raw File Metadata",
            BiosEventType::TcpPortOpen => "Open TCP Port",
            BiosEventType::TcpPortOpenBanner => "TCP Port Banner",
            BiosEventType::UdpPortOpen => "Open UDP Port",
            BiosEventType::OperatingSystem => "Operating System",
            BiosEventType::DeviceType => "Device Type",
            BiosEventType::WebServerBanner => "Web Server Banner",
            BiosEventType::WebServerHttpHeaders => "Web Server HTTP Headers",
            BiosEventType::WebServerStrangeHeader => "Strange Web Server Header",
            BiosEventType::WebServerTechnology => "Web Server Technology",
            BiosEventType::WebAnalyticsId => "Web Analytics ID",
            BiosEventType::LinkedUrlInternal => "Internal Linked URL",
            BiosEventType::LinkedUrlExternal => "External Linked URL",
            BiosEventType::TargetWebContent => "Target Web Content",
            BiosEventType::TargetWebContentType => "Target Web Content Type",
            BiosEventType::TargetWebCookie => "Target Web Cookie",
            BiosEventType::HttpCode => "HTTP Response Code",
            BiosEventType::DarknetMentionUrl => "Darknet Mention URL",
            BiosEventType::DarknetMentionContent => "Darknet Mention Content",
            BiosEventType::LeakSiteUrl => "Leak Site URL",
            BiosEventType::LeakSiteContent => "Leak Site Content",
            BiosEventType::MaliciousIpAddress => "Malicious IP Address",
            BiosEventType::MaliciousInternetName => "Malicious Internet Name",
            BiosEventType::MaliciousEmailAddr => "Malicious Email Address",
            BiosEventType::MaliciousCoHost => "Malicious Co-Host",
            BiosEventType::MaliciousAffiliateInternetName => "Malicious Affiliate Internet Name",
            BiosEventType::MaliciousAffiliateIpAddress => "Malicious Affiliate IP Address",
            BiosEventType::MaliciousSubnet => "Malicious Subnet",
            BiosEventType::MaliciousNetblock => "Malicious Netblock",
            BiosEventType::MaliciousAsn => "Malicious ASN",
            BiosEventType::MaliciousBitcoinAddress => "Malicious Bitcoin Address",
            BiosEventType::BlacklistedIpAddress => "Blacklisted IP Address",
            BiosEventType::BlacklistedInternetName => "Blacklisted Internet Name",
            BiosEventType::BlacklistedCoHost => "Blacklisted Co-Host",
            BiosEventType::BlacklistedSubnet => "Blacklisted Subnet",
            BiosEventType::BlacklistedNetblock => "Blacklisted Netblock",
            BiosEventType::VulnerabilityCveCritical => "Critical CVE Vulnerability",
            BiosEventType::VulnerabilityCveHigh => "High CVE Vulnerability",
            BiosEventType::VulnerabilityCveMedium => "Medium CVE Vulnerability",
            BiosEventType::VulnerabilityCveLow => "Low CVE Vulnerability",
            BiosEventType::VulnerabilityGeneral => "General Vulnerability",
            BiosEventType::VulnerabilityDisclosure => "Vulnerability Disclosure",
            BiosEventType::DefacedInternetName => "Defaced Internet Name",
            BiosEventType::DefacedIpAddress => "Defaced IP Address",
            BiosEventType::DatabaseExposed => "Exposed Database",
            BiosEventType::RemoteDesktopExposed => "Exposed Remote Desktop",
            BiosEventType::DnsZoneTransferPossible => "DNS Zone Transfer Possible",
            BiosEventType::InternalIpAddress => "Internal IP Address",
            BiosEventType::ProxyHost => "Proxy Host",
            BiosEventType::VpnHost => "VPN Host",
            BiosEventType::TorExitNode => "Tor Exit Node",
            BiosEventType::InterestingFile => "Interesting File",
            BiosEventType::JunkFile => "Junk File",
            BiosEventType::PasswordCompromised => "Compromised Password",
            BiosEventType::HashCompromised => "Compromised Hash",
            BiosEventType::CreditCardNumber => "Credit Card Number",
            BiosEventType::IbanNumber => "IBAN Number",
            BiosEventType::PgpKey => "PGP Key",
            BiosEventType::JobTitle => "Job Title",
            BiosEventType::DateHumanDob => "Date of Birth",
            BiosEventType::SoftwareUsed => "Software Used",
            BiosEventType::WifiAccessPoint => "WiFi Access Point",
            BiosEventType::SearchEngineWebContent => "Search Engine Web Content",
            BiosEventType::Error => "Error",
            BiosEventType::Base64Data => "Base64 Encoded Data",
            BiosEventType::Hash => "Hash Value",
            BiosEventType::DescriptionCategory => "Description Category",
            BiosEventType::DescriptionAbstract => "Description Abstract",
            BiosEventType::UrlForm => "URL Form",
            BiosEventType::UrlJavascript => "URL JavaScript",
            BiosEventType::UrlFlash => "URL Flash",
            BiosEventType::UrlWebFramework => "URL Web Framework",
            BiosEventType::UrlPassword => "URL Password Reset",
            BiosEventType::UrlUpload => "URL Upload",
            BiosEventType::UrlStatic => "URL Static",
            BiosEventType::UrlAdblockedExternal => "Adblocked External URL",
            BiosEventType::UrlAdblockedInternal => "Adblocked Internal URL",
            BiosEventType::Lei => "Legal Entity Identifier",
            BiosEventType::NetblockWhois => "Netblock WHOIS Data",
            BiosEventType::AffiliateDomainWhois => "Affiliate Domain WHOIS",
            BiosEventType::CoHostedSiteDomainWhois => "Co-Hosted Site Domain WHOIS",
            BiosEventType::SimilarDomainWhois => "Similar Domain WHOIS",
            BiosEventType::AffiliateInternetNameUnresolved => "Unresolved Affiliate Internet Name",
            BiosEventType::AffiliateInternetNameHijackable => "Hijackable Affiliate Internet Name",
            BiosEventType::AffiliateDescriptionCategory => "Affiliate Description Category",
            BiosEventType::AffiliateDescriptionAbstract => "Affiliate Description Abstract",
            BiosEventType::DarknetMention => "Darknet Mention",
            BiosEventType::PhishingUrl => "Phishing URL",
            BiosEventType::Custom(_) => "Custom Event Type",
        }
    }

    pub fn all_standard_types() -> Vec<BiosEventType> {
        vec![
            BiosEventType::Root,
            BiosEventType::IpAddress,
            BiosEventType::Ipv6Address,
            BiosEventType::NetblockOwner,
            BiosEventType::NetblockV6Owner,
            BiosEventType::InternetName,
            BiosEventType::DomainName,
            BiosEventType::DomainNameParent,
            BiosEventType::DomainRegistrar,
            BiosEventType::DomainWhois,
            BiosEventType::EmailAddr,
            BiosEventType::EmailAddrCompromised,
            BiosEventType::EmailAddrDeliverable,
            BiosEventType::EmailAddrDisposable,
            BiosEventType::EmailAddrGeneric,
            BiosEventType::EmailAddrUndeliverable,
            BiosEventType::HumanName,
            BiosEventType::PhoneNumber,
            BiosEventType::PhoneNumberCompromised,
            BiosEventType::Username,
            BiosEventType::BitcoinAddress,
            BiosEventType::EthereumAddress,
            BiosEventType::CompanyName,
            BiosEventType::PhysicalAddress,
            BiosEventType::PhysicalCoordinates,
            BiosEventType::CountryName,
            BiosEventType::GeoInfo,
            BiosEventType::BgpAsOwner,
            BiosEventType::BgpAsMember,
            BiosEventType::AffiliateEmailAddr,
            BiosEventType::AffiliateInternetName,
            BiosEventType::AffiliateIpAddress,
            BiosEventType::AffiliateDomainName,
            BiosEventType::AffiliateCompanyName,
            BiosEventType::CoHostedSite,
            BiosEventType::CoHostedSiteDomain,
            BiosEventType::AccountExternalOwned,
            BiosEventType::AccountExternalOwnedCompromised,
            BiosEventType::SocialMedia,
            BiosEventType::SimilarDomain,
            BiosEventType::SimilarAccountExternal,
            BiosEventType::PublicCodeRepo,
            BiosEventType::AppStoreEntry,
            BiosEventType::CloudStorageBucket,
            BiosEventType::CloudStorageBucketOpen,
            BiosEventType::ProviderDns,
            BiosEventType::ProviderMail,
            BiosEventType::ProviderHosting,
            BiosEventType::ProviderJavascript,
            BiosEventType::SslCertificateRaw,
            BiosEventType::SslCertificateIssued,
            BiosEventType::SslCertificateIssuer,
            BiosEventType::SslCertificateExpired,
            BiosEventType::SslCertificateMismatch,
            BiosEventType::SslCertificateExpiring,
            BiosEventType::DnsText,
            BiosEventType::DnsSrv,
            BiosEventType::DnsSpf,
            BiosEventType::RawDnsRecords,
            BiosEventType::RawRirData,
            BiosEventType::RawFileMetaData,
            BiosEventType::TcpPortOpen,
            BiosEventType::TcpPortOpenBanner,
            BiosEventType::UdpPortOpen,
            BiosEventType::OperatingSystem,
            BiosEventType::DeviceType,
            BiosEventType::WebServerBanner,
            BiosEventType::WebServerHttpHeaders,
            BiosEventType::WebServerStrangeHeader,
            BiosEventType::WebServerTechnology,
            BiosEventType::WebAnalyticsId,
            BiosEventType::LinkedUrlInternal,
            BiosEventType::LinkedUrlExternal,
            BiosEventType::TargetWebContent,
            BiosEventType::TargetWebContentType,
            BiosEventType::TargetWebCookie,
            BiosEventType::HttpCode,
            BiosEventType::DarknetMentionUrl,
            BiosEventType::DarknetMentionContent,
            BiosEventType::LeakSiteUrl,
            BiosEventType::LeakSiteContent,
            BiosEventType::MaliciousIpAddress,
            BiosEventType::MaliciousInternetName,
            BiosEventType::MaliciousEmailAddr,
            BiosEventType::MaliciousCoHost,
            BiosEventType::MaliciousAffiliateInternetName,
            BiosEventType::MaliciousAffiliateIpAddress,
            BiosEventType::MaliciousSubnet,
            BiosEventType::MaliciousNetblock,
            BiosEventType::MaliciousAsn,
            BiosEventType::MaliciousBitcoinAddress,
            BiosEventType::BlacklistedIpAddress,
            BiosEventType::BlacklistedInternetName,
            BiosEventType::BlacklistedCoHost,
            BiosEventType::BlacklistedSubnet,
            BiosEventType::BlacklistedNetblock,
            BiosEventType::VulnerabilityCveCritical,
            BiosEventType::VulnerabilityCveHigh,
            BiosEventType::VulnerabilityCveMedium,
            BiosEventType::VulnerabilityCveLow,
            BiosEventType::VulnerabilityGeneral,
            BiosEventType::VulnerabilityDisclosure,
            BiosEventType::DefacedInternetName,
            BiosEventType::DefacedIpAddress,
            BiosEventType::DatabaseExposed,
            BiosEventType::RemoteDesktopExposed,
            BiosEventType::DnsZoneTransferPossible,
            BiosEventType::InternalIpAddress,
            BiosEventType::ProxyHost,
            BiosEventType::VpnHost,
            BiosEventType::TorExitNode,
            BiosEventType::InterestingFile,
            BiosEventType::JunkFile,
            BiosEventType::PasswordCompromised,
            BiosEventType::HashCompromised,
            BiosEventType::CreditCardNumber,
            BiosEventType::IbanNumber,
            BiosEventType::PgpKey,
            BiosEventType::JobTitle,
            BiosEventType::DateHumanDob,
            BiosEventType::SoftwareUsed,
            BiosEventType::WifiAccessPoint,
            BiosEventType::SearchEngineWebContent,
            BiosEventType::Error,
            BiosEventType::Base64Data,
            BiosEventType::Hash,
            BiosEventType::DescriptionCategory,
            BiosEventType::DescriptionAbstract,
            BiosEventType::UrlForm,
            BiosEventType::UrlJavascript,
            BiosEventType::UrlFlash,
            BiosEventType::UrlWebFramework,
            BiosEventType::UrlPassword,
            BiosEventType::UrlUpload,
            BiosEventType::UrlStatic,
            BiosEventType::UrlAdblockedExternal,
            BiosEventType::UrlAdblockedInternal,
            BiosEventType::Lei,
            BiosEventType::NetblockWhois,
            BiosEventType::AffiliateDomainWhois,
            BiosEventType::CoHostedSiteDomainWhois,
            BiosEventType::SimilarDomainWhois,
            BiosEventType::AffiliateInternetNameUnresolved,
            BiosEventType::AffiliateInternetNameHijackable,
            BiosEventType::AffiliateDescriptionCategory,
            BiosEventType::AffiliateDescriptionAbstract,
            BiosEventType::DarknetMention,
            BiosEventType::PhishingUrl,
        ]
    }

    pub fn is_raw(&self) -> bool {
        matches!(
            self,
            BiosEventType::TargetWebContent
                | BiosEventType::RawDnsRecords
                | BiosEventType::RawRirData
                | BiosEventType::RawFileMetaData
                | BiosEventType::SslCertificateRaw
                | BiosEventType::DnsText
                | BiosEventType::DnsSrv
                | BiosEventType::DnsSpf
                | BiosEventType::Base64Data
                | BiosEventType::DomainWhois
                | BiosEventType::NetblockWhois
                | BiosEventType::AffiliateDomainWhois
                | BiosEventType::CoHostedSiteDomainWhois
                | BiosEventType::SimilarDomainWhois
                | BiosEventType::SearchEngineWebContent
                | BiosEventType::DarknetMentionContent
                | BiosEventType::LeakSiteContent
        )
    }

    pub fn is_sensitive(&self) -> bool {
        matches!(
            self,
            BiosEventType::PasswordCompromised
                | BiosEventType::HashCompromised
                | BiosEventType::CreditCardNumber
                | BiosEventType::IbanNumber
                | BiosEventType::EmailAddrCompromised
                | BiosEventType::PhoneNumberCompromised
                | BiosEventType::AccountExternalOwnedCompromised
                | BiosEventType::DatabaseExposed
                | BiosEventType::DarknetMentionContent
                | BiosEventType::LeakSiteContent
                | BiosEventType::UrlPassword
        )
    }

    pub fn risk_level(&self) -> &'static str {
        match self {
            BiosEventType::VulnerabilityCveCritical | BiosEventType::DatabaseExposed => "critical",
            BiosEventType::VulnerabilityCveHigh
            | BiosEventType::MaliciousIpAddress
            | BiosEventType::MaliciousInternetName
            | BiosEventType::MaliciousEmailAddr
            | BiosEventType::MaliciousCoHost
            | BiosEventType::MaliciousAffiliateInternetName
            | BiosEventType::MaliciousAffiliateIpAddress
            | BiosEventType::MaliciousSubnet
            | BiosEventType::MaliciousNetblock
            | BiosEventType::MaliciousAsn
            | BiosEventType::MaliciousBitcoinAddress
            | BiosEventType::DefacedInternetName
            | BiosEventType::DefacedIpAddress
            | BiosEventType::PhishingUrl
            | BiosEventType::PasswordCompromised
            | BiosEventType::HashCompromised
            | BiosEventType::CreditCardNumber
            | BiosEventType::IbanNumber
            | BiosEventType::DnsZoneTransferPossible
            | BiosEventType::CloudStorageBucketOpen => "high",
            BiosEventType::VulnerabilityCveMedium
            | BiosEventType::BlacklistedIpAddress
            | BiosEventType::BlacklistedInternetName
            | BiosEventType::BlacklistedCoHost
            | BiosEventType::BlacklistedSubnet
            | BiosEventType::BlacklistedNetblock
            | BiosEventType::SslCertificateExpired
            | BiosEventType::SslCertificateMismatch
            | BiosEventType::RemoteDesktopExposed
            | BiosEventType::TorExitNode
            | BiosEventType::EmailAddrCompromised
            | BiosEventType::PhoneNumberCompromised
            | BiosEventType::AccountExternalOwnedCompromised
            | BiosEventType::SslCertificateExpiring => "medium",
            BiosEventType::VulnerabilityCveLow
            | BiosEventType::VulnerabilityGeneral
            | BiosEventType::InternalIpAddress
            | BiosEventType::ProxyHost
            | BiosEventType::VpnHost => "low",
            _ => "info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTypeMeta {
    pub event: String,
    pub description: String,
    pub is_raw: bool,
    pub is_sensitive: bool,
    pub category: String,
    pub risk_level: String,
}

impl From<&BiosEventType> for EventTypeMeta {
    fn from(et: &BiosEventType) -> Self {
        Self {
            event: et.as_str().to_string(),
            description: et.description().to_string(),
            is_raw: et.is_raw(),
            is_sensitive: et.is_sensitive(),
            category: et.category().to_string(),
            risk_level: et.risk_level().to_string(),
        }
    }
}
