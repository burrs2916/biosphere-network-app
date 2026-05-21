use crate::core::{Result, ToolError};
use super::config::{SubdomainConfig, SubdomainResult, SubdomainEntry, SubdomainCategory, QUICK_WORDLIST, NORMAL_WORDLIST, DEEP_WORDLIST};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Semaphore;

pub struct SubdomainEnumTool;

impl SubdomainEnumTool {
    pub async fn enumerate(config: &SubdomainConfig) -> Result<SubdomainResult> {
        let domain = config.domain.trim().to_string();
        if domain.is_empty() {
            return Err(ToolError::ExecutionError("Domain is empty".to_string()));
        }

        let start = std::time::Instant::now();
        let mut subdomains: Vec<SubdomainEntry> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut sources_used: Vec<String> = Vec::new();

        if config.use_certificate_transparency {
            match Self::query_ct_logs(&domain).await {
                Ok(entries) => {
                    sources_used.push("Certificate Transparency".to_string());
                    for entry in entries {
                        if seen.insert(entry.subdomain.clone()) {
                            subdomains.push(entry);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("CT log query failed: {}", e);
                }
            }
        }

        if config.use_dns_bruteforce {
            let wordlist = Self::get_wordlist(&config.scan_mode, &config.wordlist);
            let brute_results = Self::dns_bruteforce(&domain, &wordlist, config.threads).await;
            sources_used.push("DNS Bruteforce".to_string());
            for entry in brute_results {
                if seen.insert(entry.subdomain.clone()) {
                    subdomains.push(entry);
                }
            }
        }

        for entry in &mut subdomains {
            let category = Self::classify_subdomain(&entry.subdomain);
            entry.category = category;
        }

        if config.use_http_probe {
            Self::http_probe(&mut subdomains, config.timeout).await;
            sources_used.push("HTTP Probe".to_string());
        }

        subdomains.sort_by(|a, b| a.subdomain.cmp(&b.subdomain));

        let alive_count = subdomains.iter().filter(|s| s.is_alive).count();
        let dead_count = subdomains.len() - alive_count;
        let total_found = subdomains.len();

        let categories = Self::build_categories(&subdomains);

        let duration = start.elapsed();
        let summary = format!(
            "Found {} subdomains for {} (Alive: {}, Dead: {}, Sources: {}, Duration: {}ms)",
            total_found,
            domain,
            alive_count,
            dead_count,
            sources_used.join(", "),
            duration.as_millis()
        );

        Ok(SubdomainResult {
            domain,
            subdomains,
            total_found,
            alive_count,
            dead_count,
            scan_duration_ms: duration.as_millis() as u64,
            sources_used,
            summary,
            categories,
        })
    }

    fn get_wordlist(scan_mode: &str, custom_wordlist: &[String]) -> Vec<String> {
        if !custom_wordlist.is_empty() {
            return custom_wordlist.to_vec();
        }
        match scan_mode {
            "quick" => QUICK_WORDLIST.iter().map(|s| s.to_string()).collect(),
            "deep" => DEEP_WORDLIST.iter().map(|s| s.to_string()).collect(),
            _ => NORMAL_WORDLIST.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn classify_subdomain(subdomain: &str) -> String {
        let lower = subdomain.to_lowercase();
        let prefix = lower.split('.').next().unwrap_or("");

        if ["www", "www1", "www2", "www3", "web", "web1", "web2", "web3", "h5", "m", "mobile", "wap"].contains(&prefix) {
            return "Web".to_string();
        }
        if ["mail", "smtp", "pop", "pop3", "imap", "email", "mx", "mx1", "mx2", "mx3", "mx4", "mail1", "mail2", "smtp1", "smtp2", "submission", "relay"].contains(&prefix) {
            return "Mail".to_string();
        }
        if ["ns", "ns1", "ns2", "ns3", "ns4", "ns5", "dns", "dns1", "dns2", "primary", "secondary"].contains(&prefix) {
            return "DNS".to_string();
        }
        if ["cdn", "cdn1", "cdn2", "cdn3", "static", "assets", "media", "img", "images", "css", "js", "files", "edge", "edge1", "edge2", "cache", "cache1", "cache2"].contains(&prefix) {
            return "CDN/Static".to_string();
        }
        if ["api", "api1", "api2", "api3", "api-v1", "api-v2", "api-dev", "api-staging", "api-prod", "rest", "graphql", "ws", "wss", "socket", "websocket"].contains(&prefix) {
            return "API".to_string();
        }
        if ["dev", "dev1", "dev2", "dev3", "staging", "stg", "stg1", "stg2", "test", "test1", "test2", "qa", "qa1", "qa2", "uat", "beta", "alpha", "demo", "sandbox", "develop", "development", "stage", "stage1", "stage2"].contains(&prefix) {
            return "Development".to_string();
        }
        if ["prod", "prod1", "prod2", "prod3", "live", "pre", "preprod", "production", "production1", "production2"].contains(&prefix) {
            return "Production".to_string();
        }
        if ["db", "database", "mysql", "postgres", "redis", "mongo", "elastic", "clickhouse", "cassandra", "tidb", "hbase", "doris", "starrocks"].contains(&prefix) {
            return "Database".to_string();
        }
        if ["admin", "admin1", "admin2", "admin3", "panel", "cpanel", "plesk", "webmin", "adminer", "phpmyadmin", "manage", "management", "manager", "dashboard", "console", "control"].contains(&prefix) {
            return "Admin".to_string();
        }
        if ["vpn", "vpn1", "vpn2", "remote", "gateway", "proxy", "proxy1", "proxy2", "sso", "auth", "oauth", "oauth1", "oauth2", "saml", "cas", "ldap", "login"].contains(&prefix) {
            return "Security/Auth".to_string();
        }
        if ["git", "gitlab", "github", "ci", "jenkins", "build", "deploy", "registry", "repo", "repository", "npm", "maven", "argo", "flux", "helm", "rancher", "sonar", "sonarqube", "codecov"].contains(&prefix) {
            return "DevOps".to_string();
        }
        if ["monitor", "grafana", "prometheus", "kibana", "log", "status", "uptime", "health", "analytics", "tracking", "telemetry", "metrics", "stats"].contains(&prefix) {
            return "Monitoring".to_string();
        }
        if ["ftp", "sftp", "backup", "bak", "storage", "bucket", "s3", "nextcloud", "owncloud", "seafile", "minio", "download", "upload"].contains(&prefix) {
            return "Storage".to_string();
        }
        if ["shop", "store", "payment", "pay", "billing", "checkout", "order", "prestashop", "magento", "woocommerce", "shopify"].contains(&prefix) {
            return "Commerce".to_string();
        }
        if ["blog", "docs", "doc", "wiki", "wiki1", "wiki2", "help", "support", "forum", "community", "jira", "confluence", "readme", "guide", "tutorial", "manual"].contains(&prefix) {
            return "Content".to_string();
        }
        if ["internal", "intranet", "extranet", "office", "corp", "hr", "crm", "erp", "oa"].contains(&prefix) {
            return "Internal".to_string();
        }
        if ["kafka", "rabbitmq", "queue", "mq", "broker", "consul", "etcd", "zookeeper", "nacos", "eureka"].contains(&prefix) {
            return "Infrastructure".to_string();
        }
        if ["traefik", "nginx", "haproxy", "envoy", "istio", "k8s", "kubernetes", "docker", "container", "pod"].contains(&prefix) {
            return "Infrastructure".to_string();
        }
        "Other".to_string()
    }

    fn build_categories(subdomains: &[SubdomainEntry]) -> Vec<SubdomainCategory> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for entry in subdomains {
            map.entry(entry.category.clone())
                .or_default()
                .push(entry.subdomain.clone());
        }
        let mut categories: Vec<SubdomainCategory> = map
            .into_iter()
            .map(|(name, subdomains)| SubdomainCategory {
                name,
                count: subdomains.len(),
                subdomains,
            })
            .collect();
        categories.sort_by(|a, b| b.count.cmp(&a.count));
        categories
    }

    async fn query_ct_logs(domain: &str) -> Result<Vec<SubdomainEntry>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);

        let resp = client.get(&url).send().await
            .map_err(|e| ToolError::ExecutionError(format!("CT query failed: {}", e)))?;

        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        let body = resp.text().await
            .map_err(|e| ToolError::ExecutionError(format!("CT response read failed: {}", e)))?;

        let entries: Vec<serde_json::Value> = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return Ok(vec![]),
        };

        let mut names_to_resolve = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for entry in entries {
            if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
                for name in name_value.split('\n') {
                    let name = name.trim().trim_start_matches("*.").to_string();
                    if !name.is_empty() && name.ends_with(domain) && seen.insert(name.clone()) {
                        names_to_resolve.push(name);
                    }
                }
            }
        }

        let semaphore = Arc::new(Semaphore::new(20));
        let mut join_set = tokio::task::JoinSet::new();

        for name in names_to_resolve {
            let semaphore = semaphore.clone();
            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let (ipv4, ipv6) = Self::resolve_domain_async(&name).await;
                let is_alive = !ipv4.is_empty() || !ipv6.is_empty();
                SubdomainEntry {
                    subdomain: name,
                    ip_addresses: ipv4,
                    ipv6_addresses: ipv6,
                    source: "Certificate Transparency".to_string(),
                    is_alive,
                    category: String::new(),
                    http_status: None,
                    http_title: None,
                    response_time_ms: None,
                }
            });
        }

        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(entry) = result {
                results.push(entry);
            }
        }

        Ok(results)
    }

    async fn dns_bruteforce(domain: &str, wordlist: &[String], threads: usize) -> Vec<SubdomainEntry> {
        let mut join_set = tokio::task::JoinSet::new();
        let semaphore = Arc::new(Semaphore::new(threads));

        for word in wordlist {
            let subdomain = format!("{}.{}", word, domain);
            let semaphore = semaphore.clone();
            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let (ipv4, ipv6) = Self::resolve_domain_async(&subdomain).await;
                if !ipv4.is_empty() || !ipv6.is_empty() {
                    Some(SubdomainEntry {
                        subdomain,
                        ip_addresses: ipv4,
                        ipv6_addresses: ipv6,
                        source: "DNS Bruteforce".to_string(),
                        is_alive: true,
                        category: String::new(),
                        http_status: None,
                        http_title: None,
                        response_time_ms: None,
                    })
                } else {
                    None
                }
            });
        }

        let mut results = Vec::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok(Some(entry)) = result {
                results.push(entry);
            }
        }

        results
    }

    async fn http_probe(subdomains: &mut [SubdomainEntry], timeout: u64) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build();

        let client = match client {
            Ok(c) => c,
            Err(_) => return,
        };

        let semaphore = Arc::new(Semaphore::new(20));
        let mut join_set = tokio::task::JoinSet::new();

        for (idx, entry) in subdomains.iter().enumerate() {
            let subdomain = entry.subdomain.clone();
            let client = client.clone();
            let semaphore = semaphore.clone();
            join_set.spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = std::time::Instant::now();
                let url = format!("https://{}", subdomain);
                let mut result: Option<(u16, String, u64)> = None;

                match client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let title = resp.text().await.ok().and_then(|body| {
                            let lower = body.to_lowercase();
                            let start_tag = lower.find("<title>")?;
                            let end_tag = lower.find("</title>")?;
                            if end_tag > start_tag {
                                let title_content = &body[start_tag + 7..end_tag];
                                Some(title_content.trim().to_string())
                            } else {
                                None
                            }
                        });
                        let elapsed = start.elapsed().as_millis() as u64;
                        result = Some((status, title.unwrap_or_default(), elapsed));
                    }
                    Err(_) => {
                        let http_url = format!("http://{}", subdomain);
                        let start = std::time::Instant::now();
                        if let Ok(resp) = client.get(&http_url).send().await {
                            let status = resp.status().as_u16();
                            let title = resp.text().await.ok().and_then(|body| {
                                let lower = body.to_lowercase();
                                let start_tag = lower.find("<title>")?;
                                let end_tag = lower.find("</title>")?;
                                if end_tag > start_tag {
                                    let title_content = &body[start_tag + 7..end_tag];
                                    Some(title_content.trim().to_string())
                                } else {
                                    None
                                }
                            });
                            let elapsed = start.elapsed().as_millis() as u64;
                            result = Some((status, title.unwrap_or_default(), elapsed));
                        }
                    }
                }

                (idx, result)
            });
        }

        let mut probe_results: HashMap<usize, (u16, String, u64)> = HashMap::new();
        while let Some(result) = join_set.join_next().await {
            if let Ok((idx, Some(data))) = result {
                probe_results.insert(idx, data);
            }
        }

        for (idx, entry) in subdomains.iter_mut().enumerate() {
            if let Some((status, title, elapsed)) = probe_results.remove(&idx) {
                entry.http_status = Some(status);
                if !title.is_empty() {
                    entry.http_title = Some(title);
                }
                entry.response_time_ms = Some(elapsed);
                entry.is_alive = true;
            }
        }
    }

    async fn resolve_domain_async(domain: &str) -> (Vec<String>, Vec<String>) {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::TokioAsyncResolver;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        match resolver.lookup_ip(domain).await {
            Ok(lookup) => {
                let ipv4: Vec<String> = lookup
                    .iter()
                    .filter_map(|ip| {
                        if ip.is_ipv4() {
                            Some(ip.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                let ipv6: Vec<String> = lookup
                    .iter()
                    .filter_map(|ip| {
                        if ip.is_ipv6() {
                            Some(ip.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
                (ipv4, ipv6)
            }
            Err(_) => (vec![], vec![]),
        }
    }
}
