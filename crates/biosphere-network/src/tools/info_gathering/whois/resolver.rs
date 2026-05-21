use crate::tools::info_gathering::whois::{WhoisConfig, WhoisResult};
use std::time::Duration;

pub struct WhoisResolver;

impl WhoisResolver {
    pub async fn query(config: WhoisConfig) -> Result<WhoisResult, Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let domain = config.domain.trim().to_lowercase();
        
        let tld = Self::extract_tld(&domain);
        let whois_server = Self::get_whois_server(&tld);
        
        let raw_response = Self::query_whois_server(&whois_server, &domain, config.timeout_ms).await?;
        
        let mut result = WhoisResult::new(domain.clone());
        result.raw_response = raw_response.clone();
        result.query_time = start.elapsed().as_millis() as u64;
        
        Self::parse_whois_response(&raw_response, &mut result);
        
        Ok(result)
    }
    
    fn extract_tld(domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            parts[parts.len() - 1].to_string()
        } else {
            "com".to_string()
        }
    }
    
    fn get_whois_server(tld: &str) -> String {
        match tld {
            "com" => "whois.verisign-grs.com:43",
            "net" => "whois.verisign-grs.com:43",
            "org" => "whois.pir.org:43",
            "io" => "whois.nic.io:43",
            "co" => "whois.nic.co:43",
            "cn" => "whois.cnnic.cn:43",
            "jp" => "whois.jprs.jp:43",
            "uk" => "whois.nic.uk:43",
            "de" => "whois.denic.de:43",
            "fr" => "whois.nic.fr:43",
            "ru" => "whois.tcinet.ru:43",
            "info" => "whois.afilias.net:43",
            "biz" => "whois.neulevel.biz:43",
            "me" => "whois.nic.me:43",
            "tv" => "whois.nic.tv:43",
            "cc" => "whois.nic.cc:43",
            "xyz" => "whois.nic.xyz:43",
            "top" => "whois.nic.top:43",
            "vip" => "whois.nic.vip:43",
            "site" => "whois.nic.site:43",
            "online" => "whois.nic.online:43",
            "tech" => "whois.nic.tech:43",
            "shop" => "whois.nic.shop:43",
            _ => "whois.iana.org:43",
        }.to_string()
    }
    
    async fn query_whois_server(
        server: &str,
        domain: &str,
        timeout_ms: u64,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::TcpStream as AsyncTcpStream;
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        
        let server_addr = server.to_string();
        let domain = domain.to_string();
        let connect_timeout = Duration::from_secs(10);
        let read_timeout = Duration::from_millis(timeout_ms.max(10000));
        
        let addr = tokio::net::lookup_host(&server_addr).await?
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Failed to resolve whois server"))?;
        
        let mut stream = tokio::time::timeout(connect_timeout, AsyncTcpStream::connect(&addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connection timeout"))??;
        
        let query = format!("{}\r\n", domain);
        stream.write_all(query.as_bytes()).await?;
        
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        
        loop {
            match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 1024 * 1024 {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    if response.is_empty() {
                        return Err(e.into());
                    }
                    break;
                }
                Err(_) => {
                    if response.is_empty() {
                        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "Read timeout")));
                    }
                    break;
                }
            }
        }
        
        Ok(String::from_utf8_lossy(&response).to_string())
    }
    
    fn parse_whois_response(response: &str, result: &mut WhoisResult) {
        for line in response.lines() {
            let line = line.trim();
            let line_lower = line.to_lowercase();
            
            if line_lower.starts_with("registrar:") || line_lower.starts_with("registrar name:") {
                result.registrar = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("creation date:") || line_lower.starts_with("created:") || line_lower.starts_with("domain created:") {
                if let Some(date) = line.splitn(2, ':').nth(1) {
                    result.created_date = Some(Self::clean_date(date.trim()));
                }
            }
            
            if line_lower.starts_with("updated date:") || line_lower.starts_with("last updated:") || line_lower.starts_with("modified:") {
                if let Some(date) = line.splitn(2, ':').nth(1) {
                    result.updated_date = Some(Self::clean_date(date.trim()));
                }
            }
            
            if line_lower.starts_with("registry expiry date:") || line_lower.starts_with("expires:") || line_lower.starts_with("expiration date:") {
                if let Some(date) = line.splitn(2, ':').nth(1) {
                    result.expiry_date = Some(Self::clean_date(date.trim()));
                }
            }
            
            if line_lower.starts_with("domain status:") || line_lower.starts_with("status:") {
                if let Some(status) = line.split(':').nth(1) {
                    let status = status.trim();
                    let status = status.split_whitespace().next().unwrap_or(status);
                    result.status.push(status.to_string());
                }
            }
            
            if line_lower.starts_with("name server:") || line_lower.starts_with("nserver:") {
                if let Some(ns) = line.split(':').nth(1) {
                    let ns = ns.trim();
                    let ns = ns.split_whitespace().next().unwrap_or(ns);
                    result.name_servers.push(ns.to_uppercase());
                }
            }
            
            if line_lower.starts_with("registrant name:") || line_lower.starts_with("registrant:") {
                result.registrant_name = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("registrant organization:") {
                result.registrant_organization = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("registrant country:") || line_lower.starts_with("registrant country/economy:") {
                result.registrant_country = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if result.registrant_country.is_none() && line_lower.starts_with("country:") && !line_lower.contains("country code") {
                result.registrant_country = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("registrant email:") {
                result.registrant_email = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("admin name:") {
                result.admin_name = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("admin email:") {
                result.admin_email = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("tech name:") {
                result.tech_name = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("tech email:") {
                result.tech_email = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
            
            if line_lower.starts_with("dnssec:") {
                result.dnssec = Some(line.split(':').nth(1).unwrap_or("").trim().to_string());
            }
        }
        
        result.name_servers.sort();
        result.name_servers.dedup();
        result.status.sort();
        result.status.dedup();
    }
    
    fn clean_date(date_str: &str) -> String {
        let date_str = date_str.trim();
        let date_str = date_str.split_whitespace().next().unwrap_or(date_str);
        date_str.to_string()
    }
}
