use super::{DnsQueryConfig, DnsQueryResult, DnsRecord, DnsQueryType};
use crate::core::{ToolError, Result};
use std::time::{Duration, Instant};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::{RecordType, RData};

pub struct DnsResolver;

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    pub fn new() -> Self {
        Self
    }

    pub async fn query(config: DnsQueryConfig) -> Result<DnsQueryResult> {
        let start_time = Instant::now();

        let resolver_config = if let Some(dns_server) = &config.dns_server {
            if let Ok(addr) = dns_server.parse::<std::net::SocketAddr>() {
                let mut cfg = ResolverConfig::new();
                cfg.add_name_server(NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                });
                cfg
            } else {
                return Err(ToolError::ExecutionError(format!(
                    "Invalid DNS server address: {}",
                    dns_server
                )));
            }
        } else {
            ResolverConfig::default()
        };

        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.timeout = Duration::from_secs(config.timeout);

        let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts);

        let result = match config.query_type {
            DnsQueryType::A => Self::query_a(&resolver, &config.domain).await,
            DnsQueryType::AAAA => Self::query_aaaa(&resolver, &config.domain).await,
            DnsQueryType::MX => Self::query_mx(&resolver, &config.domain).await,
            DnsQueryType::NS => Self::query_ns(&resolver, &config.domain).await,
            DnsQueryType::CNAME => Self::query_cname(&resolver, &config.domain).await,
            DnsQueryType::TXT => Self::query_txt(&resolver, &config.domain).await,
            DnsQueryType::SOA => Self::query_soa(&resolver, &config.domain).await,
            DnsQueryType::PTR => Self::query_ptr(&resolver, &config.domain).await,
            DnsQueryType::ANY => Self::query_any(&resolver, &config.domain).await,
        };

        let query_time = start_time.elapsed().as_millis() as i32;

        match result {
            Ok(records) => Ok(DnsQueryResult::new(config.domain, config.query_type.as_str().to_string())
                .with_records(records)
                .with_query_time(query_time)
                .with_dns_server(config.dns_server.unwrap_or_else(|| "System DNS".to_string()))),
            Err(e) => {
                let error_msg = e.to_string();
                
                if error_msg.contains("no record found") || 
                   error_msg.contains("NXDOMAIN") ||
                   error_msg.contains("No records") {
                    Ok(DnsQueryResult::new(config.domain, config.query_type.as_str().to_string())
                        .with_records(Vec::new())
                        .with_query_time(query_time)
                        .with_dns_server(config.dns_server.unwrap_or_else(|| "System DNS".to_string())))
                } else {
                    Ok(DnsQueryResult::new(config.domain, config.query_type.as_str().to_string())
                        .with_query_time(query_time)
                        .with_dns_server(config.dns_server.unwrap_or_else(|| "System DNS".to_string()))
                        .with_error(error_msg))
                }
            }
        }
    }

    async fn query_a(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup_ip(domain)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for addr in response.iter() {
            if addr.is_ipv4() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "A".to_string(),
                    "IN".to_string(),
                    300,
                    addr.to_string(),
                ));
            }
        }

        Ok(records)
    }

    async fn query_aaaa(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::AAAA)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::AAAA(addr)) = record.data() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "AAAA".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    addr.to_string(),
                ));
            }
        }

        Ok(records)
    }

    async fn query_mx(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::MX)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::MX(mx)) = record.data() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "MX".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    format!("{} {}", mx.preference(), mx.exchange()),
                ));
            }
        }

        Ok(records)
    }

    async fn query_ns(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::NS)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::NS(ns)) = record.data() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "NS".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    ns.to_string(),
                ));
            }
        }

        Ok(records)
    }

    async fn query_cname(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::CNAME)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::CNAME(cname)) = record.data() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "CNAME".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    cname.to_string(),
                ));
            }
        }

        Ok(records)
    }

    async fn query_txt(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::TXT)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::TXT(txt)) = record.data() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "TXT".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    txt.iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join(" "),
                ));
            }
        }

        Ok(records)
    }

    async fn query_soa(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::SOA)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::SOA(soa)) = record.data() {
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "SOA".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    format!(
                        "{} {} {} {} {} {} {}",
                        soa.mname(),
                        soa.rname(),
                        soa.serial(),
                        soa.refresh(),
                        soa.retry(),
                        soa.expire(),
                        soa.minimum()
                    ),
                ));
            }
        }

        Ok(records)
    }

    async fn query_ptr(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let ptr_domain = if domain.parse::<std::net::Ipv4Addr>().is_ok() {
            let ip: std::net::Ipv4Addr = domain.parse()
                .map_err(|e| ToolError::ExecutionError(format!("Invalid IPv4 address: {}", e)))?;
            let octets = ip.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
        } else if domain.parse::<std::net::Ipv6Addr>().is_ok() {
            let ip: std::net::Ipv6Addr = domain.parse()
                .map_err(|e| ToolError::ExecutionError(format!("Invalid IPv6 address: {}", e)))?;
            let segments = ip.octets();
            let mut reversed = String::new();
            for i in (0..16).rev() {
                reversed.push_str(&format!("{:x}.", segments[i]));
            }
            format!("{}ip6.arpa", reversed)
        } else {
            domain.to_string()
        };

        println!("PTR Query: {} -> {}", domain, ptr_domain);

        let response = resolver
            .lookup(&ptr_domain, RecordType::PTR)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            if let Some(RData::PTR(ptr)) = record.data() {
                println!("PTR Record found: {}", ptr);
                records.push(DnsRecord::new(
                    domain.to_string(),
                    "PTR".to_string(),
                    "IN".to_string(),
                    record.ttl() as i32,
                    ptr.to_string(),
                ));
            }
        }

        if records.is_empty() {
            println!("No PTR records found for {}", domain);
        }

        Ok(records)
    }

    async fn query_any(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, RecordType::ANY)
            .await
            .map_err(|e| ToolError::ExecutionError(format!("DNS query failed: {}", e)))?;

        let mut records = Vec::new();
        for record in response.record_iter() {
            let record_type = record.record_type().to_string();
            let ttl = record.ttl();
            let data = match record.data() {
                Some(RData::A(ip)) => ip.to_string(),
                Some(RData::AAAA(ip)) => ip.to_string(),
                Some(RData::MX(mx)) => format!("{} {}", mx.preference(), mx.exchange()),
                Some(RData::NS(ns)) => ns.to_string(),
                Some(RData::CNAME(cname)) => cname.to_string(),
                Some(RData::TXT(txt)) => txt.iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join(" "),
                Some(RData::SOA(soa)) => format!(
                    "{} {} {} {} {} {} {}",
                    soa.mname(),
                    soa.rname(),
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum()
                ),
                Some(RData::PTR(ptr)) => ptr.to_string(),
                _ => "Unknown".to_string(),
            };

            records.push(DnsRecord::new(
                domain.to_string(),
                record_type,
                "IN".to_string(),
                ttl as i32,
                data,
            ));
        }

        Ok(records)
    }
}
