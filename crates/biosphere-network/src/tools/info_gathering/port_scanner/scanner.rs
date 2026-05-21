use super::{PortScanConfig, PortScanResult, PortStatus, ScanResult};
use super::service_detect::ServiceDetector;
use super::os_detect::OSDetection;
use super::cancel::is_cancelled;
use crate::core::{ToolError, Result};
use crate::infrastructure::network::{check_tcp_port_fast, resolve_hostname, resolve_hostname_all};
use crate::infrastructure::system::SystemResources;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

pub struct Scanner {
    config: PortScanConfig,
    auto_concurrency: bool,
}

impl Scanner {
    pub fn new(config: PortScanConfig) -> Self {
        Self { 
            config,
            auto_concurrency: true,
        }
    }
    
    pub fn with_auto_concurrency(config: PortScanConfig, auto: bool) -> Self {
        Self {
            config,
            auto_concurrency: auto,
        }
    }

    pub async fn resolve_target(target: &str) -> Result<IpAddr> {
        if PortScanConfig::is_ip_address(target) {
            target.parse::<IpAddr>()
                .map_err(|e| ToolError::InvalidTarget(format!("Invalid IP address: {}", e)))
        } else {
            resolve_hostname(target).await
                .map_err(|e| ToolError::InvalidTarget(format!("Failed to resolve hostname: {}", e)))
        }
    }
    
    pub async fn resolve_target_all(target: &str) -> Result<(IpAddr, Vec<IpAddr>)> {
        if PortScanConfig::is_ip_address(target) {
            let ip = target.parse::<IpAddr>()
                .map_err(|e| ToolError::InvalidTarget(format!("Invalid IP address: {}", e)))?;
            Ok((ip, vec![ip]))
        } else {
            let all_ips = resolve_hostname_all(target).await
                .map_err(|e| ToolError::InvalidTarget(format!("Failed to resolve hostname: {}", e)))?;
            
            let ipv4: Vec<IpAddr> = all_ips.iter().filter(|ip| ip.is_ipv4()).cloned().collect();
            let ipv6: Vec<IpAddr> = all_ips.iter().filter(|ip| ip.is_ipv6()).cloned().collect();
            
            let primary_ip = ipv4.first()
                .or_else(|| ipv6.first())
                .or_else(|| all_ips.first())
                .cloned()
                .ok_or_else(|| ToolError::InvalidTarget("No IP addresses resolved".to_string()))?;
            
            Ok((primary_ip, all_ips))
        }
    }
    
    fn get_optimal_concurrency(&self) -> usize {
        if self.auto_concurrency {
            let resources = SystemResources::detect_cached();
            resources.calculate_optimal_concurrency()
        } else {
            self.config.concurrent_limit
        }
    }

    pub async fn scan_port_with_banner(
        target: IpAddr, 
        target_str: String, 
        resolved_ip: String,
        all_resolved_ips: Vec<String>,
        port: u16, 
        timeout_ms: u64
    ) -> PortScanResult {
        let is_open = check_tcp_port_fast(target, port, timeout_ms).await
            .unwrap_or(false);

        let status = if is_open {
            PortStatus::Open
        } else {
            PortStatus::Closed
        };

        let (service, version, banner) = if status == PortStatus::Open {
            let service_name = ServiceDetector::identify_service_string(port);
            
            let banner = ServiceDetector::grab_banner(target, port, timeout_ms).await;
            
            let version = if let Some(ref banner_str) = banner {
                ServiceDetector::parse_version(banner_str, port)
            } else {
                None
            };

            (service_name, version, banner)
        } else {
            (None, None, None)
        };

        PortScanResult {
            target: Some(target_str),
            resolved_ip: Some(resolved_ip),
            all_resolved_ips: Some(all_resolved_ips),
            port,
            status,
            service,
            version,
            banner,
        }
    }

    pub async fn scan_single_target(&self, target_str: &str) -> Result<Vec<PortScanResult>> {
        let (target_ip, all_ips) = Self::resolve_target_all(target_str).await?;
        let resolved_ip = target_ip.to_string();
        let all_resolved_ips: Vec<String> = all_ips.iter().map(|ip| ip.to_string()).collect();
        
        let ports = self.config.get_ports();
        let mut results = Vec::new();
        
        let concurrency = self.get_optimal_concurrency();
        let (tx, mut rx) = mpsc::channel(concurrency);

        let mut tasks = JoinSet::new();
        let timeout = self.config.timeout_ms;
        let target_string = Arc::new(target_str.to_string());
        let resolved_ip_arc = Arc::new(resolved_ip);
        let all_resolved_ips_arc = Arc::new(all_resolved_ips);

        for port in ports {
            let tx = tx.clone();
            let target = target_ip;
            let target_str_clone = Arc::clone(&target_string);
            let ip_clone = Arc::clone(&resolved_ip_arc);
            let all_ips_clone = Arc::clone(&all_resolved_ips_arc);
            
            tasks.spawn(async move {
                let result = Self::scan_port_with_banner(
                    target, 
                    (*target_str_clone).clone(), 
                    (*ip_clone).clone(), 
                    (*all_ips_clone).clone(), 
                    port, 
                    timeout
                ).await;
                let _ = tx.send(result).await;
            });
        }

        drop(tx);

        while let Some(result) = rx.recv().await {
            if result.status == PortStatus::Open {
                results.push(result);
            }
        }

        results.sort_by_key(|r| r.port);
        Ok(results)
    }

    pub async fn scan_single_target_with_os(&self, target_str: &str) -> Result<ScanResult> {
        let (target_ip, all_ips) = Self::resolve_target_all(target_str).await?;
        let resolved_ip = Arc::new(target_ip.to_string());
        let all_resolved_ips = Arc::new(all_ips.iter().map(|ip| ip.to_string()).collect::<Vec<String>>());
        
        let os_detection = OSDetection::detect(target_ip, self.config.timeout_ms).await;
        
        let ports = self.config.get_ports();
        let mut results = Vec::new();
        
        let concurrency = self.get_optimal_concurrency();
        let (tx, mut rx) = mpsc::channel(concurrency);

        let mut tasks = JoinSet::new();
        let timeout = self.config.timeout_ms;
        let target_string = Arc::new(target_str.to_string());

        for port in ports {
            let tx = tx.clone();
            let target = target_ip;
            let target_str_clone = Arc::clone(&target_string);
            let ip_clone = Arc::clone(&resolved_ip);
            let all_ips_clone = Arc::clone(&all_resolved_ips);
            
            tasks.spawn(async move {
                let result = Self::scan_port_with_banner(
                    target, 
                    (*target_str_clone).clone(), 
                    (*ip_clone).clone(), 
                    (*all_ips_clone).clone(), 
                    port, 
                    timeout
                ).await;
                let _ = tx.send(result).await;
            });
        }

        drop(tx);

        while let Some(result) = rx.recv().await {
            if result.status == PortStatus::Open {
                results.push(result);
            }
        }

        results.sort_by_key(|r| r.port);
        
        Ok(ScanResult {
            target: target_str.to_string(),
            resolved_ip: (*resolved_ip).clone(),
            all_resolved_ips: (*all_resolved_ips).clone(),
            os_detection: Some(os_detection),
            open_ports: results,
        })
    }

    pub async fn scan_with_progress<F>(&self, mut progress_callback: F) -> Result<Vec<PortScanResult>>
    where
        F: FnMut(usize, usize, usize) + Send + 'static,
    {
        let targets = self.config.parse_targets();
        
        if targets.is_empty() {
            return Err(ToolError::InvalidTarget("No valid targets provided".to_string()));
        }

        let mut all_results = Vec::new();
        let total_targets = targets.len();
        let ports_per_target = self.config.get_ports().len();
        let total_ports = total_targets * ports_per_target;

        let open_counter = Arc::new(AtomicUsize::new(0));

        for (target_index, target_str) in targets.iter().enumerate() {
            if is_cancelled() {
                break;
            }
            
            let (target_ip, all_ips) = Self::resolve_target_all(target_str).await?;
            let resolved_ip = target_ip.to_string();
            let all_resolved_ips: Vec<String> = all_ips.iter().map(|ip| ip.to_string()).collect();
            let ports = self.config.get_ports();
            let ports_count = ports.len();
            let mut results = Vec::new();
            
            let concurrency = self.get_optimal_concurrency();
            let (tx, mut rx) = mpsc::channel(concurrency);

            let mut tasks = JoinSet::new();
            let timeout = self.config.timeout_ms;
            let target_string = Arc::new(target_str.to_string());
            let resolved_ip_arc = Arc::new(resolved_ip);
            let all_resolved_ips_arc = Arc::new(all_resolved_ips);

            for port in ports {
                let tx = tx.clone();
                let target = target_ip;
                let target_str_clone = Arc::clone(&target_string);
                let ip_clone = Arc::clone(&resolved_ip_arc);
                let all_ips_clone = Arc::clone(&all_resolved_ips_arc);
                
                tasks.spawn(async move {
                    if is_cancelled() {
                        return;
                    }
                    let result = Self::scan_port_with_banner(
                        target, 
                        (*target_str_clone).clone(), 
                        (*ip_clone).clone(), 
                        (*all_ips_clone).clone(), 
                        port, 
                        timeout
                    ).await;
                    let _ = tx.send(result).await;
                });
            }

            drop(tx);

            let mut scanned_count = 0;
            let mut last_report_time = std::time::Instant::now();
            let report_interval_ms = 100;
            let min_report_interval = (ports_count / 100).max(1);

            while let Some(result) = rx.recv().await {
                if is_cancelled() {
                    break;
                }
                
                results.push(result);
                scanned_count += 1;
                
                let should_report = scanned_count % min_report_interval == 0 
                    || scanned_count == ports_count
                    || last_report_time.elapsed().as_millis() >= report_interval_ms as u128;
                
                if should_report {
                    let open_count = results.iter().filter(|r| r.status == PortStatus::Open).count();
                    
                    let total_scanned = target_index * ports_per_target + scanned_count;
                    let total_open = open_counter.load(Ordering::Relaxed) + open_count;
                    
                    progress_callback(total_scanned, total_ports, total_open);
                    last_report_time = std::time::Instant::now();
                }
            }

            let open_count = results.iter().filter(|r| r.status == PortStatus::Open).count();
            open_counter.fetch_add(open_count, Ordering::Relaxed);
            
            results.retain(|r| r.status == PortStatus::Open);
            results.sort_by_key(|r| r.port);
            all_results.extend(results);

            let total_scanned = (target_index + 1) * ports_per_target;
            let total_open = open_counter.load(Ordering::Relaxed);
            progress_callback(total_scanned, total_ports, total_open);
        }

        Ok(all_results)
    }

    pub async fn scan(&self) -> Result<Vec<PortScanResult>> {
        let targets = self.config.parse_targets();
        
        if targets.is_empty() {
            return Err(ToolError::InvalidTarget("No valid targets provided".to_string()));
        }

        let mut all_results = Vec::new();

        for target_str in targets {
            match self.scan_single_target(&target_str).await {
                Ok(results) => {
                    all_results.extend(results);
                }
                Err(e) => {
                    eprintln!("Failed to scan target {}: {}", target_str, e);
                }
            }
        }

        Ok(all_results)
    }
    
    pub fn get_system_info(&self) -> String {
        let resources = SystemResources::detect();
        resources.summary()
    }
}
