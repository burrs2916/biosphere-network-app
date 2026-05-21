#[cfg(target_os = "linux")]
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SystemResources {
    pub cpu_cores: usize,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub cpu_usage_percent: f32,
    pub load_average: f32,
}

struct CachedSystemResources {
    resources: SystemResources,
    timestamp: Instant,
}

lazy_static::lazy_static! {
    static ref CACHED_RESOURCES: Arc<Mutex<Option<CachedSystemResources>>> = Arc::new(Mutex::new(None));
}

const CACHE_TTL_SECONDS: u64 = 5;

impl SystemResources {
    pub fn detect() -> Self {
        let cpu_cores = num_cpus::get();
        
        let (total_memory_mb, available_memory_mb) = get_memory_info();
        
        let cpu_usage_percent = get_cpu_usage();
        
        let load_average = get_load_average();
        
        Self {
            cpu_cores,
            total_memory_mb,
            available_memory_mb,
            cpu_usage_percent,
            load_average,
        }
    }
    
    pub fn detect_cached() -> Self {
        let mut cache = CACHED_RESOURCES.lock().unwrap();
        
        if let Some(ref cached) = *cache {
            let elapsed = cached.timestamp.elapsed();
            if elapsed < Duration::from_secs(CACHE_TTL_SECONDS) {
                return cached.resources.clone();
            }
        }
        
        let resources = Self::detect();
        *cache = Some(CachedSystemResources {
            resources: resources.clone(),
            timestamp: Instant::now(),
        });
        
        resources
    }
    pub fn calculate_optimal_concurrency(&self) -> usize {
        let base_concurrency = self.cpu_cores * 100;
        
        let memory_factor = if self.available_memory_mb > 4096 {
            1.5
        } else if self.available_memory_mb > 2048 {
            1.0
        } else if self.available_memory_mb > 1024 {
            0.7
        } else {
            0.5
        };
        
        let cpu_factor = if self.cpu_usage_percent < 30.0 {
            1.3
        } else if self.cpu_usage_percent < 60.0 {
            1.0
        } else if self.cpu_usage_percent < 80.0 {
            0.7
        } else {
            0.5
        };
        
        let load_factor = if self.load_average < (self.cpu_cores as f32 * 0.5) {
            1.2
        } else if self.load_average < (self.cpu_cores as f32) {
            1.0
        } else {
            0.6
        };
        
        let optimal = (base_concurrency as f32 * memory_factor * cpu_factor * load_factor) as usize;
        
        let min_concurrency = 50;
        let max_concurrency = 5000;
        
        optimal.clamp(min_concurrency, max_concurrency)
    }
    
    pub fn get_recommended_timeout(&self) -> u64 {
        if self.available_memory_mb > 4096 && self.cpu_usage_percent < 50.0 {
            500
        } else if self.available_memory_mb > 2048 && self.cpu_usage_percent < 70.0 {
            1000
        } else {
            1500
        }
    }
    
    pub fn summary(&self) -> String {
        format!(
            "CPU: {} cores, Memory: {}/{} MB, CPU Usage: {:.1}%, Load: {:.2}, Optimal Concurrency: {}",
            self.cpu_cores,
            self.available_memory_mb,
            self.total_memory_mb,
            self.cpu_usage_percent,
            self.load_average,
            self.calculate_optimal_concurrency()
        )
    }
}

fn get_memory_info() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        
        if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;
            
            for line in contents.lines() {
                if line.starts_with("MemTotal:") {
                    total = parse_memory_value(line);
                } else if line.starts_with("MemAvailable:") {
                    available = parse_memory_value(line);
                }
            }
            
            return (total / 1024, available / 1024);
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        let mut total_mb = 0u64;
        let mut available_mb = 0u64;
        
        if let Ok(output) = Command::new("sysctl")
            .args(&["-n", "hw.memsize"])
            .output()
        {
            if let Ok(total_str) = String::from_utf8(output.stdout) {
                if let Ok(total_bytes) = total_str.trim().parse::<u64>() {
                    total_mb = total_bytes / (1024 * 1024);
                }
            }
        }

        if let Ok(output) = Command::new("vm_stat").output() {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut page_count: u64 = 0;
                let page_size: u64 = 16384;

                for line in output_str.lines() {
                    if line.starts_with("Pages free:") || line.starts_with("Pages inactive:") {
                        let count_str = line.split(':').nth(1)
                            .unwrap_or("")
                            .trim()
                            .trim_end_matches('.')
                            .replace(",", "")
                            .trim()
                            .to_string();
                        if let Ok(count) = count_str.parse::<u64>() {
                            page_count += count;
                        }
                    }
                }

                available_mb = (page_count * page_size) / (1024 * 1024);
            }
        }

        if total_mb > 0 && available_mb > 0 {
            return (total_mb, available_mb);
        } else if total_mb > 0 {
            return (total_mb, total_mb / 2);
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        if let Ok(output) = Command::new("wmic")
            .args(&["OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory", "/value"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let mut total = 0u64;
                let mut free = 0u64;
                
                for line in output_str.lines() {
                    if line.starts_with("TotalVisibleMemorySize=") {
                        total = line.split('=').nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0) / 1024;
                    } else if line.starts_with("FreePhysicalMemory=") {
                        free = line.split('=').nth(1)
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0) / 1024;
                    }
                }
                
                return (total, free);
            }
        }
    }
    
    (4096, 2048)
}

#[cfg(target_os = "linux")]
fn parse_memory_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn get_cpu_usage() -> f32 {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        
        if let Ok(contents) = fs::read_to_string("/proc/stat") {
            if let Some(first_line) = contents.lines().next() {
                let parts: Vec<u64> = first_line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|s| s.parse().ok())
                    .collect();
                
                if parts.len() >= 4 {
                    let total: u64 = parts.iter().sum();
                    let idle = parts[3];
                    
                    if total > 0 {
                        return ((total - idle) as f32 / total as f32) * 100.0;
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        if let Ok(output) = Command::new("ps")
            .args(&["-A", "-o", "%cpu"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let total: f32 = output_str
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.trim().parse::<f32>().ok())
                    .sum();
                
                let cpu_count = num_cpus::get() as f32;
                return (total / cpu_count).min(100.0);
            }
        }
    }
    
    50.0
}

fn get_load_average() -> f32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = fs::read_to_string("/proc/loadavg") {
            if let Some(first_value) = contents.split_whitespace().next() {
                if let Ok(load) = first_value.parse::<f32>() {
                    return load;
                }
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        if let Ok(output) = Command::new("sysctl")
            .args(&["-n", "vm.loadavg"])
            .output()
        {
            if let Ok(output_str) = String::from_utf8(output.stdout) {
                let parts: Vec<&str> = output_str.trim().split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(load) = parts[1].parse::<f32>() {
                        return load;
                    }
                }
            }
        }
    }
    
    1.0
}

pub fn get_optimal_scan_config() -> (usize, u64) {
    let resources = SystemResources::detect();
    let concurrency = resources.calculate_optimal_concurrency();
    let timeout = resources.get_recommended_timeout();
    
    (concurrency, timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_system_detection() {
        let resources = SystemResources::detect();
        println!("System Resources: {:?}", resources);
        println!("Summary: {}", resources.summary());
        
        assert!(resources.cpu_cores > 0);
        assert!(resources.total_memory_mb > 0);
        assert!(resources.available_memory_mb > 0);
        
        let optimal = resources.calculate_optimal_concurrency();
        assert!(optimal >= 50 && optimal <= 5000);
    }
    
    #[test]
    fn test_concurrency_calculation() {
        let mut resources = SystemResources::detect();
        
        resources.cpu_usage_percent = 20.0;
        resources.available_memory_mb = 8192;
        resources.load_average = 0.5;
        let high_perf = resources.calculate_optimal_concurrency();
        
        resources.cpu_usage_percent = 90.0;
        resources.available_memory_mb = 512;
        resources.load_average = 4.0;
        let low_perf = resources.calculate_optimal_concurrency();
        
        assert!(high_perf > low_perf);
        println!("High perf concurrency: {}", high_perf);
        println!("Low perf concurrency: {}", low_perf);
    }
}
