use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use crate::core::{Result, ToolError};
use super::config::*;
use md5;
use sha1::{Sha1, Digest};
use sha2::{Sha256, Sha384, Sha512};

pub struct HashCrackerTool;

impl HashCrackerTool {
    pub async fn crack(config: &HashCrackConfig) -> Result<HashCrackResult> {
        let start = Instant::now();
        let hash = config.hash.trim().to_string();

        if hash.is_empty() {
            return Err(ToolError::ExecutionError("请提供哈希值".to_string()));
        }

        let detected_type = if config.hash_type == "auto" {
            Self::detect_hash_type(&hash)
        } else {
            config.hash_type.clone()
        };

        let mut found_password: Option<String> = None;
        let mut method_used: Option<String> = None;
        let mut online_lookup_results = Vec::new();
        let mut rainbow_table_results = Vec::new();
        let mut attempts = Vec::new();

        if config.use_online_lookup {
            let online_results = Self::online_lookup(&hash, &detected_type).await;
            for result in &online_results {
                if result.found && found_password.is_none() {
                    found_password = result.password.clone();
                    method_used = Some(format!("online_lookup:{}", result.service));
                }
            }
            online_lookup_results = online_results;
        }

        if found_password.is_none() && config.use_rainbow_table {
            let rainbow_results = Self::rainbow_table_lookup(&hash, &detected_type, &config.rainbow_table_path);
            for result in &rainbow_results {
                if result.found && found_password.is_none() {
                    found_password = result.password.clone();
                    method_used = Some(format!("rainbow_table:{}", result.table_name));
                }
            }
            rainbow_table_results = rainbow_results;
        }

        if found_password.is_none() {
            let wordlist: Vec<String> = if config.use_builtin_wordlist {
                let mut wl = get_default_wordlist();
                if let Some(custom_path) = &config.wordlist_path {
                    if let Ok(custom_wl) = Self::load_wordlist(custom_path) {
                        wl.extend(custom_wl);
                    }
                }
                if config.use_rule_based {
                    let mut rule_words = Vec::new();
                    for word in &wl {
                        rule_words.extend(Self::apply_rules(word));
                    }
                    wl.extend(rule_words);
                }
                wl
            } else if let Some(path) = &config.wordlist_path {
                let mut wl = Self::load_wordlist(path)?;
                if config.use_rule_based {
                    let mut rule_words = Vec::new();
                    for word in &wl {
                        rule_words.extend(Self::apply_rules(word));
                    }
                    wl.extend(rule_words);
                }
                wl
            } else {
                return Err(ToolError::ExecutionError("请提供字典路径或启用内置字典".to_string()));
            };

            let wordlist_clipped: Vec<String> = if wordlist.len() > config.max_passwords {
                wordlist[..config.max_passwords].to_vec()
            } else {
                wordlist
            };

            let (found, att) = Self::try_wordlist(
                &hash,
                &detected_type,
                &wordlist_clipped,
                config.timeout,
            ).await;

            if found.is_some() {
                found_password = found;
                method_used = Some("dictionary_attack".to_string());
            }
            attempts = att;
        }

        let time_taken = start.elapsed().as_millis() as u64;

        let summary = if let Some(pwd) = &found_password {
            let method = method_used.as_deref().unwrap_or("unknown");
            format!("哈希破解成功！找到密码: {} (方法: {}, 耗时: {}ms)", 
                pwd, method, time_taken)
        } else {
            format!("未找到匹配密码 (在线查询: {}, 彩虹表: {}, 耗时: {}ms)", 
                online_lookup_results.len(), rainbow_table_results.len(), time_taken)
        };

        Ok(HashCrackResult {
            success: found_password.is_some(),
            found_password,
            hash_type_detected: detected_type,
            passwords_tried: attempts.len(),
            time_taken_ms: time_taken,
            summary,
            attempts,
            online_lookup_results,
            rainbow_table_results,
            method_used,
        })
    }

    fn detect_hash_type(hash: &str) -> String {
        let len = hash.len();
        let lower = hash.to_lowercase();

        if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
            return "bcrypt".to_string();
        }
        if hash.starts_with("$6$") {
            return "sha512crypt".to_string();
        }
        if hash.starts_with("$5$") {
            return "sha256crypt".to_string();
        }
        if hash.starts_with("$1$") {
            return "md5crypt".to_string();
        }
        if hash.starts_with("$apr1$") {
            return "md5apr1".to_string();
        }
        if lower.starts_with("$mysql") || hash.starts_with("*") && len == 41 {
            return "mysql".to_string();
        }
        if hash.starts_with("$pbkdf2") {
            return "pbkdf2".to_string();
        }
        if hash.starts_with("$scrypt") {
            return "scrypt".to_string();
        }
        if hash.starts_with("$argon2") {
            return "argon2".to_string();
        }
        if hash.contains("$") && len == 94 {
            return "ntlm".to_string();
        }

        match len {
            32 => {
                if lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    "md5".to_string()
                } else {
                    "unknown".to_string()
                }
            }
            40 => {
                if lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    "sha1".to_string()
                } else {
                    "unknown".to_string()
                }
            }
            56 => "sha224".to_string(),
            64 => {
                if lower.chars().all(|c| c.is_ascii_hexdigit()) {
                    "sha256".to_string()
                } else {
                    "unknown".to_string()
                }
            }
            96 => "sha384".to_string(),
            128 => "sha512".to_string(),
            8 => "crc32".to_string(),
            16 => "mysql323".to_string(),
            // 32 if hex was already handled above; NTLM detected by $ prefix check earlier
            _ => "unknown".to_string(),
        }
    }

    async fn online_lookup(hash: &str, hash_type: &str) -> Vec<OnlineLookupResult> {
        let mut results = Vec::new();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build();

        let client = match client {
            Ok(c) => c,
            Err(_) => return results,
        };

        if hash_type == "md5" || hash_type == "sha1" || hash_type == "sha256" {
            let resp = client.get("https://www.md5online.org/md5-decrypt.html".to_string())
                .send().await;
            results.push(OnlineLookupResult {
                service: "md5online.org".to_string(),
                found: false,
                password: None,
                error: resp.err().map(|e| e.to_string()),
            });
        }

        if hash_type == "md5" {
            let resp = client.get(format!("https://api.hashify.net/hash/md5/hex/{}", hash))
                .send().await;
            match resp {
                Ok(r) => {
                    if let Ok(body) = r.text().await {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                            if let Some(digest) = json.get("digest") {
                                if let Some(plaintext) = digest.get("plaintext") {
                                    let pwd = plaintext.as_str().unwrap_or("").to_string();
                                    if !pwd.is_empty() {
                                        results.push(OnlineLookupResult {
                                            service: "hashify.net".to_string(),
                                            found: true,
                                            password: Some(pwd),
                                            error: None,
                                        });
                                        return results;
                                    }
                                }
                            }
                        }
                    }
                    results.push(OnlineLookupResult {
                        service: "hashify.net".to_string(),
                        found: false,
                        password: None,
                        error: None,
                    });
                }
                Err(e) => {
                    results.push(OnlineLookupResult {
                        service: "hashify.net".to_string(),
                        found: false,
                        password: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        if hash_type == "md5" || hash_type == "sha1" {
            let resp = client.get(format!("https://hashtoolkit.com/reverse-hash?hash={}", hash))
                .header("User-Agent", "Mozilla/5.0")
                .send().await;
            match resp {
                Ok(r) => {
                    if let Ok(body) = r.text().await {
                        let found = body.contains("resolved");
                        results.push(OnlineLookupResult {
                            service: "hashtoolkit.com".to_string(),
                            found,
                            password: None,
                            error: None,
                        });
                    }
                }
                Err(e) => {
                    results.push(OnlineLookupResult {
                        service: "hashtoolkit.com".to_string(),
                        found: false,
                        password: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        if hash_type == "md5" {
            let resp = client.get(format!("https://www.nitrxgen.net/md5db/{}", hash))
                .send().await;
            match resp {
                Ok(r) => {
                    if let Ok(body) = r.text().await {
                        let pwd = body.trim().to_string();
                        if !pwd.is_empty() && !pwd.starts_with('<') {
                            results.push(OnlineLookupResult {
                                service: "nitrxgen.net".to_string(),
                                found: true,
                                password: Some(pwd),
                                error: None,
                            });
                        } else {
                            results.push(OnlineLookupResult {
                                service: "nitrxgen.net".to_string(),
                                found: false,
                                password: None,
                                error: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    results.push(OnlineLookupResult {
                        service: "nitrxgen.net".to_string(),
                        found: false,
                        password: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        results
    }

    fn rainbow_table_lookup(hash: &str, _hash_type: &str, table_path: &Option<String>) -> Vec<RainbowTableResult> {
        let mut results = Vec::new();

        if let Some(path) = table_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        let stored_hash = parts[0].trim();
                        let plaintext = parts[1].trim();
                        if stored_hash.eq_ignore_ascii_case(hash) {
                            results.push(RainbowTableResult {
                                table_name: path.clone(),
                                found: true,
                                password: Some(plaintext.to_string()),
                                error: None,
                            });
                            return results;
                        }
                    }
                }
                results.push(RainbowTableResult {
                    table_name: path.clone(),
                    found: false,
                    password: None,
                    error: None,
                });
            } else {
                results.push(RainbowTableResult {
                    table_name: path.clone(),
                    found: false,
                    password: None,
                    error: Some("Failed to read rainbow table file".to_string()),
                });
            }
        }

        let builtin_entries: &[(&str, &str)] = &[
            ("e10adc3949ba59abbe56e057f20f883e", "123456"),
            ("5f4dcc3b5aa765d61d8327deb882cf99", "password"),
            ("25d55ad283aa400af464c76d713c07ad", "123456789"),
            ("e99a18c428cb38d5f260853678922e03", "abc123"),
            ("0192023a7bbd73250516f069df18b500", "admin123"),
            ("21232f297a57a5a743894a0e4a801fc3", "admin"),
            ("e807f1fcf82d132f9bb018ca6738a19f", "1234567"),
            ("c33367701511b4f6020ec61ded352059", "654321"),
            ("fcea920f7412b5da7be0cf42b8c93759", "1234567"),
            ("96e79218965eb72c92a549dd5a330112", "111111"),
            ("aaf4c61ddcc5e8a2dabede0f3b482cd9", "hello"),
            ("b59c67bf196a4758191e42f7a70c68eb", "test"),
            ("098f6bcd4621d373cade4e832627b4f6", "test"),
            ("6c569aabbf7775ef8fc570e228c16b98", "guest"),
            ("482c811da5d5b4bc6d497ffa98491e38", "password123"),
            ("5f4dcc3b5aa765d61d8327deb882cf99", "password"),
            ("7c6a180b36896a0a8c02787eeafb0e4c", "password1"),
            ("6cb75f652a9b52798eb6cf2201057c73", "Password1"),
            ("827ccb0eea8a706c4c34a16891f84e7b", "12345"),
            ("2ac9cb7dc02b3c0083eb70898e549b63", "000000"),
        ];

        for (stored_hash, plaintext) in builtin_entries {
            if stored_hash.eq_ignore_ascii_case(hash) {
                results.push(RainbowTableResult {
                    table_name: "builtin_common_passwords".to_string(),
                    found: true,
                    password: Some(plaintext.to_string()),
                    error: None,
                });
                return results;
            }
        }

        if results.is_empty() {
            results.push(RainbowTableResult {
                table_name: "builtin_common_passwords".to_string(),
                found: false,
                password: None,
                error: None,
            });
        }

        results
    }

    fn apply_rules(word: &str) -> Vec<String> {
        let mut variants = Vec::new();
        let capitalized = {
            let mut c = word.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        };
        let upper = word.to_uppercase();
        let with_num = format!("{}1", word);
        let with_num2 = format!("{}123", word);
        let with_num3 = format!("{}!", word);
        let with_num4 = format!("{}!1", word);
        let leet = word.replace('a', "@").replace('e', "3").replace('i', "1")
            .replace('o', "0").replace('s', "$").replace('t', "7");
        let leet_cap = {
            let mut c = leet.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        };
        let reversed: String = word.chars().rev().collect();
        let doubled = format!("{}{}", word, word);
        let with_year = format!("{}2024", word);
        let with_year2 = format!("{}2025", word);
        let p_prefix = format!("p@{}", word);
        let cap_num = format!("{}1!", capitalized);
        let cap_num2 = format!("{}123!", capitalized);

        for v in [capitalized, upper, with_num, with_num2, with_num3, with_num4,
                  leet, leet_cap, reversed, doubled, with_year, with_year2,
                  p_prefix, cap_num, cap_num2] {
            if v != word && !v.is_empty() {
                variants.push(v);
            }
        }
        variants
    }

    fn load_wordlist(path: &str) -> Result<Vec<String>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let file = File::open(path)
            .map_err(|e| ToolError::ExecutionError(format!("无法打开字典文件: {}", e)))?;
        
        let reader = BufReader::new(file);
        let mut words = Vec::new();

        for word in reader.lines().map_while(|r: std::io::Result<_>| r.ok()) {
            let trimmed = word.trim().to_string();
            if !trimmed.is_empty() {
                words.push(trimmed);
            }
        }

        Ok(words)
    }

    async fn try_wordlist(
        hash: &str,
        hash_type: &str,
        wordlist: &[String],
        timeout: u64,
    ) -> (Option<String>, Vec<HashAttempt>) {
        let mut attempts = Vec::new();
        let timeout_duration = Duration::from_secs(timeout);
        let start = Instant::now();

        let semaphore = Arc::new(Semaphore::new(100));
        let mut join_set = tokio::task::JoinSet::new();

        for word in wordlist {
            if start.elapsed() > timeout_duration {
                break;
            }

            let word_clone = word.clone();
            let hash_clone = hash.to_string();
            let hash_type_clone = hash_type.to_string();
            let sem_clone = semaphore.clone();

            join_set.spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                let computed = Self::compute_hash(&word_clone, &hash_type_clone);
                let matched = computed.eq_ignore_ascii_case(&hash_clone);
                (word_clone, computed, matched)
            });
        }

        let mut found = None;
        while let Some(res) = join_set.join_next().await {
            if let Ok((word, computed, matched)) = res {
                attempts.push(HashAttempt {
                    password: word.clone(),
                    hash: computed,
                    match_found: matched,
                });

                if matched && found.is_none() {
                    found = Some(word);
                }
            }
        }

        (found, attempts)
    }

    fn compute_hash(password: &str, hash_type: &str) -> String {
        match hash_type.to_lowercase().as_str() {
            "md5" | "ntlm" => {
                let mut hasher = md5::Md5::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
            "sha1" => {
                let mut hasher = Sha1::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
            "sha224" => {
                use sha2::Sha224;
                let mut hasher = Sha224::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
            "sha384" => {
                let mut hasher = Sha384::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
            "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
            "mysql323" => {
                let mut nr: u64 = 1345345333;
                let mut nr2: u64 = 0x12345671;
                let mut add: u64 = 7;
                for byte in password.as_bytes() {
                    if *byte == b' ' || *byte == b'\t' {
                        continue;
                    }
                    nr ^= (((nr & 63) + add) * (*byte as u64)) + (nr << 8);
                    nr2 = nr2.wrapping_add((nr2 << 8) ^ nr);
                    add = add.wrapping_add(*byte as u64);
                }
                format!("{:08x}{:08x}", nr & 0x7fffffff, nr2 & 0x7fffffff)
            }
            "mysql" => {
                let mut hasher = Sha1::new();
                hasher.update(password.as_bytes());
                let hash1 = hasher.finalize();
                let mut hasher2 = Sha1::new();
                hasher2.update(hash1);
                let hash2 = hasher2.finalize();
                format!("*{}", hex::encode(hash2))
            }
            _ => {
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                format!("{:x}", result)
            }
        }
    }
}
