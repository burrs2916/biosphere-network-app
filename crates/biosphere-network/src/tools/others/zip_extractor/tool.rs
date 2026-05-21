use crate::core::{Result, ToolError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Write, BufRead, BufReader};
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipFileInfo {
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipExtractResult {
    pub success: bool,
    pub files_extracted: u32,
    pub total_size: u64,
    pub output_path: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipBruteForceResult {
    pub success: bool,
    pub password: Option<String>,
    pub attempts: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

pub struct ZipExtractor;

impl ZipExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn list_files(zip_path: &str) -> Result<Vec<ZipFileInfo>> {
        let file = File::open(zip_path)
            .map_err(|e| ToolError::NetworkError(e))?;
        
        let reader = BufReader::new(file);
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| ToolError::ParseError(format!("Invalid ZIP file: {}", e)))?;

        let mut files = Vec::new();

        for i in 0..archive.len() {
            let file = archive.by_index(i)
                .map_err(|e| ToolError::ParseError(format!("Failed to read file entry: {}", e)))?;

            files.push(ZipFileInfo {
                name: file.name().to_string(),
                size: file.size(),
                compressed_size: file.compressed_size(),
                is_dir: file.is_dir(),
                is_encrypted: file.encrypted(),
            });
        }

        Ok(files)
    }

    fn get_encrypted_indices(zip_path: &str) -> Result<Vec<usize>> {
        let file = File::open(zip_path)
            .map_err(|e| ToolError::NetworkError(e))?;
        
        let reader = BufReader::new(file);
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| ToolError::ParseError(format!("Invalid ZIP file: {}", e)))?;

        let mut indices = Vec::new();
        for i in 0..archive.len() {
            let file = archive.by_index(i)
                .map_err(|e| ToolError::ParseError(format!("Failed to read file entry: {}", e)))?;
            if file.encrypted() {
                indices.push(i);
            }
        }

        Ok(indices)
    }

    pub fn extract_with_password(
        zip_path: &str,
        output_dir: &str,
        password: Option<&str>,
    ) -> Result<ZipExtractResult> {
        let encrypted_indices = Self::get_encrypted_indices(zip_path)?;

        if !encrypted_indices.is_empty() && password.is_none() {
            return Err(ToolError::ExecutionError("Password required for encrypted file".to_string()));
        }

        let file = File::open(zip_path)
            .map_err(|e| ToolError::NetworkError(e))?;
        
        let reader = BufReader::new(file);
        let mut archive = ZipArchive::new(reader)
            .map_err(|e| ToolError::ParseError(format!("Invalid ZIP file: {}", e)))?;

        let output_path = PathBuf::from(output_dir);
        if !output_path.exists() {
            std::fs::create_dir_all(&output_path)
                .map_err(|e| ToolError::NetworkError(e))?;
        }

        let mut files_extracted = 0u32;
        let mut total_size = 0u64;
        let pwd_bytes: Vec<u8> = password.map(|p| p.as_bytes().to_vec()).unwrap_or_default();

        for i in 0..archive.len() {
            let is_encrypted = encrypted_indices.contains(&i);

            let mut file = if is_encrypted {
                archive.by_index_decrypt(i, &pwd_bytes)
                    .map_err(|e| ToolError::ParseError(format!("Wrong password or decryption failed: {}", e)))?
            } else {
                archive.by_index(i)
                    .map_err(|e| ToolError::ParseError(format!("Failed to read file entry: {}", e)))?
            };

            let file_path = output_path.join(file.name());

            if !file_path.starts_with(&output_path) {
                return Err(ToolError::ExecutionError(
                    format!("Zip Slip vulnerability detected: file '{}' attempts to escape output directory", file.name())
                ));
            }
            
            if file.is_dir() {
                std::fs::create_dir_all(&file_path)
                    .map_err(|e| ToolError::NetworkError(e))?;
            } else {
                if let Some(parent) = file_path.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| ToolError::NetworkError(e))?;
                    }
                }

                let mut output_file = File::create(&file_path)
                    .map_err(|e| ToolError::NetworkError(e))?;
                
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)
                    .map_err(|e| ToolError::NetworkError(e))?;
                
                output_file.write_all(&buffer)
                    .map_err(|e| ToolError::NetworkError(e))?;

                total_size += buffer.len() as u64;
                files_extracted += 1;
            }
        }

        Ok(ZipExtractResult {
            success: true,
            files_extracted,
            total_size,
            output_path: output_dir.to_string(),
            error: None,
        })
    }

    pub fn check_encryption(zip_path: &str) -> Result<bool> {
        let encrypted = Self::get_encrypted_indices(zip_path)?;
        Ok(!encrypted.is_empty())
    }

    fn try_password(zip_path: &str, password: &str) -> bool {
        let encrypted_indices = match Self::get_encrypted_indices(zip_path) {
            Ok(indices) => indices,
            Err(_) => return false,
        };

        if encrypted_indices.is_empty() {
            return true;
        }

        let file = match File::open(zip_path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        
        let reader = BufReader::new(file);
        let mut archive = match ZipArchive::new(reader) {
            Ok(a) => a,
            Err(_) => return false,
        };

        let pwd_bytes = password.as_bytes();

        for i in &encrypted_indices {
            let mut file = match archive.by_index_decrypt(*i, pwd_bytes) {
                Ok(f) => f,
                Err(_) => return false,
            };

            let mut buffer = Vec::new();
            match file.read_to_end(&mut buffer) {
                Ok(_) => {}
                Err(_) => return false,
            }
        }

        true
    }

    pub fn brute_force(
        zip_path: &str,
        mode: &str,
        dictionary_path: Option<&str>,
    ) -> Result<ZipBruteForceResult> {
        let start = std::time::Instant::now();
        let mut attempts: u64 = 0;

        let passwords: Vec<String> = match mode {
            "dictionary" => {
                let dict_path = dictionary_path.ok_or_else(|| {
                    ToolError::ExecutionError("Dictionary path is required for dictionary mode".to_string())
                })?;
                let file = File::open(dict_path)
                    .map_err(|e| ToolError::NetworkError(e))?;
                let reader = BufReader::new(file);
                reader.lines()
                    .filter_map(|line| line.ok())
                    .filter(|line| !line.is_empty())
                    .collect()
            }
            "common" => {
                const COMMON_PASSWORDS: &[&str] = &[
                    "password", "123456", "12345678", "1234", "qwerty",
                    "12345", "dragon", "baseball", "football",
                    "letmein", "monkey", "696969", "abc123", "mustang",
                    "michael", "shadow", "master", "jennifer", "111111",
                    "2000", "jordan", "superman", "harley",
                    "hunter", "trustno1", "ranger", "buster",
                    "thomas", "tigger", "robert", "soccer",
                    "batman", "test", "pass", "killer", "hockey",
                    "george", "charlie", "andrew", "michelle", "love",
                    "sunshine", "jessica", "pepper", "daniel", "access",
                    "123456789", "654321", "joshua", "maggie", "starwars",
                    "silver", "william", "dallas", "yankees", "123123",
                    "ashley", "666666", "hello", "amanda", "orange",
                    "biteme", "freedom", "computer", "thunder",
                    "nicole", "ginger", "heather", "hammer", "summer",
                    "corvette", "taylor", "austin", "1111",
                    "merlin", "matthew", "121212", "golf", "cheese",
                    "princess", "martin", "chelsea", "patrick", "richard",
                    "diamond", "yellow", "bigdog", "secret", "asdfgh",
                    "sparky", "cowboy", "camaro", "anthony", "matrix",
                    "falcon", "iloveyou", "bailey", "guitar", "jackson",
                    "purple", "scooter", "phoenix", "aaaaaa", "morgan",
                    "tigers", "porsche", "mickey", "maverick", "cookie",
                    "nascar", "peanut", "justin", "131313", "money",
                    "samurai", "snoopy", "rachel", "power", "knight",
                    "admin", "root", "welcome", "login", "qwerty123",
                    "password1", "password123", "changeme", "welcome1",
                    "1234567890", "0987654321", "abc1234", "test123",
                    "master1", "admin123", "letmein1", "welcome123",
                ];
                COMMON_PASSWORDS.iter().map(|s| s.to_string()).collect()
            }
            "numeric" => {
                let mut passwords = Vec::new();
                for len in 1..=6 {
                    let max = 10u32.pow(len);
                    for n in 0..max {
                        passwords.push(format!("{:0>width$}", n, width = len as usize));
                    }
                }
                passwords
            }
            _ => {
                return Err(ToolError::ExecutionError(format!("Unknown brute force mode: {}", mode)));
            }
        };

        for pwd in &passwords {
            attempts += 1;
            if Self::try_password(zip_path, pwd) {
                return Ok(ZipBruteForceResult {
                    success: true,
                    password: Some(pwd.clone()),
                    attempts,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: None,
                });
            }
        }

        Ok(ZipBruteForceResult {
            success: false,
            password: None,
            attempts,
            elapsed_ms: start.elapsed().as_millis() as u64,
            error: None,
        })
    }
}

pub fn list_zip_files(zip_path: String) -> Result<Vec<ZipFileInfo>> {
    ZipExtractor::list_files(&zip_path)
}

pub fn extract_zip(zip_path: String, output_dir: String, password: Option<String>) -> Result<ZipExtractResult> {
    ZipExtractor::extract_with_password(&zip_path, &output_dir, password.as_deref())
}

pub fn check_zip_encryption(zip_path: String) -> Result<bool> {
    ZipExtractor::check_encryption(&zip_path)
}

pub fn brute_force_zip(zip_path: String, mode: String, dictionary_path: Option<String>) -> Result<ZipBruteForceResult> {
    ZipExtractor::brute_force(&zip_path, &mode, dictionary_path.as_deref())
}
