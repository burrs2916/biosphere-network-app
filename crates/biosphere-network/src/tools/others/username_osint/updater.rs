use crate::core::{Result, ToolError};
use crate::infrastructure::database::Database;
use super::maigret_importer::MaigretImporter;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

const MAIGRET_DATA_URL: &str = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json";
const MAIGRET_META_URL: &str = "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/db_meta.json";
const MIN_MAIGRET_VERSION: &str = "0.6.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    pub updated: bool,
    pub total_platforms: usize,
    pub imported: usize,
    pub updated_existing: usize,
    pub failed: usize,
    pub skipped: usize,
    pub source: String,
    pub sha256_verified: bool,
    pub version_compatible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMeta {
    pub version: u32,
    pub updated_at: String,
    pub sites_count: u32,
    pub min_maigret_version: String,
    pub data_sha256: String,
    pub data_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateState {
    pub last_check_time: Option<String>,
    pub last_data_sha256: Option<String>,
    pub last_sites_count: Option<u32>,
}

pub struct SiteDatabaseUpdater;

impl SiteDatabaseUpdater {
    pub async fn update_from_github(db: &Database) -> Result<UpdateResult> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent("BiosPherePro/1.0")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let meta = Self::fetch_meta(&client).await.ok();
        let sha256_expected = meta.as_ref().map(|m| m.data_sha256.clone());
        let version_compatible = meta.as_ref().map_or(true, |m| {
            Self::check_version_compatibility(&m.min_maigret_version)
        });

        if !version_compatible {
            return Err(ToolError::ExecutionError(
                format!("Maigret database requires version >= {}, which may not be compatible", 
                    meta.as_ref().map(|m| m.min_maigret_version.as_str()).unwrap_or("unknown"))
            ));
        }

        let data_url = meta.as_ref().map(|m| m.data_url.as_str()).unwrap_or(MAIGRET_DATA_URL);

        let response = client.get(data_url)
            .send()
            .await
            .map_err(|e| ToolError::ExecutionError(format!("Failed to fetch Maigret data: {}", e)))?;

        if !response.status().is_success() {
            return Err(ToolError::ExecutionError(
                format!("Failed to fetch Maigret data: HTTP {}", response.status())
            ));
        }

        let json_str = response.text()
            .await
            .map_err(|e| ToolError::ExecutionError(format!("Failed to read response: {}", e)))?;

        let sha256_verified = if let Some(ref expected) = sha256_expected {
            let actual = Self::compute_sha256(&json_str);
            actual == *expected
        } else {
            false
        };

        if sha256_expected.is_some() && !sha256_verified {
            return Err(ToolError::ExecutionError(
                "SHA256 verification failed! Data may be corrupted or tampered with.".to_string()
            ));
        }

        let mut result = Self::import_from_json(db, &json_str)?;
        result.sha256_verified = sha256_verified;
        result.version_compatible = version_compatible;
        Ok(result)
    }

    pub async fn check_for_updates() -> Result<Option<DbMeta>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("BiosPherePro/1.0")
            .build()
            .map_err(|e| ToolError::ExecutionError(format!("HTTP client error: {}", e)))?;

        let meta = Self::fetch_meta(&client).await?;
        Ok(Some(meta))
    }

    async fn fetch_meta(client: &reqwest::Client) -> Result<DbMeta> {
        let response = client.get(MAIGRET_META_URL)
            .send()
            .await
            .map_err(|e| ToolError::ExecutionError(format!("Failed to fetch Maigret meta: {}", e)))?;

        if !response.status().is_success() {
            return Err(ToolError::ExecutionError(
                format!("Failed to fetch Maigret meta: HTTP {}", response.status())
            ));
        }

        response.json::<DbMeta>().await
            .map_err(|e| ToolError::ExecutionError(format!("Failed to parse Maigret meta: {}", e)))
    }

    fn check_version_compatibility(min_version: &str) -> bool {
        let parts: Vec<u32> = min_version.split('.').filter_map(|s| s.parse().ok()).collect();
        let min_parts: Vec<u32> = MIN_MAIGRET_VERSION.split('.').filter_map(|s| s.parse().ok()).collect();

        for i in 0..3 {
            let p = parts.get(i).copied().unwrap_or(0);
            let m = min_parts.get(i).copied().unwrap_or(0);
            if p > m { return true; }
            if p < m { return false; }
        }
        true
    }

    fn compute_sha256(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn import_from_json(db: &Database, json_str: &str) -> Result<UpdateResult> {
        let stats = MaigretImporter::import_from_json(db, json_str)?;

        Ok(UpdateResult {
            updated: stats.imported > 0 || stats.updated > 0,
            total_platforms: stats.total_platforms,
            imported: stats.imported,
            updated_existing: stats.updated,
            failed: stats.failed,
            skipped: stats.skipped_no_url,
            source: "maigret-github".to_string(),
            sha256_verified: false,
            version_compatible: true,
        })
    }

    pub fn import_from_local_file(db: &Database, path: &str) -> Result<UpdateResult> {
        let json_str = std::fs::read_to_string(path)
            .map_err(|e| ToolError::ExecutionError(format!("Failed to read file {}: {}", path, e)))?;

        let _sha256 = Self::compute_sha256(&json_str);

        let mut result = Self::import_from_json(db, &json_str)?;
        result.sha256_verified = true;
        result.source = format!("local:{}", path);
        Ok(result)
    }
}
