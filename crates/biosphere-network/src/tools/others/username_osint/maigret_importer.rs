use crate::core::{Result, ToolError};
use crate::infrastructure::database::models::OsintPlatform;
use crate::infrastructure::database::Database;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct MaigretData {
    sites: HashMap<String, MaigretSite>,
    #[serde(default)]
    engines: HashMap<String, MaigretEngine>,
}

#[derive(Debug, Deserialize)]
struct MaigretSite {
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "urlMain")]
    url_main: Option<String>,
    #[serde(default, rename = "urlProbe")]
    url_probe: Option<String>,
    #[serde(default, rename = "urlSubpath")]
    url_subpath: Option<String>,
    #[serde(default, rename = "checkType")]
    check_type: Option<String>,
    #[serde(default, rename = "errorType")]
    error_type: Option<String>,
    #[serde(default)]
    errors: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, rename = "presenseStrs")]
    presence_strs: Option<Vec<String>>,
    #[serde(default, rename = "absenceStrs")]
    absence_strs: Option<Vec<String>>,
    #[serde(default, rename = "regexCheck")]
    regex_check: Option<String>,
    #[serde(default, rename = "requestMethod")]
    request_method: Option<String>,
    #[serde(default, rename = "requestHeadOnly")]
    request_head_only: Option<bool>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    payload: Option<HashMap<String, String>>,
    #[serde(default, rename = "GETParams")]
    get_params: Option<HashMap<String, String>>,
    #[serde(default)]
    activation: Option<MaigretActivation>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default, rename = "idType")]
    id_type: Option<String>,
    #[serde(default, rename = "similarSearch")]
    similar_search: Option<bool>,
    #[serde(default, rename = "ignore403")]
    ignore403: Option<bool>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    protection: Option<Vec<String>>,
    #[serde(default)]
    engine: Option<String>,
    #[serde(default, rename = "usernameClaimed")]
    username_claimed: Option<String>,
    #[serde(default, rename = "usernameUnclaimed")]
    username_unclaimed: Option<String>,
    #[serde(default, rename = "alexaRank")]
    alexa_rank: Option<i64>,
    #[serde(default)]
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MaigretEngine {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    site: Option<MaigretEngineSite>,
    #[serde(default, rename = "presenseStrs")]
    presence_strs: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct MaigretEngineSite {
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "urlMain")]
    url_main: Option<String>,
    #[serde(default, rename = "urlProbe")]
    url_probe: Option<String>,
    #[serde(default, rename = "urlSubpath")]
    url_subpath: Option<String>,
    #[serde(default, rename = "checkType")]
    check_type: Option<String>,
    #[serde(default, rename = "errorType")]
    error_type: Option<String>,
    #[serde(default)]
    errors: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, rename = "presenseStrs")]
    presence_strs: Option<Vec<String>>,
    #[serde(default, rename = "absenceStrs")]
    absence_strs: Option<Vec<String>>,
    #[serde(default, rename = "regexCheck")]
    regex_check: Option<String>,
    #[serde(default, rename = "requestMethod")]
    request_method: Option<String>,
    #[serde(default, rename = "requestHeadOnly")]
    request_head_only: Option<bool>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    payload: Option<HashMap<String, String>>,
    #[serde(default, rename = "GETParams")]
    get_params: Option<HashMap<String, String>>,
    #[serde(default)]
    activation: Option<MaigretActivation>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default, rename = "idType")]
    id_type: Option<String>,
    #[serde(default, rename = "similarSearch")]
    similar_search: Option<bool>,
    #[serde(default, rename = "ignore403")]
    ignore403: Option<bool>,
    #[serde(default)]
    protection: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MaigretActivation {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    payload: Option<HashMap<String, String>>,
    #[serde(default, rename = "GETParams")]
    get_params: Option<HashMap<String, String>>,
}

pub struct MaigretImporter;

impl MaigretImporter {
    pub fn import_from_json(db: &Database, json_str: &str) -> Result<ImportStats> {
        let data: MaigretData = serde_json::from_str(json_str)
            .map_err(|e| ToolError::ExecutionError(format!("Failed to parse Maigret data.json: {}", e)))?;

        let mut stats = ImportStats::default();
        let mut platforms = Vec::new();

        for (name, site) in &data.sites {
            let engine_data = site.engine.as_ref()
                .and_then(|e| data.engines.get(e));

            let platform = Self::convert_site(name, site, engine_data);
            if let Some(p) = platform {
                platforms.push(p);
                stats.total_parsed += 1;
            } else {
                stats.skipped_no_url += 1;
            }
        }

        stats.total_platforms = platforms.len();

        for p in &platforms {
            match db.create_osint_platform(p) {
                Ok(_) => stats.imported += 1,
                Err(e) => {
                    if e.to_string().contains("UNIQUE constraint") {
                        match db.update_osint_platform(p) {
                            Ok(_) => stats.updated += 1,
                            Err(_) => stats.failed += 1,
                        }
                    } else {
                        stats.failed += 1;
                    }
                }
            }
        }

        Ok(stats)
    }

    pub fn parse_platforms_from_json(json_str: &str) -> Result<Vec<OsintPlatform>> {
        let data: MaigretData = serde_json::from_str(json_str)
            .map_err(|e| ToolError::ExecutionError(format!("Failed to parse Maigret data.json: {}", e)))?;

        let mut platforms = Vec::new();

        for (name, site) in &data.sites {
            let engine_data = site.engine.as_ref()
                .and_then(|e| data.engines.get(e));

            if let Some(p) = Self::convert_site(name, site, engine_data) {
                platforms.push(p);
            }
        }

        Ok(platforms)
    }

    fn convert_site(
        name: &str,
        site: &MaigretSite,
        engine: Option<&MaigretEngine>,
    ) -> Option<OsintPlatform> {
        let engine_site = engine.and_then(|e| e.site.as_ref());

        let url = site.url.as_deref()
            .or_else(|| engine_site.and_then(|es| es.url.as_deref()))
            .or(site.url_main.as_deref())?;

        let url_template = url.to_string();
        let url_main = site.url_main.as_deref()
            .or_else(|| engine_site.and_then(|es| es.url_main.as_deref()))
            .map(|s| s.to_string());

        let url_probe = site.url_probe.as_deref()
            .or_else(|| engine_site.and_then(|es| es.url_probe.as_deref()))
            .map(|s| s.to_string());

        let url_subpath = site.url_subpath.as_deref()
            .or_else(|| engine_site.and_then(|es| es.url_subpath.as_deref()))
            .map(|s| s.to_string());

        let check_type = site.check_type.as_deref()
            .or_else(|| engine_site.and_then(|es| es.check_type.as_deref()))
            .unwrap_or("status_code")
            .to_string();

        let error_type = site.error_type.as_deref()
            .or_else(|| engine_site.and_then(|es| es.error_type.as_deref()))
            .unwrap_or("status_code")
            .to_string();

        let presence_strs = site.presence_strs.as_ref()
            .or_else(|| engine_site.and_then(|es| es.presence_strs.as_ref()))
            .and_then(|v| serde_json::to_string(v).ok());

        let absence_strs = site.absence_strs.as_ref()
            .or_else(|| engine_site.and_then(|es| es.absence_strs.as_ref()))
            .and_then(|v| serde_json::to_string(v).ok());

        let regex_check = site.regex_check.as_deref()
            .or_else(|| engine_site.and_then(|es| es.regex_check.as_deref()))
            .map(|s| s.to_string());

        let request_method = site.request_method.as_deref()
            .or_else(|| engine_site.and_then(|es| es.request_method.as_deref()))
            .unwrap_or("GET")
            .to_string();

        let request_head_only = site.request_head_only
            .or_else(|| engine_site.and_then(|es| es.request_head_only))
            .unwrap_or(false);

        let headers = site.headers.as_ref()
            .or_else(|| engine_site.and_then(|es| es.headers.as_ref()))
            .and_then(|h| serde_json::to_string(h).ok());

        let payload = site.payload.as_ref()
            .or_else(|| engine_site.and_then(|es| es.payload.as_ref()))
            .and_then(|p| serde_json::to_string(p).ok());

        let get_params = site.get_params.as_ref()
            .or_else(|| engine_site.and_then(|es| es.get_params.as_ref()))
            .and_then(|p| serde_json::to_string(p).ok());

        let activation = site.activation.as_ref()
            .or_else(|| engine_site.and_then(|es| es.activation.as_ref()))
            .and_then(|a| serde_json::to_string(a).ok());

        let errors = site.errors.as_ref()
            .or_else(|| engine_site.and_then(|es| es.errors.as_ref()))
            .and_then(|e| serde_json::to_string(e).ok());

        let tags = site.tags.as_ref()
            .or_else(|| engine_site.and_then(|es| es.tags.as_ref()))
            .and_then(|t| serde_json::to_string(t).ok());

        let id_type = site.id_type.as_deref()
            .or_else(|| engine_site.and_then(|es| es.id_type.as_deref()))
            .unwrap_or("username")
            .to_string();

        let similar_search = site.similar_search
            .or_else(|| engine_site.and_then(|es| es.similar_search))
            .unwrap_or(false);

        let ignore403 = site.ignore403
            .or_else(|| engine_site.and_then(|es| es.ignore403))
            .unwrap_or(false);

        let disabled = site.disabled.unwrap_or(false);

        let protection = site.protection.as_ref()
            .or_else(|| engine_site.and_then(|es| es.protection.as_ref()))
            .and_then(|p| serde_json::to_string(p).ok());

        let engine_name = site.engine.clone();

        let engine_data_json = engine.map(|e| {
            serde_json::json!({
                "name": e.name,
                "presence_strs": e.presence_strs,
                "site": e.site.as_ref().map(|s| serde_json::json!({
                    "url": s.url,
                    "urlMain": s.url_main,
                    "checkType": s.check_type,
                    "errorType": s.error_type,
                    "presenseStrs": s.presence_strs,
                    "absenceStrs": s.absence_strs,
                })),
            })
        }).and_then(|v| serde_json::to_string(&v).ok());

        let username_claimed = site.username_claimed.clone();
        let username_unclaimed = site.username_unclaimed.clone();
        let alexa_rank = site.alexa_rank;

        let category = site.category.as_deref()
            .or_else(|| site.tags.as_ref().and_then(|t| t.first().map(|s| s.as_str())))
            .unwrap_or("other")
            .to_string();

        let display_name = Some(name.to_string());

        let now = Utc::now();

        Some(OsintPlatform {
            id: None,
            name: name.to_string(),
            display_name,
            category,
            url_template,
            url_main,
            url_probe,
            url_subpath,
            check_type,
            error_type,
            error_codes: None,
            error_messages: None,
            error_url: None,
            presence_strs,
            absence_strs,
            regex_check,
            request_method,
            request_head_only,
            headers,
            payload,
            get_params,
            activation,
            errors,
            tags,
            id_type,
            similar_search,
            ignore403,
            disabled,
            protection,
            engine: engine_name,
            engine_data: engine_data_json,
            username_claimed,
            username_unclaimed,
            alexa_rank,
            is_active: !disabled,
            is_built_in: false,
            priority: alexa_rank.map(|r| (100000 - r).max(0) as i32).unwrap_or(0),
            notes: None,
            source: Some("maigret".to_string()),
            created_at: now,
            updated_at: now,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportStats {
    pub total_parsed: usize,
    pub total_platforms: usize,
    pub imported: usize,
    pub updated: usize,
    pub failed: usize,
    pub skipped_no_url: usize,
}
