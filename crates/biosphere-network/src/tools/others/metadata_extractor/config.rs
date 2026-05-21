use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataExtractConfig {
    pub file_path: String,
    pub extract_exif: bool,
    pub extract_pdf: bool,
    pub extract_office: bool,
    pub extract_image: bool,
}

impl Default for MetadataExtractConfig {
    fn default() -> Self {
        Self {
            file_path: String::new(),
            extract_exif: true,
            extract_pdf: true,
            extract_office: true,
            extract_image: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataExtractResult {
    pub success: bool,
    pub file_type: String,
    pub file_size: u64,
    pub metadata: Vec<MetadataItem>,
    pub sensitive_findings: Vec<SensitiveFinding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataItem {
    pub key: String,
    pub value: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveFinding {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub value: String,
    pub recommendation: String,
}

pub struct MetadataExtractorTool;

impl MetadataExtractorTool {
    pub async fn extract(config: &MetadataExtractConfig) -> std::result::Result<MetadataExtractResult, String> {
        if config.file_path.is_empty() {
            return Err("File path is required".to_string());
        }

        let path = Path::new(&config.file_path);
        if !path.exists() {
            return Err(format!("File not found: {}", config.file_path));
        }

        let file_meta = path.metadata().map_err(|e| format!("Failed to read file metadata: {}", e))?;
        let file_size = file_meta.len();
        let file_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let extension = path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let (file_type, metadata, sensitive_findings) = Self::analyze_file(
            &extension,
            &file_name,
            file_size,
            path,
            config,
        ).await;

        let sensitive_count = sensitive_findings.len();
        let high_count = sensitive_findings.iter().filter(|f| f.severity == "high").count();
        let medium_count = sensitive_findings.iter().filter(|f| f.severity == "medium").count();

        let summary = if sensitive_count == 0 {
            format!("File {} ({}) analyzed, no sensitive metadata found", file_name, file_type)
        } else {
            format!(
                "File {} ({}) analyzed, {} sensitive items found (high: {}, medium: {})",
                file_name, file_type, sensitive_count, high_count, medium_count
            )
        };

        Ok(MetadataExtractResult {
            success: true,
            file_type,
            file_size,
            metadata,
            sensitive_findings,
            summary,
        })
    }

    async fn analyze_file(
        extension: &str,
        file_name: &str,
        file_size: u64,
        path: &Path,
        config: &MetadataExtractConfig,
    ) -> (String, Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive_findings = Vec::new();
        let file_type;

        metadata.push(MetadataItem {
            key: "Filename".to_string(),
            value: file_name.to_string(),
            category: "Basic".to_string(),
        });
        metadata.push(MetadataItem {
            key: "File Size".to_string(),
            value: format!("{} bytes ({:.2} KB)", file_size, file_size as f64 / 1024.0),
            category: "Basic".to_string(),
        });
        metadata.push(MetadataItem {
            key: "Extension".to_string(),
            value: if extension.is_empty() { "none".to_string() } else { format!(".{}", extension) },
            category: "Basic".to_string(),
        });

        if let Ok(file_meta) = path.metadata() {
            if let Ok(created) = file_meta.created() {
                if let Ok(dur) = created.duration_since(UNIX_EPOCH) {
                    metadata.push(MetadataItem {
                        key: "Created".to_string(),
                        value: format_timestamp(dur.as_secs()),
                        category: "Basic".to_string(),
                    });
                }
            }
            if let Ok(modified) = file_meta.modified() {
                if let Ok(dur) = modified.duration_since(UNIX_EPOCH) {
                    metadata.push(MetadataItem {
                        key: "Modified".to_string(),
                        value: format_timestamp(dur.as_secs()),
                        category: "Basic".to_string(),
                    });
                }
            }
            if let Ok(accessed) = file_meta.accessed() {
                if let Ok(dur) = accessed.duration_since(UNIX_EPOCH) {
                    metadata.push(MetadataItem {
                        key: "Accessed".to_string(),
                        value: format_timestamp(dur.as_secs()),
                        category: "Basic".to_string(),
                    });
                }
            }
            metadata.push(MetadataItem {
                key: "Read-Only".to_string(),
                value: if file_meta.permissions().readonly() { "Yes" } else { "No" }.to_string(),
                category: "Basic".to_string(),
            });
        }

        match extension.as_ref() {
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "webp" => {
                file_type = "Image".to_string();
                if config.extract_image || config.extract_exif {
                    let (img_meta, img_sensitive) = Self::analyze_image(path, extension, file_size);
                    metadata.extend(img_meta);
                    sensitive_findings.extend(img_sensitive);
                }
            }
            "pdf" => {
                file_type = "PDF Document".to_string();
                if config.extract_pdf {
                    let (pdf_meta, pdf_sensitive) = Self::analyze_pdf(path, file_size);
                    metadata.extend(pdf_meta);
                    sensitive_findings.extend(pdf_sensitive);
                }
            }
            "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" => {
                file_type = "Office Document".to_string();
                if config.extract_office {
                    let (office_meta, office_sensitive) = Self::analyze_office(path, extension, file_size);
                    metadata.extend(office_meta);
                    sensitive_findings.extend(office_sensitive);
                }
            }
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" => {
                file_type = "Archive".to_string();
                let (archive_meta, archive_sensitive) = Self::analyze_archive(path, extension, file_size);
                metadata.extend(archive_meta);
                sensitive_findings.extend(archive_sensitive);
            }
            "exe" | "dll" | "so" | "dylib" | "app" | "deb" | "rpm" => {
                file_type = "Executable".to_string();
                let (exe_meta, exe_sensitive) = Self::analyze_executable(path, extension, file_size);
                metadata.extend(exe_meta);
                sensitive_findings.extend(exe_sensitive);
            }
            "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" | "wma" => {
                file_type = "Audio".to_string();
                let (audio_meta, audio_sensitive) = Self::analyze_audio(path, extension, file_size);
                metadata.extend(audio_meta);
                sensitive_findings.extend(audio_sensitive);
            }
            "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" => {
                file_type = "Video".to_string();
                let (video_meta, video_sensitive) = Self::analyze_video(path, extension, file_size);
                metadata.extend(video_meta);
                sensitive_findings.extend(video_sensitive);
            }
            "html" | "htm" | "js" | "css" | "json" | "xml" | "svg" => {
                file_type = "Web File".to_string();
                let (web_meta, web_sensitive) = Self::analyze_web(path, extension, file_size);
                metadata.extend(web_meta);
                sensitive_findings.extend(web_sensitive);
            }
            "txt" | "md" | "log" | "csv" | "rtf" | "ini" | "cfg" | "conf" => {
                file_type = "Text File".to_string();
                let (text_meta, text_sensitive) = Self::analyze_text(path, extension, file_size);
                metadata.extend(text_meta);
                sensitive_findings.extend(text_sensitive);
            }
            _ => {
                file_type = format!("Unknown (.{})", extension);
                let (generic_meta, generic_sensitive) = Self::analyze_generic(path, file_size);
                metadata.extend(generic_meta);
                sensitive_findings.extend(generic_sensitive);
            }
        }

        (file_type, metadata, sensitive_findings)
    }

    fn analyze_image(path: &Path, extension: &str, file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        metadata.push(MetadataItem { key: "Format".to_string(), value: extension.to_uppercase(), category: "Image".to_string() });

        if let Ok(exif_output) = std::process::Command::new("exiftool").arg(path).output() {
            if exif_output.status.success() {
                let output = String::from_utf8_lossy(&exif_output.stdout);
                for line in output.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        let key = k.trim().to_string();
                        let val = v.trim().to_string();
                        if val.is_empty() { continue; }

                        let category = if key.starts_with("EXIF") || key.contains("Exposure") || key.contains("ISO") ||
                            key.contains("Focal") || key.contains("Aperture") || key.contains("Shutter") ||
                            key.contains("White Balance") || key.contains("Flash") {
                            "EXIF".to_string()
                        } else if key.contains("GPS") || key.contains("Location") {
                            "EXIF".to_string()
                        } else if key.contains("Make") || key.contains("Camera") || key.contains("Model") ||
                            key.contains("Lens") || key.contains("Software") {
                            "Image".to_string()
                        } else {
                            "Image".to_string()
                        };

                        let key_lower = key.to_lowercase();
                        let val_trimmed = v.trim().to_string();
                        metadata.push(MetadataItem { key, value: val, category });

                        if key_lower.contains("gps") || key_lower.contains("gps latitude") || key_lower.contains("gps longitude") {
                            sensitive.push(SensitiveFinding {
                                severity: "high".to_string(),
                                category: "GPS Location".to_string(),
                                description: "Image contains GPS coordinate information".to_string(),
                                value: val_trimmed.clone(),
                                recommendation: "Remove GPS metadata before sharing".to_string(),
                            });
                        }
                        if key_lower.contains("make") || key_lower.contains("camera model") {
                            sensitive.push(SensitiveFinding {
                                severity: "medium".to_string(),
                                category: "Device Info".to_string(),
                                description: "Image contains device model information".to_string(),
                                value: val_trimmed.clone(),
                                recommendation: "Remove device info to protect privacy".to_string(),
                            });
                        }
                        if key_lower.contains("owner") || key_lower.contains("author") || key_lower.contains("artist") {
                            sensitive.push(SensitiveFinding {
                                severity: "high".to_string(),
                                category: "Personal Info".to_string(),
                                description: "Image contains owner/author information".to_string(),
                                value: val_trimmed,
                                recommendation: "Remove personal info before sharing".to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            metadata.push(MetadataItem { key: "Note".to_string(), value: "Install exiftool for detailed EXIF extraction".to_string(), category: "System".to_string() });
            if file_size > 500_000 {
                metadata.push(MetadataItem { key: "Estimated Resolution".to_string(), value: "High resolution (large file)".to_string(), category: "Image".to_string() });
            } else {
                metadata.push(MetadataItem { key: "Estimated Resolution".to_string(), value: "Low resolution (small file)".to_string(), category: "Image".to_string() });
            }
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout);
                let desc = desc.trim();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc.to_string(), category: "Image".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_pdf(path: &Path, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        if let Ok(output) = std::process::Command::new("pdfinfo").arg(path).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        let key = k.trim().to_string();
                        let val = v.trim().to_string();
                        if val.is_empty() { continue; }
                        let category = if key.contains("PDF") || key.contains("Page") { "PDF".to_string() } else { "Document".to_string() };

                        let key_lower = key.to_lowercase();
                        metadata.push(MetadataItem { key, value: val.clone(), category });

                        if key_lower.contains("author") {
                            sensitive.push(SensitiveFinding {
                                severity: "high".to_string(),
                                category: "Personal Info".to_string(),
                                description: "PDF contains author name".to_string(),
                                value: val.clone(),
                                recommendation: "Remove author info before publishing".to_string(),
                            });
                        }
                        if key_lower.contains("creator") || key_lower.contains("producer") {
                            sensitive.push(SensitiveFinding {
                                severity: "low".to_string(),
                                category: "Software Info".to_string(),
                                description: "PDF contains creation software info".to_string(),
                                value: val,
                                recommendation: "Consider removing software info".to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(content) = String::from_utf8(bytes.iter().take(8192).cloned().collect::<Vec<u8>>()) {
                    for line in content.lines() {
                        let line = line.trim();
                        if line.starts_with('/') {
                            let parsed = if line.contains('(') {
                                line[1..].split_once('(')
                            } else if line.contains('<') {
                                line[1..].split_once('<')
                            } else {
                                None
                            };
                            if let Some((k, v)) = parsed {
                                let key = k.trim_end_matches('/').trim();
                                let val = v.trim_end_matches(')').trim_end_matches('>').trim();
                                if !key.is_empty() && !val.is_empty() && key.len() < 50 && val.len() < 200 {
                                    metadata.push(MetadataItem { key: key.to_string(), value: val.to_string(), category: "PDF".to_string() });
                                }
                            }
                        }
                    }
                }
            }
            metadata.push(MetadataItem { key: "Note".to_string(), value: "Install poppler-utils (pdfinfo) for detailed PDF metadata".to_string(), category: "System".to_string() });
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "PDF".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_office(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        let doc_type = match extension {
            "doc" | "docx" => "Word Document",
            "xls" | "xlsx" => "Excel Spreadsheet",
            "ppt" | "pptx" => "PowerPoint Presentation",
            "odt" => "OpenDocument Text",
            "ods" => "OpenDocument Spreadsheet",
            _ => "Office Document",
        };
        metadata.push(MetadataItem { key: "Document Type".to_string(), value: doc_type.to_string(), category: "Document".to_string() });

        if let Ok(output) = std::process::Command::new("exiftool").arg(path).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        let key = k.trim().to_string();
                        let val = v.trim().to_string();
                        if val.is_empty() { continue; }
                        let category = if key.contains("Page") || key.contains("Word") || key.contains("Sheet") {
                            "Document".to_string()
                        } else {
                            "Document".to_string()
                        };

                        let key_lower = key.to_lowercase();
                        metadata.push(MetadataItem { key, value: val.clone(), category });

                        if key_lower.contains("author") || key_lower.contains("creator") {
                            sensitive.push(SensitiveFinding {
                                severity: "high".to_string(),
                                category: "Personal Info".to_string(),
                                description: "Document contains author name".to_string(),
                                value: val.clone(),
                                recommendation: "Remove author info before sharing".to_string(),
                            });
                        }
                        if key_lower.contains("last modified by") || key_lower.contains("modifier") {
                            sensitive.push(SensitiveFinding {
                                severity: "high".to_string(),
                                category: "Personal Info".to_string(),
                                description: "Document contains last modifier name".to_string(),
                                value: val.clone(),
                                recommendation: "Remove modifier info before sharing".to_string(),
                            });
                        }
                        if key_lower.contains("revision") || key_lower.contains("edit time") {
                            sensitive.push(SensitiveFinding {
                                severity: "medium".to_string(),
                                category: "Revision History".to_string(),
                                description: "Document contains revision history".to_string(),
                                value: val.clone(),
                                recommendation: "Accept all revisions and clear history".to_string(),
                            });
                        }
                        if key_lower.contains("template") {
                            sensitive.push(SensitiveFinding {
                                severity: "medium".to_string(),
                                category: "Template Path".to_string(),
                                description: "Document contains template path info".to_string(),
                                value: val,
                                recommendation: "Remove template path info".to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            if extension == "docx" || extension == "xlsx" || extension == "pptx" ||
               extension == "ods" || extension == "odt" {
                if let Ok(bytes) = std::fs::read(path) {
                    if let Ok(content) = String::from_utf8(bytes.iter().take(65536).cloned().collect::<Vec<u8>>()) {
                        for tag in ["dc:creator", "dc:title", "dc:subject", "dc:description",
                                    "meta:initial-creator", "meta:creation-date", "dc:date",
                                    "cp:lastModifiedBy", "dcterms:created", "dcterms:modified",
                                    "Application", "Company", "Manager"] {
                            if let Some(start) = content.find(&format!("<{}>", tag)) {
                                let start = start + tag.len() + 2;
                                if let Some(end) = content[start..].find(&format!("</{}>", tag)) {
                                    let val = content[start..start+end].trim().to_string();
                                    if !val.is_empty() && val.len() < 200 {
                                        metadata.push(MetadataItem { key: tag.to_string(), value: val, category: "Document".to_string() });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            metadata.push(MetadataItem { key: "Note".to_string(), value: "Install exiftool for detailed Office metadata".to_string(), category: "System".to_string() });
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "Document".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_archive(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        metadata.push(MetadataItem { key: "Archive Format".to_string(), value: extension.to_uppercase(), category: "Archive".to_string() });

        match extension {
            "zip" => {
                if let Ok(output) = std::process::Command::new("unzip").args(["-l", &path.to_string_lossy()]).output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        let file_count = text.lines().count().saturating_sub(3);
                        metadata.push(MetadataItem { key: "File Count".to_string(), value: file_count.to_string(), category: "Archive".to_string() });
                        for line in text.lines().skip(3).take(5) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 4 {
                                let name = parts[3..].join(" ");
                                metadata.push(MetadataItem { key: "Contains".to_string(), value: name, category: "Archive".to_string() });
                            }
                        }
                        if file_count > 5 {
                            metadata.push(MetadataItem { key: "More Files".to_string(), value: format!("... and {} more", file_count - 5), category: "Archive".to_string() });
                        }
                    }
                }
                if let Ok(output) = std::process::Command::new("zipinfo").args(["-t", &path.to_string_lossy()]).output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        for line in text.lines() {
                            if line.contains("bytes") {
                                metadata.push(MetadataItem { key: "Uncompressed Size".to_string(), value: line.trim().to_string(), category: "Archive".to_string() });
                            }
                        }
                    }
                }
            }
            "tar" | "gz" | "tgz" | "bz2" | "xz" => {
                if let Ok(output) = std::process::Command::new("tar").args(["-tf", &path.to_string_lossy()]).output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        let files: Vec<&str> = text.lines().collect();
                        metadata.push(MetadataItem { key: "File Count".to_string(), value: files.len().to_string(), category: "Archive".to_string() });
                        for f in files.iter().take(5) {
                            metadata.push(MetadataItem { key: "Contains".to_string(), value: f.to_string(), category: "Archive".to_string() });
                        }
                        if files.len() > 5 {
                            metadata.push(MetadataItem { key: "More Files".to_string(), value: format!("... and {} more", files.len() - 5), category: "Archive".to_string() });
                        }
                    }
                }
            }
            "rar" => {
                if let Ok(output) = std::process::Command::new("unrar").args(["l", &path.to_string_lossy()]).output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        let file_count = text.lines().count().saturating_sub(6);
                        metadata.push(MetadataItem { key: "File Count".to_string(), value: file_count.to_string(), category: "Archive".to_string() });
                    }
                }
            }
            "7z" => {
                if let Ok(output) = std::process::Command::new("7z").args(["l", &path.to_string_lossy()]).output() {
                    if output.status.success() {
                        let text = String::from_utf8_lossy(&output.stdout);
                        for line in text.lines() {
                            if line.contains("files") {
                                metadata.push(MetadataItem { key: "Info".to_string(), value: line.trim().to_string(), category: "Archive".to_string() });
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    let desc_lower = desc.to_lowercase();
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "Archive".to_string() });
                    if desc_lower.contains("encrypted") {
                        metadata.push(MetadataItem { key: "Encrypted".to_string(), value: "Yes".to_string(), category: "Archive".to_string() });
                        sensitive.push(SensitiveFinding {
                            severity: "low".to_string(),
                            category: "Encryption".to_string(),
                            description: "Archive is encrypted/password-protected".to_string(),
                            value: "Password-protected archive".to_string(),
                            recommendation: "Note: encrypted archive may contain sensitive data".to_string(),
                        });
                    }
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_executable(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        let platform = match extension {
            "exe" | "dll" => "Windows",
            "so" => "Linux",
            "dylib" | "app" => "macOS",
            "deb" => "Debian Package",
            "rpm" => "RPM Package",
            _ => "Unknown",
        };
        metadata.push(MetadataItem { key: "Platform".to_string(), value: platform.to_string(), category: "Executable".to_string() });

        if let Ok(output) = std::process::Command::new("file").arg(path).output() {
            if output.status.success() {
                let desc = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc.clone(), category: "Executable".to_string() });
                    if desc.contains("x86_64") || desc.contains("x86-64") {
                        metadata.push(MetadataItem { key: "Architecture".to_string(), value: "x86_64".to_string(), category: "Executable".to_string() });
                    } else if desc.contains("ARM") || desc.contains("aarch64") {
                        metadata.push(MetadataItem { key: "Architecture".to_string(), value: "ARM/aarch64".to_string(), category: "Executable".to_string() });
                    } else if desc.contains("64-bit") {
                        metadata.push(MetadataItem { key: "Architecture".to_string(), value: "64-bit".to_string(), category: "Executable".to_string() });
                    } else if desc.contains("32-bit") {
                        metadata.push(MetadataItem { key: "Architecture".to_string(), value: "32-bit".to_string(), category: "Executable".to_string() });
                    }
                    if desc.contains("dynamically linked") {
                        metadata.push(MetadataItem { key: "Linking".to_string(), value: "Dynamic".to_string(), category: "Executable".to_string() });
                    } else if desc.contains("statically linked") {
                        metadata.push(MetadataItem { key: "Linking".to_string(), value: "Static".to_string(), category: "Executable".to_string() });
                    }
                    if desc.contains("stripped") {
                        metadata.push(MetadataItem { key: "Symbols".to_string(), value: "Stripped".to_string(), category: "Executable".to_string() });
                    } else if desc.contains("not stripped") {
                        metadata.push(MetadataItem { key: "Symbols".to_string(), value: "Not Stripped (debug symbols present)".to_string(), category: "Executable".to_string() });
                    }
                }
            }
        }

        if extension == "exe" || extension == "dll" {
            if let Ok(output) = std::process::Command::new("strings").args(["-el", &path.to_string_lossy()]).output() {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        let line = line.trim();
                        if line.contains("CompanyName") || line.contains("FileDescription") ||
                            line.contains("FileVersion") || line.contains("ProductName") ||
                            line.contains("ProductVersion") || line.contains("LegalCopyright") ||
                            line.contains("OriginalFilename") {
                            if let Some((k, v)) = line.split_once('\0').or_else(|| line.split_once(':')) {
                                let key = k.trim().trim_start_matches('\0').to_string();
                                let val = v.trim().trim_start_matches('\0').to_string();
                                if !key.is_empty() && !val.is_empty() {
                                    metadata.push(MetadataItem { key, value: val, category: "Executable".to_string() });
                                }
                            }
                        }
                    }
                }
            }
        }

        if extension == "so" || extension == "dylib" {
            if let Ok(output) = std::process::Command::new("otool").args(["-L", &path.to_string_lossy()]).output() {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines().skip(1).take(10) {
                        let dep = line.trim();
                        if !dep.is_empty() {
                            metadata.push(MetadataItem { key: "Dependency".to_string(), value: dep.to_string(), category: "Executable".to_string() });
                        }
                    }
                }
            }
        }

        sensitive.push(SensitiveFinding {
            severity: "medium".to_string(),
            category: "Code Signing".to_string(),
            description: "Executable file - verify digital signature".to_string(),
            value: "Check code signature before execution".to_string(),
            recommendation: "Verify code signature and file integrity".to_string(),
        });

        (metadata, sensitive)
    }

    fn analyze_audio(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        metadata.push(MetadataItem { key: "Audio Format".to_string(), value: extension.to_uppercase(), category: "Audio".to_string() });

        if let Ok(output) = std::process::Command::new("ffprobe")
            .args(["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", &path.to_string_lossy()])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(format) = json.get("format") {
                        if let Some(duration) = format.get("duration").and_then(|v| v.as_str()) {
                            metadata.push(MetadataItem { key: "Duration".to_string(), value: format!("{}s", duration), category: "Audio".to_string() });
                        }
                        if let Some(bit_rate) = format.get("bit_rate").and_then(|v| v.as_str()) {
                            metadata.push(MetadataItem { key: "Bit Rate".to_string(), value: format!("{} bps", bit_rate), category: "Audio".to_string() });
                        }
                        if let Some(tags) = format.get("tags") {
                            if let Some(obj) = tags.as_object() {
                                for (k, v) in obj {
                                    let val = v.as_str().unwrap_or("");
                                    if !val.is_empty() {
                                        let category = if k.starts_with("ID3") || k == "artist" || k == "album" || k == "title" || k == "genre" || k == "track" || k == "date" {
                                            "ID3".to_string()
                                        } else {
                                            "Audio".to_string()
                                        };
                                        metadata.push(MetadataItem { key: k.clone(), value: val.to_string(), category });

                                        if k == "artist" || k == "composer" || k == "performer" {
                                            sensitive.push(SensitiveFinding {
                                                severity: "low".to_string(),
                                                category: "Artist Info".to_string(),
                                                description: "Audio file contains artist information".to_string(),
                                                value: val.to_string(),
                                                recommendation: "Consider removing personal tags before sharing".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some(streams) = json.get("streams").and_then(|v| v.as_array()) {
                        for stream in streams.iter().take(1) {
                            if let Some(sample_rate) = stream.get("sample_rate").and_then(|v| v.as_str()) {
                                metadata.push(MetadataItem { key: "Sample Rate".to_string(), value: format!("{} Hz", sample_rate), category: "Audio".to_string() });
                            }
                            if let Some(channels) = stream.get("channels").and_then(|v| v.as_i64()) {
                                let ch = if channels == 1 { "Mono" } else if channels == 2 { "Stereo" } else { "Multi-channel" };
                                metadata.push(MetadataItem { key: "Channels".to_string(), value: ch.to_string(), category: "Audio".to_string() });
                            }
                            if let Some(codec) = stream.get("codec_name").and_then(|v| v.as_str()) {
                                metadata.push(MetadataItem { key: "Codec".to_string(), value: codec.to_string(), category: "Audio".to_string() });
                            }
                        }
                    }
                }
            }
        } else {
            metadata.push(MetadataItem { key: "Note".to_string(), value: "Install ffmpeg (ffprobe) for detailed audio metadata".to_string(), category: "System".to_string() });
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "Audio".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_video(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let sensitive = Vec::new();

        metadata.push(MetadataItem { key: "Video Format".to_string(), value: extension.to_uppercase(), category: "Video".to_string() });

        if let Ok(output) = std::process::Command::new("ffprobe")
            .args(["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", &path.to_string_lossy()])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(format) = json.get("format") {
                        if let Some(duration) = format.get("duration").and_then(|v| v.as_str()) {
                            metadata.push(MetadataItem { key: "Duration".to_string(), value: format!("{}s", duration), category: "Video".to_string() });
                        }
                        if let Some(bit_rate) = format.get("bit_rate").and_then(|v| v.as_str()) {
                            metadata.push(MetadataItem { key: "Bit Rate".to_string(), value: format!("{} bps", bit_rate), category: "Video".to_string() });
                        }
                        if let Some(tags) = format.get("tags") {
                            if let Some(obj) = tags.as_object() {
                                for (k, v) in obj {
                                    let val = v.as_str().unwrap_or("");
                                    if !val.is_empty() {
                                        metadata.push(MetadataItem { key: k.clone(), value: val.to_string(), category: "Video".to_string() });
                                    }
                                }
                            }
                        }
                    }
                    if let Some(streams) = json.get("streams").and_then(|v| v.as_array()) {
                        for stream in streams {
                            let stream_type = stream.get("codec_type").and_then(|v| v.as_str()).unwrap_or("unknown");
                            let prefix = if stream_type == "video" { "Video" } else { "Audio" };
                            if let Some(codec) = stream.get("codec_name").and_then(|v| v.as_str()) {
                                metadata.push(MetadataItem { key: format!("{} Codec", prefix), value: codec.to_string(), category: "Video".to_string() });
                            }
                            if stream_type == "video" {
                                if let Some(w) = stream.get("width").and_then(|v| v.as_i64()) {
                                    if let Some(h) = stream.get("height").and_then(|v| v.as_i64()) {
                                        metadata.push(MetadataItem { key: "Resolution".to_string(), value: format!("{}x{}", w, h), category: "Video".to_string() });
                                    }
                                }
                                if let Some(fps) = stream.get("r_frame_rate").and_then(|v| v.as_str()) {
                                    metadata.push(MetadataItem { key: "Frame Rate".to_string(), value: fps.to_string(), category: "Video".to_string() });
                                }
                            }
                        }
                    }
                }
            }
        } else {
            metadata.push(MetadataItem { key: "Note".to_string(), value: "Install ffmpeg (ffprobe) for detailed video metadata".to_string(), category: "System".to_string() });
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "Video".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_web(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        metadata.push(MetadataItem { key: "Web Format".to_string(), value: extension.to_uppercase(), category: "Web".to_string() });

        if let Ok(content) = std::fs::read_to_string(path) {
            let line_count = content.lines().count();
            let char_count = content.len();
            metadata.push(MetadataItem { key: "Lines".to_string(), value: line_count.to_string(), category: "Web".to_string() });
            metadata.push(MetadataItem { key: "Characters".to_string(), value: char_count.to_string(), category: "Web".to_string() });

            if extension == "html" || extension == "htm" {
                let lower = content.to_lowercase();
                if let Some(start) = lower.find("<title>") {
                    if let Some(end) = lower[start..].find("</title>") {
                        let title = content[start+7..start+end].trim().to_string();
                        if !title.is_empty() {
                            metadata.push(MetadataItem { key: "Title".to_string(), value: title, category: "Web".to_string() });
                        }
                    }
                }
                for meta_tag in ["description", "keywords", "author", "generator"] {
                    let pattern = format!("name=\"{}\"", meta_tag);
                    if let Some(pos) = lower.find(&pattern) {
                        let snippet = &content[pos..];
                        if let Some(content_start) = snippet.find("content=\"") {
                            let rest = &snippet[content_start+9..];
                            if let Some(content_end) = rest.find('"') {
                                let val = rest[..content_end].to_string();
                                if !val.is_empty() {
                                    metadata.push(MetadataItem { key: format!("Meta: {}", meta_tag), value: val, category: "Web".to_string() });
                                }
                            }
                        }
                    }
                }
            }

            if extension == "json" {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = json.as_object() {
                        for (k, v) in obj.iter().take(20) {
                            let val = match v {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Number(n) => n.to_string(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                serde_json::Value::Null => "null".to_string(),
                                _ => format!("{:?}", v),
                            };
                            metadata.push(MetadataItem { key: format!("Key: {}", k), value: val, category: "Web".to_string() });
                        }
                    } else if let Some(arr) = json.as_array() {
                        metadata.push(MetadataItem { key: "Array Length".to_string(), value: arr.len().to_string(), category: "Web".to_string() });
                    }
                }
            }

            let lower = content.to_lowercase();
            let sensitive_patterns = [
                ("password", "Password"), ("api_key", "API Key"), ("apikey", "API Key"),
                ("secret", "Secret"), ("token", "Token"), ("private_key", "Private Key"),
                ("authorization", "Authorization"), ("credential", "Credential"),
                ("aws_access_key", "AWS Access Key"), ("aws_secret", "AWS Secret"),
            ];
            for (pattern, label) in sensitive_patterns {
                if lower.contains(pattern) {
                    let context = find_context(&content, pattern, 50);
                    sensitive.push(SensitiveFinding {
                        severity: "high".to_string(),
                        category: "Potential Secret".to_string(),
                        description: format!("File may contain {}", label.to_lowercase()),
                        value: context,
                        recommendation: format!("Review and remove {} before publishing", label.to_lowercase()),
                    });
                }
            }
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "Web".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_text(path: &Path, extension: &str, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let mut sensitive = Vec::new();

        if let Ok(content) = std::fs::read_to_string(path) {
            let line_count = content.lines().count();
            let char_count = content.len();
            let word_count = content.split_whitespace().count();
            metadata.push(MetadataItem { key: "Lines".to_string(), value: line_count.to_string(), category: "Text".to_string() });
            metadata.push(MetadataItem { key: "Characters".to_string(), value: char_count.to_string(), category: "Text".to_string() });
            metadata.push(MetadataItem { key: "Words".to_string(), value: word_count.to_string(), category: "Text".to_string() });

            let lower = content.to_lowercase();
            let sensitive_patterns = [
                ("password", "Password"), ("api_key", "API Key"), ("apikey", "API Key"),
                ("secret", "Secret"), ("token", "Token"), ("private_key", "Private Key"),
                ("email", "Email Address"), ("phone", "Phone Number"),
                ("ssn", "Social Security Number"), ("credit_card", "Credit Card"),
            ];
            for (pattern, label) in sensitive_patterns {
                if lower.contains(pattern) {
                    let context = find_context(&content, pattern, 50);
                    sensitive.push(SensitiveFinding {
                        severity: "high".to_string(),
                        category: "Potential Sensitive Data".to_string(),
                        description: format!("File may contain {}", label.to_lowercase()),
                        value: context,
                        recommendation: format!("Review and protect {} data", label.to_lowercase()),
                    });
                }
            }

            if extension == "csv" {
                if let Some(first_line) = content.lines().next() {
                    let headers: Vec<&str> = first_line.split(',').collect();
                    metadata.push(MetadataItem { key: "Columns".to_string(), value: headers.len().to_string(), category: "Text".to_string() });
                    metadata.push(MetadataItem { key: "Headers".to_string(), value: headers.join(", "), category: "Text".to_string() });
                }
                let row_count = content.lines().count().saturating_sub(1);
                metadata.push(MetadataItem { key: "Rows".to_string(), value: row_count.to_string(), category: "Text".to_string() });
            }
        } else {
            metadata.push(MetadataItem { key: "Encoding".to_string(), value: "Binary/Non-UTF8".to_string(), category: "Text".to_string() });
        }

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "Text".to_string() });
                }
            }
        }

        (metadata, sensitive)
    }

    fn analyze_generic(path: &Path, _file_size: u64) -> (Vec<MetadataItem>, Vec<SensitiveFinding>) {
        let mut metadata = Vec::new();
        let sensitive = Vec::new();

        if let Ok(file_output) = std::process::Command::new("file").arg(path).output() {
            if file_output.status.success() {
                let desc = String::from_utf8_lossy(&file_output.stdout).trim().to_string();
                if !desc.is_empty() {
                    metadata.push(MetadataItem { key: "File Type".to_string(), value: desc, category: "System".to_string() });
                }
            }
        }

        if let Ok(md5_output) = std::process::Command::new("md5sum").arg(path).output() {
            if md5_output.status.success() {
                let hash = String::from_utf8_lossy(&md5_output.stdout);
                if let Some(hash_val) = hash.split_whitespace().next() {
                    metadata.push(MetadataItem { key: "MD5".to_string(), value: hash_val.to_string(), category: "System".to_string() });
                }
            }
        } else if let Ok(md5_output) = std::process::Command::new("md5").arg(path).output() {
            if md5_output.status.success() {
                let hash = String::from_utf8_lossy(&md5_output.stdout);
                if let Some(hash_val) = hash.split_whitespace().next() {
                    metadata.push(MetadataItem { key: "MD5".to_string(), value: hash_val.to_string(), category: "System".to_string() });
                }
            }
        }

        if let Ok(sha_output) = std::process::Command::new("sha256sum").arg(path).output() {
            if sha_output.status.success() {
                let hash = String::from_utf8_lossy(&sha_output.stdout);
                if let Some(hash_val) = hash.split_whitespace().next() {
                    metadata.push(MetadataItem { key: "SHA256".to_string(), value: hash_val.to_string(), category: "System".to_string() });
                }
            }
        } else if let Ok(sha_output) = std::process::Command::new("shasum").args(["-a", "256", &path.to_string_lossy()]).output() {
            if sha_output.status.success() {
                let hash = String::from_utf8_lossy(&sha_output.stdout);
                if let Some(hash_val) = hash.split_whitespace().next() {
                    metadata.push(MetadataItem { key: "SHA256".to_string(), value: hash_val.to_string(), category: "System".to_string() });
                }
            }
        }

        metadata.push(MetadataItem { key: "Note".to_string(), value: "Deep metadata extraction not supported for this file type".to_string(), category: "System".to_string() });

        (metadata, sensitive)
    }
}

fn format_timestamp(secs: u64) -> String {
    let days = secs / 86400;
    let date = chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| format!("{} seconds since epoch", secs));
    format!("{} ({} days ago)", date, days)
}

fn find_context(content: &str, pattern: &str, max_len: usize) -> String {
    let lower = content.to_lowercase();
    if let Some(pos) = lower.find(pattern) {
        let start = pos.saturating_sub(max_len / 2);
        let end = (pos + pattern.len() + max_len / 2).min(content.len());
        let ctx = content[start..end].to_string();
        let ctx = ctx.lines().next().unwrap_or(&ctx).to_string();
        if ctx.len() > max_len {
            format!("{}...", &ctx[..max_len])
        } else {
            ctx
        }
    } else {
        "Found in file".to_string()
    }
}
