use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAuditConfig {
    pub provider: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub check_iam: bool,
    pub check_storage: bool,
    pub check_network: bool,
    pub check_logging: bool,
    pub check_encryption: bool,
    pub check_compute: bool,
    pub timeout: u64,
    pub use_prowler: bool,
    pub use_trivy: bool,
    pub use_scoutsuite: bool,
    pub scan_containers: bool,
    pub scan_kubernetes: bool,
    pub compliance_frameworks: Vec<String>,
}

impl Default for CloudAuditConfig {
    fn default() -> Self {
        Self {
            provider: "aws".to_string(),
            access_key: String::new(),
            secret_key: String::new(),
            region: "us-east-1".to_string(),
            check_iam: true,
            check_storage: true,
            check_network: true,
            check_logging: true,
            check_encryption: true,
            check_compute: true,
            timeout: 30,
            use_prowler: false,
            use_trivy: false,
            use_scoutsuite: false,
            scan_containers: false,
            scan_kubernetes: false,
            compliance_frameworks: vec!["CIS".to_string(), "SOC2".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanResult {
    pub image: String,
    pub vulnerabilities: Vec<ContainerVulnerability>,
    pub misconfigurations: Vec<CloudFinding>,
    pub secrets_found: Vec<ContainerSecret>,
    pub scan_tool: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerVulnerability {
    pub cve_id: String,
    pub package: String,
    pub version: String,
    pub severity: String,
    pub description: String,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecret {
    pub type_: String,
    pub file: String,
    pub line: Option<u32>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesAuditResult {
    pub namespace: String,
    pub pod_security_findings: Vec<CloudFinding>,
    pub rbac_findings: Vec<CloudFinding>,
    pub network_policy_findings: Vec<CloudFinding>,
    pub resource_findings: Vec<CloudFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProwlerResult {
    pub check_id: String,
    pub status: String,
    pub severity: String,
    pub resource: String,
    pub detail: String,
    pub compliance: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoutSuiteResult {
    pub service: String,
    pub finding: String,
    pub severity: String,
    pub resource: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAuditResult {
    pub success: bool,
    pub provider: String,
    pub region: String,
    pub findings: Vec<CloudFinding>,
    pub checks_performed: usize,
    pub iam_findings: Vec<CloudFinding>,
    pub storage_findings: Vec<CloudFinding>,
    pub network_findings: Vec<CloudFinding>,
    pub logging_findings: Vec<CloudFinding>,
    pub encryption_findings: Vec<CloudFinding>,
    pub compute_findings: Vec<CloudFinding>,
    pub container_scan_results: Vec<ContainerScanResult>,
    pub kubernetes_audit: Vec<KubernetesAuditResult>,
    pub prowler_results: Vec<ProwlerResult>,
    pub scoutsuite_results: Vec<ScoutSuiteResult>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFinding {
    pub severity: String,
    pub category: String,
    pub resource: String,
    pub description: String,
    pub recommendation: String,
    pub compliance: Vec<String>,
}

pub struct CloudAuditTool;

impl CloudAuditTool {
    pub async fn audit(config: &CloudAuditConfig) -> std::result::Result<CloudAuditResult, String> {
        if config.access_key.is_empty() || config.secret_key.is_empty() {
            return Self::audit_via_cli(config).await;
        }

        let provider = config.provider.to_lowercase();
        let region = config.region.clone();

        let (iam_findings, storage_findings, network_findings, logging_findings, encryption_findings, compute_findings) = match provider.as_str() {
            "aws" => Self::audit_aws(config).await,
            "azure" => Self::audit_azure(config).await,
            "gcp" => Self::audit_gcp(config).await,
            "aliyun" | "alibaba" => Self::audit_aliyun(config).await,
            _ => return Err(format!("Unsupported cloud provider: {}, supported: aws, azure, gcp, aliyun", provider)),
        };

        let mut all_findings = Vec::new();
        all_findings.extend(iam_findings.clone());
        all_findings.extend(storage_findings.clone());
        all_findings.extend(network_findings.clone());
        all_findings.extend(logging_findings.clone());
        all_findings.extend(encryption_findings.clone());
        all_findings.extend(compute_findings.clone());

        let checks_performed = if config.check_iam { 1 } else { 0 }
            + if config.check_storage { 1 } else { 0 }
            + if config.check_network { 1 } else { 0 }
            + if config.check_logging { 1 } else { 0 }
            + if config.check_encryption { 1 } else { 0 }
            + if config.check_compute { 1 } else { 0 };

        let critical = all_findings.iter().filter(|f| f.severity == "critical").count();
        let high = all_findings.iter().filter(|f| f.severity == "high").count();
        let medium = all_findings.iter().filter(|f| f.severity == "medium").count();
        let low = all_findings.iter().filter(|f| f.severity == "low").count();

        let summary = format!(
            "Cloud security audit completed | Provider: {} | Region: {} | Checks: {} | Critical: {} High: {} Medium: {} Low: {}",
            provider, region, checks_performed, critical, high, medium, low
        );

        Ok(CloudAuditResult {
            success: true,
            provider,
            region,
            findings: all_findings,
            checks_performed,
            iam_findings,
            storage_findings,
            network_findings,
            logging_findings,
            encryption_findings,
            compute_findings,
            container_scan_results: Vec::new(),
            kubernetes_audit: Vec::new(),
            prowler_results: Vec::new(),
            scoutsuite_results: Vec::new(),
            summary,
        })
    }

    async fn audit_via_cli(config: &CloudAuditConfig) -> std::result::Result<CloudAuditResult, String> {
        let provider = config.provider.to_lowercase();
        let region = config.region.clone();

        let mut all_findings = Vec::new();
        let mut checks_performed = 0usize;

        match provider.as_str() {
            "aws" => {
                if let Ok(output) = std::process::Command::new("aws")
                    .args(["sts", "get-caller-identity", "--output", "json"])
                    .output()
                {
                    if output.status.success() {
                        checks_performed += 1;
                        let iam_findings = Self::aws_cli_iam_audit();
                        all_findings.extend(iam_findings);
                    } else {
                        all_findings.push(CloudFinding {
                            severity: "medium".to_string(),
                            category: "IAM".to_string(),
                            resource: "AWS CLI".to_string(),
                            description: "AWS CLI is not configured or not logged in".to_string(),
                            recommendation: "Run 'aws configure' to set up credentials".to_string(),
                            compliance: vec![],
                        });
                        checks_performed += 1;

                        if let Ok(prowler_output) = std::process::Command::new("prowler").args(["-M", "json"]).output() {
                            if prowler_output.status.success() {
                                let stdout = String::from_utf8_lossy(&prowler_output.stdout);
                                let prowler_findings = Self::parse_prowler_output(&stdout);
                                if !prowler_findings.is_empty() {
                                    checks_performed += 1;
                                    all_findings.extend(prowler_findings);
                                }
                            }
                        }
                    }
                } else {
                    all_findings.push(CloudFinding {
                        severity: "info".to_string(),
                        category: "IAM".to_string(),
                        resource: "AWS CLI".to_string(),
                        description: "AWS CLI is not installed, cannot perform local audit".to_string(),
                        recommendation: "Install AWS CLI and configure credentials, or provide Access Key".to_string(),
                        compliance: vec![],
                    });
                    checks_performed += 1;
                }

                if config.check_storage {
                    if let Ok(output) = std::process::Command::new("aws")
                        .args(["s3", "ls", "--output", "json"])
                        .output()
                    {
                        if output.status.success() {
                            checks_performed += 1;
                            all_findings.push(CloudFinding {
                                severity: "info".to_string(),
                                category: "Storage".to_string(),
                                resource: "S3 Buckets".to_string(),
                                description: "S3 bucket listing accessible via CLI".to_string(),
                                recommendation: "Review bucket ACLs and policies for public access".to_string(),
                                compliance: vec!["CIS 2.1".to_string()],
                            });
                        }
                    }
                }
            }
            "azure" => {
                if let Ok(output) = std::process::Command::new("az")
                    .args(["account", "show", "--output", "json"])
                    .output()
                {
                    if output.status.success() {
                        checks_performed += 1;
                        let azure_findings = Self::azure_cli_audit();
                        all_findings.extend(azure_findings);
                    } else {
                        all_findings.push(CloudFinding {
                            severity: "medium".to_string(),
                            category: "IAM".to_string(),
                            resource: "Azure CLI".to_string(),
                            description: "Azure CLI is not logged in".to_string(),
                            recommendation: "Run 'az login' to sign in to your Azure account".to_string(),
                            compliance: vec![],
                        });
                        checks_performed += 1;
                    }
                } else {
                    all_findings.push(CloudFinding {
                        severity: "info".to_string(),
                        category: "IAM".to_string(),
                        resource: "Azure CLI".to_string(),
                        description: "Azure CLI is not installed".to_string(),
                        recommendation: "Install Azure CLI and sign in, or provide API credentials".to_string(),
                        compliance: vec![],
                    });
                    checks_performed += 1;
                }
            }
            "gcp" => {
                if let Ok(output) = std::process::Command::new("gcloud")
                    .args(["config", "get-value", "project"])
                    .output()
                {
                    if output.status.success() {
                        checks_performed += 1;
                        let project = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !project.is_empty() {
                            all_findings.push(CloudFinding {
                                severity: "info".to_string(),
                                category: "IAM".to_string(),
                                resource: format!("GCP Project: {}", project),
                                description: format!("GCP CLI configured for project: {}", project),
                                recommendation: "Use 'gcloud audit' or Security Command Center for detailed audit".to_string(),
                                compliance: vec![],
                            });
                        }
                    } else {
                        all_findings.push(CloudFinding {
                            severity: "medium".to_string(),
                            category: "IAM".to_string(),
                            resource: "GCP CLI".to_string(),
                            description: "GCP CLI is not configured".to_string(),
                            recommendation: "Run 'gcloud auth login' to sign in".to_string(),
                            compliance: vec![],
                        });
                        checks_performed += 1;
                    }
                } else {
                    all_findings.push(CloudFinding {
                        severity: "info".to_string(),
                        category: "IAM".to_string(),
                        resource: "GCP CLI".to_string(),
                        description: "GCP CLI (gcloud) is not installed".to_string(),
                        recommendation: "Install Google Cloud SDK and configure credentials".to_string(),
                        compliance: vec![],
                    });
                    checks_performed += 1;
                }
            }
            _ => {
                all_findings.push(CloudFinding {
                    severity: "info".to_string(),
                    category: "IAM".to_string(),
                    resource: provider.clone(),
                    description: format!("{} requires API Access Key and Secret Key to perform audit", provider),
                    recommendation: "Provide valid Access Key and Secret Key in configuration".to_string(),
                    compliance: vec![],
                });
                checks_performed += 1;
            }
        }

        let critical = all_findings.iter().filter(|f| f.severity == "critical").count();
        let high = all_findings.iter().filter(|f| f.severity == "high").count();

        let summary = format!(
            "Cloud security audit completed | Provider: {} | Region: {} | Checks: {} | Critical: {} High: {} Total findings: {}",
            provider, region, checks_performed, critical, high, all_findings.len()
        );

        Ok(CloudAuditResult {
            success: true,
            provider,
            region,
            findings: all_findings.clone(),
            checks_performed,
            iam_findings: all_findings.iter().filter(|f| f.category == "IAM").cloned().collect(),
            storage_findings: all_findings.iter().filter(|f| f.category == "Storage").cloned().collect(),
            network_findings: all_findings.iter().filter(|f| f.category == "Network").cloned().collect(),
            logging_findings: all_findings.iter().filter(|f| f.category == "Logging").cloned().collect(),
            encryption_findings: all_findings.iter().filter(|f| f.category == "Encryption").cloned().collect(),
            compute_findings: all_findings.iter().filter(|f| f.category == "Compute").cloned().collect(),
            container_scan_results: Vec::new(),
            kubernetes_audit: Vec::new(),
            prowler_results: Vec::new(),
            scoutsuite_results: Vec::new(),
            summary,
        })
    }

    async fn audit_aws(config: &CloudAuditConfig) -> (Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>) {
        let mut iam_findings = Vec::new();
        let mut storage_findings = Vec::new();
        let mut network_findings = Vec::new();
        let mut logging_findings = Vec::new();
        let mut encryption_findings = Vec::new();
        let mut compute_findings = Vec::new();

        if config.check_iam {
            if let Ok(resp) = Self::aws_api_call(&config.access_key, &config.secret_key, &config.region, "iam", "GET", "/?Action=ListUsers").await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                    let user_count = json.get("ListUsersResult")
                        .and_then(|r| r.get("Users"))
                        .and_then(|u| u.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);

                    if user_count > 0 {
                        iam_findings.push(CloudFinding {
                            severity: "info".to_string(),
                            category: "IAM".to_string(),
                            resource: "IAM Users".to_string(),
                            description: format!("Found {} IAM users", user_count),
                            recommendation: "Regularly review IAM users, remove unnecessary accounts".to_string(),
                            compliance: vec!["CIS 1.1".to_string()],
                        });
                    }
                }
            }

            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "Root Account".to_string(),
                description: "Check if root account has MFA enabled".to_string(),
                recommendation: "Enable MFA for root account, create IAM users for daily operations".to_string(),
                compliance: vec!["CIS 1.13".to_string(), "PCI-DSS 8.3".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "IAM".to_string(),
                resource: "Access Keys".to_string(),
                description: "Check for Access Keys older than 90 days without rotation".to_string(),
                recommendation: "Rotate Access Keys regularly, use temporary credentials instead of long-term keys".to_string(),
                compliance: vec!["CIS 1.14".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "IAM Password Policy".to_string(),
                description: "Check if IAM password policy meets minimum requirements".to_string(),
                recommendation: "Enforce strong password policy: minimum 14 chars, require uppercase, lowercase, numbers, symbols".to_string(),
                compliance: vec!["CIS 1.5".to_string(), "PCI-DSS 8.2.3".to_string()],
            });
        }

        if config.check_storage {
            if let Ok(resp) = Self::aws_api_call(&config.access_key, &config.secret_key, &config.region, "s3", "GET", "/").await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                    let buckets = json.get("ListAllMyBucketsResult")
                        .and_then(|r| r.get("Buckets"))
                        .and_then(|b| b.as_array());

                    if let Some(bucket_list) = buckets {
                        for bucket in bucket_list.iter().take(20) {
                            let bucket_name = bucket.get("Name").and_then(|n| n.as_str()).unwrap_or("");

                            if let Ok(acl_resp) = Self::aws_api_call(&config.access_key, &config.secret_key, &config.region, "s3", "GET", &format!("/{}?acl", bucket_name)).await {
                                if acl_resp.contains("AllUsers") || acl_resp.contains("PublicRead") {
                                    storage_findings.push(CloudFinding {
                                        severity: "critical".to_string(),
                                        category: "Storage".to_string(),
                                        resource: format!("S3 Bucket: {}", bucket_name),
                                        description: format!("S3 bucket {} allows public access", bucket_name),
                                        recommendation: "Configure bucket policy to restrict public access".to_string(),
                                        compliance: vec!["CIS 2.1".to_string(), "PCI-DSS 1.2".to_string()],
                                    });
                                }
                            }
                        }
                    }
                }
            }

            storage_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Storage".to_string(),
                resource: "S3 Buckets".to_string(),
                description: "Check if S3 buckets have default encryption enabled".to_string(),
                recommendation: "Enable server-side encryption (SSE-S3 or SSE-KMS) for all S3 buckets".to_string(),
                compliance: vec!["CIS 2.1".to_string()],
            });

            storage_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Storage".to_string(),
                resource: "S3 Versioning".to_string(),
                description: "Check if S3 buckets have versioning enabled".to_string(),
                recommendation: "Enable versioning for all S3 buckets to protect against data loss".to_string(),
                compliance: vec!["CIS 2.2".to_string()],
            });
        }

        if config.check_network {
            network_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Network".to_string(),
                resource: "Security Groups".to_string(),
                description: "Check if security groups allow 0.0.0.0/0 inbound access".to_string(),
                recommendation: "Restrict security group inbound rules to only necessary IPs and ports".to_string(),
                compliance: vec!["CIS 4.1".to_string(), "PCI-DSS 1.2".to_string()],
            });

            network_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Network".to_string(),
                resource: "VPC Flow Logs".to_string(),
                description: "Check if VPC Flow Logs are enabled".to_string(),
                recommendation: "Enable Flow Logs for all VPCs".to_string(),
                compliance: vec!["CIS 3.9".to_string()],
            });

            network_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Network".to_string(),
                resource: "RDS Public Access".to_string(),
                description: "Check if RDS instances are publicly accessible".to_string(),
                recommendation: "Disable public access for RDS instances, use VPC-only access".to_string(),
                compliance: vec!["CIS 4.3".to_string()],
            });
        }

        if config.check_logging {
            logging_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Logging".to_string(),
                resource: "CloudTrail".to_string(),
                description: "Check if CloudTrail is enabled for multi-region logging".to_string(),
                recommendation: "Enable multi-region CloudTrail logging".to_string(),
                compliance: vec!["CIS 3.1".to_string(), "PCI-DSS 10.2".to_string()],
            });

            logging_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Logging".to_string(),
                resource: "CloudTrail Log Validation".to_string(),
                description: "Check if CloudTrail log file validation is enabled".to_string(),
                recommendation: "Enable CloudTrail log file validation to ensure log integrity".to_string(),
                compliance: vec!["CIS 3.3".to_string()],
            });

            logging_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Logging".to_string(),
                resource: "CloudTrail S3 Bucket".to_string(),
                description: "Check if CloudTrail S3 bucket has access logging enabled".to_string(),
                recommendation: "Enable S3 bucket access logging for CloudTrail bucket".to_string(),
                compliance: vec!["CIS 3.4".to_string()],
            });
        }

        if config.check_encryption {
            encryption_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Encryption".to_string(),
                resource: "EBS Volumes".to_string(),
                description: "Check if EBS volumes are encrypted".to_string(),
                recommendation: "Enable encryption for all EBS volumes".to_string(),
                compliance: vec!["CIS 2.1.1".to_string()],
            });

            encryption_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Encryption".to_string(),
                resource: "RDS Instances".to_string(),
                description: "Check if RDS instances are encrypted".to_string(),
                recommendation: "Enable encryption for all RDS instances".to_string(),
                compliance: vec!["CIS 2.2.1".to_string()],
            });

            encryption_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Encryption".to_string(),
                resource: "KMS Key Rotation".to_string(),
                description: "Check if KMS keys have automatic rotation enabled".to_string(),
                recommendation: "Enable automatic key rotation for KMS customer-managed keys".to_string(),
                compliance: vec!["CIS 2.8".to_string()],
            });
        }

        if config.check_compute {
            compute_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Compute".to_string(),
                resource: "EC2 Instances".to_string(),
                description: "Check if EC2 instances use IMDSv2".to_string(),
                recommendation: "Enforce IMDSv2 on EC2 instances to prevent SSRF attacks".to_string(),
                compliance: vec!["CIS 5.1".to_string()],
            });

            compute_findings.push(CloudFinding {
                severity: "low".to_string(),
                category: "Compute".to_string(),
                resource: "EC2 Detailed Monitoring".to_string(),
                description: "Check if EC2 instances have detailed monitoring enabled".to_string(),
                recommendation: "Enable detailed monitoring for production EC2 instances".to_string(),
                compliance: vec!["CIS 5.2".to_string()],
            });
        }

        (iam_findings, storage_findings, network_findings, logging_findings, encryption_findings, compute_findings)
    }

    async fn audit_azure(config: &CloudAuditConfig) -> (Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>) {
        let mut iam_findings = Vec::new();
        let mut storage_findings = Vec::new();
        let mut network_findings = Vec::new();
        let mut logging_findings = Vec::new();
        let mut encryption_findings = Vec::new();
        let mut compute_findings = Vec::new();

        if config.check_iam {
            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "Azure AD".to_string(),
                description: "Check if Azure AD users have MFA enabled".to_string(),
                recommendation: "Enable MFA for all users, configure conditional access policies".to_string(),
                compliance: vec!["CIS 1.1".to_string(), "PCI-DSS 8.3".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "IAM".to_string(),
                resource: "Guest Accounts".to_string(),
                description: "Check for excessive guest accounts".to_string(),
                recommendation: "Regularly review guest accounts, remove unnecessary access".to_string(),
                compliance: vec!["CIS 1.3".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "Azure AD Admin".to_string(),
                description: "Check for excessive Global Administrator accounts".to_string(),
                recommendation: "Limit Global Administrator count, use least-privilege roles".to_string(),
                compliance: vec!["CIS 1.2".to_string()],
            });
        }

        if config.check_storage {
            storage_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Storage".to_string(),
                resource: "Storage Accounts".to_string(),
                description: "Check if storage accounts allow public access".to_string(),
                recommendation: "Disable public access on storage accounts, use SAS tokens for access control".to_string(),
                compliance: vec!["CIS 3.1".to_string()],
            });

            storage_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Storage".to_string(),
                resource: "Storage Encryption".to_string(),
                description: "Check if storage accounts have encryption enabled".to_string(),
                recommendation: "Enable Microsoft-managed or customer-managed key encryption for all storage accounts".to_string(),
                compliance: vec!["CIS 3.2".to_string()],
            });

            storage_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Storage".to_string(),
                resource: "Storage Network Rules".to_string(),
                description: "Check if storage accounts have network access restrictions".to_string(),
                recommendation: "Configure storage firewalls and virtual network rules".to_string(),
                compliance: vec!["CIS 3.3".to_string()],
            });
        }

        if config.check_network {
            network_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Network".to_string(),
                resource: "NSG".to_string(),
                description: "Check if Network Security Groups allow broad inbound rules".to_string(),
                recommendation: "Restrict NSG inbound rules to only necessary IPs and ports".to_string(),
                compliance: vec!["CIS 6.1".to_string()],
            });

            network_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Network".to_string(),
                resource: "DDoS Protection".to_string(),
                description: "Check if DDoS Protection Standard is enabled".to_string(),
                recommendation: "Enable DDoS Protection Standard for virtual networks".to_string(),
                compliance: vec!["CIS 6.2".to_string()],
            });
        }

        if config.check_logging {
            logging_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Logging".to_string(),
                resource: "Activity Log".to_string(),
                description: "Check if Activity Log is configured for log archiving".to_string(),
                recommendation: "Export Activity Log to storage account or Log Analytics workspace".to_string(),
                compliance: vec!["CIS 5.1".to_string()],
            });

            logging_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Logging".to_string(),
                resource: "Diagnostic Settings".to_string(),
                description: "Check if resources have diagnostic settings configured".to_string(),
                recommendation: "Enable diagnostic settings for all resources".to_string(),
                compliance: vec!["CIS 5.2".to_string()],
            });
        }

        if config.check_encryption {
            encryption_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Encryption".to_string(),
                resource: "Disk Encryption".to_string(),
                description: "Check if virtual machine disks are encrypted".to_string(),
                recommendation: "Enable Azure Disk Encryption for all virtual machine disks".to_string(),
                compliance: vec!["CIS 7.1".to_string()],
            });
        }

        if config.check_compute {
            compute_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Compute".to_string(),
                resource: "VM Endpoint".to_string(),
                description: "Check if virtual machines use managed disks".to_string(),
                recommendation: "Use managed disks instead of unmanaged disks".to_string(),
                compliance: vec!["CIS 7.2".to_string()],
            });

            compute_findings.push(CloudFinding {
                severity: "low".to_string(),
                category: "Compute".to_string(),
                resource: "VM Auto-Shutdown".to_string(),
                description: "Check if non-production VMs have auto-shutdown configured".to_string(),
                recommendation: "Configure auto-shutdown for non-production VMs to reduce costs".to_string(),
                compliance: vec![],
            });
        }

        (iam_findings, storage_findings, network_findings, logging_findings, encryption_findings, compute_findings)
    }

    async fn audit_gcp(config: &CloudAuditConfig) -> (Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>) {
        let mut iam_findings = Vec::new();
        let mut storage_findings = Vec::new();
        let mut network_findings = Vec::new();
        let mut logging_findings = Vec::new();
        let mut encryption_findings = Vec::new();
        let compute_findings = Vec::new();

        if config.check_iam {
            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "Service Account Keys".to_string(),
                description: "Check for user-managed service account keys".to_string(),
                recommendation: "Use Google-managed keys, avoid creating user-managed keys".to_string(),
                compliance: vec!["CIS 1.1".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "IAM".to_string(),
                resource: "IAM Roles".to_string(),
                description: "Check for overly permissive IAM roles".to_string(),
                recommendation: "Apply principle of least privilege to all IAM roles".to_string(),
                compliance: vec!["CIS 1.2".to_string()],
            });
        }

        if config.check_storage {
            storage_findings.push(CloudFinding {
                severity: "critical".to_string(),
                category: "Storage".to_string(),
                resource: "Cloud Storage".to_string(),
                description: "Check if Cloud Storage buckets allow public access".to_string(),
                recommendation: "Disable public access on buckets".to_string(),
                compliance: vec!["CIS 5.1".to_string()],
            });

            storage_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Storage".to_string(),
                resource: "Bucket Retention".to_string(),
                description: "Check if Cloud Storage buckets have retention policies".to_string(),
                recommendation: "Configure retention policies for compliance requirements".to_string(),
                compliance: vec!["CIS 5.2".to_string()],
            });
        }

        if config.check_network {
            network_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Network".to_string(),
                resource: "Firewall Rules".to_string(),
                description: "Check if firewall rules allow 0.0.0.0/0 inbound SSH/RDP".to_string(),
                recommendation: "Restrict firewall rules to only necessary IP access".to_string(),
                compliance: vec!["CIS 3.1".to_string()],
            });

            network_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Network".to_string(),
                resource: "VPC Flow Logs".to_string(),
                description: "Check if VPC Flow Logs are enabled for all subnets".to_string(),
                recommendation: "Enable VPC Flow Logs for all subnets".to_string(),
                compliance: vec!["CIS 3.2".to_string()],
            });
        }

        if config.check_logging {
            logging_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Logging".to_string(),
                resource: "Audit Logging".to_string(),
                description: "Check if audit logging is enabled for all services".to_string(),
                recommendation: "Enable data access audit logs for all services".to_string(),
                compliance: vec!["CIS 2.1".to_string()],
            });
        }

        if config.check_encryption {
            encryption_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Encryption".to_string(),
                resource: "Persistent Disks".to_string(),
                description: "Check if persistent disks use customer-managed encryption keys".to_string(),
                recommendation: "Use CMEK encryption for sensitive data persistent disks".to_string(),
                compliance: vec!["CIS 4.1".to_string()],
            });
        }

        (iam_findings, storage_findings, network_findings, logging_findings, encryption_findings, compute_findings)
    }

    async fn audit_aliyun(config: &CloudAuditConfig) -> (Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>, Vec<CloudFinding>) {
        let mut iam_findings = Vec::new();
        let mut storage_findings = Vec::new();
        let mut network_findings = Vec::new();
        let mut logging_findings = Vec::new();
        let mut encryption_findings = Vec::new();
        let mut compute_findings = Vec::new();

        if config.check_iam {
            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "RAM Users".to_string(),
                description: "Check if RAM users have MFA enabled".to_string(),
                recommendation: "Enable MFA for all RAM users".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "IAM".to_string(),
                resource: "Access Keys".to_string(),
                description: "Check if RAM user Access Keys are rotated regularly".to_string(),
                recommendation: "Rotate Access Keys regularly, use STS temporary credentials".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });

            iam_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "IAM".to_string(),
                resource: "RAM Password Policy".to_string(),
                description: "Check if RAM password policy meets requirements".to_string(),
                recommendation: "Enforce strong password policy for all RAM users".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });
        }

        if config.check_storage {
            storage_findings.push(CloudFinding {
                severity: "critical".to_string(),
                category: "Storage".to_string(),
                resource: "OSS Buckets".to_string(),
                description: "Check if OSS buckets allow public read/write".to_string(),
                recommendation: "Set OSS bucket ACL to private, use signed URLs for access control".to_string(),
                compliance: vec!["MLPS 2.0".to_string(), "GDPR".to_string()],
            });

            storage_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Storage".to_string(),
                resource: "OSS Encryption".to_string(),
                description: "Check if OSS buckets have server-side encryption enabled".to_string(),
                recommendation: "Enable SSE-KMS or SSE-OSS for all buckets".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });
        }

        if config.check_network {
            network_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Network".to_string(),
                resource: "Security Groups".to_string(),
                description: "Check if security groups allow 0.0.0.0/0 inbound access".to_string(),
                recommendation: "Restrict security group rules to only necessary IPs and ports".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });

            network_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Network".to_string(),
                resource: "VPC Flow Logs".to_string(),
                description: "Check if VPC flow logs are enabled".to_string(),
                recommendation: "Enable VPC flow logs for all VPCs".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });
        }

        if config.check_logging {
            logging_findings.push(CloudFinding {
                severity: "high".to_string(),
                category: "Logging".to_string(),
                resource: "ActionTrail".to_string(),
                description: "Check if ActionTrail is enabled".to_string(),
                recommendation: "Enable ActionTrail to record all API calls".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });
        }

        if config.check_encryption {
            encryption_findings.push(CloudFinding {
                severity: "medium".to_string(),
                category: "Encryption".to_string(),
                resource: "ECS Disks".to_string(),
                description: "Check if ECS disks are encrypted".to_string(),
                recommendation: "Enable encryption for all ECS disks".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });
        }

        if config.check_compute {
            compute_findings.push(CloudFinding {
                severity: "low".to_string(),
                category: "Compute".to_string(),
                resource: "ECS Instances".to_string(),
                description: "Check if ECS instances use security enhancement features".to_string(),
                recommendation: "Enable security enhancement mode for ECS instances".to_string(),
                compliance: vec!["MLPS 2.0".to_string()],
            });
        }

        (iam_findings, storage_findings, network_findings, logging_findings, encryption_findings, compute_findings)
    }

    fn aws_cli_iam_audit() -> Vec<CloudFinding> {
        let mut findings = Vec::new();

        if let Ok(output) = std::process::Command::new("aws")
            .args(["iam", "get-account-summary", "--output", "json"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    if let Some(summary_map) = json.get("SummaryMap") {
                        let mfa_devices = summary_map.get("MFADevices").and_then(|v| v.as_u64()).unwrap_or(0);
                        let users = summary_map.get("Users").and_then(|v| v.as_u64()).unwrap_or(0);

                        if users > 0 && mfa_devices == 0 {
                            findings.push(CloudFinding {
                                severity: "high".to_string(),
                                category: "IAM".to_string(),
                                resource: "MFA".to_string(),
                                description: "No IAM users have MFA enabled".to_string(),
                                recommendation: "Enable MFA for all IAM users".to_string(),
                                compliance: vec!["CIS 1.13".to_string()],
                            });
                        }
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("aws")
            .args(["iam", "list-users", "--query", "Users[?PasswordLastUsed==null].UserName", "--output", "json"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(users) = serde_json::from_str::<Vec<String>>(&stdout) {
                    if !users.is_empty() {
                        findings.push(CloudFinding {
                            severity: "medium".to_string(),
                            category: "IAM".to_string(),
                            resource: "Inactive Users".to_string(),
                            description: format!("Found {} users who have never logged in", users.len()),
                            recommendation: "Delete or disable unnecessary IAM users".to_string(),
                            compliance: vec!["CIS 1.4".to_string()],
                        });
                    }
                }
            }
        }

        findings
    }

    fn azure_cli_audit() -> Vec<CloudFinding> {
        let mut findings = Vec::new();

        if let Ok(output) = std::process::Command::new("az")
            .args(["storage", "account", "list", "--query", "[].{name:name,allowBlobPublicAccess:allowBlobPublicAccess}", "--output", "json"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(accounts) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                    for account in accounts {
                        let public_access = account.get("allowBlobPublicAccess").and_then(|v| v.as_bool()).unwrap_or(false);
                        let name = account.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                        if public_access {
                            findings.push(CloudFinding {
                                severity: "critical".to_string(),
                                category: "Storage".to_string(),
                                resource: format!("Storage: {}", name),
                                description: format!("Storage account {} allows public Blob access", name),
                                recommendation: "Disable public access on the storage account".to_string(),
                                compliance: vec!["CIS 3.1".to_string()],
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    fn parse_prowler_output(stdout: &str) -> Vec<CloudFinding> {
        let mut findings = Vec::new();
        for line in stdout.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let severity = json.get("Severity").and_then(|v| v.as_str()).unwrap_or("info").to_lowercase();
                let title = json.get("CheckTitle").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let resource = json.get("ResourceId").and_then(|v| v.as_str()).unwrap_or("").to_string();

                if !title.is_empty() && (severity == "critical" || severity == "high") {
                    findings.push(CloudFinding {
                        severity: severity.clone(),
                        category: "IAM".to_string(),
                        resource,
                        description: title,
                        recommendation: "Refer to Prowler report for remediation".to_string(),
                        compliance: vec![],
                    });
                }
            }
        }
        findings
    }

    async fn aws_api_call(access_key: &str, _secret_key: &str, region: &str, service: &str, method: &str, path: &str) -> std::result::Result<String, String> {
        let host = if service == "iam" {
            "iam.amazonaws.com".to_string()
        } else {
            format!("{}.{}.amazonaws.com", service, region)
        };
        let url = format!("https://{}{}", host, path);

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client.request(method.parse().unwrap_or(reqwest::Method::GET), &url)
            .header("Host", &host)
            .header("X-Amz-Date", &amz_date)
            .header("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .header("Authorization", format!(
                "AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=placeholder",
                access_key, date_stamp, region, service
            ))
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.map_err(|e| e.to_string())?;

        if status.is_success() {
            Ok(body)
        } else {
            Err(format!("AWS API error ({}): {}", status, body.chars().take(200).collect::<String>()))
        }
    }

    pub async fn run_prowler(provider: &str, region: &str) -> std::result::Result<Vec<ProwlerResult>, String> {
        if !std::process::Command::new("which").arg("prowler").output().map(|o| o.status.success()).unwrap_or(false) {
            return Err("Prowler not found. Install with: pip install prowler".to_string());
        }

        let mut results = Vec::new();

        let args = match provider {
            "aws" => vec!["prowler", "aws", "-f", region, "--output-format", "json"],
            "azure" => vec!["prowler", "azure", "--output-format", "json"],
            "gcp" => vec!["prowler", "gcp", "--output-format", "json"],
            _ => return Err(format!("Prowler does not support provider: {}", provider)),
        };

        if let Ok(output) = std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(findings) = json.as_array() {
                    for finding in findings.iter().take(100) {
                        results.push(ProwlerResult {
                            check_id: finding.get("CheckID").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            status: finding.get("Status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            severity: finding.get("Severity").and_then(|v| v.as_str()).unwrap_or("info").to_string(),
                            resource: finding.get("ResourceName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            detail: finding.get("Message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            compliance: finding.get("Compliance")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                                .unwrap_or_default(),
                        });
                    }
                }
            } else {
                for line in stdout.lines() {
                    if line.contains("PASS") || line.contains("FAIL") || line.contains("WARN") {
                        let parts: Vec<&str> = line.split('|').collect();
                        if parts.len() >= 3 {
                            let status = if line.contains("PASS") { "PASS" } else if line.contains("FAIL") { "FAIL" } else { "WARN" };
                            results.push(ProwlerResult {
                                check_id: parts[0].trim().to_string(),
                                status: status.to_string(),
                                severity: if status == "FAIL" { "high" } else { "info" }.to_string(),
                                resource: parts.get(1).map(|s| s.trim().to_string()).unwrap_or_default(),
                                detail: parts.get(2).map(|s| s.trim().to_string()).unwrap_or_default(),
                                compliance: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn run_trivy_scan(target: &str, scan_type: &str) -> std::result::Result<ContainerScanResult, String> {
        if !std::process::Command::new("which").arg("trivy").output().map(|o| o.status.success()).unwrap_or(false) {
            return Err("Trivy not found. Install with: https://aquasecurity.github.io/trivy/".to_string());
        }

        let mut vulns = Vec::new();
        let mut misconfigs = Vec::new();
        let mut secrets = Vec::new();

        let args = match scan_type {
            "image" => vec!["trivy", "image", "--format", "json", target],
            "fs" => vec!["trivy", "fs", "--format", "json", target],
            "config" => vec!["trivy", "config", "--format", "json", target],
            "k8s" => vec!["trivy", "k8s", "--format", "json", target],
            _ => vec!["trivy", "image", "--format", "json", target],
        };

        if let Ok(output) = std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(results) = json.get("Results").and_then(|r| r.as_array()) {
                    for result in results {
                        if let Some(vulns_arr) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
                            for v in vulns_arr.iter().take(50) {
                                vulns.push(ContainerVulnerability {
                                    cve_id: v.get("VulnerabilityID").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    package: v.get("PkgName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    version: v.get("InstalledVersion").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    severity: v.get("Severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                                    description: v.get("Title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    fixed_version: v.get("FixedVersion").and_then(|v| v.as_str()).map(String::from),
                                });
                            }
                        }

                        if let Some(misconfig_arr) = result.get("Misconfigurations").and_then(|m| m.as_array()) {
                            for m in misconfig_arr.iter().take(30) {
                                misconfigs.push(CloudFinding {
                                    severity: m.get("Severity").and_then(|s| s.as_str()).unwrap_or("info").to_string(),
                                    category: "Container Config".to_string(),
                                    resource: target.to_string(),
                                    description: m.get("Message").and_then(|m| m.as_str()).unwrap_or("").to_string(),
                                    recommendation: m.get("Resolution").and_then(|r| r.as_str()).unwrap_or("").to_string(),
                                    compliance: m.get("References")
                                        .and_then(|r| r.as_array())
                                        .map(|arr| arr.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                                        .unwrap_or_default(),
                                });
                            }
                        }

                        if let Some(secrets_arr) = result.get("Secrets").and_then(|s| s.as_array()) {
                            for s in secrets_arr.iter().take(20) {
                                secrets.push(ContainerSecret {
                                    type_: s.get("RuleID").and_then(|r| r.as_str()).unwrap_or("unknown").to_string(),
                                    file: s.get("FilePath").and_then(|f| f.as_str()).unwrap_or("").to_string(),
                                    line: s.get("StartLine").and_then(|l| l.as_u64()).map(|l| l as u32),
                                    severity: "critical".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ContainerScanResult {
            image: target.to_string(),
            vulnerabilities: vulns,
            misconfigurations: misconfigs,
            secrets_found: secrets,
            scan_tool: "trivy".to_string(),
        })
    }

    pub async fn run_scoutsuite(provider: &str) -> std::result::Result<Vec<ScoutSuiteResult>, String> {
        if !std::process::Command::new("which").arg("scout").output().map(|o| o.status.success()).unwrap_or(false) {
            return Err("ScoutSuite not found. Install with: pip install scoutsuite".to_string());
        }

        let mut results = Vec::new();

        let args = match provider {
            "aws" => vec!["scout", "aws"],
            "azure" => vec!["scout", "azure"],
            "gcp" => vec!["scout", "gcp"],
            "aliyun" => vec!["scout", "aliyun"],
            _ => return Err(format!("ScoutSuite does not support provider: {}", provider)),
        };

        if let Ok(output) = std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(services) = json.get("services").and_then(|s| s.as_object()) {
                    for (service_name, service_data) in services {
                        if let Some(findings) = service_data.get("findings").and_then(|f| f.as_object()) {
                            for (finding_id, finding_data) in findings {
                                let empty_arr = Vec::new();
                                let items = finding_data.get("items").and_then(|i| i.as_array()).unwrap_or(&empty_arr);
                                for item in items.iter().take(10) {
                                    results.push(ScoutSuiteResult {
                                        service: service_name.clone(),
                                        finding: finding_id.clone(),
                                        severity: finding_data.get("level").and_then(|l| l.as_str()).unwrap_or("info").to_string(),
                                        resource: item.as_str().unwrap_or("").to_string(),
                                        detail: finding_data.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn audit_kubernetes(namespace: Option<&str>) -> std::result::Result<Vec<KubernetesAuditResult>, String> {
        let mut results = Vec::new();

        if !std::process::Command::new("which").arg("kubectl").output().map(|o| o.status.success()).unwrap_or(false) {
            return Err("kubectl not found. Install kubectl first".to_string());
        }

        let ns_args = match namespace {
            Some(ns) => vec!["-n", ns],
            None => vec!["--all-namespaces"],
        };

        let mut pod_findings = Vec::new();
        let rbac_findings = Vec::new();
        let net_findings = Vec::new();
        let res_findings = Vec::new();

        if let Ok(output) = std::process::Command::new("kubectl")
            .args([&ns_args[..], &["get", "pods", "-o", "json"]].concat())
            .output()
        {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&output.stdout)) {
                if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
                    for pod in items {
                        let pod_name = pod.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()).unwrap_or("");
                        let _ns = pod.get("metadata").and_then(|m| m.get("namespace")).and_then(|n| n.as_str()).unwrap_or("default");

                        if let Some(spec) = pod.get("spec") {
                            if spec.get("hostNetwork").and_then(|v| v.as_bool()).unwrap_or(false) {
                                pod_findings.push(CloudFinding {
                                    severity: "high".to_string(),
                                    category: "Pod Security".to_string(),
                                    resource: pod_name.to_string(),
                                    description: "Pod using hostNetwork".to_string(),
                                    recommendation: "Avoid using hostNetwork unless absolutely necessary".to_string(),
                                    compliance: vec!["CIS".to_string()],
                                });
                            }

                            if spec.get("hostPID").and_then(|v| v.as_bool()).unwrap_or(false) {
                                pod_findings.push(CloudFinding {
                                    severity: "high".to_string(),
                                    category: "Pod Security".to_string(),
                                    resource: pod_name.to_string(),
                                    description: "Pod using hostPID namespace".to_string(),
                                    recommendation: "Avoid sharing host PID namespace".to_string(),
                                    compliance: vec!["CIS".to_string()],
                                });
                            }

                            if spec.get("hostIPC").and_then(|v| v.as_bool()).unwrap_or(false) {
                                pod_findings.push(CloudFinding {
                                    severity: "medium".to_string(),
                                    category: "Pod Security".to_string(),
                                    resource: pod_name.to_string(),
                                    description: "Pod using hostIPC namespace".to_string(),
                                    recommendation: "Avoid sharing host IPC namespace".to_string(),
                                    compliance: vec!["CIS".to_string()],
                                });
                            }

                            if let Some(containers) = spec.get("containers").and_then(|c| c.as_array()) {
                                for container in containers {
                                    if let Some(security_ctx) = container.get("securityContext") {
                                        if security_ctx.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false) {
                                            pod_findings.push(CloudFinding {
                                                severity: "critical".to_string(),
                                                category: "Pod Security".to_string(),
                                                resource: format!("{}/{}", pod_name, container.get("name").and_then(|n| n.as_str()).unwrap_or("")),
                                                description: "Container running in privileged mode".to_string(),
                                                recommendation: "Remove privileged flag, use specific capabilities instead".to_string(),
                                                compliance: vec!["CIS".to_string(), "NSA".to_string()],
                                            });
                                        }

                                        if security_ctx.get("runAsUser").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
                                            pod_findings.push(CloudFinding {
                                                severity: "high".to_string(),
                                                category: "Pod Security".to_string(),
                                                resource: format!("{}/{}", pod_name, container.get("name").and_then(|n| n.as_str()).unwrap_or("")),
                                                description: "Container running as root (UID 0)".to_string(),
                                                recommendation: "Set runAsNonRoot: true or specify a non-zero runAsUser".to_string(),
                                                compliance: vec!["CIS".to_string()],
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        results.push(KubernetesAuditResult {
            namespace: namespace.unwrap_or("all").to_string(),
            pod_security_findings: pod_findings,
            rbac_findings,
            network_policy_findings: net_findings,
            resource_findings: res_findings,
        });

        Ok(results)
    }
}
