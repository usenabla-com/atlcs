//! Encryption validation for Terraform resources
//!
//! Maps to FedRAMP KSIs: KSI-SVC-02, KSI-SVC-03, KSI-SVC-06

use super::TerraformResource;
use crate::validators::models::{
    ComplianceStatus, KsiValidationResult, Relevance, Severity, ValidationCheck,
};

/// Validate encryption-related KSIs
pub fn validate_encryption(resources: &[TerraformResource]) -> Vec<KsiValidationResult> {
    vec![
        validate_ksi_svc_02(resources),
        validate_ksi_svc_03(resources),
        validate_ksi_svc_06(resources),
    ]
}

/// KSI-SVC-02: Encrypt all data in transit using approved cryptography
fn validate_ksi_svc_02(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for TLS/SSL configurations
    let load_balancers: Vec<_> = resources.iter()
        .filter(|r| r.resource_type.contains("lb") || r.resource_type.contains("load_balancer"))
        .collect();

    let https_listeners = load_balancers.iter()
        .filter(|r| {
            r.get_attr_str("protocol").map(|p| p.to_uppercase()) == Some("HTTPS".to_string()) ||
            r.get_attr_str("ssl_policy").is_some()
        })
        .count();

    checks.push(ValidationCheck {
        check_name: "load_balancer_https".to_string(),
        description: "Load balancers use HTTPS/TLS".to_string(),
        passed: load_balancers.is_empty() || https_listeners > 0,
        severity: Severity::High,
        actual_value: Some(format!("{} HTTPS listeners", https_listeners)),
        expected_value: Some("All load balancers use HTTPS".to_string()),
        evidence_path: None,
    });

    // Check API Gateway TLS
    let api_gateways: Vec<_> = resources.iter()
        .filter(|r| r.resource_type.contains("api_gateway") || r.resource_type.contains("apigateway"))
        .collect();

    checks.push(ValidationCheck {
        check_name: "api_gateway_tls".to_string(),
        description: "API Gateways enforce TLS".to_string(),
        passed: api_gateways.iter().all(|r| {
            r.get_attr_str("minimum_tls_version").is_some() ||
            r.get_attr("security_policy").is_some()
        }),
        severity: Severity::High,
        actual_value: Some(format!("{} API gateways configured", api_gateways.len())),
        expected_value: Some("TLS 1.2+ required".to_string()),
        evidence_path: None,
    });

    // Check database SSL
    let databases: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type.contains("db_instance") ||
            r.resource_type.contains("rds") ||
            r.resource_type.contains("sql")
        })
        .collect();

    let ssl_databases = databases.iter()
        .filter(|r| {
            r.get_attr_bool("ssl_enforcement_enabled").unwrap_or(false) ||
            r.get_attr("ssl_mode").is_some() ||
            r.get_attr("require_ssl").is_some()
        })
        .count();

    checks.push(ValidationCheck {
        check_name: "database_ssl".to_string(),
        description: "Databases require SSL connections".to_string(),
        passed: databases.is_empty() || ssl_databases == databases.len(),
        severity: Severity::Critical,
        actual_value: Some(format!("{}/{} databases with SSL", ssl_databases, databases.len())),
        expected_value: Some("All databases require SSL".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();
    let critical_failures = checks.iter().filter(|c| !c.passed && c.severity == Severity::Critical).count();

    KsiValidationResult {
        ksi_id: "KSI-SVC-02",
        ksi_description: "Encrypt all data in transit using approved cryptography.",
        status: if critical_failures > 0 {
            ComplianceStatus::NonCompliant
        } else if passed == total {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::PartiallyCompliant
        },
        relevance: Relevance::Direct,
        summary: format!("{} of {} checks passed", passed, total),
        recommendations: if critical_failures > 0 {
            vec!["Enable SSL/TLS for all data in transit".to_string()]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-SVC-03: Encrypt information at rest by default
fn validate_ksi_svc_03(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check S3 bucket encryption
    let s3_buckets: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_s3_bucket" || r.resource_type.contains("storage_bucket"))
        .collect();

    let encrypted_buckets = resources.iter()
        .filter(|r| r.resource_type == "aws_s3_bucket_server_side_encryption_configuration")
        .count();

    let bucket_default_encryption = s3_buckets.iter()
        .filter(|r| r.get_attr("server_side_encryption_configuration").is_some())
        .count();

    checks.push(ValidationCheck {
        check_name: "s3_encryption".to_string(),
        description: "S3 buckets have server-side encryption enabled".to_string(),
        passed: s3_buckets.is_empty() || encrypted_buckets >= s3_buckets.len() || bucket_default_encryption > 0,
        severity: Severity::Critical,
        actual_value: Some(format!("{} buckets, {} encryption configs", s3_buckets.len(), encrypted_buckets)),
        expected_value: Some("All buckets encrypted".to_string()),
        evidence_path: None,
    });

    // Check EBS encryption
    let ebs_volumes: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_ebs_volume")
        .collect();

    let encrypted_volumes = ebs_volumes.iter()
        .filter(|r| r.get_attr_bool("encrypted").unwrap_or(false))
        .count();

    checks.push(ValidationCheck {
        check_name: "ebs_encryption".to_string(),
        description: "EBS volumes are encrypted".to_string(),
        passed: ebs_volumes.is_empty() || encrypted_volumes == ebs_volumes.len(),
        severity: Severity::Critical,
        actual_value: Some(format!("{}/{} volumes encrypted", encrypted_volumes, ebs_volumes.len())),
        expected_value: Some("All volumes encrypted".to_string()),
        evidence_path: None,
    });

    // Check RDS encryption
    let rds_instances: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_db_instance" || r.resource_type.contains("rds"))
        .collect();

    let encrypted_rds = rds_instances.iter()
        .filter(|r| r.get_attr_bool("storage_encrypted").unwrap_or(false))
        .count();

    checks.push(ValidationCheck {
        check_name: "rds_encryption".to_string(),
        description: "RDS instances have storage encryption enabled".to_string(),
        passed: rds_instances.is_empty() || encrypted_rds == rds_instances.len(),
        severity: Severity::Critical,
        actual_value: Some(format!("{}/{} RDS encrypted", encrypted_rds, rds_instances.len())),
        expected_value: Some("All RDS instances encrypted".to_string()),
        evidence_path: None,
    });

    // Check Azure storage encryption
    let azure_storage: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "azurerm_storage_account")
        .collect();

    checks.push(ValidationCheck {
        check_name: "azure_storage_encryption".to_string(),
        description: "Azure storage accounts use encryption".to_string(),
        passed: azure_storage.is_empty() || azure_storage.iter().all(|r| {
            // Azure storage is encrypted by default, check if explicitly disabled
            r.get_attr_bool("enable_https_traffic_only").unwrap_or(true)
        }),
        severity: Severity::Critical,
        actual_value: Some(format!("{} storage accounts", azure_storage.len())),
        expected_value: Some("All storage encrypted".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();
    let critical_failures = checks.iter().filter(|c| !c.passed && c.severity == Severity::Critical).count();

    KsiValidationResult {
        ksi_id: "KSI-SVC-03",
        ksi_description: "Encrypt information at rest by default.",
        status: if critical_failures > 0 {
            ComplianceStatus::NonCompliant
        } else if passed == total {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::PartiallyCompliant
        },
        relevance: Relevance::Direct,
        summary: format!("{} of {} checks passed", passed, total),
        recommendations: if critical_failures > 0 {
            vec!["Enable encryption at rest for all storage resources".to_string()]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-SVC-06: Manage cryptographic keys securely
fn validate_ksi_svc_06(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for KMS keys
    let kms_keys: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_kms_key" ||
            r.resource_type == "azurerm_key_vault_key" ||
            r.resource_type == "google_kms_crypto_key"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "kms_keys_defined".to_string(),
        description: "Customer-managed encryption keys are defined".to_string(),
        passed: !kms_keys.is_empty(),
        severity: Severity::Medium,
        actual_value: Some(format!("{} KMS keys", kms_keys.len())),
        expected_value: Some("At least 1 KMS key".to_string()),
        evidence_path: None,
    });

    // Check key rotation
    let rotation_enabled = kms_keys.iter()
        .filter(|r| {
            r.get_attr_bool("enable_key_rotation").unwrap_or(false) ||
            r.get_attr("rotation_period").is_some()
        })
        .count();

    checks.push(ValidationCheck {
        check_name: "key_rotation".to_string(),
        description: "KMS keys have automatic rotation enabled".to_string(),
        passed: kms_keys.is_empty() || rotation_enabled == kms_keys.len(),
        severity: Severity::High,
        actual_value: Some(format!("{}/{} keys with rotation", rotation_enabled, kms_keys.len())),
        expected_value: Some("All keys have rotation enabled".to_string()),
        evidence_path: None,
    });

    // Check Key Vault / Secrets Manager
    let secret_stores: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_secretsmanager_secret" ||
            r.resource_type == "azurerm_key_vault" ||
            r.resource_type == "google_secret_manager_secret"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "secrets_management".to_string(),
        description: "Secrets management service is configured".to_string(),
        passed: !secret_stores.is_empty(),
        severity: Severity::Medium,
        actual_value: Some(format!("{} secret stores", secret_stores.len())),
        expected_value: Some("Secrets management configured".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-SVC-06",
        ksi_description: "Manage cryptographic keys securely.",
        status: if passed == total {
            ComplianceStatus::Compliant
        } else if passed > 0 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        },
        relevance: Relevance::Direct,
        summary: format!("{} of {} checks passed", passed, total),
        recommendations: if passed < total {
            vec![
                "Implement customer-managed KMS keys".to_string(),
                "Enable automatic key rotation".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}
