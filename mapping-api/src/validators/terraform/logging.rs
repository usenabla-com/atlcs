//! Logging and monitoring validation for Terraform resources
//!
//! Maps to FedRAMP KSIs: KSI-MLA-01, KSI-MLA-02

use super::TerraformResource;
use crate::validators::models::{
    ComplianceStatus, KsiValidationResult, Relevance, Severity, ValidationCheck,
};

/// Validate logging-related KSIs
pub fn validate_logging(resources: &[TerraformResource]) -> Vec<KsiValidationResult> {
    vec![
        validate_ksi_mla_01(resources),
        validate_ksi_mla_02(resources),
    ]
}

/// KSI-MLA-01: Implement comprehensive logging and monitoring
fn validate_ksi_mla_01(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for CloudTrail (AWS)
    let cloudtrail: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_cloudtrail")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        let multi_region = cloudtrail.iter()
            .filter(|r| r.get_attr_bool("is_multi_region_trail").unwrap_or(false))
            .count();

        checks.push(ValidationCheck {
            check_name: "cloudtrail_enabled".to_string(),
            description: "AWS CloudTrail is enabled".to_string(),
            passed: !cloudtrail.is_empty(),
            severity: Severity::Critical,
            actual_value: Some(format!("{} CloudTrail trails", cloudtrail.len())),
            expected_value: Some("CloudTrail enabled".to_string()),
            evidence_path: None,
        });

        checks.push(ValidationCheck {
            check_name: "cloudtrail_multi_region".to_string(),
            description: "CloudTrail is configured for multi-region".to_string(),
            passed: multi_region > 0 || cloudtrail.is_empty(),
            severity: Severity::High,
            actual_value: Some(format!("{} multi-region trails", multi_region)),
            expected_value: Some("Multi-region trail".to_string()),
            evidence_path: None,
        });
    }

    // Check for Azure Monitor / Log Analytics
    if resources.iter().any(|r| r.is_azure()) {
        let log_analytics: Vec<_> = resources.iter()
            .filter(|r| r.resource_type == "azurerm_log_analytics_workspace")
            .collect();

        checks.push(ValidationCheck {
            check_name: "log_analytics_workspace".to_string(),
            description: "Azure Log Analytics workspace is configured".to_string(),
            passed: !log_analytics.is_empty(),
            severity: Severity::Critical,
            actual_value: Some(format!("{} workspaces", log_analytics.len())),
            expected_value: Some("Log Analytics workspace".to_string()),
            evidence_path: None,
        });
    }

    // Check for GCP logging
    if resources.iter().any(|r| r.is_gcp()) {
        let logging_sinks: Vec<_> = resources.iter()
            .filter(|r| r.resource_type == "google_logging_project_sink")
            .collect();

        checks.push(ValidationCheck {
            check_name: "gcp_logging_sink".to_string(),
            description: "GCP logging sinks are configured".to_string(),
            passed: !logging_sinks.is_empty(),
            severity: Severity::Critical,
            actual_value: Some(format!("{} logging sinks", logging_sinks.len())),
            expected_value: Some("Logging sink configured".to_string()),
            evidence_path: None,
        });
    }

    // Check for CloudWatch log groups
    let log_groups: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_cloudwatch_log_group")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "cloudwatch_log_groups".to_string(),
            description: "CloudWatch log groups are configured".to_string(),
            passed: !log_groups.is_empty(),
            severity: Severity::High,
            actual_value: Some(format!("{} log groups", log_groups.len())),
            expected_value: Some("Log groups configured".to_string()),
            evidence_path: None,
        });

        // Check log retention
        let with_retention = log_groups.iter()
            .filter(|r| r.get_attr("retention_in_days").is_some())
            .count();

        checks.push(ValidationCheck {
            check_name: "log_retention".to_string(),
            description: "Log groups have retention policies".to_string(),
            passed: log_groups.is_empty() || with_retention > 0,
            severity: Severity::Medium,
            actual_value: Some(format!("{}/{} with retention", with_retention, log_groups.len())),
            expected_value: Some("Retention policies defined".to_string()),
            evidence_path: None,
        });
    }

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();
    let critical_failures = checks.iter().filter(|c| !c.passed && c.severity == Severity::Critical).count();

    KsiValidationResult {
        ksi_id: "KSI-MLA-01",
        ksi_description: "Implement comprehensive logging and monitoring.",
        status: if total == 0 {
            ComplianceStatus::Indeterminate
        } else if critical_failures > 0 {
            ComplianceStatus::NonCompliant
        } else if passed == total {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::PartiallyCompliant
        },
        relevance: Relevance::Direct,
        summary: if total == 0 {
            "No cloud resources to validate".to_string()
        } else {
            format!("{} of {} checks passed", passed, total)
        },
        recommendations: if critical_failures > 0 {
            vec![
                "Enable CloudTrail/Azure Monitor/GCP Logging".to_string(),
                "Configure log retention policies".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-MLA-02: Monitor for unauthorized access and anomalies
fn validate_ksi_mla_02(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for CloudWatch alarms
    let alarms: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_cloudwatch_metric_alarm" ||
            r.resource_type == "azurerm_monitor_metric_alert" ||
            r.resource_type == "google_monitoring_alert_policy"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "monitoring_alarms".to_string(),
        description: "Monitoring alarms/alerts are configured".to_string(),
        passed: !alarms.is_empty(),
        severity: Severity::High,
        actual_value: Some(format!("{} alarms", alarms.len())),
        expected_value: Some("Monitoring alarms configured".to_string()),
        evidence_path: None,
    });

    // Check for GuardDuty (AWS)
    let guardduty: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_guardduty_detector")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "guardduty_enabled".to_string(),
            description: "AWS GuardDuty threat detection is enabled".to_string(),
            passed: !guardduty.is_empty(),
            severity: Severity::High,
            actual_value: Some(format!("{} GuardDuty detectors", guardduty.len())),
            expected_value: Some("GuardDuty enabled".to_string()),
            evidence_path: None,
        });
    }

    // Check for Security Hub (AWS)
    let security_hub: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_securityhub_account")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "security_hub_enabled".to_string(),
            description: "AWS Security Hub is enabled".to_string(),
            passed: !security_hub.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} Security Hub accounts", security_hub.len())),
            expected_value: Some("Security Hub enabled".to_string()),
            evidence_path: None,
        });
    }

    // Check for Azure Security Center
    if resources.iter().any(|r| r.is_azure()) {
        let security_center: Vec<_> = resources.iter()
            .filter(|r| r.resource_type == "azurerm_security_center_subscription_pricing")
            .collect();

        checks.push(ValidationCheck {
            check_name: "azure_security_center".to_string(),
            description: "Azure Security Center is enabled".to_string(),
            passed: !security_center.is_empty(),
            severity: Severity::High,
            actual_value: Some(format!("{} Security Center configs", security_center.len())),
            expected_value: Some("Security Center enabled".to_string()),
            evidence_path: None,
        });
    }

    // Check for SNS topics (for alert notifications)
    let sns_topics: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_sns_topic")
        .collect();

    if !alarms.is_empty() && resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "alert_notifications".to_string(),
            description: "SNS topics configured for alert notifications".to_string(),
            passed: !sns_topics.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} SNS topics", sns_topics.len())),
            expected_value: Some("Alert notifications configured".to_string()),
            evidence_path: None,
        });
    }

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-MLA-02",
        ksi_description: "Monitor for unauthorized access and anomalies.",
        status: if total == 0 {
            ComplianceStatus::Indeterminate
        } else if passed == total {
            ComplianceStatus::Compliant
        } else if passed > 0 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        },
        relevance: Relevance::Direct,
        summary: if total == 0 {
            "No cloud resources to validate".to_string()
        } else {
            format!("{} of {} checks passed", passed, total)
        },
        recommendations: if passed < total && total > 0 {
            vec![
                "Enable threat detection services (GuardDuty/Security Center)".to_string(),
                "Configure monitoring alarms for security events".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}
