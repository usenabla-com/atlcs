//! IAM validation for Terraform resources
//!
//! Maps to FedRAMP KSIs: KSI-IAM-01, KSI-IAM-04

use super::TerraformResource;
use crate::validators::models::{
    ComplianceStatus, KsiValidationResult, Relevance, Severity, ValidationCheck,
};

/// Validate IAM-related KSIs
pub fn validate_iam(resources: &[TerraformResource]) -> Vec<KsiValidationResult> {
    vec![
        validate_ksi_iam_01(resources),
        validate_ksi_iam_04(resources),
    ]
}

/// KSI-IAM-01: Uniquely identify and authenticate all users
fn validate_ksi_iam_01(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for IAM users
    let iam_users: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_iam_user" ||
            r.resource_type == "azuread_user"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "iam_users_defined".to_string(),
        description: "IAM users are defined in infrastructure as code".to_string(),
        passed: !iam_users.is_empty() || resources.iter().any(|r| r.resource_type.contains("iam")),
        severity: Severity::Medium,
        actual_value: Some(format!("{} IAM users", iam_users.len())),
        expected_value: Some("IAM resources defined".to_string()),
        evidence_path: None,
    });

    // Check for MFA enforcement (AWS)
    let mfa_policies: Vec<_> = resources.iter()
        .filter(|r| {
            if r.resource_type == "aws_iam_policy" {
                if let Some(policy) = r.get_attr("policy").and_then(|p| p.as_str()) {
                    return policy.contains("aws:MultiFactorAuthPresent");
                }
            }
            false
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "mfa_policy".to_string(),
        description: "MFA enforcement policies are defined".to_string(),
        passed: !mfa_policies.is_empty(),
        severity: Severity::High,
        actual_value: Some(format!("{} MFA policies", mfa_policies.len())),
        expected_value: Some("MFA enforcement policy".to_string()),
        evidence_path: None,
    });

    // Check for identity provider (SSO)
    let identity_providers: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_iam_saml_provider" ||
            r.resource_type == "aws_iam_openid_connect_provider" ||
            r.resource_type == "azuread_application"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "identity_provider".to_string(),
        description: "Identity provider (SSO/SAML/OIDC) is configured".to_string(),
        passed: !identity_providers.is_empty(),
        severity: Severity::Medium,
        actual_value: Some(format!("{} identity providers", identity_providers.len())),
        expected_value: Some("Identity provider configured".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-IAM-01",
        ksi_description: "Uniquely identify and authenticate all users.",
        status: if passed == total {
            ComplianceStatus::Compliant
        } else if passed > 0 {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::NonCompliant
        },
        relevance: Relevance::Supporting,
        summary: format!("{} of {} checks passed", passed, total),
        recommendations: if passed < total {
            vec![
                "Implement MFA enforcement policies".to_string(),
                "Configure SSO/identity federation".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-IAM-04: Apply least privilege access controls
fn validate_ksi_iam_04(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for IAM roles (preferred over users)
    let iam_roles: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_iam_role" ||
            r.resource_type == "azurerm_role_definition"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "iam_roles_defined".to_string(),
        description: "IAM roles are defined for service access".to_string(),
        passed: !iam_roles.is_empty(),
        severity: Severity::High,
        actual_value: Some(format!("{} IAM roles", iam_roles.len())),
        expected_value: Some("IAM roles for least privilege".to_string()),
        evidence_path: None,
    });

    // Check for overly permissive policies (*:*)
    let overly_permissive: Vec<_> = resources.iter()
        .filter(|r| {
            if r.resource_type.contains("iam_policy") {
                if let Some(policy) = r.get_attr("policy").and_then(|p| p.as_str()) {
                    return policy.contains("\"Action\": \"*\"") ||
                           policy.contains("\"Action\":\"*\"") ||
                           policy.contains("\"Resource\": \"*\"") ||
                           policy.contains("\"Resource\":\"*\"");
                }
            }
            false
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "no_wildcard_permissions".to_string(),
        description: "No IAM policies use wildcard (*) permissions".to_string(),
        passed: overly_permissive.is_empty(),
        severity: Severity::Critical,
        actual_value: Some(format!("{} overly permissive policies", overly_permissive.len())),
        expected_value: Some("0 wildcard policies".to_string()),
        evidence_path: None,
    });

    // Check for role boundaries
    let permission_boundaries: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_iam_role" &&
            r.get_attr("permissions_boundary").is_some()
        })
        .collect();

    if !iam_roles.is_empty() {
        checks.push(ValidationCheck {
            check_name: "permission_boundaries".to_string(),
            description: "IAM roles use permission boundaries".to_string(),
            passed: !permission_boundaries.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{}/{} roles with boundaries", permission_boundaries.len(), iam_roles.len())),
            expected_value: Some("Permission boundaries configured".to_string()),
            evidence_path: None,
        });
    }

    // Check for assume role policies
    let assume_role_policies = iam_roles.iter()
        .filter(|r| r.get_attr("assume_role_policy").is_some())
        .count();

    checks.push(ValidationCheck {
        check_name: "assume_role_policies".to_string(),
        description: "IAM roles have assume role policies defined".to_string(),
        passed: iam_roles.is_empty() || assume_role_policies == iam_roles.len(),
        severity: Severity::High,
        actual_value: Some(format!("{}/{} roles with assume policies", assume_role_policies, iam_roles.len())),
        expected_value: Some("All roles have assume policies".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();
    let critical_failures = checks.iter().filter(|c| !c.passed && c.severity == Severity::Critical).count();

    KsiValidationResult {
        ksi_id: "KSI-IAM-04",
        ksi_description: "Apply least privilege access controls.",
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
            vec![
                "Remove wildcard (*) permissions from IAM policies".to_string(),
                "Implement least-privilege access policies".to_string(),
            ]
        } else if passed < total {
            vec!["Consider implementing permission boundaries".to_string()]
        } else {
            vec![]
        },
        checks,
    }
}
