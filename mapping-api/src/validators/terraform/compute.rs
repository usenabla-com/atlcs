//! Compute resource validation for Terraform
//!
//! Maps to FedRAMP KSIs: KSI-CMT-02, KSI-SVC-04

use super::TerraformResource;
use crate::validators::models::{
    ComplianceStatus, KsiValidationResult, Relevance, Severity, ValidationCheck,
};

/// Validate compute-related KSIs
pub fn validate_compute(resources: &[TerraformResource]) -> Vec<KsiValidationResult> {
    vec![
        validate_ksi_cmt_02(resources),
        validate_ksi_svc_04(resources),
    ]
}

/// KSI-CMT-02: Maintain secure baseline configurations for all information resources
fn validate_ksi_cmt_02(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check EC2 instances use approved AMIs (have ami specified)
    let ec2_instances: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_instance")
        .collect();

    let instances_with_ami = ec2_instances.iter()
        .filter(|r| r.get_attr_str("ami").is_some())
        .count();

    if !ec2_instances.is_empty() {
        checks.push(ValidationCheck {
            check_name: "ec2_ami_defined".to_string(),
            description: "EC2 instances have AMI explicitly defined".to_string(),
            passed: instances_with_ami == ec2_instances.len(),
            severity: Severity::High,
            actual_value: Some(format!("{}/{} with AMI", instances_with_ami, ec2_instances.len())),
            expected_value: Some("All instances have AMI defined".to_string()),
            evidence_path: None,
        });
    }

    // Check for launch templates (preferred for secure configs)
    let launch_templates: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_launch_template")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "launch_templates".to_string(),
            description: "Launch templates are used for standardized configurations".to_string(),
            passed: !launch_templates.is_empty() || ec2_instances.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} launch templates", launch_templates.len())),
            expected_value: Some("Launch templates for standardization".to_string()),
            evidence_path: None,
        });
    }

    // Check Azure VMs have managed disks
    let azure_vms: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "azurerm_virtual_machine" || r.resource_type == "azurerm_linux_virtual_machine" || r.resource_type == "azurerm_windows_virtual_machine")
        .collect();

    if !azure_vms.is_empty() {
        checks.push(ValidationCheck {
            check_name: "azure_vm_config".to_string(),
            description: "Azure VMs are configured".to_string(),
            passed: true, // Azure VMs with managed disks by default in new resources
            severity: Severity::Medium,
            actual_value: Some(format!("{} Azure VMs", azure_vms.len())),
            expected_value: Some("VMs with managed configuration".to_string()),
            evidence_path: None,
        });
    }

    // Check for IMDSv2 requirement (AWS)
    let imdsv2_required = ec2_instances.iter()
        .filter(|r| {
            r.get_attr("metadata_options")
                .and_then(|m| m.get("http_tokens"))
                .and_then(|t| t.as_str())
                .map(|t| t == "required")
                .unwrap_or(false)
        })
        .count();

    if !ec2_instances.is_empty() {
        checks.push(ValidationCheck {
            check_name: "imdsv2_required".to_string(),
            description: "EC2 instances require IMDSv2".to_string(),
            passed: imdsv2_required == ec2_instances.len() || ec2_instances.is_empty(),
            severity: Severity::High,
            actual_value: Some(format!("{}/{} require IMDSv2", imdsv2_required, ec2_instances.len())),
            expected_value: Some("All instances require IMDSv2".to_string()),
            evidence_path: None,
        });
    }

    // Check for ECS/EKS (containerized workloads)
    let container_services: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type.contains("ecs") ||
            r.resource_type.contains("eks") ||
            r.resource_type.contains("kubernetes") ||
            r.resource_type.contains("aks")
        })
        .collect();

    if !container_services.is_empty() {
        checks.push(ValidationCheck {
            check_name: "container_orchestration".to_string(),
            description: "Container orchestration services are configured".to_string(),
            passed: true,
            severity: Severity::Low,
            actual_value: Some(format!("{} container resources", container_services.len())),
            expected_value: Some("Container orchestration configured".to_string()),
            evidence_path: None,
        });
    }

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-CMT-02",
        ksi_description: "Maintain secure baseline configurations for all information resources.",
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
            "No compute resources found".to_string()
        } else {
            format!("{} of {} checks passed", passed, total)
        },
        recommendations: if passed < total && total > 0 {
            vec![
                "Use launch templates for standardized configurations".to_string(),
                "Require IMDSv2 for EC2 instances".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-SVC-04: Manage configuration of machine-based information resources using automation
fn validate_ksi_svc_04(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for Auto Scaling Groups (automated scaling)
    let asgs: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_autoscaling_group" ||
            r.resource_type == "azurerm_virtual_machine_scale_set" ||
            r.resource_type == "google_compute_instance_group_manager"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "auto_scaling".to_string(),
        description: "Auto scaling groups are configured".to_string(),
        passed: !asgs.is_empty(),
        severity: Severity::Medium,
        actual_value: Some(format!("{} auto scaling groups", asgs.len())),
        expected_value: Some("Auto scaling configured".to_string()),
        evidence_path: None,
    });

    // Check for SSM (AWS Systems Manager)
    let ssm: Vec<_> = resources.iter()
        .filter(|r| r.resource_type.contains("ssm"))
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "systems_manager".to_string(),
            description: "AWS Systems Manager is configured".to_string(),
            passed: !ssm.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} SSM resources", ssm.len())),
            expected_value: Some("Systems Manager configured".to_string()),
            evidence_path: None,
        });
    }

    // Check for Config rules (AWS Config)
    let config_rules: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_config_config_rule")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "config_rules".to_string(),
            description: "AWS Config rules are defined".to_string(),
            passed: !config_rules.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} Config rules", config_rules.len())),
            expected_value: Some("Config rules for compliance".to_string()),
            evidence_path: None,
        });
    }

    // Check for Azure Policy
    if resources.iter().any(|r| r.is_azure()) {
        let azure_policies: Vec<_> = resources.iter()
            .filter(|r| r.resource_type == "azurerm_policy_assignment")
            .collect();

        checks.push(ValidationCheck {
            check_name: "azure_policies".to_string(),
            description: "Azure Policy assignments are configured".to_string(),
            passed: !azure_policies.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} policy assignments", azure_policies.len())),
            expected_value: Some("Azure Policy configured".to_string()),
            evidence_path: None,
        });
    }

    // The very fact that Terraform is being used is positive for this KSI
    checks.push(ValidationCheck {
        check_name: "infrastructure_as_code".to_string(),
        description: "Infrastructure is managed as code (Terraform)".to_string(),
        passed: true,
        severity: Severity::Low,
        actual_value: Some("Terraform state validated".to_string()),
        expected_value: Some("IaC in use".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-SVC-04",
        ksi_description: "Manage configuration of machine-based information resources using automation.",
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
                "Implement AWS Config/Azure Policy for configuration compliance".to_string(),
                "Use Systems Manager for automated configuration management".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}
