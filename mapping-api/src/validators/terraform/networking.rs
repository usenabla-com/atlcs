//! Networking validation for Terraform resources
//!
//! Maps to FedRAMP KSIs: KSI-CNA-01, KSI-CNA-02, KSI-CNA-03, KSI-CNA-06

use super::TerraformResource;
use crate::validators::models::{
    ComplianceStatus, KsiValidationResult, Relevance, Severity, ValidationCheck,
};

/// Validate networking-related KSIs
pub fn validate_networking(resources: &[TerraformResource]) -> Vec<KsiValidationResult> {
    vec![
        validate_ksi_cna_01(resources),
        validate_ksi_cna_03(resources),
        validate_ksi_cna_06(resources),
    ]
}

/// KSI-CNA-01: Configure ALL machine-based information resources to limit inbound and outbound traffic
fn validate_ksi_cna_01(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check security groups
    let security_groups: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_security_group" ||
            r.resource_type == "azurerm_network_security_group" ||
            r.resource_type == "google_compute_firewall"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "security_groups_exist".to_string(),
        description: "Security groups/firewall rules are defined".to_string(),
        passed: !security_groups.is_empty(),
        severity: Severity::Critical,
        actual_value: Some(format!("{} security groups", security_groups.len())),
        expected_value: Some("At least 1 security group".to_string()),
        evidence_path: None,
    });

    // Check for overly permissive rules (0.0.0.0/0)
    let overly_permissive = security_groups.iter()
        .filter(|r| {
            let ingress = r.get_attr("ingress");
            if let Some(rules) = ingress.and_then(|v| v.as_array()) {
                rules.iter().any(|rule| {
                    rule.get("cidr_blocks")
                        .and_then(|c| c.as_array())
                        .map(|arr| arr.iter().any(|v| v.as_str() == Some("0.0.0.0/0")))
                        .unwrap_or(false)
                })
            } else {
                false
            }
        })
        .count();

    checks.push(ValidationCheck {
        check_name: "no_open_ingress".to_string(),
        description: "No security groups allow unrestricted inbound access (0.0.0.0/0)".to_string(),
        passed: overly_permissive == 0,
        severity: Severity::High,
        actual_value: Some(format!("{} overly permissive rules", overly_permissive)),
        expected_value: Some("0 rules with 0.0.0.0/0".to_string()),
        evidence_path: None,
    });

    // Check for NACLs (AWS)
    let nacls: Vec<_> = resources.iter()
        .filter(|r| r.resource_type == "aws_network_acl")
        .collect();

    if resources.iter().any(|r| r.is_aws()) {
        checks.push(ValidationCheck {
            check_name: "nacls_configured".to_string(),
            description: "Network ACLs are configured for defense in depth".to_string(),
            passed: !nacls.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} NACLs", nacls.len())),
            expected_value: Some("NACLs configured".to_string()),
            evidence_path: None,
        });
    }

    // Check VPC flow logs
    let flow_logs: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_flow_log" ||
            r.resource_type == "azurerm_network_watcher_flow_log"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "flow_logs_enabled".to_string(),
        description: "VPC/Network flow logs are enabled".to_string(),
        passed: !flow_logs.is_empty(),
        severity: Severity::Medium,
        actual_value: Some(format!("{} flow logs", flow_logs.len())),
        expected_value: Some("Flow logs enabled".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();
    let critical_failures = checks.iter().filter(|c| !c.passed && c.severity == Severity::Critical).count();

    KsiValidationResult {
        ksi_id: "KSI-CNA-01",
        ksi_description: "Configure ALL machine-based information resources to limit inbound and outbound traffic.",
        status: if critical_failures > 0 {
            ComplianceStatus::NonCompliant
        } else if passed == total {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::PartiallyCompliant
        },
        relevance: Relevance::Direct,
        summary: format!("{} of {} checks passed", passed, total),
        recommendations: if passed < total {
            vec![
                "Define security groups with least-privilege access".to_string(),
                "Avoid 0.0.0.0/0 in ingress rules".to_string(),
                "Enable VPC flow logs for monitoring".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-CNA-03: Segment networks and services appropriately
fn validate_ksi_cna_03(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for VPCs
    let vpcs: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_vpc" ||
            r.resource_type == "azurerm_virtual_network" ||
            r.resource_type == "google_compute_network"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "vpc_defined".to_string(),
        description: "Virtual private cloud/network is defined".to_string(),
        passed: !vpcs.is_empty(),
        severity: Severity::Critical,
        actual_value: Some(format!("{} VPCs", vpcs.len())),
        expected_value: Some("At least 1 VPC".to_string()),
        evidence_path: None,
    });

    // Check for subnets
    let subnets: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_subnet" ||
            r.resource_type == "azurerm_subnet" ||
            r.resource_type == "google_compute_subnetwork"
        })
        .collect();

    let private_subnets = subnets.iter()
        .filter(|r| {
            r.get_attr_bool("map_public_ip_on_launch") == Some(false) ||
            r.name.to_lowercase().contains("private")
        })
        .count();

    checks.push(ValidationCheck {
        check_name: "subnet_segmentation".to_string(),
        description: "Network is segmented into multiple subnets".to_string(),
        passed: subnets.len() >= 2,
        severity: Severity::High,
        actual_value: Some(format!("{} subnets ({} private)", subnets.len(), private_subnets)),
        expected_value: Some("Multiple subnets for segmentation".to_string()),
        evidence_path: None,
    });

    // Check for private subnets
    checks.push(ValidationCheck {
        check_name: "private_subnets".to_string(),
        description: "Private subnets are configured".to_string(),
        passed: private_subnets > 0 || subnets.is_empty(),
        severity: Severity::High,
        actual_value: Some(format!("{} private subnets", private_subnets)),
        expected_value: Some("At least 1 private subnet".to_string()),
        evidence_path: None,
    });

    // Check for NAT gateway (for private subnet internet access)
    let nat_gateways: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_nat_gateway" ||
            r.resource_type == "azurerm_nat_gateway" ||
            r.resource_type == "google_compute_router_nat"
        })
        .collect();

    if private_subnets > 0 {
        checks.push(ValidationCheck {
            check_name: "nat_gateway".to_string(),
            description: "NAT gateway configured for private subnet egress".to_string(),
            passed: !nat_gateways.is_empty(),
            severity: Severity::Medium,
            actual_value: Some(format!("{} NAT gateways", nat_gateways.len())),
            expected_value: Some("NAT gateway for private subnets".to_string()),
            evidence_path: None,
        });
    }

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-CNA-03",
        ksi_description: "Segment networks and services appropriately.",
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
                "Create separate VPCs or subnets for different workloads".to_string(),
                "Use private subnets for sensitive resources".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}

/// KSI-CNA-06: Implement boundary protection
fn validate_ksi_cna_06(resources: &[TerraformResource]) -> KsiValidationResult {
    let mut checks = Vec::new();

    // Check for WAF
    let waf: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type.contains("waf") ||
            r.resource_type == "azurerm_web_application_firewall_policy"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "waf_configured".to_string(),
        description: "Web Application Firewall is configured".to_string(),
        passed: !waf.is_empty(),
        severity: Severity::Medium,
        actual_value: Some(format!("{} WAF resources", waf.len())),
        expected_value: Some("WAF configured".to_string()),
        evidence_path: None,
    });

    // Check for internet gateway (controlled access)
    let igw: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type == "aws_internet_gateway" ||
            r.resource_type == "azurerm_public_ip"
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "controlled_internet_access".to_string(),
        description: "Internet access is controlled through defined gateways".to_string(),
        passed: !igw.is_empty(),
        severity: Severity::Low,
        actual_value: Some(format!("{} internet gateways/public IPs", igw.len())),
        expected_value: Some("Controlled internet access".to_string()),
        evidence_path: None,
    });

    // Check for VPN or Direct Connect
    let vpn: Vec<_> = resources.iter()
        .filter(|r| {
            r.resource_type.contains("vpn") ||
            r.resource_type.contains("direct_connect") ||
            r.resource_type.contains("express_route")
        })
        .collect();

    checks.push(ValidationCheck {
        check_name: "private_connectivity".to_string(),
        description: "Private connectivity (VPN/Direct Connect) is configured".to_string(),
        passed: !vpn.is_empty(),
        severity: Severity::Low,
        actual_value: Some(format!("{} VPN/private connections", vpn.len())),
        expected_value: Some("Private connectivity available".to_string()),
        evidence_path: None,
    });

    let passed = checks.iter().filter(|c| c.passed).count();
    let total = checks.len();

    KsiValidationResult {
        ksi_id: "KSI-CNA-06",
        ksi_description: "Implement boundary protection.",
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
                "Consider implementing a Web Application Firewall".to_string(),
                "Establish VPN for private connectivity".to_string(),
            ]
        } else {
            vec![]
        },
        checks,
    }
}
