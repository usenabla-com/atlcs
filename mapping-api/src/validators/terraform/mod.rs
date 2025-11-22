//! Terraform State validators for compliance mapping
//!
//! Validates Terraform state files against FedRAMP 20x KSIs and CMMC practices.

mod encryption;
mod networking;
mod iam;
mod logging;
mod compute;

use serde_json::Value;
use crate::validators::models::{
    ValidationResponse, KsiValidationResult, OverallComplianceStatus, ValidationMetadata,
};

pub use encryption::validate_encryption;
pub use networking::validate_networking;
pub use iam::validate_iam;
pub use logging::validate_logging;
pub use compute::validate_compute;

/// Terraform evidence types that can be validated
#[derive(Debug, Clone, Copy)]
pub enum TerraformEvidenceType {
    /// Full Terraform state file
    FullState,
    /// AWS resources only
    AwsResources,
    /// Azure resources only
    AzureResources,
    /// GCP resources only
    GcpResources,
    /// Kubernetes resources
    KubernetesResources,
}

impl TerraformEvidenceType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "full_state" => Some(Self::FullState),
            "aws_resources" => Some(Self::AwsResources),
            "azure_resources" => Some(Self::AzureResources),
            "gcp_resources" => Some(Self::GcpResources),
            "kubernetes_resources" => Some(Self::KubernetesResources),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FullState => "full_state",
            Self::AwsResources => "aws_resources",
            Self::AzureResources => "azure_resources",
            Self::GcpResources => "gcp_resources",
            Self::KubernetesResources => "kubernetes_resources",
        }
    }
}

/// Main validation function for Terraform state
pub fn validate_terraform_state(
    evidence_type: &str,
    data: &Value,
    tenant_id: &str,
    collected_at: &str,
    validated_by_tenant: &str,
    license_type: &str,
) -> ValidationResponse {
    let resources = extract_resources(data);

    let mut ksi_results: Vec<KsiValidationResult> = Vec::new();

    // Run all validators
    ksi_results.extend(validate_encryption(&resources));
    ksi_results.extend(validate_networking(&resources));
    ksi_results.extend(validate_iam(&resources));
    ksi_results.extend(validate_logging(&resources));
    ksi_results.extend(validate_compute(&resources));

    // Calculate overall status
    let compliant = ksi_results.iter().filter(|r| r.status == crate::validators::models::ComplianceStatus::Compliant).count();
    let partially = ksi_results.iter().filter(|r| r.status == crate::validators::models::ComplianceStatus::PartiallyCompliant).count();
    let non_compliant = ksi_results.iter().filter(|r| r.status == crate::validators::models::ComplianceStatus::NonCompliant).count();
    let indeterminate = ksi_results.iter().filter(|r| r.status == crate::validators::models::ComplianceStatus::Indeterminate).count();

    let total = ksi_results.len();
    let score = if total > 0 {
        ((compliant as f64 + (partially as f64 * 0.5)) / total as f64) * 100.0
    } else {
        0.0
    };

    ValidationResponse {
        source: "terraform".to_string(),
        evidence_type: evidence_type.to_string(),
        tenant_id: tenant_id.to_string(),
        collected_at: collected_at.to_string(),
        validated_at: chrono::Utc::now().to_rfc3339(),
        overall_status: OverallComplianceStatus {
            compliant,
            partially_compliant: partially,
            non_compliant,
            indeterminate,
            score,
        },
        ksi_results,
        unused_fields: vec![],
        metadata: ValidationMetadata {
            validated_by_tenant: validated_by_tenant.to_string(),
            license_type: license_type.to_string(),
            records_processed: resources.len(),
            engine_version: env!("CARGO_PKG_VERSION"),
        },
    }
}

/// Extract resources from Terraform state
fn extract_resources(data: &Value) -> Vec<TerraformResource> {
    let mut resources = Vec::new();

    // Handle Terraform state format (v4)
    if let Some(state_resources) = data.get("resources").and_then(|r| r.as_array()) {
        for resource in state_resources {
            if let Some(res) = parse_resource(resource) {
                resources.push(res);
            }
        }
    }

    // Handle array of resources directly
    if let Some(arr) = data.get("value").and_then(|v| v.as_array()) {
        for resource in arr {
            if let Some(res) = parse_resource(resource) {
                resources.push(res);
            }
        }
    }

    // Handle direct array
    if let Some(arr) = data.as_array() {
        for resource in arr {
            if let Some(res) = parse_resource(resource) {
                resources.push(res);
            }
        }
    }

    resources
}

fn parse_resource(value: &Value) -> Option<TerraformResource> {
    let resource_type = value.get("type").and_then(|t| t.as_str())
        .or_else(|| value.get("resource_type").and_then(|t| t.as_str()))?;

    let name = value.get("name").and_then(|n| n.as_str())
        .or_else(|| value.get("resource_name").and_then(|n| n.as_str()))
        .unwrap_or("unknown");

    let provider = value.get("provider").and_then(|p| p.as_str())
        .map(|p| p.to_string())
        .or_else(|| infer_provider(resource_type));

    // Get attributes from instances or directly
    let attributes = if let Some(instances) = value.get("instances").and_then(|i| i.as_array()) {
        instances.first()
            .and_then(|i| i.get("attributes"))
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        value.get("attributes").cloned()
            .or_else(|| value.get("values").cloned())
            .unwrap_or(Value::Null)
    };

    Some(TerraformResource {
        resource_type: resource_type.to_string(),
        name: name.to_string(),
        provider,
        attributes,
    })
}

fn infer_provider(resource_type: &str) -> Option<String> {
    if resource_type.starts_with("aws_") {
        Some("aws".to_string())
    } else if resource_type.starts_with("azurerm_") || resource_type.starts_with("azuread_") {
        Some("azure".to_string())
    } else if resource_type.starts_with("google_") {
        Some("gcp".to_string())
    } else if resource_type.starts_with("kubernetes_") {
        Some("kubernetes".to_string())
    } else {
        None
    }
}

/// Represents a Terraform resource
#[derive(Debug, Clone)]
pub struct TerraformResource {
    pub resource_type: String,
    pub name: String,
    pub provider: Option<String>,
    pub attributes: Value,
}

impl TerraformResource {
    pub fn get_attr(&self, key: &str) -> Option<&Value> {
        self.attributes.get(key)
    }

    pub fn get_attr_str(&self, key: &str) -> Option<&str> {
        self.get_attr(key).and_then(|v| v.as_str())
    }

    pub fn get_attr_bool(&self, key: &str) -> Option<bool> {
        self.get_attr(key).and_then(|v| v.as_bool())
    }

    pub fn is_aws(&self) -> bool {
        self.resource_type.starts_with("aws_")
    }

    pub fn is_azure(&self) -> bool {
        self.resource_type.starts_with("azurerm_") || self.resource_type.starts_with("azuread_")
    }

    pub fn is_gcp(&self) -> bool {
        self.resource_type.starts_with("google_")
    }
}
