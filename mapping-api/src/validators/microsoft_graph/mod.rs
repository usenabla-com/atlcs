pub mod conditional_access;
pub mod user_mfa;
pub mod sign_in_logs;
pub mod audit_logs;
pub mod directory_roles;
pub mod security_alerts;
pub mod compliance_policies;
pub mod device_configurations;
pub mod risk_detections;
pub mod secure_score;

use serde_json::Value;
use crate::validators::models::{KsiValidationResult, ValidationResponse, OverallComplianceStatus, ValidationMetadata};

pub use conditional_access::validate_conditional_access_policies;
pub use user_mfa::validate_user_mfa_status;
pub use sign_in_logs::validate_sign_in_logs;
pub use audit_logs::validate_audit_logs;
pub use directory_roles::validate_directory_roles;
pub use security_alerts::validate_security_alerts;
pub use compliance_policies::validate_compliance_policies;
pub use device_configurations::validate_device_configurations;
pub use risk_detections::validate_risk_detections;
pub use secure_score::validate_secure_score;

/// Main entry point for Microsoft Graph validation
pub fn validate_microsoft_graph_evidence(
    evidence_type: &str,
    data: &Value,
    tenant_id: &str,
    collected_at: &str,
    validated_by_tenant: &str,
    license_type: &str,
) -> ValidationResponse {
    let (ksi_results, records_processed) = match evidence_type {
        "conditional_access_policies" => validate_conditional_access_policies(data),
        "user_mfa_status" => validate_user_mfa_status(data),
        "sign_in_logs" => validate_sign_in_logs(data),
        "audit_logs" => validate_audit_logs(data),
        "directory_roles" => validate_directory_roles(data),
        "security_alerts" => validate_security_alerts(data),
        "compliance_policies" => validate_compliance_policies(data),
        "device_configurations" => validate_device_configurations(data),
        "risk_detections" => validate_risk_detections(data),
        "secure_score" => validate_secure_score(data),
        _ => (vec![], 0),
    };

    let overall_status = OverallComplianceStatus::from_results(&ksi_results);

    ValidationResponse {
        source: "microsoft-graph".to_string(),
        evidence_type: evidence_type.to_string(),
        tenant_id: tenant_id.to_string(),
        collected_at: collected_at.to_string(),
        validated_at: chrono::Utc::now().to_rfc3339(),
        overall_status,
        ksi_results,
        unused_fields: vec![], // Could track this if needed
        metadata: ValidationMetadata {
            validated_by_tenant: validated_by_tenant.to_string(),
            license_type: license_type.to_string(),
            records_processed,
            engine_version: env!("CARGO_PKG_VERSION"),
        },
    }
}
