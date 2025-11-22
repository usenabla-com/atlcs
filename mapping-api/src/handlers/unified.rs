//! Unified mapping handlers
//!
//! Provides consolidated endpoints:
//! - GET  /api/v1/frameworks/evidence-types?source={source}
//! - POST /api/v1/frameworks/map

use axum::{
    extract::{Extension, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::auth::{Claims, Framework, LicenseType, Scope};
use crate::catalogs::cmmc::{get_practices_by_nist_control, nist_control_matches, CmmcPractice};
use crate::validators::microsoft_graph::validate_microsoft_graph_evidence;
use crate::validators::terraform::validate_terraform_state;
use crate::validators::ValidationResponse;

// ============================================================================
// Common Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetFramework {
    #[default]
    Fedramp20x,
    Cmmc,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    MicrosoftGraph,
    Terraform,
}

impl EvidenceSource {
    fn as_str(&self) -> &'static str {
        match self {
            Self::MicrosoftGraph => "microsoft-graph",
            Self::Terraform => "terraform",
        }
    }
}

// ============================================================================
// Evidence Types Query
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EvidenceTypesQuery {
    /// Source to list evidence types for (optional - returns all if not specified)
    pub source: Option<EvidenceSource>,
}

#[derive(Debug, Serialize)]
pub struct UnifiedEvidenceTypeInfo {
    pub source: String,
    pub evidence_type: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_resources: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedramp_ksis: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmmc_practices: Option<Vec<String>>,
}

/// GET /api/v1/frameworks/evidence-types
///
/// List available evidence types with optional source filter
pub async fn list_evidence_types(
    Extension(claims): Extension<Claims>,
    Query(query): Query<EvidenceTypesQuery>,
) -> Result<Json<Vec<UnifiedEvidenceTypeInfo>>, (StatusCode, Json<ErrorResponse>)> {
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    let has_fedramp = claims.has_framework(Framework::Fedramp20x);
    let has_cmmc = claims.has_framework(Framework::Cmmc);

    let mut evidence_types = Vec::new();

    // Add Microsoft Graph evidence types
    if query.source.is_none() || query.source == Some(EvidenceSource::MicrosoftGraph) {
        evidence_types.extend(get_msgraph_evidence_types(has_fedramp, has_cmmc));
    }

    // Add Terraform evidence types
    if query.source.is_none() || query.source == Some(EvidenceSource::Terraform) {
        evidence_types.extend(get_terraform_evidence_types(has_fedramp, has_cmmc));
    }

    Ok(Json(evidence_types))
}

fn get_msgraph_evidence_types(has_fedramp: bool, has_cmmc: bool) -> Vec<UnifiedEvidenceTypeInfo> {
    vec![
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "conditional_access_policies".to_string(),
            description: "Azure AD Conditional Access policies for access control".to_string(),
            api_endpoint: Some("/identity/conditionalAccess/policies".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec![
                    "KSI-IAM-01", "KSI-IAM-02", "KSI-IAM-03", "KSI-IAM-04",
                    "KSI-IAM-05", "KSI-IAM-06", "KSI-CNA-01"
                ].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["AC-2", "AC-3", "AC-6", "AC-7", "AC-11", "AC-12", "AC-17", "AC-20", "IA-2", "IA-5"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "user_mfa_status".to_string(),
            description: "User MFA registration and authentication methods".to_string(),
            api_endpoint: Some("/reports/authenticationMethods/userRegistrationDetails".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-IAM-01", "KSI-IAM-02"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["IA-2", "IA-5"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "sign_in_logs".to_string(),
            description: "User and service principal sign-in activity".to_string(),
            api_endpoint: Some("/auditLogs/signIns".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-MLA-01", "KSI-MLA-02", "KSI-MLA-07", "KSI-IAM-02", "KSI-IAM-05"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["AC-2", "AC-7", "AU-2", "AU-3", "AU-6", "AU-12", "SI-4"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "audit_logs".to_string(),
            description: "Directory audit logs for configuration changes".to_string(),
            api_endpoint: Some("/auditLogs/directoryAudits".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-MLA-01", "KSI-CMT-01", "KSI-IAM-04", "KSI-IAM-07"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["AU-2", "AU-3", "AU-6", "AU-7", "AU-11", "AU-12", "CM-3"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "directory_roles".to_string(),
            description: "Azure AD directory roles and assignments".to_string(),
            api_endpoint: Some("/directoryRoles".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-IAM-04", "KSI-IAM-07"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["AC-2", "AC-5", "AC-6"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "security_alerts".to_string(),
            description: "Microsoft 365 Defender security alerts".to_string(),
            api_endpoint: Some("/security/alerts_v2".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-INR-01", "KSI-INR-02", "KSI-MLA-02"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["IR-4", "IR-5", "IR-6", "SI-4", "SI-5"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "compliance_policies".to_string(),
            description: "Intune device compliance policies".to_string(),
            api_endpoint: Some("/deviceManagement/deviceCompliancePolicies".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-SVC-03", "KSI-SVC-04", "KSI-CMT-02", "KSI-MLA-03", "KSI-CNA-04"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["CM-2", "CM-6", "CM-7", "SC-28", "SI-2", "SI-3"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "device_configurations".to_string(),
            description: "Intune device configuration profiles".to_string(),
            api_endpoint: Some("/deviceManagement/deviceConfigurations".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-SVC-01", "KSI-SVC-03", "KSI-SVC-04", "KSI-CNA-01", "KSI-CNA-04"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["CM-2", "CM-6", "CM-7", "AC-19", "SC-28"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "risk_detections".to_string(),
            description: "Identity Protection risk detections".to_string(),
            api_endpoint: Some("/identityProtection/riskDetections".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-MLA-02", "KSI-IAM-05", "KSI-IAM-06"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["RA-3", "RA-5", "SI-4", "AC-2"]))
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "microsoft-graph".to_string(),
            evidence_type: "secure_score".to_string(),
            description: "Microsoft Secure Score assessment".to_string(),
            api_endpoint: Some("/security/secureScores".to_string()),
            example_resources: None,
            fedramp_ksis: if has_fedramp {
                Some(vec!["KSI-SVC-01", "KSI-MLA-05", "KSI-IAM-02", "KSI-SVC-03"].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(get_cmmc_practices_for_controls(&["CA-2", "CA-7", "RA-3", "RA-5"]))
            } else { None },
        },
    ]
}

fn get_terraform_evidence_types(has_fedramp: bool, has_cmmc: bool) -> Vec<UnifiedEvidenceTypeInfo> {
    vec![
        UnifiedEvidenceTypeInfo {
            source: "terraform".to_string(),
            evidence_type: "full_state".to_string(),
            description: "Complete Terraform state file with all resources".to_string(),
            api_endpoint: None,
            example_resources: Some(vec![
                "aws_instance", "aws_s3_bucket", "aws_security_group",
                "azurerm_virtual_machine", "google_compute_instance"
            ].into_iter().map(String::from).collect()),
            fedramp_ksis: if has_fedramp {
                Some(vec![
                    "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-04", "KSI-SVC-06",
                    "KSI-CNA-01", "KSI-CNA-03", "KSI-CNA-06",
                    "KSI-IAM-01", "KSI-IAM-04",
                    "KSI-MLA-01", "KSI-MLA-02",
                    "KSI-CMT-02"
                ].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(vec![
                    "AC.L1-3.1.1", "AC.L1-3.1.2", "AC.L2-3.1.5",
                    "SC.L1-3.13.1", "SC.L2-3.13.8", "SC.L2-3.13.11",
                    "CM.L2-3.4.1", "CM.L2-3.4.2",
                    "AU.L2-3.3.1", "AU.L2-3.3.2"
                ].into_iter().map(String::from).collect())
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "terraform".to_string(),
            evidence_type: "aws_resources".to_string(),
            description: "AWS-specific resources from Terraform state".to_string(),
            api_endpoint: None,
            example_resources: Some(vec![
                "aws_instance", "aws_s3_bucket", "aws_security_group",
                "aws_iam_role", "aws_kms_key", "aws_cloudtrail"
            ].into_iter().map(String::from).collect()),
            fedramp_ksis: if has_fedramp {
                Some(vec![
                    "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-06",
                    "KSI-CNA-01", "KSI-CNA-03",
                    "KSI-IAM-04", "KSI-MLA-01", "KSI-MLA-02"
                ].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(vec![
                    "AC.L1-3.1.1", "SC.L1-3.13.1", "SC.L2-3.13.11",
                    "CM.L2-3.4.1", "AU.L2-3.3.1"
                ].into_iter().map(String::from).collect())
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "terraform".to_string(),
            evidence_type: "azure_resources".to_string(),
            description: "Azure-specific resources from Terraform state".to_string(),
            api_endpoint: None,
            example_resources: Some(vec![
                "azurerm_virtual_machine", "azurerm_storage_account",
                "azurerm_network_security_group", "azurerm_key_vault"
            ].into_iter().map(String::from).collect()),
            fedramp_ksis: if has_fedramp {
                Some(vec![
                    "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-06",
                    "KSI-CNA-01", "KSI-CNA-03",
                    "KSI-MLA-01", "KSI-MLA-02"
                ].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(vec![
                    "AC.L1-3.1.1", "SC.L1-3.13.1", "SC.L2-3.13.11",
                    "CM.L2-3.4.1", "AU.L2-3.3.1"
                ].into_iter().map(String::from).collect())
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "terraform".to_string(),
            evidence_type: "gcp_resources".to_string(),
            description: "GCP-specific resources from Terraform state".to_string(),
            api_endpoint: None,
            example_resources: Some(vec![
                "google_compute_instance", "google_storage_bucket",
                "google_compute_firewall", "google_kms_crypto_key"
            ].into_iter().map(String::from).collect()),
            fedramp_ksis: if has_fedramp {
                Some(vec![
                    "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-06",
                    "KSI-CNA-01", "KSI-CNA-03",
                    "KSI-MLA-01"
                ].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(vec![
                    "AC.L1-3.1.1", "SC.L1-3.13.1", "SC.L2-3.13.11"
                ].into_iter().map(String::from).collect())
            } else { None },
        },
        UnifiedEvidenceTypeInfo {
            source: "terraform".to_string(),
            evidence_type: "kubernetes_resources".to_string(),
            description: "Kubernetes resources from Terraform state".to_string(),
            api_endpoint: None,
            example_resources: Some(vec![
                "kubernetes_deployment", "kubernetes_service",
                "kubernetes_network_policy", "kubernetes_secret"
            ].into_iter().map(String::from).collect()),
            fedramp_ksis: if has_fedramp {
                Some(vec![
                    "KSI-CNA-01", "KSI-CNA-03", "KSI-CMT-02", "KSI-SVC-04"
                ].into_iter().map(String::from).collect())
            } else { None },
            cmmc_practices: if has_cmmc {
                Some(vec![
                    "AC.L1-3.1.1", "CM.L2-3.4.1", "CM.L2-3.4.2"
                ].into_iter().map(String::from).collect())
            } else { None },
        },
    ]
}

fn get_cmmc_practices_for_controls(controls: &[&str]) -> Vec<String> {
    let mut practice_ids: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for control in controls {
        for practice in get_practices_by_nist_control(control) {
            if seen.insert(practice.id) {
                practice_ids.push(practice.id.to_string());
            }
        }
    }

    practice_ids
}

// ============================================================================
// Unified Mapping
// ============================================================================

/// Unified mapping request body
#[derive(Debug, Deserialize)]
pub struct UnifiedMappingRequest {
    /// Evidence source
    pub source: EvidenceSource,
    /// Target framework (defaults to fedramp-20x)
    #[serde(default)]
    pub framework: TargetFramework,
    /// Source identifier (tenant_id for msgraph, state_id for terraform)
    pub source_id: String,
    /// Evidence type being submitted
    pub evidence_type: String,
    /// Raw data from the source
    pub data: serde_json::Value,
    /// Timestamp of data collection (ISO 8601)
    pub collected_at: String,
}

/// Unified mapping response
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum UnifiedMappingResponse {
    FedRamp(ValidationResponse),
    Cmmc(CmmcMappingResponse),
}

/// Response for CMMC mapping
#[derive(Debug, Serialize)]
pub struct CmmcMappingResponse {
    pub source: String,
    pub evidence_type: String,
    pub source_id: String,
    pub collected_at: String,
    pub mapped_at: String,
    pub framework: &'static str,
    pub framework_version: &'static str,
    pub mapped_practices: Vec<CmmcPracticeMapping>,
    pub summary: CmmcMappingSummary,
}

#[derive(Debug, Serialize)]
pub struct CmmcPracticeMapping {
    pub practice_id: &'static str,
    pub domain: &'static str,
    pub practice_statement: &'static str,
    pub levels: Vec<String>,
    pub relevance: &'static str,
    pub nist_controls_matched: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct CmmcMappingSummary {
    pub total_practices_mapped: usize,
    pub level1_practices: usize,
    pub level2_practices: usize,
    pub level3_practices: usize,
    pub domains_covered: Vec<String>,
}

/// POST /api/v1/frameworks/map
///
/// Unified mapping endpoint for all sources and frameworks
pub async fn map_evidence(
    Extension(claims): Extension<Claims>,
    Json(request): Json<UnifiedMappingRequest>,
) -> Result<Json<UnifiedMappingResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Verify scope
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required for this operation.".to_string(),
            }),
        ));
    }

    // Verify framework access
    match request.framework {
        TargetFramework::Fedramp20x => {
            if !claims.has_framework(Framework::Fedramp20x) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "framework_not_licensed".to_string(),
                        message: "Your license does not include FedRAMP 20x framework access.".to_string(),
                    }),
                ));
            }
        }
        TargetFramework::Cmmc => {
            if !claims.has_framework(Framework::Cmmc) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "framework_not_licensed".to_string(),
                        message: "Your license does not include CMMC framework access.".to_string(),
                    }),
                ));
            }
        }
    }

    let license_type = match claims.license_type {
        LicenseType::Standard => "standard",
        LicenseType::Enterprise => "enterprise",
    };

    // Route to appropriate handler
    match (&request.source, &request.framework) {
        (EvidenceSource::MicrosoftGraph, TargetFramework::Fedramp20x) => {
            let response = validate_microsoft_graph_evidence(
                &request.evidence_type,
                &request.data,
                &request.source_id,
                &request.collected_at,
                &claims.tenant,
                license_type,
            );
            Ok(Json(UnifiedMappingResponse::FedRamp(response)))
        }
        (EvidenceSource::MicrosoftGraph, TargetFramework::Cmmc) => {
            let nist_controls = get_nist_controls_for_msgraph_evidence(&request.evidence_type);
            let response = map_to_cmmc(
                &request.source,
                &request.evidence_type,
                &request.source_id,
                &request.collected_at,
                &nist_controls,
            );
            Ok(Json(UnifiedMappingResponse::Cmmc(response)))
        }
        (EvidenceSource::Terraform, TargetFramework::Fedramp20x) => {
            let response = validate_terraform_state(
                &request.evidence_type,
                &request.data,
                &request.source_id,
                &request.collected_at,
                &claims.tenant,
                license_type,
            );
            Ok(Json(UnifiedMappingResponse::FedRamp(response)))
        }
        (EvidenceSource::Terraform, TargetFramework::Cmmc) => {
            let nist_controls = get_nist_controls_for_terraform();
            let response = map_to_cmmc(
                &request.source,
                &request.evidence_type,
                &request.source_id,
                &request.collected_at,
                &nist_controls,
            );
            Ok(Json(UnifiedMappingResponse::Cmmc(response)))
        }
    }
}

/// Map evidence to CMMC practices
fn map_to_cmmc(
    source: &EvidenceSource,
    evidence_type: &str,
    source_id: &str,
    collected_at: &str,
    nist_controls: &[&'static str],
) -> CmmcMappingResponse {
    let mut mapped_practices: Vec<CmmcPracticeMapping> = Vec::new();
    let mut seen_practice_ids = HashSet::new();

    for control in nist_controls {
        let practices = get_practices_by_nist_control(control);
        for practice in practices {
            if seen_practice_ids.insert(practice.id) {
                let levels: Vec<String> = practice.levels.iter().map(|l| format!("{:?}", l)).collect();
                let matched_controls: Vec<&str> = practice.nist_controls
                    .iter()
                    .filter(|c| nist_controls.iter().any(|nc| nist_control_matches(c, nc)))
                    .copied()
                    .collect();

                mapped_practices.push(CmmcPracticeMapping {
                    practice_id: practice.id,
                    domain: practice.domain,
                    practice_statement: practice.practice_statement,
                    levels,
                    relevance: determine_relevance(source, evidence_type, practice),
                    nist_controls_matched: matched_controls,
                });
            }
        }
    }

    let level1_count = mapped_practices.iter()
        .filter(|p| p.levels.iter().any(|l| l == "Level1"))
        .count();
    let level2_count = mapped_practices.iter()
        .filter(|p| p.levels.iter().any(|l| l == "Level2"))
        .count();
    let level3_count = mapped_practices.iter()
        .filter(|p| p.levels.iter().any(|l| l == "Level3"))
        .count();

    let domains_covered: Vec<String> = mapped_practices.iter()
        .map(|p| p.domain.to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    CmmcMappingResponse {
        source: source.as_str().to_string(),
        evidence_type: evidence_type.to_string(),
        source_id: source_id.to_string(),
        collected_at: collected_at.to_string(),
        mapped_at: chrono::Utc::now().to_rfc3339(),
        framework: "cmmc",
        framework_version: "2.0",
        mapped_practices,
        summary: CmmcMappingSummary {
            total_practices_mapped: seen_practice_ids.len(),
            level1_practices: level1_count,
            level2_practices: level2_count,
            level3_practices: level3_count,
            domains_covered,
        },
    }
}

/// Get NIST controls for Microsoft Graph evidence types
fn get_nist_controls_for_msgraph_evidence(evidence_type: &str) -> Vec<&'static str> {
    match evidence_type {
        "conditional_access_policies" => vec![
            "AC-2", "AC-3", "AC-6", "AC-7", "AC-11", "AC-12", "AC-17", "AC-20", "IA-2", "IA-5"
        ],
        "user_mfa_status" => vec!["IA-2", "IA-5"],
        "sign_in_logs" => vec!["AC-2", "AC-7", "AU-2", "AU-3", "AU-6", "AU-12", "SI-4"],
        "audit_logs" => vec!["AU-2", "AU-3", "AU-6", "AU-7", "AU-11", "AU-12", "CM-3"],
        "directory_roles" => vec!["AC-2", "AC-5", "AC-6"],
        "security_alerts" => vec!["IR-4", "IR-5", "IR-6", "SI-4", "SI-5"],
        "compliance_policies" => vec!["CM-2", "CM-6", "CM-7", "SC-28", "SI-2", "SI-3"],
        "device_configurations" => vec!["CM-2", "CM-6", "CM-7", "AC-19", "SC-28"],
        "risk_detections" => vec!["RA-3", "RA-5", "SI-4", "AC-2"],
        "secure_score" => vec!["CA-2", "CA-7", "RA-3", "RA-5"],
        _ => vec![],
    }
}

/// Get NIST controls for Terraform evidence
fn get_nist_controls_for_terraform() -> Vec<&'static str> {
    vec![
        "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-17",
        "SC-7", "SC-8", "SC-12", "SC-13", "SC-28",
        "CM-2", "CM-6", "CM-7", "CM-8",
        "AU-2", "AU-3", "AU-6", "AU-12",
        "RA-5",
        "SI-2", "SI-4",
    ]
}

/// Determine relevance of evidence to a practice
fn determine_relevance(source: &EvidenceSource, evidence_type: &str, practice: &CmmcPractice) -> &'static str {
    let domain = practice.domain.to_lowercase();

    match source {
        EvidenceSource::MicrosoftGraph => {
            match evidence_type {
                "conditional_access_policies" => {
                    if domain.contains("access control") || domain.contains("identification") {
                        "direct"
                    } else {
                        "supporting"
                    }
                }
                "user_mfa_status" => {
                    if domain.contains("identification") { "direct" } else { "supporting" }
                }
                "sign_in_logs" | "audit_logs" => {
                    if domain.contains("audit") { "direct" } else { "supporting" }
                }
                "security_alerts" => {
                    if domain.contains("incident") || domain.contains("integrity") {
                        "direct"
                    } else {
                        "supporting"
                    }
                }
                "compliance_policies" | "device_configurations" => {
                    if domain.contains("configuration") { "direct" } else { "supporting" }
                }
                "risk_detections" | "secure_score" => {
                    if domain.contains("risk") || domain.contains("security assessment") {
                        "direct"
                    } else {
                        "supporting"
                    }
                }
                "directory_roles" => {
                    if domain.contains("access control") { "direct" } else { "supporting" }
                }
                _ => "supporting",
            }
        }
        EvidenceSource::Terraform => {
            if domain.contains("configuration") || domain.contains("system and communications") {
                "direct"
            } else if domain.contains("access control") || domain.contains("audit") {
                "direct"
            } else {
                "supporting"
            }
        }
    }
}
