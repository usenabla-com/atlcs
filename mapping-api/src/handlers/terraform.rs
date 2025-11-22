//! Terraform state handlers for compliance mapping

use axum::{extract::Extension, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{Claims, Framework, LicenseType, Scope};
use crate::catalogs::cmmc::{get_practices_by_nist_control, nist_control_matches, CmmcPractice};
use crate::validators::terraform::validate_terraform_state;
use crate::validators::ValidationResponse;

/// Terraform state evidence data to be validated
#[derive(Debug, Deserialize)]
pub struct TerraformEvidence {
    /// Identifier for the state (e.g., workspace name or backend path)
    pub state_id: String,
    /// Evidence type being submitted
    pub evidence_type: TerraformEvidenceType,
    /// Raw Terraform state data
    pub data: serde_json::Value,
    /// Timestamp of data collection (ISO 8601)
    pub collected_at: String,
    /// Target framework: "fedramp20x" (default) or "cmmc"
    #[serde(default = "default_framework")]
    pub framework: TargetFramework,
}

fn default_framework() -> TargetFramework {
    TargetFramework::Fedramp20x
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TargetFramework {
    #[default]
    Fedramp20x,
    Cmmc,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerraformEvidenceType {
    FullState,
    AwsResources,
    AzureResources,
    GcpResources,
    KubernetesResources,
}

impl TerraformEvidenceType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::FullState => "full_state",
            Self::AwsResources => "aws_resources",
            Self::AzureResources => "azure_resources",
            Self::GcpResources => "gcp_resources",
            Self::KubernetesResources => "kubernetes_resources",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Evidence type info for discovery
#[derive(Debug, Serialize)]
pub struct TerraformEvidenceTypeInfo {
    pub evidence_type: &'static str,
    pub description: &'static str,
    pub example_resources: Vec<&'static str>,
    pub fedramp_ksis: Vec<&'static str>,
    pub cmmc_practices: Vec<&'static str>,
}

/// Unified mapping response
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum TerraformMappingResponse {
    FedRamp(ValidationResponse),
    Cmmc(CmmcMappingResponse),
}

/// Response for CMMC mapping
#[derive(Debug, Serialize)]
pub struct CmmcMappingResponse {
    pub source: String,
    pub evidence_type: String,
    pub state_id: String,
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

/// GET /api/v1/sources/terraform/evidence-types
///
/// List available Terraform evidence types
pub async fn list_terraform_evidence_types(
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<TerraformEvidenceTypeInfo>>, (StatusCode, Json<ErrorResponse>)> {
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    let evidence_types = vec![
        TerraformEvidenceTypeInfo {
            evidence_type: "full_state",
            description: "Complete Terraform state file with all resources",
            example_resources: vec![
                "aws_instance", "aws_s3_bucket", "aws_security_group",
                "azurerm_virtual_machine", "google_compute_instance"
            ],
            fedramp_ksis: vec![
                "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-04", "KSI-SVC-06",
                "KSI-CNA-01", "KSI-CNA-03", "KSI-CNA-06",
                "KSI-IAM-01", "KSI-IAM-04",
                "KSI-MLA-01", "KSI-MLA-02",
                "KSI-CMT-02"
            ],
            cmmc_practices: vec![
                "AC.L1-3.1.1", "AC.L1-3.1.2", "AC.L2-3.1.5",
                "SC.L1-3.13.1", "SC.L2-3.13.8", "SC.L2-3.13.11",
                "CM.L2-3.4.1", "CM.L2-3.4.2",
                "AU.L2-3.3.1", "AU.L2-3.3.2"
            ],
        },
        TerraformEvidenceTypeInfo {
            evidence_type: "aws_resources",
            description: "AWS-specific resources from Terraform state",
            example_resources: vec![
                "aws_instance", "aws_s3_bucket", "aws_security_group",
                "aws_iam_role", "aws_kms_key", "aws_cloudtrail"
            ],
            fedramp_ksis: vec![
                "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-06",
                "KSI-CNA-01", "KSI-CNA-03",
                "KSI-IAM-04", "KSI-MLA-01", "KSI-MLA-02"
            ],
            cmmc_practices: vec![
                "AC.L1-3.1.1", "SC.L1-3.13.1", "SC.L2-3.13.11",
                "CM.L2-3.4.1", "AU.L2-3.3.1"
            ],
        },
        TerraformEvidenceTypeInfo {
            evidence_type: "azure_resources",
            description: "Azure-specific resources from Terraform state",
            example_resources: vec![
                "azurerm_virtual_machine", "azurerm_storage_account",
                "azurerm_network_security_group", "azurerm_key_vault"
            ],
            fedramp_ksis: vec![
                "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-06",
                "KSI-CNA-01", "KSI-CNA-03",
                "KSI-MLA-01", "KSI-MLA-02"
            ],
            cmmc_practices: vec![
                "AC.L1-3.1.1", "SC.L1-3.13.1", "SC.L2-3.13.11",
                "CM.L2-3.4.1", "AU.L2-3.3.1"
            ],
        },
        TerraformEvidenceTypeInfo {
            evidence_type: "gcp_resources",
            description: "GCP-specific resources from Terraform state",
            example_resources: vec![
                "google_compute_instance", "google_storage_bucket",
                "google_compute_firewall", "google_kms_crypto_key"
            ],
            fedramp_ksis: vec![
                "KSI-SVC-02", "KSI-SVC-03", "KSI-SVC-06",
                "KSI-CNA-01", "KSI-CNA-03",
                "KSI-MLA-01"
            ],
            cmmc_practices: vec![
                "AC.L1-3.1.1", "SC.L1-3.13.1", "SC.L2-3.13.11"
            ],
        },
        TerraformEvidenceTypeInfo {
            evidence_type: "kubernetes_resources",
            description: "Kubernetes resources from Terraform state",
            example_resources: vec![
                "kubernetes_deployment", "kubernetes_service",
                "kubernetes_network_policy", "kubernetes_secret"
            ],
            fedramp_ksis: vec![
                "KSI-CNA-01", "KSI-CNA-03", "KSI-CMT-02", "KSI-SVC-04"
            ],
            cmmc_practices: vec![
                "AC.L1-3.1.1", "CM.L2-3.4.1", "CM.L2-3.4.2"
            ],
        },
    ];

    Ok(Json(evidence_types))
}

/// POST /api/v1/sources/terraform/map
///
/// Maps Terraform state to the specified framework
pub async fn map_terraform_evidence(
    Extension(claims): Extension<Claims>,
    Json(evidence): Json<TerraformEvidence>,
) -> Result<Json<TerraformMappingResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    match evidence.framework {
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

            let license_type = match claims.license_type {
                LicenseType::Standard => "standard",
                LicenseType::Enterprise => "enterprise",
            };

            let response = validate_terraform_state(
                evidence.evidence_type.as_str(),
                &evidence.data,
                &evidence.state_id,
                &evidence.collected_at,
                &claims.tenant,
                license_type,
            );

            Ok(Json(TerraformMappingResponse::FedRamp(response)))
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

            let response = map_terraform_to_cmmc(&evidence);
            Ok(Json(TerraformMappingResponse::Cmmc(response)))
        }
    }
}

/// Map Terraform evidence to CMMC practices
fn map_terraform_to_cmmc(evidence: &TerraformEvidence) -> CmmcMappingResponse {
    let nist_controls = get_nist_controls_for_terraform();

    let mut mapped_practices: Vec<CmmcPracticeMapping> = Vec::new();
    let mut seen_practice_ids = std::collections::HashSet::new();

    for control in &nist_controls {
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
                    relevance: determine_relevance(practice),
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
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    CmmcMappingResponse {
        source: "terraform".to_string(),
        evidence_type: evidence.evidence_type.as_str().to_string(),
        state_id: evidence.state_id.clone(),
        collected_at: evidence.collected_at.clone(),
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

/// Get NIST controls relevant to Terraform infrastructure
fn get_nist_controls_for_terraform() -> Vec<&'static str> {
    vec![
        // Access Control
        "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-17",
        // System and Communications Protection
        "SC-7", "SC-8", "SC-12", "SC-13", "SC-28",
        // Configuration Management
        "CM-2", "CM-6", "CM-7", "CM-8",
        // Audit and Accountability
        "AU-2", "AU-3", "AU-6", "AU-12",
        // Risk Assessment
        "RA-5",
        // System and Information Integrity
        "SI-2", "SI-4",
    ]
}

fn determine_relevance(practice: &CmmcPractice) -> &'static str {
    let domain = practice.domain.to_lowercase();

    if domain.contains("configuration") || domain.contains("system and communications") {
        "direct"
    } else if domain.contains("access control") || domain.contains("audit") {
        "direct"
    } else {
        "supporting"
    }
}
