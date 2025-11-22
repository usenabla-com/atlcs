use axum::{extract::Extension, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{Claims, Framework, LicenseType, Scope};
use crate::catalogs::cmmc::{get_practices_by_nist_control, CmmcPractice};
use crate::validators::microsoft_graph::validate_microsoft_graph_evidence;
use crate::validators::ValidationResponse;

/// Microsoft Graph evidence data to be validated
#[derive(Debug, Deserialize)]
pub struct MicrosoftGraphEvidence {
    /// Tenant ID from Azure AD
    pub tenant_id: String,
    /// Evidence type being submitted
    pub evidence_type: MsGraphEvidenceType,
    /// Raw data from Microsoft Graph API
    pub data: serde_json::Value,
    /// Timestamp of data collection (ISO 8601)
    pub collected_at: String,
    /// Target framework: "fedramp-20x" (default) or "cmmc"
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
pub enum MsGraphEvidenceType {
    ConditionalAccessPolicies,
    UserMfaStatus,
    SignInLogs,
    AuditLogs,
    DirectoryRoles,
    SecurityAlerts,
    CompliancePolicies,
    DeviceConfigurations,
    RiskDetections,
    SecureScore,
}

impl MsGraphEvidenceType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::ConditionalAccessPolicies => "conditional_access_policies",
            Self::UserMfaStatus => "user_mfa_status",
            Self::SignInLogs => "sign_in_logs",
            Self::AuditLogs => "audit_logs",
            Self::DirectoryRoles => "directory_roles",
            Self::SecurityAlerts => "security_alerts",
            Self::CompliancePolicies => "compliance_policies",
            Self::DeviceConfigurations => "device_configurations",
            Self::RiskDetections => "risk_detections",
            Self::SecureScore => "secure_score",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// Unified mapping response that works for both frameworks
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum MappingResponse {
    FedRamp(ValidationResponse),
    Cmmc(CmmcMappingResponse),
}

/// Response for CMMC mapping
#[derive(Debug, Serialize)]
pub struct CmmcMappingResponse {
    pub source: String,
    pub evidence_type: String,
    pub tenant_id: String,
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

/// POST /api/v1/sources/microsoft-graph/map
///
/// Maps Microsoft Graph evidence to the specified framework (FedRAMP 20x or CMMC)
///
/// Use the `framework` field in the request body:
/// - "fedramp-20x" (default): Maps to FedRAMP 20x Phase Two KSIs
/// - "cmmc": Maps to CMMC 2.0 practices
pub async fn map_microsoft_graph_evidence(
    Extension(claims): Extension<Claims>,
    Json(evidence): Json<MicrosoftGraphEvidence>,
) -> Result<Json<MappingResponse>, (StatusCode, Json<ErrorResponse>)> {
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

    match evidence.framework {
        TargetFramework::Fedramp20x => {
            // Verify FedRAMP framework access
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

            let response = validate_microsoft_graph_evidence(
                evidence.evidence_type.as_str(),
                &evidence.data,
                &evidence.tenant_id,
                &evidence.collected_at,
                &claims.tenant,
                license_type,
            );

            Ok(Json(MappingResponse::FedRamp(response)))
        }
        TargetFramework::Cmmc => {
            // Verify CMMC framework access
            if !claims.has_framework(Framework::Cmmc) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "framework_not_licensed".to_string(),
                        message: "Your license does not include CMMC framework access.".to_string(),
                    }),
                ));
            }

            let response = map_to_cmmc(&evidence);
            Ok(Json(MappingResponse::Cmmc(response)))
        }
    }
}

/// Map evidence to CMMC practices
fn map_to_cmmc(evidence: &MicrosoftGraphEvidence) -> CmmcMappingResponse {
    // Get NIST controls relevant to this evidence type
    let nist_controls = get_nist_controls_for_evidence_type(&evidence.evidence_type);

    // Find all CMMC practices that map to these NIST controls
    let mut mapped_practices: Vec<CmmcPracticeMapping> = Vec::new();
    let mut seen_practice_ids = std::collections::HashSet::new();

    for control in &nist_controls {
        let practices = get_practices_by_nist_control(control);
        for practice in practices {
            if seen_practice_ids.insert(practice.id) {
                let levels: Vec<String> = practice.levels.iter().map(|l| format!("{:?}", l)).collect();
                let matched_controls: Vec<&str> = practice.nist_controls
                    .iter()
                    .filter(|c| nist_controls.iter().any(|nc| c.starts_with(nc)))
                    .copied()
                    .collect();

                mapped_practices.push(CmmcPracticeMapping {
                    practice_id: practice.id,
                    domain: practice.domain,
                    practice_statement: practice.practice_statement,
                    levels,
                    relevance: determine_relevance(&evidence.evidence_type, practice),
                    nist_controls_matched: matched_controls,
                });
            }
        }
    }

    // Calculate summary
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
        source: "microsoft-graph".to_string(),
        evidence_type: evidence.evidence_type.as_str().to_string(),
        tenant_id: evidence.tenant_id.clone(),
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

/// Get NIST controls relevant to each evidence type
fn get_nist_controls_for_evidence_type(evidence_type: &MsGraphEvidenceType) -> Vec<&'static str> {
    match evidence_type {
        MsGraphEvidenceType::ConditionalAccessPolicies => vec![
            "AC-2", "AC-3", "AC-6", "AC-7", "AC-11", "AC-12", "AC-17", "AC-20", "IA-2", "IA-5"
        ],
        MsGraphEvidenceType::UserMfaStatus => vec![
            "IA-2", "IA-5"
        ],
        MsGraphEvidenceType::SignInLogs => vec![
            "AC-2", "AC-7", "AU-2", "AU-3", "AU-6", "AU-12", "SI-4"
        ],
        MsGraphEvidenceType::AuditLogs => vec![
            "AU-2", "AU-3", "AU-6", "AU-7", "AU-11", "AU-12", "CM-3"
        ],
        MsGraphEvidenceType::DirectoryRoles => vec![
            "AC-2", "AC-5", "AC-6"
        ],
        MsGraphEvidenceType::SecurityAlerts => vec![
            "IR-4", "IR-5", "IR-6", "SI-4", "SI-5"
        ],
        MsGraphEvidenceType::CompliancePolicies => vec![
            "CM-2", "CM-6", "CM-7", "SC-28", "SI-2", "SI-3"
        ],
        MsGraphEvidenceType::DeviceConfigurations => vec![
            "CM-2", "CM-6", "CM-7", "AC-19", "SC-28"
        ],
        MsGraphEvidenceType::RiskDetections => vec![
            "RA-3", "RA-5", "SI-4", "AC-2"
        ],
        MsGraphEvidenceType::SecureScore => vec![
            "CA-2", "CA-7", "RA-3", "RA-5"
        ],
    }
}

/// Determine relevance of evidence to a practice
fn determine_relevance(evidence_type: &MsGraphEvidenceType, practice: &CmmcPractice) -> &'static str {
    let domain = practice.domain.to_lowercase();

    match evidence_type {
        MsGraphEvidenceType::ConditionalAccessPolicies => {
            if domain.contains("access control") || domain.contains("identification") {
                "direct"
            } else {
                "supporting"
            }
        }
        MsGraphEvidenceType::UserMfaStatus => {
            if domain.contains("identification") {
                "direct"
            } else {
                "supporting"
            }
        }
        MsGraphEvidenceType::SignInLogs | MsGraphEvidenceType::AuditLogs => {
            if domain.contains("audit") {
                "direct"
            } else {
                "supporting"
            }
        }
        MsGraphEvidenceType::SecurityAlerts => {
            if domain.contains("incident") || domain.contains("integrity") {
                "direct"
            } else {
                "supporting"
            }
        }
        MsGraphEvidenceType::CompliancePolicies | MsGraphEvidenceType::DeviceConfigurations => {
            if domain.contains("configuration") {
                "direct"
            } else {
                "supporting"
            }
        }
        MsGraphEvidenceType::RiskDetections | MsGraphEvidenceType::SecureScore => {
            if domain.contains("risk") || domain.contains("security assessment") {
                "direct"
            } else {
                "supporting"
            }
        }
        MsGraphEvidenceType::DirectoryRoles => {
            if domain.contains("access control") {
                "direct"
            } else {
                "supporting"
            }
        }
    }
}

/// GET /api/v1/sources/microsoft-graph/evidence-types
///
/// List available evidence types for Microsoft Graph with their framework mappings
pub async fn list_evidence_types(
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<EvidenceTypeInfo>>, (StatusCode, Json<ErrorResponse>)> {
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

    let evidence_types = vec![
        EvidenceTypeInfo {
            evidence_type: "conditional_access_policies".to_string(),
            description: "Azure AD Conditional Access policies for access control".to_string(),
            graph_api_endpoint: "/identity/conditionalAccess/policies".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-IAM-01", "KSI-IAM-02", "KSI-IAM-03", "KSI-IAM-04",
                "KSI-IAM-05", "KSI-IAM-06", "KSI-CNA-01"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["AC-2", "AC-3", "AC-6", "AC-7", "AC-11", "AC-12", "AC-17", "AC-20", "IA-2", "IA-5"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "user_mfa_status".to_string(),
            description: "User MFA registration and authentication methods".to_string(),
            graph_api_endpoint: "/reports/authenticationMethods/userRegistrationDetails".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec!["KSI-IAM-01", "KSI-IAM-02"].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["IA-2", "IA-5"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "sign_in_logs".to_string(),
            description: "User and service principal sign-in activity".to_string(),
            graph_api_endpoint: "/auditLogs/signIns".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-MLA-01", "KSI-MLA-02", "KSI-MLA-07", "KSI-IAM-02", "KSI-IAM-05"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["AC-2", "AC-7", "AU-2", "AU-3", "AU-6", "AU-12", "SI-4"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "audit_logs".to_string(),
            description: "Directory audit logs for configuration changes".to_string(),
            graph_api_endpoint: "/auditLogs/directoryAudits".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-MLA-01", "KSI-CMT-01", "KSI-IAM-04", "KSI-IAM-07"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["AU-2", "AU-3", "AU-6", "AU-7", "AU-11", "AU-12", "CM-3"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "directory_roles".to_string(),
            description: "Azure AD directory roles and assignments".to_string(),
            graph_api_endpoint: "/directoryRoles".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec!["KSI-IAM-04", "KSI-IAM-07"].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["AC-2", "AC-5", "AC-6"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "security_alerts".to_string(),
            description: "Microsoft 365 Defender security alerts".to_string(),
            graph_api_endpoint: "/security/alerts_v2".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-INR-01", "KSI-INR-02", "KSI-MLA-02"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["IR-4", "IR-5", "IR-6", "SI-4", "SI-5"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "compliance_policies".to_string(),
            description: "Intune device compliance policies".to_string(),
            graph_api_endpoint: "/deviceManagement/deviceCompliancePolicies".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-SVC-03", "KSI-SVC-04", "KSI-CMT-02", "KSI-MLA-03", "KSI-CNA-04"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["CM-2", "CM-6", "CM-7", "SC-28", "SI-2", "SI-3"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "device_configurations".to_string(),
            description: "Intune device configuration profiles".to_string(),
            graph_api_endpoint: "/deviceManagement/deviceConfigurations".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-SVC-01", "KSI-SVC-03", "KSI-SVC-04", "KSI-CNA-01", "KSI-CNA-04"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["CM-2", "CM-6", "CM-7", "AC-19", "SC-28"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "risk_detections".to_string(),
            description: "Identity Protection risk detections".to_string(),
            graph_api_endpoint: "/identityProtection/riskDetections".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-MLA-02", "KSI-IAM-05", "KSI-IAM-06"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["RA-3", "RA-5", "SI-4", "AC-2"])) } else { None },
        },
        EvidenceTypeInfo {
            evidence_type: "secure_score".to_string(),
            description: "Microsoft Secure Score assessment".to_string(),
            graph_api_endpoint: "/security/secureScores".to_string(),
            fedramp_ksis: if has_fedramp { Some(vec![
                "KSI-SVC-01", "KSI-MLA-05", "KSI-IAM-02", "KSI-SVC-03"
            ].into_iter().map(String::from).collect()) } else { None },
            cmmc_practices: if has_cmmc { Some(get_cmmc_practices_for_controls(&["CA-2", "CA-7", "RA-3", "RA-5"])) } else { None },
        },
    ];

    Ok(Json(evidence_types))
}

#[derive(Debug, Serialize)]
pub struct EvidenceTypeInfo {
    pub evidence_type: String,
    pub description: String,
    pub graph_api_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fedramp_ksis: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmmc_practices: Option<Vec<String>>,
}

fn get_cmmc_practices_for_controls(controls: &[&str]) -> Vec<String> {
    let mut practice_ids: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for control in controls {
        for practice in get_practices_by_nist_control(control) {
            if seen.insert(practice.id) {
                practice_ids.push(practice.id.to_string());
            }
        }
    }

    practice_ids
}
