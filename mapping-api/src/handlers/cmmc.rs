use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::{Claims, Framework, Scope};
use crate::catalogs::cmmc::{
    get_all_practices, get_enhanced_practices, get_practice_by_id, get_practices_by_domain,
    get_practices_by_level, get_practices_by_nist_control, get_practice_counts, CmmcLevel,
    CmmcPractice,
};

#[derive(Debug, Deserialize)]
pub struct CmmcQuery {
    /// Filter by CMMC level (1, 2, 3)
    pub level: Option<u8>,
    /// Filter by domain (e.g., "Access Control", "Incident Response")
    pub domain: Option<String>,
    /// Filter by NIST control (e.g., "AC-2", "IA-5")
    pub nist_control: Option<String>,
    /// Filter to only enhanced SP 800-172 practices
    pub enhanced_only: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CmmcListResponse {
    pub framework: &'static str,
    pub version: &'static str,
    pub count: usize,
    pub practices: Vec<&'static CmmcPractice>,
}

#[derive(Debug, Serialize)]
pub struct CmmcSummaryResponse {
    pub framework: &'static str,
    pub version: &'static str,
    pub level1_count: usize,
    pub level2_count: usize,
    pub level3_count: usize,
    pub domains: Vec<DomainSummary>,
}

#[derive(Debug, Serialize)]
pub struct DomainSummary {
    pub domain: &'static str,
    pub practice_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// GET /api/v1/frameworks/cmmc/practices
///
/// List all CMMC practices with optional filtering
pub async fn list_practices(
    Extension(claims): Extension<Claims>,
    Query(query): Query<CmmcQuery>,
) -> Result<Json<CmmcListResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Verify scope
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    // Verify framework access
    if !claims.has_framework(Framework::Cmmc) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "framework_not_licensed".to_string(),
                message: "Your license does not include CMMC framework access.".to_string(),
            }),
        ));
    }

    let practices = if query.enhanced_only.unwrap_or(false) {
        get_enhanced_practices()
    } else if let Some(level) = query.level {
        let cmmc_level = match level {
            1 => CmmcLevel::Level1,
            2 => CmmcLevel::Level2,
            3 => CmmcLevel::Level3,
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_level".to_string(),
                        message: "Level must be 1, 2, or 3.".to_string(),
                    }),
                ));
            }
        };
        get_practices_by_level(cmmc_level)
    } else if let Some(domain) = &query.domain {
        get_practices_by_domain(domain)
    } else if let Some(control) = &query.nist_control {
        get_practices_by_nist_control(control)
    } else {
        get_all_practices().iter().collect()
    };

    Ok(Json(CmmcListResponse {
        framework: "cmmc-2.0",
        version: "2.0",
        count: practices.len(),
        practices,
    }))
}

/// GET /api/v1/frameworks/cmmc/practices/:practice_id
///
/// Get a specific CMMC practice by ID
pub async fn get_practice(
    Extension(claims): Extension<Claims>,
    Path(practice_id): Path<String>,
) -> Result<Json<&'static CmmcPractice>, (StatusCode, Json<ErrorResponse>)> {
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    if !claims.has_framework(Framework::Cmmc) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "framework_not_licensed".to_string(),
                message: "Your license does not include CMMC framework access.".to_string(),
            }),
        ));
    }

    get_practice_by_id(&practice_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "practice_not_found".to_string(),
                    message: format!("CMMC practice '{}' not found.", practice_id),
                }),
            )
        })
        .map(Json)
}

/// GET /api/v1/frameworks/cmmc/summary
///
/// Get a summary of CMMC practices by level and domain
pub async fn get_summary(
    Extension(claims): Extension<Claims>,
) -> Result<Json<CmmcSummaryResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    if !claims.has_framework(Framework::Cmmc) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "framework_not_licensed".to_string(),
                message: "Your license does not include CMMC framework access.".to_string(),
            }),
        ));
    }

    let (level1, level2, level3) = get_practice_counts();

    let domains = vec![
        DomainSummary {
            domain: "Access Control",
            practice_count: get_practices_by_domain("Access Control").len(),
        },
        DomainSummary {
            domain: "Awareness and Training",
            practice_count: get_practices_by_domain("Awareness and Training").len(),
        },
        DomainSummary {
            domain: "Audit and Accountability",
            practice_count: get_practices_by_domain("Audit and Accountability").len(),
        },
        DomainSummary {
            domain: "Configuration Management",
            practice_count: get_practices_by_domain("Configuration Management").len(),
        },
        DomainSummary {
            domain: "Identification and Authentication",
            practice_count: get_practices_by_domain("Identification and Authentication").len(),
        },
        DomainSummary {
            domain: "Incident Response",
            practice_count: get_practices_by_domain("Incident Response").len(),
        },
        DomainSummary {
            domain: "Maintenance",
            practice_count: get_practices_by_domain("Maintenance").len(),
        },
        DomainSummary {
            domain: "Media Protection",
            practice_count: get_practices_by_domain("Media Protection").len(),
        },
        DomainSummary {
            domain: "Personnel Security",
            practice_count: get_practices_by_domain("Personnel Security").len(),
        },
        DomainSummary {
            domain: "Physical Protection",
            practice_count: get_practices_by_domain("Physical Protection").len(),
        },
        DomainSummary {
            domain: "Risk Assessment",
            practice_count: get_practices_by_domain("Risk Assessment").len(),
        },
        DomainSummary {
            domain: "Security Assessment",
            practice_count: get_practices_by_domain("Security Assessment").len(),
        },
        DomainSummary {
            domain: "System and Communications Protection",
            practice_count: get_practices_by_domain("System and Communications Protection").len(),
        },
        DomainSummary {
            domain: "System and Information Integrity",
            practice_count: get_practices_by_domain("System and Information Integrity").len(),
        },
    ];

    Ok(Json(CmmcSummaryResponse {
        framework: "cmmc-2.0",
        version: "2.0",
        level1_count: level1,
        level2_count: level2,
        level3_count: level3,
        domains,
    }))
}
