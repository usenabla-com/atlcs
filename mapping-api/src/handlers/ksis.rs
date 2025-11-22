use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::{Claims, Framework, Scope};
use crate::catalogs::fedramp_20x_phase_two::{
    get_active_ksis, get_ksi_by_id, get_ksis_by_baseline, get_ksis_by_nist_control, Baseline, Ksi,
};

#[derive(Debug, Deserialize)]
pub struct KsiQuery {
    /// Filter by baseline (low, moderate)
    pub baseline: Option<String>,
    /// Filter by NIST control (e.g., "AC-2", "IA-5")
    pub nist_control: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct KsiListResponse {
    pub framework: &'static str,
    pub version: &'static str,
    pub count: usize,
    pub ksis: Vec<&'static Ksi>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// GET /api/v1/frameworks/fedramp-20x/ksis
///
/// List all FedRAMP 20x Phase Two KSIs with optional filtering
pub async fn list_ksis(
    Extension(claims): Extension<Claims>,
    Query(query): Query<KsiQuery>,
) -> Result<Json<KsiListResponse>, (StatusCode, Json<ErrorResponse>)> {
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
    if !claims.has_framework(Framework::Fedramp20x) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "framework_not_licensed".to_string(),
                message: "Your license does not include FedRAMP 20x framework access.".to_string(),
            }),
        ));
    }

    let ksis = if let Some(baseline_str) = &query.baseline {
        let baseline = match baseline_str.to_lowercase().as_str() {
            "low" => Baseline::Low,
            "moderate" => Baseline::Moderate,
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_baseline".to_string(),
                        message: "Baseline must be 'low' or 'moderate'.".to_string(),
                    }),
                ));
            }
        };
        get_ksis_by_baseline(baseline)
    } else if let Some(control) = &query.nist_control {
        get_ksis_by_nist_control(control)
    } else {
        get_active_ksis()
    };

    Ok(Json(KsiListResponse {
        framework: "fedramp-20x-phase-two",
        version: "RFC-0014",
        count: ksis.len(),
        ksis,
    }))
}

/// GET /api/v1/frameworks/fedramp-20x/ksis/:ksi_id
///
/// Get a specific KSI by ID
pub async fn get_ksi(
    Extension(claims): Extension<Claims>,
    Path(ksi_id): Path<String>,
) -> Result<Json<&'static Ksi>, (StatusCode, Json<ErrorResponse>)> {
    if !claims.has_scope(Scope::MappingsRead) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "insufficient_scope".to_string(),
                message: "The mappings:read scope is required.".to_string(),
            }),
        ));
    }

    if !claims.has_framework(Framework::Fedramp20x) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "framework_not_licensed".to_string(),
                message: "Your license does not include FedRAMP 20x framework access.".to_string(),
            }),
        ));
    }

    get_ksi_by_id(&ksi_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "ksi_not_found".to_string(),
                message: format!("KSI '{}' not found.", ksi_id),
            }),
        )
    }).map(Json)
}
