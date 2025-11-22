use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{generate_token, Claims, Framework, LicenseType, Scope};

/// Request to generate a new license token (development only)
#[derive(Debug, Deserialize)]
pub struct GenerateTokenRequest {
    pub customer_id: String,
    pub tenant: String,
    pub license_type: LicenseType,
    pub frameworks: Vec<Framework>,
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
    pub license_type: LicenseType,
    pub frameworks: Vec<Framework>,
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

/// POST /api/v1/dev/tokens
///
/// Generate a JWT token for development/testing purposes.
/// In production, this would be handled by your payment/licensing system.
pub async fn generate_dev_token(
    Json(request): Json<GenerateTokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In production, you'd verify payment here
    let claims = Claims::new(
        request.customer_id,
        request.tenant,
        request.license_type,
        request.frameworks.clone(),
        request.scopes.clone(),
    );

    let token = generate_token(&claims).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "token_generation_failed".to_string(),
                message: format!("Failed to generate token: {}", e),
            }),
        )
    })?;

    Ok(Json(TokenResponse {
        token,
        expires_at: claims.exp,
        license_type: request.license_type,
        frameworks: request.frameworks,
        scopes: request.scopes,
    }))
}
