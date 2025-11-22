use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// JWT secret - in production, load from environment
static JWT_SECRET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "development-secret-change-in-production".to_string())
});

/// License duration: 1 year in seconds
const LICENSE_DURATION_SECS: i64 = 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (customer UUID)
    pub sub: String,
    /// Tenant/organization name
    pub tenant: String,
    /// License type
    pub license_type: LicenseType,
    /// Frameworks the license covers
    pub frameworks: Vec<Framework>,
    /// Scopes/permissions
    pub scopes: Vec<Scope>,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration (Unix timestamp) - 1 year from issuance
    pub exp: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LicenseType {
    Standard,
    Enterprise,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Framework {
    Fedramp20x,
    Cmmc,
    Nist80053,
    NistCsf,
    SocII,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    MappingsRead,
    MappingsWrite,
    EvidenceSubmit,
}

impl Claims {
    /// Create new claims with 1-year expiry
    pub fn new(
        customer_id: String,
        tenant: String,
        license_type: LicenseType,
        frameworks: Vec<Framework>,
        scopes: Vec<Scope>,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            sub: customer_id,
            tenant,
            license_type,
            frameworks,
            scopes,
            iat: now,
            exp: now + LICENSE_DURATION_SECS,
        }
    }

    /// Check if the claims have a specific scope
    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// Check if the claims cover a specific framework
    pub fn has_framework(&self, framework: Framework) -> bool {
        self.frameworks.contains(&framework)
    }
}

#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

/// Generate a JWT token for a customer (call this when they purchase)
pub fn generate_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

/// Verify and decode a JWT token
pub fn verify_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Extract bearer token from Authorization header
fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    auth_header.strip_prefix("Bearer ").or_else(|| auth_header.strip_prefix("bearer "))
}

/// JWT authentication middleware
pub async fn auth_middleware(mut request: Request, next: Next) -> Result<Response, AuthError> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) => extract_bearer_token(header).ok_or_else(|| AuthError {
            error: "invalid_header".to_string(),
            message: "Authorization header must use Bearer scheme".to_string(),
        })?,
        None => {
            return Err(AuthError {
                error: "missing_token".to_string(),
                message: "Authorization header is required".to_string(),
            })
        }
    };

    let claims = verify_token(token).map_err(|e| {
        let (error, message) = match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => (
                "token_expired".to_string(),
                "License has expired. Please renew your subscription.".to_string(),
            ),
            jsonwebtoken::errors::ErrorKind::InvalidToken => (
                "invalid_token".to_string(),
                "The provided token is invalid.".to_string(),
            ),
            jsonwebtoken::errors::ErrorKind::InvalidSignature => (
                "invalid_signature".to_string(),
                "Token signature verification failed.".to_string(),
            ),
            _ => (
                "auth_error".to_string(),
                format!("Authentication failed: {}", e),
            ),
        };
        AuthError { error, message }
    })?;

    // Store claims in request extensions for handlers to access
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let claims = Claims::new(
            "customer-123".to_string(),
            "acme-corp".to_string(),
            LicenseType::Enterprise,
            vec![Framework::Fedramp20x, Framework::Cmmc],
            vec![Scope::MappingsRead, Scope::EvidenceSubmit],
        );

        let token = generate_token(&claims).expect("Failed to generate token");
        let decoded = verify_token(&token).expect("Failed to verify token");

        assert_eq!(decoded.sub, "customer-123");
        assert_eq!(decoded.tenant, "acme-corp");
        assert!(decoded.has_scope(Scope::MappingsRead));
        assert!(decoded.has_framework(Framework::Fedramp20x));
    }

    #[test]
    fn test_token_expiry_is_one_year() {
        let claims = Claims::new(
            "customer-123".to_string(),
            "test".to_string(),
            LicenseType::Standard,
            vec![],
            vec![],
        );

        let duration = claims.exp - claims.iat;
        assert_eq!(duration, LICENSE_DURATION_SECS);
    }
}
