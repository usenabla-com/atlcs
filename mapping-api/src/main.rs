use axum::{
    middleware,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod catalogs;
mod handlers;
mod validators;

use auth::auth_middleware;
use handlers::cmmc::{get_practice, get_summary, list_practices};
use handlers::ksis::{get_ksi, list_ksis};
use handlers::microsoft_graph::{list_evidence_types, map_microsoft_graph_evidence};
use handlers::tokens::generate_dev_token;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct ApiInfo {
    name: &'static str,
    version: &'static str,
    description: &'static str,
    endpoints: Vec<EndpointInfo>,
}

#[derive(Serialize)]
struct EndpointInfo {
    method: &'static str,
    path: &'static str,
    description: &'static str,
    auth_required: bool,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn api_info() -> Json<ApiInfo> {
    Json(ApiInfo {
        name: "FedRAMP 20x Mapping API",
        version: env!("CARGO_PKG_VERSION"),
        description: "Maps evidence from various sources to FedRAMP 20x Phase Two Key Security Indicators (KSIs)",
        endpoints: vec![
            EndpointInfo {
                method: "GET",
                path: "/health",
                description: "Health check endpoint",
                auth_required: false,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1",
                description: "API information and available endpoints",
                auth_required: false,
            },
            EndpointInfo {
                method: "POST",
                path: "/api/v1/dev/tokens",
                description: "Generate a JWT token for development (not for production use)",
                auth_required: false,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1/frameworks/fedramp-20x/ksis",
                description: "List all FedRAMP 20x Phase Two KSIs",
                auth_required: true,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1/frameworks/fedramp-20x/ksis/:ksi_id",
                description: "Get a specific KSI by ID",
                auth_required: true,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1/sources/microsoft-graph/evidence-types",
                description: "List available Microsoft Graph evidence types",
                auth_required: true,
            },
            EndpointInfo {
                method: "POST",
                path: "/api/v1/sources/microsoft-graph/map",
                description: "Map Microsoft Graph evidence to FedRAMP 20x KSIs",
                auth_required: true,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1/frameworks/cmmc/practices",
                description: "List all CMMC 2.0 practices",
                auth_required: true,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1/frameworks/cmmc/practices/:practice_id",
                description: "Get a specific CMMC practice by ID",
                auth_required: true,
            },
            EndpointInfo {
                method: "GET",
                path: "/api/v1/frameworks/cmmc/summary",
                description: "Get CMMC practice summary by level and domain",
                auth_required: true,
            },
        ],
    })
}

fn public_routes() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1", get(api_info))
        .route("/api/v1/dev/tokens", post(generate_dev_token))
}

fn protected_routes() -> Router {
    Router::new()
        // FedRAMP 20x KSI catalog routes
        .route("/api/v1/frameworks/fedramp-20x/ksis", get(list_ksis))
        .route("/api/v1/frameworks/fedramp-20x/ksis/:ksi_id", get(get_ksi))
        // CMMC 2.0 catalog routes
        .route("/api/v1/frameworks/cmmc/practices", get(list_practices))
        .route(
            "/api/v1/frameworks/cmmc/practices/:practice_id",
            get(get_practice),
        )
        .route("/api/v1/frameworks/cmmc/summary", get(get_summary))
        // Microsoft Graph source routes
        .route(
            "/api/v1/sources/microsoft-graph/evidence-types",
            get(list_evidence_types),
        )
        .route(
            "/api/v1/sources/microsoft-graph/map",
            post(map_microsoft_graph_evidence),
        )
        .layer(middleware::from_fn(auth_middleware))
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mapping_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build application
    let app = Router::new()
        .merge(public_routes())
        .merge(protected_routes())
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Run server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Mapping API listening on {}", addr);
    tracing::info!("Public endpoints:");
    tracing::info!("  GET  /health");
    tracing::info!("  GET  /api/v1");
    tracing::info!("  POST /api/v1/dev/tokens");
    tracing::info!("Protected endpoints (require JWT):");
    tracing::info!("  GET  /api/v1/frameworks/fedramp-20x/ksis");
    tracing::info!("  GET  /api/v1/frameworks/fedramp-20x/ksis/:ksi_id");
    tracing::info!("  GET  /api/v1/frameworks/cmmc/practices");
    tracing::info!("  GET  /api/v1/frameworks/cmmc/practices/:practice_id");
    tracing::info!("  GET  /api/v1/frameworks/cmmc/summary");
    tracing::info!("  GET  /api/v1/sources/microsoft-graph/evidence-types");
    tracing::info!("  POST /api/v1/sources/microsoft-graph/map");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
