#!/bin/bash
#
# collect-terraform-state.sh
# Collects Terraform state from various backends for compliance assessment
#
# Usage: ./collect-terraform-state.sh <backend_type> <output_file> [options]
#
# Backend types:
#   - local: Local terraform state file (requires --state-file)
#   - s3: AWS S3 backend (requires --bucket, --key, --region)
#   - azurerm: Azure Storage backend (requires --storage-account, --container, --key)
#   - gcs: Google Cloud Storage backend (requires --bucket, --prefix)
#   - terraform-cloud: Terraform Cloud/Enterprise (requires --org, --workspace)
#
# Environment variables:
#   For S3: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional)
#   For Azure: AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_KEY or ARM_ACCESS_KEY
#   For GCS: GOOGLE_APPLICATION_CREDENTIALS
#   For TFC: TFC_TOKEN
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Parse arguments
BACKEND_TYPE="${1:-}"
OUTPUT_FILE="${2:-}"
shift 2 || true

# Parse additional options
STATE_FILE=""
S3_BUCKET=""
S3_KEY=""
S3_REGION="us-east-1"
AZURE_STORAGE_ACCOUNT=""
AZURE_CONTAINER=""
AZURE_KEY=""
GCS_BUCKET=""
GCS_PREFIX=""
TFC_ORG=""
TFC_WORKSPACE=""
EVIDENCE_TYPE="full_state"
STATE_ID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --state-file)
            STATE_FILE="$2"
            shift 2
            ;;
        --bucket)
            S3_BUCKET="$2"
            GCS_BUCKET="$2"
            shift 2
            ;;
        --key)
            S3_KEY="$2"
            AZURE_KEY="$2"
            shift 2
            ;;
        --region)
            S3_REGION="$2"
            shift 2
            ;;
        --storage-account)
            AZURE_STORAGE_ACCOUNT="$2"
            shift 2
            ;;
        --container)
            AZURE_CONTAINER="$2"
            shift 2
            ;;
        --prefix)
            GCS_PREFIX="$2"
            shift 2
            ;;
        --org)
            TFC_ORG="$2"
            shift 2
            ;;
        --workspace)
            TFC_WORKSPACE="$2"
            shift 2
            ;;
        --evidence-type)
            EVIDENCE_TYPE="$2"
            shift 2
            ;;
        --state-id)
            STATE_ID="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$BACKEND_TYPE" || -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <backend_type> <output_file> [options]"
    echo ""
    echo "Backend types: local, s3, azurerm, gcs, terraform-cloud"
    echo ""
    echo "Options:"
    echo "  --state-file <path>       Local state file path (for local backend)"
    echo "  --bucket <name>           S3/GCS bucket name"
    echo "  --key <path>              State file key/path"
    echo "  --region <region>         AWS region (default: us-east-1)"
    echo "  --storage-account <name>  Azure storage account name"
    echo "  --container <name>        Azure blob container name"
    echo "  --prefix <path>           GCS prefix"
    echo "  --org <name>              Terraform Cloud organization"
    echo "  --workspace <name>        Terraform Cloud workspace"
    echo "  --evidence-type <type>    Evidence type (default: full_state)"
    echo "  --state-id <id>           Custom state identifier"
    exit 1
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Function to collect from local file
collect_local() {
    if [[ -z "$STATE_FILE" ]]; then
        log_error "Local backend requires --state-file"
        exit 1
    fi

    if [[ ! -f "$STATE_FILE" ]]; then
        log_error "State file not found: $STATE_FILE"
        exit 1
    fi

    log_info "Reading local state file: $STATE_FILE"
    cp "$STATE_FILE" "$TEMP_DIR/terraform.tfstate"
    STATE_ID="${STATE_ID:-$(basename "$STATE_FILE" .tfstate)}"
}

# Function to collect from S3
collect_s3() {
    if [[ -z "$S3_BUCKET" || -z "$S3_KEY" ]]; then
        log_error "S3 backend requires --bucket and --key"
        exit 1
    fi

    log_info "Downloading state from S3: s3://$S3_BUCKET/$S3_KEY"

    aws s3 cp "s3://$S3_BUCKET/$S3_KEY" "$TEMP_DIR/terraform.tfstate" \
        --region "$S3_REGION"

    STATE_ID="${STATE_ID:-s3://$S3_BUCKET/$S3_KEY}"
}

# Function to collect from Azure Blob Storage
collect_azurerm() {
    if [[ -z "$AZURE_STORAGE_ACCOUNT" || -z "$AZURE_CONTAINER" || -z "$AZURE_KEY" ]]; then
        log_error "Azure backend requires --storage-account, --container, and --key"
        exit 1
    fi

    log_info "Downloading state from Azure: $AZURE_STORAGE_ACCOUNT/$AZURE_CONTAINER/$AZURE_KEY"

    az storage blob download \
        --account-name "$AZURE_STORAGE_ACCOUNT" \
        --container-name "$AZURE_CONTAINER" \
        --name "$AZURE_KEY" \
        --file "$TEMP_DIR/terraform.tfstate" \
        --auth-mode key

    STATE_ID="${STATE_ID:-azure://$AZURE_STORAGE_ACCOUNT/$AZURE_CONTAINER/$AZURE_KEY}"
}

# Function to collect from GCS
collect_gcs() {
    if [[ -z "$GCS_BUCKET" ]]; then
        log_error "GCS backend requires --bucket"
        exit 1
    fi

    local GCS_PATH="gs://$GCS_BUCKET"
    if [[ -n "$GCS_PREFIX" ]]; then
        GCS_PATH="$GCS_PATH/$GCS_PREFIX"
    fi

    log_info "Downloading state from GCS: $GCS_PATH"

    gsutil cp "$GCS_PATH/default.tfstate" "$TEMP_DIR/terraform.tfstate"

    STATE_ID="${STATE_ID:-$GCS_PATH}"
}

# Function to collect from Terraform Cloud
collect_terraform_cloud() {
    if [[ -z "$TFC_ORG" || -z "$TFC_WORKSPACE" ]]; then
        log_error "Terraform Cloud backend requires --org and --workspace"
        exit 1
    fi

    if [[ -z "${TFC_TOKEN:-}" ]]; then
        log_error "TFC_TOKEN environment variable is required"
        exit 1
    fi

    log_info "Fetching state from Terraform Cloud: $TFC_ORG/$TFC_WORKSPACE"

    # Get workspace ID
    WORKSPACE_ID=$(curl -s \
        --header "Authorization: Bearer $TFC_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "https://app.terraform.io/api/v2/organizations/$TFC_ORG/workspaces/$TFC_WORKSPACE" \
        | jq -r '.data.id')

    if [[ "$WORKSPACE_ID" == "null" || -z "$WORKSPACE_ID" ]]; then
        log_error "Failed to get workspace ID"
        exit 1
    fi

    # Get current state version
    STATE_VERSION_URL=$(curl -s \
        --header "Authorization: Bearer $TFC_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "https://app.terraform.io/api/v2/workspaces/$WORKSPACE_ID/current-state-version" \
        | jq -r '.data.attributes."hosted-state-download-url"')

    if [[ "$STATE_VERSION_URL" == "null" || -z "$STATE_VERSION_URL" ]]; then
        log_error "Failed to get state download URL"
        exit 1
    fi

    # Download state
    curl -s \
        --header "Authorization: Bearer $TFC_TOKEN" \
        "$STATE_VERSION_URL" \
        > "$TEMP_DIR/terraform.tfstate"

    STATE_ID="${STATE_ID:-tfc:$TFC_ORG/$TFC_WORKSPACE}"
}

# Collect state based on backend type
case "$BACKEND_TYPE" in
    local)
        collect_local
        ;;
    s3)
        collect_s3
        ;;
    azurerm)
        collect_azurerm
        ;;
    gcs)
        collect_gcs
        ;;
    terraform-cloud|tfc)
        collect_terraform_cloud
        ;;
    *)
        log_error "Unknown backend type: $BACKEND_TYPE"
        echo "Supported backends: local, s3, azurerm, gcs, terraform-cloud"
        exit 1
        ;;
esac

# Validate state file
if [[ ! -f "$TEMP_DIR/terraform.tfstate" ]]; then
    log_error "Failed to collect state file"
    exit 1
fi

# Check if it's valid JSON
if ! jq empty "$TEMP_DIR/terraform.tfstate" 2>/dev/null; then
    log_error "State file is not valid JSON"
    exit 1
fi

# Extract metadata
TERRAFORM_VERSION=$(jq -r '.terraform_version // "unknown"' "$TEMP_DIR/terraform.tfstate")
RESOURCE_COUNT=$(jq '[.resources[]? | .instances | length] | add // 0' "$TEMP_DIR/terraform.tfstate")
SERIAL=$(jq -r '.serial // 0' "$TEMP_DIR/terraform.tfstate")

log_info "State metadata:"
log_info "  - Terraform version: $TERRAFORM_VERSION"
log_info "  - Resource instances: $RESOURCE_COUNT"
log_info "  - Serial: $SERIAL"

# Filter resources by evidence type if needed
STATE_DATA=$(cat "$TEMP_DIR/terraform.tfstate")

if [[ "$EVIDENCE_TYPE" != "full_state" ]]; then
    log_info "Filtering resources for evidence type: $EVIDENCE_TYPE"

    case "$EVIDENCE_TYPE" in
        aws_resources)
            STATE_DATA=$(echo "$STATE_DATA" | jq '{
                version: .version,
                terraform_version: .terraform_version,
                serial: .serial,
                resources: [.resources[]? | select(.provider | contains("aws"))]
            }')
            ;;
        azure_resources)
            STATE_DATA=$(echo "$STATE_DATA" | jq '{
                version: .version,
                terraform_version: .terraform_version,
                serial: .serial,
                resources: [.resources[]? | select(.provider | contains("azurerm") or contains("azure"))]
            }')
            ;;
        gcp_resources)
            STATE_DATA=$(echo "$STATE_DATA" | jq '{
                version: .version,
                terraform_version: .terraform_version,
                serial: .serial,
                resources: [.resources[]? | select(.provider | contains("google"))]
            }')
            ;;
        kubernetes_resources)
            STATE_DATA=$(echo "$STATE_DATA" | jq '{
                version: .version,
                terraform_version: .terraform_version,
                serial: .serial,
                resources: [.resources[]? | select(.provider | contains("kubernetes"))]
            }')
            ;;
    esac

    FILTERED_COUNT=$(echo "$STATE_DATA" | jq '[.resources[]? | .instances | length] | add // 0')
    log_info "Filtered to $FILTERED_COUNT resource instances"
fi

# Create output JSON with evidence wrapper
COLLECTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg state_id "$STATE_ID" \
    --arg evidence_type "$EVIDENCE_TYPE" \
    --arg collected_at "$COLLECTED_AT" \
    --arg terraform_version "$TERRAFORM_VERSION" \
    --argjson resource_count "$RESOURCE_COUNT" \
    --argjson serial "$SERIAL" \
    --argjson data "$STATE_DATA" \
    '{
        state_id: $state_id,
        evidence_type: $evidence_type,
        collected_at: $collected_at,
        metadata: {
            terraform_version: $terraform_version,
            resource_count: $resource_count,
            serial: $serial
        },
        data: $data
    }' > "$OUTPUT_FILE"

log_info "Evidence written to: $OUTPUT_FILE"
log_info "Collection complete!"
