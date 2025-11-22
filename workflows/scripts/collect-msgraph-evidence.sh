#!/bin/bash
# collect-msgraph-evidence.sh
# Collects evidence from Microsoft Graph API for a specific evidence type
#
# Usage: ./collect-msgraph-evidence.sh <evidence_type> <output_file>
#
# Required environment variables:
#   AZURE_TENANT_ID - Azure AD tenant ID
#   AZURE_CLIENT_ID - Azure AD application (client) ID
#   AZURE_CLIENT_SECRET - Azure AD client secret
#
# Evidence types:
#   conditional_access_policies, user_mfa_status, sign_in_logs, audit_logs,
#   directory_roles, security_alerts, compliance_policies, device_configurations,
#   risk_detections, secure_score

set -euo pipefail

EVIDENCE_TYPE="${1:-}"
OUTPUT_FILE="${2:-}"

if [[ -z "$EVIDENCE_TYPE" || -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <evidence_type> <output_file>" >&2
    exit 1
fi

# Validate required environment variables
for var in AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET; do
    if [[ -z "${!var:-}" ]]; then
        echo "Error: $var environment variable is required" >&2
        exit 1
    fi
done

# Get access token from Azure AD
get_access_token() {
    local response
    response=$(curl -s -X POST \
        "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${AZURE_CLIENT_ID}" \
        -d "client_secret=${AZURE_CLIENT_SECRET}" \
        -d "scope=https://graph.microsoft.com/.default" \
        -d "grant_type=client_credentials")

    echo "$response" | jq -r '.access_token'
}

# Map evidence type to Microsoft Graph API endpoint
get_graph_endpoint() {
    local type="$1"
    case "$type" in
        conditional_access_policies)
            echo "/identity/conditionalAccess/policies"
            ;;
        user_mfa_status)
            echo "/reports/authenticationMethods/userRegistrationDetails"
            ;;
        sign_in_logs)
            echo "/auditLogs/signIns"
            ;;
        audit_logs)
            echo "/auditLogs/directoryAudits"
            ;;
        directory_roles)
            echo "/directoryRoles?\$expand=members"
            ;;
        security_alerts)
            echo "/security/alerts_v2"
            ;;
        compliance_policies)
            echo "/deviceManagement/deviceCompliancePolicies"
            ;;
        device_configurations)
            echo "/deviceManagement/deviceConfigurations"
            ;;
        risk_detections)
            echo "/identityProtection/riskDetections"
            ;;
        secure_score)
            echo "/security/secureScores?\$top=1"
            ;;
        *)
            echo "Error: Unknown evidence type: $type" >&2
            exit 1
            ;;
    esac
}

echo "Collecting $EVIDENCE_TYPE evidence..."

# Get access token
ACCESS_TOKEN=$(get_access_token)
if [[ "$ACCESS_TOKEN" == "null" || -z "$ACCESS_TOKEN" ]]; then
    echo "Error: Failed to obtain access token" >&2
    exit 1
fi

# Get the Graph API endpoint
ENDPOINT=$(get_graph_endpoint "$EVIDENCE_TYPE")

# Call Microsoft Graph API
GRAPH_URL="https://graph.microsoft.com/v1.0${ENDPOINT}"
echo "Fetching from: $GRAPH_URL"

RESPONSE=$(curl -s -X GET "$GRAPH_URL" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json")

# Check for errors in response
if echo "$RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    echo "Error from Microsoft Graph API:" >&2
    echo "$RESPONSE" | jq '.error' >&2
    exit 1
fi

# Wrap response with metadata
COLLECTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
jq -n \
    --arg tenant_id "$AZURE_TENANT_ID" \
    --arg evidence_type "$EVIDENCE_TYPE" \
    --arg collected_at "$COLLECTED_AT" \
    --argjson data "$RESPONSE" \
    '{
        tenant_id: $tenant_id,
        evidence_type: $evidence_type,
        collected_at: $collected_at,
        data: $data
    }' > "$OUTPUT_FILE"

echo "Evidence collected and saved to $OUTPUT_FILE"
