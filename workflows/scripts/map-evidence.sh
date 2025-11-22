#!/bin/bash
# map-evidence.sh
# Maps collected evidence to a compliance framework using the Mapping API
#
# Usage: ./map-evidence.sh <evidence_file> <framework> <output_file>
#
# Required environment variables:
#   MAPPING_API_URL - Base URL of the Mapping API (e.g., http://localhost:3000)
#   MAPPING_API_TOKEN - JWT token for API authentication
#
# Arguments:
#   evidence_file - JSON file containing collected evidence
#   framework - Target framework: "fedramp20x" or "cmmc"
#   output_file - Output file for mapping results

set -euo pipefail

EVIDENCE_FILE="${1:-}"
FRAMEWORK="${2:-fedramp20x}"
OUTPUT_FILE="${3:-}"

if [[ -z "$EVIDENCE_FILE" || -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <evidence_file> <framework> <output_file>" >&2
    exit 1
fi

# Validate required environment variables
for var in MAPPING_API_URL MAPPING_API_TOKEN; do
    if [[ -z "${!var:-}" ]]; then
        echo "Error: $var environment variable is required" >&2
        exit 1
    fi
done

if [[ ! -f "$EVIDENCE_FILE" ]]; then
    echo "Error: Evidence file not found: $EVIDENCE_FILE" >&2
    exit 1
fi

# Read evidence file and add framework
EVIDENCE=$(cat "$EVIDENCE_FILE")
EVIDENCE_TYPE=$(echo "$EVIDENCE" | jq -r '.evidence_type')

echo "Mapping $EVIDENCE_TYPE evidence to $FRAMEWORK framework..."

# Build the request payload
REQUEST_PAYLOAD=$(echo "$EVIDENCE" | jq --arg framework "$FRAMEWORK" '. + {framework: $framework}')

# Call the Mapping API
RESPONSE=$(curl -s -X POST "${MAPPING_API_URL}/api/v1/sources/microsoft-graph/map" \
    -H "Authorization: Bearer ${MAPPING_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_PAYLOAD")

# Check for errors
if echo "$RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    echo "Error from Mapping API:" >&2
    echo "$RESPONSE" | jq '.' >&2
    exit 1
fi

# Save response
echo "$RESPONSE" | jq '.' > "$OUTPUT_FILE"

echo "Mapping results saved to $OUTPUT_FILE"

# Print summary
if [[ "$FRAMEWORK" == "fedramp20x" ]]; then
    echo ""
    echo "=== FedRAMP 20x Mapping Summary ==="
    echo "$RESPONSE" | jq -r '.overall_status | "Score: \(.score | floor)% | Compliant: \(.compliant) | Non-compliant: \(.non_compliant)"'
elif [[ "$FRAMEWORK" == "cmmc" ]]; then
    echo ""
    echo "=== CMMC Mapping Summary ==="
    echo "$RESPONSE" | jq -r '.summary | "Total Practices: \(.total_practices_mapped) | L1: \(.level1_practices) | L2: \(.level2_practices) | L3: \(.level3_practices)"'
fi
