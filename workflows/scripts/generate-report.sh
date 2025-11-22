#!/bin/bash
# generate-report.sh
# Generates a consolidated compliance report from multiple mapping results
#
# Usage: ./generate-report.sh <results_dir> <output_file> [format]
#
# Arguments:
#   results_dir - Directory containing mapping result JSON files
#   output_file - Output file for the report
#   format - Output format: "json" (default), "markdown", or "summary"

set -euo pipefail

RESULTS_DIR="${1:-}"
OUTPUT_FILE="${2:-}"
FORMAT="${3:-json}"

if [[ -z "$RESULTS_DIR" || -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 <results_dir> <output_file> [format]" >&2
    exit 1
fi

if [[ ! -d "$RESULTS_DIR" ]]; then
    echo "Error: Results directory not found: $RESULTS_DIR" >&2
    exit 1
fi

echo "Generating $FORMAT report from $RESULTS_DIR..."

REPORT_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

case "$FORMAT" in
    json)
        # Combine all results into a single JSON report
        jq -n \
            --arg report_date "$REPORT_DATE" \
            --slurpfile results <(cat "$RESULTS_DIR"/*.json 2>/dev/null | jq -s '.') \
            '{
                report_date: $report_date,
                report_type: "fedramp-20x-compliance",
                results: $results[0]
            }' > "$OUTPUT_FILE"
        ;;

    markdown)
        {
            echo "# FedRAMP 20x Compliance Report"
            echo ""
            echo "**Generated:** $REPORT_DATE"
            echo ""
            echo "---"
            echo ""

            for file in "$RESULTS_DIR"/*.json; do
                if [[ -f "$file" ]]; then
                    EVIDENCE_TYPE=$(jq -r '.evidence_type // "unknown"' "$file")
                    echo "## Evidence: $EVIDENCE_TYPE"
                    echo ""

                    if jq -e '.overall_status' "$file" > /dev/null 2>&1; then
                        SCORE=$(jq -r '.overall_status.score | floor' "$file")
                        COMPLIANT=$(jq -r '.overall_status.compliant' "$file")
                        NON_COMPLIANT=$(jq -r '.overall_status.non_compliant' "$file")

                        echo "**Compliance Score:** ${SCORE}%"
                        echo ""
                        echo "| Status | Count |"
                        echo "|--------|-------|"
                        echo "| Compliant | $COMPLIANT |"
                        echo "| Non-compliant | $NON_COMPLIANT |"
                        echo ""

                        echo "### KSI Results"
                        echo ""
                        jq -r '.ksi_results[] | "- **\(.ksi_id)**: \(.status) - \(.summary)"' "$file"
                        echo ""
                    fi

                    echo "---"
                    echo ""
                fi
            done
        } > "$OUTPUT_FILE"
        ;;

    summary)
        {
            echo "FedRAMP 20x Compliance Summary"
            echo "=============================="
            echo "Report Date: $REPORT_DATE"
            echo ""

            for file in "$RESULTS_DIR"/*.json; do
                if [[ -f "$file" ]] && jq -e '.overall_status' "$file" > /dev/null 2>&1; then
                    EVIDENCE_TYPE=$(jq -r '.evidence_type' "$file")
                    SCORE=$(jq -r '.overall_status.score' "$file")
                    COMPLIANT=$(jq -r '.overall_status.compliant' "$file")
                    NON_COMPLIANT=$(jq -r '.overall_status.non_compliant' "$file")

                    printf "%-35s Score: %5.1f%%  Compliant: %d  Non-compliant: %d\n" \
                        "$EVIDENCE_TYPE" "$SCORE" "$COMPLIANT" "$NON_COMPLIANT"
                fi
            done
        } > "$OUTPUT_FILE"
        ;;

    *)
        echo "Error: Unknown format: $FORMAT" >&2
        exit 1
        ;;
esac

echo "Report saved to $OUTPUT_FILE"
