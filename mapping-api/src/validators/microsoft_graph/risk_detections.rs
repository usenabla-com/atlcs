use serde_json::Value;
use crate::validators::models::*;

/// Validate Risk Detections against FedRAMP 20x KSIs
/// Graph API: GET /identityProtection/riskDetections
pub fn validate_risk_detections(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let detections = extract_array(data);
    let records = detections.len();

    // Empty is actually good here - means no risks detected
    let mut results = Vec::new();

    // Categorize by risk level
    let high_risk: Vec<_> = detections.iter().filter(|d| risk_level(d) == "high").collect();
    let medium_risk: Vec<_> = detections.iter().filter(|d| risk_level(d) == "medium").collect();
    let low_risk: Vec<_> = detections.iter().filter(|d| risk_level(d) == "low").collect();

    // Categorize by state
    let remediated: Vec<_> = detections.iter().filter(|d| state_is(d, &["remediated", "dismissed"])).collect();
    let at_risk: Vec<_> = detections.iter().filter(|d| state_is(d, &["atRisk", "confirmedCompromised"])).collect();

    // Categorize by type
    let leaked_creds: Vec<_> = detections.iter().filter(|d| detection_type_contains(d, "leakedCredentials")).collect();
    let impossible_travel: Vec<_> = detections.iter().filter(|d| detection_type_contains(d, "impossibleTravel")).collect();
    let anonymous_ip: Vec<_> = detections.iter().filter(|d| detection_type_contains(d, "anonymousIP")).collect();
    let malware: Vec<_> = detections.iter().filter(|d| detection_type_contains(d, "malware")).collect();

    // KSI-MLA-02: Monitor for anomalies
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-02", "Monitor for unauthorized access and anomalies.", Relevance::Direct,
    );

    if records == 0 {
        builder = builder.add_check(ValidationCheck::passed("no_risks_detected", "No risk detections in sample - Identity Protection may be working well or not enabled"));
        builder = builder.add_recommendation("Verify Azure AD Identity Protection is enabled and configured");
    } else {
        builder = builder.add_check(ValidationCheck::passed("risk_detection_active", "Identity Protection risk detection is active")
            .with_values(format!("{} detections", records), "Detection active"));

        // Risk distribution
        builder = builder.add_check(ValidationCheck::passed("risk_categorization", "Risks are categorized by severity")
            .with_values(format!("High: {}, Medium: {}, Low: {}", high_risk.len(), medium_risk.len(), low_risk.len()), "Categorized"));

        // Detection types
        let detection_types = vec![
            (leaked_creds.len(), "leaked credentials"),
            (impossible_travel.len(), "impossible travel"),
            (anonymous_ip.len(), "anonymous IP"),
            (malware.len(), "malware-linked"),
        ];
        let active_types: Vec<_> = detection_types.iter().filter(|(count, _)| *count > 0).collect();

        if active_types.len() >= 2 {
            builder = builder.add_check(ValidationCheck::passed("diverse_detection", "Multiple risk detection types are active"));
        }
    }
    results.push(builder.build());

    // KSI-IAM-05: Zero trust / assume compromise
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-05", "Design identity and access management systems that assume resources will be compromised.", Relevance::Direct,
    );

    if records > 0 {
        builder = builder.add_check(ValidationCheck::passed("identity_protection_enabled", "Azure AD Identity Protection is actively detecting risks")
            .with_values(format!("{} detections", records), "IP enabled"));

        // Check remediation rate
        let remediation_rate = if records > 0 { remediated.len() * 100 / records } else { 0 };
        builder = builder.add_check(if remediation_rate >= 80 {
            ValidationCheck::passed("risks_remediated", "Most detected risks have been remediated")
                .with_values(format!("{}% remediated", remediation_rate), ">=80%")
        } else {
            ValidationCheck::failed("risks_remediated", "Many risks remain unremediated", Severity::High)
                .with_values(format!("{}% remediated", remediation_rate), ">=80%")
        });

        // Check for active compromises
        builder = builder.add_check(if at_risk.is_empty() {
            ValidationCheck::passed("no_confirmed_compromise", "No confirmed compromised accounts")
        } else {
            ValidationCheck::failed("no_confirmed_compromise", "Accounts confirmed compromised - immediate action required", Severity::Critical)
                .with_values(format!("{} at risk/compromised", at_risk.len()), "0 compromised")
        });

        // High-risk handling
        let high_unremediated = high_risk.iter()
            .filter(|d| !state_is(d, &["remediated", "dismissed"]))
            .count();
        builder = builder.add_check(if high_unremediated == 0 {
            ValidationCheck::passed("high_risk_handled", "All high-risk detections have been addressed")
        } else {
            ValidationCheck::failed("high_risk_handled", "Unaddressed high-risk detections", Severity::Critical)
                .with_values(format!("{} high-risk unaddressed", high_unremediated), "0 unaddressed")
        });

        if high_unremediated > 0 {
            builder = builder.add_recommendation("Immediately remediate high-risk users (force password reset, revoke sessions)");
        }
        if !at_risk.is_empty() {
            builder = builder.add_recommendation("Investigate and remediate confirmed compromised accounts immediately");
        }
    } else {
        builder = builder.add_check(ValidationCheck::passed("no_risks", "No risk detections present")
            .with_values("0 risks", "Risk detection active"));
        builder = builder.add_recommendation("Ensure Azure AD Identity Protection P2 is licensed and risk policies are configured");
    }
    results.push(builder.build());

    // KSI-IAM-06: Account management
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-06", "Disable inactive accounts and revoke access promptly.", Relevance::Supporting,
    );
    if !at_risk.is_empty() || !high_risk.is_empty() {
        builder = builder.add_check(ValidationCheck::failed("risky_accounts_active", "Risky accounts may still have active access", Severity::High)
            .with_values(format!("{} at risk accounts", at_risk.len() + high_risk.len()), "0 risky accounts"));
        builder = builder.add_recommendation("Review and disable accounts with high-risk detections");
    } else {
        builder = builder.add_check(ValidationCheck::passed("no_risky_accounts", "No high-risk or compromised accounts detected"));
    }
    results.push(builder.build());

    (results, records)
}

fn extract_array(data: &Value) -> Vec<Value> {
    match data {
        Value::Array(arr) => arr.clone(),
        Value::Object(obj) => obj.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        _ => vec![],
    }
}

fn risk_level(detection: &Value) -> &str {
    detection.get("riskLevel").and_then(|r| r.as_str()).unwrap_or("unknown")
}

fn state_is(detection: &Value, states: &[&str]) -> bool {
    detection.get("riskState").and_then(|s| s.as_str())
        .map(|s| states.iter().any(|st| s.eq_ignore_ascii_case(st)))
        .unwrap_or(false)
}

fn detection_type_contains(detection: &Value, keyword: &str) -> bool {
    detection.get("riskEventType").and_then(|t| t.as_str())
        .map(|t| t.to_lowercase().contains(&keyword.to_lowercase()))
        .unwrap_or(false)
}
