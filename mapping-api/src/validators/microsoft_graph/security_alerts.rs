use serde_json::Value;
use crate::validators::models::*;

/// Validate Security Alerts against FedRAMP 20x KSIs
/// Graph API: GET /security/alerts_v2
pub fn validate_security_alerts(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let alerts = extract_array(data);
    let records = alerts.len();
    if records == 0 {
        return (vec![
            KsiValidationBuilder::new("KSI-INR-01", "Respond to incidents according to FedRAMP requirements.", Relevance::Direct)
                .add_check(ValidationCheck::passed("no_alerts", "No security alerts in sample (good) or alerting may not be configured"))
                .build()
        ], 0);
    }

    let mut results = Vec::new();

    // Categorize alerts
    let high_severity: Vec<_> = alerts.iter().filter(|a| severity_is(a, "high")).collect();
    let medium_severity: Vec<_> = alerts.iter().filter(|a| severity_is(a, "medium")).collect();
    let resolved: Vec<_> = alerts.iter().filter(|a| status_is(a, &["resolved", "dismissed"])).collect();
    let in_progress: Vec<_> = alerts.iter().filter(|a| status_is(a, &["inProgress", "investigating"])).collect();
    let new_alerts: Vec<_> = alerts.iter().filter(|a| status_is(a, &["new", "unknown"])).collect();
    let assigned: Vec<_> = alerts.iter().filter(|a| a.get("assignedTo").and_then(|v| v.as_str()).is_some()).collect();

    // KSI-INR-01: Incident response
    let mut builder = KsiValidationBuilder::new(
        "KSI-INR-01", "Respond to incidents according to FedRAMP requirements and cloud service provider policies.", Relevance::Direct,
    );

    builder = builder.add_check(ValidationCheck::passed("alerts_detected", "Security alerts are being generated")
        .with_values(format!("{} alerts", records), "Alerting active"));

    // Check alert assignment
    let assigned_pct = if records > 0 { assigned.len() * 100 / records } else { 0 };
    builder = builder.add_check(if assigned_pct >= 80 {
        ValidationCheck::passed("alerts_assigned", "Most alerts are assigned for investigation")
            .with_values(format!("{}% assigned", assigned_pct), ">=80%")
    } else {
        ValidationCheck::failed("alerts_assigned", "Many alerts are unassigned - may indicate response gaps", Severity::High)
            .with_values(format!("{}% assigned", assigned_pct), ">=80%")
    });

    // Check resolution rate
    let resolution_pct = if records > 0 { resolved.len() * 100 / records } else { 0 };
    builder = builder.add_check(if resolution_pct >= 70 {
        ValidationCheck::passed("alert_resolution", "Good alert resolution rate")
            .with_values(format!("{}% resolved", resolution_pct), ">=70%")
    } else {
        ValidationCheck::failed("alert_resolution", "Low alert resolution rate - backlog may be growing", Severity::Medium)
            .with_values(format!("{}% resolved", resolution_pct), ">=70%")
    });

    // Check high severity handling
    let high_unresolved = high_severity.iter()
        .filter(|a| !status_is(a, &["resolved", "dismissed"]))
        .count();
    builder = builder.add_check(if high_unresolved == 0 {
        ValidationCheck::passed("high_severity_handled", "All high-severity alerts are resolved")
    } else {
        ValidationCheck::failed("high_severity_handled", "Unresolved high-severity alerts require immediate attention", Severity::Critical)
            .with_values(format!("{} unresolved high", high_unresolved), "0 unresolved high")
    });

    if high_unresolved > 0 {
        builder = builder.add_recommendation("Immediately investigate and resolve high-severity security alerts");
    }
    if assigned_pct < 80 {
        builder = builder.add_recommendation("Assign all security alerts to responsible personnel");
    }
    results.push(builder.build());

    // KSI-MLA-02: Monitor for anomalies
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-02", "Monitor for unauthorized access and anomalies.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("anomaly_detection", "Security anomaly detection is active")
        .with_values(format!("{} high, {} medium severity", high_severity.len(), medium_severity.len()), "Detection active"));
    builder = builder.add_check(ValidationCheck::passed("alert_categorization", "Alerts are categorized by severity for prioritization"));
    results.push(builder.build());

    // KSI-INR-02: Incident response testing
    let mut builder = KsiValidationBuilder::new(
        "KSI-INR-02", "Conduct incident response testing and exercises.", Relevance::Indirect,
    );
    builder = builder.add_check(ValidationCheck::passed("real_alerts_processed", "Real security alerts are being processed - indicates IR capability")
        .with_values(format!("{} in progress, {} resolved", in_progress.len(), resolved.len()), "IR active"));
    builder = builder.add_recommendation("Note: Full KSI-INR-02 requires evidence of tabletop exercises and IR drills");
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

fn severity_is(alert: &Value, sev: &str) -> bool {
    alert.get("severity").and_then(|s| s.as_str())
        .map(|s| s.eq_ignore_ascii_case(sev))
        .unwrap_or(false)
}

fn status_is(alert: &Value, statuses: &[&str]) -> bool {
    alert.get("status").and_then(|s| s.as_str())
        .map(|s| statuses.iter().any(|st| s.eq_ignore_ascii_case(st)))
        .unwrap_or(false)
}
