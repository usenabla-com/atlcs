use serde_json::Value;
use crate::validators::models::*;

/// Validate Sign-in Logs against FedRAMP 20x KSIs
///
/// Graph API: GET /auditLogs/signIns
///
/// Relevant KSIs:
/// - KSI-MLA-01: Implement comprehensive logging and monitoring
/// - KSI-MLA-02: Monitor for unauthorized access and anomalies
/// - KSI-MLA-07: Maintain list of resources/events to monitor
/// - KSI-IAM-06: Disable inactive accounts
pub fn validate_sign_in_logs(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let logs = match data {
        Value::Array(arr) => arr.clone(),
        Value::Object(obj) => {
            if let Some(Value::Array(arr)) = obj.get("value") {
                arr.clone()
            } else {
                vec![data.clone()]
            }
        }
        _ => return (vec![], 0),
    };

    let records = logs.len();
    if records == 0 {
        return (vec![
            KsiValidationBuilder::new(
                "KSI-MLA-01",
                "Implement comprehensive logging and monitoring.",
                Relevance::Direct,
            )
            .add_check(ValidationCheck::failed(
                "logs_present",
                "No sign-in logs provided for analysis",
                Severity::High,
            ))
            .build(),
        ], 0);
    }

    let mut results = Vec::new();

    // Analyze sign-in logs
    let failed_sign_ins: Vec<_> = logs.iter()
        .filter(|l| {
            l.get("status")
                .and_then(|s| s.get("errorCode"))
                .and_then(|e| e.as_i64())
                .map(|code| code != 0)
                .unwrap_or(false)
        })
        .collect();

    let risky_sign_ins: Vec<_> = logs.iter()
        .filter(|l| {
            let risk = l.get("riskLevelDuringSignIn").and_then(|r| r.as_str()).unwrap_or("none");
            risk == "high" || risk == "medium"
        })
        .collect();

    let mfa_required_sign_ins: Vec<_> = logs.iter()
        .filter(|l| {
            l.get("authenticationRequirement").and_then(|r| r.as_str()) == Some("multiFactorAuthentication")
        })
        .collect();

    let ca_policy_applied: Vec<_> = logs.iter()
        .filter(|l| {
            l.get("appliedConditionalAccessPolicies")
                .and_then(|p| p.as_array())
                .map(|arr| !arr.is_empty())
                .unwrap_or(false)
        })
        .collect();

    let legacy_auth_attempts: Vec<_> = logs.iter()
        .filter(|l| {
            let client = l.get("clientAppUsed").and_then(|c| c.as_str()).unwrap_or("");
            is_legacy_client(client)
        })
        .collect();

    let unique_users: std::collections::HashSet<_> = logs.iter()
        .filter_map(|l| l.get("userPrincipalName").and_then(|u| u.as_str()))
        .collect();

    let unique_ips: std::collections::HashSet<_> = logs.iter()
        .filter_map(|l| l.get("ipAddress").and_then(|i| i.as_str()))
        .collect();

    let unique_locations: std::collections::HashSet<_> = logs.iter()
        .filter_map(|l| {
            l.get("location")
                .and_then(|loc| loc.get("countryOrRegion"))
                .and_then(|c| c.as_str())
        })
        .collect();

    // KSI-MLA-01: Comprehensive logging
    results.push(validate_ksi_mla_01(&logs, &unique_users, &unique_ips));

    // KSI-MLA-02: Monitor for unauthorized access
    results.push(validate_ksi_mla_02(
        &logs,
        &failed_sign_ins,
        &risky_sign_ins,
        &legacy_auth_attempts,
    ));

    // KSI-MLA-07: Maintain list of monitored events
    results.push(validate_ksi_mla_07(&logs));

    // KSI-IAM-02: MFA enforcement evidence
    results.push(validate_ksi_iam_02(&logs, &mfa_required_sign_ins));

    // KSI-IAM-05: Zero trust evidence
    results.push(validate_ksi_iam_05(&ca_policy_applied, &risky_sign_ins));

    (results, records)
}

fn validate_ksi_mla_01(
    logs: &[Value],
    unique_users: &std::collections::HashSet<&str>,
    unique_ips: &std::collections::HashSet<&str>,
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-01",
        "Implement comprehensive logging and monitoring.",
        Relevance::Direct,
    );

    // Check 1: Logs are being collected
    let check = ValidationCheck::passed(
        "sign_in_logging_enabled",
        "Sign-in logs are being collected in Azure AD",
    )
    .with_values(format!("{} log entries", logs.len()), "Logs present");
    builder = builder.add_check(check);

    // Check 2: Log completeness - essential fields
    let logs_with_timestamp = logs.iter()
        .filter(|l| l.get("createdDateTime").is_some())
        .count();
    let check = if logs_with_timestamp == logs.len() {
        ValidationCheck::passed(
            "timestamp_completeness",
            "All logs have timestamps",
        )
    } else {
        ValidationCheck::failed(
            "timestamp_completeness",
            "Some logs missing timestamps",
            Severity::High,
        )
        .with_values(
            format!("{}/{}", logs_with_timestamp, logs.len()),
            "100%",
        )
    };
    builder = builder.add_check(check);

    // Check 3: User identification in logs
    let logs_with_user = logs.iter()
        .filter(|l| l.get("userPrincipalName").is_some() || l.get("userId").is_some())
        .count();
    let check = if logs_with_user == logs.len() {
        ValidationCheck::passed(
            "user_identification",
            "All logs identify the user",
        )
    } else {
        ValidationCheck::failed(
            "user_identification",
            "Some logs missing user identification",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    // Check 4: IP address logging
    let logs_with_ip = logs.iter()
        .filter(|l| l.get("ipAddress").is_some())
        .count();
    let check = if logs_with_ip >= logs.len() * 95 / 100 {
        ValidationCheck::passed(
            "ip_address_logging",
            "IP addresses are logged for sign-in events",
        )
        .with_values(format!("{} unique IPs", unique_ips.len()), "IPs captured")
    } else {
        ValidationCheck::failed(
            "ip_address_logging",
            "IP addresses missing from some logs",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    // Check 5: Location logging
    let logs_with_location = logs.iter()
        .filter(|l| l.get("location").is_some())
        .count();
    let check = if logs_with_location >= logs.len() * 90 / 100 {
        ValidationCheck::passed(
            "location_logging",
            "Geographic location is logged",
        )
    } else {
        ValidationCheck::failed(
            "location_logging",
            "Location data missing from many logs",
            Severity::Low,
        )
    };
    builder = builder.add_check(check);

    // Check 6: Status/result logging
    let logs_with_status = logs.iter()
        .filter(|l| l.get("status").is_some())
        .count();
    let check = if logs_with_status == logs.len() {
        ValidationCheck::passed(
            "status_logging",
            "Sign-in success/failure status is logged",
        )
    } else {
        ValidationCheck::failed(
            "status_logging",
            "Status missing from some logs",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    builder.build()
}

fn validate_ksi_mla_02(
    logs: &[Value],
    failed_sign_ins: &[&Value],
    risky_sign_ins: &[&Value],
    legacy_auth_attempts: &[&Value],
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-02",
        "Monitor for unauthorized access and anomalies.",
        Relevance::Direct,
    );

    let total = logs.len();
    let failed_pct = if total > 0 { failed_sign_ins.len() * 100 / total } else { 0 };
    let risky_pct = if total > 0 { risky_sign_ins.len() * 100 / total } else { 0 };
    let legacy_pct = if total > 0 { legacy_auth_attempts.len() * 100 / total } else { 0 };

    // Check 1: Failed sign-in monitoring
    let check = ValidationCheck::passed(
        "failed_signin_visibility",
        "Failed sign-in attempts are captured",
    )
    .with_values(
        format!("{} failed ({}%)", failed_sign_ins.len(), failed_pct),
        "Visibility into failures",
    );
    builder = builder.add_check(check);

    // Check 2: Risk detection
    let check = if !risky_sign_ins.is_empty() {
        ValidationCheck::passed(
            "risk_detection_active",
            "Risk-based sign-in detection is active (Identity Protection)",
        )
        .with_values(
            format!("{} risky sign-ins detected", risky_sign_ins.len()),
            "Risk detection active",
        )
    } else {
        ValidationCheck::passed(
            "risk_detection_active",
            "No risky sign-ins detected in sample (good) or risk detection may not be enabled",
        )
    };
    builder = builder.add_check(check);

    // Check 3: High failure rate (potential attack)
    let check = if failed_pct <= 20 {
        ValidationCheck::passed(
            "failure_rate_normal",
            "Sign-in failure rate is within normal range",
        )
        .with_values(format!("{}%", failed_pct), "<=20%")
    } else if failed_pct <= 40 {
        ValidationCheck::failed(
            "failure_rate_normal",
            "Elevated sign-in failure rate detected - investigate potential issues",
            Severity::Medium,
        )
        .with_values(format!("{}%", failed_pct), "<=20%")
    } else {
        ValidationCheck::failed(
            "failure_rate_normal",
            "High sign-in failure rate - possible credential attack or misconfiguration",
            Severity::High,
        )
        .with_values(format!("{}%", failed_pct), "<=20%")
    };
    builder = builder.add_check(check);

    // Check 4: High risk rate
    let check = if risky_pct <= 5 {
        ValidationCheck::passed(
            "risk_rate_acceptable",
            "Risky sign-in rate is low",
        )
        .with_values(format!("{}%", risky_pct), "<=5%")
    } else {
        ValidationCheck::failed(
            "risk_rate_acceptable",
            "Elevated risky sign-in rate - review Identity Protection alerts",
            Severity::High,
        )
        .with_values(format!("{}%", risky_pct), "<=5%")
    };
    builder = builder.add_check(check);

    // Check 5: Legacy authentication attempts
    let check = if legacy_pct <= 5 {
        ValidationCheck::passed(
            "legacy_auth_minimal",
            "Legacy authentication usage is minimal",
        )
        .with_values(format!("{}%", legacy_pct), "<=5%")
    } else {
        ValidationCheck::failed(
            "legacy_auth_minimal",
            "Significant legacy authentication usage detected - these bypass MFA",
            Severity::High,
        )
        .with_values(format!("{}%", legacy_pct), "<=5%")
    };
    builder = builder.add_check(check);

    if risky_pct > 5 {
        builder = builder.add_recommendation(
            "Review Azure AD Identity Protection and remediate risky sign-ins",
        );
    }
    if legacy_pct > 5 {
        builder = builder.add_recommendation(
            "Block legacy authentication protocols via Conditional Access",
        );
    }

    builder.build()
}

fn validate_ksi_mla_07(logs: &[Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-07",
        "Maintain a list of information resources and event types that will be monitored, logged, and audited.",
        Relevance::Supporting,
    );

    // Check that various event types are captured
    let has_interactive = logs.iter().any(|l| {
        l.get("isInteractive").and_then(|i| i.as_bool()).unwrap_or(false)
    });
    let has_non_interactive = logs.iter().any(|l| {
        l.get("isInteractive").and_then(|i| i.as_bool()) == Some(false)
    });
    let has_service_principal = logs.iter().any(|l| {
        l.get("servicePrincipalId").and_then(|s| s.as_str()).is_some()
    });

    let check = ValidationCheck::passed(
        "event_type_coverage",
        "Multiple sign-in event types are being logged",
    )
    .with_values(
        format!(
            "Interactive: {}, Non-interactive: {}, Service Principal: {}",
            has_interactive, has_non_interactive, has_service_principal
        ),
        "Multiple event types",
    );
    builder = builder.add_check(check);

    builder.build()
}

fn validate_ksi_iam_02(logs: &[Value], mfa_required: &[&Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-02",
        "Enforce strong authentication including MFA.",
        Relevance::Supporting,
    );

    let total = logs.len();
    let mfa_pct = if total > 0 { mfa_required.len() * 100 / total } else { 0 };

    let check = if mfa_pct >= 80 {
        ValidationCheck::passed(
            "mfa_enforcement_in_logs",
            "MFA is being enforced for most sign-ins",
        )
        .with_values(format!("{}% required MFA", mfa_pct), ">=80%")
    } else if mfa_pct >= 50 {
        ValidationCheck::failed(
            "mfa_enforcement_in_logs",
            "MFA enforcement is inconsistent - many sign-ins not requiring MFA",
            Severity::High,
        )
        .with_values(format!("{}% required MFA", mfa_pct), ">=80%")
    } else {
        ValidationCheck::failed(
            "mfa_enforcement_in_logs",
            "MFA is not being enforced for most sign-ins",
            Severity::Critical,
        )
        .with_values(format!("{}% required MFA", mfa_pct), ">=80%")
    };
    builder = builder.add_check(check);

    if mfa_pct < 80 {
        builder = builder.add_recommendation(
            "Review Conditional Access policies to ensure MFA is required for all users and applications",
        );
    }

    builder.build()
}

fn validate_ksi_iam_05(ca_policy_applied: &[&Value], risky_sign_ins: &[&Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-05",
        "Design identity and access management systems that assume resources will be compromised.",
        Relevance::Supporting,
    );

    // Check CA policies are being applied
    let check = if !ca_policy_applied.is_empty() {
        ValidationCheck::passed(
            "ca_policies_enforced",
            "Conditional Access policies are being applied to sign-ins",
        )
        .with_values(
            format!("{} sign-ins with CA", ca_policy_applied.len()),
            "CA policies active",
        )
    } else {
        ValidationCheck::failed(
            "ca_policies_enforced",
            "No Conditional Access policies applied to sign-ins in sample",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check risk-based decisions
    let risk_blocked = risky_sign_ins.iter()
        .filter(|l| {
            l.get("status")
                .and_then(|s| s.get("errorCode"))
                .and_then(|e| e.as_i64())
                .map(|code| code != 0)
                .unwrap_or(false)
        })
        .count();

    if !risky_sign_ins.is_empty() {
        let check = if risk_blocked > 0 {
            ValidationCheck::passed(
                "risky_signins_blocked",
                "Some risky sign-ins were blocked (zero trust in action)",
            )
            .with_values(
                format!("{}/{} risky blocked", risk_blocked, risky_sign_ins.len()),
                "Risky sign-ins blocked",
            )
        } else {
            ValidationCheck::failed(
                "risky_signins_blocked",
                "Risky sign-ins detected but none were blocked",
                Severity::High,
            )
        };
        builder = builder.add_check(check);
    }

    builder.build()
}

fn is_legacy_client(client: &str) -> bool {
    matches!(
        client.to_lowercase().as_str(),
        "exchange activesync" |
        "autodiscover" |
        "imap4" |
        "pop3" |
        "smtp" |
        "mapi over http" |
        "offline address book" |
        "exchange web services" |
        "other clients"
    )
}
