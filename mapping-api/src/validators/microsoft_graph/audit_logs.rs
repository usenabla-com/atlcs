use serde_json::Value;
use crate::validators::models::*;

/// Validate Audit Logs against FedRAMP 20x KSIs
/// Graph API: GET /auditLogs/directoryAudits
pub fn validate_audit_logs(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let logs = extract_array(data);
    let records = logs.len();
    if records == 0 {
        return (vec![empty_result("KSI-MLA-01", "Implement comprehensive logging and monitoring.")], 0);
    }

    let mut results = Vec::new();

    // Categorize audit events
    let user_mgmt_events: Vec<_> = logs.iter()
        .filter(|l| category_matches(l, &["UserManagement", "User"]))
        .collect();
    let group_mgmt_events: Vec<_> = logs.iter()
        .filter(|l| category_matches(l, &["GroupManagement", "Group"]))
        .collect();
    let app_mgmt_events: Vec<_> = logs.iter()
        .filter(|l| category_matches(l, &["ApplicationManagement", "Application"]))
        .collect();
    let role_mgmt_events: Vec<_> = logs.iter()
        .filter(|l| category_matches(l, &["RoleManagement", "Role"]))
        .collect();
    let policy_events: Vec<_> = logs.iter()
        .filter(|l| category_matches(l, &["Policy", "Authorization"]))
        .collect();

    // KSI-MLA-01: Comprehensive logging
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-01", "Implement comprehensive logging and monitoring.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("audit_logging_enabled", "Directory audit logs are being collected")
        .with_values(format!("{} events", records), "Logs present"));

    let has_all_categories = !user_mgmt_events.is_empty() && !group_mgmt_events.is_empty() && !role_mgmt_events.is_empty();
    builder = builder.add_check(if has_all_categories {
        ValidationCheck::passed("category_coverage", "Multiple audit categories are being logged")
    } else {
        ValidationCheck::failed("category_coverage", "Some audit categories may not be captured", Severity::Medium)
    });
    results.push(builder.build());

    // KSI-CMT-01: Log service modifications
    let mut builder = KsiValidationBuilder::new(
        "KSI-CMT-01", "Log and monitor service modifications.", Relevance::Direct,
    );
    let config_changes: Vec<_> = logs.iter()
        .filter(|l| activity_contains(l, &["Update", "Set", "Add", "Remove", "Delete"]))
        .collect();
    builder = builder.add_check(ValidationCheck::passed("config_changes_logged", "Configuration changes are being logged")
        .with_values(format!("{} change events", config_changes.len()), "Changes logged"));
    results.push(builder.build());

    // KSI-IAM-04: Least privilege (role changes)
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-04", "Apply least privilege access controls.", Relevance::Supporting,
    );
    builder = builder.add_check(if !role_mgmt_events.is_empty() {
        ValidationCheck::passed("role_changes_logged", "Role assignment changes are being audited")
            .with_values(format!("{} role events", role_mgmt_events.len()), "Role audit active")
    } else {
        ValidationCheck::failed("role_changes_logged", "No role management events in sample", Severity::Low)
    });
    results.push(builder.build());

    // KSI-IAM-07: Account lifecycle
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-07", "Securely manage the lifecycle and privileges of all accounts, roles, and groups.", Relevance::Direct,
    );
    builder = builder.add_check(if !user_mgmt_events.is_empty() {
        ValidationCheck::passed("user_lifecycle_logged", "User lifecycle events are logged")
    } else {
        ValidationCheck::failed("user_lifecycle_logged", "No user management events in sample", Severity::Medium)
    });
    builder = builder.add_check(if !group_mgmt_events.is_empty() {
        ValidationCheck::passed("group_lifecycle_logged", "Group management events are logged")
    } else {
        ValidationCheck::failed("group_lifecycle_logged", "No group management events in sample", Severity::Low)
    });
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

fn category_matches(log: &Value, categories: &[&str]) -> bool {
    log.get("category").and_then(|c| c.as_str())
        .map(|cat| categories.iter().any(|c| cat.contains(c)))
        .unwrap_or(false)
}

fn activity_contains(log: &Value, actions: &[&str]) -> bool {
    log.get("activityDisplayName").and_then(|a| a.as_str())
        .map(|act| actions.iter().any(|a| act.contains(a)))
        .unwrap_or(false)
}

fn empty_result(ksi_id: &'static str, desc: &'static str) -> KsiValidationResult {
    KsiValidationBuilder::new(ksi_id, desc, Relevance::Direct).build()
}
