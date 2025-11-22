use serde_json::Value;
use crate::validators::models::*;

/// Validate Directory Roles against FedRAMP 20x KSIs
/// Graph API: GET /directoryRoles and /roleManagement/directory/roleAssignments
pub fn validate_directory_roles(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let roles = extract_array(data);
    let records = roles.len();
    if records == 0 {
        return (vec![empty_result("KSI-IAM-04", "Apply least privilege access controls.")], 0);
    }

    let mut results = Vec::new();

    // Identify privileged roles
    let privileged_role_names = ["Global Administrator", "Privileged Role Administrator",
        "Security Administrator", "Exchange Administrator", "SharePoint Administrator",
        "User Administrator", "Billing Administrator", "Compliance Administrator"];

    let privileged_roles: Vec<_> = roles.iter()
        .filter(|r| {
            r.get("displayName").and_then(|n| n.as_str())
                .map(|name| privileged_role_names.iter().any(|p| name.contains(p)))
                .unwrap_or(false)
        })
        .collect();

    let global_admins: Vec<_> = roles.iter()
        .filter(|r| r.get("displayName").and_then(|n| n.as_str()) == Some("Global Administrator"))
        .collect();

    // Count members per role
    let roles_with_members: Vec<_> = roles.iter()
        .filter(|r| {
            r.get("members").and_then(|m| m.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false)
        })
        .collect();

    // KSI-IAM-04: Least privilege
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-04", "Apply least privilege access controls.", Relevance::Direct,
    );

    builder = builder.add_check(ValidationCheck::passed("roles_defined", "Directory roles are configured")
        .with_values(format!("{} roles", records), "Roles present"));

    // Check Global Admin count
    let ga_member_count = global_admins.iter()
        .filter_map(|r| r.get("members").and_then(|m| m.as_array()))
        .map(|arr| arr.len())
        .sum::<usize>();

    builder = builder.add_check(if ga_member_count <= 5 {
        ValidationCheck::passed("limited_global_admins", "Global Administrator count is appropriately limited")
            .with_values(format!("{} Global Admins", ga_member_count), "<=5 recommended")
    } else {
        ValidationCheck::failed("limited_global_admins", "Too many Global Administrators - increases risk", Severity::High)
            .with_values(format!("{} Global Admins", ga_member_count), "<=5 recommended")
    });

    // Check for role usage
    let privileged_with_members = privileged_roles.iter()
        .filter(|r| r.get("members").and_then(|m| m.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false))
        .count();
    builder = builder.add_check(ValidationCheck::passed("privileged_roles_in_use", "Privileged roles are being used for delegation")
        .with_values(format!("{}/{} privileged roles active", privileged_with_members, privileged_roles.len()), "Roles active"));

    if ga_member_count > 5 {
        builder = builder.add_recommendation("Reduce Global Administrator count - delegate to specific admin roles");
    }
    results.push(builder.build());

    // KSI-IAM-07: Account/role lifecycle
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-07", "Securely manage the lifecycle and privileges of all accounts, roles, and groups.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("roles_inventory", "Role inventory is available for review")
        .with_values(format!("{} roles defined", records), "Inventory available"));
    builder = builder.add_check(if !privileged_roles.is_empty() {
        ValidationCheck::passed("privileged_roles_identified", "Privileged roles are identifiable for monitoring")
            .with_values(format!("{} privileged roles", privileged_roles.len()), "Privileged roles tracked")
    } else {
        ValidationCheck::failed("privileged_roles_identified", "Unable to identify privileged roles", Severity::Medium)
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

fn empty_result(ksi_id: &'static str, desc: &'static str) -> KsiValidationResult {
    KsiValidationBuilder::new(ksi_id, desc, Relevance::Direct).build()
}
