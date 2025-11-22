use serde_json::Value;
use crate::validators::models::*;

/// Validate User MFA Status against FedRAMP 20x KSIs
///
/// Graph API: GET /reports/authenticationMethods/userRegistrationDetails
///
/// Relevant KSIs:
/// - KSI-IAM-01: Uniquely identify and authenticate all users
/// - KSI-IAM-02: Enforce strong authentication including MFA
pub fn validate_user_mfa_status(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let users = match data {
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

    let records = users.len();
    if records == 0 {
        return (vec![
            KsiValidationBuilder::new(
                "KSI-IAM-02",
                "Enforce strong authentication including MFA.",
                Relevance::Direct,
            )
            .build(),
        ], 0);
    }

    let mut results = Vec::new();

    // Analyze MFA status
    let mfa_registered: Vec<_> = users.iter()
        .filter(|u| u.get("isMfaRegistered").and_then(|m| m.as_bool()).unwrap_or(false))
        .collect();

    let mfa_capable: Vec<_> = users.iter()
        .filter(|u| u.get("isMfaCapable").and_then(|m| m.as_bool()).unwrap_or(false))
        .collect();

    let passwordless_capable: Vec<_> = users.iter()
        .filter(|u| u.get("isPasswordlessCapable").and_then(|m| m.as_bool()).unwrap_or(false))
        .collect();

    let sspr_registered: Vec<_> = users.iter()
        .filter(|u| u.get("isSsprRegistered").and_then(|m| m.as_bool()).unwrap_or(false))
        .collect();

    // Analyze authentication methods
    let mut method_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for user in &users {
        if let Some(methods) = user.get("methodsRegistered").and_then(|m| m.as_array()) {
            for method in methods {
                if let Some(m) = method.as_str() {
                    *method_counts.entry(m.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    // Check for weak methods only
    let users_with_only_sms: Vec<_> = users.iter()
        .filter(|u| {
            let methods = u.get("methodsRegistered")
                .and_then(|m| m.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            methods.len() == 1 && methods.contains(&"mobilePhone")
        })
        .collect();

    // Admin users without strong MFA
    let admin_users: Vec<_> = users.iter()
        .filter(|u| {
            u.get("userType").and_then(|t| t.as_str()) == Some("Admin") ||
            u.get("isAdmin").and_then(|a| a.as_bool()).unwrap_or(false)
        })
        .collect();

    let admins_without_strong_mfa: Vec<_> = admin_users.iter()
        .filter(|u| {
            let methods = u.get("methodsRegistered")
                .and_then(|m| m.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();
            !methods.iter().any(|m| {
                *m == "microsoftAuthenticatorPush" ||
                *m == "windowsHelloForBusiness" ||
                *m == "fido2"
            })
        })
        .collect();

    // KSI-IAM-01: Uniquely identify and authenticate all users
    results.push(validate_ksi_iam_01(&users));

    // KSI-IAM-02: Enforce strong authentication including MFA
    results.push(validate_ksi_iam_02(
        &users,
        &mfa_registered,
        &mfa_capable,
        &passwordless_capable,
        &users_with_only_sms,
        &admin_users,
        &admins_without_strong_mfa,
        &method_counts,
    ));

    (results, records)
}

fn validate_ksi_iam_01(users: &[Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-01",
        "Uniquely identify and authenticate all users.",
        Relevance::Supporting,
    );

    // Check all users have unique identifiers
    let users_with_upn = users.iter()
        .filter(|u| u.get("userPrincipalName").and_then(|n| n.as_str()).is_some())
        .count();

    let check = if users_with_upn == users.len() {
        ValidationCheck::passed(
            "unique_identifiers",
            "All users have unique principal names (UPNs)",
        )
        .with_values(format!("{}/{} users", users_with_upn, users.len()), "100%")
    } else {
        ValidationCheck::failed(
            "unique_identifiers",
            "Some users missing unique principal names",
            Severity::High,
        )
        .with_values(
            format!("{}/{} users have UPN", users_with_upn, users.len()),
            "100%",
        )
    };
    builder = builder.add_check(check);

    builder.build()
}

fn validate_ksi_iam_02(
    users: &[Value],
    mfa_registered: &[&Value],
    mfa_capable: &[&Value],
    passwordless_capable: &[&Value],
    users_with_only_sms: &[&Value],
    admin_users: &[&Value],
    admins_without_strong_mfa: &[&&Value],
    method_counts: &std::collections::HashMap<String, usize>,
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-02",
        "Enforce strong authentication including MFA.",
        Relevance::Direct,
    );

    let total = users.len();
    let mfa_pct = if total > 0 { mfa_registered.len() * 100 / total } else { 0 };

    // Check 1: MFA registration rate
    let check = if mfa_pct >= 95 {
        ValidationCheck::passed(
            "mfa_registration_rate",
            "95%+ of users have MFA registered",
        )
        .with_values(format!("{}%", mfa_pct), ">=95%")
    } else if mfa_pct >= 80 {
        ValidationCheck::failed(
            "mfa_registration_rate",
            "MFA registration rate is below 95%",
            Severity::High,
        )
        .with_values(format!("{}%", mfa_pct), ">=95%")
    } else {
        ValidationCheck::failed(
            "mfa_registration_rate",
            "MFA registration rate is critically low",
            Severity::Critical,
        )
        .with_values(format!("{}%", mfa_pct), ">=95%")
    };
    builder = builder.add_check(check);

    // Check 2: MFA capability
    let capable_pct = if total > 0 { mfa_capable.len() * 100 / total } else { 0 };
    let check = if capable_pct >= 95 {
        ValidationCheck::passed(
            "mfa_capability",
            "95%+ of users are MFA capable",
        )
        .with_values(format!("{}%", capable_pct), ">=95%")
    } else {
        ValidationCheck::failed(
            "mfa_capability",
            "Some users are not MFA capable",
            Severity::High,
        )
        .with_values(format!("{}%", capable_pct), ">=95%")
    };
    builder = builder.add_check(check);

    // Check 3: Strong authentication methods (not just SMS)
    let sms_only_pct = if total > 0 { users_with_only_sms.len() * 100 / total } else { 0 };
    let check = if sms_only_pct <= 10 {
        ValidationCheck::passed(
            "strong_mfa_methods",
            "Most users have strong MFA methods (not SMS-only)",
        )
        .with_values(format!("{}% SMS-only", sms_only_pct), "<=10% SMS-only")
    } else {
        ValidationCheck::failed(
            "strong_mfa_methods",
            "Too many users rely on SMS-only for MFA (weaker security)",
            Severity::Medium,
        )
        .with_values(format!("{}% SMS-only", sms_only_pct), "<=10% SMS-only")
    };
    builder = builder.add_check(check);

    // Check 4: Admin MFA with strong methods
    if !admin_users.is_empty() {
        let check = if admins_without_strong_mfa.is_empty() {
            ValidationCheck::passed(
                "admin_strong_mfa",
                "All admin users have strong MFA methods (Authenticator, FIDO2, or Windows Hello)",
            )
        } else {
            ValidationCheck::failed(
                "admin_strong_mfa",
                "Some admin users lack strong MFA methods",
                Severity::Critical,
            )
            .with_values(
                format!("{} admins without strong MFA", admins_without_strong_mfa.len()),
                "0 admins without strong MFA",
            )
        };
        builder = builder.add_check(check);
    }

    // Check 5: Passwordless adoption
    let passwordless_pct = if total > 0 { passwordless_capable.len() * 100 / total } else { 0 };
    let check = if passwordless_pct >= 20 {
        ValidationCheck::passed(
            "passwordless_adoption",
            "Good passwordless authentication adoption",
        )
        .with_values(format!("{}%", passwordless_pct), ">=20%")
    } else {
        ValidationCheck::failed(
            "passwordless_adoption",
            "Low passwordless adoption - consider promoting FIDO2/Windows Hello",
            Severity::Low,
        )
        .with_values(format!("{}%", passwordless_pct), ">=20%")
    };
    builder = builder.add_check(check);

    // Check 6: Method diversity
    let has_strong_methods = method_counts.get("microsoftAuthenticatorPush").unwrap_or(&0) > &0 ||
        method_counts.get("fido2").unwrap_or(&0) > &0 ||
        method_counts.get("windowsHelloForBusiness").unwrap_or(&0) > &0;
    let check = if has_strong_methods {
        ValidationCheck::passed(
            "strong_methods_available",
            "Strong authentication methods are in use (Authenticator, FIDO2, or Windows Hello)",
        )
    } else {
        ValidationCheck::failed(
            "strong_methods_available",
            "No users with strong authentication methods - only weak methods in use",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Recommendations
    if mfa_pct < 95 {
        builder = builder.add_recommendation(format!(
            "Enroll remaining {} users in MFA",
            total - mfa_registered.len()
        ));
    }
    if !users_with_only_sms.is_empty() {
        builder = builder.add_recommendation(format!(
            "Migrate {} users from SMS-only MFA to Microsoft Authenticator or FIDO2",
            users_with_only_sms.len()
        ));
    }
    if !admins_without_strong_mfa.is_empty() {
        builder = builder.add_recommendation(
            "Require all administrators to use Microsoft Authenticator, FIDO2, or Windows Hello",
        );
    }

    builder.build()
}
