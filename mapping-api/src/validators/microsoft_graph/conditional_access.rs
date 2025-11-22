use serde_json::Value;
use crate::validators::models::*;

/// Validate Conditional Access Policies against FedRAMP 20x KSIs
///
/// Graph API: GET /identity/conditionalAccess/policies
///
/// Relevant KSIs:
/// - KSI-IAM-01: Uniquely identify and authenticate all users
/// - KSI-IAM-02: Enforce strong authentication including MFA
/// - KSI-IAM-03: Authenticate and authorize all devices and services
/// - KSI-IAM-04: Apply least privilege access controls
/// - KSI-IAM-05: Design IAM systems assuming compromise (zero trust)
/// - KSI-IAM-06: Disable inactive accounts and revoke access promptly
/// - KSI-CNA-01: Configure resources to limit inbound/outbound traffic
pub fn validate_conditional_access_policies(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let policies = match data {
        Value::Array(arr) => arr.clone(),
        Value::Object(obj) => {
            // Handle OData response format
            if let Some(Value::Array(arr)) = obj.get("value") {
                arr.clone()
            } else {
                vec![data.clone()]
            }
        }
        _ => return (vec![], 0),
    };

    let records = policies.len();
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

    // Analyze policies
    let enabled_policies: Vec<_> = policies.iter()
        .filter(|p| p.get("state").and_then(|s| s.as_str()) == Some("enabled"))
        .collect();

    let mfa_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_requires_mfa(p))
        .collect();

    let all_users_mfa_policies: Vec<_> = mfa_policies.iter()
        .filter(|p| policy_applies_to_all_users(p))
        .collect();

    let privileged_role_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_targets_privileged_roles(p))
        .collect();

    let device_compliance_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_requires_compliant_device(p))
        .collect();

    let location_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_has_location_conditions(p))
        .collect();

    let session_control_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_has_session_controls(p))
        .collect();

    let sign_in_risk_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_uses_sign_in_risk(p))
        .collect();

    let user_risk_policies: Vec<_> = enabled_policies.iter()
        .filter(|p| policy_uses_user_risk(p))
        .collect();

    // KSI-IAM-01: Uniquely identify and authenticate all users
    results.push(validate_ksi_iam_01(&enabled_policies));

    // KSI-IAM-02: Enforce strong authentication including MFA
    results.push(validate_ksi_iam_02(
        &enabled_policies,
        &mfa_policies,
        &all_users_mfa_policies,
    ));

    // KSI-IAM-03: Authenticate and authorize all devices and services
    results.push(validate_ksi_iam_03(
        &enabled_policies,
        &device_compliance_policies,
    ));

    // KSI-IAM-04: Apply least privilege access controls
    results.push(validate_ksi_iam_04(
        &enabled_policies,
        &privileged_role_policies,
    ));

    // KSI-IAM-05: Zero trust / assume compromise
    results.push(validate_ksi_iam_05(
        &enabled_policies,
        &session_control_policies,
        &sign_in_risk_policies,
        &user_risk_policies,
        &location_policies,
    ));

    // KSI-IAM-06: Disable inactive accounts
    results.push(validate_ksi_iam_06(&enabled_policies));

    // KSI-CNA-01: Limit inbound/outbound traffic
    results.push(validate_ksi_cna_01(&location_policies));

    (results, records)
}

fn validate_ksi_iam_01(enabled_policies: &[&Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-01",
        "Uniquely identify and authenticate all users.",
        Relevance::Supporting,
    );

    // Check if there are any enabled policies at all
    let check = if !enabled_policies.is_empty() {
        ValidationCheck::passed(
            "enabled_policies_exist",
            "Conditional Access policies are enabled and enforcing authentication requirements",
        )
        .with_values(
            format!("{} policies enabled", enabled_policies.len()),
            "At least 1 policy",
        )
    } else {
        ValidationCheck::failed(
            "enabled_policies_exist",
            "No enabled Conditional Access policies found",
            Severity::High,
        )
        .with_values("0 policies", "At least 1 policy")
    };
    builder = builder.add_check(check);

    // Check for policies that block legacy authentication
    let legacy_auth_blocked = enabled_policies.iter().any(|p| policy_blocks_legacy_auth(p));
    let check = if legacy_auth_blocked {
        ValidationCheck::passed(
            "legacy_auth_blocked",
            "Legacy authentication protocols are blocked",
        )
    } else {
        ValidationCheck::failed(
            "legacy_auth_blocked",
            "No policy found blocking legacy authentication (Basic Auth, IMAP, POP3, etc.)",
            Severity::High,
        )
        .with_values("Not blocked", "Legacy auth should be blocked")
    };
    builder = builder.add_check(check);

    if !legacy_auth_blocked {
        builder = builder.add_recommendation(
            "Create a Conditional Access policy to block legacy authentication protocols",
        );
    }

    builder.build()
}

fn validate_ksi_iam_02(
    enabled_policies: &[&Value],
    mfa_policies: &[&&Value],
    all_users_mfa_policies: &[&&&Value],
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-02",
        "Enforce strong authentication including MFA.",
        Relevance::Direct,
    );

    // Check 1: MFA policies exist
    let check = if !mfa_policies.is_empty() {
        ValidationCheck::passed(
            "mfa_policies_exist",
            "Policies requiring MFA are configured",
        )
        .with_values(
            format!("{} MFA policies", mfa_policies.len()),
            "At least 1 MFA policy",
        )
    } else {
        ValidationCheck::failed(
            "mfa_policies_exist",
            "No Conditional Access policies requiring MFA found",
            Severity::Critical,
        )
        .with_values("0 MFA policies", "At least 1 MFA policy")
    };
    builder = builder.add_check(check);

    // Check 2: MFA for all users
    let check = if !all_users_mfa_policies.is_empty() {
        ValidationCheck::passed(
            "mfa_all_users",
            "MFA is required for all users",
        )
    } else {
        ValidationCheck::failed(
            "mfa_all_users",
            "No policy requires MFA for all users - MFA may only apply to specific groups",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check 3: MFA for admin portals
    let admin_portal_mfa = enabled_policies.iter().any(|p| {
        policy_requires_mfa(p) && policy_targets_admin_portals(p)
    });
    let check = if admin_portal_mfa {
        ValidationCheck::passed(
            "mfa_admin_portals",
            "MFA is required for administrative portals (Azure Portal, M365 Admin, etc.)",
        )
    } else {
        ValidationCheck::failed(
            "mfa_admin_portals",
            "No specific MFA requirement for administrative portals",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check 4: MFA for privileged roles
    let privileged_mfa = enabled_policies.iter().any(|p| {
        policy_requires_mfa(p) && policy_targets_privileged_roles(p)
    });
    let check = if privileged_mfa {
        ValidationCheck::passed(
            "mfa_privileged_roles",
            "MFA is required for privileged directory roles",
        )
    } else {
        ValidationCheck::failed(
            "mfa_privileged_roles",
            "No specific MFA requirement for privileged roles (Global Admin, etc.)",
            Severity::Critical,
        )
    };
    builder = builder.add_check(check);

    // Recommendations
    if mfa_policies.is_empty() {
        builder = builder.add_recommendation(
            "Create Conditional Access policies requiring MFA for all users and applications",
        );
    }
    if all_users_mfa_policies.is_empty() {
        builder = builder.add_recommendation(
            "Ensure MFA policy applies to 'All users' rather than specific groups only",
        );
    }
    if !privileged_mfa {
        builder = builder.add_recommendation(
            "Create a policy requiring MFA specifically for privileged directory roles",
        );
    }

    builder.build()
}

fn validate_ksi_iam_03(
    enabled_policies: &[&Value],
    device_compliance_policies: &[&&Value],
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-03",
        "Authenticate and authorize all devices and services.",
        Relevance::Direct,
    );

    // Check 1: Device compliance policies exist
    let check = if !device_compliance_policies.is_empty() {
        ValidationCheck::passed(
            "device_compliance_required",
            "Policies requiring compliant or hybrid Azure AD joined devices exist",
        )
        .with_values(
            format!("{} device policies", device_compliance_policies.len()),
            "At least 1 device compliance policy",
        )
    } else {
        ValidationCheck::failed(
            "device_compliance_required",
            "No policies requiring device compliance or hybrid Azure AD join",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check 2: Device state conditions used
    let device_state_used = enabled_policies.iter().any(|p| {
        p.get("conditions")
            .and_then(|c| c.get("devices"))
            .is_some()
    });
    let check = if device_state_used {
        ValidationCheck::passed(
            "device_conditions_used",
            "Device state conditions are used in access policies",
        )
    } else {
        ValidationCheck::failed(
            "device_conditions_used",
            "No policies use device state conditions",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    // Check 3: Unmanaged device restrictions
    let unmanaged_restricted = enabled_policies.iter().any(|p| {
        p.get("sessionControls")
            .and_then(|s| s.get("applicationEnforcedRestrictions"))
            .and_then(|a| a.get("isEnabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    });
    let check = if unmanaged_restricted {
        ValidationCheck::passed(
            "unmanaged_device_restrictions",
            "Application-enforced restrictions for unmanaged devices are configured",
        )
    } else {
        ValidationCheck::failed(
            "unmanaged_device_restrictions",
            "No application-enforced restrictions for unmanaged devices",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    if device_compliance_policies.is_empty() {
        builder = builder.add_recommendation(
            "Create policies requiring devices to be compliant or Hybrid Azure AD joined",
        );
    }

    builder.build()
}

fn validate_ksi_iam_04(
    enabled_policies: &[&Value],
    privileged_role_policies: &[&&Value],
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-04",
        "Apply least privilege access controls.",
        Relevance::Supporting,
    );

    // Check 1: Privileged role policies exist
    let check = if !privileged_role_policies.is_empty() {
        ValidationCheck::passed(
            "privileged_role_controls",
            "Specific access controls for privileged roles are configured",
        )
    } else {
        ValidationCheck::failed(
            "privileged_role_controls",
            "No specific Conditional Access policies for privileged directory roles",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check 2: Group-based access controls
    let group_based = enabled_policies.iter().any(|p| {
        p.get("conditions")
            .and_then(|c| c.get("users"))
            .and_then(|u| u.get("includeGroups"))
            .and_then(|g| g.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false)
    });
    let check = if group_based {
        ValidationCheck::passed(
            "group_based_access",
            "Policies use group-based access controls",
        )
    } else {
        ValidationCheck::failed(
            "group_based_access",
            "No policies target specific groups - consider using groups for least privilege",
            Severity::Low,
        )
    };
    builder = builder.add_check(check);

    // Check 3: Application-specific policies
    let app_specific = enabled_policies.iter().any(|p| {
        let apps = p.get("conditions")
            .and_then(|c| c.get("applications"))
            .and_then(|a| a.get("includeApplications"))
            .and_then(|i| i.as_array());
        if let Some(apps) = apps {
            apps.iter().any(|a| a.as_str() != Some("All"))
        } else {
            false
        }
    });
    let check = if app_specific {
        ValidationCheck::passed(
            "app_specific_policies",
            "Application-specific access policies exist",
        )
    } else {
        ValidationCheck::failed(
            "app_specific_policies",
            "All policies apply to 'All applications' - consider app-specific controls",
            Severity::Low,
        )
    };
    builder = builder.add_check(check);

    if privileged_role_policies.is_empty() {
        builder = builder.add_recommendation(
            "Create stricter Conditional Access policies specifically for privileged directory roles",
        );
    }

    builder.build()
}

fn validate_ksi_iam_05(
    enabled_policies: &[&Value],
    session_control_policies: &[&&Value],
    sign_in_risk_policies: &[&&Value],
    user_risk_policies: &[&&Value],
    location_policies: &[&&Value],
) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-05",
        "Design identity and access management systems that assume resources will be compromised.",
        Relevance::Direct,
    );

    // Check 1: Sign-in risk policies (Identity Protection)
    let check = if !sign_in_risk_policies.is_empty() {
        ValidationCheck::passed(
            "sign_in_risk_policies",
            "Sign-in risk-based policies are configured (Zero Trust)",
        )
        .with_values(
            format!("{} risk policies", sign_in_risk_policies.len()),
            "At least 1",
        )
    } else {
        ValidationCheck::failed(
            "sign_in_risk_policies",
            "No sign-in risk-based Conditional Access policies found",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check 2: User risk policies
    let check = if !user_risk_policies.is_empty() {
        ValidationCheck::passed(
            "user_risk_policies",
            "User risk-based policies are configured",
        )
    } else {
        ValidationCheck::failed(
            "user_risk_policies",
            "No user risk-based policies - consider requiring password change for risky users",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    // Check 3: Session controls (token lifetime, persistent browser)
    let check = if !session_control_policies.is_empty() {
        ValidationCheck::passed(
            "session_controls",
            "Session controls are configured (sign-in frequency, persistent browser)",
        )
    } else {
        ValidationCheck::failed(
            "session_controls",
            "No session control policies - sessions may persist indefinitely",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    // Check 4: Location-based controls (named locations, trusted IPs)
    let check = if !location_policies.is_empty() {
        ValidationCheck::passed(
            "location_based_controls",
            "Location-based access controls are configured",
        )
    } else {
        ValidationCheck::failed(
            "location_based_controls",
            "No location-based access controls - access allowed from any location",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    // Check 5: Block high-risk sign-ins
    let blocks_high_risk = enabled_policies.iter().any(|p| {
        let has_high_risk = p.get("conditions")
            .and_then(|c| c.get("signInRiskLevels"))
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().any(|l| l.as_str() == Some("high")))
            .unwrap_or(false);
        let blocks = p.get("grantControls")
            .and_then(|g| g.get("builtInControls"))
            .and_then(|b| b.as_array())
            .map(|arr| arr.iter().any(|c| c.as_str() == Some("block")))
            .unwrap_or(false);
        has_high_risk && blocks
    });
    let check = if blocks_high_risk {
        ValidationCheck::passed(
            "block_high_risk",
            "High-risk sign-ins are blocked",
        )
    } else {
        ValidationCheck::failed(
            "block_high_risk",
            "No policy explicitly blocks high-risk sign-ins",
            Severity::High,
        )
    };
    builder = builder.add_check(check);

    if sign_in_risk_policies.is_empty() {
        builder = builder.add_recommendation(
            "Enable Azure AD Identity Protection and create risk-based Conditional Access policies",
        );
    }
    if session_control_policies.is_empty() {
        builder = builder.add_recommendation(
            "Configure session controls to limit token lifetime and require re-authentication",
        );
    }

    builder.build()
}

fn validate_ksi_iam_06(enabled_policies: &[&Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-IAM-06",
        "Disable inactive accounts and revoke access promptly.",
        Relevance::Indirect,
    );

    // Conditional Access can support this through session controls
    let has_sign_in_frequency = enabled_policies.iter().any(|p| {
        p.get("sessionControls")
            .and_then(|s| s.get("signInFrequency"))
            .and_then(|f| f.get("isEnabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    });

    let check = if has_sign_in_frequency {
        ValidationCheck::passed(
            "sign_in_frequency",
            "Sign-in frequency controls help ensure inactive sessions are terminated",
        )
    } else {
        ValidationCheck::failed(
            "sign_in_frequency",
            "No sign-in frequency controls - users may remain signed in indefinitely",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    builder = builder.add_recommendation(
        "Note: Full KSI-IAM-06 compliance requires Azure AD user lifecycle management, not just Conditional Access",
    );

    builder.build()
}

fn validate_ksi_cna_01(location_policies: &[&&Value]) -> KsiValidationResult {
    let mut builder = KsiValidationBuilder::new(
        "KSI-CNA-01",
        "Configure ALL machine-based information resources to limit inbound and outbound traffic.",
        Relevance::Supporting,
    );

    let check = if !location_policies.is_empty() {
        ValidationCheck::passed(
            "location_restrictions",
            "Location-based access restrictions help limit access by network location",
        )
        .with_values(
            format!("{} location policies", location_policies.len()),
            "At least 1",
        )
    } else {
        ValidationCheck::failed(
            "location_restrictions",
            "No location-based restrictions - access allowed from any IP/location",
            Severity::Medium,
        )
    };
    builder = builder.add_check(check);

    builder = builder.add_recommendation(
        "Note: Full KSI-CNA-01 compliance requires network security groups, firewalls, etc.",
    );

    builder.build()
}

// Helper functions to analyze policy properties

fn policy_requires_mfa(policy: &Value) -> bool {
    policy
        .get("grantControls")
        .and_then(|g| g.get("builtInControls"))
        .and_then(|b| b.as_array())
        .map(|arr| arr.iter().any(|c| c.as_str() == Some("mfa")))
        .unwrap_or(false)
}

fn policy_applies_to_all_users(policy: &Value) -> bool {
    policy
        .get("conditions")
        .and_then(|c| c.get("users"))
        .and_then(|u| u.get("includeUsers"))
        .and_then(|i| i.as_array())
        .map(|arr| arr.iter().any(|u| u.as_str() == Some("All")))
        .unwrap_or(false)
}

fn policy_targets_privileged_roles(policy: &Value) -> bool {
    policy
        .get("conditions")
        .and_then(|c| c.get("users"))
        .and_then(|u| u.get("includeRoles"))
        .and_then(|r| r.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

fn policy_targets_admin_portals(policy: &Value) -> bool {
    let admin_app_ids = [
        "797f4846-ba00-4fd7-ba43-dac1f8f63013", // Azure Management
        "00000006-0000-0ff1-ce00-000000000000", // Microsoft 365 Admin Center
        "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", // Azure Portal
    ];

    policy
        .get("conditions")
        .and_then(|c| c.get("applications"))
        .and_then(|a| a.get("includeApplications"))
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter().any(|app| {
                app.as_str()
                    .map(|s| admin_app_ids.contains(&s) || s == "All")
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

fn policy_requires_compliant_device(policy: &Value) -> bool {
    policy
        .get("grantControls")
        .and_then(|g| g.get("builtInControls"))
        .and_then(|b| b.as_array())
        .map(|arr| {
            arr.iter().any(|c| {
                let s = c.as_str().unwrap_or("");
                s == "compliantDevice" || s == "domainJoinedDevice"
            })
        })
        .unwrap_or(false)
}

fn policy_has_location_conditions(policy: &Value) -> bool {
    policy
        .get("conditions")
        .and_then(|c| c.get("locations"))
        .map(|l| !l.is_null())
        .unwrap_or(false)
}

fn policy_has_session_controls(policy: &Value) -> bool {
    let session = policy.get("sessionControls");
    if let Some(s) = session {
        let sign_in_freq = s.get("signInFrequency")
            .and_then(|f| f.get("isEnabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);
        let persistent = s.get("persistentBrowser")
            .and_then(|p| p.get("isEnabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);
        sign_in_freq || persistent
    } else {
        false
    }
}

fn policy_uses_sign_in_risk(policy: &Value) -> bool {
    policy
        .get("conditions")
        .and_then(|c| c.get("signInRiskLevels"))
        .and_then(|r| r.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

fn policy_uses_user_risk(policy: &Value) -> bool {
    policy
        .get("conditions")
        .and_then(|c| c.get("userRiskLevels"))
        .and_then(|r| r.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

fn policy_blocks_legacy_auth(policy: &Value) -> bool {
    let targets_legacy = policy
        .get("conditions")
        .and_then(|c| c.get("clientAppTypes"))
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter().any(|t| {
                let s = t.as_str().unwrap_or("");
                s == "exchangeActiveSync" || s == "other"
            })
        })
        .unwrap_or(false);

    let blocks = policy
        .get("grantControls")
        .and_then(|g| g.get("builtInControls"))
        .and_then(|b| b.as_array())
        .map(|arr| arr.iter().any(|c| c.as_str() == Some("block")))
        .unwrap_or(false);

    targets_legacy && blocks
}
