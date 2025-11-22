use serde_json::Value;
use crate::validators::models::*;

/// Validate Intune Compliance Policies against FedRAMP 20x KSIs
/// Graph API: GET /deviceManagement/deviceCompliancePolicies
pub fn validate_compliance_policies(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let policies = extract_array(data);
    let records = policies.len();
    if records == 0 {
        return (vec![empty_result("KSI-SVC-04", "Manage configuration of machine-based information resources using automation.")], 0);
    }

    let mut results = Vec::new();

    // Analyze policies
    let enabled_policies: Vec<_> = policies.iter().filter(|p| !is_disabled(p)).collect();
    let encryption_required: Vec<_> = policies.iter().filter(|p| requires_encryption(p)).collect();
    let password_required: Vec<_> = policies.iter().filter(|p| requires_password(p)).collect();
    let firewall_required: Vec<_> = policies.iter().filter(|p| requires_firewall(p)).collect();
    let antivirus_required: Vec<_> = policies.iter().filter(|p| requires_antivirus(p)).collect();
    let os_version_required: Vec<_> = policies.iter().filter(|p| requires_min_os(p)).collect();

    // KSI-SVC-04: Automated configuration management
    let mut builder = KsiValidationBuilder::new(
        "KSI-SVC-04", "Manage configuration of machine-based information resources using automation.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("compliance_policies_exist", "Intune compliance policies automate device configuration enforcement")
        .with_values(format!("{} policies", enabled_policies.len()), "Policies defined"));
    builder = builder.add_check(if !encryption_required.is_empty() {
        ValidationCheck::passed("encryption_enforced", "Device encryption is enforced via policy")
    } else {
        ValidationCheck::failed("encryption_enforced", "No compliance policy enforces device encryption", Severity::High)
    });
    results.push(builder.build());

    // KSI-SVC-03: Encrypt at rest
    let mut builder = KsiValidationBuilder::new(
        "KSI-SVC-03", "Encrypt information at rest by default.", Relevance::Direct,
    );
    builder = builder.add_check(if !encryption_required.is_empty() {
        ValidationCheck::passed("storage_encryption", "Storage encryption is required by compliance policy")
            .with_values(format!("{} policies require encryption", encryption_required.len()), "Encryption required")
    } else {
        ValidationCheck::failed("storage_encryption", "No compliance policies require device encryption", Severity::Critical)
    });
    if encryption_required.is_empty() {
        builder = builder.add_recommendation("Enable 'Require encryption of data storage on device' in compliance policies");
    }
    results.push(builder.build());

    // KSI-CMT-02: Secure baseline configurations
    let mut builder = KsiValidationBuilder::new(
        "KSI-CMT-02", "Maintain secure baseline configurations for all information resources.", Relevance::Direct,
    );
    let security_controls = vec![
        (!password_required.is_empty(), "password"),
        (!encryption_required.is_empty(), "encryption"),
        (!firewall_required.is_empty(), "firewall"),
        (!antivirus_required.is_empty(), "antivirus"),
    ];
    let enabled_controls: Vec<_> = security_controls.iter().filter(|(enabled, _)| *enabled).collect();

    builder = builder.add_check(if enabled_controls.len() >= 3 {
        ValidationCheck::passed("baseline_controls", "Multiple security baseline controls are enforced")
            .with_values(format!("{}/4 controls", enabled_controls.len()), ">=3 controls")
    } else {
        ValidationCheck::failed("baseline_controls", "Insufficient security baseline controls in compliance policies", Severity::High)
            .with_values(format!("{}/4 controls", enabled_controls.len()), ">=3 controls")
    });

    for (enabled, name) in &security_controls {
        builder = builder.add_check(if *enabled {
            ValidationCheck::passed(&format!("{}_required", name), &format!("{} requirement is enforced", name))
        } else {
            ValidationCheck::failed(&format!("{}_required", name), &format!("{} is not required by any policy", name), Severity::Medium)
        });
    }
    results.push(builder.build());

    // KSI-MLA-03: Vulnerability response (OS updates)
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-03", "Rapidly detect and respond to vulnerabilities.", Relevance::Supporting,
    );
    builder = builder.add_check(if !os_version_required.is_empty() {
        ValidationCheck::passed("os_version_enforcement", "Minimum OS version is enforced - helps ensure patches applied")
    } else {
        ValidationCheck::failed("os_version_enforcement", "No minimum OS version requirement - devices may run outdated software", Severity::High)
    });
    results.push(builder.build());

    // KSI-CNA-04: Malicious code protection
    let mut builder = KsiValidationBuilder::new(
        "KSI-CNA-04", "Implement malicious code protection.", Relevance::Direct,
    );
    builder = builder.add_check(if !antivirus_required.is_empty() {
        ValidationCheck::passed("antivirus_required", "Antivirus/antimalware is required by compliance policy")
    } else {
        ValidationCheck::failed("antivirus_required", "No policy requires antivirus - devices may lack malware protection", Severity::Critical)
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

fn is_disabled(policy: &Value) -> bool {
    policy.get("state").and_then(|s| s.as_str()) == Some("disabled")
}

fn requires_encryption(policy: &Value) -> bool {
    bool_setting(policy, "storageRequireEncryption") ||
    bool_setting(policy, "bitLockerEnabled") ||
    bool_setting(policy, "encryptionRequired")
}

fn requires_password(policy: &Value) -> bool {
    bool_setting(policy, "passwordRequired") ||
    bool_setting(policy, "passwordRequiredToUnlockFromIdle")
}

fn requires_firewall(policy: &Value) -> bool {
    bool_setting(policy, "firewallEnabled") ||
    bool_setting(policy, "firewallRequired")
}

fn requires_antivirus(policy: &Value) -> bool {
    bool_setting(policy, "antivirusRequired") ||
    bool_setting(policy, "defenderEnabled") ||
    bool_setting(policy, "realTimeProtectionEnabled")
}

fn requires_min_os(policy: &Value) -> bool {
    policy.get("osMinimumVersion").and_then(|v| v.as_str()).is_some() ||
    policy.get("minOsVersion").and_then(|v| v.as_str()).is_some()
}

fn bool_setting(policy: &Value, key: &str) -> bool {
    policy.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn empty_result(ksi_id: &'static str, desc: &'static str) -> KsiValidationResult {
    KsiValidationBuilder::new(ksi_id, desc, Relevance::Direct).build()
}
