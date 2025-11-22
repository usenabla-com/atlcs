use serde_json::Value;
use crate::validators::models::*;

/// Validate Intune Device Configurations against FedRAMP 20x KSIs
/// Graph API: GET /deviceManagement/deviceConfigurations
pub fn validate_device_configurations(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let configs = extract_array(data);
    let records = configs.len();
    if records == 0 {
        return (vec![empty_result("KSI-SVC-01", "Continuously evaluate machine-based information resources for opportunities to improve security.")], 0);
    }

    let mut results = Vec::new();

    // Categorize configurations
    let security_configs: Vec<_> = configs.iter()
        .filter(|c| is_security_config(c))
        .collect();
    let endpoint_protection: Vec<_> = configs.iter()
        .filter(|c| config_type_contains(c, &["endpointProtection", "defender", "antivirus"]))
        .collect();
    let firewall_configs: Vec<_> = configs.iter()
        .filter(|c| config_type_contains(c, &["firewall", "network"]))
        .collect();
    let encryption_configs: Vec<_> = configs.iter()
        .filter(|c| config_type_contains(c, &["bitlocker", "encryption", "filevault"]))
        .collect();

    // Assigned configs (actually deployed)
    let assigned_configs: Vec<_> = configs.iter()
        .filter(|c| {
            c.get("assignments").and_then(|a| a.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false) ||
            c.get("deviceStatusOverview").is_some()
        })
        .collect();

    // KSI-SVC-01: Continuously evaluate security
    let mut builder = KsiValidationBuilder::new(
        "KSI-SVC-01", "Continuously evaluate machine-based information resources for opportunities to improve security.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("config_profiles", "Device configuration profiles are defined")
        .with_values(format!("{} profiles", records), "Profiles exist"));
    builder = builder.add_check(if !security_configs.is_empty() {
        ValidationCheck::passed("security_configs", "Security-focused configuration profiles exist")
            .with_values(format!("{} security profiles", security_configs.len()), "Security profiles")
    } else {
        ValidationCheck::failed("security_configs", "No security-focused configuration profiles found", Severity::High)
    });

    let assigned_pct = if records > 0 { assigned_configs.len() * 100 / records } else { 0 };
    builder = builder.add_check(if assigned_pct >= 80 {
        ValidationCheck::passed("configs_deployed", "Most configuration profiles are assigned/deployed")
            .with_values(format!("{}% deployed", assigned_pct), ">=80%")
    } else {
        ValidationCheck::failed("configs_deployed", "Many profiles not deployed - may be unused", Severity::Medium)
            .with_values(format!("{}% deployed", assigned_pct), ">=80%")
    });
    results.push(builder.build());

    // KSI-SVC-03: Encryption at rest
    let mut builder = KsiValidationBuilder::new(
        "KSI-SVC-03", "Encrypt information at rest by default.", Relevance::Direct,
    );
    builder = builder.add_check(if !encryption_configs.is_empty() {
        ValidationCheck::passed("encryption_profiles", "Encryption configuration profiles are deployed")
            .with_values(format!("{} encryption profiles", encryption_configs.len()), "Encryption configured")
    } else {
        ValidationCheck::failed("encryption_profiles", "No encryption configuration profiles found", Severity::High)
    });
    results.push(builder.build());

    // KSI-CNA-01: Limit traffic (firewall)
    let mut builder = KsiValidationBuilder::new(
        "KSI-CNA-01", "Configure ALL machine-based information resources to limit inbound and outbound traffic.", Relevance::Direct,
    );
    builder = builder.add_check(if !firewall_configs.is_empty() {
        ValidationCheck::passed("firewall_profiles", "Firewall configuration profiles are deployed")
            .with_values(format!("{} firewall profiles", firewall_configs.len()), "Firewall configured")
    } else {
        ValidationCheck::failed("firewall_profiles", "No firewall configuration profiles found", Severity::High)
    });
    if firewall_configs.is_empty() {
        builder = builder.add_recommendation("Create Intune profiles to configure Windows Firewall or macOS firewall");
    }
    results.push(builder.build());

    // KSI-CNA-04: Malicious code protection
    let mut builder = KsiValidationBuilder::new(
        "KSI-CNA-04", "Implement malicious code protection.", Relevance::Direct,
    );
    builder = builder.add_check(if !endpoint_protection.is_empty() {
        ValidationCheck::passed("endpoint_protection", "Endpoint protection profiles are deployed (Defender, AV)")
            .with_values(format!("{} protection profiles", endpoint_protection.len()), "Endpoint protection")
    } else {
        ValidationCheck::failed("endpoint_protection", "No endpoint protection configuration profiles", Severity::Critical)
    });
    results.push(builder.build());

    // KSI-SVC-04: Automated configuration
    let mut builder = KsiValidationBuilder::new(
        "KSI-SVC-04", "Manage configuration of machine-based information resources using automation.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("automated_config", "Intune provides automated device configuration management")
        .with_values(format!("{} profiles deployed", assigned_configs.len()), "Automation active"));
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

fn is_security_config(config: &Value) -> bool {
    let name = config.get("displayName").and_then(|n| n.as_str()).unwrap_or("").to_lowercase();
    let odata_type = config.get("@odata.type").and_then(|t| t.as_str()).unwrap_or("").to_lowercase();

    name.contains("security") || name.contains("protection") || name.contains("firewall") ||
    name.contains("defender") || name.contains("encryption") || name.contains("bitlocker") ||
    odata_type.contains("endpointprotection") || odata_type.contains("defender")
}

fn config_type_contains(config: &Value, keywords: &[&str]) -> bool {
    let name = config.get("displayName").and_then(|n| n.as_str()).unwrap_or("").to_lowercase();
    let odata_type = config.get("@odata.type").and_then(|t| t.as_str()).unwrap_or("").to_lowercase();

    keywords.iter().any(|k| name.contains(k) || odata_type.contains(k))
}

fn empty_result(ksi_id: &'static str, desc: &'static str) -> KsiValidationResult {
    KsiValidationBuilder::new(ksi_id, desc, Relevance::Direct).build()
}
