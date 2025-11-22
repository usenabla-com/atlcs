use serde_json::Value;
use crate::validators::models::*;

/// Validate Secure Score against FedRAMP 20x KSIs
/// Graph API: GET /security/secureScores
///
/// Schema reference: https://learn.microsoft.com/en-us/graph/api/resources/securescore
/// - secureScore: currentScore, maxScore, controlScores[]
/// - controlScore: controlName, controlCategory, description, score (NO maxScore per control)
pub fn validate_secure_score(data: &Value) -> (Vec<KsiValidationResult>, usize) {
    let scores = extract_array(data);
    let records = scores.len();
    if records == 0 {
        return (vec![empty_result("KSI-SVC-01", "Continuously evaluate machine-based information resources for opportunities to improve security.")], 0);
    }

    // Get the most recent score (first in array)
    let current_score = scores.first().unwrap();
    let mut results = Vec::new();

    // Extract top-level score data (these exist at secureScore level)
    let current = current_score.get("currentScore").and_then(|s| s.as_f64()).unwrap_or(0.0);
    let max = current_score.get("maxScore").and_then(|s| s.as_f64()).unwrap_or(100.0);
    let pct = if max > 0.0 { (current / max * 100.0).round() } else { 0.0 };

    // Extract control scores (per Graph API: controlName, controlCategory, description, score)
    let control_scores = current_score.get("controlScores")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    // Categorize controls by controlCategory field
    let identity_controls: Vec<_> = control_scores.iter()
        .filter(|c| control_category(c) == "Identity")
        .collect();
    let device_controls: Vec<_> = control_scores.iter()
        .filter(|c| control_category(c) == "Device")
        .collect();
    let data_controls: Vec<_> = control_scores.iter()
        .filter(|c| control_category(c) == "Data")
        .collect();
    let apps_controls: Vec<_> = control_scores.iter()
        .filter(|c| control_category(c) == "Apps")
        .collect();

    // Calculate category scores using sum of control scores
    // Note: Graph API doesn't provide per-control maxScore, so we use total score as indicator
    let identity_total = calc_category_total(&identity_controls);
    let device_total = calc_category_total(&device_controls);
    let data_total = calc_category_total(&data_controls);
    let _apps_total = calc_category_total(&apps_controls);

    // Find zero-score controls (controls with no points earned)
    let zero_controls: Vec<_> = control_scores.iter()
        .filter(|c| {
            let score = c.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0);
            score == 0.0
        })
        .collect();

    // KSI-SVC-01: Continuously evaluate security
    let mut builder = KsiValidationBuilder::new(
        "KSI-SVC-01", "Continuously evaluate machine-based information resources for opportunities to improve security.", Relevance::Direct,
    );

    builder = builder.add_check(ValidationCheck::passed("secure_score_enabled", "Microsoft Secure Score is being tracked")
        .with_values(format!("{:.0}/{:.0} ({:.0}%)", current, max, pct), "Score tracked"));

    builder = builder.add_check(if pct >= 80.0 {
        ValidationCheck::passed("overall_score", "Overall Secure Score is excellent")
            .with_values(format!("{:.0}%", pct), ">=80%")
    } else if pct >= 60.0 {
        ValidationCheck::failed("overall_score", "Secure Score is good but has room for improvement", Severity::Medium)
            .with_values(format!("{:.0}%", pct), ">=80%")
    } else if pct >= 40.0 {
        ValidationCheck::failed("overall_score", "Secure Score is below recommended level", Severity::High)
            .with_values(format!("{:.0}%", pct), ">=80%")
    } else {
        ValidationCheck::failed("overall_score", "Secure Score is critically low", Severity::Critical)
            .with_values(format!("{:.0}%", pct), ">=80%")
    });

    // Category breakdown - using control count and total score as indicators
    if !identity_controls.is_empty() {
        let identity_control_count = identity_controls.len();
        let has_good_identity = identity_total > 0.0 && identity_control_count >= 2;
        builder = builder.add_check(if has_good_identity {
            ValidationCheck::passed("identity_controls", "Identity security controls are contributing to score")
                .with_values(format!("{} controls, {:.0} pts", identity_control_count, identity_total), "Controls active")
        } else {
            ValidationCheck::failed("identity_controls", "Identity security controls need attention", Severity::High)
                .with_values(format!("{} controls, {:.0} pts", identity_control_count, identity_total), "Controls active")
        });
    }

    if !device_controls.is_empty() {
        let device_control_count = device_controls.len();
        let has_good_device = device_total > 0.0 && device_control_count >= 2;
        builder = builder.add_check(if has_good_device {
            ValidationCheck::passed("device_controls", "Device security controls are contributing to score")
                .with_values(format!("{} controls, {:.0} pts", device_control_count, device_total), "Controls active")
        } else {
            ValidationCheck::failed("device_controls", "Device security controls need attention", Severity::High)
                .with_values(format!("{} controls, {:.0} pts", device_control_count, device_total), "Controls active")
        });
    }

    // Recommendations from zero-score controls (using description field per Graph API schema)
    for ctrl in zero_controls.iter().take(3) {
        if let Some(name) = ctrl.get("controlName").and_then(|n| n.as_str()) {
            let desc = ctrl.get("description").and_then(|d| d.as_str()).unwrap_or("");
            if !desc.is_empty() {
                builder = builder.add_recommendation(format!("{}: {}", name, desc));
            } else {
                builder = builder.add_recommendation(format!("Enable: {}", name));
            }
        }
    }
    results.push(builder.build());

    // KSI-MLA-05: Continuously monitor configurations
    let mut builder = KsiValidationBuilder::new(
        "KSI-MLA-05", "Continuously monitor security configurations.", Relevance::Direct,
    );
    builder = builder.add_check(ValidationCheck::passed("config_monitoring", "Secure Score continuously monitors security configuration")
        .with_values(format!("{} controls monitored", control_scores.len()), "Continuous monitoring"));
    results.push(builder.build());

    // KSI-IAM-02: MFA (if identity controls exist)
    if !identity_controls.is_empty() {
        let mfa_controls: Vec<_> = identity_controls.iter()
            .filter(|c| control_name_contains(c, "MFA") || control_name_contains(c, "multi-factor"))
            .collect();

        let mut builder = KsiValidationBuilder::new(
            "KSI-IAM-02", "Enforce strong authentication including MFA.", Relevance::Supporting,
        );

        let mfa_total = calc_category_total_nested(&mfa_controls);
        if !mfa_controls.is_empty() {
            // MFA controls with positive score indicate MFA is configured
            builder = builder.add_check(if mfa_total > 0.0 {
                ValidationCheck::passed("mfa_controls", "MFA-related Secure Score controls are contributing points")
                    .with_values(format!("{} MFA controls, {:.0} pts", mfa_controls.len(), mfa_total), "MFA active")
            } else {
                ValidationCheck::failed("mfa_controls", "MFA-related controls have zero score", Severity::High)
                    .with_values(format!("{} controls, 0 pts", mfa_controls.len()), "MFA active")
            });
        }
        results.push(builder.build());
    }

    // KSI-SVC-03: Data protection (from data controls)
    if !data_controls.is_empty() {
        let mut builder = KsiValidationBuilder::new(
            "KSI-SVC-03", "Encrypt information at rest by default.", Relevance::Supporting,
        );
        builder = builder.add_check(if data_total > 0.0 {
            ValidationCheck::passed("data_protection_controls", "Data protection controls are contributing to score")
                .with_values(format!("{} controls, {:.0} pts", data_controls.len(), data_total), "Data protection active")
        } else {
            ValidationCheck::failed("data_protection_controls", "Data protection controls need attention", Severity::Medium)
                .with_values(format!("{} controls, 0 pts", data_controls.len()), "Data protection active")
        });
        results.push(builder.build());
    }

    (results, records)
}

fn extract_array(data: &Value) -> Vec<Value> {
    match data {
        Value::Array(arr) => arr.clone(),
        Value::Object(obj) => obj.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        _ => vec![data.clone()],
    }
}

fn control_category(ctrl: &Value) -> &str {
    ctrl.get("controlCategory").and_then(|c| c.as_str()).unwrap_or("")
}

fn control_name_contains(ctrl: &Value, keyword: &str) -> bool {
    ctrl.get("controlName").and_then(|n| n.as_str())
        .map(|n| n.to_lowercase().contains(&keyword.to_lowercase()))
        .unwrap_or(false)
}

/// Calculate total score for a category (Graph API only provides score, not maxScore per control)
fn calc_category_total(controls: &[&Value]) -> f64 {
    controls.iter()
        .filter_map(|c| c.get("score").and_then(|s| s.as_f64()))
        .sum()
}

/// Calculate total score for nested reference (double reference from iter().filter())
fn calc_category_total_nested(controls: &[&&Value]) -> f64 {
    controls.iter()
        .filter_map(|c| c.get("score").and_then(|s| s.as_f64()))
        .sum()
}

fn empty_result(ksi_id: &'static str, desc: &'static str) -> KsiValidationResult {
    KsiValidationBuilder::new(ksi_id, desc, Relevance::Direct).build()
}
