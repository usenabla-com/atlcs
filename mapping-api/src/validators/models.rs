use serde::Serialize;

/// Result of validating evidence against a KSI
#[derive(Debug, Clone, Serialize)]
pub struct KsiValidationResult {
    /// KSI identifier (e.g., "KSI-IAM-02")
    pub ksi_id: &'static str,
    /// KSI description
    pub ksi_description: &'static str,
    /// Overall compliance status
    pub status: ComplianceStatus,
    /// Relevance of this evidence to the KSI
    pub relevance: Relevance,
    /// Individual checks performed
    pub checks: Vec<ValidationCheck>,
    /// Summary of findings
    pub summary: String,
    /// Recommendations for remediation (if any)
    pub recommendations: Vec<String>,
}

/// Compliance status for a KSI
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    /// All requirements are met
    Compliant,
    /// Some requirements are met, others are not
    PartiallyCompliant,
    /// Requirements are not met
    NonCompliant,
    /// Unable to determine compliance (missing data)
    Indeterminate,
    /// Not applicable to this evidence type
    NotApplicable,
}

/// How relevant this evidence is to the KSI
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Relevance {
    /// This evidence directly proves/disproves the KSI
    Direct,
    /// This evidence supports the KSI but doesn't fully prove it
    Supporting,
    /// This evidence is tangentially related
    Indirect,
}

/// Individual validation check
#[derive(Debug, Clone, Serialize)]
pub struct ValidationCheck {
    /// What was checked
    pub check_name: String,
    /// Description of the check
    pub description: String,
    /// Result of the check
    pub passed: bool,
    /// Severity if failed
    pub severity: Severity,
    /// The actual value found (if applicable)
    pub actual_value: Option<String>,
    /// The expected value (if applicable)
    pub expected_value: Option<String>,
    /// JSON path to the relevant field
    pub evidence_path: Option<String>,
}

/// Severity of a failed check
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Critical - must be fixed for compliance
    Critical,
    /// High - strongly recommended to fix
    High,
    /// Medium - should be addressed
    Medium,
    /// Low - minor issue
    Low,
    /// Informational - not a compliance issue
    Info,
}

/// Full validation response
#[derive(Debug, Serialize)]
pub struct ValidationResponse {
    /// Source system
    pub source: String,
    /// Evidence type that was validated
    pub evidence_type: String,
    /// Tenant/organization identifier
    pub tenant_id: String,
    /// When the evidence was collected
    pub collected_at: String,
    /// When validation was performed
    pub validated_at: String,
    /// Overall compliance summary
    pub overall_status: OverallComplianceStatus,
    /// Individual KSI validation results
    pub ksi_results: Vec<KsiValidationResult>,
    /// Fields in the evidence that weren't used
    pub unused_fields: Vec<String>,
    /// Processing metadata
    pub metadata: ValidationMetadata,
}

/// Overall compliance status across all KSIs
#[derive(Debug, Serialize)]
pub struct OverallComplianceStatus {
    /// Count of compliant KSIs
    pub compliant: usize,
    /// Count of partially compliant KSIs
    pub partially_compliant: usize,
    /// Count of non-compliant KSIs
    pub non_compliant: usize,
    /// Count of indeterminate KSIs
    pub indeterminate: usize,
    /// Percentage score (compliant + 0.5*partial) / total * 100
    pub score: f64,
}

impl OverallComplianceStatus {
    pub fn from_results(results: &[KsiValidationResult]) -> Self {
        let mut compliant = 0;
        let mut partially_compliant = 0;
        let mut non_compliant = 0;
        let mut indeterminate = 0;

        for result in results {
            match result.status {
                ComplianceStatus::Compliant => compliant += 1,
                ComplianceStatus::PartiallyCompliant => partially_compliant += 1,
                ComplianceStatus::NonCompliant => non_compliant += 1,
                ComplianceStatus::Indeterminate => indeterminate += 1,
                ComplianceStatus::NotApplicable => {}
            }
        }

        let total = compliant + partially_compliant + non_compliant;
        let score = if total > 0 {
            ((compliant as f64) + (partially_compliant as f64 * 0.5)) / (total as f64) * 100.0
        } else {
            0.0
        };

        Self {
            compliant,
            partially_compliant,
            non_compliant,
            indeterminate,
            score,
        }
    }
}

/// Metadata about the validation process
#[derive(Debug, Serialize)]
pub struct ValidationMetadata {
    /// Tenant that performed the validation
    pub validated_by_tenant: String,
    /// License type used
    pub license_type: String,
    /// Number of records processed
    pub records_processed: usize,
    /// Validation engine version
    pub engine_version: &'static str,
}

/// Helper to create validation checks
impl ValidationCheck {
    pub fn passed(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            check_name: name.into(),
            description: description.into(),
            passed: true,
            severity: Severity::Info,
            actual_value: None,
            expected_value: None,
            evidence_path: None,
        }
    }

    pub fn failed(
        name: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            check_name: name.into(),
            description: description.into(),
            passed: false,
            severity,
            actual_value: None,
            expected_value: None,
            evidence_path: None,
        }
    }

    pub fn with_values(
        mut self,
        actual: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        self.actual_value = Some(actual.into());
        self.expected_value = Some(expected.into());
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.evidence_path = Some(path.into());
        self
    }
}

/// Helper to build KSI validation results
pub struct KsiValidationBuilder {
    ksi_id: &'static str,
    ksi_description: &'static str,
    relevance: Relevance,
    checks: Vec<ValidationCheck>,
    recommendations: Vec<String>,
}

impl KsiValidationBuilder {
    pub fn new(ksi_id: &'static str, ksi_description: &'static str, relevance: Relevance) -> Self {
        Self {
            ksi_id,
            ksi_description,
            relevance,
            checks: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    pub fn add_check(mut self, check: ValidationCheck) -> Self {
        self.checks.push(check);
        self
    }

    pub fn add_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendations.push(rec.into());
        self
    }

    pub fn build(self) -> KsiValidationResult {
        let (status, summary) = self.calculate_status();
        KsiValidationResult {
            ksi_id: self.ksi_id,
            ksi_description: self.ksi_description,
            status,
            relevance: self.relevance,
            checks: self.checks,
            summary,
            recommendations: self.recommendations,
        }
    }

    fn calculate_status(&self) -> (ComplianceStatus, String) {
        if self.checks.is_empty() {
            return (
                ComplianceStatus::Indeterminate,
                "No validation checks could be performed - missing required data".to_string(),
            );
        }

        let total = self.checks.len();
        let passed = self.checks.iter().filter(|c| c.passed).count();
        let critical_failures = self
            .checks
            .iter()
            .filter(|c| !c.passed && c.severity == Severity::Critical)
            .count();

        if passed == total {
            (
                ComplianceStatus::Compliant,
                format!("All {} validation checks passed", total),
            )
        } else if critical_failures > 0 {
            (
                ComplianceStatus::NonCompliant,
                format!(
                    "{} of {} checks passed; {} critical failures",
                    passed, total, critical_failures
                ),
            )
        } else if passed > 0 {
            (
                ComplianceStatus::PartiallyCompliant,
                format!("{} of {} checks passed", passed, total),
            )
        } else {
            (
                ComplianceStatus::NonCompliant,
                format!("All {} checks failed", total),
            )
        }
    }
}
