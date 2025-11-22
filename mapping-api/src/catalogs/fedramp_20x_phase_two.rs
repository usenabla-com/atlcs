use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Ksi {
    pub id: &'static str,
    pub description: &'static str,
    #[serde(serialize_with = "serialize_baselines")]
    pub applies_to: &'static [Baseline],
    pub nist_controls: &'static [&'static str],
    pub status: KsiStatus,
}

fn serialize_baselines<S>(baselines: &&'static [Baseline], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(baselines.len()))?;
    for b in *baselines {
        seq.serialize_element(b)?;
    }
    seq.end()
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Baseline {
    Low,
    Moderate,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum KsiStatus {
    Active,
    Retired,
    Updated,
    New,
}

/// FedRAMP 20x Phase Two Key Security Indicators (RFC-0014)
pub static FEDRAMP_20X_PHASE_TWO_KSIS: &[Ksi] = &[
    // ===== CED - Cybersecurity Education =====
    Ksi {
        id: "KSI-CED-01",
        description: "Ensure all employees receive security and privacy awareness training, incident response training, and are familiar with all relevant policies and procedures.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AT-2", "AT-2.2", "AT-2.3", "AT-3.5", "AT-4", "IR-2.3"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-CED-02",
        description: "Provide role-based training for personnel with security responsibilities.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AT-2", "AT-2.3", "AT-3", "SR-11.1"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CED-03",
        description: "Require role-specific training for development and engineering staff covering best practices for delivering secure software.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CP-3", "IR-2", "PS-6"],
        status: KsiStatus::New,
    },

    // ===== CMT - Change Management =====
    Ksi {
        id: "KSI-CMT-01",
        description: "Log and monitor service modifications.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AU-2", "CM-3", "CM-3.2", "CM-4.2", "CM-6", "CM-8.3", "MA-2"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-CMT-02",
        description: "Maintain secure baseline configurations for all information resources.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-2", "CM-3", "CM-5", "CM-6", "CM-7", "CM-8.1", "SI-3"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CMT-03",
        description: "Implement persistent automated testing and validation of changes.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-3", "CM-3.2", "CM-4.2", "SI-2"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-CMT-04",
        description: "Consistently follow a documented change management procedure.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-3", "CM-3.2", "CM-3.4", "CM-5", "CM-7.1", "CM-9"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-CMT-05",
        description: "Assess security impact of changes before deployment.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CA-7.4", "CM-3.4", "CM-4", "CM-7.1", "SI-2"],
        status: KsiStatus::Active,
    },

    // ===== CNA - Communications and Network Architecture =====
    Ksi {
        id: "KSI-CNA-01",
        description: "Configure ALL machine-based information resources to limit inbound and outbound traffic.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-17.3", "CA-9", "CM-7.1", "SC-7.5", "SI-8"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-CNA-02",
        description: "Encrypt all data in transit.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-17.3", "AC-18.1", "AC-18.3", "AC-20.1", "CA-9", "SC-7.3", "SC-7.4", "SC-7.5", "SC-7.8", "SC-8", "SC-10", "SI-10", "SI-11", "SI-16"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CNA-03",
        description: "Segment networks and services appropriately.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-12", "AC-17.3", "CA-9", "SC-4", "SC-7", "SC-7.7", "SC-8", "SC-10"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CNA-04",
        description: "Implement malicious code protection.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-2", "SI-3"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CNA-05",
        description: "Protect against denial of service attacks and unwanted spam.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["SC-5", "SI-8", "SI-8.2"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-CNA-06",
        description: "Implement boundary protection.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &[],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CNA-07",
        description: "Use secure architecture design principles.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-17.3", "CM-2", "PL-10"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-CNA-08",
        description: "Use automated services to persistently assess the security posture of all services and automatically enforce secure operations.",
        applies_to: &[Baseline::Moderate],
        nist_controls: &["CA-2.1", "CA-7.1"],
        status: KsiStatus::New,
    },

    // ===== IAM - Identity and Access Management =====
    Ksi {
        id: "KSI-IAM-01",
        description: "Uniquely identify and authenticate all users.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2", "IA-2", "IA-2.1", "IA-2.2", "IA-2.8", "IA-5", "IA-8", "SC-23"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-IAM-02",
        description: "Enforce strong authentication including MFA.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2", "AC-3", "IA-2.1", "IA-2.2", "IA-2.8", "IA-5.1", "IA-5.2", "IA-5.6", "IA-6", "SC-23"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-IAM-03",
        description: "Authenticate and authorize all devices and services.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2", "AC-2.2", "AC-4", "AC-6.5", "IA-3", "IA-5.2", "RA-5.5"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-IAM-04",
        description: "Apply least privilege access controls.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2", "AC-2.1", "AC-2.2", "AC-2.3", "AC-2.4", "AC-2.6", "AC-3", "AC-4", "AC-5", "AC-6", "AC-6.1", "AC-6.2", "AC-6.5", "AC-6.7", "AC-6.9", "AC-6.10", "AC-7", "AC-17", "AC-17.4", "AC-20.1", "AU-9.4", "CM-5", "CM-7", "CM-7.2", "CM-7.5", "CM-9", "IA-4", "IA-4.4", "IA-7", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-9", "RA-5.5", "SC-2", "SC-23", "SC-39"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-IAM-05",
        description: "Design identity and access management systems that assume resources will be compromised.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2.5", "AC-2.6", "AC-3", "AC-4", "AC-6", "AC-12", "AC-14", "AC-17", "AC-17.1", "AC-17.2", "AC-17.3", "AC-20", "AC-20.1", "CM-2.7", "CM-9", "IA-2", "IA-3", "IA-4", "IA-4.4", "IA-5.2", "IA-5.6", "IA-11", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "SC-4", "SC-20", "SC-21", "SC-22", "SC-23", "SC-39", "SI-3"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-IAM-06",
        description: "Disable inactive accounts and revoke access promptly.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2", "AC-2.1", "AC-2.3", "AC-2.13", "AC-7", "PS-4", "PS-8"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-IAM-07",
        description: "Securely manage the lifecycle and privileges of all accounts, roles, and groups.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2.2", "AC-2.3", "AC-2.13", "AC-6.7", "IA-4.4", "IA-12", "IA-12.2", "IA-12.3", "IA-12.5"],
        status: KsiStatus::New,
    },

    // ===== INR - Incident Response =====
    Ksi {
        id: "KSI-INR-01",
        description: "Respond to incidents according to FedRAMP requirements and cloud service provider policies.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["IR-4", "IR-4.1", "IR-6", "IR-6.1", "IR-6.3", "IR-7", "IR-7.1", "IR-8", "IR-8.1", "SI-4.5"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-INR-02",
        description: "Conduct incident response testing and exercises.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["IR-3", "IR-4", "IR-4.1", "IR-5", "IR-8"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-INR-03",
        description: "Maintain incident response capabilities.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["IR-3", "IR-4", "IR-4.1", "IR-8"],
        status: KsiStatus::Active,
    },

    // ===== MLA - Monitoring, Logging, and Auditing =====
    Ksi {
        id: "KSI-MLA-01",
        description: "Implement comprehensive logging and monitoring.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-17.1", "AC-20.1", "AU-2", "AU-3", "AU-3.1", "AU-4", "AU-5", "AU-6.1", "AU-6.3", "AU-7", "AU-7.1", "AU-8", "AU-9", "AU-11", "IR-4.1", "SI-4.2", "SI-4.4", "SI-7.7"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-MLA-02",
        description: "Monitor for unauthorized access and anomalies.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2.4", "AC-6.9", "AU-2", "AU-6", "AU-6.1", "SI-4", "SI-4.4"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-MLA-03",
        description: "Rapidly detect and respond to vulnerabilities following requirements and recommendations in the FedRAMP Vulnerability Response and Detection standard.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AU-5", "CA-5", "CA-7", "RA-5", "RA-5.2", "SA-22", "SI-2", "SI-2.2", "SI-3", "SI-5", "SI-7.7", "SI-10", "SI-11"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-MLA-04",
        description: "Superseded by KSI-MLA-03.",
        applies_to: &[],
        nist_controls: &[],
        status: KsiStatus::Retired,
    },
    Ksi {
        id: "KSI-MLA-05",
        description: "Continuously monitor security configurations.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CA-7", "CM-2", "CM-6", "SI-7.7"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-MLA-06",
        description: "Superseded by KSI-MLA-03.",
        applies_to: &[],
        nist_controls: &[],
        status: KsiStatus::Retired,
    },
    Ksi {
        id: "KSI-MLA-07",
        description: "Maintain a list of information resources and event types that will be monitored, logged, and audited.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2.4", "AC-6.9", "AC-17.1", "AC-20.1", "AU-2", "AU-7.1", "AU-12", "SI-4.4", "SI-4.5", "SI-7.7"],
        status: KsiStatus::New,
    },
    Ksi {
        id: "KSI-MLA-08",
        description: "Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data.",
        applies_to: &[Baseline::Moderate],
        nist_controls: &["SI-11"],
        status: KsiStatus::New,
    },

    // ===== PIY - Planning, Inventory, and Yourself =====
    Ksi {
        id: "KSI-PIY-01",
        description: "Generate inventories of information resources from authoritative sources.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-2.2", "CM-7.5", "CM-8", "CM-8.1", "CM-12", "CM-12.1", "CP-2.8"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-PIY-02",
        description: "Document the security objectives and requirements for each information resource.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-1", "AC-21", "AT-1", "AU-1", "CA-1", "CA-2", "CM-1", "CP-1", "CP-2.1", "CP-2.8", "CP-4.1", "IA-1", "IR-1", "MA-1", "MP-1", "PE-1", "PL-1", "PL-2", "PL-4", "PL-4.1", "PS-1", "RA-1", "RA-9", "SA-1", "SC-1", "SI-1", "SR-1", "SR-2", "SR-3", "SR-11"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-PIY-03",
        description: "Perform risk assessments.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["RA-5.11"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-PIY-04",
        description: "Build security and privacy considerations into the Software Development Lifecycle and align with CISA Secure By Design principles.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-5", "AU-3.3", "CM-3.4", "PL-8", "PM-7", "SA-3", "SA-8", "SC-4", "SC-18", "SI-10", "SI-11", "SI-16"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-PIY-05",
        description: "Implement a secure system development lifecycle.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &[],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-PIY-06",
        description: "Have staff and budget for security commensurate with the size, complexity, scope, executive priorities, and risk of the service offering that demonstrates commitment to delivering a secure service.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-5", "CA-2", "CP-2.1", "CP-4.1", "IR-3.2", "PM-3", "SA-2", "SA-3", "SR-2.1"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-PIY-07",
        description: "Manage mobile code securely.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CA-7.4", "SC-18"],
        status: KsiStatus::Active,
    },

    // ===== RPL - Resilience and Planning =====
    Ksi {
        id: "KSI-RPL-01",
        description: "Establish system recovery objectives.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CP-2.3", "CP-10"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-RPL-02",
        description: "Implement backup and recovery capabilities.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CP-2", "CP-2.1", "CP-2.3", "CP-4.1", "CP-6", "CP-6.1", "CP-6.3", "CP-7", "CP-7.1", "CP-7.2", "CP-7.3", "CP-8", "CP-8.1", "CP-8.2", "CP-10", "CP-10.2"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-RPL-03",
        description: "Protect backup data.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-2.3", "CP-6", "CP-9", "CP-10", "CP-10.2", "SI-12"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-RPL-04",
        description: "Test backup and recovery procedures.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CP-2.1", "CP-2.3", "CP-4", "CP-4.1", "CP-6", "CP-6.1", "CP-9.1", "CP-10", "IR-3", "IR-3.2"],
        status: KsiStatus::Active,
    },

    // ===== SVC - Secure Virtualization and Containers =====
    Ksi {
        id: "KSI-SVC-01",
        description: "Continuously evaluate machine-based information resources for opportunities to improve security.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-7.1", "CM-12.1", "MA-2", "PL-8", "SC-7", "SC-39", "SI-2.2", "SI-4", "SR-10"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-SVC-02",
        description: "Encrypt all data in transit using approved cryptography.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-1", "AC-17.2", "CP-9.8", "SC-8", "SC-8.1", "SC-13", "SC-20", "SC-21", "SC-22", "SC-23"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-SVC-03",
        description: "Encrypt information at rest by default.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-19.5", "AC-20.2", "AC-21", "CM-12", "CP-9.8", "SC-13", "SC-28", "SC-28.1"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-SVC-04",
        description: "Manage configuration of machine-based information resources using automation.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-2.4", "CM-2", "CM-2.2", "CM-2.3", "CM-6", "CM-7.1", "PL-9", "PL-10", "SA-5", "SI-5", "SR-10"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-SVC-05",
        description: "Use cryptographic methods to validate the integrity of machine-based information resources.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CM-2.2", "CM-8.3", "SC-13", "SC-23", "SI-7", "SI-7.1", "SR-10"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-SVC-06",
        description: "Manage cryptographic keys securely.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-17.2", "IA-5.2", "IA-5.6", "SC-12", "SC-17"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-SVC-07",
        description: "Perform regular security assessments.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CA-7.4", "RA-5", "RA-7"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-SVC-08",
        description: "Ensure that changes do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of information resources.",
        applies_to: &[Baseline::Moderate],
        nist_controls: &["SC-4"],
        status: KsiStatus::New,
    },
    Ksi {
        id: "KSI-SVC-09",
        description: "Use mechanisms that continuously validate the authenticity and integrity of communications between information resources.",
        applies_to: &[Baseline::Moderate],
        nist_controls: &["SC-23", "SI-7.1"],
        status: KsiStatus::New,
    },
    Ksi {
        id: "KSI-SVC-10",
        description: "Remove unwanted information promptly, including from backups if appropriate.",
        applies_to: &[Baseline::Moderate],
        nist_controls: &["SI-12.3", "SI-18.4"],
        status: KsiStatus::New,
    },

    // ===== TPR - Third-Party Risk =====
    Ksi {
        id: "KSI-TPR-01",
        description: "Follow the requirements and recommendations in the FedRAMP Minimum Assessment Standard regarding third-party information resources.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["CA-3", "CM-10", "PS-7", "SA-4.9"],
        status: KsiStatus::Updated,
    },
    Ksi {
        id: "KSI-TPR-02",
        description: "Superseded by KSI-TPR-01.",
        applies_to: &[],
        nist_controls: &["AC-21", "CA-3", "CM-12", "PS-7", "SA-2", "SA-4", "SA-4.1", "SA-4.2", "SA-4.9", "SA-9", "SA-9.2", "SA-10", "SA-11", "SA-15"],
        status: KsiStatus::Retired,
    },
    Ksi {
        id: "KSI-TPR-03",
        description: "Assess supply chain risks.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-20", "RA-3.1", "SA-9", "SA-10", "SA-11", "SA-15.3", "SA-22", "SI-7.1", "SR-5", "SR-6"],
        status: KsiStatus::Active,
    },
    Ksi {
        id: "KSI-TPR-04",
        description: "Monitor third-party services.",
        applies_to: &[Baseline::Low, Baseline::Moderate],
        nist_controls: &["AC-20", "CA-3", "IR-6.3", "PS-7", "RA-5", "SA-9", "SI-5", "SR-5", "SR-6", "SR-8"],
        status: KsiStatus::Active,
    },
];

/// Get all active KSIs (excludes retired)
pub fn get_active_ksis() -> Vec<&'static Ksi> {
    FEDRAMP_20X_PHASE_TWO_KSIS
        .iter()
        .filter(|ksi| ksi.status != KsiStatus::Retired)
        .collect()
}

/// Get KSIs by baseline
pub fn get_ksis_by_baseline(baseline: Baseline) -> Vec<&'static Ksi> {
    FEDRAMP_20X_PHASE_TWO_KSIS
        .iter()
        .filter(|ksi| ksi.applies_to.contains(&baseline) && ksi.status != KsiStatus::Retired)
        .collect()
}

/// Get KSI by ID
pub fn get_ksi_by_id(id: &str) -> Option<&'static Ksi> {
    FEDRAMP_20X_PHASE_TWO_KSIS.iter().find(|ksi| ksi.id == id)
}

/// Get KSIs that map to a specific NIST control
pub fn get_ksis_by_nist_control(control: &str) -> Vec<&'static Ksi> {
    FEDRAMP_20X_PHASE_TWO_KSIS
        .iter()
        .filter(|ksi| ksi.nist_controls.contains(&control) && ksi.status != KsiStatus::Retired)
        .collect()
}
