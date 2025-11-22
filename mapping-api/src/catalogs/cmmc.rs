use serde::Serialize;

/// CMMC (Cybersecurity Maturity Model Certification) 2.0 Catalog
///
/// CMMC Level 1: 17 practices (FAR 52.204-21 basic safeguarding)
/// CMMC Level 2: 110 practices (NIST SP 800-171 r3)
/// CMMC Level 3: 110 + 24 enhanced practices (SP 800-171 + selected SP 800-172)

#[derive(Debug, Clone, Serialize)]
pub struct CmmcPractice {
    pub id: &'static str,
    pub domain: &'static str,
    pub capability: &'static str,
    pub practice_statement: &'static str,
    #[serde(serialize_with = "serialize_levels")]
    pub levels: &'static [CmmcLevel],
    pub nist_controls: &'static [&'static str],
    pub sp800_171_ref: Option<&'static str>,
    pub sp800_172_ref: Option<&'static str>,
}

fn serialize_levels<S>(levels: &&'static [CmmcLevel], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(levels.len()))?;
    for l in *levels {
        seq.serialize_element(l)?;
    }
    seq.end()
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum CmmcLevel {
    Level1,
    Level2,
    Level3,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum CmmcDomain {
    AccessControl,
    AwarenessAndTraining,
    AuditAndAccountability,
    ConfigurationManagement,
    IdentificationAndAuthentication,
    IncidentResponse,
    Maintenance,
    MediaProtection,
    PersonnelSecurity,
    PhysicalProtection,
    RiskAssessment,
    SecurityAssessment,
    SystemAndCommunicationsProtection,
    SystemAndInformationIntegrity,
    Planning,
    SystemAndServicesAcquisition,
    SupplyChainRiskManagement,
}

/// CMMC 2.0 Practices Catalog
pub static CMMC_PRACTICES: &[CmmcPractice] = &[
    // =============================================================================
    // ACCESS CONTROL (AC) DOMAIN
    // =============================================================================

    // Level 1 Practices
    CmmcPractice {
        id: "AC.L1-3.1.1",
        domain: "Access Control",
        capability: "Establish system access requirements",
        practice_statement: "Limit information system access to authorized users, processes acting on behalf of authorized users, or devices (including other information systems).",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-2", "AC-3", "AC-17"],
        sp800_171_ref: Some("3.1.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L1-3.1.2",
        domain: "Access Control",
        capability: "Establish system access requirements",
        practice_statement: "Limit information system access to the types of transactions and functions that authorized users are permitted to execute.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-2", "AC-3", "AC-6"],
        sp800_171_ref: Some("3.1.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L1-3.1.20",
        domain: "Access Control",
        capability: "Control external connections",
        practice_statement: "Verify and control/limit connections to and use of external information systems.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-20"],
        sp800_171_ref: Some("3.1.20"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L1-3.1.22",
        domain: "Access Control",
        capability: "Control portable storage",
        practice_statement: "Control information posted or processed on publicly accessible information systems.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-22"],
        sp800_171_ref: Some("3.1.22"),
        sp800_172_ref: None,
    },

    // Level 2 Access Control Practices
    CmmcPractice {
        id: "AC.L2-3.1.3",
        domain: "Access Control",
        capability: "Control CUI flow",
        practice_statement: "Control the flow of CUI in accordance with approved authorizations.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-4"],
        sp800_171_ref: Some("3.1.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.4",
        domain: "Access Control",
        capability: "Separation of duties",
        practice_statement: "Separate the duties of individuals to reduce the risk of malevolent activity without collusion.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-5"],
        sp800_171_ref: Some("3.1.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.5",
        domain: "Access Control",
        capability: "Least privilege",
        practice_statement: "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-6", "AC-6(1)", "AC-6(5)"],
        sp800_171_ref: Some("3.1.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.6",
        domain: "Access Control",
        capability: "Non-privileged account use",
        practice_statement: "Use non-privileged accounts or roles when accessing non-security functions.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-6(2)"],
        sp800_171_ref: Some("3.1.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.7",
        domain: "Access Control",
        capability: "Privileged functions",
        practice_statement: "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-6(9)", "AC-6(10)"],
        sp800_171_ref: Some("3.1.7"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.8",
        domain: "Access Control",
        capability: "Unsuccessful login attempts",
        practice_statement: "Limit unsuccessful logon attempts.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-7"],
        sp800_171_ref: Some("3.1.8"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.9",
        domain: "Access Control",
        capability: "Privacy and security notices",
        practice_statement: "Provide privacy and security notices consistent with applicable CUI rules.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-8"],
        sp800_171_ref: Some("3.1.9"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.10",
        domain: "Access Control",
        capability: "Session lock",
        practice_statement: "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-11", "AC-11(1)"],
        sp800_171_ref: Some("3.1.10"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.11",
        domain: "Access Control",
        capability: "Session termination",
        practice_statement: "Terminate (automatically) a user session after a defined condition.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-12"],
        sp800_171_ref: Some("3.1.11"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.12",
        domain: "Access Control",
        capability: "Remote access control",
        practice_statement: "Monitor and control remote access sessions.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-17(1)"],
        sp800_171_ref: Some("3.1.12"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.13",
        domain: "Access Control",
        capability: "Remote access encryption",
        practice_statement: "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-17(2)"],
        sp800_171_ref: Some("3.1.13"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.14",
        domain: "Access Control",
        capability: "Remote access routing",
        practice_statement: "Route remote access via managed access control points.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-17(3)"],
        sp800_171_ref: Some("3.1.14"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.15",
        domain: "Access Control",
        capability: "Privileged remote access",
        practice_statement: "Authorize remote execution of privileged commands and remote access to security-relevant information.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-17(4)"],
        sp800_171_ref: Some("3.1.15"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.16",
        domain: "Access Control",
        capability: "Wireless access authorization",
        practice_statement: "Authorize wireless access prior to allowing such connections.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-18"],
        sp800_171_ref: Some("3.1.16"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.17",
        domain: "Access Control",
        capability: "Wireless access protection",
        practice_statement: "Protect wireless access using authentication and encryption.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-18(1)"],
        sp800_171_ref: Some("3.1.17"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.18",
        domain: "Access Control",
        capability: "Mobile device connection",
        practice_statement: "Control connection of mobile devices.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-19"],
        sp800_171_ref: Some("3.1.18"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.19",
        domain: "Access Control",
        capability: "Mobile device encryption",
        practice_statement: "Encrypt CUI on mobile devices and mobile computing platforms.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-19(5)"],
        sp800_171_ref: Some("3.1.19"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AC.L2-3.1.21",
        domain: "Access Control",
        capability: "Portable storage use",
        practice_statement: "Limit use of portable storage devices on external systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AC-20(2)"],
        sp800_171_ref: Some("3.1.21"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Access Control (SP 800-172)
    CmmcPractice {
        id: "AC.L3-3.1.1e",
        domain: "Access Control",
        capability: "Dual authorization",
        practice_statement: "Employ dual authorization to execute critical or sensitive system and organizational operations.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["AC-3(2)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.1.1e"),
    },
    CmmcPractice {
        id: "AC.L3-3.1.2e",
        domain: "Access Control",
        capability: "Organization-controlled assets",
        practice_statement: "Restrict access to systems and system components to only those information resources that are owned, provisioned, or issued by the organization.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["AC-3(13)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.1.2e"),
    },
    CmmcPractice {
        id: "AC.L3-3.1.3e",
        domain: "Access Control",
        capability: "Secure information transfer",
        practice_statement: "Employ organization-defined secure information transfer solutions to control information flows between security domains on connected systems.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["AC-4(6)", "AC-4(8)", "AC-4(17)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.1.3e"),
    },

    // =============================================================================
    // AWARENESS AND TRAINING (AT) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "AT.L2-3.2.1",
        domain: "Awareness and Training",
        capability: "Security awareness",
        practice_statement: "Ensure that managers, systems administrators, and users of organizational systems are made aware of the security risks associated with their activities and of the applicable policies, standards, and procedures related to the security of those systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AT-2"],
        sp800_171_ref: Some("3.2.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AT.L2-3.2.2",
        domain: "Awareness and Training",
        capability: "Role-based training",
        practice_statement: "Ensure that personnel are trained to carry out their assigned information security-related duties and responsibilities.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AT-3"],
        sp800_171_ref: Some("3.2.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AT.L2-3.2.3",
        domain: "Awareness and Training",
        capability: "Insider threat awareness",
        practice_statement: "Provide security awareness training on recognizing and reporting potential indicators of insider threat.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AT-2(2)"],
        sp800_171_ref: Some("3.2.3"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Awareness and Training (SP 800-172)
    CmmcPractice {
        id: "AT.L3-3.2.1e",
        domain: "Awareness and Training",
        capability: "Advanced threat awareness",
        practice_statement: "Provide awareness training focused on recognizing and responding to threats from social engineering, advanced persistent threat actors, breaches, and suspicious behaviors; update the training at organization-defined frequency or when there are significant changes to the threat.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["AT-2(1)", "AT-2(3)", "AT-2(5)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.2.1e"),
    },
    CmmcPractice {
        id: "AT.L3-3.2.2e",
        domain: "Awareness and Training",
        capability: "Practical exercises",
        practice_statement: "Include practical exercises in awareness training that are aligned with current threat scenarios and provide feedback to individuals involved in the training and their supervisors.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["AT-2(1)", "AT-3(3)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.2.2e"),
    },

    // =============================================================================
    // AUDIT AND ACCOUNTABILITY (AU) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "AU.L2-3.3.1",
        domain: "Audit and Accountability",
        capability: "System auditing",
        practice_statement: "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-2", "AU-3", "AU-3(1)", "AU-6", "AU-11", "AU-12"],
        sp800_171_ref: Some("3.3.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.2",
        domain: "Audit and Accountability",
        capability: "User accountability",
        practice_statement: "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-2", "AU-3", "AU-6(1)"],
        sp800_171_ref: Some("3.3.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.3",
        domain: "Audit and Accountability",
        capability: "Event review",
        practice_statement: "Review and update logged events.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-2(3)"],
        sp800_171_ref: Some("3.3.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.4",
        domain: "Audit and Accountability",
        capability: "Audit failure alerting",
        practice_statement: "Alert in the event of an audit logging process failure.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-5"],
        sp800_171_ref: Some("3.3.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.5",
        domain: "Audit and Accountability",
        capability: "Audit correlation",
        practice_statement: "Correlate audit record review, analysis, and reporting processes for investigation and response to indications of unlawful, unauthorized, suspicious, or unusual activity.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-6(3)"],
        sp800_171_ref: Some("3.3.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.6",
        domain: "Audit and Accountability",
        capability: "Audit reduction",
        practice_statement: "Provide audit record reduction and report generation to support on-demand analysis and reporting.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-7"],
        sp800_171_ref: Some("3.3.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.7",
        domain: "Audit and Accountability",
        capability: "Time stamps",
        practice_statement: "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source to generate time stamps for audit records.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-8"],
        sp800_171_ref: Some("3.3.7"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.8",
        domain: "Audit and Accountability",
        capability: "Audit protection",
        practice_statement: "Protect audit information and audit logging tools from unauthorized access, modification, and deletion.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-9"],
        sp800_171_ref: Some("3.3.8"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "AU.L2-3.3.9",
        domain: "Audit and Accountability",
        capability: "Audit management",
        practice_statement: "Limit management of audit logging functionality to a subset of privileged users.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["AU-9(4)"],
        sp800_171_ref: Some("3.3.9"),
        sp800_172_ref: None,
    },

    // =============================================================================
    // CONFIGURATION MANAGEMENT (CM) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "CM.L2-3.4.1",
        domain: "Configuration Management",
        capability: "System baselining",
        practice_statement: "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-2", "CM-6", "CM-8", "CM-8(1)"],
        sp800_171_ref: Some("3.4.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.2",
        domain: "Configuration Management",
        capability: "Security configurations",
        practice_statement: "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-6"],
        sp800_171_ref: Some("3.4.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.3",
        domain: "Configuration Management",
        capability: "System change management",
        practice_statement: "Track, review, approve or disapprove, and log changes to organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-3"],
        sp800_171_ref: Some("3.4.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.4",
        domain: "Configuration Management",
        capability: "Impact analysis",
        practice_statement: "Analyze the security impact of changes prior to implementation.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-4"],
        sp800_171_ref: Some("3.4.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.5",
        domain: "Configuration Management",
        capability: "Access restrictions",
        practice_statement: "Define, document, approve, and enforce physical and logical access restrictions associated with changes to organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-5"],
        sp800_171_ref: Some("3.4.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.6",
        domain: "Configuration Management",
        capability: "Least functionality",
        practice_statement: "Employ the principle of least functionality by configuring organizational systems to provide only essential capabilities.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-7"],
        sp800_171_ref: Some("3.4.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.7",
        domain: "Configuration Management",
        capability: "Nonessential functionality",
        practice_statement: "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-7(1)", "CM-7(2)"],
        sp800_171_ref: Some("3.4.7"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.8",
        domain: "Configuration Management",
        capability: "Application execution policy",
        practice_statement: "Apply deny-by-exception (blacklisting) policy to prevent the use of unauthorized software or deny-all, permit-by-exception (whitelisting) policy to allow the execution of authorized software.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-7(4)", "CM-7(5)"],
        sp800_171_ref: Some("3.4.8"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CM.L2-3.4.9",
        domain: "Configuration Management",
        capability: "User-installed software",
        practice_statement: "Control and monitor user-installed software.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CM-11"],
        sp800_171_ref: Some("3.4.9"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Configuration Management (SP 800-172)
    CmmcPractice {
        id: "CM.L3-3.4.1e",
        domain: "Configuration Management",
        capability: "Authoritative source",
        practice_statement: "Establish and maintain an authoritative source and repository to provide a trusted source and accountability for approved and implemented system components.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["CM-2(2)", "CM-3(3)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.4.1e"),
    },
    CmmcPractice {
        id: "CM.L3-3.4.2e",
        domain: "Configuration Management",
        capability: "Automated detection",
        practice_statement: "Employ automated mechanisms to detect misconfigured or unauthorized system components; after detection, remove the components or place the components in a quarantine or remediation network to facilitate patching, re-configuration, or other mitigations.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["CM-2(2)", "SI-4(7)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.4.2e"),
    },
    CmmcPractice {
        id: "CM.L3-3.4.3e",
        domain: "Configuration Management",
        capability: "Automated discovery",
        practice_statement: "Employ automated discovery and management tools to maintain an up-to-date, complete, accurate, and readily available inventory of system components.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["CM-8(2)", "CM-8(4)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.4.3e"),
    },

    // =============================================================================
    // IDENTIFICATION AND AUTHENTICATION (IA) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "IA.L1-3.5.1",
        domain: "Identification and Authentication",
        capability: "User identification",
        practice_statement: "Identify information system users, processes acting on behalf of users, or devices.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-2", "IA-5"],
        sp800_171_ref: Some("3.5.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L1-3.5.2",
        domain: "Identification and Authentication",
        capability: "User authentication",
        practice_statement: "Authenticate (or verify) the identities of those users, processes, or devices, as a prerequisite to allowing access to organizational information systems.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-2", "IA-5"],
        sp800_171_ref: Some("3.5.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.3",
        domain: "Identification and Authentication",
        capability: "Multifactor authentication",
        practice_statement: "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-2(1)", "IA-2(2)"],
        sp800_171_ref: Some("3.5.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.4",
        domain: "Identification and Authentication",
        capability: "Replay-resistant authentication",
        practice_statement: "Employ replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-2(8)"],
        sp800_171_ref: Some("3.5.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.5",
        domain: "Identification and Authentication",
        capability: "Identifier reuse",
        practice_statement: "Prevent reuse of identifiers for a defined period.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-4"],
        sp800_171_ref: Some("3.5.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.6",
        domain: "Identification and Authentication",
        capability: "Identifier handling",
        practice_statement: "Disable identifiers after a defined period of inactivity.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-4"],
        sp800_171_ref: Some("3.5.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.7",
        domain: "Identification and Authentication",
        capability: "Password complexity",
        practice_statement: "Enforce a minimum password complexity and change of characters when new passwords are created.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-5(1)"],
        sp800_171_ref: Some("3.5.7"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.8",
        domain: "Identification and Authentication",
        capability: "Password reuse",
        practice_statement: "Prohibit password reuse for a specified number of generations.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-5(1)"],
        sp800_171_ref: Some("3.5.8"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.9",
        domain: "Identification and Authentication",
        capability: "Temporary passwords",
        practice_statement: "Allow temporary password use for system logons with an immediate change to a permanent password.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-5(1)"],
        sp800_171_ref: Some("3.5.9"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.10",
        domain: "Identification and Authentication",
        capability: "Cryptographically-protected passwords",
        practice_statement: "Store and transmit only cryptographically-protected passwords.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-5(1)"],
        sp800_171_ref: Some("3.5.10"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IA.L2-3.5.11",
        domain: "Identification and Authentication",
        capability: "Obscure feedback",
        practice_statement: "Obscure feedback of authentication information.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IA-6"],
        sp800_171_ref: Some("3.5.11"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Identification and Authentication (SP 800-172)
    CmmcPractice {
        id: "IA.L3-3.5.1e",
        domain: "Identification and Authentication",
        capability: "Bidirectional authentication",
        practice_statement: "Identify and authenticate organization-defined systems and system components before establishing a network connection using bidirectional authentication that is cryptographically based and replay resistant.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["IA-3(1)", "SC-23(3)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.5.1e"),
    },
    CmmcPractice {
        id: "IA.L3-3.5.2e",
        domain: "Identification and Authentication",
        capability: "Automated password management",
        practice_statement: "Employ automated mechanisms for the generation, protection, rotation, and management of passwords for systems and system components that do not support multifactor authentication or complex account management.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["IA-5(18)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.5.2e"),
    },
    CmmcPractice {
        id: "IA.L3-3.5.3e",
        domain: "Identification and Authentication",
        capability: "Device attestation",
        practice_statement: "Employ automated or manual/procedural mechanisms to prohibit system components from connecting to organizational systems unless the components are known, authenticated, in a properly configured state, or in a trust profile.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["IA-3(4)", "SI-4(24)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.5.3e"),
    },

    // =============================================================================
    // INCIDENT RESPONSE (IR) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "IR.L2-3.6.1",
        domain: "Incident Response",
        capability: "Incident handling",
        practice_statement: "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IR-2", "IR-4", "IR-5", "IR-6", "IR-7"],
        sp800_171_ref: Some("3.6.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IR.L2-3.6.2",
        domain: "Incident Response",
        capability: "Incident reporting",
        practice_statement: "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IR-6"],
        sp800_171_ref: Some("3.6.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "IR.L2-3.6.3",
        domain: "Incident Response",
        capability: "Incident response testing",
        practice_statement: "Test the organizational incident response capability.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["IR-3"],
        sp800_171_ref: Some("3.6.3"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Incident Response (SP 800-172)
    CmmcPractice {
        id: "IR.L3-3.6.1e",
        domain: "Incident Response",
        capability: "Security operations center",
        practice_statement: "Establish and maintain a security operations center capability that operates at an organization-defined time period.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["IR-4(10)", "SI-4(7)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.6.1e"),
    },
    CmmcPractice {
        id: "IR.L3-3.6.2e",
        domain: "Incident Response",
        capability: "Cyber incident response team",
        practice_statement: "Establish and maintain a cyber incident response team that can be deployed by the organization within an organization-defined time period.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["IR-4(11)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.6.2e"),
    },

    // =============================================================================
    // MAINTENANCE (MA) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "MA.L2-3.7.1",
        domain: "Maintenance",
        capability: "System maintenance",
        practice_statement: "Perform maintenance on organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MA-2"],
        sp800_171_ref: Some("3.7.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MA.L2-3.7.2",
        domain: "Maintenance",
        capability: "Maintenance control",
        practice_statement: "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MA-3", "MA-3(1)", "MA-3(2)"],
        sp800_171_ref: Some("3.7.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MA.L2-3.7.3",
        domain: "Maintenance",
        capability: "Equipment sanitization",
        practice_statement: "Ensure equipment removed for off-site maintenance is sanitized of any CUI.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MA-2"],
        sp800_171_ref: Some("3.7.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MA.L2-3.7.4",
        domain: "Maintenance",
        capability: "Media inspection",
        practice_statement: "Check media containing diagnostic and test programs for malicious code before the media are used in organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MA-3(2)"],
        sp800_171_ref: Some("3.7.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MA.L2-3.7.5",
        domain: "Maintenance",
        capability: "Nonlocal maintenance",
        practice_statement: "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections and terminate such connections when nonlocal maintenance is complete.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MA-4"],
        sp800_171_ref: Some("3.7.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MA.L2-3.7.6",
        domain: "Maintenance",
        capability: "Maintenance personnel",
        practice_statement: "Supervise the maintenance activities of maintenance personnel without required access authorization.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MA-5"],
        sp800_171_ref: Some("3.7.6"),
        sp800_172_ref: None,
    },

    // =============================================================================
    // MEDIA PROTECTION (MP) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "MP.L1-3.8.3",
        domain: "Media Protection",
        capability: "Media disposal",
        practice_statement: "Sanitize or destroy information system media containing Federal Contract Information before disposal or release for reuse.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-6"],
        sp800_171_ref: Some("3.8.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.1",
        domain: "Media Protection",
        capability: "Media protection",
        practice_statement: "Protect (i.e., physically control and securely store) system media containing CUI, both paper and digital.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-2", "MP-4"],
        sp800_171_ref: Some("3.8.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.2",
        domain: "Media Protection",
        capability: "Media access",
        practice_statement: "Limit access to CUI on system media to authorized users.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-2"],
        sp800_171_ref: Some("3.8.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.4",
        domain: "Media Protection",
        capability: "Media markings",
        practice_statement: "Mark media with necessary CUI markings and distribution limitations.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-3"],
        sp800_171_ref: Some("3.8.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.5",
        domain: "Media Protection",
        capability: "Media accountability",
        practice_statement: "Control access to media containing CUI and maintain accountability for media during transport outside of controlled areas.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-5"],
        sp800_171_ref: Some("3.8.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.6",
        domain: "Media Protection",
        capability: "Portable storage encryption",
        practice_statement: "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport unless otherwise protected by alternative physical safeguards.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-5(4)"],
        sp800_171_ref: Some("3.8.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.7",
        domain: "Media Protection",
        capability: "Removable media",
        practice_statement: "Control the use of removable media on system components.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-7"],
        sp800_171_ref: Some("3.8.7"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.8",
        domain: "Media Protection",
        capability: "Shared media",
        practice_statement: "Prohibit the use of portable storage devices when such devices have no identifiable owner.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["MP-7(1)"],
        sp800_171_ref: Some("3.8.8"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "MP.L2-3.8.9",
        domain: "Media Protection",
        capability: "Backup protection",
        practice_statement: "Protect the confidentiality of backup CUI at storage locations.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CP-9"],
        sp800_171_ref: Some("3.8.9"),
        sp800_172_ref: None,
    },

    // =============================================================================
    // PERSONNEL SECURITY (PS) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "PS.L2-3.9.1",
        domain: "Personnel Security",
        capability: "Screen individuals",
        practice_statement: "Screen individuals prior to authorizing access to organizational systems containing CUI.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PS-3"],
        sp800_171_ref: Some("3.9.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "PS.L2-3.9.2",
        domain: "Personnel Security",
        capability: "CUI protection during personnel actions",
        practice_statement: "Ensure that organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PS-4", "PS-5"],
        sp800_171_ref: Some("3.9.2"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Personnel Security (SP 800-172)
    CmmcPractice {
        id: "PS.L3-3.9.1e",
        domain: "Personnel Security",
        capability: "Enhanced personnel screening",
        practice_statement: "Conduct organization-defined enhanced personnel screening for individuals and reassess individual positions and access to CUI at organization-defined frequency.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["PS-3(3)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.9.1e"),
    },
    CmmcPractice {
        id: "PS.L3-3.9.2e",
        domain: "Personnel Security",
        capability: "Adverse information",
        practice_statement: "Ensure that organizational systems are protected if adverse information develops or is obtained about individuals with access to CUI.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["PS-7"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.9.2e"),
    },

    // =============================================================================
    // PHYSICAL PROTECTION (PE) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "PE.L1-3.10.1",
        domain: "Physical Protection",
        capability: "Limit physical access",
        practice_statement: "Limit physical access to organizational information systems, equipment, and the respective operating environments to authorized individuals.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PE-2", "PE-4", "PE-5", "PE-6"],
        sp800_171_ref: Some("3.10.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "PE.L1-3.10.3",
        domain: "Physical Protection",
        capability: "Escort visitors",
        practice_statement: "Escort visitors and monitor visitor activity.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PE-3"],
        sp800_171_ref: Some("3.10.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "PE.L1-3.10.4",
        domain: "Physical Protection",
        capability: "Physical access logs",
        practice_statement: "Maintain audit logs of physical access.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PE-8"],
        sp800_171_ref: Some("3.10.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "PE.L1-3.10.5",
        domain: "Physical Protection",
        capability: "Manage physical access",
        practice_statement: "Control and manage physical access devices.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PE-3"],
        sp800_171_ref: Some("3.10.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "PE.L2-3.10.2",
        domain: "Physical Protection",
        capability: "Protect and monitor facility",
        practice_statement: "Protect and monitor the physical facility and support infrastructure for organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PE-2", "PE-3", "PE-6"],
        sp800_171_ref: Some("3.10.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "PE.L2-3.10.6",
        domain: "Physical Protection",
        capability: "Alternative work sites",
        practice_statement: "Enforce safeguarding measures for CUI at alternate work sites.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PE-17"],
        sp800_171_ref: Some("3.10.6"),
        sp800_172_ref: None,
    },

    // =============================================================================
    // RISK ASSESSMENT (RA) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "RA.L2-3.11.1",
        domain: "Risk Assessment",
        capability: "Risk assessments",
        practice_statement: "Periodically assess the risk to organizational operations (including mission, functions, image, or reputation), organizational assets, and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["RA-3"],
        sp800_171_ref: Some("3.11.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "RA.L2-3.11.2",
        domain: "Risk Assessment",
        capability: "Vulnerability scan",
        practice_statement: "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["RA-5"],
        sp800_171_ref: Some("3.11.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "RA.L2-3.11.3",
        domain: "Risk Assessment",
        capability: "Vulnerability remediation",
        practice_statement: "Remediate vulnerabilities in accordance with risk assessments.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["RA-5"],
        sp800_171_ref: Some("3.11.3"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Risk Assessment (SP 800-172)
    CmmcPractice {
        id: "RA.L3-3.11.1e",
        domain: "Risk Assessment",
        capability: "Threat-informed risk assessment",
        practice_statement: "Employ organization-defined sources of threat intelligence as part of a risk assessment to guide and inform the development of organizational systems, security architectures, selection of security solutions, monitoring, threat hunting, and response and recovery activities.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["RA-3(2)", "RA-3(3)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.1e"),
    },
    CmmcPractice {
        id: "RA.L3-3.11.2e",
        domain: "Risk Assessment",
        capability: "Cyber threat hunting",
        practice_statement: "Conduct cyber threat hunting activities at organization-defined frequency or following organization-defined event to search for indicators of compromise in organization-defined systems and detect, track, and disrupt threats that evade existing controls.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["RA-10"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.2e"),
    },
    CmmcPractice {
        id: "RA.L3-3.11.3e",
        domain: "Risk Assessment",
        capability: "Advanced automation",
        practice_statement: "Employ advanced automation and analytics capabilities in support of analysts to predict and identify risks to organizations, systems, and system components.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["RA-3(4)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.3e"),
    },
    CmmcPractice {
        id: "RA.L3-3.11.4e",
        domain: "Risk Assessment",
        capability: "Security solution documentation",
        practice_statement: "Document or reference in the system security plan the security solution selected, the rationale for the security solution, and the risk determination.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["PL-2"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.4e"),
    },
    CmmcPractice {
        id: "RA.L3-3.11.5e",
        domain: "Risk Assessment",
        capability: "Security effectiveness assessment",
        practice_statement: "Assess the effectiveness of security solutions at organization-defined frequency to address anticipated risk to organizational systems and the organization based on current and accumulated threat intelligence.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["CA-2(2)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.5e"),
    },
    CmmcPractice {
        id: "RA.L3-3.11.6e",
        domain: "Risk Assessment",
        capability: "Supply chain risk assessment",
        practice_statement: "Assess, respond to, and monitor supply chain risks associated with organizational systems and system components.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SR-2", "SR-3"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.6e"),
    },
    CmmcPractice {
        id: "RA.L3-3.11.7e",
        domain: "Risk Assessment",
        capability: "Supply chain risk management plan",
        practice_statement: "Develop a plan for managing supply chain risks associated with organizational systems and system components; update the plan at organization-defined frequency.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SR-2"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.11.7e"),
    },

    // =============================================================================
    // SECURITY ASSESSMENT (CA) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "CA.L2-3.12.1",
        domain: "Security Assessment",
        capability: "Security control assessment",
        practice_statement: "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CA-2"],
        sp800_171_ref: Some("3.12.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CA.L2-3.12.2",
        domain: "Security Assessment",
        capability: "Plan of action",
        practice_statement: "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities in organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CA-5"],
        sp800_171_ref: Some("3.12.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CA.L2-3.12.3",
        domain: "Security Assessment",
        capability: "Continuous monitoring",
        practice_statement: "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["CA-7"],
        sp800_171_ref: Some("3.12.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "CA.L2-3.12.4",
        domain: "Security Assessment",
        capability: "System security plan",
        practice_statement: "Develop, document, and periodically update system security plans that describe system boundaries, system environments of operation, how security requirements are implemented, and the relationships with or connections to other systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["PL-2"],
        sp800_171_ref: Some("3.12.4"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced Security Assessment (SP 800-172)
    CmmcPractice {
        id: "CA.L3-3.12.1e",
        domain: "Security Assessment",
        capability: "Penetration testing",
        practice_statement: "Conduct penetration testing at organization-defined frequency, leveraging automated scanning tools and ad hoc tests using subject matter experts.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["CA-8", "CA-8(1)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.12.1e"),
    },

    // =============================================================================
    // SYSTEM AND COMMUNICATIONS PROTECTION (SC) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "SC.L1-3.13.1",
        domain: "System and Communications Protection",
        capability: "Boundary protection",
        practice_statement: "Monitor, control, and protect organizational communications (i.e., information transmitted or received by organizational information systems) at the external boundaries and key internal boundaries of the information systems.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-7"],
        sp800_171_ref: Some("3.13.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L1-3.13.5",
        domain: "System and Communications Protection",
        capability: "Public-access system separation",
        practice_statement: "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-7"],
        sp800_171_ref: Some("3.13.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.2",
        domain: "System and Communications Protection",
        capability: "Security engineering",
        practice_statement: "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security within organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SA-8"],
        sp800_171_ref: Some("3.13.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.3",
        domain: "System and Communications Protection",
        capability: "Role separation",
        practice_statement: "Separate user functionality from system management functionality.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-2"],
        sp800_171_ref: Some("3.13.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.4",
        domain: "System and Communications Protection",
        capability: "Shared resource control",
        practice_statement: "Prevent unauthorized and unintended information transfer via shared system resources.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-4"],
        sp800_171_ref: Some("3.13.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.6",
        domain: "System and Communications Protection",
        capability: "Network communication by exception",
        practice_statement: "Deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-7(5)"],
        sp800_171_ref: Some("3.13.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.7",
        domain: "System and Communications Protection",
        capability: "Split tunneling",
        practice_statement: "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks (i.e., split tunneling).",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-7(7)"],
        sp800_171_ref: Some("3.13.7"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.8",
        domain: "System and Communications Protection",
        capability: "Data in transit",
        practice_statement: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-8"],
        sp800_171_ref: Some("3.13.8"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.9",
        domain: "System and Communications Protection",
        capability: "Connections termination",
        practice_statement: "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-10"],
        sp800_171_ref: Some("3.13.9"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.10",
        domain: "System and Communications Protection",
        capability: "Key management",
        practice_statement: "Establish and manage cryptographic keys for cryptography employed in organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-12"],
        sp800_171_ref: Some("3.13.10"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.11",
        domain: "System and Communications Protection",
        capability: "CUI encryption",
        practice_statement: "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-13"],
        sp800_171_ref: Some("3.13.11"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.12",
        domain: "System and Communications Protection",
        capability: "Collaborative device control",
        practice_statement: "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-15"],
        sp800_171_ref: Some("3.13.12"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.13",
        domain: "System and Communications Protection",
        capability: "Mobile code",
        practice_statement: "Control and monitor the use of mobile code.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-18"],
        sp800_171_ref: Some("3.13.13"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.14",
        domain: "System and Communications Protection",
        capability: "Voice over Internet Protocol",
        practice_statement: "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-19"],
        sp800_171_ref: Some("3.13.14"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.15",
        domain: "System and Communications Protection",
        capability: "Communications authenticity",
        practice_statement: "Protect the authenticity of communications sessions.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-23"],
        sp800_171_ref: Some("3.13.15"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SC.L2-3.13.16",
        domain: "System and Communications Protection",
        capability: "Data at rest",
        practice_statement: "Protect the confidentiality of CUI at rest.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SC-28"],
        sp800_171_ref: Some("3.13.16"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced System and Communications Protection (SP 800-172)
    CmmcPractice {
        id: "SC.L3-3.13.1e",
        domain: "System and Communications Protection",
        capability: "System diversity",
        practice_statement: "Create diversity in organization-defined system components to reduce the extent of malicious code propagation.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SC-29"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.13.1e"),
    },
    CmmcPractice {
        id: "SC.L3-3.13.2e",
        domain: "System and Communications Protection",
        capability: "Unpredictability",
        practice_statement: "Implement the organization-defined changes to organizational systems and system components to introduce a degree of unpredictability into operations.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SC-30"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.13.2e"),
    },
    CmmcPractice {
        id: "SC.L3-3.13.3e",
        domain: "System and Communications Protection",
        capability: "Deception",
        practice_statement: "Employ organization-defined technical and procedural means to confuse and mislead adversaries.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SC-30(4)", "SC-26"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.13.3e"),
    },
    CmmcPractice {
        id: "SC.L3-3.13.4e",
        domain: "System and Communications Protection",
        capability: "Isolation techniques",
        practice_statement: "Employ organization-defined physical isolation techniques or organization-defined logical isolation techniques in organizational systems and system components.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SC-3", "SC-7(21)", "SC-39"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.13.4e"),
    },
    CmmcPractice {
        id: "SC.L3-3.13.5e",
        domain: "System and Communications Protection",
        capability: "Distributed processing",
        practice_statement: "Distribute and relocate organization-defined system functions or resources at organization-defined frequency.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SC-36"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.13.5e"),
    },

    // =============================================================================
    // SYSTEM AND INFORMATION INTEGRITY (SI) DOMAIN
    // =============================================================================

    CmmcPractice {
        id: "SI.L1-3.14.1",
        domain: "System and Information Integrity",
        capability: "Flaw remediation",
        practice_statement: "Identify, report, and correct information and information system flaws in a timely manner.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-2"],
        sp800_171_ref: Some("3.14.1"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SI.L1-3.14.2",
        domain: "System and Information Integrity",
        capability: "Malicious code protection",
        practice_statement: "Provide protection from malicious code at appropriate locations within organizational information systems.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-3"],
        sp800_171_ref: Some("3.14.2"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SI.L1-3.14.4",
        domain: "System and Information Integrity",
        capability: "Update malicious code protection",
        practice_statement: "Update malicious code protection mechanisms when new releases are available.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-3"],
        sp800_171_ref: Some("3.14.4"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SI.L1-3.14.5",
        domain: "System and Information Integrity",
        capability: "System and file scanning",
        practice_statement: "Perform periodic scans of the information system and real-time scans of files from external sources as files are downloaded, opened, or executed.",
        levels: &[CmmcLevel::Level1, CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-3"],
        sp800_171_ref: Some("3.14.5"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SI.L2-3.14.3",
        domain: "System and Information Integrity",
        capability: "Security alerts and advisories",
        practice_statement: "Monitor system security alerts and advisories and take action in response.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-5"],
        sp800_171_ref: Some("3.14.3"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SI.L2-3.14.6",
        domain: "System and Information Integrity",
        capability: "Monitor communications",
        practice_statement: "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-4"],
        sp800_171_ref: Some("3.14.6"),
        sp800_172_ref: None,
    },
    CmmcPractice {
        id: "SI.L2-3.14.7",
        domain: "System and Information Integrity",
        capability: "Identify unauthorized use",
        practice_statement: "Identify unauthorized use of organizational systems.",
        levels: &[CmmcLevel::Level2, CmmcLevel::Level3],
        nist_controls: &["SI-4"],
        sp800_171_ref: Some("3.14.7"),
        sp800_172_ref: None,
    },

    // Level 3 Enhanced System and Information Integrity (SP 800-172)
    CmmcPractice {
        id: "SI.L3-3.14.1e",
        domain: "System and Information Integrity",
        capability: "Software integrity verification",
        practice_statement: "Verify the integrity of organization-defined security critical or essential software using root of trust mechanisms or cryptographic signatures.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SI-7", "SI-7(1)", "SI-7(6)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.1e"),
    },
    CmmcPractice {
        id: "SI.L3-3.14.2e",
        domain: "System and Information Integrity",
        capability: "Behavior monitoring",
        practice_statement: "Monitor organizational systems and system components on an ongoing basis for anomalous or suspicious behavior.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SI-4(2)", "SI-4(24)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.2e"),
    },
    CmmcPractice {
        id: "SI.L3-3.14.3e",
        domain: "System and Information Integrity",
        capability: "IoT/OT security",
        practice_statement: "Ensure that organization-defined systems and system components are included in the scope of the specified enhanced security requirements or are segregated in purpose-specific networks.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SC-7(21)", "SI-4(17)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.3e"),
    },
    CmmcPractice {
        id: "SI.L3-3.14.4e",
        domain: "System and Information Integrity",
        capability: "System refresh",
        practice_statement: "Refresh organization-defined systems and system components from a known, trusted state at organization-defined frequency.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SI-14"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.4e"),
    },
    CmmcPractice {
        id: "SI.L3-3.14.5e",
        domain: "System and Information Integrity",
        capability: "CUI storage review",
        practice_statement: "Conduct reviews of persistent organizational storage locations at organization-defined frequency and remove CUI that is no longer needed.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SI-12(3)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.5e"),
    },
    CmmcPractice {
        id: "SI.L3-3.14.6e",
        domain: "System and Information Integrity",
        capability: "Threat indicators",
        practice_statement: "Use threat indicator information and effective mitigations obtained from organization-defined external organizations to guide and inform intrusion detection and threat hunting.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SI-4(4)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.6e"),
    },
    CmmcPractice {
        id: "SI.L3-3.14.7e",
        domain: "System and Information Integrity",
        capability: "Software verification",
        practice_statement: "Verify the correctness of organization-defined security critical or essential software, firmware, and hardware components using organization-defined verification methods or techniques.",
        levels: &[CmmcLevel::Level3],
        nist_controls: &["SI-7(9)", "SI-7(10)"],
        sp800_171_ref: None,
        sp800_172_ref: Some("3.14.7e"),
    },
];

/// Get all CMMC practices
pub fn get_all_practices() -> &'static [CmmcPractice] {
    CMMC_PRACTICES
}

/// Get practices by CMMC level
pub fn get_practices_by_level(level: CmmcLevel) -> Vec<&'static CmmcPractice> {
    CMMC_PRACTICES
        .iter()
        .filter(|p| p.levels.contains(&level))
        .collect()
}

/// Get practices by domain
pub fn get_practices_by_domain(domain: &str) -> Vec<&'static CmmcPractice> {
    CMMC_PRACTICES
        .iter()
        .filter(|p| p.domain.eq_ignore_ascii_case(domain))
        .collect()
}

/// Get a practice by ID
pub fn get_practice_by_id(id: &str) -> Option<&'static CmmcPractice> {
    CMMC_PRACTICES.iter().find(|p| p.id == id)
}

/// Get practices that map to a specific NIST control
pub fn get_practices_by_nist_control(control: &str) -> Vec<&'static CmmcPractice> {
    CMMC_PRACTICES
        .iter()
        .filter(|p| p.nist_controls.iter().any(|c| nist_control_matches(c, control)))
        .collect()
}

/// Check if a NIST control matches, handling the parent-child relationship properly.
/// e.g., "AC-2" matches "AC-2", "AC-2(1)", "AC-2(2)" but NOT "AC-20" or "AC-21"
pub fn nist_control_matches(practice_control: &str, search_control: &str) -> bool {
    if practice_control == search_control {
        return true;
    }
    // Check if practice_control is a sub-control of search_control
    // e.g., "AC-2(1)" starts with "AC-2(" when searching for "AC-2"
    if practice_control.starts_with(search_control) {
        let remainder = &practice_control[search_control.len()..];
        // Must be followed by '(' for sub-control or nothing for exact match
        return remainder.starts_with('(') || remainder.is_empty();
    }
    false
}

/// Get Level 1 practices (17 basic practices - FCI protection)
pub fn get_level1_practices() -> Vec<&'static CmmcPractice> {
    get_practices_by_level(CmmcLevel::Level1)
}

/// Get Level 2 practices (110 practices - CUI protection, maps to SP 800-171)
pub fn get_level2_practices() -> Vec<&'static CmmcPractice> {
    get_practices_by_level(CmmcLevel::Level2)
}

/// Get Level 3 practices (134 practices - CUI protection against APT, includes SP 800-172)
pub fn get_level3_practices() -> Vec<&'static CmmcPractice> {
    get_practices_by_level(CmmcLevel::Level3)
}

/// Get only the enhanced practices from SP 800-172 (Level 3 only)
pub fn get_enhanced_practices() -> Vec<&'static CmmcPractice> {
    CMMC_PRACTICES
        .iter()
        .filter(|p| p.sp800_172_ref.is_some())
        .collect()
}

/// Get practice count summary
pub fn get_practice_counts() -> (usize, usize, usize) {
    let level1 = get_level1_practices().len();
    let level2 = get_level2_practices().len();
    let level3 = get_level3_practices().len();
    (level1, level2, level3)
}
