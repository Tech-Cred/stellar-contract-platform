//! Bounded, deterministic contract interface and artifact heuristics.
//!
//! These checks are intentionally narrow and fully deterministic. They are
//! **not** a security audit and must not be presented as one. Heuristics marked
//! `experimental` may change or be removed.
//!
//! Each check emits a finding with a stable id so CI can suppress or track
//! individual rules.

use std::collections::{BTreeMap, BTreeSet};

use observatory_core::{ObservatoryError, Result};
use observatory_interface::ContractInterface;
use observatory_spec::{SpecSeverity, SpecType};
use observatory_wasm::{WasmReport, CONTRACT_ENV_META_SECTION, CONTRACT_META_SECTION};
use serde::{Deserialize, Serialize};

/// Overall audit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditStatus {
    /// No findings.
    Pass,
    /// Only warnings.
    Warn,
    /// At least one error.
    Error,
}

/// Severity of a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FindingSeverity {
    /// A potential issue that does not block every workflow.
    Warn,
    /// A high-confidence structural inconsistency.
    Error,
}

/// How certain the heuristic is about a reported potential issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FindingConfidence {
    /// Directly observable from the interface or artifact.
    High,
    /// Supported by the available evidence but worth reviewing.
    Medium,
    /// A heuristic signal; no conclusion should be drawn from it alone.
    Low,
}

/// A single audit finding.
///
/// Findings describe **potential issues** only. They are bounded structural
/// heuristics and never claim a confirmed vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, for example `interface.empty-name`.
    pub id: String,
    /// Severity.
    pub severity: FindingSeverity,
    /// Human-readable explanation of the potential issue.
    pub message: String,
    /// Optional stable path.
    pub path: Option<String>,
    /// Whether the rule is experimental.
    pub experimental: bool,
    /// Confidence in the heuristic result.
    pub confidence: FindingConfidence,
    /// Bounded observations backing the finding (at most two entries).
    pub evidence: Vec<String>,
    /// Non-prescriptive next step for reviewing the potential issue.
    pub recommendation: String,
}

impl Finding {
    /// Fill confidence, evidence, and recommendation from the rule guidance.
    fn with_guidance(mut self) -> Self {
        let (confidence, recommendation) = guidance_for(&self.id);
        self.confidence = confidence;
        self.recommendation = recommendation.to_string();
        let observed = self.message.clone();
        self.evidence = vec![observed.clone()];
        if let Some(path) = &self.path {
            self.evidence.push(format!("Observed at {path}"));
        }
        self.message = format!("Potential issue: {observed}");
        self
    }
}

/// Construct a finding and populate its guidance fields in one step.
macro_rules! finding {
    ($($field:ident : $value:expr),* $(,)?) => {{
        let base = Finding {
            $($field: $value,)*
            confidence: FindingConfidence::Medium,
            evidence: Vec::new(),
            recommendation: String::new(),
        };
        base.with_guidance()
    }};
}

/// The result of running heuristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    /// Overall status.
    pub status: AuditStatus,
    /// Findings, deterministically ordered by id then path.
    pub findings: Vec<Finding>,
    /// Findings hidden by a baseline suppression, counted separately.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suppressed: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// A baseline suppression file.
///
/// Suppressions are keyed by rule id and, optionally, a finding path. A
/// suppression without a path matches every finding with that rule id. Every
/// suppression states a reason so CI history explains why it exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SuppressionFile {
    /// The suppressions, in file order.
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
}

/// One baseline suppression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    /// The rule id to hide, for example `artifact.no-code`.
    pub rule: String,
    /// Exact finding path to hide; absent hides the rule at every path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Why the finding is accepted. Required and non-empty.
    pub reason: String,
    /// Last day the suppression applies (`YYYY-MM-DD`, inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

impl SuppressionFile {
    /// Validate every suppression against the rule registry and its fields.
    ///
    /// `today` is an ISO `YYYY-MM-DD` date used only to check expiry syntax;
    /// expired suppressions are inactive, not errors.
    pub fn validate(&self, today: &str) -> Result<()> {
        validate_date(today)?;
        for suppression in &self.suppressions {
            validate_rule_id(&suppression.rule)?;
            if suppression.reason.trim().is_empty() {
                return Err(ObservatoryError::invalid(format!(
                    "suppression for rule `{}` must state a reason",
                    suppression.rule
                )));
            }
            if suppression
                .path
                .as_deref()
                .is_some_and(|path| path.trim().is_empty())
            {
                return Err(ObservatoryError::invalid(format!(
                    "suppression for rule `{}` has an empty path",
                    suppression.rule
                )));
            }
            if let Some(expires) = &suppression.expires {
                validate_date(expires).map_err(|_| {
                    ObservatoryError::invalid(format!(
                        "suppression for rule `{}` has invalid expiry `{expires}`; expected YYYY-MM-DD",
                        suppression.rule
                    ))
                })?;
            }
        }
        Ok(())
    }

    fn matches(&self, finding: &Finding, today: &str) -> bool {
        self.suppressions.iter().any(|suppression| {
            suppression.rule == finding.id
                && suppression
                    .path
                    .as_ref()
                    .is_none_or(|path| finding.path.as_ref() == Some(path))
                && !suppression
                    .expires
                    .as_deref()
                    .is_some_and(|expires| expires < today)
        })
    }
}

/// Today's UTC date as `YYYY-MM-DD`, without a calendar dependency.
#[must_use]
pub fn current_utc_date() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    iso_date_from_days((seconds / 86_400) as i64)
}

fn iso_date_from_days(days: i64) -> String {
    // Civil-from-days (Howard Hinnant), proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}")
}

fn validate_date(value: &str) -> Result<()> {
    let invalid =
        || ObservatoryError::invalid(format!("invalid date `{value}`; expected YYYY-MM-DD"));
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let year: i64 = value[0..4].parse().map_err(|_| invalid())?;
    let month: u32 = value[5..7].parse().map_err(|_| invalid())?;
    let day: u32 = value[8..10].parse().map_err(|_| invalid())?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(invalid()),
    };
    if !(1..=maximum_day).contains(&day) {
        return Err(invalid());
    }
    Ok(())
}

/// Every rule id this crate can emit.
///
/// `docs/security.md` documents each one; a test asserts the two stay in sync.
pub const RULE_IDS: &[&str] = &[
    "artifact.duplicate-metadata-section",
    "artifact.memory64",
    "artifact.metadata-without-code",
    "artifact.metadata-without-contract-spec",
    "artifact.no-code",
    "artifact.no-contract-spec",
    "artifact.no-memory",
    "artifact.oversized-spec",
    "artifact.truncated-report",
    "event.too-many-prefix-topics",
    "function.duplicate-param",
    "function.empty-name",
    "function.unknown-type",
    "interface.duplicate-event",
    "interface.duplicate-function",
    "interface.duplicate-type",
    "interface.empty",
    "interface.no-functions",
    "naming.mixed-script",
    "naming.zero-width",
    "spec.error",
    "spec.info",
    "spec.warning",
    "type.duplicate-case",
    "type.duplicate-field",
];

/// Short SARIF descriptions, sorted by rule id like [`RULE_IDS`].
///
/// A test keeps the two lists in sync. These are the same bounded heuristics
/// documented in `docs/security.md`; none of them is a security certification.
const RULE_DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "artifact.duplicate-metadata-section",
        "More than one Soroban metadata section is present",
    ),
    (
        "artifact.memory64",
        "Module declares a 64-bit linear memory, which Soroban does not use",
    ),
    (
        "artifact.metadata-without-code",
        "Soroban metadata is present but the module has no code section",
    ),
    (
        "artifact.metadata-without-contract-spec",
        "Soroban metadata is present but there is no `contractspecv0` section",
    ),
    ("artifact.no-code", "Module contains no code section"),
    (
        "artifact.no-contract-spec",
        "Module has no `contractspecv0` section and may not be a Soroban contract",
    ),
    ("artifact.no-memory", "Module declares no linear memory"),
    (
        "artifact.oversized-spec",
        "Contract specification section is unusually large",
    ),
    (
        "artifact.truncated-report",
        "Import, export, or custom-section listing was truncated",
    ),
    (
        "event.too-many-prefix-topics",
        "Event declares more than two prefix topics",
    ),
    (
        "function.duplicate-param",
        "Function has duplicate parameter names",
    ),
    ("function.empty-name", "Function has an empty name"),
    (
        "function.unknown-type",
        "Function parameter references an unknown type",
    ),
    (
        "interface.duplicate-event",
        "Event name is declared more than once",
    ),
    (
        "interface.duplicate-function",
        "Function name is declared more than once",
    ),
    (
        "interface.duplicate-type",
        "Type name is declared more than once",
    ),
    ("interface.empty", "Interface declares no public entities"),
    (
        "interface.no-functions",
        "Interface declares types or events but no functions",
    ),
    (
        "naming.mixed-script",
        "Name mixes ASCII and non-ASCII letters (possible homoglyph)",
    ),
    (
        "naming.zero-width",
        "Name contains zero-width or control characters",
    ),
    (
        "spec.error",
        "Specification validation found an inconsistency",
    ),
    (
        "spec.info",
        "Specification validation found an informational issue",
    ),
    ("spec.warning", "Specification validation found a warning"),
    (
        "type.duplicate-case",
        "Union or enum declares a case more than once",
    ),
    (
        "type.duplicate-field",
        "Struct declares a field more than once",
    ),
];

/// Confidence and review guidance for every registered rule id.
///
/// Sorted by rule id like [`RULE_IDS`]; a test keeps the three lists in sync.
/// Guidance is intentionally non-prescriptive: findings flag potential issues
/// and never claim a confirmed vulnerability.
const RULE_GUIDANCE: &[(&str, FindingConfidence, &str)] = &[
    (
        "artifact.duplicate-metadata-section",
        FindingConfidence::Medium,
        "Remove duplicate Soroban metadata sections so decoders see one definition.",
    ),
    (
        "artifact.memory64",
        FindingConfidence::High,
        "Rebuild for 32-bit linear memory before targeting Soroban.",
    ),
    (
        "artifact.metadata-without-code",
        FindingConfidence::High,
        "Include executable code or remove the metadata section.",
    ),
    (
        "artifact.metadata-without-contract-spec",
        FindingConfidence::Medium,
        "Add a `contractspecv0` section or remove the metadata section.",
    ),
    (
        "artifact.no-code",
        FindingConfidence::High,
        "Include a code section or verify this is the intended artifact.",
    ),
    (
        "artifact.no-contract-spec",
        FindingConfidence::Medium,
        "Add a `contractspecv0` section when deploying a Soroban contract.",
    ),
    (
        "artifact.no-memory",
        FindingConfidence::Medium,
        "Declare linear memory if the contract needs it.",
    ),
    (
        "artifact.oversized-spec",
        FindingConfidence::Low,
        "Review the specification size and split oversized metadata where possible.",
    ),
    (
        "artifact.truncated-report",
        FindingConfidence::Medium,
        "Inspect with higher limits or a smaller artifact to see the complete listing.",
    ),
    (
        "event.too-many-prefix-topics",
        FindingConfidence::High,
        "Reduce prefix topics to at most two.",
    ),
    (
        "function.duplicate-param",
        FindingConfidence::Medium,
        "Rename duplicate parameters so callers can distinguish them.",
    ),
    (
        "function.empty-name",
        FindingConfidence::High,
        "Give the function a non-empty name.",
    ),
    (
        "function.unknown-type",
        FindingConfidence::High,
        "Check the referenced type name and declare it in the interface.",
    ),
    (
        "interface.duplicate-event",
        FindingConfidence::High,
        "Remove or rename the duplicate event declaration.",
    ),
    (
        "interface.duplicate-function",
        FindingConfidence::High,
        "Remove or rename the duplicate function declaration.",
    ),
    (
        "interface.duplicate-type",
        FindingConfidence::High,
        "Remove or rename the duplicate type declaration.",
    ),
    (
        "interface.empty",
        FindingConfidence::Medium,
        "Declare at least one public entity or remove the empty interface.",
    ),
    (
        "interface.no-functions",
        FindingConfidence::Low,
        "Add a function when the interface needs callable entry points.",
    ),
    (
        "naming.mixed-script",
        FindingConfidence::Low,
        "Use a consistent script or escape ambiguous characters.",
    ),
    (
        "naming.zero-width",
        FindingConfidence::Low,
        "Remove zero-width or control characters from names.",
    ),
    (
        "spec.error",
        FindingConfidence::High,
        "Address the specification error before publishing the interface.",
    ),
    (
        "spec.info",
        FindingConfidence::Low,
        "Review the informational specification note; no change may be required.",
    ),
    (
        "spec.warning",
        FindingConfidence::Medium,
        "Review the specification warning and update the interface if needed.",
    ),
    (
        "type.duplicate-case",
        FindingConfidence::Medium,
        "Rename duplicate cases so decoders can distinguish them.",
    ),
    (
        "type.duplicate-field",
        FindingConfidence::Medium,
        "Rename duplicate fields so decoders can distinguish them.",
    ),
];

fn rule_description(id: &str) -> &'static str {
    RULE_DESCRIPTIONS
        .iter()
        .find(|(rule, _)| *rule == id)
        .map_or("Audit rule", |(_, description)| description)
}

fn guidance_for(id: &str) -> (FindingConfidence, &'static str) {
    RULE_GUIDANCE
        .iter()
        .find(|(rule, _, _)| *rule == id)
        .map_or(
            (
                FindingConfidence::Medium,
                "Review the reported interface or artifact details.",
            ),
            |(_, confidence, recommendation)| (*confidence, *recommendation),
        )
}

/// Map an audit severity to a SARIF result level.
fn sarif_level(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Error => "error",
        FindingSeverity::Warn => "warning",
    }
}

/// Render an audit report as a deterministic SARIF 2.1.0 document.
///
/// Rules are emitted once per finding id and both rules and results are sorted,
/// so identical reports produce byte-identical documents. Findings carry a
/// `locations` entry only when the rule records a stable path. The document
/// describes bounded heuristics; it is **not** a security certification and
/// must not be presented as one.
#[must_use]
pub fn to_sarif(report: &AuditReport) -> serde_json::Value {
    let mut findings: Vec<&Finding> = report.findings.iter().collect();
    findings.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.message.cmp(&b.message))
    });

    let mut rules = Vec::new();
    let mut seen = BTreeSet::new();
    for finding in &findings {
        if seen.insert(finding.id.as_str()) {
            rules.push(serde_json::json!({
                "id": finding.id,
                "shortDescription": { "text": rule_description(&finding.id) },
                "defaultConfiguration": { "level": sarif_level(finding.severity) },
            }));
        }
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|finding| {
            let mut result = serde_json::json!({
                "ruleId": finding.id,
                "level": sarif_level(finding.severity),
                "message": { "text": finding.message },
                "properties": {
                    "confidence": finding.confidence,
                    "evidence": &finding.evidence,
                    "recommendation": &finding.recommendation,
                },
            });
            if let Some(path) = &finding.path {
                result["locations"] = serde_json::json!([
                    { "physicalLocation": { "artifactLocation": { "uri": path } } }
                ]);
            }
            result
        })
        .collect();

    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "stellar-contract-platform",
                    "informationUri": "https://github.com/AyinkxLab/stellar-contract-platform",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "note": "Bounded deterministic heuristics; this is not a security certification."
            },
        }],
    })
}

/// Rule ids that are experimental.
///
/// Experimental rules are excluded by default; enable them explicitly through
/// [`AuditConfig::enabled`].
pub const EXPERIMENTAL_RULE_IDS: &[&str] = &[
    "artifact.duplicate-metadata-section",
    "artifact.memory64",
    "artifact.metadata-without-code",
    "artifact.metadata-without-contract-spec",
    "artifact.no-contract-spec",
    "artifact.no-memory",
    "artifact.oversized-spec",
    "function.duplicate-param",
    "interface.empty",
    "interface.no-functions",
    "naming.mixed-script",
    "naming.zero-width",
    "type.duplicate-case",
    "type.duplicate-field",
];

/// Rule selection and severity overrides for the audit heuristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Rule ids to run.
    ///
    /// When absent, every non-experimental rule runs. Any rule not listed is
    /// skipped, including experimental rules listed by default nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<String>>,
    /// Replacements for a rule's default severity, keyed by rule id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub severity: BTreeMap<String, FindingSeverity>,
}

impl AuditConfig {
    /// Validate every configured rule id against [`RULE_IDS`].
    pub fn validate(&self) -> Result<()> {
        if let Some(enabled) = &self.enabled {
            for id in enabled {
                validate_rule_id(id)?;
            }
        }
        for id in self.severity.keys() {
            validate_rule_id(id)?;
        }
        Ok(())
    }

    fn apply(&self, report: AuditReport) -> AuditReport {
        let enabled: BTreeSet<&str> = match &self.enabled {
            Some(ids) => ids.iter().map(String::as_str).collect(),
            None => RULE_IDS
                .iter()
                .copied()
                .filter(|id| !EXPERIMENTAL_RULE_IDS.contains(id))
                .collect(),
        };
        let mut findings: Vec<Finding> = report
            .findings
            .into_iter()
            .filter(|finding| enabled.contains(finding.id.as_str()))
            .collect();
        for finding in &mut findings {
            if let Some(severity) = self.severity.get(&finding.id) {
                finding.severity = *severity;
            }
        }
        AuditReport::from_findings(findings)
    }
}

fn validate_rule_id(id: &str) -> Result<()> {
    if RULE_IDS.contains(&id) {
        Ok(())
    } else {
        Err(ObservatoryError::invalid(format!(
            "unknown audit rule id `{id}`; expected one of: {}",
            RULE_IDS.join(", ")
        )))
    }
}

impl AuditReport {
    fn from_findings(mut findings: Vec<Finding>) -> Self {
        findings.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.path.cmp(&b.path)));
        let status = if findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Error)
        {
            AuditStatus::Error
        } else if findings.is_empty() {
            AuditStatus::Pass
        } else {
            AuditStatus::Warn
        };
        AuditReport {
            status,
            findings,
            suppressed: 0,
        }
    }

    /// Merge two reports into one.
    #[must_use]
    pub fn merge(self, other: AuditReport) -> AuditReport {
        let mut findings = self.findings;
        findings.extend(other.findings);
        let mut report = AuditReport::from_findings(findings);
        report.suppressed = self.suppressed + other.suppressed;
        report
    }

    /// Count findings of a severity.
    #[must_use]
    pub fn count(&self, severity: FindingSeverity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }

    /// Hide findings matched by `baseline`, counting them in
    /// [`AuditReport::suppressed`].
    ///
    /// The status is recomputed from the remaining findings, so hiding the only
    /// error can turn the report into a pass. The baseline is validated first;
    /// an unknown rule id, a missing reason, or a malformed expiry is an error.
    pub fn apply_suppressions(
        self,
        baseline: &SuppressionFile,
        today: &str,
    ) -> Result<AuditReport> {
        baseline.validate(today)?;
        let mut findings = Vec::with_capacity(self.findings.len());
        let mut suppressed = self.suppressed;
        for finding in self.findings {
            if baseline.matches(&finding, today) {
                suppressed += 1;
            } else {
                findings.push(finding);
            }
        }
        let mut report = AuditReport::from_findings(findings);
        report.suppressed = suppressed;
        Ok(report)
    }
}

/// Run interface heuristics.
#[must_use]
pub fn audit_interface(interface: &ContractInterface) -> AuditReport {
    let mut findings = Vec::new();

    for issue in observatory_spec::validate(&interface.to_spec()) {
        findings.push(finding! {
            id: format!(
                "spec.{}",
                match issue.severity {
                    SpecSeverity::Error => "error",
                    SpecSeverity::Warning => "warning",
                    SpecSeverity::Info => "info",
                }
            ),
            severity: match issue.severity {
                SpecSeverity::Error => FindingSeverity::Error,
                SpecSeverity::Warning => FindingSeverity::Warn,
                SpecSeverity::Info => FindingSeverity::Warn,
            },
            message: issue.message,
            path: None,
            experimental: false,
        });
    }

    if interface.functions.is_empty() && !interface.is_empty() {
        findings.push(finding! {
            id: "interface.no-functions".to_string(),
            severity: FindingSeverity::Warn,
            message: "interface declares types or events but no functions".to_string(),
            path: None,
            experimental: true,
        });
    }

    if interface.functions.is_empty() && interface.is_empty() {
        findings.push(finding! {
            id: "interface.empty".to_string(),
            severity: FindingSeverity::Warn,
            message: "interface declares no public entities".to_string(),
            path: None,
            experimental: true,
        });
    }

    for function in &interface.functions {
        if function.name.trim().is_empty() {
            findings.push(finding! {
                id: "function.empty-name".to_string(),
                severity: FindingSeverity::Error,
                message: "a function has an empty name".to_string(),
                path: Some("function::".to_string()),
                experimental: false,
            });
        }
        let mut names: Vec<&str> = function
            .inputs
            .iter()
            .map(|input| input.name.as_str())
            .collect();
        names.sort_unstable();
        for pair in names.windows(2) {
            if !pair[0].is_empty() && pair[0] == pair[1] {
                findings.push(finding! {
                    id: "function.duplicate-param".to_string(),
                    severity: FindingSeverity::Warn,
                    message: format!(
                        "function `{}` has duplicate parameter name `{}`",
                        function.name, pair[0]
                    ),
                    path: Some(format!("function::{}", function.name)),
                    experimental: true,
                });
            }
        }
        for input in &function.inputs {
            if references_unknown(interface, &input.ty) {
                findings.push(finding! {
                    id: "function.unknown-type".to_string(),
                    severity: FindingSeverity::Error,
                    message: format!(
                        "function `{}` parameter `{}` references an unknown type",
                        function.name, input.name
                    ),
                    path: Some(format!("function::{}", function.name)),
                    experimental: false,
                });
            }
        }
    }

    for event in &interface.events {
        if event.prefix_topics.len() > 2 {
            findings.push(finding! {
                id: "event.too-many-prefix-topics".to_string(),
                severity: FindingSeverity::Error,
                message: format!(
                    "event `{}` declares {} prefix topics; the specification allows at most 2",
                    event.name,
                    event.prefix_topics.len()
                ),
                path: Some(format!("event::{}", event.name)),
                experimental: false,
            });
        }
    }

    for name in duplicate_names(interface.functions.iter().map(|item| item.name.as_str())) {
        findings.push(finding! {
            id: "interface.duplicate-function".to_string(),
            severity: FindingSeverity::Error,
            message: format!("function `{name}` is declared more than once"),
            path: Some(format!("function::{name}")),
            experimental: false,
        });
    }
    for name in duplicate_names(
        interface
            .structs
            .iter()
            .map(|item| item.name.as_str())
            .chain(interface.unions.iter().map(|item| item.name.as_str()))
            .chain(interface.enums.iter().map(|item| item.name.as_str()))
            .chain(interface.error_enums.iter().map(|item| item.name.as_str())),
    ) {
        findings.push(finding! {
            id: "interface.duplicate-type".to_string(),
            severity: FindingSeverity::Error,
            message: format!("type `{name}` is declared more than once"),
            path: Some(format!("type::{name}")),
            experimental: false,
        });
    }
    for name in duplicate_names(interface.events.iter().map(|item| item.name.as_str())) {
        findings.push(finding! {
            id: "interface.duplicate-event".to_string(),
            severity: FindingSeverity::Error,
            message: format!("event `{name}` is declared more than once"),
            path: Some(format!("event::{name}")),
            experimental: false,
        });
    }

    for item in &interface.structs {
        for name in duplicate_names(item.fields.iter().map(|field| field.name.as_str())) {
            findings.push(finding! {
                id: "type.duplicate-field".to_string(),
                severity: FindingSeverity::Warn,
                message: format!(
                    "struct `{}` declares field `{name}` more than once",
                    item.name
                ),
                path: Some(format!("type::{}", item.name)),
                experimental: true,
            });
        }
    }
    for item in &interface.unions {
        for name in duplicate_names(item.cases.iter().map(|case| case.name.as_str())) {
            findings.push(finding! {
                id: "type.duplicate-case".to_string(),
                severity: FindingSeverity::Warn,
                message: format!(
                    "union `{}` declares case `{name}` more than once",
                    item.name
                ),
                path: Some(format!("type::{}", item.name)),
                experimental: true,
            });
        }
    }
    for item in interface
        .enums
        .iter()
        .map(|item| (&item.name, &item.cases))
        .chain(
            interface
                .error_enums
                .iter()
                .map(|item| (&item.name, &item.cases)),
        )
    {
        for name in duplicate_names(item.1.iter().map(|case| case.name.as_str())) {
            findings.push(finding! {
                id: "type.duplicate-case".to_string(),
                severity: FindingSeverity::Warn,
                message: format!("enum `{}` declares case `{name}` more than once", item.0),
                path: Some(format!("type::{}", item.0)),
                experimental: true,
            });
        }
    }

    findings.extend(naming_findings(interface));

    AuditReport::from_findings(findings)
}

fn naming_findings(interface: &ContractInterface) -> Vec<Finding> {
    let mut names: Vec<(&str, &str)> = Vec::new();
    for function in &interface.functions {
        names.push(("function", function.name.as_str()));
        for input in &function.inputs {
            names.push(("function", input.name.as_str()));
        }
    }
    for item in &interface.structs {
        names.push(("type", item.name.as_str()));
        for field in &item.fields {
            names.push(("type", field.name.as_str()));
        }
    }
    for item in &interface.unions {
        names.push(("type", item.name.as_str()));
        for case in &item.cases {
            names.push(("type", case.name.as_str()));
        }
    }
    for item in interface
        .enums
        .iter()
        .map(|item| (&item.name, &item.cases))
        .chain(
            interface
                .error_enums
                .iter()
                .map(|item| (&item.name, &item.cases)),
        )
    {
        names.push(("type", item.0.as_str()));
        for case in item.1 {
            names.push(("type", case.name.as_str()));
        }
    }
    for event in &interface.events {
        names.push(("event", event.name.as_str()));
    }

    let mut seen = BTreeSet::new();
    let mut findings = Vec::new();
    for (kind, name) in names {
        if name.is_empty() || !seen.insert((kind, name)) {
            continue;
        }
        let path = format!("{kind}::{name}");
        if has_zero_width(name) {
            findings.push(finding! {
                id: "naming.zero-width".to_string(),
                severity: FindingSeverity::Warn,
                message: format!("name `{name}` contains zero-width or control characters"),
                path: Some(path),
                experimental: true,
            });
        }
        if has_mixed_script(name) {
            findings.push(finding! {
                id: "naming.mixed-script".to_string(),
                severity: FindingSeverity::Warn,
                message: format!(
                    "name `{name}` mixes ASCII and non-ASCII letters (possible homoglyph)"
                ),
                path: Some(format!("{kind}::{name}")),
                experimental: true,
            });
        }
    }
    findings
}

fn has_zero_width(name: &str) -> bool {
    name.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{00AD}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{FEFF}'
            )
    })
}

fn has_mixed_script(name: &str) -> bool {
    let mut ascii_letter = false;
    let mut non_ascii_letter = false;
    for character in name.chars() {
        if character.is_alphabetic() {
            if character.is_ascii() {
                ascii_letter = true;
            } else {
                non_ascii_letter = true;
            }
        }
    }
    ascii_letter && non_ascii_letter
}

/// Run interface heuristics under a rule configuration.
///
/// Disabled rules are skipped and severity overrides are applied. Unknown rule
/// ids are rejected.
pub fn audit_interface_with_config(
    interface: &ContractInterface,
    config: &AuditConfig,
) -> Result<AuditReport> {
    config.validate()?;
    Ok(config.apply(audit_interface(interface)))
}

/// Run artifact heuristics.
#[must_use]
pub fn audit_artifact(report: &WasmReport) -> AuditReport {
    let mut findings = Vec::new();

    if report.code_section_bytes == 0 {
        findings.push(finding! {
            id: "artifact.no-code".to_string(),
            severity: FindingSeverity::Warn,
            message: "module contains no code section".to_string(),
            path: None,
            experimental: false,
        });
    }
    if !report.has_contract_spec {
        findings.push(finding! {
            id: "artifact.no-contract-spec".to_string(),
            severity: FindingSeverity::Warn,
            message: "module has no `contractspecv0` section; it may not be a Soroban contract"
                .to_string(),
            path: None,
            experimental: true,
        });
    }
    if report.truncated {
        findings.push(finding! {
            id: "artifact.truncated-report".to_string(),
            severity: FindingSeverity::Warn,
            message: "import, export, or custom-section listing was truncated by limits"
                .to_string(),
            path: None,
            experimental: false,
        });
    }
    if report.memories.is_empty() {
        findings.push(finding! {
            id: "artifact.no-memory".to_string(),
            severity: FindingSeverity::Warn,
            message: "module declares no linear memory".to_string(),
            path: None,
            experimental: true,
        });
    }
    if report.memories.iter().any(|memory| memory.memory64) {
        findings.push(finding! {
            id: "artifact.memory64".to_string(),
            severity: FindingSeverity::Warn,
            message: "module declares a 64-bit memory (memory64 proposal); Soroban \
                      contracts use 32-bit linear memory"
                .to_string(),
            path: None,
            experimental: true,
        });
    }
    if let Some(spec_bytes) = report.contract_spec_bytes {
        if spec_bytes > 4 * 1024 * 1024 {
            findings.push(finding! {
                id: "artifact.oversized-spec".to_string(),
                severity: FindingSeverity::Warn,
                message: format!(
                    "contract specification section is unusually large ({spec_bytes} bytes)"
                ),
                path: None,
                experimental: true,
            });
        }
    }

    let metadata_sections: Vec<&str> = report
        .custom_sections
        .iter()
        .filter(|section| {
            section.name == CONTRACT_META_SECTION || section.name == CONTRACT_ENV_META_SECTION
        })
        .map(|section| section.name.as_str())
        .collect();
    if !metadata_sections.is_empty() && !report.has_contract_spec {
        findings.push(finding! {
            id: "artifact.metadata-without-contract-spec".to_string(),
            severity: FindingSeverity::Warn,
            message: "module carries Soroban metadata but no `contractspecv0` section".to_string(),
            path: None,
            experimental: true,
        });
    }
    if !metadata_sections.is_empty() && report.code_section_bytes == 0 {
        findings.push(finding! {
            id: "artifact.metadata-without-code".to_string(),
            severity: FindingSeverity::Warn,
            message: "module carries Soroban metadata but no code section".to_string(),
            path: None,
            experimental: true,
        });
    }
    let mut reported_sections = BTreeSet::new();
    let mut seen_sections = BTreeSet::new();
    for name in metadata_sections {
        if !seen_sections.insert(name) && reported_sections.insert(name) {
            findings.push(finding! {
                id: "artifact.duplicate-metadata-section".to_string(),
                severity: FindingSeverity::Warn,
                message: format!("custom section `{name}` is declared more than once"),
                path: Some(name.to_string()),
                experimental: true,
            });
        }
    }

    AuditReport::from_findings(findings)
}

/// Run artifact heuristics under a rule configuration.
///
/// Disabled rules are skipped and severity overrides are applied. Unknown rule
/// ids are rejected.
pub fn audit_artifact_with_config(
    report: &WasmReport,
    config: &AuditConfig,
) -> Result<AuditReport> {
    config.validate()?;
    Ok(config.apply(audit_artifact(report)))
}

fn duplicate_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for name in names {
        if !name.is_empty() && !seen.insert(name) {
            duplicates.insert(name);
        }
    }
    duplicates.into_iter().collect()
}

fn references_unknown(interface: &ContractInterface, ty: &SpecType) -> bool {
    match ty {
        SpecType::Udt { name } => !interface.has_type(name),
        SpecType::Option(inner) | SpecType::Vec(inner) => references_unknown(interface, inner),
        SpecType::Result { ok, error } => {
            references_unknown(interface, ok) || references_unknown(interface, error)
        }
        SpecType::Map { key, value } => {
            references_unknown(interface, key) || references_unknown(interface, value)
        }
        SpecType::Tuple(types) => types.iter().any(|ty| references_unknown(interface, ty)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use observatory_spec::normalize;
    use observatory_testutil::spec::{
        spec_enum, spec_error_enum, spec_event, spec_function, spec_struct, spec_union, ty_udt,
    };
    use observatory_testutil::{
        custom_section, encode_spec_entries, minimal_module, module_with_spec,
        CONTRACT_SPEC_SECTION,
    };
    use stellar_xdr::{ScSpecEntry, ScSpecEventParamLocationV0, ScSpecTypeDef};

    fn interface(entries: Vec<ScSpecEntry>) -> ContractInterface {
        ContractInterface::from_spec(normalize(entries))
    }

    /// Well-formed interfaces that must stay free of audit findings.
    fn interface_corpus() -> Vec<(&'static str, Vec<ScSpecEntry>)> {
        vec![
            (
                "token",
                vec![
                    spec_function(
                        "transfer",
                        &[("to", ty_udt("Recipient")), ("amount", ScSpecTypeDef::I128)],
                        Some(ScSpecTypeDef::Bool),
                    ),
                    spec_function(
                        "balance",
                        &[("owner", ScSpecTypeDef::Address)],
                        Some(ScSpecTypeDef::I128),
                    ),
                    spec_struct("Recipient", &[("address", ScSpecTypeDef::Address)]),
                    spec_enum("Status", &[("Active", 0), ("Frozen", 1)]),
                    spec_union(
                        "Change",
                        &[("None", None), ("Amount", Some(vec![ScSpecTypeDef::I128]))],
                    ),
                    spec_error_enum("Error", &[("NotAuthorized", 1)]),
                    spec_event(
                        "Transfer",
                        &["transfer"],
                        &[(
                            "amount",
                            ScSpecTypeDef::I128,
                            ScSpecEventParamLocationV0::Data,
                        )],
                    ),
                ],
            ),
            (
                "greeting",
                vec![
                    spec_function(
                        "hello",
                        &[("name", ScSpecTypeDef::String)],
                        Some(ScSpecTypeDef::Symbol),
                    ),
                    spec_struct("Greeting", &[("name", ScSpecTypeDef::String)]),
                ],
            ),
            (
                "counter",
                vec![
                    spec_function("increment", &[], None),
                    spec_function("get", &[], Some(ScSpecTypeDef::U32)),
                ],
            ),
        ]
    }

    /// A valid module with a code section, linear memory, and a contract spec.
    fn module_with_code_and_spec(entries: &[ScSpecEntry]) -> Vec<u8> {
        let mut module =
            wat::parse_str(r#"(module (memory 1) (func (export "hello")))"#).expect("valid wat");
        module.extend(custom_section(
            CONTRACT_SPEC_SECTION,
            &encode_spec_entries(entries),
        ));
        module
    }

    #[test]
    fn clean_interface_passes() {
        let report = audit_interface(&interface(vec![
            spec_function("hello", &[("to", ty_udt("Greeting"))], None),
            spec_struct("Greeting", &[("name", ScSpecTypeDef::String)]),
        ]));
        assert_eq!(report.status, AuditStatus::Pass);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn duplicate_functions_are_errors() {
        let report = audit_interface(&interface(vec![
            spec_function("a", &[], None),
            spec_function("a", &[], None),
        ]));
        assert_eq!(report.status, AuditStatus::Error);
        assert!(report.count(FindingSeverity::Error) >= 1);
    }

    #[test]
    fn unknown_type_reference_is_error() {
        let report = audit_interface(&interface(vec![spec_function(
            "f",
            &[("x", ty_udt("Missing"))],
            None,
        )]));
        assert_eq!(report.status, AuditStatus::Error);
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "function.unknown-type"));
    }

    fn module_with_metadata(entries: &[ScSpecEntry], sections: &[&str]) -> Vec<u8> {
        let mut module = module_with_code_and_spec(entries);
        for name in sections {
            module.extend(custom_section(name, &[]));
        }
        module
    }

    #[test]
    fn duplicate_interface_entries_are_errors() {
        let report = audit_interface(&interface(vec![
            spec_function("a", &[], None),
            spec_function("a", &[], None),
            spec_struct("S", &[]),
            spec_enum("S", &[("A", 0)]),
            spec_event("evt", &[], &[]),
            spec_event("evt", &[], &[]),
        ]));
        for id in [
            "interface.duplicate-function",
            "interface.duplicate-type",
            "interface.duplicate-event",
        ] {
            assert!(
                report.findings.iter().any(|finding| finding.id == id),
                "missing {id}: {:?}",
                report.findings
            );
        }
        assert_eq!(report.status, AuditStatus::Error);
    }

    #[test]
    fn duplicate_interface_entries_are_not_invented() {
        let report = audit_interface(&interface(vec![
            spec_function("a", &[], None),
            spec_struct("S", &[]),
            spec_enum("E", &[("A", 0)]),
            spec_event("evt", &[], &[]),
        ]));
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id.starts_with("interface.duplicate")));
    }

    #[test]
    fn duplicate_members_are_warnings() {
        let report = audit_interface(&interface(vec![
            spec_struct("S", &[("a", ScSpecTypeDef::U32), ("a", ScSpecTypeDef::U32)]),
            spec_union("U", &[("A", None), ("A", Some(vec![ScSpecTypeDef::U32]))]),
            spec_enum("E", &[("A", 0), ("A", 1)]),
        ]));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.id == "type.duplicate-field"));
        assert!(
            report
                .findings
                .iter()
                .filter(|finding| finding.id == "type.duplicate-case")
                .count()
                >= 2
        );
    }

    #[test]
    fn duplicate_members_are_not_invented() {
        let report = audit_interface(&interface(vec![
            spec_struct("S", &[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U32)]),
            spec_union("U", &[("A", None), ("B", None)]),
            spec_enum("E", &[("A", 0), ("B", 1)]),
        ]));
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id == "type.duplicate-field"
                || finding.id == "type.duplicate-case"));
    }

    #[test]
    fn artifact_metadata_without_spec_is_reported() {
        let mut module =
            wat::parse_str(r#"(module (memory 1) (func (export "hello")))"#).expect("valid wat");
        module.extend(custom_section(observatory_wasm::CONTRACT_META_SECTION, &[]));
        let report = audit_artifact(&observatory_wasm::inspect(&module).unwrap());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.metadata-without-contract-spec"));

        let clean = module_with_metadata(
            &[spec_function("hello", &[], None)],
            &[CONTRACT_META_SECTION],
        );
        let report = audit_artifact(&observatory_wasm::inspect(&clean).unwrap());
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.metadata-without-contract-spec"));
    }

    #[test]
    fn artifact_metadata_without_code_is_reported() {
        let mut module = module_with_spec(&[spec_function("hello", &[], None)]);
        module.extend(custom_section(CONTRACT_META_SECTION, &[]));
        let report = audit_artifact(&observatory_wasm::inspect(&module).unwrap());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.metadata-without-code"));

        let clean = module_with_metadata(
            &[spec_function("hello", &[], None)],
            &[CONTRACT_META_SECTION],
        );
        let report = audit_artifact(&observatory_wasm::inspect(&clean).unwrap());
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.metadata-without-code"));
    }

    #[test]
    fn duplicate_metadata_sections_are_reported_once() {
        let module = module_with_metadata(
            &[spec_function("hello", &[], None)],
            &[CONTRACT_META_SECTION, CONTRACT_META_SECTION],
        );
        let report = audit_artifact(&observatory_wasm::inspect(&module).unwrap());
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.id == "artifact.duplicate-metadata-section")
                .count(),
            1
        );

        let clean = module_with_metadata(
            &[spec_function("hello", &[], None)],
            &[CONTRACT_META_SECTION],
        );
        let report = audit_artifact(&observatory_wasm::inspect(&clean).unwrap());
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.duplicate-metadata-section"));
    }

    #[test]
    fn artifact_without_spec_warns() {
        let wasm = module_with_spec(&[spec_function("f", &[], None)]);
        let inspected = observatory_wasm::inspect(&wasm).unwrap();
        let report = audit_artifact(&inspected);
        assert_eq!(report.status, AuditStatus::Warn);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.id == "artifact.no-contract-spec"));
        let empty = observatory_wasm::inspect(&minimal_module()).unwrap();
        let report = audit_artifact(&empty);
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "artifact.no-contract-spec"));
    }

    #[test]
    fn false_positive_corpus_is_clean() {
        for (name, entries) in interface_corpus() {
            let report = audit_interface(&interface(entries));
            assert!(
                report.status == AuditStatus::Pass && report.findings.is_empty(),
                "false positive in interface fixture `{name}`: {:?}",
                report.findings
            );
        }
        for (name, entries) in interface_corpus() {
            let wasm = module_with_code_and_spec(&entries);
            let inspected = observatory_wasm::inspect(&wasm).unwrap();
            let report = audit_artifact(&inspected);
            assert!(
                report.status == AuditStatus::Pass && report.findings.is_empty(),
                "false positive in artifact fixture `{name}`: {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn merge_is_deterministic() {
        let a = audit_interface(&interface(vec![spec_function("a", &[], None)]));
        let b = audit_artifact(&observatory_wasm::inspect(&minimal_module()).unwrap());
        let first = a.clone().merge(b.clone());
        let second = a.merge(b);
        assert_eq!(first, second);
    }

    fn finding(id: &str, path: Option<&str>, level: FindingSeverity) -> Finding {
        finding! {
            id: id.to_string(),
            severity: level,
            message: "test finding".to_string(),
            path: path.map(str::to_string),
            experimental: false,
        }
    }

    fn suppression(
        rule: &str,
        path: Option<&str>,
        reason: &str,
        expires: Option<&str>,
    ) -> Suppression {
        Suppression {
            rule: rule.to_string(),
            path: path.map(str::to_string),
            reason: reason.to_string(),
            expires: expires.map(str::to_string),
        }
    }

    #[test]
    fn suppressions_hide_findings_and_count_them_separately() {
        let report = AuditReport::from_findings(vec![
            finding("spec.error", None, FindingSeverity::Error),
            finding("artifact.no-code", None, FindingSeverity::Warn),
        ]);
        let baseline = SuppressionFile {
            suppressions: vec![suppression("spec.error", None, "accepted upstream", None)],
        };

        let suppressed = report.apply_suppressions(&baseline, "2026-01-01").unwrap();

        assert_eq!(suppressed.findings.len(), 1);
        assert_eq!(suppressed.findings[0].id, "artifact.no-code");
        assert_eq!(suppressed.suppressed, 1);
        assert_eq!(suppressed.status, AuditStatus::Warn);
    }

    #[test]
    fn suppressing_the_only_error_recomputes_the_status() {
        let report =
            AuditReport::from_findings(vec![finding("spec.error", None, FindingSeverity::Error)]);
        let baseline = SuppressionFile {
            suppressions: vec![suppression(
                "spec.error",
                None,
                "known false positive",
                None,
            )],
        };
        let suppressed = report.apply_suppressions(&baseline, "2026-01-01").unwrap();
        assert!(suppressed.findings.is_empty());
        assert_eq!(suppressed.status, AuditStatus::Pass);
        assert_eq!(suppressed.suppressed, 1);
    }

    #[test]
    fn a_path_suppression_only_matches_that_path() {
        let report = AuditReport::from_findings(vec![
            finding(
                "function.empty-name",
                Some("function::a"),
                FindingSeverity::Error,
            ),
            finding(
                "function.empty-name",
                Some("function::b"),
                FindingSeverity::Error,
            ),
        ]);
        let baseline = SuppressionFile {
            suppressions: vec![suppression(
                "function.empty-name",
                Some("function::a"),
                "generated stub",
                None,
            )],
        };
        let suppressed = report.apply_suppressions(&baseline, "2026-01-01").unwrap();
        assert_eq!(suppressed.findings.len(), 1);
        assert_eq!(suppressed.findings[0].path.as_deref(), Some("function::b"));
        assert_eq!(suppressed.suppressed, 1);
    }

    #[test]
    fn expired_suppressions_are_inactive() {
        let report = AuditReport::from_findings(vec![finding(
            "artifact.no-code",
            None,
            FindingSeverity::Warn,
        )]);
        let baseline = SuppressionFile {
            suppressions: vec![suppression(
                "artifact.no-code",
                None,
                "temporary waiver",
                Some("2025-12-31"),
            )],
        };

        let expired = report
            .clone()
            .apply_suppressions(&baseline, "2026-01-01")
            .unwrap();
        assert_eq!(expired.findings.len(), 1);
        assert_eq!(expired.suppressed, 0);

        let last_day = report.apply_suppressions(&baseline, "2025-12-31").unwrap();
        assert!(last_day.findings.is_empty());
        assert_eq!(last_day.suppressed, 1);
    }

    #[test]
    fn invalid_suppression_files_are_rejected() {
        let report = AuditReport::from_findings(vec![finding(
            "artifact.no-code",
            None,
            FindingSeverity::Warn,
        )]);

        for (baseline, needle) in [
            (
                SuppressionFile {
                    suppressions: vec![suppression("artifact.nope", None, "reason", None)],
                },
                "unknown audit rule id `artifact.nope`",
            ),
            (
                SuppressionFile {
                    suppressions: vec![suppression("artifact.no-code", None, "  ", None)],
                },
                "must state a reason",
            ),
            (
                SuppressionFile {
                    suppressions: vec![suppression(
                        "artifact.no-code",
                        None,
                        "reason",
                        Some("2026-13-01"),
                    )],
                },
                "invalid expiry",
            ),
            (
                SuppressionFile {
                    suppressions: vec![suppression("artifact.no-code", Some(" "), "reason", None)],
                },
                "empty path",
            ),
        ] {
            let error = report
                .clone()
                .apply_suppressions(&baseline, "2026-01-01")
                .unwrap_err();
            assert!(error.to_string().contains(needle), "{error}");
        }
    }

    #[test]
    fn merge_sums_suppressed_counts() {
        let baseline = SuppressionFile {
            suppressions: vec![suppression("artifact.no-code", None, "reason", None)],
        };
        let report = AuditReport::from_findings(vec![finding(
            "artifact.no-code",
            None,
            FindingSeverity::Warn,
        )]);
        let a = report
            .clone()
            .apply_suppressions(&baseline, "2026-01-01")
            .unwrap();
        let merged = a.merge(report);
        assert_eq!(merged.suppressed, 1);
        assert_eq!(merged.findings.len(), 1);
    }

    #[test]
    fn iso_dates_are_computed_without_a_calendar_dependency() {
        assert_eq!(iso_date_from_days(0), "1970-01-01");
        assert_eq!(iso_date_from_days(19_782), "2024-02-29");
        let today = current_utc_date();
        assert!(validate_date(&today).is_ok(), "{today}");
        assert!(validate_date("2023-02-29").is_err());
        assert!(validate_date("2024-02-29").is_ok());
        assert!(validate_date("2026-1-01").is_err());
    }

    #[test]
    fn registered_rule_ids_are_sorted_and_unique() {
        let mut sorted = RULE_IDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, RULE_IDS);
    }

    #[test]
    fn experimental_ids_are_registered_and_sorted() {
        let mut sorted = EXPERIMENTAL_RULE_IDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, EXPERIMENTAL_RULE_IDS);
        for id in EXPERIMENTAL_RULE_IDS {
            assert!(
                RULE_IDS.contains(id),
                "unregistered experimental rule `{id}`"
            );
        }
    }

    #[test]
    fn default_config_skips_experimental_rules() {
        let wasm = observatory_wasm::inspect(&minimal_module()).unwrap();
        let report = audit_artifact_with_config(&wasm, &AuditConfig::default()).unwrap();
        assert!(report.findings.iter().all(|finding| !finding.experimental));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.no-code"));
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.id == "artifact.no-contract-spec"));
    }

    #[test]
    fn unlisted_rules_are_skipped() {
        let wasm = observatory_wasm::inspect(&minimal_module()).unwrap();
        let config = AuditConfig {
            enabled: Some(vec!["artifact.no-contract-spec".to_string()]),
            severity: BTreeMap::new(),
        };
        let report = audit_artifact_with_config(&wasm, &config).unwrap();
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec!["artifact.no-contract-spec"]
        );
    }

    #[test]
    fn severity_override_changes_the_status() {
        let wasm = observatory_wasm::inspect(&minimal_module()).unwrap();
        let config = AuditConfig {
            enabled: Some(vec!["artifact.no-code".to_string()]),
            severity: BTreeMap::from([("artifact.no-code".to_string(), FindingSeverity::Error)]),
        };
        let report = audit_artifact_with_config(&wasm, &config).unwrap();
        assert_eq!(report.status, AuditStatus::Error);
        assert_eq!(report.findings[0].severity, FindingSeverity::Error);
    }

    #[test]
    fn unknown_rule_ids_are_rejected() {
        let wasm = observatory_wasm::inspect(&minimal_module()).unwrap();
        let enabled = AuditConfig {
            enabled: Some(vec!["artifact.nope".to_string()]),
            severity: BTreeMap::new(),
        };
        let error = audit_artifact_with_config(&wasm, &enabled).unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown audit rule id `artifact.nope`"));

        let severity = AuditConfig {
            enabled: None,
            severity: BTreeMap::from([("artifact.nope".to_string(), FindingSeverity::Warn)]),
        };
        let error = audit_artifact_with_config(&wasm, &severity).unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown audit rule id `artifact.nope`"));
    }

    #[test]
    fn every_registered_rule_is_documented() {
        let doc = include_str!("../../../docs/security.md");
        for id in RULE_IDS {
            assert!(
                doc.contains(&format!("`{id}`")),
                "rule `{id}` is missing from docs/security.md"
            );
        }
    }

    #[test]
    fn emitted_rule_ids_are_registered() {
        let report = audit_interface(&interface(vec![
            spec_function(
                "",
                &[("x", ty_udt("Missing")), ("x", ScSpecTypeDef::U32)],
                None,
            ),
            spec_function("a", &[], None),
            spec_function("a", &[], None),
            spec_struct("S", &[("f", ScSpecTypeDef::U32), ("f", ScSpecTypeDef::U32)]),
            spec_enum("E", &[("A", 0), ("A", 1)]),
        ]));
        let artifact = audit_artifact(&observatory_wasm::inspect(&minimal_module()).unwrap());
        for finding in report.findings.iter().chain(&artifact.findings) {
            assert!(
                RULE_IDS.contains(&finding.id.as_str()),
                "unregistered rule id `{}`",
                finding.id
            );
        }
    }

    #[test]
    fn naming_heuristics_are_experimental_and_implemented() {
        assert!(has_mixed_script("\u{0430}mount"));
        assert!(!has_mixed_script("amount"));
        assert!(has_zero_width("Pay\u{200B}load"));
        assert!(!has_zero_width("Payload"));

        for id in ["naming.mixed-script", "naming.zero-width"] {
            assert!(RULE_IDS.contains(&id), "{id} must be registered");
            assert!(
                EXPERIMENTAL_RULE_IDS.contains(&id),
                "{id} must be experimental"
            );
        }

        let default = AuditConfig::default();
        let report = default.apply(AuditReport::from_findings(vec![finding! {
            id: "naming.mixed-script".to_string(),
            severity: FindingSeverity::Warn,
            message: "test".to_string(),
            path: None,
            experimental: true,
        }]));
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.id.starts_with("naming.")),
            "experimental naming rules must be off by default"
        );
    }

    #[test]
    fn rule_descriptions_cover_the_registry() {
        let ids: Vec<&str> = RULE_DESCRIPTIONS.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, RULE_IDS);
        for (id, description) in RULE_DESCRIPTIONS {
            assert!(!description.trim().is_empty(), "empty description for {id}");
        }
    }

    #[test]
    fn every_rule_has_confidence_and_recommendation() {
        let ids: Vec<&str> = RULE_GUIDANCE.iter().map(|(id, _, _)| *id).collect();
        assert_eq!(ids, RULE_IDS);
        for (id, _, recommendation) in RULE_GUIDANCE {
            assert!(!recommendation.trim().is_empty(), "empty guidance for {id}");
            let item = finding! {
                id: (*id).to_string(),
                severity: FindingSeverity::Warn,
                message: "observed value".to_string(),
                path: None,
                experimental: false,
            };
            assert!(item.message.starts_with("Potential issue:"));
            assert_eq!(item.recommendation, *recommendation);
            assert_eq!(item.evidence, vec!["observed value".to_string()]);
            assert!(!item.message.contains("confirmed vulnerability"));
        }
    }

    #[test]
    fn emitted_findings_carry_bounded_evidence() {
        let reports = vec![
            audit_interface(&interface(vec![
                spec_function("", &[("x", ty_udt("Missing"))], None),
                spec_function("a", &[], None),
                spec_function("a", &[], None),
            ])),
            audit_artifact(&observatory_wasm::inspect(&minimal_module()).unwrap()),
        ];
        let mut checked = 0;
        for report in reports {
            for item in &report.findings {
                checked += 1;
                assert!(item.message.starts_with("Potential issue:"));
                assert!((1..=2).contains(&item.evidence.len()));
                assert!(!item.recommendation.trim().is_empty());
                assert!(RULE_GUIDANCE.iter().any(|(id, _, _)| *id == item.id));
            }
        }
        assert!(checked > 0, "fixtures should produce findings");
    }

    #[test]
    fn sarif_document_has_a_valid_structure() {
        let report = AuditReport::from_findings(vec![
            finding(
                "function.empty-name",
                Some("function::"),
                FindingSeverity::Error,
            ),
            finding("artifact.no-code", None, FindingSeverity::Warn),
            finding(
                "function.empty-name",
                Some("function::second"),
                FindingSeverity::Error,
            ),
        ]);
        let document = to_sarif(&report);

        assert_eq!(document["version"], "2.1.0");
        assert_eq!(
            document["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        let runs = document["runs"].as_array().expect("runs array");
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        assert!(run["tool"]["driver"]["name"]
            .as_str()
            .is_some_and(|name| !name.is_empty()));
        assert!(run["properties"]["note"]
            .as_str()
            .is_some_and(|note| note.contains("not a security certification")));

        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert!(!rules.is_empty());
        let mut rule_ids = Vec::new();
        for rule in rules {
            let id = rule["id"].as_str().expect("rule id");
            assert!(RULE_IDS.contains(&id), "unregistered rule id `{id}`");
            assert!(rule["shortDescription"]["text"]
                .as_str()
                .is_some_and(|text| !text.is_empty()));
            assert!(matches!(
                rule["defaultConfiguration"]["level"].as_str(),
                Some("error" | "warning" | "note" | "none")
            ));
            rule_ids.push(id.to_string());
        }
        let mut sorted_rules = rule_ids.clone();
        sorted_rules.sort();
        sorted_rules.dedup();
        assert_eq!(rule_ids, sorted_rules, "rules must be sorted and unique");

        let results = run["results"].as_array().expect("results array");
        assert_eq!(results.len(), report.findings.len());
        let mut result_keys = Vec::new();
        for result in results {
            let rule_id = result["ruleId"].as_str().expect("result rule id");
            assert!(
                rule_ids.iter().any(|id| id == rule_id),
                "result references an undeclared rule `{rule_id}`"
            );
            assert!(matches!(
                result["level"].as_str(),
                Some("error" | "warning" | "note" | "none")
            ));
            assert!(!result["message"]["text"]
                .as_str()
                .expect("result message")
                .is_empty());
            match result["locations"].as_array() {
                Some(locations) => {
                    assert_eq!(locations.len(), 1);
                    result_keys.push(format!(
                        "{rule_id}|{}",
                        locations[0]["physicalLocation"]["artifactLocation"]["uri"]
                            .as_str()
                            .expect("location uri")
                    ));
                }
                None => result_keys.push(format!("{rule_id}|")),
            }
        }
        let mut sorted_results = result_keys.clone();
        sorted_results.sort();
        assert_eq!(result_keys, sorted_results, "results must be sorted");
        assert_eq!(
            result_keys,
            vec![
                "artifact.no-code|",
                "function.empty-name|function::",
                "function.empty-name|function::second",
            ]
        );
    }

    #[test]
    fn sarif_output_is_deterministic() {
        let findings = vec![
            finding("artifact.no-code", None, FindingSeverity::Warn),
            finding(
                "function.empty-name",
                Some("function::b"),
                FindingSeverity::Error,
            ),
            finding(
                "function.empty-name",
                Some("function::a"),
                FindingSeverity::Error,
            ),
        ];
        let first = to_sarif(&AuditReport::from_findings(findings.clone()));
        let second = to_sarif(&AuditReport::from_findings(findings));
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
    }
}
