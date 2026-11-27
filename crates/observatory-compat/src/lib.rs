//! Documented interface compatibility rules engine.
//!
//! Compatibility is a policy decision layered on top of the raw diff. The
//! engine never returns a bare boolean: it returns a status, the explicit rules
//! that fired, and the underlying changes.
//!
//! # Default (strict) rules
//!
//! A change is **incompatible** when it is a removal or a modification of an
//! existing public contract surface:
//!
//! | Rule | Default |
//! | ---- | ------- |
//! | Removing a function | incompatible |
//! | Changing a function signature (parameters or return type) | incompatible |
//! | Removing a type | incompatible |
//! | Renaming a type (identical shape) | incompatible |
//! | Changing a type definition | incompatible |
//! | Adding an enum case | incompatible by default, configurable |
//! | Removing an event | incompatible |
//! | Renaming an event (identical shape) | incompatible |
//! | Changing an event | incompatible |
//! | Adding a function, type, or event | compatible |
//! | Documentation-only changes | compatible (informational) |
//!
//! Any of the removal/modification rules can be relaxed through
//! [`CompatibilityPolicy`]. Relaxing a rule does not make the change disappear;
//! it is reported as a non-breaking note.
//!
//! Enum additions have their own rule. Adding a variant is breaking by default
//! because consumers with exhaustive matches, fixed discriminants, or stored
//! representations may reject or misread the new case. Teams that treat enums as
//! open can set [`CompatibilityPolicy::enum_case_addition_is_breaking`] to
//! `false`; that flag affects enum additions only, never struct or union changes,
//! removals, value changes, or function/event rules.
//!
//! If the baseline interface is empty there is nothing to compare against, so
//! the status is [`CompatibilityStatus::Unknown`] rather than a false verdict.

use observatory_diff::{diff, ChangeKind, InterfaceDiff, Severity};
use observatory_interface::ContractInterface;
use serde::{Deserialize, Serialize};

/// The overall compatibility verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    /// No breaking change under the active policy.
    Compatible,
    /// At least one breaking change under the active policy.
    Incompatible,
    /// There is insufficient information to decide.
    Unknown,
}

/// Configuration of the compatibility rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityPolicy {
    /// Removing a function is breaking.
    pub function_removal_is_breaking: bool,
    /// Changing a function signature is breaking.
    pub signature_change_is_breaking: bool,
    /// Removing a type is breaking.
    pub type_removal_is_breaking: bool,
    /// Changing a type definition is breaking.
    pub type_change_is_breaking: bool,
    /// Adding a case to an existing enum or error enum is breaking.
    ///
    /// The default is `true`: an added variant can break exhaustive matches and
    /// fixed discriminants in consumers. Set it to `false` only when consumers
    /// treat enums as open. This rule is independent of
    /// [`Self::type_change_is_breaking`] and applies only to case additions.
    pub enum_case_addition_is_breaking: bool,
    /// Removing an event is breaking.
    pub event_removal_is_breaking: bool,
    /// Changing an event definition is breaking.
    pub event_change_is_breaking: bool,
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        CompatibilityPolicy::strict()
    }
}

impl CompatibilityPolicy {
    /// The default strict policy.
    #[must_use]
    pub fn strict() -> Self {
        CompatibilityPolicy {
            function_removal_is_breaking: true,
            signature_change_is_breaking: true,
            type_removal_is_breaking: true,
            type_change_is_breaking: true,
            enum_case_addition_is_breaking: true,
            event_removal_is_breaking: true,
            event_change_is_breaking: true,
        }
    }

    /// A lenient policy that treats all changes as non-breaking notes.
    ///
    /// This is useful only when downstream consumers are known to tolerate any
    /// interface change; use it deliberately.
    #[must_use]
    pub fn lenient() -> Self {
        CompatibilityPolicy {
            function_removal_is_breaking: false,
            signature_change_is_breaking: false,
            type_removal_is_breaking: false,
            type_change_is_breaking: false,
            enum_case_addition_is_breaking: false,
            event_removal_is_breaking: false,
            event_change_is_breaking: false,
        }
    }

    /// Whether a change kind is breaking under this policy.
    #[must_use]
    pub fn is_breaking(&self, kind: ChangeKind) -> bool {
        match kind {
            ChangeKind::FunctionRemoved => self.function_removal_is_breaking,
            ChangeKind::FunctionRenamed | ChangeKind::FunctionChanged => {
                self.signature_change_is_breaking
            }
            ChangeKind::TypeRemoved | ChangeKind::TypeRenamed => self.type_removal_is_breaking,
            ChangeKind::TypeChanged => self.type_change_is_breaking,
            ChangeKind::EnumCaseAdded => self.enum_case_addition_is_breaking,
            ChangeKind::EventRemoved | ChangeKind::EventRenamed => self.event_removal_is_breaking,
            ChangeKind::EventChanged => self.event_change_is_breaking,
            ChangeKind::FunctionAdded | ChangeKind::TypeAdded | ChangeKind::EventAdded => false,
        }
    }
}

/// One rule outcome with its explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityReason {
    /// Whether this reason makes the interface incompatible.
    pub breaking: bool,
    /// A stable path, for example `function::transfer`.
    pub path: String,
    /// Human-readable explanation.
    pub message: String,
}

/// The result of assessing compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityAssessment {
    /// Overall verdict.
    pub status: CompatibilityStatus,
    /// The active policy.
    pub policy: CompatibilityPolicy,
    /// Reasons that contributed to the verdict, deterministically ordered.
    pub reasons: Vec<CompatibilityReason>,
    /// The underlying diff.
    pub diff: InterfaceDiff,
}

impl CompatibilityAssessment {
    /// Whether the status is [`CompatibilityStatus::Incompatible`].
    #[must_use]
    pub fn is_incompatible(&self) -> bool {
        self.status == CompatibilityStatus::Incompatible
    }
}

/// Assess compatibility of `new` relative to the `old` baseline under `policy`.
#[must_use]
pub fn assess(
    old: &ContractInterface,
    new: &ContractInterface,
    policy: CompatibilityPolicy,
) -> CompatibilityAssessment {
    let diff = diff(old, new);

    if old.is_empty() {
        return CompatibilityAssessment {
            status: CompatibilityStatus::Unknown,
            policy,
            reasons: vec![CompatibilityReason {
                breaking: false,
                path: "interface".to_string(),
                message:
                    "baseline interface is empty; there is no public surface to compare against"
                        .to_string(),
            }],
            diff,
        };
    }

    let mut reasons = Vec::new();
    let mut incompatible = false;
    for change in &diff.changes {
        if change.severity == Severity::Informational {
            continue;
        }
        let breaking = policy.is_breaking(change.kind);
        incompatible |= breaking;
        reasons.push(CompatibilityReason {
            breaking,
            path: change.path.clone(),
            message: change.detail.clone(),
        });
    }

    let status = if incompatible {
        CompatibilityStatus::Incompatible
    } else {
        CompatibilityStatus::Compatible
    };

    CompatibilityAssessment {
        status,
        policy,
        reasons,
        diff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use observatory_spec::normalize;
    use observatory_testutil::spec::{
        spec_enum, spec_error_enum, spec_event, spec_function, spec_struct, spec_union,
    };
    use stellar_xdr::{ScSpecEntry, ScSpecTypeDef};

    fn interface(entries: Vec<ScSpecEntry>) -> ContractInterface {
        ContractInterface::from_spec(normalize(entries))
    }

    #[test]
    fn removed_function_is_incompatible() {
        let old = interface(vec![
            spec_function("a", &[], None),
            spec_function("b", &[], None),
        ]);
        let new = interface(vec![spec_function("a", &[], None)]);
        let assessment = assess(&old, &new, CompatibilityPolicy::default());
        assert_eq!(assessment.status, CompatibilityStatus::Incompatible);
        assert!(assessment.is_incompatible());
        assert!(assessment
            .reasons
            .iter()
            .any(|r| r.breaking && r.path == "function::b"));
    }

    #[test]
    fn added_function_is_compatible() {
        let old = interface(vec![spec_function("a", &[], None)]);
        let new = interface(vec![
            spec_function("a", &[], None),
            spec_function("b", &[], None),
        ]);
        let assessment = assess(&old, &new, CompatibilityPolicy::default());
        assert_eq!(assessment.status, CompatibilityStatus::Compatible);
    }

    #[test]
    fn changed_signature_is_incompatible() {
        let old = interface(vec![spec_function("f", &[("x", ScSpecTypeDef::U32)], None)]);
        let new = interface(vec![spec_function("f", &[("x", ScSpecTypeDef::U64)], None)]);
        let assessment = assess(&old, &new, CompatibilityPolicy::default());
        assert_eq!(assessment.status, CompatibilityStatus::Incompatible);
    }

    #[test]
    fn type_change_is_incompatible() {
        let old = interface(vec![spec_struct("S", &[("a", ScSpecTypeDef::U32)])]);
        let new = interface(vec![spec_struct("S", &[("a", ScSpecTypeDef::U64)])]);
        assert_eq!(
            assess(&old, &new, CompatibilityPolicy::default()).status,
            CompatibilityStatus::Incompatible
        );
    }

    #[test]
    fn enum_case_addition_is_breaking_by_default() {
        let old = interface(vec![spec_enum("Status", &[("Active", 0)])]);
        let new = interface(vec![spec_enum("Status", &[("Active", 0), ("Paused", 1)])]);
        let assessment = assess(&old, &new, CompatibilityPolicy::default());
        assert_eq!(assessment.status, CompatibilityStatus::Incompatible);
        assert!(assessment.reasons.iter().any(|reason| {
            reason.breaking && reason.path == "type::Status" && reason.message.contains("Paused")
        }));
    }

    #[test]
    fn enum_addition_flag_changes_only_enum_additions() {
        let mut policy = CompatibilityPolicy::strict();
        policy.enum_case_addition_is_breaking = false;

        // An enum case addition becomes a note.
        let enum_old = interface(vec![spec_enum("Status", &[("Active", 0)])]);
        let enum_new = interface(vec![spec_enum("Status", &[("Active", 0), ("Paused", 1)])]);
        let enum_assessment = assess(&enum_old, &enum_new, policy);
        assert_eq!(enum_assessment.status, CompatibilityStatus::Compatible);
        assert!(enum_assessment
            .reasons
            .iter()
            .all(|reason| !reason.breaking));

        // Removing a case and changing a value are still generic type changes.
        let removal = assess(
            &interface(vec![spec_enum("Status", &[("Active", 0), ("Paused", 1)])]),
            &interface(vec![spec_enum("Status", &[("Active", 0)])]),
            policy,
        );
        assert_eq!(removal.status, CompatibilityStatus::Incompatible);
        let value_change = assess(
            &interface(vec![spec_enum("Status", &[("Active", 0)])]),
            &interface(vec![spec_enum("Status", &[("Active", 7)])]),
            policy,
        );
        assert_eq!(value_change.status, CompatibilityStatus::Incompatible);

        // Struct and union additions remain governed by type_change_is_breaking.
        let struct_change = assess(
            &interface(vec![spec_struct("Config", &[("a", ScSpecTypeDef::U32)])]),
            &interface(vec![spec_struct(
                "Config",
                &[("a", ScSpecTypeDef::U32), ("b", ScSpecTypeDef::U64)],
            )]),
            policy,
        );
        assert_eq!(struct_change.status, CompatibilityStatus::Incompatible);
        let union_change = assess(
            &interface(vec![spec_union("Payload", &[("None", None)])]),
            &interface(vec![spec_union(
                "Payload",
                &[("None", None), ("Some", Some(vec![ScSpecTypeDef::U32]))],
            )]),
            policy,
        );
        assert_eq!(union_change.status, CompatibilityStatus::Incompatible);

        // Function and event rules are untouched by the flag.
        let function_change = assess(
            &interface(vec![spec_function("f", &[("x", ScSpecTypeDef::U32)], None)]),
            &interface(vec![spec_function("f", &[("x", ScSpecTypeDef::U64)], None)]),
            policy,
        );
        assert_eq!(function_change.status, CompatibilityStatus::Incompatible);
        let event_removal = assess(
            &interface(vec![
                spec_function("keep", &[], None),
                spec_event("e", &[], &[]),
            ]),
            &interface(vec![spec_function("keep", &[], None)]),
            policy,
        );
        assert_eq!(event_removal.status, CompatibilityStatus::Incompatible);
    }

    #[test]
    fn error_enum_addition_follows_the_same_flag() {
        let old = interface(vec![spec_error_enum("Error", &[("NotFound", 1)])]);
        let new = interface(vec![spec_error_enum(
            "Error",
            &[("NotFound", 1), ("Denied", 2)],
        )]);
        assert_eq!(
            assess(&old, &new, CompatibilityPolicy::strict()).status,
            CompatibilityStatus::Incompatible
        );
        let mut policy = CompatibilityPolicy::strict();
        policy.enum_case_addition_is_breaking = false;
        assert_eq!(
            assess(&old, &new, policy).status,
            CompatibilityStatus::Compatible
        );
    }

    #[test]
    fn lenient_policy_accepts_removals_as_notes() {
        let old = interface(vec![
            spec_function("a", &[], None),
            spec_event("e", &[], &[]),
        ]);
        let new = interface(vec![spec_function("a", &[], None)]);
        let assessment = assess(&old, &new, CompatibilityPolicy::lenient());
        assert_eq!(assessment.status, CompatibilityStatus::Compatible);
        assert!(assessment
            .reasons
            .iter()
            .any(|r| !r.breaking && r.path == "event::e"));
    }

    #[test]
    fn empty_baseline_is_unknown() {
        let new = interface(vec![spec_function("a", &[], None)]);
        let assessment = assess(
            &ContractInterface::from_spec(Default::default()),
            &new,
            CompatibilityPolicy::default(),
        );
        assert_eq!(assessment.status, CompatibilityStatus::Unknown);
    }

    #[test]
    fn assessment_is_deterministic() {
        let old = interface(vec![
            spec_function("b", &[], None),
            spec_function("a", &[], None),
        ]);
        let new = interface(vec![spec_function("c", &[], None)]);
        let first = assess(&old, &new, CompatibilityPolicy::default());
        let second = assess(&old, &new, CompatibilityPolicy::default());
        assert_eq!(first, second);
    }
}
