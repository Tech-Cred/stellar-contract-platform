//! Deterministic diffing of two contract interfaces.
//!
//! The diff enumerates *what changed* and assigns each change a default
//! severity. It does not claim a compatibility verdict; that is the job of
//! `observatory-compat`, which applies an explicit policy on top of these
//! changes.
//!
//! # Default severity rules
//!
//! | Change | Default severity |
//! | ------ | ---------------- |
//! | Function added | non-breaking |
//! | Function removed | breaking |
//! | Function renamed (identical signature) | breaking |
//! | Function signature changed | breaking |
//! | Function documentation only | informational |
//! | Type added | non-breaking |
//! | Type removed | breaking |
//! | Type renamed (identical shape) | breaking |
//! | Type definition changed | breaking |
//! | Type documentation only | informational |
//! | Event added | non-breaking |
//! | Event removed | breaking |
//! | Event renamed (identical shape) | breaking |
//! | Event definition changed | breaking |

use observatory_interface::ContractInterface;
use observatory_spec::{SpecEvent, SpecFunction, SpecStruct, SpecType, SpecUnion};
use serde::{Deserialize, Serialize};

/// Default severity assigned to a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Purely informational; no interface impact.
    Informational,
    /// Additive or otherwise safe.
    NonBreaking,
    /// Potentially or definitely breaks consumers.
    Breaking,
}

/// The kind of a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A function was added.
    FunctionAdded,
    /// A function was removed.
    FunctionRemoved,
    /// A function changed.
    FunctionChanged,
    /// A function was renamed (a removal and an addition with an identical
    /// signature).
    FunctionRenamed,
    /// A type was added.
    TypeAdded,
    /// A type was removed.
    TypeRemoved,
    /// A type was renamed (a removal and an addition with an identical shape).
    TypeRenamed,
    /// A type changed.
    TypeChanged,
    /// An event was added.
    EventAdded,
    /// An event was removed.
    EventRemoved,
    /// An event was renamed (a removal and an addition with an identical
    /// shape).
    EventRenamed,
    /// An event changed.
    EventChanged,
}

impl ChangeKind {
    fn rank(self) -> u8 {
        match self {
            ChangeKind::FunctionRemoved => 0,
            ChangeKind::FunctionRenamed => 1,
            ChangeKind::FunctionChanged => 2,
            ChangeKind::FunctionAdded => 3,
            ChangeKind::TypeRemoved => 4,
            ChangeKind::TypeRenamed => 5,
            ChangeKind::TypeChanged => 6,
            ChangeKind::TypeAdded => 7,
            ChangeKind::EventRemoved => 8,
            ChangeKind::EventRenamed => 9,
            ChangeKind::EventChanged => 10,
            ChangeKind::EventAdded => 11,
        }
    }
}

/// A single interface change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// The kind of change.
    pub kind: ChangeKind,
    /// Default severity.
    pub severity: Severity,
    /// A stable path, for example `function::transfer`.
    pub path: String,
    /// Human-readable detail.
    pub detail: String,
    /// Previous rendering, when applicable.
    pub old: Option<String>,
    /// New rendering, when applicable.
    pub new: Option<String>,
}

/// Aggregate counts of a diff.
///
/// [`Self::by_kind`] only contains kinds that occurred, keyed in the stable
/// [`ChangeKind`] declaration order. An absent key means zero, which keeps the
/// summary compact for CI gates.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Total number of changes.
    pub total: usize,
    /// Breaking change count.
    pub breaking: usize,
    /// Non-breaking change count.
    pub non_breaking: usize,
    /// Informational change count.
    pub informational: usize,
    /// Change count per kind.
    pub by_kind: std::collections::BTreeMap<ChangeKind, usize>,
}

/// The result of diffing two interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceDiff {
    /// All changes, deterministically ordered.
    pub changes: Vec<Change>,
    /// Aggregate counts.
    pub summary: DiffSummary,
}

impl InterfaceDiff {
    /// Whether any change is breaking.
    #[must_use]
    pub fn has_breaking_changes(&self) -> bool {
        self.summary.breaking > 0
    }

    /// Return a view containing only breaking changes.
    ///
    /// The full-diff summary is preserved so callers can report accurate
    /// counts even when the change list is filtered.
    #[must_use]
    pub fn breaking_only(&self) -> Self {
        Self {
            changes: self
                .changes
                .iter()
                .filter(|change| change.severity == Severity::Breaking)
                .cloned()
                .collect(),
            summary: self.summary.clone(),
        }
    }
}

/// Diff two canonical interfaces. The result is deterministic.
#[must_use]
pub fn diff(old: &ContractInterface, new: &ContractInterface) -> InterfaceDiff {
    let mut changes = Vec::new();
    diff_functions(old, new, &mut changes);
    diff_types(old, new, &mut changes);
    diff_events(old, new, &mut changes);

    changes.sort_by(|a, b| {
        a.kind
            .rank()
            .cmp(&b.kind.rank())
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.detail.cmp(&b.detail))
    });

    let mut summary = DiffSummary::default();
    for change in &changes {
        summary.total += 1;
        match change.severity {
            Severity::Breaking => summary.breaking += 1,
            Severity::NonBreaking => summary.non_breaking += 1,
            Severity::Informational => summary.informational += 1,
        }
        *summary.by_kind.entry(change.kind).or_insert(0) += 1;
    }
    InterfaceDiff { changes, summary }
}

/// Render a diff as deterministic Markdown, grouped by severity.
#[must_use]
pub fn render_markdown(result: &InterfaceDiff) -> String {
    let mut out = String::from("# Interface diff\n\n");
    out.push_str(&format!(
        "- Breaking: {}\n- Non-breaking: {}\n- Informational: {}\n",
        result.summary.breaking, result.summary.non_breaking, result.summary.informational
    ));
    for (severity, title) in [
        (Severity::Breaking, "Breaking"),
        (Severity::NonBreaking, "Non-breaking"),
        (Severity::Informational, "Informational"),
    ] {
        out.push_str(&format!("\n## {title}\n\n"));
        let mut any = false;
        for change in result
            .changes
            .iter()
            .filter(|change| change.severity == severity)
        {
            out.push_str(&format!("- `{}`: {}\n", change.path, change.detail));
            any = true;
        }
        if !any {
            out.push_str("_None._\n");
        }
    }
    out
}

fn diff_functions(old: &ContractInterface, new: &ContractInterface, out: &mut Vec<Change>) {
    // Same-name changes.
    for function in &old.functions {
        let Some(replacement) = new.function(&function.name) else {
            continue;
        };
        if function == replacement {
            continue;
        }
        if same_signature(function, replacement) {
            out.push(Change {
                kind: ChangeKind::FunctionChanged,
                severity: Severity::Informational,
                path: format!("function::{}", function.name),
                detail: format!("documentation of `{}` changed", function.name),
                old: None,
                new: None,
            });
        } else {
            out.push(Change {
                kind: ChangeKind::FunctionChanged,
                severity: Severity::Breaking,
                path: format!("function::{}", function.name),
                detail: describe_function_change(function, replacement),
                old: Some(render_function(function)),
                new: Some(render_function(replacement)),
            });
        }
    }

    let removed: Vec<&SpecFunction> = old
        .functions
        .iter()
        .filter(|function| new.function(&function.name).is_none())
        .collect();
    let added: Vec<&SpecFunction> = new
        .functions
        .iter()
        .filter(|function| old.function(&function.name).is_none())
        .collect();

    // Pair a removal with an addition only when their signature is identical
    // and the pairing is unambiguous (exactly one removal and one addition for
    // that signature). A signature with no parameters is too generic to anchor
    // a rename, so it is never paired. Otherwise, do not guess.
    let removed_by_signature = group_by_signature(&removed);
    let added_by_signature = group_by_signature(&added);
    let mut renamed: Vec<(&SpecFunction, &SpecFunction)> = Vec::new();
    for (signature, removals) in &removed_by_signature {
        if removals.iter().all(|function| function.inputs.is_empty()) {
            continue;
        }
        if let Some(additions) = added_by_signature.get(signature) {
            if removals.len() == 1 && additions.len() == 1 {
                renamed.push((removals[0], additions[0]));
            }
        }
    }
    renamed.sort_by(|a, b| {
        a.0.name
            .cmp(&b.0.name)
            .then_with(|| a.1.name.cmp(&b.1.name))
    });

    let paired_removed: std::collections::BTreeSet<&str> =
        renamed.iter().map(|(old, _)| old.name.as_str()).collect();
    let paired_added: std::collections::BTreeSet<&str> =
        renamed.iter().map(|(_, new)| new.name.as_str()).collect();

    for (old_function, new_function) in &renamed {
        out.push(Change {
            kind: ChangeKind::FunctionRenamed,
            severity: Severity::Breaking,
            path: format!("function::{}", old_function.name),
            detail: format!(
                "function `{}` was renamed to `{}` (identical signature; heuristic pairing)",
                old_function.name, new_function.name
            ),
            old: Some(render_function(old_function)),
            new: Some(render_function(new_function)),
        });
    }
    for function in removed {
        if paired_removed.contains(function.name.as_str()) {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::FunctionRemoved,
            severity: Severity::Breaking,
            path: format!("function::{}", function.name),
            detail: format!("function `{}` was removed", function.name),
            old: Some(render_function(function)),
            new: None,
        });
    }
    for function in added {
        if paired_added.contains(function.name.as_str()) {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::FunctionAdded,
            severity: Severity::NonBreaking,
            path: format!("function::{}", function.name),
            detail: format!("function `{}` was added", function.name),
            old: None,
            new: Some(render_function(function)),
        });
    }
}

fn group_by_signature<'a>(
    functions: &[&'a SpecFunction],
) -> std::collections::BTreeMap<String, Vec<&'a SpecFunction>> {
    let mut groups: std::collections::BTreeMap<String, Vec<&SpecFunction>> =
        std::collections::BTreeMap::new();
    for function in functions {
        groups
            .entry(signature_key(function))
            .or_default()
            .push(function);
    }
    groups
}

fn signature_key(function: &SpecFunction) -> String {
    let params = function
        .inputs
        .iter()
        .map(|input| format!("{}:{}", input.name, input.ty))
        .collect::<Vec<_>>()
        .join(",");
    format!("({params})->{}", render_outputs(&function.outputs))
}

fn diff_types(old: &ContractInterface, new: &ContractInterface, out: &mut Vec<Change>) {
    let old_types = type_map(old);
    let new_types = type_map(new);

    for (name, old_entry) in &old_types {
        if let Some(new_entry) = new_types.get(name) {
            if old_entry.render != new_entry.render {
                out.push(Change {
                    kind: ChangeKind::TypeChanged,
                    severity: Severity::Breaking,
                    path: format!("type::{name}"),
                    detail: format!("type `{name}` changed"),
                    old: Some(old_entry.render.clone()),
                    new: Some(new_entry.render.clone()),
                });
            }
        }
    }

    let removed: Vec<(&String, &TypeEntry)> = old_types
        .iter()
        .filter(|(name, _)| !new_types.contains_key(*name))
        .collect();
    let added: Vec<(&String, &TypeEntry)> = new_types
        .iter()
        .filter(|(name, _)| !old_types.contains_key(*name))
        .collect();

    // Pair a removal with an addition only when their canonical shape is
    // identical and the pairing is unambiguous (exactly one removal and one
    // addition for that shape). Otherwise, do not guess.
    let removed_by_shape = group_types_by_shape(&removed);
    let added_by_shape = group_types_by_shape(&added);
    let mut renamed: Vec<(&String, &TypeEntry, &String, &TypeEntry)> = Vec::new();
    for (shape, removals) in &removed_by_shape {
        if let Some(additions) = added_by_shape.get(shape) {
            if removals.len() == 1 && additions.len() == 1 {
                renamed.push((removals[0].0, removals[0].1, additions[0].0, additions[0].1));
            }
        }
    }
    renamed.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.2.cmp(b.2)));

    let paired_removed: std::collections::BTreeSet<&str> = renamed
        .iter()
        .map(|(old_name, _, _, _)| old_name.as_str())
        .collect();
    let paired_added: std::collections::BTreeSet<&str> = renamed
        .iter()
        .map(|(_, _, new_name, _)| new_name.as_str())
        .collect();

    for (old_name, old_entry, new_name, new_entry) in &renamed {
        out.push(Change {
            kind: ChangeKind::TypeRenamed,
            severity: Severity::Breaking,
            path: format!("type::{old_name}"),
            detail: format!(
                "type `{old_name}` was renamed to `{new_name}` (identical shape; heuristic pairing)"
            ),
            old: Some(old_entry.render.clone()),
            new: Some(new_entry.render.clone()),
        });
    }
    for (name, entry) in &removed {
        if paired_removed.contains(name.as_str()) {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::TypeRemoved,
            severity: Severity::Breaking,
            path: format!("type::{name}"),
            detail: format!("type `{name}` was removed"),
            old: Some(entry.render.clone()),
            new: None,
        });
    }
    for (name, entry) in &added {
        if paired_added.contains(name.as_str()) {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::TypeAdded,
            severity: Severity::NonBreaking,
            path: format!("type::{name}"),
            detail: format!("type `{name}` was added"),
            old: None,
            new: Some(entry.render.clone()),
        });
    }
}

fn diff_events(old: &ContractInterface, new: &ContractInterface, out: &mut Vec<Change>) {
    for event in &old.events {
        if let Some(replacement) = new
            .events
            .iter()
            .find(|candidate| candidate.name == event.name)
        {
            if event != replacement {
                out.push(Change {
                    kind: ChangeKind::EventChanged,
                    severity: Severity::Breaking,
                    path: format!("event::{}", event.name),
                    detail: format!("event `{}` changed", event.name),
                    old: Some(render_event(event)),
                    new: Some(render_event(replacement)),
                });
            }
        }
    }

    let removed: Vec<&SpecEvent> = old
        .events
        .iter()
        .filter(|event| {
            !new.events
                .iter()
                .any(|candidate| candidate.name == event.name)
        })
        .collect();
    let added: Vec<&SpecEvent> = new
        .events
        .iter()
        .filter(|event| {
            !old.events
                .iter()
                .any(|candidate| candidate.name == event.name)
        })
        .collect();

    // Pair a removal with an addition only when the prefix topics, parameters,
    // and data format match exactly and the pairing is unambiguous (exactly one
    // removal and one addition for that shape). Otherwise, do not guess.
    let removed_by_shape = group_events_by_shape(&removed);
    let added_by_shape = group_events_by_shape(&added);
    let mut renamed: Vec<(&SpecEvent, &SpecEvent)> = Vec::new();
    for (shape, removals) in &removed_by_shape {
        if let Some(additions) = added_by_shape.get(shape) {
            if removals.len() == 1 && additions.len() == 1 {
                renamed.push((removals[0], additions[0]));
            }
        }
    }
    renamed.sort_by(|a, b| {
        a.0.name
            .cmp(&b.0.name)
            .then_with(|| a.1.name.cmp(&b.1.name))
    });

    let paired_removed: std::collections::BTreeSet<&str> = renamed
        .iter()
        .map(|(event, _)| event.name.as_str())
        .collect();
    let paired_added: std::collections::BTreeSet<&str> = renamed
        .iter()
        .map(|(_, event)| event.name.as_str())
        .collect();

    for (old_event, new_event) in &renamed {
        out.push(Change {
            kind: ChangeKind::EventRenamed,
            severity: Severity::Breaking,
            path: format!("event::{}", old_event.name),
            detail: format!(
                "event `{}` was renamed to `{}` (identical shape; heuristic pairing)",
                old_event.name, new_event.name
            ),
            old: Some(render_event(old_event)),
            new: Some(render_event(new_event)),
        });
    }
    for event in &removed {
        if paired_removed.contains(event.name.as_str()) {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::EventRemoved,
            severity: Severity::Breaking,
            path: format!("event::{}", event.name),
            detail: format!("event `{}` was removed", event.name),
            old: Some(render_event(event)),
            new: None,
        });
    }
    for event in &added {
        if paired_added.contains(event.name.as_str()) {
            continue;
        }
        out.push(Change {
            kind: ChangeKind::EventAdded,
            severity: Severity::NonBreaking,
            path: format!("event::{}", event.name),
            detail: format!("event `{}` was added", event.name),
            old: None,
            new: Some(render_event(event)),
        });
    }
}

fn group_events_by_shape<'a>(
    events: &[&'a SpecEvent],
) -> std::collections::BTreeMap<String, Vec<&'a SpecEvent>> {
    let mut groups: std::collections::BTreeMap<String, Vec<&SpecEvent>> =
        std::collections::BTreeMap::new();
    for event in events {
        groups
            .entry(event_shape_key(event))
            .or_default()
            .push(event);
    }
    groups
}

fn event_shape_key(event: &SpecEvent) -> String {
    let prefix_topics = event.prefix_topics.join("\u{1f}");
    let params = event
        .params
        .iter()
        .map(|param| format!("{}:{}@{}", param.name, param.ty, param.location))
        .collect::<Vec<_>>()
        .join(",");
    format!("event[{prefix_topics}]({params}){}", event.data_format)
}

struct TypeEntry {
    render: String,
    shape: String,
}

fn type_map(interface: &ContractInterface) -> std::collections::BTreeMap<String, TypeEntry> {
    let mut map = std::collections::BTreeMap::new();
    for item in &interface.structs {
        map.insert(
            item.name.clone(),
            TypeEntry {
                render: render_struct(item),
                shape: struct_shape_key(item),
            },
        );
    }
    for item in &interface.unions {
        map.insert(
            item.name.clone(),
            TypeEntry {
                render: render_union(item),
                shape: union_shape_key(item),
            },
        );
    }
    for item in &interface.enums {
        map.insert(
            item.name.clone(),
            TypeEntry {
                render: render_enum(&item.name, &item.cases),
                shape: enum_shape_key("enum", &item.cases),
            },
        );
    }
    for item in &interface.error_enums {
        map.insert(
            item.name.clone(),
            TypeEntry {
                render: render_enum(&item.name, &item.cases),
                shape: enum_shape_key("error_enum", &item.cases),
            },
        );
    }
    map
}

fn group_types_by_shape<'a>(
    types: &[(&'a String, &'a TypeEntry)],
) -> std::collections::BTreeMap<String, Vec<(&'a String, &'a TypeEntry)>> {
    let mut groups: std::collections::BTreeMap<String, Vec<(&String, &TypeEntry)>> =
        std::collections::BTreeMap::new();
    for &(name, entry) in types {
        groups
            .entry(entry.shape.clone())
            .or_default()
            .push((name, entry));
    }
    groups
}

fn struct_shape_key(item: &SpecStruct) -> String {
    let fields = item
        .fields
        .iter()
        .map(|field| format!("{}:{}", field.name, field.ty))
        .collect::<Vec<_>>()
        .join(",");
    format!("struct({fields})")
}

fn union_shape_key(item: &SpecUnion) -> String {
    let cases = item
        .cases
        .iter()
        .map(|case| {
            let types = case
                .types
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            format!("{}({types})", case.name)
        })
        .collect::<Vec<_>>()
        .join("|");
    format!("union{{{cases}}}")
}

fn enum_shape_key(kind: &str, cases: &[observatory_spec::SpecEnumCase]) -> String {
    let cases = cases
        .iter()
        .map(|case| format!("{}={}", case.name, case.value))
        .collect::<Vec<_>>()
        .join(",");
    format!("{kind}{{{cases}}}")
}

fn same_signature(a: &SpecFunction, b: &SpecFunction) -> bool {
    a.inputs == b.inputs && a.outputs == b.outputs
}

fn describe_function_change(old: &SpecFunction, new: &SpecFunction) -> String {
    let mut parts = Vec::new();
    let max = old.inputs.len().max(new.inputs.len());
    for index in 0..max {
        match (old.inputs.get(index), new.inputs.get(index)) {
            (Some(left), Some(right)) if left.name == right.name && left.ty == right.ty => {}
            (Some(left), Some(right)) => parts.push(format!(
                "parameter {} changed from `{}: {}` to `{}: {}`",
                index + 1,
                left.name,
                left.ty,
                right.name,
                right.ty
            )),
            (Some(left), None) => parts.push(format!(
                "parameter {} `{}: {}` removed",
                index + 1,
                left.name,
                left.ty
            )),
            (None, Some(right)) => parts.push(format!(
                "parameter {} `{}: {}` added",
                index + 1,
                right.name,
                right.ty
            )),
            (None, None) => {}
        }
    }
    if old.outputs != new.outputs {
        parts.push(format!(
            "return type changed from `{}` to `{}`",
            render_outputs(&old.outputs),
            render_outputs(&new.outputs)
        ));
    }
    if parts.is_empty() {
        "documentation changed".to_string()
    } else {
        parts.join("; ")
    }
}

fn render_outputs(outputs: &[SpecType]) -> String {
    match outputs.first() {
        Some(ty) => ty.to_string(),
        None => "()".to_string(),
    }
}

fn render_function(function: &SpecFunction) -> String {
    let params = function
        .inputs
        .iter()
        .map(|input| format!("{}: {}", input.name, input.ty))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}({}) -> {}",
        function.name,
        params,
        render_outputs(&function.outputs)
    )
}

fn render_struct(item: &SpecStruct) -> String {
    let fields = item
        .fields
        .iter()
        .map(|field| format!("{}: {}", field.name, field.ty))
        .collect::<Vec<_>>()
        .join(", ");
    format!("struct {}({})", item.name, fields)
}

fn render_union(item: &SpecUnion) -> String {
    let cases = item
        .cases
        .iter()
        .map(|case| {
            if case.types.is_empty() {
                case.name.clone()
            } else {
                let types = case
                    .types
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{}({types})", case.name)
            }
        })
        .collect::<Vec<_>>()
        .join(" | ");
    format!("union {} {{ {cases} }}", item.name)
}

fn render_enum(name: &str, cases: &[observatory_spec::SpecEnumCase]) -> String {
    let cases = cases
        .iter()
        .map(|case| format!("{} = {}", case.name, case.value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("enum {name} {{ {cases} }}")
}

fn render_event(event: &SpecEvent) -> String {
    let params = event
        .params
        .iter()
        .map(|param| format!("{}: {} ({})", param.name, param.ty, param.location))
        .collect::<Vec<_>>()
        .join(", ");
    format!("event {}({})", event.name, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use observatory_spec::normalize;
    use observatory_testutil::spec::{
        spec_enum, spec_error_enum, spec_event, spec_function, spec_function_with_doc, spec_struct,
        spec_union,
    };
    use stellar_xdr::{ScSpecEntry, ScSpecEventParamLocationV0, ScSpecTypeDef};

    fn interface(entries: Vec<ScSpecEntry>) -> ContractInterface {
        ContractInterface::from_spec(normalize(entries))
    }

    /// Assert that diffing `old` against `new` yields exactly one change with the
    /// expected kind, severity, and path.
    fn assert_single_change(
        old: Vec<ScSpecEntry>,
        new: Vec<ScSpecEntry>,
        kind: ChangeKind,
        severity: Severity,
        path: &str,
    ) {
        let result = diff(&interface(old), &interface(new));
        assert_eq!(
            result.changes.len(),
            1,
            "expected exactly one change, got {:?}",
            result.changes
        );
        let change = &result.changes[0];
        assert_eq!(change.kind, kind);
        assert_eq!(change.severity, severity);
        assert_eq!(change.path, path);
    }

    #[test]
    fn detects_added_and_removed_functions() {
        let old = interface(vec![
            spec_function("keep", &[], None),
            spec_function("gone", &[], None),
        ]);
        let new = interface(vec![
            spec_function("keep", &[], None),
            spec_function("fresh", &[], None),
        ]);
        let result = diff(&old, &new);
        assert!(result
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::FunctionRemoved
                && c.path == "function::gone"
                && c.severity == Severity::Breaking));
        assert!(result
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::FunctionAdded
                && c.path == "function::fresh"
                && c.severity == Severity::NonBreaking));
        assert_eq!(result.summary.breaking, 1);
        assert_eq!(result.summary.non_breaking, 1);
        assert!(result.has_breaking_changes());
    }

    #[test]
    fn detects_parameter_and_return_changes() {
        let old = interface(vec![spec_function(
            "f",
            &[("x", ScSpecTypeDef::U32)],
            Some(ScSpecTypeDef::Bool),
        )]);
        let new = interface(vec![spec_function(
            "f",
            &[("x", ScSpecTypeDef::U64)],
            Some(ScSpecTypeDef::Bool),
        )]);
        let result = diff(&old, &new);
        let change = result
            .changes
            .iter()
            .find(|c| c.kind == ChangeKind::FunctionChanged)
            .unwrap();
        assert_eq!(change.severity, Severity::Breaking);
        assert!(change.detail.contains("parameter 1 changed"));
    }

    #[test]
    fn documentation_only_change_is_informational() {
        let function = spec_function("f", &[("x", ScSpecTypeDef::U32)], None);
        let mut with_doc = spec_function("f", &[("x", ScSpecTypeDef::U32)], None);
        if let ScSpecEntry::FunctionV0(function) = &mut with_doc {
            function.doc = stellar_xdr::StringM::try_from("hello").unwrap();
        }
        let result = diff(&interface(vec![function]), &interface(vec![with_doc]));
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].severity, Severity::Informational);
    }

    #[test]
    fn detects_type_and_event_changes() {
        let old = interface(vec![
            spec_struct("S", &[("a", ScSpecTypeDef::U32)]),
            spec_enum("E", &[("A", 0)]),
            spec_event("evt", &[], &[]),
        ]);
        let new = interface(vec![
            spec_struct("S", &[("a", ScSpecTypeDef::U64)]),
            spec_event("evt", &[], &[]),
        ]);
        let result = diff(&old, &new);
        assert!(result
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::TypeChanged));
        assert!(result
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::TypeRemoved));
        assert!(!result
            .changes
            .iter()
            .any(|c| c.kind == ChangeKind::EventRemoved || c.kind == ChangeKind::EventChanged));
    }

    #[test]
    fn identical_interfaces_have_no_changes() {
        let entries = vec![spec_function("a", &[], None), spec_struct("S", &[])];
        let result = diff(&interface(entries.clone()), &interface(entries));
        assert!(result.changes.is_empty());
        assert_eq!(result.summary.total, 0);
        assert!(result.summary.by_kind.is_empty());
    }

    #[test]
    fn summary_counts_match_the_change_list() {
        let old = interface(vec![
            spec_function("gone", &[("x", ScSpecTypeDef::U32)], None),
            spec_function("kept", &[("x", ScSpecTypeDef::U32)], None),
            spec_struct("Old", &[("a", ScSpecTypeDef::U32)]),
            spec_event("evt", &["transfer"], &[]),
        ]);
        let new = interface(vec![
            spec_function("kept", &[("x", ScSpecTypeDef::U64)], None),
            spec_function("fresh", &[], None),
            spec_struct("New", &[("a", ScSpecTypeDef::U32)]),
            spec_event("evt", &["transfer"], &[]),
        ]);
        let result = diff(&old, &new);

        assert_eq!(result.summary.total, result.changes.len());
        assert_eq!(
            result.summary.breaking,
            result
                .changes
                .iter()
                .filter(|change| change.severity == Severity::Breaking)
                .count()
        );
        assert_eq!(
            result.summary.non_breaking,
            result
                .changes
                .iter()
                .filter(|change| change.severity == Severity::NonBreaking)
                .count()
        );
        assert_eq!(
            result.summary.informational,
            result
                .changes
                .iter()
                .filter(|change| change.severity == Severity::Informational)
                .count()
        );
        for kind in result.summary.by_kind.values() {
            assert!(*kind > 0);
        }
        assert_eq!(
            result.summary.by_kind.values().sum::<usize>(),
            result.changes.len()
        );
        for change in &result.changes {
            assert!(
                result
                    .summary
                    .by_kind
                    .get(&change.kind)
                    .copied()
                    .unwrap_or(0)
                    > 0,
                "kind {:?} is missing from the summary",
                change.kind
            );
        }

        let first = serde_json::to_string(&result).unwrap();
        let second = serde_json::to_string(&diff(&old, &new)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn diff_is_deterministic() {
        let old = interface(vec![
            spec_function("b", &[], None),
            spec_function("a", &[], None),
        ]);
        let new = interface(vec![spec_function("c", &[], None)]);
        let first = diff(&old, &new);
        let second = diff(&old, &new);
        assert_eq!(first, second);
    }

    #[test]
    fn detects_unambiguous_renames() {
        let old = interface(vec![spec_function(
            "transfer",
            &[("to", ScSpecTypeDef::Address)],
            Some(ScSpecTypeDef::Bool),
        )]);
        let new = interface(vec![spec_function(
            "send",
            &[("to", ScSpecTypeDef::Address)],
            Some(ScSpecTypeDef::Bool),
        )]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::FunctionRenamed);
        assert_eq!(result.changes[0].severity, Severity::Breaking);
        assert!(result.changes[0].detail.contains("renamed"));
        assert!(result.changes[0].detail.contains("heuristic"));
    }

    #[test]
    fn identical_multi_parameter_signature_is_a_rename() {
        let old = interface(vec![spec_function(
            "swap",
            &[("a", ScSpecTypeDef::I128), ("b", ScSpecTypeDef::Address)],
            Some(ScSpecTypeDef::Bool),
        )]);
        let new = interface(vec![spec_function(
            "exchange",
            &[("a", ScSpecTypeDef::I128), ("b", ScSpecTypeDef::Address)],
            Some(ScSpecTypeDef::Bool),
        )]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::FunctionRenamed);
    }

    #[test]
    fn zero_argument_pairs_are_not_guessed_as_renames() {
        let old = interface(vec![spec_function("before", &[], None)]);
        let new = interface(vec![spec_function("after", &[], None)]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::FunctionRenamed));
        assert_eq!(result.summary.breaking, 1);
        assert_eq!(result.summary.non_breaking, 1);
    }

    #[test]
    fn different_signature_is_not_a_rename() {
        let old = interface(vec![spec_function("a", &[("x", ScSpecTypeDef::U32)], None)]);
        let new = interface(vec![spec_function("b", &[("x", ScSpecTypeDef::U64)], None)]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::FunctionRenamed));
        assert!(result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::FunctionRemoved));
        assert!(result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::FunctionAdded));
    }

    #[test]
    fn ambiguous_signature_is_not_guessed() {
        let old = interface(vec![
            spec_function("a", &[], None),
            spec_function("b", &[], None),
        ]);
        let new = interface(vec![spec_function("c", &[], None)]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::FunctionRenamed));
        assert_eq!(result.summary.breaking, 2);
        assert_eq!(result.summary.non_breaking, 1);
    }

    #[test]
    fn detects_unambiguous_struct_rename() {
        let old = interface(vec![spec_struct("OldName", &[("a", ScSpecTypeDef::U32)])]);
        let new = interface(vec![spec_struct("NewName", &[("a", ScSpecTypeDef::U32)])]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::TypeRenamed);
        assert_eq!(result.changes[0].severity, Severity::Breaking);
        assert_eq!(result.changes[0].path, "type::OldName");
        assert!(result.changes[0].detail.contains("renamed to `NewName`"));
        assert!(result.changes[0].detail.contains("heuristic"));
    }

    #[test]
    fn detects_unambiguous_enum_and_union_renames() {
        let old = interface(vec![
            spec_enum("OldEnum", &[("A", 0), ("B", 1)]),
            spec_union(
                "OldUnion",
                &[("None", None), ("Some", Some(vec![ScSpecTypeDef::U32]))],
            ),
        ]);
        let new = interface(vec![
            spec_enum("NewEnum", &[("A", 0), ("B", 1)]),
            spec_union(
                "NewUnion",
                &[("None", None), ("Some", Some(vec![ScSpecTypeDef::U32]))],
            ),
        ]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 2);
        assert!(result
            .changes
            .iter()
            .all(|change| change.kind == ChangeKind::TypeRenamed));
        assert!(result
            .changes
            .iter()
            .any(|change| change.path == "type::OldEnum" && change.detail.contains("NewEnum")));
        assert!(result
            .changes
            .iter()
            .any(|change| change.path == "type::OldUnion" && change.detail.contains("NewUnion")));
    }

    #[test]
    fn detects_unambiguous_error_enum_rename() {
        let old = interface(vec![spec_error_enum("OldError", &[("NotFound", 1)])]);
        let new = interface(vec![spec_error_enum("NewError", &[("NotFound", 1)])]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::TypeRenamed);
    }

    #[test]
    fn different_type_shape_is_not_a_rename() {
        let old = interface(vec![spec_struct("OldName", &[("a", ScSpecTypeDef::U32)])]);
        let new = interface(vec![spec_struct("NewName", &[("a", ScSpecTypeDef::U64)])]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::TypeRenamed));
        assert!(result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::TypeRemoved));
        assert!(result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::TypeAdded));
    }

    #[test]
    fn enum_and_error_enum_are_not_paired() {
        let old = interface(vec![spec_enum("OldName", &[("A", 0)])]);
        let new = interface(vec![spec_error_enum("NewName", &[("A", 0)])]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::TypeRenamed));
    }

    #[test]
    fn ambiguous_type_shape_is_not_guessed() {
        let old = interface(vec![
            spec_struct("First", &[("a", ScSpecTypeDef::U32)]),
            spec_struct("Second", &[("a", ScSpecTypeDef::U32)]),
        ]);
        let new = interface(vec![spec_struct("Third", &[("a", ScSpecTypeDef::U32)])]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::TypeRenamed));
        assert_eq!(
            result
                .changes
                .iter()
                .filter(|change| change.kind == ChangeKind::TypeRemoved)
                .count(),
            2
        );
        assert_eq!(
            result
                .changes
                .iter()
                .filter(|change| change.kind == ChangeKind::TypeAdded)
                .count(),
            1
        );
    }

    #[test]
    fn detects_unambiguous_event_rename() {
        let old = interface(vec![spec_event(
            "old_event",
            &["transfer", "v1"],
            &[(
                "amount",
                ScSpecTypeDef::I128,
                ScSpecEventParamLocationV0::Data,
            )],
        )]);
        let new = interface(vec![spec_event(
            "new_event",
            &["transfer", "v1"],
            &[(
                "amount",
                ScSpecTypeDef::I128,
                ScSpecEventParamLocationV0::Data,
            )],
        )]);
        let result = diff(&old, &new);
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].kind, ChangeKind::EventRenamed);
        assert_eq!(result.changes[0].severity, Severity::Breaking);
        assert_eq!(result.changes[0].path, "event::old_event");
        assert!(result.changes[0].detail.contains("renamed to `new_event`"));
        assert!(result.changes[0].detail.contains("heuristic"));
    }

    #[test]
    fn different_event_shape_is_not_a_rename() {
        let old = interface(vec![spec_event(
            "old_event",
            &["transfer"],
            &[(
                "amount",
                ScSpecTypeDef::I128,
                ScSpecEventParamLocationV0::Data,
            )],
        )]);
        let new = interface(vec![spec_event(
            "new_event",
            &["mint"],
            &[(
                "amount",
                ScSpecTypeDef::I128,
                ScSpecEventParamLocationV0::Data,
            )],
        )]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::EventRenamed));
        assert!(result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::EventRemoved));
        assert!(result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::EventAdded));
    }

    #[test]
    fn ambiguous_event_shape_is_not_guessed() {
        let old = interface(vec![
            spec_event("first", &["transfer"], &[]),
            spec_event("second", &["transfer"], &[]),
        ]);
        let new = interface(vec![spec_event("third", &["transfer"], &[])]);
        let result = diff(&old, &new);
        assert!(!result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::EventRenamed));
        assert_eq!(
            result
                .changes
                .iter()
                .filter(|change| change.kind == ChangeKind::EventRemoved)
                .count(),
            2
        );
        assert_eq!(
            result
                .changes
                .iter()
                .filter(|change| change.kind == ChangeKind::EventAdded)
                .count(),
            1
        );
    }

    #[test]
    fn renders_deterministic_markdown() {
        let old = interface(vec![
            spec_function("a", &[("x", ScSpecTypeDef::U32)], None),
            spec_function("b", &[], None),
        ]);
        let new = interface(vec![spec_function("a", &[("x", ScSpecTypeDef::U32)], None)]);
        let result = diff(&old, &new);
        let markdown = render_markdown(&result);
        assert!(markdown.starts_with("# Interface diff"));
        assert!(markdown.contains("## Breaking"));
        assert!(markdown.contains("`function::b`"));
        assert_eq!(markdown, render_markdown(&result));
    }

    #[test]
    fn breaking_only_keeps_summary_and_preserves_order() {
        let old = interface(vec![spec_function("removed", &[], None)]);
        let new = interface(vec![spec_function("added", &[], None)]);
        let result = diff(&old, &new);
        let filtered = result.breaking_only();

        assert_eq!(filtered.summary, result.summary);
        assert!(filtered
            .changes
            .iter()
            .all(|change| change.severity == Severity::Breaking));
        let expected: Vec<&str> = result
            .changes
            .iter()
            .filter(|change| change.severity == Severity::Breaking)
            .map(|change| change.path.as_str())
            .collect();
        let actual: Vec<&str> = filtered
            .changes
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(actual, vec!["function::removed"]);
    }

    #[test]
    fn breaking_only_without_breaking_changes_is_empty() {
        let old = interface(vec![]);
        let new = interface(vec![spec_function("added", &[], None)]);
        let result = diff(&old, &new);
        let filtered = result.breaking_only();

        assert!(filtered.changes.is_empty());
        assert_eq!(filtered.summary, result.summary);
    }

    #[test]
    fn change_kind_function_added() {
        assert_single_change(
            vec![],
            vec![spec_function("added", &[("x", ScSpecTypeDef::U32)], None)],
            ChangeKind::FunctionAdded,
            Severity::NonBreaking,
            "function::added",
        );
    }

    #[test]
    fn change_kind_function_removed() {
        assert_single_change(
            vec![spec_function("removed", &[("x", ScSpecTypeDef::U32)], None)],
            vec![],
            ChangeKind::FunctionRemoved,
            Severity::Breaking,
            "function::removed",
        );
    }

    #[test]
    fn change_kind_function_changed() {
        assert_single_change(
            vec![spec_function("changed", &[("x", ScSpecTypeDef::U32)], None)],
            vec![spec_function("changed", &[("x", ScSpecTypeDef::U64)], None)],
            ChangeKind::FunctionChanged,
            Severity::Breaking,
            "function::changed",
        );
    }

    #[test]
    fn change_kind_function_renamed() {
        assert_single_change(
            vec![spec_function(
                "old_fn",
                &[("to", ScSpecTypeDef::Address)],
                Some(ScSpecTypeDef::Bool),
            )],
            vec![spec_function(
                "new_fn",
                &[("to", ScSpecTypeDef::Address)],
                Some(ScSpecTypeDef::Bool),
            )],
            ChangeKind::FunctionRenamed,
            Severity::Breaking,
            "function::old_fn",
        );
    }

    #[test]
    fn change_kind_type_added() {
        assert_single_change(
            vec![],
            vec![spec_struct("Added", &[("a", ScSpecTypeDef::U32)])],
            ChangeKind::TypeAdded,
            Severity::NonBreaking,
            "type::Added",
        );
    }

    #[test]
    fn change_kind_type_removed() {
        assert_single_change(
            vec![spec_struct("Removed", &[("a", ScSpecTypeDef::U32)])],
            vec![],
            ChangeKind::TypeRemoved,
            Severity::Breaking,
            "type::Removed",
        );
    }

    #[test]
    fn change_kind_type_changed() {
        assert_single_change(
            vec![spec_struct("Changed", &[("a", ScSpecTypeDef::U32)])],
            vec![spec_struct("Changed", &[("a", ScSpecTypeDef::U64)])],
            ChangeKind::TypeChanged,
            Severity::Breaking,
            "type::Changed",
        );
    }

    #[test]
    fn change_kind_type_renamed() {
        assert_single_change(
            vec![spec_struct("OldName", &[("a", ScSpecTypeDef::U32)])],
            vec![spec_struct("NewName", &[("a", ScSpecTypeDef::U32)])],
            ChangeKind::TypeRenamed,
            Severity::Breaking,
            "type::OldName",
        );
    }

    #[test]
    fn change_kind_event_added() {
        assert_single_change(
            vec![],
            vec![spec_event("added", &["added"], &[])],
            ChangeKind::EventAdded,
            Severity::NonBreaking,
            "event::added",
        );
    }

    #[test]
    fn change_kind_event_removed() {
        assert_single_change(
            vec![spec_event("removed", &["removed"], &[])],
            vec![],
            ChangeKind::EventRemoved,
            Severity::Breaking,
            "event::removed",
        );
    }

    #[test]
    fn change_kind_event_changed() {
        assert_single_change(
            vec![spec_event("changed", &["one"], &[])],
            vec![spec_event("changed", &["two"], &[])],
            ChangeKind::EventChanged,
            Severity::Breaking,
            "event::changed",
        );
    }

    #[test]
    fn change_kind_event_renamed() {
        assert_single_change(
            vec![spec_event(
                "old_event",
                &["transfer", "v1"],
                &[(
                    "amount",
                    ScSpecTypeDef::I128,
                    ScSpecEventParamLocationV0::Data,
                )],
            )],
            vec![spec_event(
                "new_event",
                &["transfer", "v1"],
                &[(
                    "amount",
                    ScSpecTypeDef::I128,
                    ScSpecEventParamLocationV0::Data,
                )],
            )],
            ChangeKind::EventRenamed,
            Severity::Breaking,
            "event::old_event",
        );
    }

    #[test]
    fn change_kind_function_documentation_is_informational() {
        assert_single_change(
            vec![spec_function(
                "documented",
                &[("x", ScSpecTypeDef::U32)],
                None,
            )],
            vec![spec_function_with_doc(
                "documented",
                "docs",
                &[("x", ScSpecTypeDef::U32)],
                None,
            )],
            ChangeKind::FunctionChanged,
            Severity::Informational,
            "function::documented",
        );
    }
}
