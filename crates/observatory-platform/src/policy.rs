//! Compatibility policy documents.
//!
//! A policy document spells out the rules that the `strict` and `lenient`
//! presets encode. It uses the same file formats and strict validation as the
//! project configuration: unknown fields are rejected so a typo cannot silently
//! relax a rule.

use std::path::Path;

use observatory_compat::CompatibilityPolicy;
use observatory_core::{ObservatoryError, Result};

use crate::ConfigFormat;

/// Parse a compatibility policy document from text.
pub fn parse_policy(input: &str, format: ConfigFormat) -> Result<CompatibilityPolicy> {
    let parsed = match format {
        ConfigFormat::Yaml => serde_yaml_ng::from_str(input).map_err(|error| error.to_string()),
        ConfigFormat::Toml => toml::from_str(input).map_err(|error| error.to_string()),
        ConfigFormat::Json => serde_json::from_str(input).map_err(|error| error.to_string()),
    };
    parsed.map_err(|error| {
        ObservatoryError::invalid(format!("invalid compatibility policy: {error}"))
    })
}

/// Load a compatibility policy document, inferring the format from the path.
pub fn load_policy(path: &Path) -> Result<CompatibilityPolicy> {
    let format = ConfigFormat::from_path(path)?;
    let text = std::fs::read_to_string(path).map_err(|error| {
        ObservatoryError::invalid(format!("cannot read `{}`: {error}", path.display()))
    })?;
    parse_policy(&text, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT_YAML: &str = "\
function_removal_is_breaking: true
signature_change_is_breaking: true
type_removal_is_breaking: true
type_change_is_breaking: true
event_removal_is_breaking: true
event_change_is_breaking: true
";

    const LENIENT_YAML: &str = "\
function_removal_is_breaking: false
signature_change_is_breaking: false
type_removal_is_breaking: false
type_change_is_breaking: false
struct_field_addition_is_breaking: false
event_removal_is_breaking: false
event_change_is_breaking: false
";

    #[test]
    fn parses_a_valid_policy() {
        let policy = parse_policy(STRICT_YAML, ConfigFormat::Yaml).unwrap();
        assert!(policy.function_removal_is_breaking);
        assert!(policy.event_change_is_breaking);
    }

    #[test]
    fn struct_field_addition_rule_defaults_to_strict_when_omitted() {
        let legacy = "\
function_removal_is_breaking: true
signature_change_is_breaking: true
type_removal_is_breaking: true
type_change_is_breaking: true
event_removal_is_breaking: true
event_change_is_breaking: true
";
        let parsed = parse_policy(legacy, ConfigFormat::Yaml).unwrap();
        assert!(parsed.struct_field_addition_is_breaking);
    }

    #[test]
    fn rejects_unknown_fields_by_name() {
        let input = format!("{STRICT_YAML}event_addition_is_breaking: true\n");
        let error = parse_policy(&input, ConfigFormat::Yaml).unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
        let message = error.to_string();
        assert!(message.contains("event_addition_is_breaking"), "{message}");
        assert!(message.contains("unknown field"), "{message}");
    }

    #[test]
    fn rejects_invalid_values_by_field() {
        let input = STRICT_YAML.replace(
            "function_removal_is_breaking: true",
            "function_removal_is_breaking: sometimes",
        );
        let error = parse_policy(&input, ConfigFormat::Yaml).unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
        let message = error.to_string();
        assert!(
            message.contains("function_removal_is_breaking"),
            "{message}"
        );
        assert!(message.contains("boolean"), "{message}");
    }

    #[test]
    fn presets_are_expressible_as_documents() {
        assert_eq!(
            parse_policy(STRICT_YAML, ConfigFormat::Yaml).unwrap(),
            CompatibilityPolicy::strict()
        );
        assert_eq!(
            parse_policy(LENIENT_YAML, ConfigFormat::Yaml).unwrap(),
            CompatibilityPolicy::lenient()
        );
        let json = r#"{
                "function_removal_is_breaking": false,
                "signature_change_is_breaking": false,
                "type_removal_is_breaking": false,
                "type_change_is_breaking": false,
                "struct_field_addition_is_breaking": false,
                "event_removal_is_breaking": false,
                "event_change_is_breaking": false
            }"#;
        assert_eq!(
            parse_policy(json, ConfigFormat::Json).unwrap(),
            CompatibilityPolicy::lenient()
        );
    }
}
