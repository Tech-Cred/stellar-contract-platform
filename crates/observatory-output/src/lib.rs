//! Stable report envelope and JSON rendering.
//!
//! Every JSON report is wrapped in an envelope carrying the tool name, version,
//! report kind, and schema version. This lets automation pin a schema and detect
//! changes. Human mode prints the same data without the envelope.

use observatory_core::{ObservatoryError, Result, SCHEMA_VERSION, TOOL_NAME};
use serde::{Deserialize, Serialize};

/// A machine-readable report envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report<T> {
    /// Schema version of the envelope.
    pub schema_version: String,
    /// The report kind, for example `inspect`.
    pub kind: String,
    /// Producing tool.
    pub tool: String,
    /// Producing tool version.
    pub version: String,
    /// The report payload.
    pub data: T,
}

/// Wrap a payload in a versioned envelope.
pub fn report<T>(kind: &str, data: T) -> Report<T> {
    Report {
        schema_version: SCHEMA_VERSION.to_string(),
        kind: kind.to_string(),
        tool: TOOL_NAME.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        data,
    }
}

impl<T: Serialize> Report<T> {
    /// Serialize to compact JSON.
    pub fn to_json(&self) -> Result<String> {
        to_json(self)
    }

    /// Serialize to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String> {
        to_json_pretty(self)
    }
}

/// A machine-readable error report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorReport {
    /// Schema version.
    pub schema_version: String,
    /// Always `error`.
    pub kind: String,
    /// Stable error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Stable JSON-RPC failure kind, when the error came from RPC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_kind: Option<String>,
    /// Raw JSON-RPC code exactly as received, when one was present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_code: Option<i64>,
}

impl ErrorReport {
    /// Build an error report from a typed error.
    #[must_use]
    pub fn from_error(error: &ObservatoryError) -> Self {
        let rpc = error.rpc_error();
        ErrorReport {
            schema_version: SCHEMA_VERSION.to_string(),
            kind: "error".to_string(),
            code: error.code().as_str().to_string(),
            message: error.to_string(),
            rpc_kind: rpc.map(|rpc| rpc.kind().as_str().to_string()),
            rpc_code: rpc.and_then(observatory_core::RpcError::code),
        }
    }

    /// Serialize to compact JSON.
    pub fn to_json(&self) -> Result<String> {
        to_json(self)
    }
}

/// Serialize any value to compact JSON.
pub fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|error| ObservatoryError::internal(format!("json serialization: {error}")))
}

/// Serialize any value to pretty JSON.
pub fn to_json_pretty<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| ObservatoryError::internal(format!("json serialization: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Payload {
        answer: u32,
    }

    #[test]
    fn envelope_carries_schema_and_kind() {
        let report = report("inspect", Payload { answer: 42 });
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.kind, "inspect");
        let json = report.to_json().unwrap();
        assert!(json.contains("\"schema_version\":\""));
        assert!(json.contains("\"answer\":42"));
    }

    #[test]
    fn error_report_uses_stable_code() {
        let error = ObservatoryError::wasm("bad");
        let report = ErrorReport::from_error(&error);
        assert_eq!(report.kind, "error");
        assert_eq!(report.code, "wasm");
        assert!(report.to_json().unwrap().contains("\"code\":\"wasm\""));
    }

    #[test]
    fn error_report_exposes_rpc_kind_and_raw_code() {
        let error = ObservatoryError::from_rpc_error(observatory_core::RpcError::from_code(
            -32602,
            "bad params",
        ));
        let report = ErrorReport::from_error(&error);
        assert_eq!(report.code, "rpc");
        assert_eq!(report.rpc_kind.as_deref(), Some("invalid_params"));
        assert_eq!(report.rpc_code, Some(-32602));
        let json = report.to_json().unwrap();
        assert!(json.contains("\"rpc_kind\":\"invalid_params\""));
        assert!(json.contains("\"rpc_code\":-32602"));
    }

    #[test]
    fn non_rpc_error_reports_omit_rpc_fields() {
        let report = ErrorReport::from_error(&ObservatoryError::wasm("bad"));
        assert!(report.rpc_kind.is_none());
        assert!(report.rpc_code.is_none());
        assert!(!report.to_json().unwrap().contains("rpc_kind"));
    }

    #[test]
    fn json_output_is_deterministic() {
        let a = report("x", Payload { answer: 1 }).to_json().unwrap();
        let b = report("x", Payload { answer: 1 }).to_json().unwrap();
        assert_eq!(a, b);
    }

    const SCHEMA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/schemas");

    fn schema(kind: &str) -> serde_json::Value {
        let path = format!("{SCHEMA_DIR}/{kind}.schema.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("cannot read {path}: {error}");
        });
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("invalid JSON in {path}: {error}"))
    }

    /// One representative instance per published report kind.
    fn samples() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("health", serde_json::json!({ "status": "ok" })),
            (
                "readiness",
                serde_json::json!({ "status": "ready", "auth_required": true }),
            ),
            (
                "version",
                serde_json::json!({
                    "tool": TOOL_NAME,
                    "version": "0.1.0",
                    "schema_version": SCHEMA_VERSION,
                    "api_version": "v1",
                }),
            ),
            (
                "metrics",
                serde_json::json!({
                    "requests_total": 42,
                    "analyses_total": 7,
                    "errors_total": 3,
                    "rate_limited_total": 0,
                    "auth_failures": {
                        "insufficient_permission": 0,
                        "invalid_key": 3,
                        "missing_key": 1,
                    },
                    "rate_limit_rejections": { "window_exceeded": 0 },
                }),
            ),
            (
                "inspect",
                serde_json::json!({ "wasm": {}, "interface": null, "audit": null }),
            ),
            ("spec", serde_json::json!({ "spec": {}, "summary": {} })),
            (
                "spec.function",
                serde_json::json!({ "function": {}, "summary": {} }),
            ),
            (
                "spec.type",
                serde_json::json!({
                    "structs": [],
                    "unions": [],
                    "enums": [],
                    "error_enums": [],
                }),
            ),
            (
                "events",
                serde_json::json!({ "total": 1, "returned": 1, "events": [] }),
            ),
            (
                "diff",
                serde_json::json!({
                    "changes": [],
                    "summary": {
                        "total": 0,
                        "breaking": 0,
                        "non_breaking": 0,
                        "informational": 0,
                        "by_kind": {},
                    },
                }),
            ),
            (
                "compat",
                serde_json::json!({
                    "status": "compatible",
                    "policy": {},
                    "reasons": [],
                    "diff": {},
                }),
            ),
            (
                "fingerprint",
                serde_json::json!({
                    "artifact_sha256": "a".repeat(64),
                    "interface_sha256": null,
                }),
            ),
            (
                "security",
                serde_json::json!({ "status": "PASS", "findings": [] }),
            ),
            (
                "deployment",
                serde_json::json!({
                    "contract_id": "C...",
                    "wasm_hash": null,
                    "last_modified_ledger_seq": null,
                    "live_until_ledger_seq": null,
                    "found": false,
                }),
            ),
            (
                "verify",
                serde_json::json!({
                    "status": "MATCH",
                    "contract_id": "C...",
                    "network": "testnet",
                    "local_wasm_hash": "aa",
                    "deployed_wasm_hash": "aa",
                    "detail": "hashes match",
                }),
            ),
            (
                "verify.interface",
                serde_json::json!({
                    "artifact": {
                        "status": "MATCH",
                        "contract_id": "C...",
                        "network": "testnet",
                        "local_wasm_hash": "aa",
                        "deployed_wasm_hash": "aa",
                        "detail": "hashes match",
                    },
                    "interface_match": true,
                    "local_interface_sha256": null,
                    "deployed_interface_sha256": null,
                    "diff": null,
                    "compatibility": null,
                    "source_verification": "not_performed",
                    "detail": "interfaces are identical",
                }),
            ),
            (
                "verify.metadata",
                serde_json::json!({ "entries": { "build": "soroban" } }),
            ),
            (
                "verify.compare",
                serde_json::json!({ "equal": true, "compared_keys": 1, "differences": [] }),
            ),
            (
                "repro",
                serde_json::json!({
                    "env_meta": null,
                    "build_metadata": null,
                    "comparison": {
                        "state": "not_compared",
                        "env_meta_equal": null,
                        "build_metadata": null,
                        "detail": "no reference artifact supplied",
                    },
                    "source_reproduction": "not_performed",
                }),
            ),
            (
                "repro.dependencies",
                serde_json::json!({
                    "dependencies": [
                        { "name": "soroban-sdk", "version": "22.0.0" }
                    ],
                    "comparison": {
                        "state": "match",
                        "compared_dependencies": 1,
                        "differences": [],
                        "detail": "dependency metadata matches the reference artifact",
                    },
                }),
            ),
            (
                "repro.sbom",
                serde_json::json!({
                    "format": "observatory-sbom/1",
                    "component": {
                        "name": "example-contract",
                        "version": null,
                        "hashes": [{
                            "algorithm": "sha256",
                            "value": "0000000000000000000000000000000000000000000000000000000000000000",
                        }],
                    },
                    "dependencies": null,
                    "unavailable": ["component.version", "dependencies"],
                }),
            ),
            (
                "doctor",
                serde_json::json!({
                    "tool": TOOL_NAME,
                    "version": "0.1.0",
                    "schema_version": SCHEMA_VERSION,
                    "capabilities": ["inspect"],
                    "rpc_transport": "fixture/mock only",
                    "networks": [{
                        "name": "testnet",
                        "passphrase": "Test SDF Network ; September 2015",
                        "default_rpc_url": "https://soroban-testnet.stellar.org",
                    }],
                }),
            ),
        ]
    }

    #[test]
    fn every_report_kind_validates_against_its_schema() {
        let mut kinds: Vec<String> = std::fs::read_dir(SCHEMA_DIR)
            .expect("read docs/schemas")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter_map(|name| name.strip_suffix(".schema.json").map(str::to_string))
            // The canonical interface document has its own schema and is not a
            // report envelope; observatory-interface tests validate it.
            .filter(|kind| kind != "interface")
            .collect();
        kinds.sort_unstable();

        let mut tested: Vec<String> = Vec::new();
        for (kind, data) in samples() {
            let schema = schema(kind);
            assert_eq!(
                schema["properties"]["schema_version"]["const"],
                SCHEMA_VERSION
            );
            assert_eq!(schema["properties"]["kind"]["const"], kind);
            assert_eq!(schema["properties"]["tool"]["const"], TOOL_NAME);

            let instance = serde_json::to_value(report(kind, data)).unwrap();
            let validator = jsonschema::validator_for(&schema)
                .unwrap_or_else(|error| panic!("invalid schema for {kind}: {error}"));
            assert!(
                validator.is_valid(&instance),
                "representative `{kind}` output failed validation: {instance}"
            );
            tested.push(kind.to_string());
        }
        tested.push("error".to_string());
        tested.sort_unstable();
        assert_eq!(
            tested, kinds,
            "a schema document has no representative sample"
        );

        let error_schema = schema("error");
        assert_eq!(
            error_schema["properties"]["schema_version"]["const"],
            SCHEMA_VERSION
        );
        let error_instance =
            serde_json::to_value(ErrorReport::from_error(&ObservatoryError::wasm("bad"))).unwrap();
        assert!(jsonschema::validator_for(&error_schema)
            .unwrap()
            .is_valid(&error_instance));
    }

    #[test]
    fn invalid_reports_fail_validation() {
        let schema = schema("inspect");
        let validator = jsonschema::validator_for(&schema).unwrap();
        let missing_data = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "inspect",
            "tool": TOOL_NAME,
            "version": "0.1.0",
        });
        assert!(!validator.is_valid(&missing_data));

        let wrong_kind = serde_json::to_value(report("diff", Payload { answer: 1 })).unwrap();
        assert!(!validator.is_valid(&wrong_kind));
    }
}
