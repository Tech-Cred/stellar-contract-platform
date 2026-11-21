//! Typed request models for the REST API.
//!
//! All artifact input is base64-encoded WASM. Requests are validated before any
//! analysis runs, and the decoded size is bounded.

use observatory_core::limits::MAX_WASM_BYTES;
use observatory_core::{ObservatoryError, Result};
use serde::Deserialize;
use serde_json::Value;

use base64::Engine as _;

/// Request body for inspection.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectRequest {
    /// Base64-encoded WASM artifact.
    pub wasm_base64: String,
    /// Whether to include security heuristics.
    #[serde(default)]
    pub security: bool,
}

/// Request body for a single-artifact operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmRequest {
    /// Base64-encoded WASM artifact.
    pub wasm_base64: String,
}

/// Request body for a two-artifact operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffRequest {
    /// Base64-encoded baseline artifact.
    pub old_wasm_base64: String,
    /// Base64-encoded updated artifact.
    pub new_wasm_base64: String,
}

/// Request body for a compatibility assessment.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityRequest {
    /// Base64-encoded baseline artifact.
    pub old_wasm_base64: String,
    /// Base64-encoded updated artifact.
    pub new_wasm_base64: String,
    /// Policy name: `strict` (default) or `lenient`.
    #[serde(default = "default_policy")]
    pub policy: String,
}

fn default_policy() -> String {
    "strict".to_string()
}

/// Request body for the fixture-backed events endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsRequest {
    /// Event fixture: an array, an object with an `events` array, a single raw
    /// event object, or a base64 `ContractEvent`.
    pub fixture: Value,
    /// Only keep events for this contract id.
    #[serde(default)]
    pub contract: Option<String>,
    /// Only keep events whose topic matches this text.
    #[serde(default)]
    pub topic: Option<String>,
    /// Only keep events of this type (`system`, `contract`, `diagnostic`).
    #[serde(default, rename = "type")]
    pub event_type: Option<String>,
    /// Maximum number of events to return.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Request body for enqueuing a background job.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJobRequest {
    /// Caller-defined job kind.
    pub kind: String,
    /// Optional idempotency key; repeating it returns the existing job.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Attempt budget (1-10).
    #[serde(default)]
    pub max_attempts: Option<u32>,
}

/// Request body for cancelling a job.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelJobRequest {
    /// Job id to cancel.
    pub id: String,
}

/// Request body for creating a webhook subscription.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookRequest {
    /// The HTTPS endpoint that receives deliveries.
    pub url: String,
    /// Selected event names; at least one is required.
    pub events: Vec<String>,
}

/// Request body for updating a webhook subscription.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhookRequest {
    /// Replacement HTTPS endpoint.
    #[serde(default)]
    pub url: Option<String>,
    /// Replacement event selection; at least one is required when present.
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// Whether deliveries are active.
    #[serde(default)]
    pub active: Option<bool>,
}

/// Decode a base64 WASM field with a hard size bound.
pub fn decode_wasm(field: &str) -> Result<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(field.trim())
        .map_err(|error| ObservatoryError::invalid(format!("invalid base64 artifact: {error}")))?;
    if bytes.len() > MAX_WASM_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "artifact is {} bytes, exceeding the {} byte limit",
            bytes.len(),
            MAX_WASM_BYTES
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_valid_base64() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello");
        assert_eq!(decode_wasm(&encoded).unwrap(), b"hello");
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(decode_wasm("not base64!!!").is_err());
    }

    #[test]
    fn parses_requests_and_rejects_unknown_fields() {
        let request: InspectRequest = serde_json::from_value(json!({
            "wasm_base64": "AA==", "security": true
        }))
        .unwrap();
        assert!(request.security);
        assert!(
            serde_json::from_value::<InspectRequest>(json!({ "wasm_base64": "AA==", "x": 1 }))
                .is_err()
        );
        let compatibility: CompatibilityRequest = serde_json::from_value(json!({
            "old_wasm_base64": "AA==", "new_wasm_base64": "AA=="
        }))
        .unwrap();
        assert_eq!(compatibility.policy, "strict");
    }
}
