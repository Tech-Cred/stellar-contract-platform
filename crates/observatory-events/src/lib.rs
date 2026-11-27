//! Soroban contract event normalization, filtering, and JSON representation.
//!
//! Events are supplied as a fixture document. Each event carries base64 XDR
//! `ScVal` topics and data, which are decoded with the real Stellar XDR types
//! and rendered to stable JSON.
//!
//! # Fixture format
//!
//! ```json
//! {
//!   "events": [
//!     {
//!       "contractId": "C...",
//!       "ledger": 123,
//!       "txHash": "abcd",
//!       "type": "contract",
//!       "topics": ["<base64 ScVal>", "<base64 ScVal>"],
//!       "data": "<base64 ScVal>"
//!     }
//!   ]
//! }
//! ```
//!
//! A bare array of event objects is also accepted. `topics` and `data` are
//! optional. `type` defaults to `contract`.
//!
//! # Event types
//!
//! A normalized event always reports one of the three Stellar event types in
//! lowercase: `system`, `contract`, or `diagnostic`. Fixture input is
//! canonicalized to lowercase, and raw XDR uses the enum's own type name, so
//! the same event always normalizes to the same `event_type` string.
//!
//! `diagnostic` events share the [`EventRecord`] shape with the other types:
//! their topics and data are decoded and rendered identically. A diagnostic
//! event's `contract_id` is `None` when the host emitted it outside a contract
//! context, and its topics conventionally name the diagnostic kind (for
//! example `fn_call`, `log`, or `error`).
//!
//! Raw `ContractEvent` XDR is accepted too. Pass a base64 blob directly, or a
//! fixture entry with an `xdr` field (the `eventXdr` spelling is also accepted):
//!
//! ```json
//! { "events": [{ "xdr": "<base64 ContractEvent>" }] }
//! ```
//!
//! A raw event has no ledger or transaction metadata, so those fields are
//! `null`. Its contract id, type, topics, and data are normalized exactly like
//! a fixture entry.
//!
//! # Limitation
//!
//! Declared events in the contract specification (`contractspecv0`) and
//! historical event data are different things: the specification declares the
//! shape of events, while a fixture contains concrete emitted events. This crate
//! handles the latter.

use observatory_core::limits::{MAX_EVENTS, MAX_EVENT_FILE_BYTES, MAX_EVENT_XDR_BYTES};
use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_xdr::{ContractEvent, ContractEventBody, Limits, ReadXdr, ScVal, WriteXdr};

/// A normalized contract event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// Contract id (C... strkey), when known.
    pub contract_id: Option<String>,
    /// Ledger sequence, when known.
    pub ledger: Option<u32>,
    /// Transaction hash, when known.
    pub tx_hash: Option<String>,
    /// Event type: `system`, `contract`, or `diagnostic` (lowercase).
    pub event_type: String,
    /// Topics rendered as JSON strings, in order.
    pub topics: Vec<String>,
    /// Original base64-encoded `ScVal` XDR topics, in order.
    #[serde(default)]
    pub raw_topics: Vec<String>,
    /// Symbol/string text extracted from topics, for filtering.
    pub topic_symbols: Vec<String>,
    /// Data rendered as JSON.
    pub data: String,
    /// Original base64-encoded `ScVal` XDR data.
    #[serde(default)]
    pub raw_data: String,
}

struct RawScValXdr {
    topics: Vec<String>,
    data: String,
}

/// A parsed topic filter.
///
/// Bare text keeps the legacy substring behavior. `name=<value>` matches one
/// extracted topic symbol exactly, and `indexN=<value>` matches the symbol at
/// zero-based position `N` exactly. Structured forms never fall back to the
/// rendered topic JSON, so indices stay deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicFilter {
    /// Legacy substring match against symbols or rendered topics.
    Contains(String),
    /// Exact match against any extracted symbol.
    Name(String),
    /// Exact match against the extracted symbol at a zero-based index.
    Index(usize, String),
}

impl TopicFilter {
    /// Parse a `--topic` value, rejecting malformed structured filters.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() {
            return Err(ObservatoryError::invalid("topic filter must not be empty"));
        }
        if let Some(value) = raw.strip_prefix("name=") {
            if value.is_empty() {
                return Err(ObservatoryError::invalid(
                    "topic filter name= requires a non-empty value",
                ));
            }
            return Ok(Self::Name(value.to_string()));
        }
        if let Some(rest) = raw.strip_prefix("index") {
            let Some((digits, value)) = rest.split_once('=') else {
                return Err(ObservatoryError::invalid(
                    "topic filter indexN= requires an index and a value",
                ));
            };
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ObservatoryError::invalid(
                    "topic filter index must be a non-negative decimal integer",
                ));
            }
            let index = digits
                .parse::<usize>()
                .map_err(|_| ObservatoryError::invalid("topic filter index is out of range"))?;
            if value.is_empty() {
                return Err(ObservatoryError::invalid(
                    "topic filter indexN= requires a non-empty value",
                ));
            }
            return Ok(Self::Index(index, value.to_string()));
        }
        if raw.contains('=') {
            return Err(ObservatoryError::invalid(format!(
                "unsupported topic filter '{raw}'; use name=<value> or indexN=<value>"
            )));
        }
        Ok(Self::Contains(raw.to_string()))
    }

    fn matches(&self, event: &EventRecord) -> bool {
        match self {
            Self::Contains(text) => {
                event
                    .topic_symbols
                    .iter()
                    .any(|symbol| symbol.contains(text.as_str()))
                    || event
                        .topics
                        .iter()
                        .any(|rendered| rendered.contains(text.as_str()))
            }
            Self::Name(expected) => event.topic_symbols.iter().any(|symbol| symbol == expected),
            Self::Index(index, expected) => event
                .topic_symbols
                .get(*index)
                .is_some_and(|symbol| symbol == expected),
        }
    }
}

/// A filter over a set of events.
///
/// Filters are applied in a fixed order: contract, then type, then topic, then
/// limit. Each filter that is `None` is a no-op.
///
/// Diagnostic events are filtered like any other event, with one consequence
/// worth knowing: the contract filter requires an exact `contract_id` match, so
/// events without a contract id (including diagnostic events emitted outside a
/// contract) never match it. The type filter is case-insensitive, so
/// `type = diagnostic` selects diagnostic events regardless of contract.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventFilter {
    /// Only keep events for this contract id.
    pub contract: Option<String>,
    /// Only keep events whose topic text or rendered topic contains this value.
    pub topic: Option<String>,
    /// Structured topic filter, taking precedence over `topic` when present.
    pub topic_filter: Option<TopicFilter>,
    /// Only keep events of this type.
    pub event_type: Option<String>,
    /// Keep at most this many events (applied last).
    pub limit: Option<usize>,
}

/// Parse an event fixture from a JSON string.
pub fn parse_events_str(input: &str) -> Result<Vec<EventRecord>> {
    if input.len() > MAX_EVENT_FILE_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "event fixture is {} bytes, exceeding the {} byte limit",
            input.len(),
            MAX_EVENT_FILE_BYTES
        )));
    }
    match serde_json::from_str(input) {
        Ok(value) => parse_events(&value),
        Err(json_error) => {
            let trimmed = input.trim();
            // A bare base64 `ContractEvent` is not JSON. Try it only when the
            // input does not look like a JSON document, so malformed fixtures
            // keep their JSON-specific error.
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                return Err(ObservatoryError::decode(format!(
                    "invalid event JSON: {json_error}"
                )));
            }
            parse_contract_event_xdr(trimmed).map(|event| vec![event])
        }
    }
}

/// Parse an event fixture from a JSON value.
pub fn parse_events(value: &Value) -> Result<Vec<EventRecord>> {
    if let Some(encoded) = value.as_str() {
        return parse_contract_event_xdr(encoded).map(|event| vec![event]);
    }
    let array = if let Some(events) = value.get("events").and_then(Value::as_array) {
        events
    } else if let Some(events) = value.as_array() {
        events
    } else if is_raw_event_entry(value) {
        return parse_event(value).map(|event| vec![event]);
    } else {
        return Err(ObservatoryError::decode(
            "event fixture must be an array, an object with an `events` array, or a base64 ContractEvent",
        ));
    };
    if array.len() > MAX_EVENTS {
        return Err(ObservatoryError::invalid(format!(
            "event fixture has {} events, exceeding the {MAX_EVENTS} limit",
            array.len()
        )));
    }
    array.iter().map(parse_event).collect()
}

/// Parse one event object from a `getEvents` RPC result.
///
/// RPC events encode `topic` and `value` as base64 `ScVal`s. The normalizer maps
/// `contractId`, `ledger`, `txHash`, and `type`, and reuses the same rendering as
/// fixture events. The older fixture-style `topics`/`data` keys are accepted too.
pub fn parse_rpc_event(value: &Value) -> Result<EventRecord> {
    let object = value
        .as_object()
        .ok_or_else(|| ObservatoryError::decode("RPC event must be a JSON object"))?;
    let contract_id = object
        .get("contractId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let ledger = object
        .get("ledger")
        .and_then(Value::as_u64)
        .map(|value| value as u32);
    let tx_hash = object
        .get("txHash")
        .and_then(Value::as_str)
        .map(str::to_string);
    let event_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("contract")
        .to_ascii_lowercase();
    let topics = object
        .get("topic")
        .or_else(|| object.get("topics"))
        .and_then(Value::as_array)
        .ok_or_else(|| ObservatoryError::decode("RPC event is missing a topic array"))?;
    let mut decoded_topics = Vec::with_capacity(topics.len());
    let mut raw_topics = Vec::with_capacity(topics.len());
    for topic in topics {
        let (decoded, raw) = decode_rpc_scval(topic)?;
        decoded_topics.push(decoded);
        raw_topics.push(raw);
    }
    let data = object
        .get("value")
        .or_else(|| object.get("data"))
        .ok_or_else(|| ObservatoryError::decode("RPC event is missing a value"))?;
    let (data, raw_data) = decode_rpc_scval(data)?;
    record_from_parts(
        contract_id,
        ledger,
        tx_hash,
        event_type,
        &decoded_topics,
        &data,
        RawScValXdr {
            topics: raw_topics,
            data: raw_data,
        },
    )
}

/// Parse every event in a `getEvents` result object.
pub fn parse_rpc_events(result: &Value) -> Result<Vec<EventRecord>> {
    let events = result
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| ObservatoryError::decode("getEvents result must contain an events array"))?;
    if events.len() > MAX_EVENTS {
        return Err(ObservatoryError::invalid(format!(
            "getEvents result has {} events, exceeding the {MAX_EVENTS} limit",
            events.len()
        )));
    }
    events.iter().map(parse_rpc_event).collect()
}

fn decode_rpc_scval(value: &Value) -> Result<(ScVal, String)> {
    let encoded = value
        .as_str()
        .ok_or_else(|| ObservatoryError::decode("RPC event ScVal must be a base64 string"))?;
    decode_bounded_scval(encoded, "RPC event ScVal")
}

/// Apply a filter to a set of events.
#[must_use]
pub fn filter(events: &[EventRecord], filter: &EventFilter) -> Vec<EventRecord> {
    let topic_filter = filter.topic_filter.clone().or_else(|| {
        filter
            .topic
            .as_ref()
            .map(|topic| TopicFilter::Contains(topic.clone()))
    });
    let mut out: Vec<EventRecord> = events
        .iter()
        .filter(|event| {
            filter
                .contract
                .as_ref()
                .is_none_or(|contract| event.contract_id.as_deref() == Some(contract.as_str()))
        })
        .filter(|event| {
            filter
                .event_type
                .as_ref()
                .is_none_or(|kind| event.event_type.eq_ignore_ascii_case(kind))
        })
        .filter(|event| {
            topic_filter
                .as_ref()
                .is_none_or(|topic| topic.matches(event))
        })
        .cloned()
        .collect();
    if let Some(limit) = filter.limit {
        out.truncate(limit);
    }
    out
}

/// Decode a base64 `ContractEvent` XDR blob into the normalized event shape.
///
/// Raw events do not carry ledger or transaction metadata, so [`EventRecord::ledger`]
/// and [`EventRecord::tx_hash`] are `None`. The contract id, event type, topics,
/// and data are mapped exactly as they are for fixture `ScVal` entries.
pub fn parse_contract_event_xdr(encoded: &str) -> Result<EventRecord> {
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return Err(ObservatoryError::decode(
            "ContractEvent XDR input must not be empty",
        ));
    }
    if encoded.len() > MAX_EVENT_FILE_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "ContractEvent XDR is {} bytes, exceeding the {} byte limit",
            encoded.len(),
            MAX_EVENT_FILE_BYTES
        )));
    }
    let event = ContractEvent::from_xdr_base64(encoded, Limits::none())
        .map_err(|error| ObservatoryError::decode(format!("invalid ContractEvent XDR: {error}")))?;
    record_from_contract_event(&event)
}

fn record_from_contract_event(event: &ContractEvent) -> Result<EventRecord> {
    let ContractEventBody::V0(body) = &event.body;
    let raw_topics = body
        .topics
        .iter()
        .map(encode_scval)
        .collect::<Result<Vec<_>>>()?;
    let raw_data = encode_scval(&body.data)?;
    record_from_parts(
        event
            .contract_id
            .as_ref()
            .map(|contract_id| format!("{}", stellar_strkey::Contract(contract_id.0 .0))),
        None,
        None,
        event.type_.name().to_ascii_lowercase(),
        body.topics.as_slice(),
        &body.data,
        RawScValXdr {
            topics: raw_topics,
            data: raw_data,
        },
    )
}

fn record_from_parts(
    contract_id: Option<String>,
    ledger: Option<u32>,
    tx_hash: Option<String>,
    event_type: String,
    topics: &[ScVal],
    data: &ScVal,
    raw: RawScValXdr,
) -> Result<EventRecord> {
    let mut rendered_topics = Vec::with_capacity(topics.len());
    let mut topic_symbols = Vec::new();
    for topic in topics {
        rendered_topics.push(render_scval(topic)?);
        if let Some(text) = scval_text(topic) {
            topic_symbols.push(text);
        }
    }

    Ok(EventRecord {
        contract_id,
        ledger,
        tx_hash,
        event_type,
        topics: rendered_topics,
        raw_topics: raw.topics,
        topic_symbols,
        data: render_scval(data)?,
        raw_data: raw.data,
    })
}

fn is_raw_event_entry(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        matches!(object.get("xdr"), Some(Value::String(_)))
            || matches!(object.get("eventXdr"), Some(Value::String(_)))
    })
}

fn parse_event(value: &Value) -> Result<EventRecord> {
    let object = value
        .as_object()
        .ok_or_else(|| ObservatoryError::decode("event entry must be a JSON object"))?;
    if let Some(raw) = object.get("xdr").or_else(|| object.get("eventXdr")) {
        let encoded = raw
            .as_str()
            .ok_or_else(|| ObservatoryError::decode("`xdr` must be a base64 string"))?;
        let mut record = parse_contract_event_xdr(encoded)?;
        // Preserve fixture-only metadata supplied next to the raw event.
        if record.contract_id.is_none() {
            record.contract_id = object
                .get("contractId")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if record.ledger.is_none() {
            record.ledger = object
                .get("ledger")
                .and_then(Value::as_u64)
                .map(|value| value as u32);
        }
        if record.tx_hash.is_none() {
            record.tx_hash = object
                .get("txHash")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        return Ok(record);
    }
    let topics_value = object.get("topics");
    let (topics, raw_topics) = match topics_value {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let encoded = item.as_str().ok_or_else(|| {
                    ObservatoryError::decode("event topic must be a base64 string")
                })?;
                decode_bounded_scval(encoded, "event topic")
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .unzip(),
        Some(_) => return Err(ObservatoryError::decode("`topics` must be an array")),
        None => (Vec::new(), Vec::new()),
    };
    let (data, raw_data) = match object.get("data") {
        Some(Value::String(encoded)) => decode_bounded_scval(encoded, "event data")?,
        Some(Value::Null) | None => {
            let data = ScVal::Void;
            let raw = encode_scval(&data)?;
            (data, raw)
        }
        Some(_) => return Err(ObservatoryError::decode("`data` must be a base64 string")),
    };

    record_from_parts(
        object
            .get("contractId")
            .and_then(Value::as_str)
            .map(str::to_string),
        object
            .get("ledger")
            .and_then(Value::as_u64)
            .map(|value| value as u32),
        object
            .get("txHash")
            .and_then(Value::as_str)
            .map(str::to_string),
        object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("contract")
            .trim()
            .to_ascii_lowercase(),
        &topics,
        &data,
        RawScValXdr {
            topics: raw_topics,
            data: raw_data,
        },
    )
}

fn decode_bounded_scval(encoded: &str, description: &str) -> Result<(ScVal, String)> {
    let encoded = encoded.trim();
    if encoded.len() > MAX_EVENT_XDR_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "{description} is {} bytes, exceeding the {} byte limit",
            encoded.len(),
            MAX_EVENT_XDR_BYTES
        )));
    }
    let decoded = ScVal::from_xdr_base64(encoded, Limits::none())
        .map_err(|error| ObservatoryError::decode(format!("invalid {description} XDR: {error}")))?;
    Ok((decoded, encoded.to_string()))
}

fn encode_scval(value: &ScVal) -> Result<String> {
    value
        .to_xdr_base64(Limits::none())
        .map_err(|error| ObservatoryError::internal(format!("failed to encode ScVal XDR: {error}")))
}

fn render_scval(value: &ScVal) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|error| ObservatoryError::internal(format!("failed to render ScVal: {error}")))
}

fn scval_text(value: &ScVal) -> Option<String> {
    match value {
        ScVal::Symbol(symbol) => Some(symbol.0.to_string()),
        ScVal::String(text) => Some(text.0.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use stellar_xdr::{
        ContractEventType, ContractEventV0, ContractId, ExtensionPoint, Hash, ScSymbol, StringM,
        WriteXdr,
    };

    fn symbol_base64(text: &str) -> String {
        ScVal::Symbol(ScSymbol(StringM::try_from(text).unwrap()))
            .to_xdr_base64(Limits::none())
            .unwrap()
    }

    fn contract_event(contract_id: Option<[u8; 32]>) -> ContractEvent {
        let topics = vec![
            ScVal::Symbol(ScSymbol(StringM::try_from("transfer").unwrap())),
            ScVal::Symbol(ScSymbol(StringM::try_from("from").unwrap())),
        ];
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: contract_id.map(|bytes| ContractId(Hash(bytes))),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: topics.try_into().unwrap(),
                data: ScVal::Symbol(ScSymbol(StringM::try_from("amount").unwrap())),
            }),
        }
    }

    fn contract_event_base64(contract_id: Option<[u8; 32]>) -> String {
        contract_event(contract_id)
            .to_xdr_base64(Limits::none())
            .unwrap()
    }

    fn fixture() -> Value {
        json!({
            "events": [
                {
                    "contractId": "CAAA",
                    "ledger": 10,
                    "type": "contract",
                    "topics": [symbol_base64("transfer"), symbol_base64("from")],
                    "data": symbol_base64("amount")
                },
                {
                    "contractId": "CBBB",
                    "ledger": 11,
                    "type": "system",
                    "topics": [symbol_base64("mint")],
                    "data": null
                }
            ]
        })
    }

    #[test]
    fn parses_fixture() {
        let events = parse_events(&fixture()).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].topic_symbols, vec!["transfer", "from"]);
        assert!(events[0].topics[0].contains("transfer"));
        assert_eq!(events[0].raw_topics[0], symbol_base64("transfer"));
        assert_eq!(events[0].raw_topics[1], symbol_base64("from"));
        assert_eq!(events[0].raw_data, symbol_base64("amount"));
        assert_eq!(events[1].event_type, "system");
    }

    #[test]
    fn accepts_bare_array() {
        let value = json!([{ "type": "contract", "topics": [], "data": null }]);
        assert_eq!(parse_events(&value).unwrap().len(), 1);
    }

    #[test]
    fn canonicalizes_event_types_to_lowercase() {
        let events = parse_events(&json!([
            { "type": "SYSTEM", "topics": [], "data": null },
            { "type": "Contract", "topics": [], "data": null },
            { "type": " Diagnostic ", "topics": [], "data": null }
        ]))
        .unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            vec!["system", "contract", "diagnostic"]
        );
    }

    fn mixed_event_fixture() -> Value {
        json!({
            "events": [
                {
                    "contractId": "CAAA",
                    "type": "contract",
                    "topics": [symbol_base64("transfer")],
                    "data": null
                },
                {
                    "type": "system",
                    "topics": [symbol_base64("mint")],
                    "data": null
                },
                {
                    "type": "diagnostic",
                    "topics": [symbol_base64("log")],
                    "data": symbol_base64("boom")
                },
                {
                    "contractId": "CAAA",
                    "type": "diagnostic",
                    "topics": [symbol_base64("fn_call")],
                    "data": null
                }
            ]
        })
    }

    #[test]
    fn filters_diagnostic_events_predictably() {
        let events = parse_events(&mixed_event_fixture()).unwrap();

        let diagnostics = filter(
            &events,
            &EventFilter {
                event_type: Some("DIAGNOSTIC".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics
            .iter()
            .all(|event| event.event_type == "diagnostic"));

        let topic = filter(
            &events,
            &EventFilter {
                topic: Some("log".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(topic.len(), 1);
        assert_eq!(topic[0].event_type, "diagnostic");
        assert_eq!(topic[0].contract_id, None);

        // An event without a contract id never matches a contract filter.
        let by_contract = filter(
            &events,
            &EventFilter {
                contract: Some("CAAA".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(by_contract.len(), 2);
        assert!(by_contract
            .iter()
            .all(|event| { event.contract_id.as_deref() == Some("CAAA") }));

        let combined = filter(
            &events,
            &EventFilter {
                contract: Some("CAAA".to_string()),
                event_type: Some("diagnostic".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].topic_symbols, vec!["fn_call"]);
    }

    #[test]
    fn decodes_raw_diagnostic_event_distinctly() {
        let event = ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: None,
            type_: ContractEventType::Diagnostic,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![ScVal::Symbol(ScSymbol(StringM::try_from("log").unwrap()))]
                    .try_into()
                    .unwrap(),
                data: ScVal::Symbol(ScSymbol(StringM::try_from("boom").unwrap())),
            }),
        };
        let encoded = event.to_xdr_base64(Limits::none()).unwrap();
        let record = parse_contract_event_xdr(&encoded).unwrap();
        assert_eq!(record.event_type, "diagnostic");
        assert_eq!(record.contract_id, None);
        assert_eq!(record.topic_symbols, vec!["log"]);

        let kept = filter(
            &[record],
            &EventFilter {
                event_type: Some("diagnostic".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn filters_by_contract_topic_and_type() {
        let events = parse_events(&fixture()).unwrap();

        let by_contract = filter(
            &events,
            &EventFilter {
                contract: Some("CAAA".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(by_contract.len(), 1);

        let by_topic = filter(
            &events,
            &EventFilter {
                topic: Some("mint".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(by_topic.len(), 1);
        assert_eq!(by_topic[0].contract_id.as_deref(), Some("CBBB"));

        let by_type = filter(
            &events,
            &EventFilter {
                event_type: Some("SYSTEM".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(by_type.len(), 1);
    }

    #[test]
    fn parses_structured_topic_filters() {
        assert_eq!(
            TopicFilter::parse("transfer").unwrap(),
            TopicFilter::Contains("transfer".to_string())
        );
        assert_eq!(
            TopicFilter::parse("name=transfer").unwrap(),
            TopicFilter::Name("transfer".to_string())
        );
        assert_eq!(
            TopicFilter::parse("index0=transfer").unwrap(),
            TopicFilter::Index(0, "transfer".to_string())
        );
        assert_eq!(
            TopicFilter::parse("index12=from").unwrap(),
            TopicFilter::Index(12, "from".to_string())
        );
    }

    #[test]
    fn rejects_malformed_topic_filters() {
        for raw in [
            "",
            "name=",
            "index=",
            "index=transfer",
            "index-1=transfer",
            "indexA=transfer",
            "index999999999999999999999999999999999999=transfer",
            "index0=",
            "idx0=transfer",
            "namex=transfer",
        ] {
            assert!(
                TopicFilter::parse(raw).is_err(),
                "accepted malformed filter {raw}"
            );
        }
    }

    #[test]
    fn structured_topic_filters_match_exact_symbols() {
        let value = json!([
            {
                "type": "contract",
                "topics": [symbol_base64("transfer"), symbol_base64("from")],
                "data": null
            },
            {
                "type": "contract",
                "topics": [symbol_base64("transfer"), symbol_base64("to")],
                "data": null
            }
        ]);
        let events = parse_events(&value).unwrap();

        let by_name = filter(
            &events,
            &EventFilter {
                topic_filter: Some(TopicFilter::parse("name=transfer").unwrap()),
                ..Default::default()
            },
        );
        assert_eq!(by_name.len(), 2);

        let by_index = filter(
            &events,
            &EventFilter {
                topic_filter: Some(TopicFilter::parse("index1=from").unwrap()),
                ..Default::default()
            },
        );
        assert_eq!(by_index.len(), 1);
        assert_eq!(by_index[0].topic_symbols, vec!["transfer", "from"]);

        let substring_does_not_match = filter(
            &events,
            &EventFilter {
                topic_filter: Some(TopicFilter::parse("name=trans").unwrap()),
                ..Default::default()
            },
        );
        assert!(substring_does_not_match.is_empty());

        let wrong_index = filter(
            &events,
            &EventFilter {
                topic_filter: Some(TopicFilter::parse("index1=transfer").unwrap()),
                ..Default::default()
            },
        );
        assert!(wrong_index.is_empty());
    }

    #[test]
    fn topic_index_counts_extracted_symbols_only() {
        let number = ScVal::U32(7).to_xdr_base64(Limits::none()).unwrap();
        let value = json!([{
            "type": "contract",
            "topics": [number, symbol_base64("transfer")],
            "data": null
        }]);
        let events = parse_events(&value).unwrap();
        assert_eq!(events[0].topic_symbols, vec!["transfer"]);

        let zero = filter(
            &events,
            &EventFilter {
                topic_filter: Some(TopicFilter::parse("index0=transfer").unwrap()),
                ..Default::default()
            },
        );
        assert_eq!(zero.len(), 1);

        let one = filter(
            &events,
            &EventFilter {
                topic_filter: Some(TopicFilter::parse("index1=transfer").unwrap()),
                ..Default::default()
            },
        );
        assert!(one.is_empty());
    }

    #[test]
    fn applies_limit_last() {
        let events = parse_events(&fixture()).unwrap();
        let limited = filter(
            &events,
            &EventFilter {
                contract: Some("CAAA".to_string()),
                limit: Some(0),
                ..Default::default()
            },
        );
        assert!(limited.is_empty());
    }

    #[test]
    fn rejects_malformed_base64() {
        let value = json!([{ "topics": ["not base64!!!"], "data": null }]);
        assert!(parse_events(&value).is_err());
    }

    #[test]
    fn rejects_wrong_shape() {
        assert!(parse_events(&json!({ "foo": 1 })).is_err());
        assert!(parse_events(&json!([1, 2, 3])).is_err());
    }

    #[test]
    fn empty_events_are_allowed() {
        assert!(parse_events(&json!({ "events": [] })).unwrap().is_empty());
    }

    #[test]
    fn decodes_raw_contract_event_xdr() {
        let contract_id = [9u8; 32];
        let expected_id = format!("{}", stellar_strkey::Contract(contract_id));
        let encoded = contract_event_base64(Some(contract_id));

        let raw = parse_contract_event_xdr(&encoded).unwrap();
        assert_eq!(raw.contract_id.as_deref(), Some(expected_id.as_str()));
        assert_eq!(raw.event_type, "contract");
        assert_eq!(raw.topic_symbols, vec!["transfer", "from"]);
        assert_eq!(raw.topics.len(), 2);
        assert_eq!(raw.raw_topics[0], symbol_base64("transfer"));
        assert_eq!(raw.raw_topics[1], symbol_base64("from"));
        assert!(raw.data.contains("amount"));
        assert_eq!(raw.raw_data, symbol_base64("amount"));
        assert_eq!(raw.ledger, None);
        assert_eq!(raw.tx_hash, None);

        let fixture = json!([{
            "contractId": expected_id,
            "type": "contract",
            "topics": [symbol_base64("transfer"), symbol_base64("from")],
            "data": symbol_base64("amount")
        }]);
        assert_eq!(parse_events(&fixture).unwrap()[0], raw);
    }

    #[test]
    fn decodes_raw_event_inside_a_fixture_entry() {
        let encoded = contract_event_base64(None);
        let events = parse_events(&json!({
            "events": [{ "xdr": encoded, "ledger": 77, "txHash": "abc" }]
        }))
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].contract_id, None);
        assert_eq!(events[0].ledger, Some(77));
        assert_eq!(events[0].tx_hash.as_deref(), Some("abc"));
    }

    #[test]
    fn accepts_a_bare_raw_event_blob() {
        let encoded = contract_event_base64(Some([3u8; 32]));
        let events = parse_events_str(&encoded).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "contract");
    }

    #[test]
    fn rejects_malformed_contract_event_xdr() {
        let error = parse_contract_event_xdr("not base64!!!").unwrap_err();
        assert_eq!(error.code(), observatory_core::ErrorCode::Decode);
        assert!(error.to_string().contains("ContractEvent"));
        assert!(parse_events_str("not base64!!!").is_err());
    }

    #[test]
    fn parses_a_get_events_rpc_page() {
        let result = json!({
            "events": [{
                "contractId": "CAAA",
                "ledger": 12,
                "txHash": "deadbeef",
                "type": "contract",
                "topic": [symbol_base64("transfer"), symbol_base64("from")],
                "value": symbol_base64("amount")
            }],
            "cursor": "next"
        });
        let events = parse_rpc_events(&result).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].contract_id.as_deref(), Some("CAAA"));
        assert_eq!(events[0].ledger, Some(12));
        assert_eq!(events[0].tx_hash.as_deref(), Some("deadbeef"));
        assert_eq!(events[0].topic_symbols, vec!["transfer", "from"]);
        assert_eq!(events[0].raw_topics[0], symbol_base64("transfer"));
        assert_eq!(events[0].raw_topics[1], symbol_base64("from"));
        assert!(events[0].data.contains("amount"));
        assert_eq!(events[0].raw_data, symbol_base64("amount"));
    }

    #[test]
    fn rejects_oversized_raw_scval() {
        let oversized = "A".repeat(MAX_EVENT_XDR_BYTES + 1);
        let error = decode_bounded_scval(&oversized, "event data").unwrap_err();
        assert_eq!(error.code(), observatory_core::ErrorCode::InvalidInput);
        assert!(error.to_string().contains("exceeding"));
    }

    #[test]
    fn rejects_an_rpc_event_without_topics_or_value() {
        let missing_topics = json!({ "value": symbol_base64("amount") });
        assert!(parse_rpc_event(&missing_topics).is_err());
        let missing_value = json!({ "topic": [symbol_base64("transfer")] });
        assert!(parse_rpc_event(&missing_value).is_err());
    }
}
