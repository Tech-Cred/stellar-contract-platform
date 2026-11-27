//! Coarse application services composed from the contract-intelligence crates.
//!
//! The service layer performs no analysis itself; it sequences the engine
//! crates and returns typed outcomes. Transports (CLI, HTTP) call these
//! services so analysis logic lives in exactly one place.

use observatory_audit::AuditReport;
use observatory_compat::{assess, CompatibilityAssessment, CompatibilityPolicy};
use observatory_core::hash::HashAlgorithm;
use observatory_core::Result;
use observatory_diff::{diff, InterfaceDiff};
use observatory_events::{parse_events_str, EventRecord};
use observatory_interface::ContractInterface;
use observatory_rpc::{RpcClient, Transport};
use observatory_spec::{parse_wasm, summarize, ContractSpec, SpecReport};
use observatory_verify::{verify_local_vs_deployed, VerificationResult};
use observatory_wasm::{inspect, WasmReport};
use serde::Serialize;

/// Stateless application service over the contract-intelligence engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct Observatory;

/// Outcome of an inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectOutcome {
    /// The WASM report.
    pub wasm: WasmReport,
    /// The canonical interface, when a specification is present.
    pub interface: Option<ContractInterface>,
    /// Security heuristics, when requested.
    pub audit: Option<AuditReport>,
}

/// Outcome of a specification read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecOutcome {
    /// The normalized specification.
    pub spec: ContractSpec,
    /// Counts and validation issues.
    pub summary: SpecReport,
}

/// Outcome of fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FingerprintOutcome {
    /// Artifact digest.
    ///
    /// The field name is retained for compatibility; `algorithm` identifies the
    /// digest. The default is SHA-256.
    pub artifact_sha256: String,
    /// Canonical interface digest, when present.
    ///
    /// The field name is retained for compatibility; `algorithm` identifies the
    /// digest. The default is SHA-256.
    pub interface_sha256: Option<String>,
    /// Hash algorithm used for both digests.
    pub algorithm: HashAlgorithm,
}

impl Observatory {
    /// Create the service.
    #[must_use]
    pub fn new() -> Self {
        Observatory
    }

    /// Inspect a WASM artifact, optionally running security heuristics.
    #[tracing::instrument(name = "service.inspect", skip(wasm))]
    pub fn inspect(&self, wasm: &[u8], security: bool) -> Result<InspectOutcome> {
        let report = inspect(wasm)?;
        let interface = ContractInterface::from_wasm(wasm).ok();
        let audit = if security {
            let mut audit = observatory_audit::audit_artifact(&report);
            if let Some(interface) = &interface {
                audit = audit.merge(observatory_audit::audit_interface(interface));
            }
            Some(audit)
        } else {
            None
        };
        Ok(InspectOutcome {
            wasm: report,
            interface,
            audit,
        })
    }

    /// Read and validate the contract specification.
    #[tracing::instrument(name = "service.spec", skip(wasm))]
    pub fn spec(&self, wasm: &[u8]) -> Result<SpecOutcome> {
        let spec = parse_wasm(wasm)?;
        let summary = summarize(&spec);
        Ok(SpecOutcome { spec, summary })
    }

    /// Diff two interfaces.
    #[tracing::instrument(name = "service.diff", skip(old, new))]
    pub fn diff(&self, old: &[u8], new: &[u8]) -> Result<InterfaceDiff> {
        let old = ContractInterface::from_wasm(old)?;
        let new = ContractInterface::from_wasm(new)?;
        Ok(diff(&old, &new))
    }

    /// Assess compatibility under a policy.
    #[tracing::instrument(name = "service.compatibility", skip(old, new, policy))]
    pub fn compatibility(
        &self,
        old: &[u8],
        new: &[u8],
        policy: CompatibilityPolicy,
    ) -> Result<CompatibilityAssessment> {
        let old = ContractInterface::from_wasm(old)?;
        let new = ContractInterface::from_wasm(new)?;
        Ok(assess(&old, &new, policy))
    }

    /// Compute artifact and interface fingerprints with `algorithm`.
    #[tracing::instrument(name = "service.fingerprint", skip(wasm))]
    pub fn fingerprint_with(
        &self,
        wasm: &[u8],
        algorithm: HashAlgorithm,
    ) -> Result<FingerprintOutcome> {
        let artifact_sha256 = observatory_wasm::artifact_fingerprint_with(wasm, algorithm);
        let interface_sha256 = match ContractInterface::from_wasm(wasm) {
            Ok(interface) => Some(interface.fingerprint_with(algorithm)?),
            Err(_) => None,
        };
        Ok(FingerprintOutcome {
            artifact_sha256,
            interface_sha256,
            algorithm,
        })
    }

    /// Compute artifact and interface fingerprints with the default SHA-256.
    pub fn fingerprint(&self, wasm: &[u8]) -> Result<FingerprintOutcome> {
        self.fingerprint_with(wasm, HashAlgorithm::Sha256)
    }

    /// Run security heuristics over an artifact and its interface.
    #[tracing::instrument(name = "service.security", skip(wasm))]
    pub fn security(&self, wasm: &[u8]) -> Result<AuditReport> {
        let report = inspect(wasm)?;
        let mut audit = observatory_audit::audit_artifact(&report);
        if let Ok(interface) = ContractInterface::from_wasm(wasm) {
            audit = audit.merge(observatory_audit::audit_interface(&interface));
        }
        Ok(audit)
    }

    /// Parse an event fixture.
    pub fn events(&self, json: &str) -> Result<Vec<EventRecord>> {
        parse_events_str(json)
    }

    /// Parse and filter an event fixture supplied as a JSON value.
    #[tracing::instrument(
        name = "service.events_filtered",
        skip(value, contract, topic, event_type, limit)
    )]
    pub fn events_filtered(
        &self,
        value: &serde_json::Value,
        contract: Option<&str>,
        topic: Option<&str>,
        event_type: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<EventRecord>> {
        let events = observatory_events::parse_events(value)?;
        let topic_filter = topic
            .map(observatory_events::TopicFilter::parse)
            .transpose()?;
        Ok(observatory_events::filter(
            &events,
            &observatory_events::EventFilter {
                contract: contract.map(str::to_string),
                topic: None,
                topic_filter,
                event_type: event_type.map(str::to_string),
                limit,
            },
        ))
    }

    /// Verify a local artifact against a deployment over a transport.
    #[tracing::instrument(name = "service.verify", skip(local_wasm, client))]
    pub fn verify<T: Transport>(
        &self,
        local_wasm: &[u8],
        client: &RpcClient<T>,
        contract_id: &str,
        network: &str,
    ) -> Result<VerificationResult> {
        verify_local_vs_deployed(local_wasm, client, contract_id, network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use observatory_testutil::module_with_spec;
    use observatory_testutil::spec::{spec_function, spec_struct, ty_udt};
    use stellar_xdr::ScSpecTypeDef;

    fn contract() -> Vec<u8> {
        module_with_spec(&[
            spec_function(
                "transfer",
                &[("to", ty_udt("Recipient")), ("amount", ScSpecTypeDef::I128)],
                Some(ScSpecTypeDef::Bool),
            ),
            spec_struct("Recipient", &[("address", ScSpecTypeDef::Address)]),
        ])
    }

    #[test]
    fn inspect_reports_interface_and_audit() {
        let outcome = Observatory.inspect(&contract(), true).unwrap();
        assert!(outcome.wasm.has_contract_spec);
        assert!(outcome.interface.is_some());
        assert!(outcome.audit.is_some());
    }

    #[test]
    fn spec_summarizes() {
        let outcome = Observatory.spec(&contract()).unwrap();
        assert_eq!(outcome.summary.functions, 1);
        assert_eq!(outcome.summary.structs, 1);
    }

    #[test]
    fn fingerprint_is_stable_and_meaningful() {
        let a = Observatory.fingerprint(&contract()).unwrap();
        let b = Observatory.fingerprint(&contract()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.artifact_sha256.len(), 64);
        assert!(a.interface_sha256.is_some());
        assert_eq!(a.algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn fingerprint_reports_selected_algorithm() {
        let outcome = Observatory
            .fingerprint_with(&contract(), HashAlgorithm::Sha512)
            .unwrap();
        assert_eq!(outcome.algorithm, HashAlgorithm::Sha512);
        assert_eq!(outcome.artifact_sha256.len(), 128);
        assert!(outcome
            .interface_sha256
            .as_deref()
            .is_some_and(|digest| digest.len() == 128));
        assert_ne!(
            outcome.artifact_sha256,
            Observatory
                .fingerprint(&contract())
                .unwrap()
                .artifact_sha256
        );
    }

    #[test]
    fn diff_and_compatibility() {
        let old = module_with_spec(&[spec_function("a", &[], None), spec_function("b", &[], None)]);
        let new = module_with_spec(&[spec_function("a", &[], None)]);
        let diff = Observatory.diff(&old, &new).unwrap();
        assert_eq!(diff.summary.breaking, 1);
        let assessment = Observatory
            .compatibility(&old, &new, CompatibilityPolicy::strict())
            .unwrap();
        assert!(assessment.is_incompatible());
    }

    #[test]
    fn malformed_wasm_is_a_structured_error() {
        let error = Observatory.inspect(b"not wasm", false).unwrap_err();
        assert!(matches!(error, observatory_core::ObservatoryError::Wasm(_)));
    }

    #[test]
    fn service_methods_emit_spans() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SpanRecorder {
            names: Arc<Mutex<Vec<String>>>,
            next: Arc<AtomicU64>,
        }

        impl tracing::Subscriber for SpanRecorder {
            fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                self.names
                    .lock()
                    .unwrap()
                    .push(span.metadata().name().to_string());
                let next = self.next.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::span::Id::from_u64(next)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, _event: &tracing::Event<'_>) {}

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        // A dedicated thread keeps this recording away from other tests
        // running concurrently on shared tracing dispatch state.
        let handle = std::thread::spawn(|| {
            let recorder = SpanRecorder {
                names: Arc::new(Mutex::new(Vec::new())),
                next: Arc::new(AtomicU64::new(0)),
            };
            let names = recorder.names.clone();
            tracing::subscriber::with_default(recorder, || {
                // Spans can occasionally be skipped by the scoped dispatcher
                // machinery under parallel test execution, so repeat the
                // calls a few times.
                for _ in 0..5 {
                    let _ = Observatory.inspect(&contract(), true);
                    let _ = Observatory.spec(&contract());
                    let _ = Observatory.fingerprint(&contract());
                    let _ = Observatory.security(&contract());
                    let _ = Observatory.events_filtered(
                        &serde_json::json!({ "events": [] }),
                        None,
                        None,
                        None,
                        Some(1),
                    );
                }
            });
            let recorded = names.lock().unwrap().clone();
            recorded
        });
        let names = handle.join().unwrap();
        for expected in [
            "service.inspect",
            "service.security",
            "service.events_filtered",
        ] {
            assert!(
                names.contains(&expected.to_string()),
                "missing span {expected}; recorded: {names:?}"
            );
        }
        assert!(
            names
                .iter()
                .any(|name| name == "service.spec" || name == "service.fingerprint"),
            "missing spans service.spec/service.fingerprint; recorded: {names:?}"
        );
    }
}
