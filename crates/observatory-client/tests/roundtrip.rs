//! Round-trip tests against a local Observatory API instance on loopback.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use observatory_api::Api;
use observatory_client::{ApiErrorCode, Client, ClientError, Policy};
use observatory_core::hash::HashAlgorithm;
use observatory_platform::{PlatformConfig, RateLimitConfig, Role};
use observatory_testutil::module_with_spec;
use observatory_testutil::spec::spec_function;
use stellar_xdr::ScSpecTypeDef;

fn start_api(limit: u32) -> (SocketAddr, String) {
    let config = PlatformConfig {
        require_auth: true,
        rate_limit: RateLimitConfig {
            limit,
            window_secs: 60,
        },
        ..PlatformConfig::default()
    };
    let api = Api::new(config);
    let key = api
        .generate_key(Role::Developer, "client-roundtrip")
        .expect("generate key");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local address");
    let api = Arc::new(api);
    std::thread::spawn(move || observatory_api::http::serve(listener, api));
    (addr, key)
}

fn client(addr: SocketAddr, key: &str) -> Client {
    Client::builder(format!("http://{addr}"))
        .api_key(key)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client")
}

fn contract(names: &[&str]) -> Vec<u8> {
    let entries: Vec<_> = names
        .iter()
        .map(|name| spec_function(name, &[], Some(ScSpecTypeDef::Bool)))
        .collect();
    module_with_spec(&entries)
}

#[test]
fn round_trips_every_endpoint_against_a_local_instance() {
    let (addr, key) = start_api(100);
    let client = client(addr, &key);

    assert_eq!(client.health().unwrap().status, "ok");
    let readiness = client.readiness().unwrap();
    assert_eq!(readiness.status, "ready");
    assert!(readiness.auth_required);
    let version = client.version().unwrap();
    assert_eq!(version.api_version, "v1");
    assert_eq!(version.tool, observatory_core::TOOL_NAME);

    let wasm = contract(&["hello"]);
    let inspected = client.inspect(&wasm, false).unwrap();
    assert!(inspected.wasm.has_contract_spec);
    assert_eq!(inspected.wasm.artifact_sha256.len(), 64);
    assert!(inspected.interface.is_some());
    assert!(inspected.audit.is_none());

    assert!(client.inspect(&wasm, true).unwrap().audit.is_some());

    let spec = client.spec(&wasm).unwrap();
    assert_eq!(spec.spec.functions[0].name, "hello");
    assert_eq!(spec.summary.functions, 1);

    let old = contract(&["hello", "goodbye"]);
    let new = contract(&["hello"]);
    let diff = client.diff(&old, &new).unwrap();
    assert!(diff
        .changes
        .iter()
        .any(|change| change.path.contains("goodbye")));

    let assessment = client.compatibility(&old, &new, Policy::Strict).unwrap();
    assert!(assessment.reasons.iter().any(|reason| reason.breaking));

    let fingerprint = client.fingerprint(&wasm).unwrap();
    assert_eq!(fingerprint.artifact_sha256.len(), 64);
    assert!(fingerprint.interface_sha256.is_some());
    assert_eq!(fingerprint.algorithm, HashAlgorithm::Sha256);

    let sha512 = client
        .fingerprint_with(&wasm, HashAlgorithm::Sha512)
        .unwrap();
    assert_eq!(sha512.algorithm, HashAlgorithm::Sha512);
    assert_eq!(sha512.artifact_sha256.len(), 128);

    let audit = client.security(&wasm).unwrap();
    assert!(audit.findings.iter().all(|finding| !finding.id.is_empty()));
}

#[test]
fn maps_authentication_and_rate_limit_errors() {
    let (addr, key) = start_api(1);

    let unauthenticated = Client::new(format!("http://{addr}")).unwrap();
    let error = unauthenticated
        .inspect(&contract(&["hello"]), false)
        .unwrap_err();
    match error {
        ClientError::Api { status, code, .. } => {
            assert_eq!(status, 401);
            assert_eq!(code, ApiErrorCode::Unauthorized);
        }
        other => panic!("expected a typed API error, got {other}"),
    }

    let client = client(addr, &key);
    assert_eq!(client.health().unwrap().status, "ok");
    let error = client.health().unwrap_err();
    match error {
        ClientError::Api { status, code, .. } => {
            assert_eq!(status, 429);
            assert_eq!(code, ApiErrorCode::RateLimited);
        }
        other => panic!("expected a typed rate-limit error, got {other}"),
    }
}

#[test]
fn rejects_configuration_and_oversized_artifacts() {
    assert!(matches!(
        Client::new("not-a-url"),
        Err(ClientError::Config(_))
    ));
    let client = Client::new("http://127.0.0.1:1").unwrap();
    let oversized = vec![0u8; observatory_core::limits::MAX_WASM_BYTES + 1];
    assert!(matches!(
        client.fingerprint(&oversized),
        Err(ClientError::RequestTooLarge { .. })
    ));
}
