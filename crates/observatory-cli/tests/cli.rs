//! End-to-end CLI tests. These spawn the built binary and exercise the full
//! pipeline against deterministic fixtures; no network access is required.

use std::io::Write;

use assert_cmd::Command;
use observatory_testutil::spec::{
    spec_enum_with_doc, spec_function, spec_function_with_doc, spec_struct, spec_struct_with_doc,
    spec_union_with_doc, ty_udt,
};
use observatory_testutil::{minimal_module, module_with_spec};
use predicates::prelude::*;
use stellar_xdr::{ScSpecEntry, ScSpecTypeDef};

fn binary() -> Command {
    Command::cargo_bin("stellar-contract-platform").expect("binary builds")
}

fn write_temp(bytes: &[u8], suffix: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(suffix)
        .tempfile()
        .expect("create temp file");
    file.write_all(bytes).expect("write temp file");
    file.flush().expect("flush temp file");
    file
}

fn contract_entries() -> Vec<ScSpecEntry> {
    vec![
        spec_function(
            "transfer",
            &[("to", ty_udt("Recipient")), ("amount", ScSpecTypeDef::I128)],
            Some(ScSpecTypeDef::Bool),
        ),
        spec_struct("Recipient", &[("address", ScSpecTypeDef::Address)]),
    ]
}

#[test]
fn inspect_reports_contract_spec() {
    let file = write_temp(&module_with_spec(&contract_entries()), ".wasm");
    binary()
        .args(["inspect", file.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"has_contract_spec\": true"))
        .stdout(predicate::str::contains("\"schema_version\""));
}

#[test]
fn inspect_dumps_a_custom_section_and_reports_absence() {
    let module = observatory_testutil::module_with_custom_section("hello", &[9, 8, 7]);
    let file = write_temp(&module, ".wasm");
    binary()
        .args([
            "inspect",
            file.path().to_str().unwrap(),
            "--dump-section",
            "hello",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"present\": true"))
        .stdout(predicate::str::contains("\"hex\": \"090807\""));

    binary()
        .args([
            "inspect",
            file.path().to_str().unwrap(),
            "--dump-section",
            "missing",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("custom section `missing`: absent"));
}

#[test]
fn inspect_security_emits_audit() {
    let file = write_temp(&module_with_spec(&contract_entries()), ".wasm");
    binary()
        .args([
            "inspect",
            file.path().to_str().unwrap(),
            "--security",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"audit\""));
}

#[test]
fn inspect_security_applies_a_baseline_suppression() {
    let wasm = module_with_spec(&contract_entries());
    let file = write_temp(&wasm, ".wasm");
    let baseline = write_temp(
        b"suppressions:\n  - rule: artifact.no-code\n    reason: generated artifact\n",
        ".yml",
    );
    binary()
        .args([
            "inspect",
            file.path().to_str().unwrap(),
            "--security",
            "--baseline",
            baseline.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"suppressed\": 1"))
        .stdout(predicate::str::contains("\"findings\": []"));
}

#[test]
fn inspect_security_rejects_an_invalid_baseline() {
    let wasm = module_with_spec(&contract_entries());
    let file = write_temp(&wasm, ".wasm");
    let baseline = write_temp(
        b"{\"suppressions\":[{\"rule\":\"artifact.nope\",\"reason\":\"x\"}]}",
        ".json",
    );
    binary()
        .args([
            "inspect",
            file.path().to_str().unwrap(),
            "--security",
            "--baseline",
            baseline.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown audit rule id"));
}

#[test]
fn spec_lists_functions() {
    let file = write_temp(&module_with_spec(&contract_entries()), ".wasm");
    binary()
        .args(["spec", file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("transfer"));
}

fn documented_entries() -> Vec<ScSpecEntry> {
    vec![
        spec_function_with_doc(
            "transfer",
            "Transfer tokens to a recipient.\nEmits a transfer event.",
            &[("to", ty_udt("Recipient")), ("amount", ScSpecTypeDef::I128)],
            Some(ScSpecTypeDef::Bool),
        ),
        spec_struct_with_doc(
            "Recipient",
            "A transfer recipient.",
            &[
                ("address", "The recipient address.", ScSpecTypeDef::Address),
                ("memo", "", ScSpecTypeDef::U32),
            ],
        ),
        spec_union_with_doc(
            "Payload",
            "A transfer payload.",
            &[
                ("None", "No payload.", None),
                (
                    "Amount",
                    "An amount payload.",
                    Some(vec![ScSpecTypeDef::I128]),
                ),
            ],
        ),
        spec_enum_with_doc(
            "Status",
            "Transfer status.",
            &[("Active", "The transfer is active.", 0), ("Paused", "", 1)],
        ),
    ]
}

#[test]
fn spec_renders_documentation_in_human_output() {
    let file = write_temp(&module_with_spec(&documented_entries()), ".wasm");
    let path = file.path().to_str().unwrap();
    binary()
        .args(["spec", path])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Transfer tokens to a recipient.\n      Emits a transfer event.",
        ))
        .stdout(predicate::str::contains("A transfer recipient."))
        .stdout(predicate::str::contains("A transfer payload."))
        .stdout(predicate::str::contains("Transfer status."));

    // JSON output is unchanged: docs remain structured fields on the model.
    binary()
        .args(["spec", path, "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"doc\": \"Transfer tokens to a recipient.\\\\nEmits a transfer event.\"",
        ));
}

#[test]
fn spec_omits_empty_documentation() {
    let file = write_temp(&module_with_spec(&contract_entries()), ".wasm");
    let output = binary()
        .args(["spec", file.path().to_str().unwrap()])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fn transfer"));
    assert!(
        !stdout.lines().any(|line| line.trim().is_empty()),
        "empty docs must not emit blank lines: {stdout}"
    );
}

#[test]
fn spec_type_renders_udt_documentation() {
    let file = write_temp(&module_with_spec(&documented_entries()), ".wasm");
    let path = file.path().to_str().unwrap();

    binary()
        .args(["spec", path, "--type", "Recipient"])
        .assert()
        .success()
        .stdout(predicate::str::contains("struct Recipient"))
        .stdout(predicate::str::contains("A transfer recipient."))
        .stdout(predicate::str::contains("field address: address"))
        .stdout(predicate::str::contains("The recipient address."));

    binary()
        .args(["spec", path, "--type", "Payload"])
        .assert()
        .success()
        .stdout(predicate::str::contains("union Payload"))
        .stdout(predicate::str::contains("A transfer payload."))
        .stdout(predicate::str::contains("case None"))
        .stdout(predicate::str::contains("No payload."))
        .stdout(predicate::str::contains("case Amount(i128)"))
        .stdout(predicate::str::contains("An amount payload."));

    let first = binary()
        .args(["spec", path, "--type", "Status"])
        .output()
        .expect("run binary");
    assert!(first.status.success());
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.contains("enum Status"));
    assert!(stdout.contains("Transfer status."));
    assert!(stdout.contains("case Active = 0"));
    assert!(stdout.contains("The transfer is active."));

    // The same type renders identically on repeated runs.
    let second = binary()
        .args(["spec", path, "--type", "Status"])
        .output()
        .expect("run binary");
    assert_eq!(first.stdout, second.stdout);

    // JSON output remains structured and unchanged.
    binary()
        .args(["spec", path, "--type", "Recipient", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "\"doc\": \"The recipient address.\"",
        ));
}

#[test]
fn fingerprint_defaults_to_sha256() {
    let file = write_temp(&minimal_module(), ".wasm");
    let assert = binary()
        .args(["fingerprint", file.path().to_str().unwrap(), "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["data"]["algorithm"], "sha256");
    assert_eq!(
        report["data"]["artifact_sha256"].as_str().unwrap().len(),
        64
    );
}

#[test]
fn fingerprint_selects_sha512() {
    let file = write_temp(
        &module_with_spec(&[spec_function("ping", &[], Some(ScSpecTypeDef::Bool))]),
        ".wasm",
    );
    let assert = binary()
        .args([
            "fingerprint",
            file.path().to_str().unwrap(),
            "--algorithm",
            "sha512",
            "--json",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["data"]["algorithm"], "sha512");
    assert_eq!(
        report["data"]["artifact_sha256"].as_str().unwrap().len(),
        128
    );
    assert_eq!(
        report["data"]["interface_sha256"].as_str().unwrap().len(),
        128
    );
}

#[test]
fn fingerprint_rejects_unknown_algorithm() {
    let file = write_temp(&minimal_module(), ".wasm");
    binary()
        .args([
            "fingerprint",
            file.path().to_str().unwrap(),
            "--algorithm",
            "md5",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unsupported hash algorithm"));
}

#[test]
fn diff_and_compat_report_breaking_change() {
    let old = write_temp(
        &module_with_spec(&[spec_function("a", &[], None), spec_function("b", &[], None)]),
        ".wasm",
    );
    let new = write_temp(&module_with_spec(&[spec_function("a", &[], None)]), ".wasm");

    binary()
        .args([
            "diff",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("function::b"))
        .stdout(predicate::str::contains("breaking"));

    binary()
        .args([
            "compat",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
        ])
        .assert()
        .code(6)
        .stdout(predicate::str::contains("incompatible"));
}

#[test]
fn events_filters_fixture() {
    use stellar_xdr::{Limits, ScSymbol, StringM, WriteXdr};
    let topic = stellar_xdr::ScVal::Symbol(ScSymbol(StringM::try_from("transfer").unwrap()))
        .to_xdr_base64(Limits::none())
        .unwrap();
    let fixture = format!(
        r#"{{"events":[{{"contractId":"CAAA","type":"contract","topics":["{topic}"],"data":null}}]}}"#
    );
    let file = write_temp(fixture.as_bytes(), ".json");
    binary()
        .args([
            "events",
            file.path().to_str().unwrap(),
            "--topic",
            "transfer",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"returned\": 1"));
}

#[test]
fn events_accept_structured_topic_filters() {
    use stellar_xdr::{Limits, ScSymbol, StringM, WriteXdr};
    fn topic(text: &str) -> String {
        stellar_xdr::ScVal::Symbol(ScSymbol(StringM::try_from(text).unwrap()))
            .to_xdr_base64(Limits::none())
            .unwrap()
    }
    let fixture = format!(
        r#"{{"events":[
            {{"contractId":"CAAA","type":"contract","topics":["{}","{}"],"data":null}},
            {{"contractId":"CBBB","type":"contract","topics":["{}","{}"],"data":null}}
        ]}}"#,
        topic("transfer"),
        topic("from"),
        topic("transfer"),
        topic("to"),
    );
    let file = write_temp(fixture.as_bytes(), ".json");
    let path = file.path().to_str().unwrap();

    binary()
        .args(["events", path, "--topic", "name=transfer", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"returned\": 2"));

    binary()
        .args(["events", path, "--topic", "index1=from", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"returned\": 1"));

    binary()
        .args(["events", path, "--topic", "index=from", "--json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("topic filter"));
}

#[test]
fn completions_emit_non_empty_scripts() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        binary()
            .args(["completions", shell])
            .assert()
            .success()
            .stdout(predicate::str::is_empty().not())
            .stdout(predicate::str::contains("stellar-contract-platform"));
    }
}

#[test]
fn doctor_reports_capabilities() {
    binary()
        .args(["doctor", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fingerprint"))
        .stdout(predicate::str::contains("fixture/mock only"));
}

#[test]
fn missing_file_is_an_input_error() {
    binary()
        .args(["inspect", "definitely-missing.wasm"])
        .assert()
        .code(3);
}

#[test]
fn invalid_arguments_are_a_usage_error() {
    binary().arg("not-a-command").assert().code(2);
}

#[test]
fn api_openapi_documents_contract_routes() {
    binary()
        .args(["api", "openapi"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"openapi\""))
        .stdout(predicate::str::contains("/api/v1/contracts/inspect"))
        .stdout(predicate::str::contains("securitySchemes"));
}

#[test]
fn format_json_matches_the_json_flag() {
    binary()
        .args(["doctor", "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\""));
    binary()
        .args(["doctor", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\""));
}

#[test]
fn inspect_security_emits_deterministic_sarif() {
    let file = write_temp(&minimal_module(), ".wasm");
    let path = file.path().to_str().unwrap().to_string();
    let run = || {
        let output = binary()
            .args(["inspect", &path, "--security", "--format", "sarif"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(output).expect("utf-8 stdout")
    };

    let first = run();
    assert_eq!(first, run(), "SARIF output must be deterministic");
    let document: serde_json::Value = serde_json::from_str(&first).expect("valid SARIF JSON");
    assert_eq!(document["version"], "2.1.0");
    let rules = document["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules");
    let results = document["runs"][0]["results"].as_array().expect("results");
    assert!(rules.iter().any(|rule| rule["id"] == "artifact.no-code"));
    assert!(!results.is_empty());
    for result in results {
        let rule_id = result["ruleId"].as_str().expect("result rule id");
        assert!(rules.iter().any(|rule| rule["id"] == rule_id));
    }
}

#[test]
fn sarif_requires_the_security_flag() {
    let file = write_temp(&minimal_module(), ".wasm");
    binary()
        .args([
            "inspect",
            file.path().to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("inspect --security"));
}

#[test]
fn format_human_is_an_alias_for_text() {
    binary()
        .args(["doctor", "--format", "human"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stellar-contract-platform"))
        .stdout(predicate::str::contains("\"schema_version\"").not());
    binary()
        .args(["doctor", "--format", "text"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stellar-contract-platform"));
}

#[test]
fn verbose_writes_diagnostics_to_stderr_and_quiet_suppresses_them() {
    binary()
        .args(["doctor", "--verbose"])
        .assert()
        .success()
        .stderr(predicate::str::contains("running `doctor`"));
    binary()
        .args(["doctor"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
    binary()
        .args(["doctor", "--verbose", "--quiet"])
        .assert()
        .success()
        .stderr(predicate::str::is_empty())
        .stdout(predicate::str::contains("stellar-contract-platform"));
}

fn instance_xdr(hash: [u8; 32]) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, Limits, ScAddress, ScContractInstance, ScVal, WriteXdr,
    };
    let data = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(ContractId(Hash([9u8; 32]))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(hash)),
            storage: None,
        }),
    });
    data.to_xdr_base64(Limits::none()).unwrap()
}

fn code_xdr(wasm: &[u8], hash: [u8; 32]) -> String {
    use stellar_xdr::{
        ContractCodeCostInputs, ContractCodeEntry, ContractCodeEntryExt, ContractCodeEntryV1,
        ExtensionPoint, Hash, LedgerEntryData, Limits, WriteXdr,
    };
    let data = LedgerEntryData::ContractCode(ContractCodeEntry {
        ext: ContractCodeEntryExt::V1(ContractCodeEntryV1 {
            ext: ExtensionPoint::V0,
            cost_inputs: ContractCodeCostInputs {
                ext: ExtensionPoint::V0,
                n_instructions: 1,
                n_functions: 1,
                n_globals: 0,
                n_table_entries: 0,
                n_types: 0,
                n_data_segments: 0,
                n_elem_segments: 0,
                n_imports: 0,
                n_exports: 1,
                n_data_segment_bytes: 0,
            },
        }),
        hash: Hash(hash),
        code: wasm.to_vec().try_into().unwrap(),
    });
    data.to_xdr_base64(Limits::none()).unwrap()
}

fn instance_fixture(hash: [u8; 32]) -> String {
    format!(
        r#"{{"getLedgerEntries":{{"__sequence":[{{"entries":[{{"key":"","xdr":"{}"}}]}}]}}}}"#,
        instance_xdr(hash)
    )
}

fn deployment_fixture(hash: [u8; 32], wasm: &[u8]) -> String {
    format!(
        r#"{{"getLedgerEntries":{{"__sequence":[{{"entries":[{{"key":"","xdr":"{}"}}]}},{{"entries":[{{"key":"","xdr":"{}"}}]}}]}}}}"#,
        instance_xdr(hash),
        code_xdr(wasm, hash)
    )
}

const EMPTY_LEDGER_ENTRIES_FIXTURE: &str =
    r#"{"getLedgerEntries":{"__sequence":[{"entries":[]}]}}"#;

fn verify_artifact_args<'a>(wasm: &'a str, contract: &'a str, fixture: &'a str) -> [&'a str; 7] {
    [
        "verify",
        "artifact",
        wasm,
        "--contract",
        contract,
        "--rpc-fixture",
        fixture,
    ]
}

#[test]
fn unsupported_configuration_extension_exits_5() {
    let config = write_temp(b"project: {}\n", ".txt");
    let config = config.path().to_str().unwrap();
    binary()
        .args(["inspect", "unused.wasm", "--config", config, "--json"])
        .assert()
        .code(5)
        .stdout(predicate::str::contains("\"kind\":\"error\""))
        .stdout(predicate::str::contains("\"code\":\"unsupported\""));

    binary()
        .args(["inspect", "unused.wasm", "--config", config])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("error: unsupported:"))
        .stderr(predicate::str::contains(
            "unsupported configuration extension",
        ));
}

#[test]
fn verify_artifact_mismatch_exits_7() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let wasm_file = write_temp(&wasm, ".wasm");
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let fixture = instance_fixture([7u8; 32]);
    let fixture_file = write_temp(fixture.as_bytes(), ".json");
    let args = verify_artifact_args(
        wasm_file.path().to_str().unwrap(),
        &contract_id,
        fixture_file.path().to_str().unwrap(),
    );

    binary()
        .args(args)
        .arg("--json")
        .assert()
        .code(7)
        .stdout(predicate::str::contains("\"kind\": \"verify\""))
        .stdout(predicate::str::contains("\"status\": \"MISMATCH\""))
        .stdout(predicate::str::contains("\"deployed_wasm_hash\""));

    binary()
        .args(args)
        .assert()
        .code(7)
        .stdout(predicate::str::contains("status: Mismatch"))
        .stdout(predicate::str::contains("deployed_wasm_hash:"));
}

#[test]
fn verify_artifact_inconclusive_exits_8() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let wasm_file = write_temp(&wasm, ".wasm");
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let fixture_file = write_temp(EMPTY_LEDGER_ENTRIES_FIXTURE.as_bytes(), ".json");
    let args = verify_artifact_args(
        wasm_file.path().to_str().unwrap(),
        &contract_id,
        fixture_file.path().to_str().unwrap(),
    );

    binary()
        .args(args)
        .arg("--json")
        .assert()
        .code(8)
        .stdout(predicate::str::contains("\"kind\": \"verify\""))
        .stdout(predicate::str::contains(
            "\"status\": \"INSUFFICIENT_DATA\"",
        ));

    binary()
        .args(args)
        .assert()
        .code(8)
        .stdout(predicate::str::contains("status: InsufficientData"))
        .stdout(predicate::str::contains(
            "no contract instance entry was returned",
        ));
}

#[test]
fn verify_failure_policy_can_ignore_a_mismatch() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let wasm_file = write_temp(&wasm, ".wasm");
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let fixture = instance_fixture([7u8; 32]);
    let fixture_file = write_temp(fixture.as_bytes(), ".json");
    let config = write_temp(b"ci:\n  fail_on: INSUFFICIENT_DATA\n", ".yml");
    let args = verify_artifact_args(
        wasm_file.path().to_str().unwrap(),
        &contract_id,
        fixture_file.path().to_str().unwrap(),
    );

    binary()
        .args(args)
        .arg("--config")
        .arg(config.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("status: Mismatch"));
}

#[test]
fn verify_failure_policy_can_fail_on_inconclusive_results_only() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let wasm_file = write_temp(&wasm, ".wasm");
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let fixture_file = write_temp(EMPTY_LEDGER_ENTRIES_FIXTURE.as_bytes(), ".json");
    let args = verify_artifact_args(
        wasm_file.path().to_str().unwrap(),
        &contract_id,
        fixture_file.path().to_str().unwrap(),
    );
    let ignore = write_temp(b"ci:\n  fail_on: MISMATCH\n", ".yml");
    binary()
        .args(args)
        .arg("--config")
        .arg(ignore.path().to_str().unwrap())
        .assert()
        .success();

    let fail = write_temp(b"ci:\n  fail_on: MISMATCH, INSUFFICIENT_DATA\n", ".yml");
    binary()
        .args(args)
        .arg("--config")
        .arg(fail.path().to_str().unwrap())
        .assert()
        .code(8);
}

#[test]
fn verify_failure_policy_rejects_unknown_statuses() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let wasm_file = write_temp(&wasm, ".wasm");
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let fixture_file = write_temp(EMPTY_LEDGER_ENTRIES_FIXTURE.as_bytes(), ".json");
    let config = write_temp(b"ci:\n  fail_on: MAYBE\n", ".yml");
    let args = verify_artifact_args(
        wasm_file.path().to_str().unwrap(),
        &contract_id,
        fixture_file.path().to_str().unwrap(),
    );
    binary()
        .args(args)
        .arg("--config")
        .arg(config.path().to_str().unwrap())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown verification status"));
}

#[test]
fn verify_interface_reports_a_match_against_a_fixture() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let fixture = format!(
        r#"{{"getLedgerEntries":{{"__sequence":[{{"entries":[{{"key":"","xdr":"{}"}}]}},{{"entries":[{{"key":"","xdr":"{}"}}]}}]}}}}"#,
        instance_xdr([7u8; 32]),
        code_xdr(&wasm, [7u8; 32])
    );
    let wasm_file = write_temp(&wasm, ".wasm");
    let fixture_file = write_temp(fixture.as_bytes(), ".json");
    binary()
        .args([
            "verify",
            "interface",
            wasm_file.path().to_str().unwrap(),
            "--contract",
            &contract_id,
            "--rpc-fixture",
            fixture_file.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"interface_match\": true"))
        .stdout(predicate::str::contains(
            "\"source_verification\": \"not_performed\"",
        ))
        .stdout(predicate::str::contains("\"compatibility\""));
}

#[test]
fn deployment_compare_reports_identical_local_artifacts_as_matched() {
    let wasm = module_with_spec(&[spec_function("hello", &[], None)]);
    let left = write_temp(&wasm, ".wasm");
    let right = write_temp(&wasm, ".wasm");
    binary()
        .args([
            "deployment",
            "compare",
            "--left-wasm",
            left.path().to_str().unwrap(),
            "--right-wasm",
            right.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\": \"deployment.compare\""))
        .stdout(predicate::str::contains("\"hash\": \"match\""))
        .stdout(predicate::str::contains("\"interface\": \"match\""));
}

#[test]
fn deployment_compare_separates_hash_from_interface_changes() {
    let wasm = module_with_spec(&[spec_function("hello", &[], None)]);
    let mut other = wasm.clone();
    other.extend(observatory_testutil::custom_section("build", b"different"));
    let left = write_temp(&wasm, ".wasm");
    let right = write_temp(&other, ".wasm");

    binary()
        .args([
            "deployment",
            "compare",
            "--left-wasm",
            left.path().to_str().unwrap(),
            "--right-wasm",
            right.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"hash\": \"mismatch\""))
        .stdout(predicate::str::contains("\"interface\": \"match\""));

    let changed = module_with_spec(&[spec_function("goodbye", &[], None)]);
    let changed_file = write_temp(&changed, ".wasm");
    binary()
        .args([
            "deployment",
            "compare",
            "--left-wasm",
            left.path().to_str().unwrap(),
            "--right-wasm",
            changed_file.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"interface\": \"mismatch\""))
        .stdout(predicate::str::contains("function::hello"));
}

#[test]
fn deployment_compare_accepts_two_rpc_fixtures() {
    let wasm = module_with_spec(&[spec_function("hello", &[], None)]);
    let contract_id = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let left_fixture = deployment_fixture([7u8; 32], &wasm);
    let right_fixture = deployment_fixture([7u8; 32], &wasm);
    let left = write_temp(left_fixture.as_bytes(), ".json");
    let right = write_temp(right_fixture.as_bytes(), ".json");
    binary()
        .args([
            "deployment",
            "compare",
            "--contract",
            &contract_id,
            "--left-fixture",
            left.path().to_str().unwrap(),
            "--right-fixture",
            right.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"hash\": \"match\""))
        .stdout(predicate::str::contains("\"interface\": \"match\""));
}

fn metadata_module() -> Vec<u8> {
    use stellar_xdr::{
        Limits, ScEnvMetaEntry, ScEnvMetaEntryInterfaceVersion, ScMetaEntry, ScMetaV0, WriteXdr,
    };
    let mut module = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let env = ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(ScEnvMetaEntryInterfaceVersion {
        protocol: 22,
        pre_release: 0,
    });
    module.extend(observatory_testutil::custom_section(
        observatory_wasm::CONTRACT_ENV_META_SECTION,
        &env.to_xdr(Limits::none()).unwrap(),
    ));
    let metadata = [
        ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: "rsver".try_into().unwrap(),
            val: "1.85.0".try_into().unwrap(),
        }),
        ScMetaEntry::ScMetaV0(ScMetaV0 {
            key: "dep:serde".try_into().unwrap(),
            val: "1.0.200".try_into().unwrap(),
        }),
    ];
    let mut payload = Vec::new();
    for entry in metadata {
        payload.extend(entry.to_xdr(Limits::none()).unwrap());
    }
    module.extend(observatory_testutil::custom_section(
        observatory_wasm::CONTRACT_META_SECTION,
        &payload,
    ));
    module
}

#[test]
fn repro_reports_dependency_metadata_deterministically() {
    let wasm = metadata_module();
    let file = write_temp(&wasm, ".wasm");
    let path = file.path().to_str().unwrap();
    binary()
        .args([
            "repro",
            path,
            "--dependencies",
            "--reference",
            path,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\": \"repro.dependencies\""))
        .stdout(predicate::str::contains("\"name\": \"serde\""))
        .stdout(predicate::str::contains("\"version\": \"1.0.200\""))
        .stdout(predicate::str::contains("\"state\": \"match\""));
}

#[test]
fn repro_reports_metadata_without_claiming_source_reproduction() {
    let wasm = metadata_module();
    let file = write_temp(&wasm, ".wasm");
    let path = file.path().to_str().unwrap();
    binary()
        .args(["repro", path, "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\": \"repro\""))
        .stdout(predicate::str::contains("\"protocol\": 22"))
        .stdout(predicate::str::contains("\"rsver\""))
        .stdout(predicate::str::contains("\"state\": \"not_compared\""))
        .stdout(predicate::str::contains(
            "\"source_reproduction\": \"not_performed\"",
        ));

    binary()
        .args(["repro", path, "--reference", path, "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"state\": \"match\""));
}

#[test]
fn repro_sbom_is_valid_json_and_marks_absent_data() {
    let wasm = metadata_module();
    let file = write_temp(&wasm, ".wasm");
    let path = file.path().to_str().unwrap();
    let output = binary()
        .args(["repro", path, "--sbom", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\": \"repro.sbom\""))
        .stdout(predicate::str::contains(
            "\"format\": \"observatory-sbom/1\"",
        ))
        .stdout(predicate::str::contains("\"algorithm\": \"sha256\""))
        .stdout(predicate::str::contains("\"dependencies\""))
        .get_output()
        .stdout
        .clone();
    let document: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(document["data"]["component"]["name"].is_null());
    assert_eq!(document["data"]["dependencies"][0]["name"], "serde");
    assert!(document["data"]["component"]["version"].is_null());
    assert_eq!(
        document["data"]["unavailable"],
        serde_json::json!(["component.name", "component.version"])
    );
}

#[test]
fn diff_markdown_renders_severity_sections() {
    let old = write_temp(
        &module_with_spec(&[spec_function("a", &[], None), spec_function("b", &[], None)]),
        ".wasm",
    );
    let new = write_temp(&module_with_spec(&[spec_function("a", &[], None)]), ".wasm");
    binary()
        .args([
            "diff",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
            "--markdown",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("# Interface diff"))
        .stdout(predicate::str::contains("## Breaking"))
        .stdout(predicate::str::contains("`function::b`"));
}

#[test]
fn config_file_selects_compatibility_policy() {
    let old = write_temp(
        &module_with_spec(&[spec_function("a", &[], None), spec_function("b", &[], None)]),
        ".wasm",
    );
    let new = write_temp(&module_with_spec(&[spec_function("a", &[], None)]), ".wasm");
    let config = write_temp(
        b"analysis:\n  compatibility:\n    policy: lenient\n",
        ".yml",
    );
    binary()
        .args([
            "compat",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
            "--config",
            config.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"compatible\""));

    // The same change is incompatible under the default strict policy.
    binary()
        .args([
            "compat",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
        ])
        .assert()
        .code(6);
}

#[test]
fn policy_file_selects_rules_and_echoes_the_resolved_policy() {
    let old = write_temp(
        &module_with_spec(&[spec_function("a", &[], None), spec_function("b", &[], None)]),
        ".wasm",
    );
    let new = write_temp(&module_with_spec(&[spec_function("a", &[], None)]), ".wasm");
    let lenient = write_temp(
        b"function_removal_is_breaking: false\n\
          signature_change_is_breaking: false\n\
          type_removal_is_breaking: false\n\
          type_change_is_breaking: false\n\
          struct_field_addition_is_breaking: false\n\
          event_removal_is_breaking: false\n\
          event_change_is_breaking: false\n",
        ".yml",
    );
    binary()
        .args([
            "compat",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
            "--policy-file",
            lenient.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"compatible\""))
        .stdout(predicate::str::contains(
            "\"function_removal_is_breaking\": false",
        ))
        .stdout(predicate::str::contains(
            "\"struct_field_addition_is_breaking\": false",
        ));

    let invalid = write_temp(b"function_removal_is_breaking: sometimes\n", ".yml");
    binary()
        .args([
            "compat",
            old.path().to_str().unwrap(),
            new.path().to_str().unwrap(),
            "--policy-file",
            invalid.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("function_removal_is_breaking"))
        .stdout(predicate::str::contains("\"code\":\"invalid_input\""));
}

#[test]
fn struct_addition_fixture_follows_the_explicit_policy() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/compat");
    let old = root.join("struct-addition/baseline.wasm");
    let new = root.join("struct-addition/head.wasm");
    let old = old.to_str().unwrap();
    let new = new.to_str().unwrap();

    binary()
        .args(["compat", old, new, "--json"])
        .assert()
        .code(6)
        .stdout(predicate::str::contains("\"status\": \"incompatible\""))
        .stdout(predicate::str::contains("type::Payload"));

    let policy = write_temp(
        b"function_removal_is_breaking: true\n\
          signature_change_is_breaking: true\n\
          type_removal_is_breaking: true\n\
          type_change_is_breaking: true\n\
          struct_field_addition_is_breaking: false\n\
          event_removal_is_breaking: true\n\
          event_change_is_breaking: true\n",
        ".yml",
    );
    binary()
        .args([
            "compat",
            old,
            new,
            "--policy-file",
            policy.path().to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"compatible\""))
        .stdout(predicate::str::contains(
            "\"struct_field_addition_is_breaking\": false",
        ));
}

#[test]
fn verify_batch_reports_aggregate_status_from_a_manifest() {
    let wasm = module_with_spec(&[spec_function("hello", &[], Some(ScSpecTypeDef::Bool))]);
    let wasm_file = write_temp(&wasm, ".wasm");
    let fixture = instance_fixture([7u8; 32]);
    let fixture_file = write_temp(fixture.as_bytes(), ".json");
    let contract_a = format!("{}", stellar_strkey::Contract([9u8; 32]));
    let contract_b = format!("{}", stellar_strkey::Contract([10u8; 32]));
    let wasm_path = wasm_file.path().to_str().unwrap();
    let fixture_path = fixture_file.path().to_str().unwrap();
    let manifest = serde_json::json!({
        "entries": [
            {"artifact": wasm_path, "contract": contract_a, "rpc_fixture": fixture_path},
            {"artifact": wasm_path, "contract": contract_b, "rpc_fixture": fixture_path}
        ]
    });
    let manifest_file = write_temp(manifest.to_string().as_bytes(), ".json");

    binary()
        .args(["verify", "batch", manifest_file.path().to_str().unwrap()])
        .arg("--json")
        .assert()
        .code(7)
        .stdout(predicate::str::contains("\"kind\": \"verify.batch\""))
        .stdout(predicate::str::contains("\"total\": 2"))
        .stdout(predicate::str::contains("\"mismatched\": 2"));
}
