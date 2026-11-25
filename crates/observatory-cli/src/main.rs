//! `stellar-contract-platform` command-line interface.
//!
//! Exit codes:
//! * `0` success
//! * `2` usage error
//! * `3` input or filesystem error
//! * `4` parse/decode error
//! * `5` unsupported feature
//! * `6` an interface change was incompatible
//! * `7` verification mismatch
//! * `8` verification was inconclusive

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use observatory_compat::{assess, CompatibilityStatus};
use observatory_core::{
    ExitCode as ObservatoryExit, Network, ObservatoryError, OutputFormat, Result,
};
use observatory_diff::{diff, Severity};
use observatory_interface::ContractInterface;
use observatory_output::{report, ErrorReport};
use observatory_rpc::{Endpoint, MockTransport, RpcClient};
use observatory_verify::VerificationStatus;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "stellar-contract-platform",
    version,
    about = "Contract intelligence, inspection, compatibility, and verification for Stellar/Soroban",
    long_about = None
)]
struct Cli {
    /// Emit machine-readable JSON (alias for `--format json`).
    #[arg(long, global = true)]
    json: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = FormatArg::Text, global = true)]
    format: FormatArg,

    /// Path to a project configuration file (`observatory.yml`/`.toml`/`.json`).
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Select a named per-network configuration profile.
    #[arg(long, global = true, value_name = "NAME")]
    profile: Option<String>,

    /// Increase logging verbosity (repeatable).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress non-essential output.
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect a WASM contract artifact.
    Inspect {
        /// Path to a `.wasm` file.
        wasm: PathBuf,
        /// Also run bounded interface/artifact heuristics.
        #[arg(long)]
        security: bool,
        /// Dump a named custom section as bounded hex (max 64 KiB).
        #[arg(long, value_name = "NAME")]
        dump_section: Option<String>,
        /// Baseline suppression file (`.json`, `.yml`/`.yaml`, or `.toml`).
        #[arg(long, value_name = "FILE", requires = "security")]
        baseline: Option<PathBuf>,
    },
    /// Inspect the contract specification embedded in a WASM artifact.
    Spec {
        /// Path to a `.wasm` file.
        wasm: PathBuf,
        /// Show a single function by name.
        #[arg(long)]
        function: Option<String>,
        /// Show a single type by name.
        #[arg(long, value_name = "TYPE")]
        r#type: Option<String>,
    },
    /// Analyze contract events from a JSON fixture or a mock `getEvents` RPC page.
    Events {
        /// Path to an event fixture JSON file.
        file: Option<PathBuf>,
        /// Path to a mock `getEvents` RPC fixture (offline, opt-in).
        #[arg(long, value_name = "PATH", conflicts_with = "file")]
        rpc_fixture: Option<PathBuf>,
        /// Filter by contract id.
        #[arg(long)]
        contract: Option<String>,
        /// Filter by topic text.
        #[arg(long)]
        topic: Option<String>,
        /// Filter by event type.
        #[arg(long = "type")]
        event_type: Option<String>,
        /// Limit the number of returned events.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Diff two contract interfaces.
    Diff {
        /// Baseline contract WASM.
        old: PathBuf,
        /// Updated contract WASM.
        new: PathBuf,
        /// Render the diff as Markdown (human mode only).
        #[arg(long)]
        markdown: bool,
    },
    /// Assess compatibility of two contract interfaces.
    Compat {
        /// Baseline contract WASM.
        old: PathBuf,
        /// Updated contract WASM.
        new: PathBuf,
        /// Compatibility policy: `strict` or `lenient` (overrides the project config).
        #[arg(long, conflicts_with = "policy_file")]
        policy: Option<String>,
        /// Compatibility policy document (`.yml`, `.yaml`, `.toml`, or `.json`).
        #[arg(long, value_name = "FILE")]
        policy_file: Option<PathBuf>,
    },
    /// Compute deterministic fingerprints for a contract artifact.
    Fingerprint {
        /// Path to a `.wasm` file.
        wasm: PathBuf,
    },
    /// Inspect a deployed contract using a mocked RPC fixture.
    #[command(subcommand)]
    Deployment(DeploymentCommand),
    /// Verify a local artifact against a deployment, or compare build metadata.
    #[command(subcommand)]
    Verify(VerifyCommand),
    /// Report embedded environment and build metadata for reproducibility.
    Repro {
        /// Path to a `.wasm` file.
        wasm: PathBuf,
        /// Reference artifact to compare embedded metadata against.
        #[arg(long)]
        reference: Option<PathBuf>,
        /// Report `dep:` dependency entries and compare them with `--reference`.
        #[arg(long, conflicts_with = "sbom")]
        dependencies: bool,
        /// Emit a minimal SBOM instead of the reproducibility report.
        #[arg(long, conflicts_with_all = ["reference", "dependencies"])]
        sbom: bool,
    },
    /// Run the REST API server or print its OpenAPI document.
    #[command(subcommand)]
    Api(ApiCommand),
    /// Report environment and capabilities.
    Doctor,
    /// Generate a shell completion script.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Subcommand)]
enum DeploymentCommand {
    /// Inspect a deployed contract.
    Inspect {
        /// Contract id (C... strkey).
        contract: String,
        /// JSON fixture mapping RPC method to result.
        #[arg(long)]
        rpc_fixture: PathBuf,
        /// Network label (defaults to the project config, then `testnet`).
        #[arg(long)]
        network: Option<String>,
        /// RPC endpoint URL (recorded only in this build).
        #[arg(long)]
        rpc_url: Option<String>,
    },
    /// Compare one contract across two networks or local artifacts.
    Compare {
        /// Contract id (required when either side uses an RPC fixture).
        #[arg(long)]
        contract: Option<String>,
        /// Local WASM artifact for the left side.
        #[arg(long, conflicts_with = "left_fixture")]
        left_wasm: Option<PathBuf>,
        /// RPC fixture for the left side (requires `--contract`).
        #[arg(long)]
        left_fixture: Option<PathBuf>,
        /// Network label for the left side.
        #[arg(long, default_value = "mainnet")]
        left_network: String,
        /// Local WASM artifact for the right side.
        #[arg(long, conflicts_with = "right_fixture")]
        right_wasm: Option<PathBuf>,
        /// RPC fixture for the right side (requires `--contract`).
        #[arg(long)]
        right_fixture: Option<PathBuf>,
        /// Network label for the right side.
        #[arg(long, default_value = "testnet")]
        right_network: String,
    },
}

#[derive(Debug, Subcommand)]
enum VerifyCommand {
    /// Verify a local artifact against a deployed contract.
    Artifact {
        /// Path to a `.wasm` file.
        wasm: PathBuf,
        /// Contract id (C... strkey).
        #[arg(long)]
        contract: String,
        /// JSON fixture mapping RPC method to result.
        #[arg(long)]
        rpc_fixture: PathBuf,
        /// Network label (defaults to the project config, then `testnet`).
        #[arg(long)]
        network: Option<String>,
    },
    /// Compare the local interface against the deployed contract's interface.
    Interface {
        /// Path to a `.wasm` file.
        wasm: PathBuf,
        /// Contract id (C... strkey).
        #[arg(long)]
        contract: String,
        /// JSON fixture mapping RPC method to result.
        #[arg(long)]
        rpc_fixture: PathBuf,
        /// Network label (defaults to the project config, then `testnet`).
        #[arg(long)]
        network: Option<String>,
    },
    /// Parse and print a build metadata JSON document.
    Metadata {
        /// Path to a build metadata JSON file.
        file: PathBuf,
    },
    /// Compare two build metadata JSON documents.
    Compare {
        /// Left metadata JSON file.
        left: PathBuf,
        /// Right metadata JSON file.
        right: PathBuf,
    },
    /// Verify every artifact listed in a batch manifest.
    Batch {
        /// JSON manifest with an `entries` array (see docs/cli.md).
        manifest: PathBuf,
        /// Fallback network for entries that omit `network`.
        #[arg(long)]
        network: Option<String>,
    },
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchManifest {
    entries: Vec<BatchEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchEntry {
    artifact: PathBuf,
    contract: String,
    rpc_fixture: PathBuf,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ApiCommand {
    /// Serve the REST API.
    Serve {
        /// Address to bind, for example 127.0.0.1:8080.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        /// Disable authentication (local development only).
        #[arg(long)]
        no_auth: bool,
        /// Requests allowed per window.
        #[arg(long)]
        rate_limit: Option<u32>,
        /// Rate-limit window length in seconds.
        #[arg(long, default_value_t = 60)]
        window_secs: u64,
        /// Register a key as ROLE:PLAINTEXT (repeatable), for example developer:sco_...
        #[arg(long = "key")]
        keys: Vec<String>,
        /// Maximum concurrent in-flight connections.
        #[arg(long, default_value_t = 64)]
        max_connections: usize,
        /// Socket read timeout in seconds.
        #[arg(long, default_value_t = 10)]
        read_timeout_secs: u64,
        /// Socket write timeout in seconds.
        #[arg(long, default_value_t = 10)]
        write_timeout_secs: u64,
        /// Maximum request line size in bytes.
        #[arg(long, default_value_t = 8 * 1024)]
        max_request_line_bytes: usize,
        /// Maximum single header line size in bytes.
        #[arg(long, default_value_t = 8 * 1024)]
        max_header_line_bytes: usize,
        /// Maximum number of header lines.
        #[arg(long, default_value_t = 100)]
        max_headers: usize,
        /// Maximum request body size in bytes.
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        max_body_bytes: usize,
    },
    /// Print the OpenAPI document.
    Openapi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum FormatArg {
    /// Human-readable text.
    #[value(alias = "human")]
    Text,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0 for audit findings (requires `inspect --security`).
    Sarif,
}

impl From<FormatArg> for OutputFormat {
    fn from(value: FormatArg) -> Self {
        match value {
            FormatArg::Text => OutputFormat::Human,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Sarif => OutputFormat::Sarif,
        }
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Inspect { .. } => "inspect",
        Command::Spec { .. } => "spec",
        Command::Events { .. } => "events",
        Command::Diff { .. } => "diff",
        Command::Compat { .. } => "compat",
        Command::Fingerprint { .. } => "fingerprint",
        Command::Deployment(_) => "deployment",
        Command::Verify(_) => "verify",
        Command::Repro { .. } => "repro",
        Command::Api(_) => "api",
        Command::Doctor => "doctor",
        Command::Completions { .. } => "completions",
    }
}

/// Install the tracing subscriber: stderr logs filtered by `RUST_LOG`
/// (default `info`). Spans carry no artifact contents.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = if cli.json {
        OutputFormat::Json
    } else {
        cli.format.into()
    };
    match run(&cli, format) {
        Ok(code) => ExitCode::from(code.code()),
        Err(error) => {
            emit_error(format, &error);
            ExitCode::from(error.exit_code().code())
        }
    }
}

fn run(cli: &Cli, format: OutputFormat) -> Result<ObservatoryExit> {
    if format == OutputFormat::Sarif
        && !matches!(&cli.command, Command::Inspect { security: true, .. })
    {
        return Err(ObservatoryError::invalid(
            "SARIF output is only available for `inspect --security`",
        ));
    }
    if cli.verbose > 0 && !cli.quiet {
        eprintln!(
            "{}: running `{}` (format={format})",
            observatory_core::TOOL_NAME,
            command_name(&cli.command)
        );
    }
    let project = load_config(cli)?;
    project.selected_profile(cli.profile.as_deref())?;
    match &cli.command {
        Command::Inspect {
            wasm,
            security,
            dump_section,
            baseline,
        } => {
            let bytes = observatory_wasm::load_file(wasm)?;
            let report = observatory_wasm::inspect(&bytes)?;
            let interface = ContractInterface::from_wasm(&bytes).ok();
            let mut audit = observatory_audit::audit_artifact_with_config(&report, &project.audit)?;
            if *security {
                if let Some(interface) = &interface {
                    audit = audit.merge(observatory_audit::audit_interface_with_config(
                        interface,
                        &project.audit,
                    )?);
                }
            }
            if let Some(path) = baseline {
                let suppressions = load_suppressions(path)?;
                audit = audit
                    .apply_suppressions(&suppressions, &observatory_audit::current_utc_date())?;
            }
            if format == OutputFormat::Sarif {
                let document = observatory_audit::to_sarif(&audit);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&document)
                        .map_err(|error| ObservatoryError::internal(error.to_string()))?
                );
                return Ok(ObservatoryExit::Success);
            }
            let section = match dump_section {
                Some(name) => {
                    let dump = observatory_wasm::dump_custom_section(&bytes, name)?;
                    Some(serde_json::json!({
                        "name": name,
                        "present": dump.is_some(),
                        "size_bytes": dump.as_ref().map(|dump| dump.size_bytes),
                        "hex": dump.as_ref().map(|dump| &dump.hex),
                    }))
                }
                None => None,
            };
            let mut payload = serde_json::json!({
                "wasm": report,
                "interface": interface,
                "audit": if *security { Some(audit) } else { None },
            });
            if let Some(section) = section {
                payload["section"] = section;
            }
            emit(format, "inspect", &payload, || print_inspect(&payload))?;
            Ok(ObservatoryExit::Success)
        }
        Command::Spec {
            wasm,
            function,
            r#type,
        } => {
            let bytes = observatory_wasm::load_file(wasm)?;
            let spec = observatory_spec::parse_wasm(&bytes)?;
            let summary = observatory_spec::summarize(&spec);
            if let Some(name) = function {
                let found = spec.function(name).cloned().ok_or_else(|| {
                    ObservatoryError::invalid(format!("no function named `{name}`"))
                })?;
                let payload = serde_json::json!({ "function": &found, "summary": &summary });
                let display = format!("function {}({})", found.name, render_params(&found.inputs));
                emit(format, "spec.function", &payload, || {
                    println!("{display}");
                })?;
                return Ok(ObservatoryExit::Success);
            }
            if let Some(name) = r#type {
                let payload = serde_json::json!({
                    "structs": spec.structs.iter().filter(|item| &item.name == name).collect::<Vec<_>>(),
                    "unions": spec.unions.iter().filter(|item| &item.name == name).collect::<Vec<_>>(),
                    "enums": spec.enums.iter().filter(|item| &item.name == name).collect::<Vec<_>>(),
                    "error_enums": spec.error_enums.iter().filter(|item| &item.name == name).collect::<Vec<_>>(),
                });
                let empty = payload["structs"].as_array().is_none_or(Vec::is_empty)
                    && payload["unions"].as_array().is_none_or(Vec::is_empty)
                    && payload["enums"].as_array().is_none_or(Vec::is_empty)
                    && payload["error_enums"].as_array().is_none_or(Vec::is_empty);
                if empty {
                    return Err(ObservatoryError::invalid(format!("no type named `{name}`")));
                }
                emit(format, "spec.type", &payload, || print_type(&spec, name))?;
                return Ok(ObservatoryExit::Success);
            }
            let payload = serde_json::json!({ "spec": &spec, "summary": &summary });
            emit(format, "spec", &payload, || print_spec(&spec, &summary))?;
            Ok(ObservatoryExit::Success)
        }
        Command::Events {
            file,
            rpc_fixture,
            contract,
            topic,
            event_type,
            limit,
        } => {
            let events = match (file, rpc_fixture) {
                (Some(file), None) => {
                    let text = read_text(file)?;
                    observatory_events::parse_events_str(&text)?
                }
                (None, Some(fixture)) => fetch_rpc_events(fixture, *limit)?,
                (Some(_), Some(_)) => {
                    return Err(observatory_core::ObservatoryError::invalid(
                        "events accepts either a fixture file or --rpc-fixture, not both",
                    ));
                }
                (None, None) => {
                    return Err(observatory_core::ObservatoryError::invalid(
                        "events requires a fixture file or --rpc-fixture",
                    ));
                }
            };
            let filtered = observatory_events::filter(
                &events,
                &observatory_events::EventFilter {
                    contract: contract.clone(),
                    topic: topic.clone(),
                    event_type: event_type.clone(),
                    limit: *limit,
                },
            );
            let payload = serde_json::json!({
                "total": events.len(),
                "returned": filtered.len(),
                "events": filtered,
            });
            emit(format, "events", &payload, || print_events(&payload))?;
            Ok(ObservatoryExit::Success)
        }
        Command::Diff { old, new, markdown } => {
            let old_interface = load_interface(old)?;
            let new_interface = load_interface(new)?;
            let result = diff(&old_interface, &new_interface);
            if *markdown && format == OutputFormat::Human {
                print!("{}", observatory_diff::render_markdown(&result));
            } else {
                emit(format, "diff", &result, || print_diff(&result))?;
            }
            Ok(ObservatoryExit::Success)
        }
        Command::Compat {
            old,
            new,
            policy,
            policy_file,
        } => {
            let policy = if let Some(path) = policy_file {
                observatory_platform::load_policy(path)?
            } else {
                match policy.as_deref() {
                    Some("strict") => observatory_platform::CompatibilityPolicy::strict(),
                    Some("lenient") => observatory_platform::CompatibilityPolicy::lenient(),
                    Some(other) => {
                        return Err(ObservatoryError::invalid(format!(
                            "unknown policy `{other}`; expected strict or lenient"
                        )))
                    }
                    None => project.compatibility_policy_for(cli.profile.as_deref())?,
                }
            };
            let old_interface = load_interface(old)?;
            let new_interface = load_interface(new)?;
            let assessment = assess(&old_interface, &new_interface, policy);
            emit(format, "compat", &assessment, || print_compat(&assessment))?;
            Ok(match assessment.status {
                CompatibilityStatus::Incompatible => ObservatoryExit::Incompatible,
                _ => ObservatoryExit::Success,
            })
        }
        Command::Fingerprint { wasm } => {
            // Hash by streaming so large artifacts are not buffered whole. The
            // interface fingerprint still needs the bytes; when the artifact
            // exceeds the load bound it is simply omitted.
            let artifact = observatory_wasm::artifact_fingerprint_file(wasm)?;
            let interface = match observatory_wasm::load_file(wasm) {
                Ok(bytes) => ContractInterface::from_wasm(&bytes)
                    .ok()
                    .map(|interface| interface.fingerprint())
                    .transpose()?,
                Err(_) => None,
            };
            let payload = serde_json::json!({
                "artifact_sha256": artifact,
                "interface_sha256": interface,
            });
            emit(format, "fingerprint", &payload, || {
                print_fingerprint(&payload)
            })?;
            Ok(ObservatoryExit::Success)
        }
        Command::Deployment(DeploymentCommand::Inspect {
            contract,
            rpc_fixture,
            network,
            rpc_url,
        }) => {
            let client = fixture_client(rpc_fixture)?;
            let network = resolve_network(&project, network).parse::<Network>()?;
            let endpoint = rpc_url
                .as_deref()
                .or(project.rpc_endpoint_for(cli.profile.as_deref())?)
                .unwrap_or(network.profile().default_rpc_url);
            let _ = Endpoint::parse(endpoint)?;
            let info = observatory_deployment::inspect_on_network(&client, contract, network)?;
            emit(format, "deployment", &info, || print_deployment(&info))?;
            Ok(ObservatoryExit::Success)
        }
        Command::Deployment(DeploymentCommand::Compare {
            contract,
            left_wasm,
            left_fixture,
            left_network,
            right_wasm,
            right_fixture,
            right_network,
        }) => {
            let contract = contract.as_deref();
            let left = load_network_contract(
                contract,
                left_network,
                left_wasm.as_deref(),
                left_fixture.as_deref(),
            )?;
            let right = load_network_contract(
                contract,
                right_network,
                right_wasm.as_deref(),
                right_fixture.as_deref(),
            )?;
            let comparison = observatory_deployment::compare_networks(left, right);
            emit(format, "deployment.compare", &comparison, || {
                print_network_comparison(&comparison)
            })?;
            Ok(ObservatoryExit::Success)
        }
        Command::Verify(VerifyCommand::Artifact {
            wasm,
            contract,
            rpc_fixture,
            network,
        }) => {
            let failures = verification_failure_policy(&project)?;
            let bytes = observatory_wasm::load_file(wasm)?;
            let client = fixture_client(rpc_fixture)?;
            let network = resolve_network(&project, network);
            let result =
                observatory_verify::verify_local_vs_deployed(&bytes, &client, contract, &network)?;
            emit(format, "verify", &result, || print_verification(&result))?;
            Ok(verification_exit(result.status, &failures))
        }
        Command::Verify(VerifyCommand::Interface {
            wasm,
            contract,
            rpc_fixture,
            network,
        }) => {
            let failures = verification_failure_policy(&project)?;
            let bytes = observatory_wasm::load_file(wasm)?;
            let client = fixture_client(rpc_fixture)?;
            let network = resolve_network(&project, network);
            let result = observatory_verify::verify_interface(&bytes, &client, contract, &network)?;
            emit(format, "verify.interface", &result, || {
                print_interface_verification(&result);
            })?;
            let status = match result.interface_match {
                Some(true) => VerificationStatus::Match,
                Some(false) => VerificationStatus::Mismatch,
                None => VerificationStatus::InsufficientData,
            };
            Ok(verification_exit(status, &failures))
        }
        Command::Verify(VerifyCommand::Metadata { file }) => {
            let value = read_json(file)?;
            let metadata = observatory_verify::BuildMetadata::from_json(&value)?;
            emit(format, "verify.metadata", &metadata, || {
                for (key, value) in &metadata.entries {
                    println!("{key} = {value}");
                }
            })?;
            Ok(ObservatoryExit::Success)
        }
        Command::Verify(VerifyCommand::Compare { left, right }) => {
            let left = observatory_verify::BuildMetadata::from_json(&read_json(left)?)?;
            let right = observatory_verify::BuildMetadata::from_json(&read_json(right)?)?;
            let comparison = observatory_verify::compare_build_metadata(&left, &right);
            emit(format, "verify.compare", &comparison, || {
                println!("equal: {}", comparison.equal);
                for difference in &comparison.differences {
                    println!(
                        "  {}\n    left:  {}\n    right: {}",
                        difference.key,
                        difference.left.as_deref().unwrap_or("<none>"),
                        difference.right.as_deref().unwrap_or("<none>")
                    );
                }
            })?;
            Ok(ObservatoryExit::Success)
        }
        Command::Verify(VerifyCommand::Batch { manifest, network }) => {
            let failures = verification_failure_policy(&project)?;
            let value = read_json(manifest)?;
            let manifest: BatchManifest = serde_json::from_value(value).map_err(|error| {
                ObservatoryError::invalid(format!("invalid batch manifest: {error}"))
            })?;
            if manifest.entries.is_empty() {
                return Err(ObservatoryError::invalid(
                    "batch manifest must contain at least one entry",
                ));
            }
            let mut results = Vec::with_capacity(manifest.entries.len());
            for entry in &manifest.entries {
                let bytes = observatory_wasm::load_file(&entry.artifact)?;
                let client = fixture_client(&entry.rpc_fixture)?;
                let choice = entry.network.clone().or_else(|| network.clone());
                let network = resolve_network(&project, &choice);
                results.push(observatory_verify::verify_local_vs_deployed(
                    &bytes,
                    &client,
                    &entry.contract,
                    &network,
                )?);
            }
            let batch = observatory_verify::BatchVerification::from_results(results);
            emit(format, "verify.batch", &batch, || print_batch(&batch))?;
            Ok(verification_exit(batch.status(), &failures))
        }
        Command::Repro {
            wasm,
            reference,
            dependencies,
            sbom,
        } => {
            let bytes = observatory_wasm::load_file(wasm)?;
            let reference_bytes = reference
                .as_ref()
                .map(|path| observatory_wasm::load_file(path))
                .transpose()?;
            if *sbom {
                let document = observatory_verify::sbom(&bytes)?;
                emit(format, "repro.sbom", &document, || {
                    print_sbom(&document);
                })?;
            } else if *dependencies {
                let report =
                    observatory_verify::dependency_report(&bytes, reference_bytes.as_deref())?;
                emit(format, "repro.dependencies", &report, || {
                    print_dependencies(&report);
                })?;
            } else {
                let report =
                    observatory_verify::reproducibility_report(&bytes, reference_bytes.as_deref())?;
                emit(format, "repro", &report, || {
                    print_reproducibility(&report);
                })?;
            }
            Ok(ObservatoryExit::Success)
        }
        Command::Api(ApiCommand::Openapi) => {
            let document = observatory_api::openapi::document();
            let json = serde_json::to_string_pretty(&document)
                .map_err(|error| ObservatoryError::internal(error.to_string()))?;
            println!("{json}");
            Ok(ObservatoryExit::Success)
        }
        Command::Api(ApiCommand::Serve {
            bind,
            no_auth,
            rate_limit,
            window_secs,
            keys,
            max_connections,
            read_timeout_secs,
            write_timeout_secs,
            max_request_line_bytes,
            max_header_line_bytes,
            max_headers,
            max_body_bytes,
        }) => {
            init_tracing();
            let config = observatory_platform::PlatformConfig {
                require_auth: if *no_auth {
                    false
                } else {
                    project.api.require_auth
                },
                rate_limit: observatory_platform::RateLimitConfig {
                    limit: rate_limit.unwrap_or_else(|| project.rate_limit().limit),
                    window_secs: if rate_limit.is_some() {
                        *window_secs
                    } else {
                        project.rate_limit().window_secs
                    },
                },
                route_limits: project.route_limits(),
                cors: project.cors(),
            };
            let api = observatory_api::Api::new(config);
            for spec in keys {
                let (role, plaintext) = spec.split_once(':').ok_or_else(|| {
                    ObservatoryError::invalid(format!("--key must be ROLE:KEY, got `{spec}`"))
                })?;
                let role: observatory_platform::Role =
                    role.parse().map_err(ObservatoryError::invalid)?;
                api.insert_plaintext_key(plaintext, role, "cli")?;
            }
            let limits = observatory_api::HttpLimits {
                max_connections: *max_connections,
                read_timeout: std::time::Duration::from_secs(*read_timeout_secs),
                write_timeout: std::time::Duration::from_secs(*write_timeout_secs),
                max_request_line_bytes: *max_request_line_bytes,
                max_header_line_bytes: *max_header_line_bytes,
                max_headers: *max_headers,
                max_body_bytes: *max_body_bytes,
            };
            let listener = std::net::TcpListener::bind(bind).map_err(ObservatoryError::Io)?;
            let addr = listener.local_addr().map_err(ObservatoryError::Io)?;
            if !cli.quiet {
                eprintln!("stellar-contract-platform API listening on http://{addr}");
            }
            observatory_api::http::serve_with_limits(listener, std::sync::Arc::new(api), limits);
            Ok(ObservatoryExit::Success)
        }
        Command::Doctor => {
            let networks = Network::all()
                .iter()
                .map(|network| {
                    serde_json::json!({
                        "name": network.name(),
                        "passphrase": network.passphrase(),
                        "default_rpc_url": network.default_rpc_url(),
                    })
                })
                .collect::<Vec<_>>();
            let payload = serde_json::json!({
                "tool": observatory_core::TOOL_NAME,
                "version": env!("CARGO_PKG_VERSION"),
                "schema_version": observatory_core::SCHEMA_VERSION,
                "capabilities": [
                    "inspect", "spec", "events", "diff", "compat",
                    "fingerprint", "deployment", "verify", "repro", "doctor"
                ],
                "rpc_transport": "fixture/mock only (no live HTTP transport yet)",
                "networks": networks,
            });
            emit(format, "doctor", &payload, || {
                println!("{} {}", payload["tool"], payload["version"]);
                println!("rpc transport: {}", payload["rpc_transport"]);
            })?;
            Ok(ObservatoryExit::Success)
        }
        Command::Completions { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(*shell, &mut command, name, &mut std::io::stdout());
            Ok(ObservatoryExit::Success)
        }
    }
}

fn load_config(cli: &Cli) -> Result<observatory_platform::ProjectConfig> {
    if let Some(path) = &cli.config {
        return observatory_platform::ProjectConfig::from_path(path);
    }
    let directory = std::env::current_dir().map_err(ObservatoryError::Io)?;
    Ok(observatory_platform::ProjectConfig::discover(&directory)?
        .map(|(_path, config)| config)
        .unwrap_or_default())
}

fn resolve_network(
    project: &observatory_platform::ProjectConfig,
    provided: &Option<String>,
) -> String {
    provided
        .clone()
        .or_else(|| project.network().map(str::to_string))
        .unwrap_or_else(|| "testnet".to_string())
}

/// Verification statuses that fail the build, from `ci.fail_on`.
///
/// The default keeps the historical policy: a mismatch is exit `7` and an
/// inconclusive or errored comparison is exit `8`.
fn verification_failure_policy(
    project: &observatory_platform::ProjectConfig,
) -> Result<BTreeSet<String>> {
    project.ci.failure_statuses()
}

fn verification_exit(status: VerificationStatus, failures: &BTreeSet<String>) -> ObservatoryExit {
    let name = match status {
        VerificationStatus::Match => "MATCH",
        VerificationStatus::Mismatch => "MISMATCH",
        VerificationStatus::InsufficientData => "INSUFFICIENT_DATA",
        VerificationStatus::Error => "ERROR",
    };
    if !failures.contains(name) {
        return ObservatoryExit::Success;
    }
    match status {
        VerificationStatus::Match => ObservatoryExit::Success,
        VerificationStatus::Mismatch => ObservatoryExit::Mismatch,
        VerificationStatus::InsufficientData | VerificationStatus::Error => {
            ObservatoryExit::InsufficientData
        }
    }
}

fn load_interface(path: &Path) -> Result<ContractInterface> {
    let bytes = observatory_wasm::load_file(path)?;
    ContractInterface::from_wasm(&bytes)
}

fn fixture_client(path: &Path) -> Result<RpcClient<MockTransport>> {
    let value = read_json(path)?;
    let transport = MockTransport::from_json(&value)?;
    let endpoint = Endpoint::parse("https://fixture.invalid")?;
    Ok(RpcClient::new(endpoint, transport))
}

fn fetch_rpc_events(
    path: &Path,
    limit: Option<usize>,
) -> Result<Vec<observatory_events::EventRecord>> {
    let client = fixture_client(path)?;
    let page_limit = limit.unwrap_or(100).clamp(1, 1000);
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;
    // Bound the number of requests even if a fixture keeps returning a cursor.
    for _ in 0..1000 {
        let mut pagination = serde_json::json!({ "limit": page_limit });
        if let Some(cursor) = &cursor {
            pagination["cursor"] = serde_json::json!(cursor);
        }
        let page = client.get_events(serde_json::json!({ "pagination": pagination }))?;
        for event in &page.events {
            events.push(observatory_events::parse_rpc_event(event)?);
        }
        if events.len() > observatory_core::limits::MAX_EVENTS {
            return Err(ObservatoryError::invalid(format!(
                "RPC events exceeded the {} event limit",
                observatory_core::limits::MAX_EVENTS
            )));
        }
        match page.cursor {
            Some(next) if !next.is_empty() && cursor.as_deref() != Some(next.as_str()) => {
                cursor = Some(next);
            }
            _ => break,
        }
    }
    Ok(events)
}

fn load_network_contract(
    contract: Option<&str>,
    network: &str,
    wasm: Option<&Path>,
    fixture: Option<&Path>,
) -> Result<observatory_deployment::NetworkContract> {
    match (wasm, fixture) {
        (Some(path), None) => {
            let bytes = observatory_wasm::load_file(path)?;
            observatory_deployment::network_contract_from_wasm(network, contract, &bytes)
        }
        (None, Some(path)) => {
            let contract = contract.ok_or_else(|| {
                ObservatoryError::invalid(
                    "--contract is required when a side is loaded from an RPC fixture",
                )
            })?;
            let client = fixture_client(path)?;
            observatory_deployment::network_contract_from_rpc(&client, contract, network)
        }
        _ => Err(ObservatoryError::invalid(
            "each side needs exactly one of --left-wasm/--left-fixture (or the right equivalents)",
        )),
    }
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|error| {
        ObservatoryError::invalid(format!("cannot read `{}`: {error}", path.display()))
    })
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let text = read_text(path)?;
    serde_json::from_str(&text).map_err(|error| {
        ObservatoryError::decode(format!("invalid JSON in `{}`: {error}", path.display()))
    })
}

fn load_suppressions(path: &Path) -> Result<observatory_audit::SuppressionFile> {
    let format = observatory_platform::ConfigFormat::from_path(path)?;
    let text = read_text(path)?;
    let parsed: std::result::Result<observatory_audit::SuppressionFile, String> = match format {
        observatory_platform::ConfigFormat::Yaml => {
            serde_yaml_ng::from_str(&text).map_err(|error| error.to_string())
        }
        observatory_platform::ConfigFormat::Toml => {
            toml::from_str(&text).map_err(|error| error.to_string())
        }
        observatory_platform::ConfigFormat::Json => {
            serde_json::from_str(&text).map_err(|error| error.to_string())
        }
    };
    parsed.map_err(|error| {
        ObservatoryError::invalid(format!(
            "invalid suppression file `{}`: {error}",
            path.display()
        ))
    })
}

fn emit<T: Serialize>(
    format: OutputFormat,
    kind: &str,
    data: &T,
    human: impl FnOnce(),
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", report(kind, data).to_json_pretty()?);
        }
        OutputFormat::Human => human(),
        OutputFormat::Sarif => {
            return Err(ObservatoryError::invalid(
                "SARIF output is only available for `inspect --security`",
            ));
        }
    }
    Ok(())
}

fn emit_error(format: OutputFormat, error: &ObservatoryError) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                ErrorReport::from_error(error).to_json().unwrap_or_default()
            );
        }
        OutputFormat::Human | OutputFormat::Sarif => eprintln!("error: {error}"),
    }
}

fn render_params(params: &[observatory_spec::SpecParam]) -> String {
    params
        .iter()
        .map(|param| format!("{}: {}", param.name, param.ty))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Expand the escape sequences that `StringM` uses in its `Display` output.
///
/// Documents are decoded from XDR into the model via `Display`, which escapes
/// newlines and other control bytes. Human output should show the real text.
fn unescape_doc(doc: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    let mut chars = doc.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Print a documentation string, indented, omitting an empty doc entirely.
fn print_doc(doc: &str, indent: &str) {
    let doc = unescape_doc(doc);
    let doc = doc.trim();
    if doc.is_empty() {
        return;
    }
    for line in doc.lines() {
        println!("{indent}{}", line.trim_end());
    }
}

fn print_inspect(payload: &serde_json::Value) {
    let wasm = &payload["wasm"];
    println!(
        "artifact: {}",
        wasm["artifact_sha256"].as_str().unwrap_or_default()
    );
    println!(
        "size: {} bytes, version {}",
        wasm["size_bytes"], wasm["version"]
    );
    println!(
        "functions: {}, exports: {}, imports: {}, custom sections: {}",
        wasm["function_count"],
        wasm["exports"].as_array().map_or(0, Vec::len),
        wasm["imports"].as_array().map_or(0, Vec::len),
        wasm["custom_sections"].as_array().map_or(0, Vec::len)
    );
    println!(
        "contract spec: {}",
        if wasm["has_contract_spec"].as_bool().unwrap_or(false) {
            "present"
        } else {
            "absent"
        }
    );
    if let Some(audit) = payload.get("audit").filter(|value| !value.is_null()) {
        let suppressed = audit["suppressed"].as_u64().unwrap_or(0);
        if suppressed > 0 {
            println!(
                "audit: {} ({suppressed} suppressed)",
                audit["status"].as_str().unwrap_or("PASS")
            );
        } else {
            println!("audit: {}", audit["status"].as_str().unwrap_or("PASS"));
        }
    }
    if let Some(section) = payload.get("section").filter(|value| !value.is_null()) {
        let name = section["name"].as_str().unwrap_or_default();
        if section["present"].as_bool().unwrap_or(false) {
            println!(
                "custom section `{name}`: {} bytes",
                section["size_bytes"].as_u64().unwrap_or(0)
            );
            println!("{}", section["hex"].as_str().unwrap_or_default());
        } else {
            println!("custom section `{name}`: absent");
        }
    }
}

fn print_spec(spec: &observatory_spec::ContractSpec, summary: &observatory_spec::SpecReport) {
    println!(
        "functions: {}, structs: {}, unions: {}, enums: {}, errors: {}, events: {}",
        summary.functions,
        summary.structs,
        summary.unions,
        summary.enums,
        summary.error_enums,
        summary.events
    );
    for function in &spec.functions {
        println!(
            "  fn {}({}) -> {}",
            function.name,
            render_params(&function.inputs),
            function
                .outputs
                .first()
                .map(ToString::to_string)
                .unwrap_or_else(|| "()".to_string())
        );
        print_doc(&function.doc, "      ");
    }
    for item in &spec.structs {
        println!("  struct {}", item.name);
        print_doc(&item.doc, "      ");
    }
    for item in &spec.unions {
        println!("  union {}", item.name);
        print_doc(&item.doc, "      ");
    }
    for item in &spec.enums {
        println!("  enum {}", item.name);
        print_doc(&item.doc, "      ");
    }
    for item in &spec.error_enums {
        println!("  error enum {}", item.name);
        print_doc(&item.doc, "      ");
    }
}

fn print_type(spec: &observatory_spec::ContractSpec, name: &str) {
    for item in spec.structs.iter().filter(|item| item.name == name) {
        println!("struct {}", item.name);
        print_doc(&item.doc, "  ");
        for field in &item.fields {
            println!("  field {}: {}", field.name, field.ty);
            print_doc(&field.doc, "    ");
        }
    }
    for item in spec.unions.iter().filter(|item| item.name == name) {
        println!("union {}", item.name);
        print_doc(&item.doc, "  ");
        for case in &item.cases {
            if case.types.is_empty() {
                println!("  case {}", case.name);
            } else {
                let types = case
                    .types
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("  case {}({types})", case.name);
            }
            print_doc(&case.doc, "    ");
        }
    }
    for item in spec.enums.iter().filter(|item| item.name == name) {
        println!("enum {}", item.name);
        print_doc(&item.doc, "  ");
        for case in &item.cases {
            println!("  case {} = {}", case.name, case.value);
            print_doc(&case.doc, "    ");
        }
    }
    for item in spec.error_enums.iter().filter(|item| item.name == name) {
        println!("error enum {}", item.name);
        print_doc(&item.doc, "  ");
        for case in &item.cases {
            println!("  case {} = {}", case.name, case.value);
            print_doc(&case.doc, "    ");
        }
    }
}

fn print_events(payload: &serde_json::Value) {
    println!("events: {} of {}", payload["returned"], payload["total"]);
    if let Some(events) = payload["events"].as_array() {
        for event in events {
            println!(
                "  [{}] {} topics={}",
                event["ledger"],
                event["event_type"].as_str().unwrap_or(""),
                event["topics"].as_array().map_or(0, Vec::len)
            );
        }
    }
}

fn print_diff(result: &observatory_diff::InterfaceDiff) {
    println!(
        "changes: {} breaking, {} non-breaking, {} informational",
        result.summary.breaking, result.summary.non_breaking, result.summary.informational
    );
    for change in &result.changes {
        let marker = match change.severity {
            Severity::Breaking => "!",
            Severity::NonBreaking => "+",
            Severity::Informational => "~",
        };
        println!("{marker} {}: {}", change.path, change.detail);
    }
}

fn print_compat(assessment: &observatory_compat::CompatibilityAssessment) {
    let status = match assessment.status {
        CompatibilityStatus::Compatible => "compatible",
        CompatibilityStatus::Incompatible => "incompatible",
        CompatibilityStatus::Unknown => "unknown",
    };
    println!("status: {status}");
    for reason in &assessment.reasons {
        println!(
            "  {} {}",
            if reason.breaking { "breaking" } else { "note" },
            reason.message
        );
    }
}

fn print_fingerprint(payload: &serde_json::Value) {
    println!("artifact_sha256: {}", payload["artifact_sha256"]);
    if let Some(interface) = payload["interface_sha256"].as_str() {
        println!("interface_sha256: {interface}");
    }
}

fn print_deployment(info: &observatory_deployment::DeploymentInfo) {
    println!("contract: {}", info.contract_id);
    println!("found: {}", info.found);
    if let Some(profile) = &info.network {
        println!("network: {} ({})", profile.network, profile.passphrase);
    }
    println!(
        "wasm_hash: {}",
        info.wasm_hash.as_deref().unwrap_or("<unknown>")
    );
    if let Some(storage) = &info.storage {
        println!(
            "storage: {} entries ({} inspected{})",
            storage.entry_count,
            storage.inspected_entries,
            if storage.truncated { ", truncated" } else { "" }
        );
        for (kind, count) in &storage.key_types {
            println!("  key {kind}: {count}");
        }
        for (kind, count) in &storage.value_types {
            println!("  value {kind}: {count}");
        }
    }
}

fn print_network_comparison(comparison: &observatory_deployment::NetworkComparison) {
    let verdict = |value: observatory_deployment::ComparisonVerdict| match value {
        observatory_deployment::ComparisonVerdict::Match => "match",
        observatory_deployment::ComparisonVerdict::Mismatch => "mismatch",
        observatory_deployment::ComparisonVerdict::Unknown => "unknown",
    };
    println!(
        "networks: {} vs {}",
        comparison.left.network, comparison.right.network
    );
    println!(
        "wasm_hash: {} ({} vs {})",
        verdict(comparison.hash),
        comparison.left.wasm_hash.as_deref().unwrap_or("<unknown>"),
        comparison.right.wasm_hash.as_deref().unwrap_or("<unknown>")
    );
    println!("interface: {}", verdict(comparison.interface));
    if let Some(diff) = &comparison.interface_diff {
        print_diff(diff);
    }
}

fn print_interface_verification(result: &observatory_verify::InterfaceVerification) {
    match result.interface_match {
        Some(true) => println!("interface: identical"),
        Some(false) => println!("interface: differs"),
        None => println!("interface: unknown ({})", result.detail),
    }
    if let Some(local) = &result.local_interface_sha256 {
        println!("local_interface_sha256: {local}");
    }
    if let Some(deployed) = &result.deployed_interface_sha256 {
        println!("deployed_interface_sha256: {deployed}");
    }
    println!("artifact: {:?}", result.artifact.status);
    println!("source_verification: {}", result.source_verification);
    if let Some(diff) = &result.diff {
        print_diff(diff);
    }
    if let Some(compatibility) = &result.compatibility {
        print_compat(compatibility);
    }
}

fn print_sbom(sbom: &observatory_verify::Sbom) {
    println!("format: {}", sbom.format);
    println!(
        "component: {}@{}",
        sbom.component.name.as_deref().unwrap_or("<unknown>"),
        sbom.component.version.as_deref().unwrap_or("<unknown>")
    );
    for hash in &sbom.component.hashes {
        println!("{}: {}", hash.algorithm, hash.value);
    }
    match &sbom.dependencies {
        Some(dependencies) => {
            println!("dependencies:");
            for dependency in dependencies {
                println!(
                    "  {} = {}",
                    dependency.name,
                    dependency.version.as_deref().unwrap_or("<unknown>")
                );
            }
        }
        None => println!("dependencies: <unavailable>"),
    }
    if !sbom.unavailable.is_empty() {
        println!("unavailable: {}", sbom.unavailable.join(", "));
    }
}

fn print_dependencies(report: &observatory_verify::DependencyReport) {
    match &report.dependencies {
        Some(dependencies) => {
            println!("dependencies:");
            for dependency in dependencies {
                println!(
                    "  {} = {}",
                    dependency.name,
                    dependency.version.as_deref().unwrap_or("<unknown>")
                );
            }
        }
        None => println!("dependencies: <unavailable>"),
    }
    let state = match report.comparison.state {
        observatory_verify::DependencyComparisonState::Unavailable => "unavailable",
        observatory_verify::DependencyComparisonState::Match => "match",
        observatory_verify::DependencyComparisonState::Mismatch => "mismatch",
    };
    println!("comparison: {state}");
    println!("{}", report.comparison.detail);
    for difference in &report.comparison.differences {
        println!(
            "  {}\n    left:  {}\n    right: {}",
            difference.name,
            difference.left.as_deref().unwrap_or("<none>"),
            difference.right.as_deref().unwrap_or("<none>")
        );
    }
}

fn print_reproducibility(report: &observatory_verify::ReproducibilityReport) {
    match &report.env_meta {
        Some(meta) => println!(
            "environment: protocol {}, pre-release {}",
            meta.protocol, meta.pre_release
        ),
        None => println!("environment: <none>"),
    }
    match &report.build_metadata {
        Some(metadata) if !metadata.entries.is_empty() => {
            println!("build metadata:");
            for (key, value) in &metadata.entries {
                println!("  {key} = {value}");
            }
        }
        _ => println!("build metadata: <none>"),
    }
    let state = match report.comparison.state {
        observatory_verify::MetadataComparisonState::NotCompared => "not_compared",
        observatory_verify::MetadataComparisonState::Match => "match",
        observatory_verify::MetadataComparisonState::Mismatch => "mismatch",
    };
    println!("comparison: {state}");
    println!("{}", report.comparison.detail);
    println!("source_reproduction: {}", report.source_reproduction);
    println!("note: source reproduction was not performed");
}

fn print_verification(result: &observatory_verify::VerificationResult) {
    println!("status: {:?}", result.status);
    println!("{detail}", detail = result.detail);
    println!("local_wasm_hash: {}", result.local_wasm_hash);
    if let Some(deployed) = &result.deployed_wasm_hash {
        println!("deployed_wasm_hash: {deployed}");
    }
}

fn print_batch(batch: &observatory_verify::BatchVerification) {
    for result in &batch.results {
        println!(
            "{}: {:?} ({})",
            result.contract_id, result.status, result.detail
        );
    }
    println!(
        "total: {} matched: {} mismatched: {} insufficient_data: {}",
        batch.summary.total,
        batch.summary.matched,
        batch.summary.mismatched,
        batch.summary.insufficient_data
    );
}
