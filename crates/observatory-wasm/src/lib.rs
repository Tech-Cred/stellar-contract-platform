//! Safe, deterministic inspection of Soroban contract WASM.
//!
//! This crate never executes a module. It parses the binary with a bounded,
//! streaming parser and reports structure. All failures become
//! [`observatory_core::ObservatoryError`].
//!
//! The report is stable, ordered, and JSON-serializable so it can be used in
//! CI. Ordering of imports, exports, and custom sections follows module order,
//! which is meaningful for WASM.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use observatory_core::hash::sha256_hex;
use observatory_core::limits::{
    MAX_CUSTOM_SECTIONS, MAX_DATA_SEGMENTS, MAX_ELEMENT_SEGMENTS, MAX_EXPORTS, MAX_IMPORTS,
    MAX_TABLES, MAX_WASM_BYTES,
};
use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasmparser::{
    ElementItems, ExternalKind, KnownCustom, Name, NameMap, Parser, Payload, TypeRef,
};

/// Custom section name carrying the Soroban contract specification.
pub const CONTRACT_SPEC_SECTION: &str = "contractspecv0";
/// Custom section name carrying contract-level metadata.
pub const CONTRACT_META_SECTION: &str = "contractmetav0";
/// Custom section name carrying the contract environment metadata.
pub const CONTRACT_ENV_META_SECTION: &str = "contractenvmetav0";

/// Maximum custom-section payload size that [`dump_custom_section`] will
/// return as hex, in bytes (64 KiB).
///
/// The cap bounds both the copy and the rendered output. Larger sections are
/// rejected rather than truncated, so a dump is never mistaken for the whole
/// payload.
pub const MAX_DUMP_BYTES: usize = 64 * 1024;

/// Chunk size used when hashing a file incrementally, in bytes (64 KiB).
///
/// Streaming hashing keeps peak memory bounded by this buffer regardless of the
/// artifact size.
pub const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum number of `producers` entries retained across all categories.
pub const MAX_PRODUCER_ENTRIES: usize = 64;

/// Maximum number of function or type names retained from the `name` section.
pub const MAX_NAME_ENTRIES: usize = 64;

/// Maximum length of a single name retained from the `name` section, in bytes.
///
/// The name section does not limit string lengths, so names longer than this
/// are skipped rather than copied into a report.
pub const MAX_NAME_BYTES: usize = 256;

/// Preamble that identifies a WebAssembly component-model binary.
///
/// A core module declares version `1` as `01 00 00 00`. A component declares
/// version `0x0d`, layer `1`, and a reserved `0`, as `0d 00 01 00`. Inspecting
/// components is out of scope for this crate.
pub const COMPONENT_PREAMBLE: [u8; 4] = [0x0d, 0x00, 0x01, 0x00];

/// A single import entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportInfo {
    /// Import module, for example `env`.
    pub module: String,
    /// Import name.
    pub name: String,
    /// Import kind: `func`, `table`, `memory`, `global`, or `tag`.
    pub kind: String,
}

/// A single export entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportInfo {
    /// Export name.
    pub name: String,
    /// Export kind: `func`, `table`, `memory`, `global`, or `tag`.
    pub kind: String,
}

/// A custom section entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomSectionInfo {
    /// Section name.
    pub name: String,
    /// Payload size in bytes.
    pub size: usize,
}

/// Memory declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// Initial number of 64 KiB pages.
    pub initial_pages: u64,
    /// Maximum number of pages, if declared.
    pub maximum_pages: Option<u64>,
    /// Whether the memory is shared.
    pub shared: bool,
    /// Whether this is a 64-bit memory (the WebAssembly `memory64` proposal).
    pub memory64: bool,
}

/// One `producers` entry: a tool name and its version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerEntry {
    /// Tool name, preserved verbatim.
    pub name: String,
    /// Tool version, preserved verbatim.
    pub version: String,
}

/// Build provenance decoded from the `producers` custom section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducersInfo {
    /// `language` entries.
    pub language: Vec<ProducerEntry>,
    /// `processed-by` entries.
    pub processed_by: Vec<ProducerEntry>,
    /// `sdk` entries.
    pub sdk: Vec<ProducerEntry>,
}

/// Bounded names decoded from the optional WASM `name` custom section.
///
/// Each map is keyed by the index being named. Empty maps are omitted from
/// JSON, and the whole object is omitted when no names were retained.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameInfo {
    /// Module name, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Function names by function index, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<BTreeMap<u32, String>>,
    /// Type names by type index, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<BTreeMap<u32, String>>,
}

impl NameInfo {
    fn is_empty(&self) -> bool {
        self.module.is_none()
            && self.functions.as_ref().is_none_or(BTreeMap::is_empty)
            && self.types.as_ref().is_none_or(BTreeMap::is_empty)
    }
}

/// The start section, when declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartInfo {
    /// Index of the start function.
    pub function_index: u32,
}

/// A bounded summary of a data segment. Contents are never retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataSegmentInfo {
    /// Payload size in bytes.
    pub size_bytes: usize,
}

/// A bounded summary of an element segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementSegmentInfo {
    /// Number of items in the segment.
    pub item_count: usize,
}

/// A table declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableInfo {
    /// Element type, for example `funcref`.
    pub element_type: String,
    /// Initial number of elements.
    pub initial: u64,
    /// Maximum number of elements, if declared.
    pub maximum: Option<u64>,
}

/// The result of inspecting a WASM artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmReport {
    /// Artifact size in bytes.
    pub size_bytes: usize,
    /// WASM binary version.
    pub version: u32,
    /// SHA-256 of the artifact bytes.
    pub artifact_sha256: String,
    /// Number of types declared.
    pub type_count: usize,
    /// Number of functions declared.
    pub function_count: usize,
    /// Number of tables declared.
    pub table_count: usize,
    /// Number of globals declared.
    pub global_count: usize,
    /// Start section, when declared.
    pub start: Option<StartInfo>,
    /// Number of data segments declared.
    pub data_segment_count: usize,
    /// Bounded data segment summaries; never the segment contents.
    pub data_segments: Vec<DataSegmentInfo>,
    /// Number of element segments declared.
    pub element_segment_count: usize,
    /// Bounded element segment summaries.
    pub element_segments: Vec<ElementSegmentInfo>,
    /// Bounded table declarations.
    pub tables: Vec<TableInfo>,
    /// Declared memories.
    pub memories: Vec<MemoryInfo>,
    /// Declared imports in module order.
    pub imports: Vec<ImportInfo>,
    /// Declared exports in module order.
    pub exports: Vec<ExportInfo>,
    /// Custom sections in module order.
    pub custom_sections: Vec<CustomSectionInfo>,
    /// Build provenance from the `producers` section, when present and valid.
    pub producers: Option<ProducersInfo>,
    /// Function, module, and type names from the `name` section, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<NameInfo>,
    /// Total byte size of the code section.
    pub code_section_bytes: usize,
    /// Whether a `contractspecv0` section is present.
    pub has_contract_spec: bool,
    /// Size of the `contractspecv0` section payload, if present.
    pub contract_spec_bytes: Option<usize>,
    /// Whether a bounded report list was clipped or malformed entries skipped.
    pub truncated: bool,
}

impl WasmReport {
    /// Names of exported functions, in module order.
    #[must_use]
    pub fn exported_function_names(&self) -> Vec<&str> {
        self.exports
            .iter()
            .filter(|export| export.kind == "func")
            .map(|export| export.name.as_str())
            .collect()
    }
}

/// Read a WASM artifact from disk with a hard size bound.
pub fn load_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        ObservatoryError::Io(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", path.display()),
        ))
    })?;
    if metadata.len() > MAX_WASM_BYTES as u64 {
        return Err(ObservatoryError::invalid(format!(
            "`{}` is {} bytes, which exceeds the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_WASM_BYTES
        )));
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() > MAX_WASM_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "`{}` exceeds the {} byte limit",
            path.display(),
            MAX_WASM_BYTES
        )));
    }
    Ok(bytes)
}

/// Validate that `bytes` is a well-formed WASM module.
pub fn validate(bytes: &[u8]) -> Result<()> {
    inspect(bytes).map(|_| ())
}

/// Inspect a WASM module without executing it.
pub fn inspect(bytes: &[u8]) -> Result<WasmReport> {
    if bytes.len() < 8 {
        return Err(ObservatoryError::wasm(
            "input is too short to be a WASM module",
        ));
    }
    if &bytes[0..4] != b"\0asm" {
        return Err(ObservatoryError::wasm(
            "input does not start with the WASM magic bytes",
        ));
    }
    if bytes[4..8] == COMPONENT_PREAMBLE {
        return Err(ObservatoryError::unsupported(
            "WebAssembly component-model binaries are not supported; \
             only core WASM modules are in scope for contract inspection",
        ));
    }

    let mut report = WasmReport {
        size_bytes: bytes.len(),
        version: 0,
        artifact_sha256: sha256_hex(bytes),
        type_count: 0,
        function_count: 0,
        table_count: 0,
        global_count: 0,
        start: None,
        data_segment_count: 0,
        data_segments: Vec::new(),
        element_segment_count: 0,
        element_segments: Vec::new(),
        tables: Vec::new(),
        memories: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        custom_sections: Vec::new(),
        producers: None,
        name: None,
        code_section_bytes: 0,
        has_contract_spec: false,
        contract_spec_bytes: None,
        truncated: false,
    };

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
        match payload {
            Payload::Version { num, .. } => report.version = u32::from(num),
            Payload::TypeSection(reader) => report.type_count = reader.count() as usize,
            Payload::FunctionSection(reader) => report.function_count = reader.count() as usize,
            Payload::TableSection(reader) => {
                report.table_count = reader.count() as usize;
                for table in reader {
                    let table = table.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
                    if report.tables.len() >= MAX_TABLES {
                        report.truncated = true;
                        break;
                    }
                    report.tables.push(TableInfo {
                        element_type: table.ty.element_type.to_string(),
                        initial: table.ty.initial,
                        maximum: table.ty.maximum,
                    });
                }
            }
            Payload::GlobalSection(reader) => report.global_count = reader.count() as usize,
            Payload::StartSection { func, .. } => {
                report.start = Some(StartInfo {
                    function_index: func,
                });
            }
            Payload::DataSection(reader) => {
                report.data_segment_count = reader.count() as usize;
                for data in reader {
                    let data = data.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
                    if report.data_segments.len() >= MAX_DATA_SEGMENTS {
                        report.truncated = true;
                        break;
                    }
                    report.data_segments.push(DataSegmentInfo {
                        size_bytes: data.data.len(),
                    });
                }
            }
            Payload::ElementSection(reader) => {
                report.element_segment_count = reader.count() as usize;
                for element in reader {
                    let element =
                        element.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
                    if report.element_segments.len() >= MAX_ELEMENT_SEGMENTS {
                        report.truncated = true;
                        break;
                    }
                    let item_count = match &element.items {
                        ElementItems::Functions(items) => items.count() as usize,
                        ElementItems::Expressions(_, items) => items.count() as usize,
                    };
                    report
                        .element_segments
                        .push(ElementSegmentInfo { item_count });
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory =
                        memory.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
                    report.memories.push(MemoryInfo {
                        initial_pages: memory.initial,
                        maximum_pages: memory.maximum,
                        shared: memory.shared,
                        memory64: memory.memory64,
                    });
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    if report.imports.len() >= MAX_IMPORTS {
                        report.truncated = true;
                        break;
                    }
                    let import =
                        import.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
                    report.imports.push(ImportInfo {
                        module: import.module.to_string(),
                        name: import.name.to_string(),
                        kind: type_ref_kind(&import.ty).to_string(),
                    });
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    if report.exports.len() >= MAX_EXPORTS {
                        report.truncated = true;
                        break;
                    }
                    let export =
                        export.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
                    report.exports.push(ExportInfo {
                        name: export.name.to_string(),
                        kind: external_kind(&export.kind).to_string(),
                    });
                }
            }
            Payload::CodeSectionStart { size, .. } => report.code_section_bytes = size as usize,
            Payload::CustomSection(section) => {
                if report.custom_sections.len() >= MAX_CUSTOM_SECTIONS {
                    report.truncated = true;
                    continue;
                }
                let name = section.name().to_string();
                let size = section.data().len();
                if name == CONTRACT_SPEC_SECTION {
                    report.has_contract_spec = true;
                    report.contract_spec_bytes = Some(size);
                }
                if name == "producers" && report.producers.is_none() {
                    if let KnownCustom::Producers(reader) = section.as_known() {
                        let (producers, truncated) = collect_producers(reader);
                        report.producers = Some(producers);
                        report.truncated |= truncated;
                    }
                }
                if name == "name" && report.name.is_none() {
                    if let KnownCustom::Name(reader) = section.as_known() {
                        let (names, truncated) = collect_names(reader);
                        report.truncated |= truncated;
                        if !names.is_empty() {
                            report.name = Some(names);
                        }
                    }
                }
                report
                    .custom_sections
                    .push(CustomSectionInfo { name, size });
            }
            _ => {}
        }
    }

    if report.version == 0 {
        return Err(ObservatoryError::wasm("missing or invalid WASM version"));
    }

    Ok(report)
}

/// A bounded hex dump of a custom section payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionDump {
    /// Section name.
    pub name: String,
    /// Payload size in bytes.
    pub size_bytes: usize,
    /// Payload rendered as lowercase hex.
    pub hex: String,
}

/// Dump a named custom section payload as bounded hex.
///
/// Returns `Ok(None)` when the section is absent and a structured error when
/// its payload exceeds [`MAX_DUMP_BYTES`]. The section is only read, never
/// executed.
pub fn dump_custom_section(bytes: &[u8], name: &str) -> Result<Option<SectionDump>> {
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
        if let Payload::CustomSection(section) = payload {
            if section.name() == name {
                let data = section.data();
                if data.len() > MAX_DUMP_BYTES {
                    return Err(ObservatoryError::invalid(format!(
                        "custom section `{name}` is {} bytes, exceeding the {MAX_DUMP_BYTES} byte dump limit",
                        data.len()
                    )));
                }
                let mut hex = String::with_capacity(data.len() * 2);
                for byte in data {
                    std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"))
                        .expect("writing to a String cannot fail");
                }
                return Ok(Some(SectionDump {
                    name: name.to_string(),
                    size_bytes: data.len(),
                    hex,
                }));
            }
        }
    }
    Ok(None)
}

/// Extract the raw bytes of a named custom section, if present.
pub fn extract_custom_section(bytes: &[u8], name: &str) -> Result<Option<Vec<u8>>> {
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|error| ObservatoryError::wasm(error.to_string()))?;
        if let Payload::CustomSection(section) = payload {
            if section.name() == name {
                return Ok(Some(section.data().to_vec()));
            }
        }
    }
    Ok(None)
}

/// Compute the canonical artifact fingerprint (SHA-256 of the bytes).
#[must_use]
pub fn artifact_fingerprint(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// Compute the artifact fingerprint by streaming the file in bounded chunks.
///
/// Unlike [`artifact_fingerprint`], this never holds the whole artifact in
/// memory: peak memory is one [`HASH_CHUNK_BYTES`] buffer, regardless of file
/// size. The digest is identical to hashing the full contents at once.
pub fn artifact_fingerprint_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        ObservatoryError::Io(std::io::Error::new(
            error.kind(),
            format!("{}: {error}", path.display()),
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            ObservatoryError::Io(std::io::Error::new(
                error.kind(),
                format!("{}: {error}", path.display()),
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Decode `producers` entries, bounding the total retained.
fn collect_producers(reader: wasmparser::ProducersSectionReader<'_>) -> (ProducersInfo, bool) {
    let mut info = ProducersInfo::default();
    let mut total = 0usize;
    let mut truncated = false;
    for field in reader {
        let Ok(field) = field else {
            continue;
        };
        let category = field.name;
        for value in field.values {
            let Ok(value) = value else {
                continue;
            };
            if total >= MAX_PRODUCER_ENTRIES {
                truncated = true;
                break;
            }
            let entry = ProducerEntry {
                name: value.name.to_string(),
                version: value.version.to_string(),
            };
            match category {
                "language" => info.language.push(entry),
                "processed-by" => info.processed_by.push(entry),
                "sdk" => info.sdk.push(entry),
                _ => continue,
            }
            total += 1;
        }
        if truncated {
            break;
        }
    }
    (info, truncated)
}

/// Decode bounded module, function, and type names.
///
/// Unsupported and malformed subsections are skipped rather than reported as
/// inspection errors. A malformed map may leave the section reader in an
/// unknown state, so that map stops at the first bad entry.
fn collect_names(reader: wasmparser::NameSectionReader<'_>) -> (NameInfo, bool) {
    let mut info = NameInfo::default();
    let mut truncated = false;
    for subsection in reader {
        let Ok(subsection) = subsection else {
            truncated = true;
            break;
        };
        match subsection {
            Name::Module { name, .. } => {
                if name.len() > MAX_NAME_BYTES {
                    truncated = true;
                } else {
                    info.module = Some(name.to_string());
                }
            }
            Name::Function(map) => {
                let mut functions = BTreeMap::new();
                collect_name_map(map, &mut functions, &mut truncated);
                if !functions.is_empty() {
                    info.functions = Some(functions);
                }
            }
            Name::Type(map) => {
                let mut types = BTreeMap::new();
                collect_name_map(map, &mut types, &mut truncated);
                if !types.is_empty() {
                    info.types = Some(types);
                }
            }
            _ => {}
        }
    }
    (info, truncated)
}

fn collect_name_map(map: NameMap<'_>, out: &mut BTreeMap<u32, String>, truncated: &mut bool) {
    for naming in map {
        let Ok(naming) = naming else {
            *truncated = true;
            break;
        };
        if out.len() >= MAX_NAME_ENTRIES {
            *truncated = true;
            break;
        }
        if naming.name.len() > MAX_NAME_BYTES {
            *truncated = true;
            continue;
        }
        out.insert(naming.index, naming.name.to_string());
    }
}

fn type_ref_kind(ty: &TypeRef) -> &'static str {
    match ty {
        TypeRef::Func(_) => "func",
        TypeRef::Table(_) => "table",
        TypeRef::Memory(_) => "memory",
        TypeRef::Global(_) => "global",
        TypeRef::Tag(_) => "tag",
        TypeRef::FuncExact(_) => "func",
    }
}

fn external_kind(kind: &ExternalKind) -> &'static str {
    match kind {
        ExternalKind::Func => "func",
        ExternalKind::Table => "table",
        ExternalKind::Memory => "memory",
        ExternalKind::Global => "global",
        ExternalKind::Tag => "tag",
        ExternalKind::FuncExact => "func",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use observatory_testutil::{
        minimal_module, module_with_custom_section, module_with_names, module_with_producers,
        CONTRACT_SPEC_SECTION,
    };

    #[test]
    fn inspects_minimal_module() {
        let report = inspect(&minimal_module()).unwrap();
        assert_eq!(report.version, 1);
        assert_eq!(report.size_bytes, 8);
        assert!(report.imports.is_empty());
        assert!(report.exports.is_empty());
        assert!(!report.has_contract_spec);
        assert_eq!(report.name, None);
        assert_eq!(report.artifact_sha256, sha256_hex(&minimal_module()));
    }

    #[test]
    fn rejects_short_input() {
        let error = inspect(&[0x00, 0x61]).unwrap_err();
        assert!(matches!(error, ObservatoryError::Wasm(_)));
    }

    #[test]
    fn rejects_bad_magic() {
        let error = inspect(b"not wasm at all!!").unwrap_err();
        assert!(matches!(error, ObservatoryError::Wasm(_)));
    }

    #[test]
    fn rejects_component_model_binaries() {
        let component = [b"\0asm".as_slice(), &COMPONENT_PREAMBLE].concat();
        let error = inspect(&component).unwrap_err();
        assert_eq!(
            error.code(),
            observatory_core::ErrorCode::Unsupported,
            "{error}"
        );
        let ObservatoryError::Unsupported(message) = error else {
            panic!("expected unsupported error");
        };
        assert!(message.contains("component"), "{message}");
    }

    #[test]
    fn detects_contract_spec_section() {
        let module = module_with_custom_section(CONTRACT_SPEC_SECTION, &[1, 2, 3, 4]);
        let report = inspect(&module).unwrap();
        assert!(report.has_contract_spec);
        assert_eq!(report.contract_spec_bytes, Some(4));
        assert!(report
            .custom_sections
            .iter()
            .any(|section| section.name == CONTRACT_SPEC_SECTION));
    }

    #[test]
    fn extracts_custom_section_bytes() {
        let module = module_with_custom_section("hello", &[9, 8, 7]);
        let data = extract_custom_section(&module, "hello").unwrap();
        assert_eq!(data, Some(vec![9, 8, 7]));
        assert_eq!(extract_custom_section(&module, "missing").unwrap(), None);
    }

    #[test]
    fn dumps_a_custom_section_as_bounded_hex() {
        let module = module_with_custom_section("hello", &[9, 8, 7]);
        let dump = dump_custom_section(&module, "hello").unwrap().unwrap();
        assert_eq!(dump.name, "hello");
        assert_eq!(dump.size_bytes, 3);
        assert_eq!(dump.hex, "090807");
    }

    #[test]
    fn dumps_absent_section_as_none() {
        let module = module_with_custom_section("hello", &[1]);
        assert_eq!(dump_custom_section(&module, "missing").unwrap(), None);
    }

    #[test]
    fn rejects_a_section_larger_than_the_dump_limit() {
        let payload = vec![0u8; MAX_DUMP_BYTES + 1];
        let module = module_with_custom_section("big", &payload);
        let error = dump_custom_section(&module, "big").unwrap_err();
        assert!(matches!(error, ObservatoryError::InvalidInput(_)));
        assert!(error.to_string().contains("dump limit"));
    }

    #[test]
    fn reports_imports_exports_and_memory() {
        let wasm = wat::parse_str(
            r#"(module
                (import "env" "dbg" (func $dbg (param i32)))
                (memory 1 2)
                (func (export "hello") (param i32) (result i32) local.get 0)
                (global (export "g") i32 (i32.const 7))
            )"#,
        )
        .unwrap();
        let report = inspect(&wasm).unwrap();
        assert_eq!(report.imports.len(), 1);
        assert_eq!(report.imports[0].module, "env");
        assert_eq!(report.imports[0].name, "dbg");
        assert_eq!(report.imports[0].kind, "func");
        assert!(report.exported_function_names().contains(&"hello"));
        assert_eq!(report.memories.len(), 1);
        assert_eq!(report.memories[0].initial_pages, 1);
        assert_eq!(report.memories[0].maximum_pages, Some(2));
        assert!(!report.memories[0].memory64);
        assert!(report.code_section_bytes > 0);
    }

    #[test]
    fn reports_names_from_a_wat_fixture() {
        let wasm = wat::parse_str(
            r#"(module $demo
                (type $counter (func))
                (func $increment (type $counter))
            )"#,
        )
        .unwrap();
        let report = inspect(&wasm).unwrap();
        let names = report.name.expect("wat fixture has a name section");
        assert_eq!(names.module.as_deref(), Some("demo"));
        assert!(names
            .functions
            .as_ref()
            .is_some_and(|map| map.values().any(|name| name == "increment")));
        assert!(names
            .types
            .as_ref()
            .is_some_and(|map| map.values().any(|name| name == "counter")));
    }

    #[test]
    fn reports_module_function_and_type_names() {
        let module = module_with_names(Some("demo"), &[(3, "run"), (0, "init")], &[(1, "Config")]);
        let report = inspect(&module).unwrap();
        let names = report.name.as_ref().expect("name section");
        assert_eq!(names.module.as_deref(), Some("demo"));
        let functions = names.functions.as_ref().expect("function names");
        assert_eq!(functions.get(&0).map(String::as_str), Some("init"));
        assert_eq!(functions.get(&3).map(String::as_str), Some("run"));
        let types = names.types.as_ref().expect("type names");
        assert_eq!(types.get(&1).map(String::as_str), Some("Config"));

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["name"]["module"], "demo");
        assert_eq!(json["name"]["functions"]["0"], "init");
        assert_eq!(json["name"]["types"]["1"], "Config");
    }

    #[test]
    fn names_are_omitted_when_the_section_is_absent() {
        let report = inspect(&minimal_module()).unwrap();
        assert!(report.name.is_none());
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("name").is_none(), "{json}");
    }

    #[test]
    fn malformed_name_section_does_not_fail_inspection() {
        // Module-name subsection declares five bytes but supplies one.
        let module = module_with_custom_section("name", &[0, 5, b'a']);
        let report = inspect(&module).unwrap();
        assert_eq!(report.name, None);
        assert!(report.truncated);
    }

    #[test]
    fn names_are_bounded() {
        let names: Vec<(u32, String)> = (0..MAX_NAME_ENTRIES + 3)
            .map(|index: usize| (index as u32, format!("function-{index}")))
            .collect();
        let entries: Vec<(u32, &str)> = names
            .iter()
            .map(|(index, name)| (*index, name.as_str()))
            .collect();
        let module = module_with_names(None, &entries, &[]);
        let report = inspect(&module).unwrap();
        let truncated = report.truncated;
        let names = report.name.expect("function names");
        let functions = names.functions.expect("function map");
        assert_eq!(functions.len(), MAX_NAME_ENTRIES);
        assert!(truncated);
        assert!(names.module.is_none());
    }

    #[test]
    fn oversized_names_are_skipped() {
        let long = "x".repeat(MAX_NAME_BYTES + 1);
        let module = module_with_names(None, &[(0, &long)], &[]);
        let report = inspect(&module).unwrap();
        assert!(report.truncated);
        assert_eq!(report.name, None);
    }

    #[test]
    fn reports_start_tables_data_and_element_details() {
        let wasm = wat::parse_str(
            r#"(module
                (table 2 4 funcref)
                (memory 1)
                (global i32 (i32.const 7))
                (func $f)
                (start $f)
                (data (i32.const 0) "hello")
                (elem (i32.const 0) $f)
            )"#,
        )
        .unwrap();
        let report = inspect(&wasm).unwrap();
        assert_eq!(report.start, Some(StartInfo { function_index: 0 }));
        assert_eq!(report.table_count, 1);
        assert_eq!(report.tables.len(), 1);
        assert_eq!(report.tables[0].element_type, "funcref");
        assert_eq!(report.tables[0].initial, 2);
        assert_eq!(report.tables[0].maximum, Some(4));
        assert_eq!(report.global_count, 1);
        assert_eq!(report.data_segment_count, 1);
        assert_eq!(
            report.data_segments,
            vec![DataSegmentInfo { size_bytes: 5 }]
        );
        assert_eq!(report.element_segment_count, 1);
        assert_eq!(
            report.element_segments,
            vec![ElementSegmentInfo { item_count: 1 }]
        );
        // Segment contents must never be materialised in the report.
        assert!(!format!("{report:?}").contains("hello"));
    }

    #[test]
    fn reports_absent_start_data_and_element_sections() {
        let report = inspect(&minimal_module()).unwrap();
        assert_eq!(report.start, None);
        assert_eq!(report.table_count, 0);
        assert!(report.tables.is_empty());
        assert_eq!(report.data_segment_count, 0);
        assert!(report.data_segments.is_empty());
        assert_eq!(report.element_segment_count, 0);
        assert!(report.element_segments.is_empty());
    }

    #[test]
    fn malformed_detail_sections_are_structured_errors() {
        // A data section that declares one segment but supplies no payload.
        let wasm = [b"\0asm".as_slice(), &[1, 0, 0, 0], &[11, 2, 1, 0]].concat();
        let error = inspect(&wasm).unwrap_err();
        assert!(matches!(error, ObservatoryError::Wasm(_)));

        // A start section whose declared length runs past the input.
        let wasm = [b"\0asm".as_slice(), &[1, 0, 0, 0], &[8, 3, 0]].concat();
        let error = inspect(&wasm).unwrap_err();
        assert!(matches!(error, ObservatoryError::Wasm(_)));
    }

    #[test]
    fn fingerprint_changes_with_content() {
        let a = artifact_fingerprint(&minimal_module());
        let b = artifact_fingerprint(&module_with_custom_section("x", &[1]));
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn load_file_bound_is_enforced() {
        let error = load_file(Path::new("does-not-exist.wasm")).unwrap_err();
        assert!(matches!(error, ObservatoryError::Io(_)));
    }

    #[test]
    fn streaming_and_in_memory_hashes_match() {
        let payload = vec![0x42u8; HASH_CHUNK_BYTES * 3 + 17];
        let module = module_with_custom_section("blob", &payload);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact.wasm");
        std::fs::write(&path, &module).unwrap();

        assert_eq!(
            artifact_fingerprint(&module),
            artifact_fingerprint_file(&path).unwrap()
        );
    }

    #[test]
    fn streaming_hash_reports_io_errors() {
        let error = artifact_fingerprint_file(Path::new("does-not-exist.wasm")).unwrap_err();
        assert!(matches!(error, ObservatoryError::Io(_)));
    }

    #[test]
    fn reports_memory64_flag() {
        let wasm64 = wat::parse_str("(module (memory i64 1 2))").unwrap();
        let report = inspect(&wasm64).unwrap();
        assert_eq!(report.memories.len(), 1);
        assert!(report.memories[0].memory64);

        let wasm32 = wat::parse_str("(module (memory 1 2))").unwrap();
        let report = inspect(&wasm32).unwrap();
        assert!(!report.memories[0].memory64);
    }

    #[test]
    fn reports_producers_custom_section() {
        let module = module_with_producers(&[
            ("language", &[("Rust", "1.80")]),
            ("processed-by", &[("rustc", "1.80.0")]),
            ("sdk", &[("soroban-sdk", "21.0.0")]),
        ]);
        let report = inspect(&module).unwrap();
        let producers = report.producers.expect("producers section");
        assert_eq!(
            producers.language,
            vec![ProducerEntry {
                name: "Rust".to_string(),
                version: "1.80".to_string(),
            }]
        );
        assert_eq!(producers.processed_by[0].name, "rustc");
        assert_eq!(producers.sdk[0].name, "soroban-sdk");
    }

    #[test]
    fn absent_producers_is_not_an_error() {
        let report = inspect(&minimal_module()).unwrap();
        assert!(report.producers.is_none());
    }
}
