//! Deterministic fixture builders shared by Observatory test suites.
//!
//! Fixtures are constructed from bytes rather than checked-in binaries so tests
//! are reproducible and reviewable. WASM custom sections are assembled by hand
//! because the contract specification lives in a `contractspecv0` custom
//! section carrying XDR-encoded entries.

use stellar_xdr::{Limits, ScSpecEntry, WriteXdr};

pub mod spec;

/// The WASM 1.0 module header.
pub const WASM_HEADER: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// The Soroban contract specification custom section name.
pub const CONTRACT_SPEC_SECTION: &str = "contractspecv0";

/// Encode an unsigned integer as LEB128 (the WASM variable-length integer).
#[must_use]
pub fn leb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Build a WASM custom section with the given name and payload.
#[must_use]
pub fn custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut contents = Vec::new();
    contents.extend(leb128(name.len() as u64));
    contents.extend_from_slice(name.as_bytes());
    contents.extend_from_slice(payload);
    let mut out = vec![0x00];
    out.extend(leb128(contents.len() as u64));
    out.extend(contents);
    out
}

/// A minimal, valid, empty WASM module.
#[must_use]
pub fn minimal_module() -> Vec<u8> {
    WASM_HEADER.to_vec()
}

/// A WASM module containing a single custom section.
#[must_use]
pub fn module_with_custom_section(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = minimal_module();
    out.extend(custom_section(name, payload));
    out
}

/// Encode a sequence of contract specification entries as a raw XDR stream.
#[must_use]
pub fn encode_spec_entries(entries: &[ScSpecEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let bytes = entry.to_xdr(Limits::none()).expect("encode spec entry");
        out.extend(bytes);
    }
    out
}

/// A WASM module containing a `contractspecv0` section for `entries`.
#[must_use]
pub fn module_with_spec(entries: &[ScSpecEntry]) -> Vec<u8> {
    module_with_custom_section(CONTRACT_SPEC_SECTION, &encode_spec_entries(entries))
}

/// Encode the payload of a `producers` custom section.
///
/// `fields` are `(category, [(tool, version)])` tuples, for example
/// `("language", &[("Rust", "1.80")])`.
#[must_use]
pub fn encode_producers(fields: &[(&str, &[(&str, &str)])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(leb128(fields.len() as u64));
    for (category, values) in fields {
        out.extend(leb128(category.len() as u64));
        out.extend_from_slice(category.as_bytes());
        out.extend(leb128(values.len() as u64));
        for &(tool, version) in *values {
            out.extend(leb128(tool.len() as u64));
            out.extend_from_slice(tool.as_bytes());
            out.extend(leb128(version.len() as u64));
            out.extend_from_slice(version.as_bytes());
        }
    }
    out
}

/// A WASM module containing a `producers` custom section.
#[must_use]
pub fn module_with_producers(fields: &[(&str, &[(&str, &str)])]) -> Vec<u8> {
    module_with_custom_section("producers", &encode_producers(fields))
}

/// Encode a `name` section name map: a count followed by index/name pairs.
#[must_use]
pub fn encode_name_map(entries: &[(u32, &str)]) -> Vec<u8> {
    let mut out = leb128(entries.len() as u64);
    for (index, name) in entries {
        out.extend(leb128(u64::from(*index)));
        out.extend(leb128(name.len() as u64));
        out.extend_from_slice(name.as_bytes());
    }
    out
}

/// Encode a `name` custom section payload with module, function, and type names.
#[must_use]
pub fn encode_name_section(
    module: Option<&str>,
    functions: &[(u32, &str)],
    types: &[(u32, &str)],
) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(name) = module {
        let mut payload = leb128(name.len() as u64);
        payload.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend(leb128(payload.len() as u64));
        out.extend(payload);
    }
    for (id, entries) in [(1u8, functions), (4u8, types)] {
        let payload = encode_name_map(entries);
        out.push(id);
        out.extend(leb128(payload.len() as u64));
        out.extend(payload);
    }
    out
}

/// A WASM module containing a `name` custom section.
#[must_use]
pub fn module_with_names(
    module: Option<&str>,
    functions: &[(u32, &str)],
    types: &[(u32, &str)],
) -> Vec<u8> {
    module_with_custom_section("name", &encode_name_section(module, functions, types))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128_encodes_known_values() {
        assert_eq!(leb128(0), vec![0x00]);
        assert_eq!(leb128(127), vec![0x7f]);
        assert_eq!(leb128(128), vec![0x80, 0x01]);
        assert_eq!(leb128(624485), vec![0xe5, 0x8e, 0x26]);
    }

    #[test]
    fn custom_section_has_correct_shape() {
        let section = custom_section("hi", &[1, 2, 3]);
        assert_eq!(section[0], 0x00);
        assert_eq!(section[1] as usize, 1 + 2 + 3);
        assert_eq!(section[2], 2);
        assert_eq!(&section[3..5], b"hi");
        assert_eq!(&section[5..], &[1, 2, 3]);
    }

    #[test]
    fn minimal_module_is_eight_bytes() {
        assert_eq!(minimal_module(), WASM_HEADER);
    }

    #[test]
    fn producers_payload_carries_fields_and_values() {
        let payload = encode_producers(&[
            ("language", &[("Rust", "1.80")]),
            ("sdk", &[("soroban-sdk", "21.0.0")]),
        ]);
        // Two fields, then the first name length.
        assert_eq!(payload[0], 2);
        assert_eq!(payload[1], 8);
        assert_eq!(&payload[2..10], b"language");
    }

    #[test]
    fn name_payload_uses_expected_subsection_ids() {
        let payload = encode_name_section(Some("demo"), &[(0, "run")], &[(1, "Config")]);
        assert_eq!(payload[0], 0);
        assert_eq!(&payload[..5], &[0, 5, 4, b'd', b'e']);
        assert!(payload.windows(2).any(|w| w == [1, 6]));
        assert!(payload.windows(2).any(|w| w == [4, 9]));
    }
}
