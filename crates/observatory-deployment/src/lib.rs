//! Deployed contract inspection.
//!
//! Deployment lookup reads the contract instance ledger entry through
//! `getLedgerEntries` and decodes the returned `LedgerEntryData` XDR to recover
//! the deployed WASM hash. The ledger key and entry are real Stellar XDR types;
//! nothing about the RPC shape is invented.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};

use observatory_core::limits::MAX_WASM_BYTES;
use observatory_core::{Network, NetworkProfile, ObservatoryError, Result};
use observatory_diff::{diff, InterfaceDiff};
use observatory_interface::ContractInterface;
use observatory_rpc::{LedgerEntryResult, RpcClient, Transport};
use serde::Serialize;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScContractInstance,
    ScMap, ScVal, WriteXdr,
};

/// Default number of ledger entries retained by a [`LedgerEntryCache`].
pub const DEFAULT_LEDGER_CACHE_CAPACITY: usize = 128;

/// Maximum instance-storage entries inspected for type counts.
///
/// The instance entry's storage map can be large. Only the first
/// `MAX_STORAGE_ENTRIES_INSPECTED` entries contribute to the reported type
/// counts; the total entry count is still reported and `truncated` is set when
/// the map is larger. Entry values are never serialized.
pub const MAX_STORAGE_ENTRIES_INSPECTED: usize = 256;

/// Bounded summary of a contract instance's storage map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstanceStorage {
    /// Total number of entries declared by the instance storage map.
    pub entry_count: usize,
    /// Number of entries inspected for type counts.
    pub inspected_entries: usize,
    /// Whether `entry_count` exceeded [`MAX_STORAGE_ENTRIES_INSPECTED`].
    pub truncated: bool,
    /// Counts of inspected keys by `ScVal` type name.
    pub key_types: BTreeMap<String, usize>,
    /// Counts of inspected values by `ScVal` type name.
    pub value_types: BTreeMap<String, usize>,
}

/// Information recovered about a deployed contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeploymentInfo {
    /// The contract id (C... strkey) that was queried.
    pub contract_id: String,
    /// The deployed executable WASM hash (hex), if the contract is WASM-backed.
    pub wasm_hash: Option<String>,
    /// Last modified ledger sequence of the instance entry.
    pub last_modified_ledger_seq: Option<u32>,
    /// Live-until ledger sequence of the instance entry.
    pub live_until_ledger_seq: Option<u32>,
    /// Whether a contract instance entry was found.
    pub found: bool,
    /// Bounded storage summary, when the instance carries a storage map.
    pub storage: Option<InstanceStorage>,
    /// The resolved network profile, when the lookup was made on a named network.
    pub network: Option<NetworkProfile>,
}

/// A contract observed on one network, ready for cross-network comparison.
///
/// The interface itself is retained for diffing but is not serialized; reports
/// carry its fingerprint and the resulting changes instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkContract {
    /// Human-readable network label.
    pub network: String,
    /// The contract id, when the contract was looked up rather than supplied
    /// as a local artifact.
    pub contract_id: Option<String>,
    /// The deployed WASM hash (hex), when known.
    pub wasm_hash: Option<String>,
    /// Canonical fingerprint of the interface, when known.
    pub interface_sha256: Option<String>,
    /// The parsed interface, retained for diffing but not serialized.
    #[serde(skip)]
    pub interface: Option<ContractInterface>,
}

/// The verdict for one aspect (hash or interface) of a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVerdict {
    /// Both sides are known and equal.
    Match,
    /// Both sides are known and differ.
    Mismatch,
    /// At least one side is unknown, so no verdict is possible.
    Unknown,
}

/// The structured result of comparing one contract across two networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkComparison {
    /// The left side.
    pub left: NetworkContract,
    /// The right side.
    pub right: NetworkContract,
    /// Whether the deployed WASM hashes match.
    pub hash: ComparisonVerdict,
    /// Whether the canonical interface fingerprints match.
    pub interface: ComparisonVerdict,
    /// Per-change detail when both interfaces are known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_diff: Option<InterfaceDiff>,
}

/// Build a network contract from local WASM bytes.
///
/// This is the offline path used by tests and by `--left-wasm`/`--right-wasm`.
pub fn network_contract_from_wasm(
    network: impl Into<String>,
    contract_id: Option<&str>,
    wasm: &[u8],
) -> Result<NetworkContract> {
    let interface = ContractInterface::from_wasm(wasm).ok();
    let interface_sha256 = interface
        .as_ref()
        .map(ContractInterface::fingerprint)
        .transpose()?;
    Ok(NetworkContract {
        network: network.into(),
        contract_id: contract_id.map(str::to_string),
        wasm_hash: Some(observatory_wasm::artifact_fingerprint(wasm)),
        interface_sha256,
        interface,
    })
}

/// Build a network contract by inspecting a deployment through `client`.
///
/// This is the source abstraction for a live or fixture-backed RPC lookup.
pub fn network_contract_from_rpc<T: Transport>(
    client: &RpcClient<T>,
    contract_id: &str,
    network: impl Into<String>,
) -> Result<NetworkContract> {
    let network = network.into();
    let info = inspect(client, contract_id)?;
    let mut contract = NetworkContract {
        network: network.clone(),
        contract_id: Some(contract_id.to_string()),
        wasm_hash: info.wasm_hash.clone(),
        interface_sha256: None,
        interface: None,
    };
    if let Some(hash) = &info.wasm_hash {
        if let Some(wasm) = deployed_wasm(client, hash)? {
            let local = network_contract_from_wasm(network, Some(contract_id), &wasm)?;
            contract.interface = local.interface;
            contract.interface_sha256 = local.interface_sha256;
        }
    }
    Ok(contract)
}

/// Compare one contract across two networks.
///
/// Hashes and interfaces are reported independently so a hash mismatch and an
/// interface change are never conflated. Unknown sides yield
/// [`ComparisonVerdict::Unknown`] rather than a false match.
#[must_use]
pub fn compare_networks(left: NetworkContract, right: NetworkContract) -> NetworkComparison {
    let hash = verdict(left.wasm_hash.as_deref(), right.wasm_hash.as_deref());
    let interface = verdict(
        left.interface_sha256.as_deref(),
        right.interface_sha256.as_deref(),
    );
    let interface_diff = match (&left.interface, &right.interface) {
        (Some(left), Some(right)) => Some(diff(left, right)),
        _ => None,
    };
    NetworkComparison {
        left,
        right,
        hash,
        interface,
        interface_diff,
    }
}

fn verdict(left: Option<&str>, right: Option<&str>) -> ComparisonVerdict {
    match (left, right) {
        (Some(left), Some(right)) if left == right => ComparisonVerdict::Match,
        (Some(_), Some(_)) => ComparisonVerdict::Mismatch,
        _ => ComparisonVerdict::Unknown,
    }
}

/// A small, bounded, in-memory cache for `getLedgerEntries` lookups.
///
/// The cache is scoped to one process run: it is never persisted and never
/// shared between runs or processes. It is opt-in — pass it to
/// [`inspect_with_cache`] or [`deployed_wasm_with_cache`]. Entries are evicted
/// in insertion order once [`capacity`](LedgerEntryCache::capacity) is reached,
/// and missing entries are cached too so repeated misses do not hit the RPC.
///
/// A capacity of `0` disables caching while keeping the same call shape.
#[derive(Debug)]
pub struct LedgerEntryCache {
    capacity: usize,
    entries: RefCell<VecDeque<(String, Option<LedgerEntryResult>)>>,
}

impl LedgerEntryCache {
    /// Creates a cache with the given capacity. `0` disables caching.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        LedgerEntryCache {
            capacity,
            entries: RefCell::new(VecDeque::new()),
        }
    }

    /// Creates a cache with [`DEFAULT_LEDGER_CACHE_CAPACITY`].
    #[must_use]
    pub fn with_default_capacity() -> Self {
        LedgerEntryCache::new(DEFAULT_LEDGER_CACHE_CAPACITY)
    }

    /// The maximum number of entries retained.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of cached entries, including cached misses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.borrow().len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every cached entry.
    pub fn clear(&self) {
        self.entries.borrow_mut().clear();
    }

    fn get(&self, key: &str) -> Option<Option<LedgerEntryResult>> {
        self.entries
            .borrow()
            .iter()
            .find(|(cached, _)| cached == key)
            .map(|(_, entry)| entry.clone())
    }

    fn insert(&self, key: String, entry: Option<LedgerEntryResult>) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self.entries.borrow_mut();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back((key, entry));
    }

    /// Returns a cached entry, fetching it through `client` on a miss.
    ///
    /// Both hits and misses are cached; a miss is stored as `None`.
    pub fn get_or_fetch<T: Transport>(
        &self,
        client: &RpcClient<T>,
        ledger_key: &str,
    ) -> Result<Option<LedgerEntryResult>> {
        if let Some(cached) = self.get(ledger_key) {
            return Ok(cached);
        }
        let entries = client.get_ledger_entries(&[ledger_key.to_string()])?;
        let entry = entries.into_iter().next();
        self.insert(ledger_key.to_string(), entry.clone());
        Ok(entry)
    }
}

/// Decode a contract id strkey into its 32-byte hash.
pub fn contract_id_hash(input: &str) -> Result<[u8; 32]> {
    let parsed = stellar_strkey::Strkey::from_string(input.trim())
        .map_err(|error| ObservatoryError::invalid(format!("invalid contract id: {error}")))?;
    match parsed {
        stellar_strkey::Strkey::Contract(contract) => Ok(contract.0),
        _ => Err(ObservatoryError::invalid(
            "provided strkey is not a contract id (expected a C... strkey)",
        )),
    }
}

/// Build the base64-XDR ledger key for a contract instance entry.
pub fn contract_instance_key(contract_id: &str) -> Result<String> {
    let hash = contract_id_hash(contract_id)?;
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash(hash))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    key.to_xdr_base64(Limits::none()).map_err(|error| {
        ObservatoryError::internal(format!("failed to encode ledger key: {error}"))
    })
}

/// Inspect a deployed contract, returning its deployed WASM hash when known.
pub fn inspect<T: Transport>(client: &RpcClient<T>, contract_id: &str) -> Result<DeploymentInfo> {
    let key = contract_instance_key(contract_id)?;
    let entries = client.get_ledger_entries(&[key])?;
    deployment_info(contract_id, entries.first())
}

/// Inspect a deployed contract on a named network, recording the resolved
/// [`NetworkProfile`] in the result.
pub fn inspect_on_network<T: Transport>(
    client: &RpcClient<T>,
    contract_id: &str,
    network: Network,
) -> Result<DeploymentInfo> {
    let mut info = inspect(client, contract_id)?;
    info.network = Some(network.profile());
    Ok(info)
}

/// Inspect a deployed contract using a [`LedgerEntryCache`].
///
/// Repeating the same lookup with the same cache performs one RPC call.
pub fn inspect_with_cache<T: Transport>(
    client: &RpcClient<T>,
    contract_id: &str,
    cache: &LedgerEntryCache,
) -> Result<DeploymentInfo> {
    let key = contract_instance_key(contract_id)?;
    let entry = cache.get_or_fetch(client, &key)?;
    deployment_info(contract_id, entry.as_ref())
}

fn deployment_info(contract_id: &str, entry: Option<&LedgerEntryResult>) -> Result<DeploymentInfo> {
    let Some(entry) = entry else {
        return Ok(DeploymentInfo {
            contract_id: contract_id.to_string(),
            wasm_hash: None,
            last_modified_ledger_seq: None,
            live_until_ledger_seq: None,
            found: false,
            storage: None,
            network: None,
        });
    };
    let instance = decode_instance(entry)?;
    let wasm_hash = instance
        .as_ref()
        .and_then(|instance| match &instance.executable {
            ContractExecutable::Wasm(hash) => Some(hex::encode(hash.0)),
            _ => None,
        });
    let storage = instance
        .as_ref()
        .and_then(|instance| instance.storage.as_ref())
        .map(storage_summary);
    Ok(DeploymentInfo {
        contract_id: contract_id.to_string(),
        wasm_hash,
        last_modified_ledger_seq: entry.last_modified_ledger_seq,
        live_until_ledger_seq: entry.live_until_ledger_seq,
        found: true,
        storage,
        network: None,
    })
}

/// Decode the contract instance from a ledger entry, when the entry is one.
fn decode_instance(entry: &LedgerEntryResult) -> Result<Option<ScContractInstance>> {
    let data = LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())
        .map_err(|error| ObservatoryError::decode(format!("invalid ledger entry XDR: {error}")))?;
    let LedgerEntryData::ContractData(contract) = data else {
        return Ok(None);
    };
    match contract.val {
        ScVal::ContractInstance(instance) => Ok(Some(instance)),
        _ => Ok(None),
    }
}

/// Decode the WASM hash from a ledger entry result, if it is a WASM-backed instance.
pub fn decode_wasm_hash(entry: &LedgerEntryResult) -> Result<Option<String>> {
    Ok(
        decode_instance(entry)?.and_then(|instance| match instance.executable {
            ContractExecutable::Wasm(hash) => Some(hex::encode(hash.0)),
            _ => None,
        }),
    )
}

/// Summarize a storage map without serializing keys or values.
fn storage_summary(map: &ScMap) -> InstanceStorage {
    let entry_count = map.len();
    let mut key_types = BTreeMap::new();
    let mut value_types = BTreeMap::new();
    let mut inspected_entries = 0;
    for entry in map.iter().take(MAX_STORAGE_ENTRIES_INSPECTED) {
        *key_types
            .entry(scval_type_name(&entry.key).to_string())
            .or_insert(0) += 1;
        *value_types
            .entry(scval_type_name(&entry.val).to_string())
            .or_insert(0) += 1;
        inspected_entries += 1;
    }
    InstanceStorage {
        entry_count,
        inspected_entries,
        truncated: entry_count > inspected_entries,
        key_types,
        value_types,
    }
}

/// Stable type name for an `ScVal`, used as a bounded counting bucket.
fn scval_type_name(value: &ScVal) -> &'static str {
    match value {
        ScVal::Bool(_) => "bool",
        ScVal::Void => "void",
        ScVal::Error(_) => "error",
        ScVal::U32(_) => "u32",
        ScVal::I32(_) => "i32",
        ScVal::U64(_) => "u64",
        ScVal::I64(_) => "i64",
        ScVal::Timepoint(_) => "timepoint",
        ScVal::Duration(_) => "duration",
        ScVal::U128(_) => "u128",
        ScVal::I128(_) => "i128",
        ScVal::U256(_) => "u256",
        ScVal::I256(_) => "i256",
        ScVal::Bytes(_) => "bytes",
        ScVal::String(_) => "string",
        ScVal::Symbol(_) => "symbol",
        ScVal::Vec(_) => "vec",
        ScVal::Map(_) => "map",
        ScVal::Address(_) => "address",
        ScVal::ContractInstance(_) => "contract_instance",
        ScVal::LedgerKeyContractInstance => "ledger_key_contract_instance",
        ScVal::LedgerKeyNonce(_) => "ledger_key_nonce",
        ScVal::ExecutableTag(_) => "executable_tag",
    }
}

/// Fetch and decode the deployed WASM code for a WASM hash (hex).
///
/// Returns `None` when no code entry exists for the hash.
pub fn deployed_wasm<T: Transport>(
    client: &RpcClient<T>,
    wasm_hash_hex: &str,
) -> Result<Option<Vec<u8>>> {
    let key = contract_code_key(wasm_hash_hex)?;
    let entries = client.get_ledger_entries(&[key])?;
    decode_deployed_wasm(entries.first())
}

/// Fetch deployed WASM using a [`LedgerEntryCache`].
///
/// Repeating the same lookup with the same cache performs one RPC call.
pub fn deployed_wasm_with_cache<T: Transport>(
    client: &RpcClient<T>,
    wasm_hash_hex: &str,
    cache: &LedgerEntryCache,
) -> Result<Option<Vec<u8>>> {
    let key = contract_code_key(wasm_hash_hex)?;
    let entry = cache.get_or_fetch(client, &key)?;
    decode_deployed_wasm(entry.as_ref())
}

fn contract_code_key(wasm_hash_hex: &str) -> Result<String> {
    let bytes = hex::decode(wasm_hash_hex.trim())
        .map_err(|error| ObservatoryError::invalid(format!("invalid wasm hash: {error}")))?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ObservatoryError::invalid("wasm hash must be 32 bytes"))?;
    let key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: Hash(hash) });
    key.to_xdr_base64(Limits::none()).map_err(|error| {
        ObservatoryError::internal(format!("failed to encode ledger key: {error}"))
    })
}

fn decode_deployed_wasm(entry: Option<&LedgerEntryResult>) -> Result<Option<Vec<u8>>> {
    let Some(entry) = entry else {
        return Ok(None);
    };
    let data = LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())
        .map_err(|error| ObservatoryError::decode(format!("invalid ledger entry XDR: {error}")))?;
    let LedgerEntryData::ContractCode(code) = data else {
        return Ok(None);
    };
    check_wasm_size(code.code.len())?;
    Ok(Some(code.code.to_vec()))
}

/// Reject deployed code larger than [`MAX_WASM_BYTES`].
fn check_wasm_size(len: usize) -> Result<()> {
    if len > MAX_WASM_BYTES {
        return Err(ObservatoryError::invalid(format!(
            "deployed WASM is {len} bytes, exceeding the {MAX_WASM_BYTES} byte limit"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use observatory_rpc::{Endpoint, MockTransport};
    use serde_json::json;
    use stellar_xdr::{
        ContractCodeCostInputs, ContractCodeEntry, ContractCodeEntryExt, ContractCodeEntryV1,
        ContractDataEntry, ExtensionPoint, LedgerEntryData, ScContractInstance, ScMap, ScMapEntry,
        WriteXdr,
    };

    fn contract_id() -> String {
        format!("{}", stellar_strkey::Contract([9u8; 32]))
    }

    fn instance_entry(hash_byte: u8) -> LedgerEntryResult {
        instance_entry_with_storage(hash_byte, None)
    }

    fn instance_entry_with_storage(hash_byte: u8, storage: Option<ScMap>) -> LedgerEntryResult {
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash([9u8; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash([hash_byte; 32])),
                storage,
            }),
        });
        LedgerEntryResult {
            key: String::new(),
            xdr: data.to_xdr_base64(Limits::none()).unwrap(),
            last_modified_ledger_seq: Some(123),
            live_until_ledger_seq: None,
        }
    }

    fn code_entry(code: &[u8]) -> LedgerEntryResult {
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
            hash: Hash([5u8; 32]),
            code: code.to_vec().try_into().unwrap(),
        });
        LedgerEntryResult {
            key: String::new(),
            xdr: data.to_xdr_base64(Limits::none()).unwrap(),
            last_modified_ledger_seq: Some(1),
            live_until_ledger_seq: None,
        }
    }

    #[test]
    fn parses_contract_id_and_builds_key() {
        let id = contract_id();
        assert_eq!(contract_id_hash(&id).unwrap(), [9u8; 32]);
        let key = contract_instance_key(&id).unwrap();
        assert!(!key.is_empty());
    }

    #[test]
    fn rejects_non_contract_strkey() {
        let account = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        assert!(contract_id_hash(&account).is_err());
        assert!(contract_id_hash("not-a-strkey").is_err());
    }

    #[test]
    fn decodes_wasm_hash() {
        let entry = instance_entry(7);
        assert_eq!(
            decode_wasm_hash(&entry).unwrap(),
            Some(hex::encode([7u8; 32]))
        );
    }

    #[test]
    fn instance_storage_is_summarized_without_values() {
        let storage = ScMap::try_from(vec![
            ScMapEntry {
                key: ScVal::U32(1),
                val: ScVal::Bool(true),
            },
            ScMapEntry {
                key: ScVal::U32(2),
                val: ScVal::I32(-1),
            },
            ScMapEntry {
                key: ScVal::Bool(false),
                val: ScVal::Void,
            },
        ])
        .unwrap();
        let entry = instance_entry_with_storage(3, Some(storage));
        let transport = instance_transport(&entry);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);

        let info = inspect(&client, &contract_id()).unwrap();
        let summary = info.storage.expect("storage is present");
        assert_eq!(summary.entry_count, 3);
        assert_eq!(summary.inspected_entries, 3);
        assert!(!summary.truncated);
        assert_eq!(
            summary.key_types,
            BTreeMap::from([("bool".to_string(), 1), ("u32".to_string(), 2)])
        );
        assert_eq!(
            summary.value_types,
            BTreeMap::from([
                ("bool".to_string(), 1),
                ("i32".to_string(), 1),
                ("void".to_string(), 1)
            ])
        );
        assert_eq!(info.wasm_hash, Some(hex::encode([3u8; 32])));
    }

    #[test]
    fn oversized_instance_storage_is_bounded() {
        let entries: Vec<ScMapEntry> = (0..MAX_STORAGE_ENTRIES_INSPECTED + 5)
            .map(|index| ScMapEntry {
                key: ScVal::U32(index as u32),
                val: ScVal::U32(index as u32),
            })
            .collect();
        let entry = instance_entry_with_storage(4, Some(ScMap::try_from(entries).unwrap()));
        let transport = instance_transport(&entry);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);

        let summary = inspect(&client, &contract_id())
            .unwrap()
            .storage
            .expect("storage is present");
        assert_eq!(summary.entry_count, MAX_STORAGE_ENTRIES_INSPECTED + 5);
        assert_eq!(summary.inspected_entries, MAX_STORAGE_ENTRIES_INSPECTED);
        assert!(summary.truncated);
        assert_eq!(
            summary.key_types.values().sum::<usize>(),
            MAX_STORAGE_ENTRIES_INSPECTED
        );
        assert_eq!(summary.key_types, summary.value_types);
    }

    #[test]
    fn instance_without_storage_reports_none() {
        let entry = instance_entry(3);
        let transport = instance_transport(&entry);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        assert_eq!(inspect(&client, &contract_id()).unwrap().storage, None);
    }

    #[test]
    fn mock_deployment_inspection() {
        let entry = instance_entry(3);
        let transport = MockTransport::new().with_result(
            "getLedgerEntries",
            json!({ "entries": [ {
                "key": entry.key,
                "xdr": entry.xdr,
                "lastModifiedLedgerSeq": 123
            } ] }),
        );
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let info = inspect(&client, &contract_id()).unwrap();
        assert!(info.found);
        assert_eq!(info.wasm_hash, Some(hex::encode([3u8; 32])));
        assert_eq!(info.last_modified_ledger_seq, Some(123));
    }

    #[test]
    fn missing_deployment_is_reported() {
        let transport =
            MockTransport::new().with_result("getLedgerEntries", json!({ "entries": [] }));
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let info = inspect(&client, &contract_id()).unwrap();
        assert!(!info.found);
        assert_eq!(info.wasm_hash, None);
    }

    #[test]
    fn fetches_deployed_wasm_bytes() {
        let wasm = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let entry = code_entry(&wasm);
        let transport = MockTransport::new().with_result(
            "getLedgerEntries",
            json!({ "entries": [ { "key": "", "xdr": entry.xdr } ] }),
        );
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        let fetched = deployed_wasm(&client, &hex::encode([5u8; 32])).unwrap();
        assert_eq!(fetched, Some(wasm.to_vec()));
    }

    #[test]
    fn rejects_deployed_wasm_over_the_documented_limit() {
        assert!(check_wasm_size(MAX_WASM_BYTES).is_ok());
        let error = check_wasm_size(MAX_WASM_BYTES + 1).unwrap_err();
        assert_eq!(error.code(), observatory_core::ErrorCode::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("exceeding the 67108864 byte limit"),
            "{error}"
        );
    }

    #[test]
    fn deployed_wasm_missing_entry_is_none() {
        let transport =
            MockTransport::new().with_result("getLedgerEntries", json!({ "entries": [] }));
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        assert_eq!(
            deployed_wasm(&client, &hex::encode([5u8; 32])).unwrap(),
            None
        );
    }

    #[test]
    fn deployed_wasm_rejects_bad_hash() {
        let transport = MockTransport::new();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);
        assert!(deployed_wasm(&client, "not-hex").is_err());
        assert!(deployed_wasm(&client, &hex::encode([1u8; 8])).is_err());
    }

    fn instance_transport(entry: &LedgerEntryResult) -> MockTransport {
        MockTransport::new().with_result(
            "getLedgerEntries",
            json!({ "entries": [ {
                "key": entry.key,
                "xdr": entry.xdr,
                "lastModifiedLedgerSeq": 123
            } ] }),
        )
    }

    #[test]
    fn repeated_cached_lookup_calls_the_transport_once() {
        let entry = instance_entry(3);
        let transport = instance_transport(&entry);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let cache = LedgerEntryCache::with_default_capacity();

        let first = inspect_with_cache(&client, &contract_id(), &cache).unwrap();
        let second = inspect_with_cache(&client, &contract_id(), &cache).unwrap();

        assert_eq!(first, second);
        assert_eq!(transport.calls(), vec!["getLedgerEntries".to_string()]);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cached_misses_are_reused_too() {
        let transport =
            MockTransport::new().with_result("getLedgerEntries", json!({ "entries": [] }));
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let cache = LedgerEntryCache::new(4);

        assert!(
            !inspect_with_cache(&client, &contract_id(), &cache)
                .unwrap()
                .found
        );
        assert!(
            !inspect_with_cache(&client, &contract_id(), &cache)
                .unwrap()
                .found
        );

        assert_eq!(transport.calls().len(), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_capacity_is_bounded_and_zero_disables_it() {
        let entry = instance_entry(3);
        let transport = instance_transport(&entry);
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);

        let bounded = LedgerEntryCache::new(1);
        let other = format!("{}", stellar_strkey::Contract([8u8; 32]));
        let _ = inspect_with_cache(&client, &contract_id(), &bounded).unwrap();
        let _ = inspect_with_cache(&client, &other, &bounded).unwrap();
        assert_eq!(bounded.len(), 1);

        let disabled = LedgerEntryCache::new(0);
        let _ = inspect_with_cache(&client, &contract_id(), &disabled).unwrap();
        let _ = inspect_with_cache(&client, &contract_id(), &disabled).unwrap();
        assert!(disabled.is_empty());
        assert_eq!(transport.calls().len(), 4);
    }

    #[test]
    fn deployed_wasm_cache_calls_the_transport_once() {
        let wasm = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let entry = code_entry(&wasm);
        let transport = MockTransport::new().with_result(
            "getLedgerEntries",
            json!({ "entries": [ { "key": "", "xdr": entry.xdr } ] }),
        );
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), &transport);
        let cache = LedgerEntryCache::with_default_capacity();
        let hash = hex::encode([5u8; 32]);

        assert_eq!(
            deployed_wasm_with_cache(&client, &hash, &cache).unwrap(),
            Some(wasm.to_vec())
        );
        assert_eq!(
            deployed_wasm_with_cache(&client, &hash, &cache).unwrap(),
            Some(wasm.to_vec())
        );

        assert_eq!(transport.calls().len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    fn spec_module(functions: &[&str]) -> Vec<u8> {
        let entries = functions
            .iter()
            .map(|name| observatory_testutil::spec::spec_function(name, &[], None))
            .collect::<Vec<_>>();
        observatory_testutil::module_with_spec(&entries)
    }

    #[test]
    fn identical_contracts_match_on_hash_and_interface() {
        let wasm = spec_module(&["hello"]);
        let left = network_contract_from_wasm("mainnet", Some(&contract_id()), &wasm).unwrap();
        let right = network_contract_from_wasm("testnet", Some(&contract_id()), &wasm).unwrap();

        let comparison = compare_networks(left, right);

        assert_eq!(comparison.hash, ComparisonVerdict::Match);
        assert_eq!(comparison.interface, ComparisonVerdict::Match);
        assert!(comparison
            .interface_diff
            .as_ref()
            .is_some_and(|diff| diff.changes.is_empty()));
    }

    #[test]
    fn differing_artifacts_report_a_hash_mismatch_only() {
        let left = network_contract_from_wasm("mainnet", None, &spec_module(&["hello"])).unwrap();
        let mut other = spec_module(&["hello"]);
        other.extend(observatory_testutil::custom_section("build", b"different"));
        let right = network_contract_from_wasm("testnet", None, &other).unwrap();

        let comparison = compare_networks(left, right);

        assert_eq!(comparison.hash, ComparisonVerdict::Mismatch);
        assert_eq!(comparison.interface, ComparisonVerdict::Match);
        assert!(comparison
            .interface_diff
            .as_ref()
            .is_some_and(|diff| diff.changes.is_empty()));
    }

    #[test]
    fn differing_interfaces_report_per_change_detail() {
        let left =
            network_contract_from_wasm("mainnet", None, &spec_module(&["hello", "extra"])).unwrap();
        let right = network_contract_from_wasm("testnet", None, &spec_module(&["hello"])).unwrap();

        let comparison = compare_networks(left, right);

        assert_eq!(comparison.hash, ComparisonVerdict::Mismatch);
        assert_eq!(comparison.interface, ComparisonVerdict::Mismatch);
        let diff = comparison
            .interface_diff
            .expect("both interfaces are known");
        assert!(diff.changes.iter().any(|change| {
            change.path == "function::extra"
                && change.severity == observatory_diff::Severity::Breaking
        }));
        assert!(!diff.changes.is_empty());
    }

    #[test]
    fn rpc_source_loads_the_deployed_hash_and_interface() {
        let wasm = spec_module(&["hello"]);
        let instance = instance_entry(5);
        let code = code_entry(&wasm);
        let transport = MockTransport::from_json(&json!({ "getLedgerEntries": { "__sequence": [
            { "entries": [ { "key": instance.key, "xdr": instance.xdr } ] },
            { "entries": [ { "key": code.key, "xdr": code.xdr } ] }
        ] } }))
        .unwrap();
        let client = RpcClient::new(Endpoint::parse("https://example.org").unwrap(), transport);

        let contract = network_contract_from_rpc(&client, &contract_id(), "mainnet").unwrap();

        assert_eq!(contract.network, "mainnet");
        assert_eq!(contract.wasm_hash, Some(hex::encode([5u8; 32])));
        assert!(contract.interface.is_some());
        assert!(contract.interface_sha256.is_some());
    }
}
