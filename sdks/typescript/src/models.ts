/**
 * Response models matching the Observatory OpenAPI document and the published
 * JSON Schemas under `docs/schemas/`.
 */

/** Versioned report envelope wrapping every successful response. */
export interface Report<T> {
  schema_version: string;
  kind: string;
  tool: string;
  version: string;
  data: T;
}

/** Error envelope. */
export interface ErrorReport {
  schema_version: string;
  kind: "error";
  code: string;
  message: string;
  rpc_kind?: string;
  rpc_code?: number;
}

export interface Health {
  status: string;
}

export interface Readiness {
  status: string;
  auth_required: boolean;
}

export interface VersionInfo {
  tool: string;
  version: string;
  schema_version: string;
  api_version: string;
}

export interface MemoryInfo {
  initial_pages: number;
  maximum_pages: number | null;
  shared: boolean;
}

export interface ImportInfo {
  module: string;
  name: string;
  kind: string;
}

export interface ExportInfo {
  name: string;
  kind: string;
}

export interface CustomSectionInfo {
  name: string;
  size: number;
}

export interface NameInfo {
  /** Module name, when present. */
  module?: string;
  /** Function names keyed by function index. */
  functions?: Record<string, string>;
  /** Type names keyed by type index. */
  types?: Record<string, string>;
}

export interface WasmReport {
  size_bytes: number;
  version: number;
  artifact_sha256: string;
  type_count: number;
  function_count: number;
  table_count: number;
  global_count: number;
  memories: MemoryInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  custom_sections: CustomSectionInfo[];
  /** Present only when the `name` custom section yields at least one name. */
  name?: NameInfo;
  code_section_bytes: number;
  has_contract_spec: boolean;
  contract_spec_bytes: number | null;
  truncated: boolean;
}

export type SpecType =
  | "val"
  | "bool"
  | "void"
  | "error"
  | "u32"
  | "i32"
  | "u64"
  | "i64"
  | "timepoint"
  | "duration"
  | "u128"
  | "i128"
  | "u256"
  | "i256"
  | "bytes"
  | "string"
  | "symbol"
  | "address"
  | "muxed_address"
  | { option: SpecType }
  | { result: { ok: SpecType; error: SpecType } }
  | { vec: SpecType }
  | { map: { key: SpecType; value: SpecType } }
  | { tuple: SpecType[] }
  | { bytes_n: { bytes: number } }
  | { udt: { name: string } };

export interface SpecParam {
  name: string;
  doc: string;
  ty: SpecType;
}

export interface SpecFunction {
  name: string;
  doc: string;
  inputs: SpecParam[];
  outputs: SpecType[];
}

export interface SpecField {
  name: string;
  doc: string;
  ty: SpecType;
}

export interface SpecStruct {
  name: string;
  doc: string;
  fields: SpecField[];
}

export interface SpecUnionCase {
  name: string;
  doc: string;
  types: SpecType[];
}

export interface SpecUnion {
  name: string;
  doc: string;
  cases: SpecUnionCase[];
}

export interface SpecEnumCase {
  name: string;
  value: number;
}

export interface SpecEnum {
  name: string;
  doc: string;
  cases: SpecEnumCase[];
}

export interface SpecEventParam {
  name: string;
  ty: SpecType;
  location: string;
}

export interface SpecEvent {
  name: string;
  doc: string;
  prefix_topics: string[];
  params: SpecEventParam[];
  data_format: string;
}

export interface ContractSpec {
  functions: SpecFunction[];
  structs: SpecStruct[];
  unions: SpecUnion[];
  enums: SpecEnum[];
  error_enums: SpecEnum[];
  events: SpecEvent[];
}

export interface SpecIssue {
  severity: "info" | "warning" | "error";
  message: string;
}

export interface SpecSummary {
  functions: number;
  structs: number;
  unions: number;
  enums: number;
  error_enums: number;
  events: number;
  issues: SpecIssue[];
}

export interface ContractInterface {
  schema_version: string;
  functions: SpecFunction[];
  structs: SpecStruct[];
  unions: SpecUnion[];
  enums: SpecEnum[];
  error_enums: SpecEnum[];
  events: SpecEvent[];
}

export type AuditStatus = "PASS" | "WARN" | "ERROR";

export type FindingConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  id: string;
  severity: "WARN" | "ERROR";
  message: string;
  path: string | null;
  experimental: boolean;
  confidence: FindingConfidence;
  /** Bounded observations backing the potential issue (one or two entries). */
  evidence: string[];
  /** Non-prescriptive next step for reviewing the potential issue. */
  recommendation: string;
}

export interface AuditReport {
  status: AuditStatus;
  findings: Finding[];
}

export interface InspectResponse {
  wasm: WasmReport;
  interface: ContractInterface | null;
  audit: AuditReport | null;
}

export interface SpecResponse {
  spec: ContractSpec;
  summary: SpecSummary;
}

export interface FingerprintResponse {
  artifact_sha256: string;
  interface_sha256: string | null;
}

export type ChangeSeverity = "informational" | "non_breaking" | "breaking";

export interface Change {
  kind: string;
  severity: ChangeSeverity;
  path: string;
  detail: string;
  old: string | null;
  new: string | null;
}

export interface DiffSummary {
  total: number;
  breaking: number;
  non_breaking: number;
  informational: number;
  /** Counts per change kind; an absent kind is zero. */
  by_kind: Partial<Record<string, number>>;
}

export interface InterfaceDiff {
  changes: Change[];
  summary: DiffSummary;
}

export type CompatibilityStatus = "compatible" | "incompatible" | "unknown";

export interface CompatibilityPolicy {
  function_removal_is_breaking: boolean;
  signature_change_is_breaking: boolean;
  type_removal_is_breaking: boolean;
  type_change_is_breaking: boolean;
  event_removal_is_breaking: boolean;
  event_change_is_breaking: boolean;
}

export interface CompatibilityReason {
  breaking: boolean;
  path: string;
  message: string;
}

export interface CompatibilityAssessment {
  status: CompatibilityStatus;
  policy: CompatibilityPolicy;
  reasons: CompatibilityReason[];
  diff: InterfaceDiff;
}
