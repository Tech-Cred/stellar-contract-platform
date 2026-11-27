"""Typed request and response models for the Observatory v1 API.

Response models are ``TypedDict`` definitions: the client validates the report
envelope and returns the ``data`` object unchanged. Forward-compatible response
fields are therefore preserved while callers still get static types.
"""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypedDict

Policy = Literal["strict", "lenient"]
JsonObject = dict[str, Any]
# XDR type shapes are recursive tagged objects; keeping the object arm as JSON
# avoids losing fields introduced by newer servers.
SpecType = str | JsonObject


@dataclass(frozen=True, slots=True)
class WasmRequest:
    """A request carrying one contract artifact."""

    wasm: bytes

    def payload(self) -> JsonObject:
        """Encode the artifact for the JSON transport."""
        return {"wasm_base64": b64encode(self.wasm).decode("ascii")}


@dataclass(frozen=True, slots=True)
class InspectRequest:
    """Request body for ``POST /contracts/inspect``."""

    wasm: bytes
    security: bool = False

    def payload(self) -> JsonObject:
        """Encode the artifact and security flag."""
        return {"wasm_base64": b64encode(self.wasm).decode("ascii"), "security": self.security}


@dataclass(frozen=True, slots=True)
class DiffRequest:
    """Request body for ``POST /contracts/diff``."""

    old_wasm: bytes
    new_wasm: bytes

    def payload(self) -> JsonObject:
        """Encode both artifacts."""
        return {
            "old_wasm_base64": b64encode(self.old_wasm).decode("ascii"),
            "new_wasm_base64": b64encode(self.new_wasm).decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class CompatibilityRequest:
    """Request body for ``POST /contracts/compatibility``."""

    old_wasm: bytes
    new_wasm: bytes
    policy: Policy = "strict"

    def payload(self) -> JsonObject:
        """Encode both artifacts and the named policy preset."""
        return {
            "old_wasm_base64": b64encode(self.old_wasm).decode("ascii"),
            "new_wasm_base64": b64encode(self.new_wasm).decode("ascii"),
            "policy": self.policy,
        }


class Health(TypedDict):
    """Public liveness response data."""

    status: str


class Readiness(TypedDict):
    """Public readiness response data."""

    status: str
    auth_required: bool


class VersionInfo(TypedDict):
    """Public version response data."""

    tool: str
    version: str
    schema_version: str
    api_version: str


class MemoryInfo(TypedDict):
    """A WASM memory declaration."""

    initial_pages: int
    maximum_pages: int | None
    shared: bool


class ImportInfo(TypedDict):
    """A WASM import."""

    module: str
    name: str
    kind: str


class ExportInfo(TypedDict):
    """A WASM export."""

    name: str
    kind: str


class CustomSectionInfo(TypedDict):
    """A WASM custom section."""

    name: str
    size: int


class WasmReport(TypedDict):
    """Bounded inspection result for a contract artifact."""

    size_bytes: int
    version: int
    artifact_sha256: str
    type_count: int
    function_count: int
    table_count: int
    global_count: int
    memories: list[MemoryInfo]
    imports: list[ImportInfo]
    exports: list[ExportInfo]
    custom_sections: list[CustomSectionInfo]
    code_section_bytes: int
    has_contract_spec: bool
    contract_spec_bytes: int | None
    truncated: bool


class SpecParam(TypedDict):
    """A function parameter."""

    name: str
    doc: str
    ty: SpecType


class SpecFunction(TypedDict):
    """A contract function declaration."""

    name: str
    doc: str
    inputs: list[SpecParam]
    outputs: list[SpecType]


class SpecField(TypedDict):
    """A struct field."""

    name: str
    doc: str
    ty: SpecType


class SpecStruct(TypedDict):
    """A struct declaration."""

    name: str
    doc: str
    fields: list[SpecField]


class SpecUnionCase(TypedDict):
    """A union case."""

    name: str
    doc: str
    types: list[SpecType]


class SpecUnion(TypedDict):
    """A union declaration."""

    name: str
    doc: str
    cases: list[SpecUnionCase]


class SpecEnumCase(TypedDict):
    """An enum case with its stable discriminant."""

    name: str
    value: int


class SpecEnum(TypedDict):
    """An enum or error-enum declaration."""

    name: str
    doc: str
    cases: list[SpecEnumCase]


class SpecEventParam(TypedDict):
    """An event parameter."""

    name: str
    ty: SpecType
    location: str


class SpecEvent(TypedDict):
    """An event declaration."""

    name: str
    doc: str
    prefix_topics: list[str]
    params: list[SpecEventParam]
    data_format: str


class ContractSpec(TypedDict):
    """The normalized contract specification."""

    functions: list[SpecFunction]
    structs: list[SpecStruct]
    unions: list[SpecUnion]
    enums: list[SpecEnum]
    error_enums: list[SpecEnum]
    events: list[SpecEvent]


class SpecIssue(TypedDict):
    """A normalization issue."""

    severity: Literal["info", "warning", "error"]
    message: str


class SpecSummary(TypedDict):
    """Counts and issues for a contract specification."""

    functions: int
    structs: int
    unions: int
    enums: int
    error_enums: int
    events: int
    issues: list[SpecIssue]


class ContractInterface(TypedDict):
    """The canonical interface derived from a contract specification."""

    schema_version: str
    functions: list[SpecFunction]
    structs: list[SpecStruct]
    unions: list[SpecUnion]
    enums: list[SpecEnum]
    error_enums: list[SpecEnum]
    events: list[SpecEvent]


class Finding(TypedDict):
    """A bounded security heuristic result."""

    id: str
    severity: Literal["WARN", "ERROR"]
    message: str
    path: str | None
    experimental: bool


class AuditReport(TypedDict):
    """Security audit result."""

    status: Literal["PASS", "WARN", "ERROR"]
    findings: list[Finding]


class InspectResponse(TypedDict):
    """Response data for ``inspect``."""

    wasm: WasmReport
    interface: ContractInterface | None
    audit: AuditReport | None


class SpecResponse(TypedDict):
    """Response data for ``spec``."""

    spec: ContractSpec
    summary: SpecSummary


class FingerprintResponse(TypedDict):
    """Response data for ``fingerprint``."""

    artifact_sha256: str
    interface_sha256: str | None


class Change(TypedDict):
    """One interface difference."""

    kind: str
    severity: Literal["informational", "non_breaking", "breaking"]
    path: str
    detail: str
    old: str | None
    new: str | None


class DiffSummary(TypedDict):
    """Deterministic counts for an interface diff."""

    total: int
    breaking: int
    non_breaking: int
    informational: int
    by_kind: dict[str, int]


class InterfaceDiff(TypedDict):
    """Response data for ``diff``."""

    changes: list[Change]
    summary: DiffSummary


class CompatibilityPolicy(TypedDict):
    """The resolved policy echoed by the compatibility endpoint."""

    function_removal_is_breaking: bool
    signature_change_is_breaking: bool
    type_removal_is_breaking: bool
    type_change_is_breaking: bool
    enum_case_addition_is_breaking: bool
    event_removal_is_breaking: bool
    event_change_is_breaking: bool


class CompatibilityReason(TypedDict):
    """One policy outcome with its explanation."""

    breaking: bool
    path: str
    message: str


class CompatibilityAssessment(TypedDict):
    """Response data for ``compatibility``."""

    status: Literal["compatible", "incompatible", "unknown"]
    policy: CompatibilityPolicy
    reasons: list[CompatibilityReason]
    diff: InterfaceDiff


class ReportEnvelope(TypedDict):
    """The versioned envelope wrapping every successful response."""

    schema_version: str
    kind: str
    tool: str
    version: str
    data: JsonObject


class ErrorEnvelope(TypedDict):
    """The versioned error envelope."""

    schema_version: NotRequired[str]
    kind: NotRequired[str]
    code: str
    message: str
    rpc_kind: NotRequired[str]
    rpc_code: NotRequired[int]
