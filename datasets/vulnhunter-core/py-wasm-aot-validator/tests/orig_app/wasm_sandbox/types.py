"""Core AST, value-type, and error definitions for `wasm_sandbox`."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class WasmError(Exception):
    """Base error for all WebAssembly decoding, validation, linking, and trap failures."""


class DecodeError(WasmError):
    """Raised when binary `.wasm` bytes violate WebAssembly binary encoding rules."""


class ValidationError(WasmError):
    """Raised when a decoded `Module` violates WebAssembly static type/validation rules."""


class LinkError(WasmError):
    """Raised when module imports or active segment bounds fail during instantiation."""


class TrapError(WasmError):
    """Raised when execution hits a deterministic WebAssembly runtime trap."""


class ValType(IntEnum):
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C
    FUNCREF = 0x70

    @classmethod
    def from_byte(cls, b: int) -> "ValType":
        try:
            return cls(b)
        except ValueError as exc:
            raise DecodeError(f"Unknown value type byte: 0x{b:02x}") from exc


WASM_PAGE_BYTES = 65536


@dataclass(frozen=True)
class FuncType:
    params: tuple[ValType, ...]
    results: tuple[ValType, ...]


@dataclass(frozen=True)
class Limits:
    minimum: int
    maximum: int | None = None


@dataclass(frozen=True)
class TableType:
    elem_type: ValType
    limits: Limits


@dataclass(frozen=True)
class GlobalType:
    val_type: ValType
    mutable: bool


@dataclass(frozen=True)
class MemArg:
    align: int
    offset: int


@dataclass(frozen=True)
class BlockSignature:
    """Normalized block type: either inline empty/single-result or type-section index."""

    kind: str  # "empty" | "valtype" | "typeidx"
    val_type: ValType | None = None
    type_idx: int | None = None


@dataclass(frozen=True)
class Instruction:
    opcode: str
    imm: Any = None


@dataclass(frozen=True)
class ImportDesc:
    module: str
    name: str
    kind: str  # "func" | "table" | "mem" | "global"
    desc: int | TableType | Limits | GlobalType


@dataclass(frozen=True)
class GlobalDef:
    global_type: GlobalType
    init_expr: tuple[Instruction, ...]


@dataclass(frozen=True)
class ExportDesc:
    name: str
    kind: str  # "func" | "table" | "mem" | "global"
    index: int


@dataclass(frozen=True)
class ElemSegment:
    table_idx: int
    offset_expr: tuple[Instruction, ...]
    func_indices: tuple[int, ...]


@dataclass(frozen=True)
class DataSegment:
    mem_idx: int
    offset_expr: tuple[Instruction, ...]
    init_bytes: bytes


@dataclass(frozen=True)
class FunctionBody:
    type_idx: int
    locals: tuple[ValType, ...]
    body: tuple[Instruction, ...]


@dataclass
class Module:
    types: list[FuncType] = field(default_factory=list)
    imports: list[ImportDesc] = field(default_factory=list)
    functions: list[FunctionBody] = field(default_factory=list)
    tables: list[TableType] = field(default_factory=list)
    memories: list[Limits] = field(default_factory=list)
    globals: list[GlobalDef] = field(default_factory=list)
    exports: list[ExportDesc] = field(default_factory=list)
    start_func: int | None = None
    elems: list[ElemSegment] = field(default_factory=list)
    datas: list[DataSegment] = field(default_factory=list)
