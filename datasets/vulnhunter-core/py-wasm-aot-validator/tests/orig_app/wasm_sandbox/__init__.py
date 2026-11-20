"""
`wasm_sandbox`: WebAssembly Core 1.0/2.0 Binary Decoder, Structured Type Validator,
Multi-Module Linker, and Deterministic Sandboxed Interpreter.

Soundness Invariants:
 1. `decode_module(raw)` accepts only canonically encoded WebAssembly 1.0/2.0 binary
    modules (including 5-byte canonical LEB128 bounds on 32-bit integers).
 2. `validate_module(mod)` enforces WebAssembly structured control-flow typing:
    stack-polymorphic instructions after unconditional transfers (`unreachable`, `br`,
    `br_table`, `return`) remain strictly confined to their enclosing control frame's
    stack height, single-sided `if` blocks satisfy `params == results`, and branch
    tables verify exact label-type equality (`param_types` for `loop` targets vs
    `result_types` for `block`/`if` targets).
 3. `Linker.instantiate(mod)` validates all import types/limits and all active `data`
    and `elem` segment bounds prior to mutating shared store `Memory` or `Table` state.
 4. `Instance.invoke(name, args)` enforces exact `FuncType` signatures on `call_indirect`
    and computes linear-memory effective addresses `ea = uint32(addr) + uint32(offset)`
    without 32-bit modular wraparound before checking `[ea, ea + width) <= len(memory)`.
"""

from .asm import ModuleBuilder
from .binary_decoder import decode_module
from .executor import FuncRefHandle, HostFunc, Instance, MemoryInstance, TableInstance, GlobalInstance
from .linker import Linker
from .types import (
    DecodeError,
    FuncType,
    Limits,
    LinkError,
    MemArg,
    Module,
    TrapError,
    ValType,
    ValidationError,
)
from .validator import validate_module

__all__ = [
    "DecodeError",
    "FuncRefHandle",
    "FuncType",
    "GlobalInstance",
    "HostFunc",
    "Instance",
    "Limits",
    "LinkError",
    "Linker",
    "MemArg",
    "MemoryInstance",
    "Module",
    "ModuleBuilder",
    "TableInstance",
    "TrapError",
    "ValType",
    "ValidationError",
    "decode_module",
    "validate_module",
]
