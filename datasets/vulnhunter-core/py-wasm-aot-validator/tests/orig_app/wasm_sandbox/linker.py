"""
Multi-Module WebAssembly Import Linker & Atomic Segment Instantiator.

Instantiation Contracts (WebAssembly Core §4.5.4):
 1. Every module must pass `validate_module(mod)` before instantiation.
 2. Imported functions must match exact `FuncType`; imported tables/memories must
    satisfy limits subtyping (`actual_size >= import.minimum`, and if `import.maximum`
    is specified, `actual.maximum` must be specified and `<= import.maximum`); imported
    globals must match exact `GlobalType` (`val_type` and `mutable`).
 3. All active `elem` and `data` segment offsets (`uint32` unsigned offset!) and bounds
    (`offset + length <= target_capacity`) MUST be validated BEFORE writing any segment
    elements or bytes into shared/imported `TableInstance` or `MemoryInstance` objects!
    If any active segment is out-of-bounds, `instantiate()` raises `LinkError` (or
    `TrapError`) with ZERO partial mutations left in imported memories or tables.
"""

from __future__ import annotations

from typing import Any

from .executor import (
    FuncEntity,
    FuncRefHandle,
    GlobalInstance,
    Instance,
    MemoryInstance,
    TableInstance,
    WasmFunc,
)
from .types import GlobalType, Instruction, Limits, LinkError, Module, TableType
from .validator import validate_module

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def _check_limits_match(actual_cur: int, actual_max: int | None, required: Limits, label: str) -> None:
    if actual_cur < required.minimum:
        raise LinkError(f"{label} size {actual_cur} is smaller than required minimum {required.minimum}")
    if required.maximum is not None:
        if actual_max is None or actual_max > required.maximum:
            raise LinkError(f"{label} maximum {actual_max} does not satisfy required maximum {required.maximum}")


def _eval_const_expr(
    expr: tuple[Instruction, ...],
    globals_list: list[GlobalInstance],
    funcs: list[FuncEntity],
) -> Any:
    ins = expr[0]
    if ins.opcode == "i32.const":
        return ins.imm & MASK32
    if ins.opcode == "i64.const":
        return ins.imm & MASK64
    if ins.opcode == "ref.null":
        return None
    if ins.opcode == "ref.func":
        return FuncRefHandle(funcs[ins.imm], f"func_{ins.imm}")
    if ins.opcode == "global.get":
        return globals_list[ins.imm].value
    raise LinkError(f"Unsupported constant expression opcode: {ins.opcode}")


class Linker:
    def __init__(self) -> None:
        self._imports: dict[tuple[str, str], Any] = {}

    def define(self, module_name: str, field_name: str, item: Any) -> None:
        self._imports[(module_name, field_name)] = item

    def register_instance(self, module_name: str, inst: Instance) -> None:
        for exp_name, exp_val in inst.exports.items():
            self._imports[(module_name, exp_name)] = exp_val

    def instantiate(self, mod: Module) -> Instance:
        validate_module(mod)

        funcs: list[FuncEntity] = []
        tables: list[TableInstance] = []
        memories: list[MemoryInstance] = []
        globals_list: list[GlobalInstance] = []

        for imp in mod.imports:
            key = (imp.module, imp.name)
            if key not in self._imports:
                raise LinkError(f"Missing import {imp.module}.{imp.name}")
            ext = self._imports[key]

            if imp.kind == "func":
                if not isinstance(ext, FuncEntity):
                    raise LinkError(f"Import {imp.module}.{imp.name} is not a function")
                expected_ft = mod.types[int(imp.desc)]
                if ext.func_type != expected_ft:
                    raise LinkError(f"Imported function {imp.module}.{imp.name} signature mismatch")
                funcs.append(ext)
            elif imp.kind == "table":
                assert isinstance(imp.desc, TableType)
                if not isinstance(ext, TableInstance):
                    raise LinkError(f"Import {imp.module}.{imp.name} is not a table")
                if ext.table_type.elem_type != imp.desc.elem_type:
                    raise LinkError("Imported table element type mismatch")
                _check_limits_match(
                    len(ext.elements),
                    ext.table_type.limits.maximum,
                    imp.desc.limits,
                    f"table {imp.module}.{imp.name}",
                )
                tables.append(ext)
            elif imp.kind == "mem":
                assert isinstance(imp.desc, Limits)
                if not isinstance(ext, MemoryInstance):
                    raise LinkError(f"Import {imp.module}.{imp.name} is not a memory")
                _check_limits_match(
                    ext.pages,
                    ext.limits.maximum,
                    imp.desc,
                    f"memory {imp.module}.{imp.name}",
                )
                memories.append(ext)
            elif imp.kind == "global":
                assert isinstance(imp.desc, GlobalType)
                if not isinstance(ext, GlobalInstance):
                    raise LinkError(f"Import {imp.module}.{imp.name} is not a global")
                if ext.global_type != imp.desc:
                    raise LinkError(f"Imported global {imp.module}.{imp.name} type/mutability mismatch")
                globals_list.append(ext)

        # Create dummy Instance shell first so WasmFunc closures bind to it
        inst = Instance(
            module=mod,
            funcs=funcs,
            tables=tables,
            memories=memories,
            globals_list=globals_list,
            exports={},
        )

        base_fn = len(funcs)
        for idx, fb in enumerate(mod.functions):
            ft = mod.types[fb.type_idx]
            funcs.append(WasmFunc(inst, ft, fb, base_fn + idx))

        for tt in mod.tables:
            tables.append(TableInstance(tt))

        for mem_lim in mod.memories:
            memories.append(MemoryInstance(mem_lim))

        for gdef in mod.globals:
            init_val = _eval_const_expr(gdef.init_expr, globals_list, funcs)
            globals_list.append(GlobalInstance(gdef.global_type, init_val))

        # Populate active element segments (flawed: mutates imported tables before checking all segments!)
        for el in mod.elems:
            tab = tables[el.table_idx]
            offset = _eval_const_expr(el.offset_expr, globals_list, funcs)
            if offset + len(el.func_indices) > len(tab.elements):
                raise LinkError("Element segment does not fit in table")
            for i, fn_i in enumerate(el.func_indices):
                tab.elements[offset + i] = FuncRefHandle(funcs[fn_i], f"func_{fn_i}")

        # Populate active data segments (flawed: mutates imported memories before checking all segments!)
        for ds in mod.datas:
            mem = memories[ds.mem_idx]
            offset = _eval_const_expr(ds.offset_expr, globals_list, funcs)
            end = offset + len(ds.init_bytes)
            if end > len(mem.data):
                raise LinkError("Data segment does not fit in memory")
            mem.data[offset:end] = ds.init_bytes

        exports_map: dict[str, Any] = {}
        for exp in mod.exports:
            if exp.kind == "func":
                exports_map[exp.name] = funcs[exp.index]
            elif exp.kind == "table":
                exports_map[exp.name] = tables[exp.index]
            elif exp.kind == "mem":
                exports_map[exp.name] = memories[exp.index]
            elif exp.kind == "global":
                exports_map[exp.name] = globals_list[exp.index]
        inst.exports = exports_map

        if mod.start_func is not None:
            funcs[mod.start_func].invoke([], [100_000], 0)

        return inst
