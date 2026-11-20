"""
WebAssembly Structured Control-Flow & Stack-Polymorphic Type Validator.

Validation Contracts (WebAssembly Core §3.3):
 - Each control frame (`func`, `block`, `loop`, `if`) records its `start_height` on
   the operand stack, its `param_types`, `result_types`, and `unreachable` flag.
 - When `frame.unreachable` is set (after `unreachable`, `br`, `br_table`, `return`),
   operand pops synthesize `UNKNOWN` ONLY when `len(val_stack) == frame.start_height`;
   values pushed onto the stack below `frame.start_height` belong to enclosing outer
   frames and must NEVER be popped or mutated by inner frames!
 - An `if` block without a matching `else` branch implicitly passes its input
   `param_types` directly to the exit when the condition is `0`, so `param_types`
   MUST equal `result_types`.
 - `label_types(frame)` is `frame.param_types` for `loop` frames and `frame.result_types`
   for `block`/`if`/`func` frames. Every target in `br_table [l_0..l_k] l_default`
   MUST have the exact same `label_types` tuple as `l_default`!
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import (
    BlockSignature,
    FuncType,
    GlobalType,
    Instruction,
    Limits,
    MemArg,
    Module,
    TableType,
    ValType,
    ValidationError,
)

UNKNOWN = "UNKNOWN"
StackType = ValType | str


@dataclass
class ControlFrame:
    opcode: str  # "func" | "block" | "loop" | "if"
    param_types: tuple[ValType, ...]
    result_types: tuple[ValType, ...]
    start_height: int
    unreachable: bool = False
    has_else: bool = False

    def label_types(self) -> tuple[ValType, ...]:
        if self.opcode == "loop":
            return self.param_types
        return self.result_types


def _validate_limits(lim: Limits, max_bound: int | None = None) -> None:
    if lim.minimum < 0:
        raise ValidationError("Negative limit minimum")
    if max_bound is not None and lim.minimum > max_bound:
        raise ValidationError(f"Limit minimum {lim.minimum} exceeds ceiling {max_bound}")
    if lim.maximum is not None:
        if lim.maximum < lim.minimum:
            raise ValidationError(f"Limit maximum {lim.maximum} < minimum {lim.minimum}")
        if max_bound is not None and lim.maximum > max_bound:
            raise ValidationError(f"Limit maximum {lim.maximum} exceeds ceiling {max_bound}")


def _resolve_block_sig(mod: Module, sig: BlockSignature) -> FuncType:
    if sig.kind == "empty":
        return FuncType(params=(), results=())
    if sig.kind == "valtype":
        assert sig.val_type is not None
        return FuncType(params=(), results=(sig.val_type,))
    if sig.kind == "typeidx":
        assert sig.type_idx is not None
        if sig.type_idx < 0 or sig.type_idx >= len(mod.types):
            raise ValidationError(f"Block type index {sig.type_idx} out of bounds")
        return mod.types[sig.type_idx]
    raise ValidationError(f"Unknown block signature kind: {sig.kind}")


def _validate_const_expr(
    expr: tuple[Instruction, ...],
    expected_type: ValType,
    imported_globals: list[GlobalType],
    total_funcs: int,
) -> None:
    if len(expr) != 1:
        raise ValidationError("Constant expression must contain exactly one instruction")
    ins = expr[0]
    if ins.opcode == "i32.const":
        actual = ValType.I32
    elif ins.opcode == "i64.const":
        actual = ValType.I64
    elif ins.opcode == "ref.null":
        actual = ins.imm
    elif ins.opcode == "ref.func":
        if ins.imm < 0 or ins.imm >= total_funcs:
            raise ValidationError(f"ref.func index {ins.imm} out of bounds")
        actual = ValType.FUNCREF
    elif ins.opcode == "global.get":
        g_idx = ins.imm
        if g_idx < 0 or g_idx >= len(imported_globals):
            raise ValidationError("Constant expression global.get may only reference imported globals")
        if imported_globals[g_idx].mutable:
            raise ValidationError("Constant expression global.get requires an immutable global")
        actual = imported_globals[g_idx].val_type
    else:
        raise ValidationError(f"Instruction '{ins.opcode}' is not valid in a constant expression")

    if actual != expected_type:
        raise ValidationError(f"Constant expression type mismatch: expected {expected_type}, got {actual}")


class _FuncValidator:
    def __init__(
        self,
        mod: Module,
        func_types: list[FuncType],
        tables: list[TableType],
        memories: list[Limits],
        globals_list: list[GlobalType],
        referenced_funcs: set[int],
        local_types: list[ValType],
        ret_types: tuple[ValType, ...],
    ) -> None:
        self.mod = mod
        self.func_types = func_types
        self.tables = tables
        self.memories = memories
        self.globals_list = globals_list
        self.referenced_funcs = referenced_funcs
        self.local_types = local_types
        self.val_stack: list[StackType] = []
        self.ctrl_stack: list[ControlFrame] = [
            ControlFrame(
                opcode="func",
                param_types=(),
                result_types=ret_types,
                start_height=0,
            )
        ]

    @property
    def cur_frame(self) -> ControlFrame:
        return self.ctrl_stack[-1]

    def push_val(self, vt: StackType) -> None:
        self.val_stack.append(vt)

    def push_vals(self, vts: tuple[ValType, ...] | list[StackType]) -> None:
        for t in vts:
            self.push_val(t)

    def pop_val(self, expected: StackType | None = None) -> StackType:
        frame = self.cur_frame
        if len(self.val_stack) == 0 and frame.unreachable:
            return expected if expected is not None else UNKNOWN
        if len(self.val_stack) <= frame.start_height:
            if not frame.unreachable:
                raise ValidationError(f"Operand stack exhausted inside '{frame.opcode}' frame")
            # Intentionally flawed: pops across `frame.start_height` when `len(self.val_stack) > 0`!
        actual = self.val_stack.pop()
        if actual != UNKNOWN and expected is not None and expected != UNKNOWN and actual != expected:
            raise ValidationError(f"Type mismatch on operand stack: expected {expected}, got {actual}")
        return expected if (actual == UNKNOWN and expected is not None) else actual

    def pop_vals(self, expected_types: tuple[ValType, ...]) -> list[StackType]:
        popped: list[StackType] = []
        for exp in reversed(expected_types):
            popped.append(self.pop_val(exp))
        popped.reverse()
        return popped

    def mark_unreachable(self) -> None:
        frame = self.cur_frame
        del self.val_stack[frame.start_height :]
        frame.unreachable = True

    def get_target_frame(self, depth: int) -> ControlFrame:
        if depth < 0 or depth >= len(self.ctrl_stack):
            raise ValidationError(f"Branch label depth {depth} out of bounds")
        return self.ctrl_stack[len(self.ctrl_stack) - 1 - depth]

    def check_memarg(self, memarg: MemArg, natural_bytes: int) -> None:
        if len(self.memories) == 0:
            raise ValidationError("Memory instruction requires at least one declared or imported memory")
        if memarg.align < 0 or (1 << memarg.align) > natural_bytes:
            raise ValidationError(f"Alignment 2^{memarg.align} exceeds natural access width {natural_bytes}")

    def validate_body(self, body: tuple[Instruction, ...]) -> None:
        for ins in body:
            op = ins.opcode
            if op == "unreachable":
                self.mark_unreachable()
            elif op == "nop":
                pass
            elif op in ("block", "loop"):
                ft = _resolve_block_sig(self.mod, ins.imm)
                self.pop_vals(ft.params)
                start_h = len(self.val_stack)
                self.push_vals(ft.params)
                self.ctrl_stack.append(
                    ControlFrame(
                        opcode=op,
                        param_types=ft.params,
                        result_types=ft.results,
                        start_height=start_h,
                    )
                )
            elif op == "if":
                self.pop_val(ValType.I32)
                ft = _resolve_block_sig(self.mod, ins.imm)
                self.pop_vals(ft.params)
                start_h = len(self.val_stack)
                self.push_vals(ft.params)
                self.ctrl_stack.append(
                    ControlFrame(
                        opcode="if",
                        param_types=ft.params,
                        result_types=ft.results,
                        start_height=start_h,
                    )
                )
            elif op == "else":
                frame = self.cur_frame
                if frame.opcode != "if" or frame.has_else:
                    raise ValidationError("'else' only valid once inside an 'if' block")
                self.pop_vals(frame.result_types)
                if len(self.val_stack) != frame.start_height:
                    raise ValidationError("Extra values left on operand stack at 'else'")
                frame.has_else = True
                frame.unreachable = False
                self.push_vals(frame.param_types)
            elif op == "end":
                if len(self.ctrl_stack) <= 1:
                    raise ValidationError("Unexpected nested 'end'")
                frame = self.cur_frame
                self.pop_vals(frame.result_types)
                if len(self.val_stack) != frame.start_height:
                    raise ValidationError(f"Operand stack height mismatch at end of '{frame.opcode}'")
                self.ctrl_stack.pop()
                self.push_vals(frame.result_types)
            elif op == "br":
                target = self.get_target_frame(ins.imm)
                self.pop_vals(target.label_types())
                self.mark_unreachable()
            elif op == "br_if":
                self.pop_val(ValType.I32)
                target = self.get_target_frame(ins.imm)
                vals = self.pop_vals(target.label_types())
                self.push_vals(vals)
            elif op == "br_table":
                targets, default_target = ins.imm
                self.pop_val(ValType.I32)
                def_frame = self.get_target_frame(default_target)
                expected_arity = len(def_frame.result_types)
                for t_depth in targets:
                    t_frame = self.get_target_frame(t_depth)
                    if len(t_frame.result_types) != expected_arity:
                        raise ValidationError("br_table target arity mismatch")
                self.pop_vals(def_frame.result_types)
                self.mark_unreachable()
            elif op == "return":
                func_frame = self.ctrl_stack[0]
                self.pop_vals(func_frame.result_types)
                self.mark_unreachable()
            elif op == "call":
                fn_idx = ins.imm
                if fn_idx < 0 or fn_idx >= len(self.func_types):
                    raise ValidationError(f"Function index {fn_idx} out of bounds")
                ft = self.func_types[fn_idx]
                self.pop_vals(ft.params)
                self.push_vals(ft.results)
            elif op == "call_indirect":
                type_idx, table_idx = ins.imm
                if table_idx < 0 or table_idx >= len(self.tables):
                    raise ValidationError(f"Table index {table_idx} out of bounds")
                if self.tables[table_idx].elem_type != ValType.FUNCREF:
                    raise ValidationError("call_indirect requires a funcref table")
                if type_idx < 0 or type_idx >= len(self.mod.types):
                    raise ValidationError(f"Type index {type_idx} out of bounds")
                ft = self.mod.types[type_idx]
                self.pop_val(ValType.I32)
                self.pop_vals(ft.params)
                self.push_vals(ft.results)
            elif op == "drop":
                self.pop_val()
            elif op == "select":
                self.pop_val(ValType.I32)
                t2 = self.pop_val()
                t1 = self.pop_val()
                if t1 not in (UNKNOWN, ValType.I32, ValType.I64, ValType.F32, ValType.F64) or t2 not in (
                    UNKNOWN,
                    ValType.I32,
                    ValType.I64,
                    ValType.F32,
                    ValType.F64,
                ):
                    raise ValidationError("Untyped 'select' only supports numeric value types")
                if t1 != UNKNOWN and t2 != UNKNOWN and t1 != t2:
                    raise ValidationError(f"select operand mismatch: {t1} vs {t2}")
                self.push_val(t2 if t1 == UNKNOWN else t1)
            elif op == "local.get":
                idx = ins.imm
                if idx < 0 or idx >= len(self.local_types):
                    raise ValidationError(f"Local index {idx} out of bounds")
                self.push_val(self.local_types[idx])
            elif op == "local.set":
                idx = ins.imm
                if idx < 0 or idx >= len(self.local_types):
                    raise ValidationError(f"Local index {idx} out of bounds")
                self.pop_val(self.local_types[idx])
            elif op == "local.tee":
                idx = ins.imm
                if idx < 0 or idx >= len(self.local_types):
                    raise ValidationError(f"Local index {idx} out of bounds")
                vt = self.local_types[idx]
                self.pop_val(vt)
                self.push_val(vt)
            elif op == "global.get":
                idx = ins.imm
                if idx < 0 or idx >= len(self.globals_list):
                    raise ValidationError(f"Global index {idx} out of bounds")
                self.push_val(self.globals_list[idx].val_type)
            elif op == "global.set":
                idx = ins.imm
                if idx < 0 or idx >= len(self.globals_list):
                    raise ValidationError(f"Global index {idx} out of bounds")
                if not self.globals_list[idx].mutable:
                    raise ValidationError(f"Cannot global.set immutable global {idx}")
                self.pop_val(self.globals_list[idx].val_type)
            elif op == "table.get":
                idx = ins.imm
                if idx < 0 or idx >= len(self.tables):
                    raise ValidationError(f"Table index {idx} out of bounds")
                self.pop_val(ValType.I32)
                self.push_val(self.tables[idx].elem_type)
            elif op == "table.set":
                idx = ins.imm
                if idx < 0 or idx >= len(self.tables):
                    raise ValidationError(f"Table index {idx} out of bounds")
                self.pop_val(self.tables[idx].elem_type)
                self.pop_val(ValType.I32)
            elif op == "i32.load":
                self.check_memarg(ins.imm, 4)
                self.pop_val(ValType.I32)
                self.push_val(ValType.I32)
            elif op == "i64.load":
                self.check_memarg(ins.imm, 8)
                self.pop_val(ValType.I32)
                self.push_val(ValType.I64)
            elif op in ("i32.load8_s", "i32.load8_u"):
                self.check_memarg(ins.imm, 1)
                self.pop_val(ValType.I32)
                self.push_val(ValType.I32)
            elif op == "i32.store":
                self.check_memarg(ins.imm, 4)
                self.pop_val(ValType.I32)
                self.pop_val(ValType.I32)
            elif op == "i64.store":
                self.check_memarg(ins.imm, 8)
                self.pop_val(ValType.I64)
                self.pop_val(ValType.I32)
            elif op == "i32.store8":
                self.check_memarg(ins.imm, 1)
                self.pop_val(ValType.I32)
                self.pop_val(ValType.I32)
            elif op == "memory.size":
                if len(self.memories) == 0:
                    raise ValidationError("memory.size requires a memory")
                self.push_val(ValType.I32)
            elif op == "memory.grow":
                if len(self.memories) == 0:
                    raise ValidationError("memory.grow requires a memory")
                self.pop_val(ValType.I32)
                self.push_val(ValType.I32)
            elif op == "i32.const":
                self.push_val(ValType.I32)
            elif op == "i64.const":
                self.push_val(ValType.I64)
            elif op == "ref.null":
                self.push_val(ins.imm)
            elif op == "ref.func":
                if ins.imm not in self.referenced_funcs:
                    raise ValidationError(f"Unreferenced function index {ins.imm} in ref.func")
                self.push_val(ValType.FUNCREF)
            elif op == "ref.is_null":
                self.pop_val(ValType.FUNCREF)
                self.push_val(ValType.I32)
            elif op == "i32.eqz":
                self.pop_val(ValType.I32)
                self.push_val(ValType.I32)
            elif op in (
                "i32.eq",
                "i32.ne",
                "i32.lt_s",
                "i32.lt_u",
                "i32.gt_s",
                "i32.gt_u",
                "i32.le_s",
                "i32.le_u",
                "i32.ge_s",
                "i32.ge_u",
                "i32.add",
                "i32.sub",
                "i32.mul",
                "i32.div_s",
                "i32.div_u",
                "i32.and",
                "i32.or",
                "i32.xor",
                "i32.shl",
                "i32.shr_s",
                "i32.shr_u",
            ):
                self.pop_val(ValType.I32)
                self.pop_val(ValType.I32)
                self.push_val(ValType.I32)
            elif op == "i64.eqz":
                self.pop_val(ValType.I64)
                self.push_val(ValType.I32)
            elif op in (
                "i64.eq",
                "i64.ne",
                "i64.lt_s",
                "i64.lt_u",
                "i64.gt_s",
                "i64.gt_u",
                "i64.le_s",
                "i64.le_u",
                "i64.ge_s",
                "i64.ge_u",
            ):
                self.pop_val(ValType.I64)
                self.pop_val(ValType.I64)
                self.push_val(ValType.I32)
            elif op in (
                "i64.add",
                "i64.sub",
                "i64.mul",
                "i64.and",
                "i64.or",
                "i64.xor",
                "i64.shl",
                "i64.shr_s",
                "i64.shr_u",
            ):
                self.pop_val(ValType.I64)
                self.pop_val(ValType.I64)
                self.push_val(ValType.I64)
            elif op == "i32.wrap_i64":
                self.pop_val(ValType.I64)
                self.push_val(ValType.I32)
            elif op in ("i64.extend_i32_s", "i64.extend_i32_u"):
                self.pop_val(ValType.I32)
                self.push_val(ValType.I64)
            else:
                raise ValidationError(f"Unhandled instruction in validator: {op}")

        if len(self.ctrl_stack) != 1:
            raise ValidationError("Unclosed control block in function body")
        func_frame = self.ctrl_stack[0]
        self.pop_vals(func_frame.result_types)
        if len(self.val_stack) != 0:
            raise ValidationError("Extra values remaining on function operand stack at exit")


def validate_module(mod: Module) -> None:
    func_types: list[FuncType] = []
    tables: list[TableType] = []
    memories: list[Limits] = []
    imported_globals: list[GlobalType] = []

    for imp in mod.imports:
        if imp.kind == "func":
            assert isinstance(imp.desc, int)
            if imp.desc < 0 or imp.desc >= len(mod.types):
                raise ValidationError(f"Imported function type index {imp.desc} out of bounds")
            func_types.append(mod.types[imp.desc])
        elif imp.kind == "table":
            assert isinstance(imp.desc, TableType)
            _validate_limits(imp.desc.limits)
            tables.append(imp.desc)
        elif imp.kind == "mem":
            assert isinstance(imp.desc, Limits)
            _validate_limits(imp.desc, max_bound=65536)
            memories.append(imp.desc)
        elif imp.kind == "global":
            assert isinstance(imp.desc, GlobalType)
            imported_globals.append(imp.desc)

    for fb in mod.functions:
        if fb.type_idx < 0 or fb.type_idx >= len(mod.types):
            raise ValidationError(f"Function type index {fb.type_idx} out of bounds")
        func_types.append(mod.types[fb.type_idx])

    for tt in mod.tables:
        _validate_limits(tt.limits)
        tables.append(tt)

    for mem_lim in mod.memories:
        _validate_limits(mem_lim, max_bound=65536)
        memories.append(mem_lim)

    if len(memories) > 1:
        raise ValidationError("WebAssembly 1.0/2.0 core module supports at most 1 memory")

    all_globals: list[GlobalType] = list(imported_globals)
    referenced_funcs: set[int] = set()

    for g in mod.globals:
        _validate_const_expr(g.init_expr, g.global_type.val_type, imported_globals, len(func_types))
        for ins in g.init_expr:
            if ins.opcode == "ref.func":
                referenced_funcs.add(ins.imm)
        all_globals.append(g.global_type)

    seen_exports: set[str] = set()
    for exp in mod.exports:
        if exp.name in seen_exports:
            raise ValidationError(f"Duplicate export name: {exp.name!r}")
        seen_exports.add(exp.name)
        if exp.kind == "func":
            if exp.index < 0 or exp.index >= len(func_types):
                raise ValidationError(f"Exported func index {exp.index} out of bounds")
            referenced_funcs.add(exp.index)
        elif exp.kind == "table":
            if exp.index < 0 or exp.index >= len(tables):
                raise ValidationError(f"Exported table index {exp.index} out of bounds")
        elif exp.kind == "mem":
            if exp.index < 0 or exp.index >= len(memories):
                raise ValidationError(f"Exported mem index {exp.index} out of bounds")
        elif exp.kind == "global":
            if exp.index < 0 or exp.index >= len(all_globals):
                raise ValidationError(f"Exported global index {exp.index} out of bounds")

    if mod.start_func is not None:
        if mod.start_func < 0 or mod.start_func >= len(func_types):
            raise ValidationError(f"Start function index {mod.start_func} out of bounds")
        if mod.start_func >= 0 and func_types[mod.start_func] != FuncType(params=(), results=()):
            raise ValidationError("Start function must have signature [] -> []")

    for el in mod.elems:
        if el.table_idx < 0 or el.table_idx >= len(tables):
            raise ValidationError(f"Elem segment table index {el.table_idx} out of bounds")
        _validate_const_expr(el.offset_expr, ValType.I32, imported_globals, len(func_types))
        for fn_i in el.func_indices:
            if fn_i < 0 or fn_i >= len(func_types):
                raise ValidationError(f"Elem segment function index {fn_i} out of bounds")
            referenced_funcs.add(fn_i)

    for ds in mod.datas:
        if ds.mem_idx < 0 or ds.mem_idx >= len(memories):
            raise ValidationError(f"Data segment memory index {ds.mem_idx} out of bounds")
        _validate_const_expr(ds.offset_expr, ValType.I32, imported_globals, len(func_types))

    num_imported_funcs = sum(1 for imp in mod.imports if imp.kind == "func")
    for idx, fb in enumerate(mod.functions):
        ft = func_types[num_imported_funcs + idx]
        local_types = list(ft.params) + list(fb.locals)
        fv = _FuncValidator(
            mod=mod,
            func_types=func_types,
            tables=tables,
            memories=memories,
            globals_list=all_globals,
            referenced_funcs=referenced_funcs,
            local_types=local_types,
            ret_types=ft.results,
        )
        fv.validate_body(fb.body)
