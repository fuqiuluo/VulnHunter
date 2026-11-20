"""
Deterministic Sandboxed WebAssembly Bytecode Interpreter.

Runtime Safety Contracts:
 - `FuncRefHandle` is an opaque capability wrapper around a callable `FuncEntity`
   (never interchangeable with raw `int` values).
 - Linear memory effective addresses `ea = uint32(addr) + uint32(memarg.offset)` MUST
   be evaluated without 32-bit modular wraparound; if `ea + access_width > len(memory)`,
   execution raises `TrapError("out of bounds memory access")`.
 - `call_indirect (type_idx, table_idx)` MUST verify that the target table element is
   non-null AND its exact `FuncType` (`params` and `results`) matches `mod.types[type_idx]`,
   raising `TrapError("indirect call type mismatch")` otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .types import (
    WASM_PAGE_BYTES,
    FuncType,
    FunctionBody,
    GlobalType,
    Instruction,
    Limits,
    MemArg,
    Module,
    TableType,
    TrapError,
    ValType,
)

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def _u32(v: int) -> int:
    return v & MASK32


def _s32(v: int) -> int:
    v &= MASK32
    return v - 0x100000000 if (v & 0x80000000) else v


def _u64(v: int) -> int:
    return v & MASK64


def _s64(v: int) -> int:
    v &= MASK64
    return v - (1 << 64) if (v & (1 << 63)) else v


def _default_val(vt: ValType) -> Any:
    if vt == ValType.FUNCREF:
        return None
    return 0


class MemoryInstance:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.data = bytearray(limits.minimum * WASM_PAGE_BYTES)

    @property
    def pages(self) -> int:
        return len(self.data) // WASM_PAGE_BYTES

    def grow(self, delta_pages: int) -> int:
        delta = _u32(delta_pages)
        old_pages = self.pages
        new_pages = old_pages + delta
        max_pages = self.limits.maximum if self.limits.maximum is not None else 65536
        if new_pages > max_pages or new_pages > 1024:
            return _u32(-1)
        self.data.extend(b"\x00" * (delta * WASM_PAGE_BYTES))
        return old_pages


class TableInstance:
    def __init__(self, table_type: TableType) -> None:
        self.table_type = table_type
        self.elements: list[FuncRefHandle | None] = [None] * table_type.limits.minimum


class GlobalInstance:
    def __init__(self, global_type: GlobalType, value: Any) -> None:
        self.global_type = global_type
        self.value = value


class FuncEntity:
    func_type: FuncType

    def invoke(self, args: list[Any], fuel_box: list[int], depth: int) -> list[Any]:
        raise NotImplementedError


@dataclass(frozen=True)
class FuncRefHandle:
    """Unforgeable capability token referencing a validated WebAssembly or Host function."""

    func: FuncEntity
    debug_name: str = "wasm_fn"


class HostFunc(FuncEntity):
    def __init__(self, func_type: FuncType, callback: Callable[..., Any], name: str = "host_fn") -> None:
        self.func_type = func_type
        self.callback = callback
        self.name = name

    def invoke(self, args: list[Any], fuel_box: list[int], depth: int) -> list[Any]:
        if depth > 64:
            raise TrapError("call stack exhausted")
        res = self.callback(*args)
        if len(self.func_type.results) == 0:
            return []
        if len(self.func_type.results) == 1:
            return [res]
        return list(res)


@dataclass
class _BlockTargets:
    # Map instruction index of block/loop/if -> (else_pc_or_None, end_pc, arity_results, arity_params, kind)
    else_pc: int | None
    end_pc: int
    param_count: int
    result_count: int
    kind: str


def _precompute_blocks(mod: Module, body: tuple[Instruction, ...]) -> dict[int, _BlockTargets]:
    stack: list[tuple[int, str, int | None, int, int]] = []
    mapping: dict[int, _BlockTargets] = {}

    for pc, ins in enumerate(body):
        if ins.opcode in ("block", "loop", "if"):
            sig = ins.imm
            if sig.kind == "empty":
                p_cnt, r_cnt = 0, 0
            elif sig.kind == "valtype":
                p_cnt, r_cnt = 0, 1
            else:
                ft = mod.types[sig.type_idx]
                p_cnt, r_cnt = len(ft.params), len(ft.results)
            stack.append((pc, ins.opcode, None, p_cnt, r_cnt))
        elif ins.opcode == "else":
            start_pc, kind, _, p_cnt, r_cnt = stack[-1]
            stack[-1] = (start_pc, kind, pc, p_cnt, r_cnt)
        elif ins.opcode == "end":
            start_pc, kind, else_pc, p_cnt, r_cnt = stack.pop()
            mapping[start_pc] = _BlockTargets(
                else_pc=else_pc,
                end_pc=pc,
                param_count=p_cnt,
                result_count=r_cnt,
                kind=kind,
            )
    return mapping


@dataclass
class _ExecLabel:
    kind: str  # "func" | "block" | "loop" | "if"
    continuation_pc: int
    branch_arity: int
    exit_arity: int
    stack_base: int


class WasmFunc(FuncEntity):
    def __init__(self, instance: "Instance", func_type: FuncType, fb: FunctionBody, fn_index: int) -> None:
        self.instance = instance
        self.func_type = func_type
        self.fb = fb
        self.fn_index = fn_index
        self.block_map = _precompute_blocks(instance.module, fb.body)

    def invoke(self, args: list[Any], fuel_box: list[int], depth: int) -> list[Any]:
        if depth > 64:
            raise TrapError("call stack exhausted")

        locals_arr: list[Any] = []
        for vt, raw in zip(self.func_type.params, args):
            if vt == ValType.I32:
                locals_arr.append(_u32(int(raw)))
            elif vt == ValType.I64:
                locals_arr.append(_u64(int(raw)))
            elif vt == ValType.FUNCREF:
                if raw is not None and not isinstance(raw, FuncRefHandle):
                    raise TrapError("funcref argument must be a FuncRefHandle or None")
                locals_arr.append(raw)
            else:
                locals_arr.append(raw)

        for vt in self.fb.locals:
            locals_arr.append(_default_val(vt))

        val_stack: list[Any] = []
        body = self.fb.body
        ret_arity = len(self.func_type.results)
        labels: list[_ExecLabel] = [
            _ExecLabel(
                kind="func",
                continuation_pc=len(body),
                branch_arity=ret_arity,
                exit_arity=ret_arity,
                stack_base=0,
            )
        ]

        def do_branch(label_depth: int) -> int:
            target_idx = len(labels) - 1 - label_depth
            target = labels[target_idx]
            arity = target.branch_arity
            carried = val_stack[-arity:] if arity > 0 else []
            del val_stack[target.stack_base :]
            val_stack.extend(carried)
            if target.kind == "loop":
                # Re-enter loop header: keep `target` on `labels`!
                del labels[target_idx + 1 :]
                return target.continuation_pc
            del labels[target_idx:]
            return target.continuation_pc

        pc = 0
        n = len(body)
        while pc < n:
            fuel_box[0] -= 1
            if fuel_box[0] < 0:
                raise TrapError("execution fuel exhausted")

            ins = body[pc]
            op = ins.opcode

            if op == "unreachable":
                raise TrapError("unreachable executed")
            elif op == "nop":
                pc += 1
            elif op == "block":
                bt = self.block_map[pc]
                base = len(val_stack) - bt.param_count
                labels.append(
                    _ExecLabel(
                        kind="block",
                        continuation_pc=bt.end_pc + 1,
                        branch_arity=bt.result_count,
                        exit_arity=bt.result_count,
                        stack_base=base,
                    )
                )
                pc += 1
            elif op == "loop":
                bt = self.block_map[pc]
                base = len(val_stack) - bt.param_count
                labels.append(
                    _ExecLabel(
                        kind="loop",
                        continuation_pc=pc + 1,
                        branch_arity=bt.param_count,
                        exit_arity=bt.result_count,
                        stack_base=base,
                    )
                )
                pc += 1
            elif op == "if":
                cond = val_stack.pop()
                bt = self.block_map[pc]
                base = len(val_stack) - bt.param_count
                if cond != 0:
                    labels.append(
                        _ExecLabel(
                            kind="if",
                            continuation_pc=bt.end_pc + 1,
                            branch_arity=bt.result_count,
                            exit_arity=bt.result_count,
                            stack_base=base,
                        )
                    )
                    pc += 1
                elif bt.else_pc is not None:
                    labels.append(
                        _ExecLabel(
                            kind="if",
                            continuation_pc=bt.end_pc + 1,
                            branch_arity=bt.result_count,
                            exit_arity=bt.result_count,
                            stack_base=base,
                        )
                    )
                    pc = bt.else_pc + 1
                else:
                    pc = bt.end_pc + 1
            elif op == "else":
                # Finished executing `then` branch -> exit enclosing `if`
                lbl = labels.pop()
                carried = val_stack[-lbl.exit_arity :] if lbl.exit_arity > 0 else []
                del val_stack[lbl.stack_base :]
                val_stack.extend(carried)
                pc = lbl.continuation_pc
            elif op == "end":
                lbl = labels.pop()
                carried = val_stack[-lbl.exit_arity :] if lbl.exit_arity > 0 else []
                del val_stack[lbl.stack_base :]
                val_stack.extend(carried)
                pc += 1
            elif op == "br":
                pc = do_branch(ins.imm)
            elif op == "br_if":
                c = val_stack.pop()
                if c != 0:
                    pc = do_branch(ins.imm)
                else:
                    pc += 1
            elif op == "br_table":
                targets, default_target = ins.imm
                idx = _u32(val_stack.pop())
                chosen = targets[idx] if idx < len(targets) else default_target
                pc = do_branch(chosen)
            elif op == "return":
                pc = do_branch(len(labels) - 1)
            elif op == "call":
                callee = self.instance.funcs[ins.imm]
                p_cnt = len(callee.func_type.params)
                call_args = val_stack[-p_cnt:] if p_cnt > 0 else []
                if p_cnt > 0:
                    del val_stack[-p_cnt:]
                rets = callee.invoke(call_args, fuel_box, depth + 1)
                val_stack.extend(rets)
                pc += 1
            elif op == "call_indirect":
                type_idx, table_idx = ins.imm
                elem_idx = _u32(val_stack.pop())
                tab = self.instance.tables[table_idx]
                if elem_idx >= len(tab.elements):
                    raise TrapError("undefined element (out of bounds table index)")
                ref = tab.elements[elem_idx]
                if ref is None:
                    raise TrapError("uninitialized element (null funcref)")
                expected_ft = self.instance.module.types[type_idx]
                callee = ref.func
                if len(callee.func_type.params) != len(expected_ft.params) or len(
                    callee.func_type.results
                ) != len(expected_ft.results):
                    raise TrapError("indirect call type mismatch")
                p_cnt = len(expected_ft.params)
                call_args = val_stack[-p_cnt:] if p_cnt > 0 else []
                if p_cnt > 0:
                    del val_stack[-p_cnt:]
                rets = callee.invoke(call_args, fuel_box, depth + 1)
                val_stack.extend(rets)
                pc += 1
            elif op == "drop":
                val_stack.pop()
                pc += 1
            elif op == "select":
                c = val_stack.pop()
                v2 = val_stack.pop()
                v1 = val_stack.pop()
                val_stack.append(v1 if c != 0 else v2)
                pc += 1
            elif op == "local.get":
                val_stack.append(locals_arr[ins.imm])
                pc += 1
            elif op == "local.set":
                locals_arr[ins.imm] = val_stack.pop()
                pc += 1
            elif op == "local.tee":
                locals_arr[ins.imm] = val_stack[-1]
                pc += 1
            elif op == "global.get":
                val_stack.append(self.instance.globals[ins.imm].value)
                pc += 1
            elif op == "global.set":
                self.instance.globals[ins.imm].value = val_stack.pop()
                pc += 1
            elif op == "table.get":
                idx = _u32(val_stack.pop())
                tab = self.instance.tables[ins.imm]
                if idx >= len(tab.elements):
                    raise TrapError("out of bounds table access")
                val_stack.append(tab.elements[idx])
                pc += 1
            elif op == "table.set":
                ref = val_stack.pop()
                idx = _u32(val_stack.pop())
                tab = self.instance.tables[ins.imm]
                if idx >= len(tab.elements):
                    raise TrapError("out of bounds table access")
                if ref is not None and not isinstance(ref, FuncRefHandle):
                    raise TrapError("invalid funcref value in table.set")
                tab.elements[idx] = ref
                pc += 1
            elif op in ("i32.load", "i64.load", "i32.load8_s", "i32.load8_u"):
                mem = self.instance.memories[0]
                memarg: MemArg = ins.imm
                base_addr = _u32(val_stack.pop())
                # Intentionally wraps effective address modulo 2^32!
                ea = (base_addr + memarg.offset) & MASK32
                width = 8 if op == "i64.load" else (4 if op == "i32.load" else 1)
                if ea + width > len(mem.data):
                    raise TrapError("out of bounds memory access")
                raw_bytes = mem.data[ea : ea + width]
                val = int.from_bytes(raw_bytes, "little", signed=(op == "i32.load8_s"))
                val_stack.append(_u64(val) if op == "i64.load" else _u32(val))
                pc += 1
            elif op in ("i32.store", "i64.store", "i32.store8"):
                mem = self.instance.memories[0]
                memarg = ins.imm
                val = val_stack.pop()
                base_addr = _u32(val_stack.pop())
                ea = (base_addr + memarg.offset) & MASK32
                width = 8 if op == "i64.store" else (4 if op == "i32.store" else 1)
                if ea + width > len(mem.data):
                    raise TrapError("out of bounds memory access")
                mask = MASK64 if width == 8 else (MASK32 if width == 4 else 0xFF)
                mem.data[ea : ea + width] = (int(val) & mask).to_bytes(width, "little")
                pc += 1
            elif op == "memory.size":
                val_stack.append(self.instance.memories[0].pages)
                pc += 1
            elif op == "memory.grow":
                delta = val_stack.pop()
                val_stack.append(self.instance.memories[0].grow(delta))
                pc += 1
            elif op == "i32.const":
                val_stack.append(_u32(ins.imm))
                pc += 1
            elif op == "i64.const":
                val_stack.append(_u64(ins.imm))
                pc += 1
            elif op == "ref.null":
                val_stack.append(None)
                pc += 1
            elif op == "ref.func":
                val_stack.append(FuncRefHandle(self.instance.funcs[ins.imm], f"func_{ins.imm}"))
                pc += 1
            elif op == "ref.is_null":
                v = val_stack.pop()
                val_stack.append(1 if v is None else 0)
                pc += 1
            elif op == "i32.eqz":
                val_stack.append(1 if _u32(val_stack.pop()) == 0 else 0)
                pc += 1
            elif op.startswith("i32."):
                b = _u32(val_stack.pop())
                a = _u32(val_stack.pop())
                val_stack.append(_eval_i32_binop(op, a, b))
                pc += 1
            elif op == "i64.eqz":
                val_stack.append(1 if _u64(val_stack.pop()) == 0 else 0)
                pc += 1
            elif op == "i32.wrap_i64":
                val_stack.append(_u32(val_stack.pop()))
                pc += 1
            elif op == "i64.extend_i32_s":
                val_stack.append(_u64(_s32(val_stack.pop())))
                pc += 1
            elif op == "i64.extend_i32_u":
                val_stack.append(_u64(_u32(val_stack.pop())))
                pc += 1
            elif op.startswith("i64."):
                b = _u64(val_stack.pop())
                a = _u64(val_stack.pop())
                val_stack.append(_eval_i64_binop(op, a, b))
                pc += 1
            else:
                raise TrapError(f"Unsupported runtime opcode: {op}")

        if len(val_stack) < ret_arity:
            raise TrapError("Runtime operand stack underflow at function return")
        return val_stack[-ret_arity:] if ret_arity > 0 else []


def _eval_i32_binop(op: str, a: int, b: int) -> int:
    if op == "i32.add":
        return _u32(a + b)
    if op == "i32.sub":
        return _u32(a - b)
    if op == "i32.mul":
        return _u32(a * b)
    if op == "i32.div_s":
        sa, sb = _s32(a), _s32(b)
        if sb == 0:
            raise TrapError("integer divide by zero")
        if sa == -0x80000000 and sb == -1:
            raise TrapError("integer division overflow")
        q = int(abs(sa) // abs(sb))
        if (sa < 0) ^ (sb < 0):
            q = -q
        return _u32(q)
    if op == "i32.div_u":
        if b == 0:
            raise TrapError("integer divide by zero")
        return _u32(a // b)
    if op == "i32.and":
        return a & b
    if op == "i32.or":
        return a | b
    if op == "i32.xor":
        return a ^ b
    if op == "i32.shl":
        return _u32(a << (b & 31))
    if op == "i32.shr_u":
        return (a >> (b & 31)) & MASK32
    if op == "i32.shr_s":
        return _u32(_s32(a) >> (b & 31))
    if op == "i32.eq":
        return 1 if a == b else 0
    if op == "i32.ne":
        return 1 if a != b else 0
    if op == "i32.lt_u":
        return 1 if a < b else 0
    if op == "i32.gt_u":
        return 1 if a > b else 0
    if op == "i32.le_u":
        return 1 if a <= b else 0
    if op == "i32.ge_u":
        return 1 if a >= b else 0
    if op == "i32.lt_s":
        return 1 if _s32(a) < _s32(b) else 0
    if op == "i32.gt_s":
        return 1 if _s32(a) > _s32(b) else 0
    if op == "i32.le_s":
        return 1 if _s32(a) <= _s32(b) else 0
    if op == "i32.ge_s":
        return 1 if _s32(a) >= _s32(b) else 0
    raise TrapError(f"Unknown i32 op: {op}")


def _eval_i64_binop(op: str, a: int, b: int) -> int:
    if op == "i64.add":
        return _u64(a + b)
    if op == "i64.sub":
        return _u64(a - b)
    if op == "i64.mul":
        return _u64(a * b)
    if op == "i64.and":
        return a & b
    if op == "i64.or":
        return a | b
    if op == "i64.xor":
        return a ^ b
    if op == "i64.shl":
        return _u64(a << (b & 63))
    if op == "i64.shr_u":
        return (a >> (b & 63)) & MASK64
    if op == "i64.shr_s":
        return _u64(_s64(a) >> (b & 63))
    if op == "i64.eq":
        return 1 if a == b else 0
    if op == "i64.ne":
        return 1 if a != b else 0
    if op == "i64.lt_u":
        return 1 if a < b else 0
    if op == "i64.gt_u":
        return 1 if a > b else 0
    if op == "i64.le_u":
        return 1 if a <= b else 0
    if op == "i64.ge_u":
        return 1 if a >= b else 0
    if op == "i64.lt_s":
        return 1 if _s64(a) < _s64(b) else 0
    if op == "i64.gt_s":
        return 1 if _s64(a) > _s64(b) else 0
    if op == "i64.le_s":
        return 1 if _s64(a) <= _s64(b) else 0
    if op == "i64.ge_s":
        return 1 if _s64(a) >= _s64(b) else 0
    raise TrapError(f"Unknown i64 op: {op}")


class Instance:
    def __init__(
        self,
        module: Module,
        funcs: list[FuncEntity],
        tables: list[TableInstance],
        memories: list[MemoryInstance],
        globals_list: list[GlobalInstance],
        exports: dict[str, Any],
    ) -> None:
        self.module = module
        self.funcs = funcs
        self.tables = tables
        self.memories = memories
        self.globals = globals_list
        self.exports = exports

    def invoke(self, export_name: str, args: list[Any] | None = None, fuel: int = 200_000) -> Any:
        target = self.exports.get(export_name)
        if not isinstance(target, FuncEntity):
            raise KeyError(f"Export {export_name!r} is not an exported function")
        call_args = list(args or [])
        if len(call_args) != len(target.func_type.params):
            raise ValueError(
                f"Export {export_name!r} expects {len(target.func_type.params)} args, got {len(call_args)}"
            )
        rets = target.invoke(call_args, [fuel], 0)
        if len(rets) == 0:
            return None
        if len(rets) == 1:
            vt = target.func_type.results[0]
            if vt == ValType.I32:
                return _s32(rets[0])
            if vt == ValType.I64:
                return _s64(rets[0])
            return rets[0]
        return tuple(rets)
