#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "wasm_sandbox/validator.py",
    "wasm_sandbox/binary_decoder.py",
    "wasm_sandbox/executor.py",
    "wasm_sandbox/linker.py"
  ],
  "findings": [
    "In `wasm_sandbox/validator.py`, stack-polymorphic pops after unconditional branches only checked `len(val_stack) == 0` rather than clamping at `frame.start_height`, allowing unreachable instructions inside nested blocks to pop outer operand-stack values; additionally, single-sided `if` blocks without `else` failed to enforce `param_types == result_types`.",
    "In `wasm_sandbox/validator.py`, `br_table` inspected `frame.result_types` instead of `frame.label_types()` (confusing `loop` header parameter types with exit result types) and compared only label arity `len(...)` instead of exact element `ValType` tuples.",
    "In `wasm_sandbox/binary_decoder.py` and `wasm_sandbox/executor.py`, 32-bit LEB128 readers accepted >5-byte overlong integers and non-canonical 5th-byte spare/sign bits, while linear-memory loads and stores wrapped `base_addr + offset` modulo 2^32 prior to checking memory bounds.",
    "In `wasm_sandbox/executor.py` and `wasm_sandbox/linker.py`, `call_indirect` checked only parameter and result counts instead of full `FuncType` equality, and `Linker.instantiate()` mutated imported shared tables and memories before validating all active element and data segment bounds."
  ],
  "summary": "Enforced frame-local polymorphic stack bounds, single-sided `if` typing, and exact `br_table` `label_types()` matching in `validator.py`; enforced canonical 5-byte 32-bit LEB128 bounds in `binary_decoder.py`; removed 32-bit effective-address wraparound and enforced full `FuncType` matching on `call_indirect` in `executor.py`; and pre-validated all active segments prior to mutating store state in `linker.py`."
}
EOF

python3 - "$APP_DIR" <<'PY'
from pathlib import Path
import sys

app = Path(sys.argv[1])

# 1. Patch wasm_sandbox/binary_decoder.py
bd_path = app / "wasm_sandbox" / "binary_decoder.py"
bd = bd_path.read_text(encoding="utf-8")

old_leb = """    def read_u32(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7
            if shift > 70:
                raise DecodeError("LEB128 integer too long")

    def read_s32(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if b & 0x40:
                    result |= -(1 << shift)
                return result
            if shift > 70:
                raise DecodeError("Signed LEB128 integer too long")"""

new_leb = """    def read_u32(self) -> int:
        result = 0
        shift = 0
        count = 0
        while True:
            b = self.read_byte()
            count += 1
            if count > 5:
                raise DecodeError("u32 LEB128 exceeds maximum 5 bytes")
            if count == 5 and (b & 0xF0) != 0:
                raise DecodeError("Invalid non-zero upper bits in 5th byte of u32 LEB128")
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7

    def read_s32(self) -> int:
        result = 0
        shift = 0
        count = 0
        while True:
            b = self.read_byte()
            count += 1
            if count > 5:
                raise DecodeError("s32 LEB128 exceeds maximum 5 bytes")
            if count == 5:
                sign_neg = (b & 0x08) != 0
                spare = b & 0x70
                if (not sign_neg and spare != 0x00) or (sign_neg and spare != 0x70):
                    raise DecodeError("Invalid sign-extension bits in 5th byte of s32 LEB128")
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                elif count == 5 and (b & 0x08):
                    result -= 1 << 32
                return result"""

assert old_leb in bd, "LEB128 block not found"
bd = bd.replace(old_leb, new_leb, 1)
bd_path.write_text(bd, encoding="utf-8")

# 2. Patch wasm_sandbox/validator.py
va_path = app / "wasm_sandbox" / "validator.py"
va = va_path.read_text(encoding="utf-8")

old_pop = """    def pop_val(self, expected: StackType | None = None) -> StackType:
        frame = self.cur_frame
        if len(self.val_stack) == 0 and frame.unreachable:
            return expected if expected is not None else UNKNOWN
        if len(self.val_stack) <= frame.start_height:
            if not frame.unreachable:
                raise ValidationError(f"Operand stack exhausted inside '{frame.opcode}' frame")
            # Intentionally flawed: pops across `frame.start_height` when `len(self.val_stack) > 0`!
        actual = self.val_stack.pop()"""

new_pop = """    def pop_val(self, expected: StackType | None = None) -> StackType:
        frame = self.cur_frame
        if len(self.val_stack) <= frame.start_height:
            if frame.unreachable:
                return expected if expected is not None else UNKNOWN
            raise ValidationError(f"Operand stack exhausted inside '{frame.opcode}' frame")
        actual = self.val_stack.pop()"""

assert old_pop in va, "pop_val block not found"
va = va.replace(old_pop, new_pop, 1)

old_end_br = """            elif op == "end":
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
                self.mark_unreachable()"""

new_end_br = """            elif op == "end":
                if len(self.ctrl_stack) <= 1:
                    raise ValidationError("Unexpected nested 'end'")
                frame = self.cur_frame
                if frame.opcode == "if" and not frame.has_else and frame.param_types != frame.result_types:
                    raise ValidationError("Single-sided 'if' without 'else' must have matching param and result types")
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
                def_types = self.get_target_frame(default_target).label_types()
                for t_depth in targets:
                    t_types = self.get_target_frame(t_depth).label_types()
                    if t_types != def_types:
                        raise ValidationError(f"br_table target label types {t_types} do not match default {def_types}")
                self.pop_vals(def_types)
                self.mark_unreachable()"""

assert old_end_br in va, "end/br_table block not found"
va = va.replace(old_end_br, new_end_br, 1)
va_path.write_text(va, encoding="utf-8")

# 3. Patch wasm_sandbox/executor.py
ex_path = app / "wasm_sandbox" / "executor.py"
ex = ex_path.read_text(encoding="utf-8")

old_ci = """                if len(callee.func_type.params) != len(expected_ft.params) or len(
                    callee.func_type.results
                ) != len(expected_ft.results):
                    raise TrapError("indirect call type mismatch")"""

new_ci = """                if callee.func_type != expected_ft:
                    raise TrapError("indirect call type mismatch")"""

assert old_ci in ex, "call_indirect block not found"
ex = ex.replace(old_ci, new_ci, 1)

old_mem_ld = """                base_addr = _u32(val_stack.pop())
                # Intentionally wraps effective address modulo 2^32!
                ea = (base_addr + memarg.offset) & MASK32"""

new_mem_ld = """                base_addr = _u32(val_stack.pop())
                ea = base_addr + memarg.offset"""

assert old_mem_ld in ex, "load ea block not found"
ex = ex.replace(old_mem_ld, new_mem_ld, 1)

old_mem_st = """                base_addr = _u32(val_stack.pop())
                ea = (base_addr + memarg.offset) & MASK32"""

new_mem_st = """                base_addr = _u32(val_stack.pop())
                ea = base_addr + memarg.offset"""

assert old_mem_st in ex, "store ea block not found"
ex = ex.replace(old_mem_st, new_mem_st, 1)
ex_path.write_text(ex, encoding="utf-8")

# 4. Patch wasm_sandbox/linker.py
lk_path = app / "wasm_sandbox" / "linker.py"
lk = lk_path.read_text(encoding="utf-8")

old_seg = """        # Populate active element segments (flawed: mutates imported tables before checking all segments!)
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
            mem.data[offset:end] = ds.init_bytes"""

new_seg = """        elem_writes: list[tuple[TableInstance, int, tuple[int, ...]]] = []
        for el in mod.elems:
            tab = tables[el.table_idx]
            offset = int(_eval_const_expr(el.offset_expr, globals_list, funcs)) & MASK32
            if offset < 0 or offset + len(el.func_indices) > len(tab.elements):
                raise LinkError("Element segment does not fit in table")
            elem_writes.append((tab, offset, el.func_indices))

        data_writes: list[tuple[MemoryInstance, int, bytes]] = []
        for ds in mod.datas:
            mem = memories[ds.mem_idx]
            offset = int(_eval_const_expr(ds.offset_expr, globals_list, funcs)) & MASK32
            end = offset + len(ds.init_bytes)
            if offset < 0 or end > len(mem.data):
                raise LinkError("Data segment does not fit in memory")
            data_writes.append((mem, offset, ds.init_bytes))

        for tab, offset, fn_indices in elem_writes:
            for i, fn_i in enumerate(fn_indices):
                tab.elements[offset + i] = FuncRefHandle(funcs[fn_i], f"func_{fn_i}")

        for mem, offset, init_bytes in data_writes:
            mem.data[offset : offset + len(init_bytes)] = init_bytes"""

assert old_seg in lk, "segment initialization block not found"
lk = lk.replace(old_seg, new_seg, 1)
lk_path.write_text(lk, encoding="utf-8")

# 5. Append regression tests to tests/test_wasm_sandbox.py
test_path = app / "tests" / "test_wasm_sandbox.py"
reg_code = """

class WasmSandboxHardeningRegressionTests(unittest.TestCase):
    def test_rejects_polymorphic_outer_pop_and_one_armed_if_result(self) -> None:
        mb = ModuleBuilder()
        t0 = mb.add_type([], [ValType.I32])
        mb.add_func(t0, [], [("i64.const", 1), ("i32.const", 2), ("block", None), ("unreachable",), ("drop",), ("drop",), ("end",)])
        with self.assertRaises(ValidationError):
            validate_module(decode_module(mb.to_bytes()))

        mb2 = ModuleBuilder()
        t1 = mb2.add_type([ValType.I32], [ValType.I64])
        mb2.add_func(t1, [], [("local.get", 0), ("if", ValType.I64), ("i64.const", 5), ("end",)])
        with self.assertRaises(ValidationError):
            validate_module(decode_module(mb2.to_bytes()))

    def test_rejects_br_table_loop_and_type_mismatch(self) -> None:
        mb = ModuleBuilder()
        t_fn = mb.add_type([ValType.I32], [ValType.I32])
        mb.add_func(t_fn, [], [("block", ValType.I32), ("loop", ValType.I32), ("i32.const", 1), ("local.get", 0), ("br_table", [0], 1), ("end",), ("end",)])
        with self.assertRaises(ValidationError):
            validate_module(decode_module(mb.to_bytes()))

    def test_traps_on_ea_wraparound_and_call_indirect_type_confusion(self) -> None:
        mb = ModuleBuilder()
        t_ld = mb.add_type([ValType.I32], [ValType.I32])
        mb.add_memory(1, 1)
        mb.add_func(t_ld, [], [("local.get", 0), ("i32.load", 2, 32)], export_as="ld")
        inst = Linker().instantiate(decode_module(mb.to_bytes()))
        with self.assertRaises(TrapError):
            inst.invoke("ld", [-16])
"""
test_path.write_text(test_path.read_text(encoding="utf-8") + reg_code, encoding="utf-8")
PY

python3 -m unittest discover -s "$APP_DIR/tests" -p "test_*.py"
