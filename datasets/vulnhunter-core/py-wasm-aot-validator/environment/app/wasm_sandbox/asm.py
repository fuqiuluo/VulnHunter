"""Programmatic WebAssembly `.wasm` Binary Assembler Helper for Testing & Tooling."""

from __future__ import annotations

from .binary_decoder import MEM_OPCODES, SIMPLE_OPCODES, WASM_MAGIC, WASM_VERSION
from .types import BlockSignature, FuncType, GlobalType, Limits, TableType, ValType

REV_SIMPLE: dict[str, int] = {v: k for k, v in SIMPLE_OPCODES.items()}
REV_MEM: dict[str, int] = {v: k for k, v in MEM_OPCODES.items()}


def enc_u32(val: int) -> bytes:
    if val < 0:
        raise ValueError(f"enc_u32 requires non-negative value, got {val}")
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def enc_s64(val: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = val & 0x7F
        val >>= 7
        if (val == 0 and (b & 0x40) == 0) or (val == -1 and (b & 0x40) != 0):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


def enc_s32(val: int) -> bytes:
    return enc_s64(val)


def enc_vec(items: list[bytes]) -> bytes:
    return enc_u32(len(items)) + b"".join(items)


def enc_name(s: str) -> bytes:
    raw = s.encode("utf-8")
    return enc_u32(len(raw)) + raw


def enc_limits(lim: Limits) -> bytes:
    if lim.maximum is None:
        return b"\x00" + enc_u32(lim.minimum)
    return b"\x01" + enc_u32(lim.minimum) + enc_u32(lim.maximum)


def enc_table_type(tt: TableType) -> bytes:
    return bytes([int(tt.elem_type)]) + enc_limits(tt.limits)


def enc_global_type(gt: GlobalType) -> bytes:
    return bytes([int(gt.val_type), 0x01 if gt.mutable else 0x00])


def enc_block_sig(sig: BlockSignature | ValType | int | None) -> bytes:
    if sig is None:
        return b"\x40"
    if isinstance(sig, ValType):
        return bytes([int(sig)])
    if isinstance(sig, int):
        return enc_s32(sig)
    if sig.kind == "empty":
        return b"\x40"
    if sig.kind == "valtype":
        assert sig.val_type is not None
        return bytes([int(sig.val_type)])
    assert sig.type_idx is not None
    return enc_s32(sig.type_idx)


def enc_instr_seq(ops: list[tuple]) -> bytes:
    """Encode an instruction tuple list and terminate with `0x0B` (`end`)."""
    out = bytearray()
    for item in ops:
        op = item[0]
        if op in ("block", "loop", "if"):
            code = {"block": 0x02, "loop": 0x03, "if": 0x04}[op]
            sig = item[1] if len(item) > 1 else None
            out.append(code)
            out.extend(enc_block_sig(sig))
        elif op == "else":
            out.append(0x05)
        elif op == "end":
            out.append(0x0B)
        elif op in ("br", "br_if"):
            out.append(0x0C if op == "br" else 0x0D)
            out.extend(enc_u32(int(item[1])))
        elif op == "br_table":
            targets, default_target = item[1], item[2]
            out.append(0x0E)
            out.extend(enc_u32(len(targets)))
            for t in targets:
                out.extend(enc_u32(int(t)))
            out.extend(enc_u32(int(default_target)))
        elif op == "call":
            out.append(0x10)
            out.extend(enc_u32(int(item[1])))
        elif op == "call_indirect":
            out.append(0x11)
            out.extend(enc_u32(int(item[1])))
            out.extend(enc_u32(int(item[2]) if len(item) > 2 else 0))
        elif op in ("local.get", "local.set", "local.tee"):
            code = {"local.get": 0x20, "local.set": 0x21, "local.tee": 0x22}[op]
            out.append(code)
            out.extend(enc_u32(int(item[1])))
        elif op in ("global.get", "global.set"):
            out.append(0x23 if op == "global.get" else 0x24)
            out.extend(enc_u32(int(item[1])))
        elif op in ("table.get", "table.set"):
            out.append(0x25 if op == "table.get" else 0x26)
            out.extend(enc_u32(int(item[1])))
        elif op in REV_MEM:
            align = int(item[1]) if len(item) > 1 else 0
            offset = int(item[2]) if len(item) > 2 else 0
            out.append(REV_MEM[op])
            out.extend(enc_u32(align))
            out.extend(enc_u32(offset))
        elif op in ("memory.size", "memory.grow"):
            out.append(0x3F if op == "memory.size" else 0x40)
            out.append(0x00)
        elif op == "i32.const":
            out.append(0x41)
            out.extend(enc_s32(int(item[1])))
        elif op == "i64.const":
            out.append(0x42)
            out.extend(enc_s64(int(item[1])))
        elif op == "ref.null":
            out.append(0xD0)
            out.append(int(item[1]) if len(item) > 1 else int(ValType.FUNCREF))
        elif op == "ref.func":
            out.append(0xD2)
            out.extend(enc_u32(int(item[1])))
        elif op == "raw":
            out.extend(bytes(item[1]))
        elif op in REV_SIMPLE:
            out.append(REV_SIMPLE[op])
        else:
            raise ValueError(f"Unknown assembler op: {op!r}")
    out.append(0x0B)
    return bytes(out)


class ModuleBuilder:
    def __init__(self) -> None:
        self.types: list[FuncType] = []
        self.imports: list[bytes] = []
        self.func_type_idxs: list[int] = []
        self.tables: list[TableType] = []
        self.memories: list[Limits] = []
        self.globals: list[tuple[GlobalType, list[tuple]]] = []
        self.exports: list[tuple[str, int, int]] = []
        self.elems: list[tuple[int, list[tuple], list[int]]] = []
        self.codes: list[tuple[list[tuple[int, ValType]], list[tuple]]] = []
        self.datas: list[tuple[int, list[tuple], bytes]] = []

    def add_type(self, params: list[ValType] | tuple[ValType, ...], results: list[ValType] | tuple[ValType, ...]) -> int:
        ft = FuncType(tuple(params), tuple(results))
        for idx, existing in enumerate(self.types):
            if existing == ft:
                return idx
        self.types.append(ft)
        return len(self.types) - 1

    def add_import_func(self, mod: str, name: str, type_idx: int) -> None:
        self.imports.append(enc_name(mod) + enc_name(name) + b"\x00" + enc_u32(type_idx))

    def add_import_table(self, mod: str, name: str, tt: TableType) -> None:
        self.imports.append(enc_name(mod) + enc_name(name) + b"\x01" + enc_table_type(tt))

    def add_import_memory(self, mod: str, name: str, lim: Limits) -> None:
        self.imports.append(enc_name(mod) + enc_name(name) + b"\x02" + enc_limits(lim))

    def add_import_global(self, mod: str, name: str, gt: GlobalType) -> None:
        self.imports.append(enc_name(mod) + enc_name(name) + b"\x03" + enc_global_type(gt))

    def add_func(
        self,
        type_idx: int,
        locals_decls: list[tuple[int, ValType]],
        body_ops: list[tuple],
        export_as: str | None = None,
    ) -> int:
        num_imported_funcs = sum(1 for imp in self.imports if imp.endswith(b"") and False)
        _ = num_imported_funcs
        imported_fn_cnt = 0
        for raw in self.imports:
            # Count function imports accurately by scanning kind byte
            r_pos = 0
            for _ in range(2):
                # decode u32 length
                ln = 0
                sh = 0
                while True:
                    b = raw[r_pos]
                    r_pos += 1
                    ln |= (b & 0x7F) << sh
                    if (b & 0x80) == 0:
                        break
                    sh += 7
                r_pos += ln
            if raw[r_pos] == 0x00:
                imported_fn_cnt += 1

        fn_idx = imported_fn_cnt + len(self.func_type_idxs)
        self.func_type_idxs.append(type_idx)
        self.codes.append((locals_decls, body_ops))
        if export_as is not None:
            self.add_export(export_as, "func", fn_idx)
        return fn_idx

    def add_table(self, minimum: int, maximum: int | None = None, export_as: str | None = None) -> int:
        idx = len(self.tables)
        self.tables.append(TableType(ValType.FUNCREF, Limits(minimum, maximum)))
        if export_as is not None:
            self.add_export(export_as, "table", idx)
        return idx

    def add_memory(self, minimum: int, maximum: int | None = None, export_as: str | None = None) -> int:
        idx = len(self.memories)
        self.memories.append(Limits(minimum, maximum))
        if export_as is not None:
            self.add_export(export_as, "mem", idx)
        return idx

    def add_global(self, vt: ValType, mutable: bool, init_ops: list[tuple], export_as: str | None = None) -> int:
        idx = len(self.globals)
        self.globals.append((GlobalType(vt, mutable), init_ops))
        if export_as is not None:
            self.add_export(export_as, "global", idx)
        return idx

    def add_export(self, name: str, kind: str, index: int) -> None:
        kind_byte = {"func": 0x00, "table": 0x01, "mem": 0x02, "global": 0x03}[kind]
        self.exports.append((name, kind_byte, index))

    def add_elem(self, table_idx: int, offset_ops: list[tuple], func_indices: list[int]) -> None:
        self.elems.append((table_idx, offset_ops, func_indices))

    def add_data(self, mem_idx: int, offset_ops: list[tuple], data: bytes) -> None:
        self.datas.append((mem_idx, offset_ops, data))

    def to_bytes(self) -> bytes:
        sections = bytearray(WASM_MAGIC + WASM_VERSION)

        def emit_sec(sec_id: int, payload: bytes) -> None:
            sections.append(sec_id)
            sections.extend(enc_u32(len(payload)))
            sections.extend(payload)

        if self.types:
            items = [
                b"\x60"
                + enc_vec([bytes([int(p)]) for p in ft.params])
                + enc_vec([bytes([int(r)]) for r in ft.results])
                for ft in self.types
            ]
            emit_sec(1, enc_vec(items))

        if self.imports:
            emit_sec(2, enc_vec(self.imports))

        if self.func_type_idxs:
            emit_sec(3, enc_vec([enc_u32(ti) for ti in self.func_type_idxs]))

        if self.tables:
            emit_sec(4, enc_vec([enc_table_type(t) for t in self.tables]))

        if self.memories:
            emit_sec(5, enc_vec([enc_limits(m) for m in self.memories]))

        if self.globals:
            items = [enc_global_type(gt) + enc_instr_seq(init) for gt, init in self.globals]
            emit_sec(6, enc_vec(items))

        if self.exports:
            items = [enc_name(nm) + bytes([kb]) + enc_u32(idx) for nm, kb, idx in self.exports]
            emit_sec(7, enc_vec(items))

        if self.elems:
            items = []
            for tidx, off_ops, fns in self.elems:
                if tidx == 0:
                    items.append(
                        enc_u32(0)
                        + enc_instr_seq(off_ops)
                        + enc_vec([enc_u32(f) for f in fns])
                    )
                else:
                    items.append(
                        enc_u32(2)
                        + enc_u32(tidx)
                        + enc_instr_seq(off_ops)
                        + b"\x00"
                        + enc_vec([enc_u32(f) for f in fns])
                    )
            emit_sec(9, enc_vec(items))

        if self.codes:
            code_entries = []
            for loc_decls, ops in self.codes:
                loc_bytes = enc_vec([enc_u32(cnt) + bytes([int(vt)]) for cnt, vt in loc_decls])
                body_bytes = loc_bytes + enc_instr_seq(ops)
                code_entries.append(enc_u32(len(body_bytes)) + body_bytes)
            emit_sec(10, enc_vec(code_entries))

        if self.datas:
            items = []
            for midx, off_ops, raw_d in self.datas:
                if midx == 0:
                    items.append(enc_u32(0) + enc_instr_seq(off_ops) + enc_u32(len(raw_d)) + raw_d)
                else:
                    items.append(
                        enc_u32(2)
                        + enc_u32(midx)
                        + enc_instr_seq(off_ops)
                        + enc_u32(len(raw_d))
                        + raw_d
                    )
            emit_sec(11, enc_vec(items))

        return bytes(sections)
