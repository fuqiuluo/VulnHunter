"""
WebAssembly 1.0/2.0 Binary Format Decoder (`\x00asm\x01\x00\x00\x00`).

Specification Contracts (WebAssembly Core §5.2.2):
 - Unsigned 32-bit LEB128 (`u32`) must consume at most `ceil(32 / 7) == 5` bytes,
   and if 5 bytes are consumed, unused upper bits `(byte_5 & 0xF0)` must be `0`.
 - Signed 32-bit LEB128 (`s32`) must consume at most 5 bytes, and if 5 bytes are
   consumed, the unused upper bits `(byte_5 & 0x70)` must properly sign-extend bit 31
   (`0x00` when `(byte_5 & 0x08) == 0`, or `0x70` when `(byte_5 & 0x08) != 0`).
 - Signed 64-bit LEB128 (`s64`) must consume at most `ceil(64 / 7) == 10` bytes, with
   valid sign-extension bits on byte 10 (`0x00` for non-negative, `0x7E` for negative).
"""

from __future__ import annotations

from .types import (
    BlockSignature,
    DataSegment,
    DecodeError,
    ElemSegment,
    ExportDesc,
    FuncType,
    FunctionBody,
    GlobalDef,
    GlobalType,
    ImportDesc,
    Instruction,
    Limits,
    MemArg,
    Module,
    TableType,
    ValType,
)

WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"

SIMPLE_OPCODES: dict[int, str] = {
    0x00: "unreachable",
    0x01: "nop",
    0x0F: "return",
    0x1A: "drop",
    0x1B: "select",
    0x45: "i32.eqz",
    0x46: "i32.eq",
    0x47: "i32.ne",
    0x48: "i32.lt_s",
    0x49: "i32.lt_u",
    0x4A: "i32.gt_s",
    0x4B: "i32.gt_u",
    0x4C: "i32.le_s",
    0x4D: "i32.le_u",
    0x4E: "i32.ge_s",
    0x4F: "i32.ge_u",
    0x50: "i64.eqz",
    0x51: "i64.eq",
    0x52: "i64.ne",
    0x53: "i64.lt_s",
    0x54: "i64.lt_u",
    0x55: "i64.gt_s",
    0x56: "i64.gt_u",
    0x57: "i64.le_s",
    0x58: "i64.le_u",
    0x59: "i64.ge_s",
    0x5A: "i64.ge_u",
    0x6A: "i32.add",
    0x6B: "i32.sub",
    0x6C: "i32.mul",
    0x6D: "i32.div_s",
    0x6E: "i32.div_u",
    0x71: "i32.and",
    0x72: "i32.or",
    0x73: "i32.xor",
    0x74: "i32.shl",
    0x75: "i32.shr_s",
    0x76: "i32.shr_u",
    0x7C: "i64.add",
    0x7D: "i64.sub",
    0x7E: "i64.mul",
    0x83: "i64.and",
    0x84: "i64.or",
    0x85: "i64.xor",
    0x86: "i64.shl",
    0x87: "i64.shr_s",
    0x88: "i64.shr_u",
    0xA7: "i32.wrap_i64",
    0xAC: "i64.extend_i32_s",
    0xAD: "i64.extend_i32_u",
    0xD1: "ref.is_null",
}

MEM_OPCODES: dict[int, str] = {
    0x28: "i32.load",
    0x29: "i64.load",
    0x2C: "i32.load8_s",
    0x2D: "i32.load8_u",
    0x36: "i32.store",
    0x37: "i64.store",
    0x3A: "i32.store8",
}


class ByteReader:
    def __init__(self, buf: bytes, start: int = 0, end: int | None = None) -> None:
        self.buf = buf
        self.pos = start
        self.end = len(buf) if end is None else end

    def remaining(self) -> int:
        return self.end - self.pos

    def at_end(self) -> bool:
        return self.pos >= self.end

    def read_byte(self) -> int:
        if self.pos >= self.end:
            raise DecodeError("Unexpected EOF while reading byte")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise DecodeError(f"Unexpected EOF while reading {n} bytes")
        chunk = self.buf[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def subreader(self, length: int) -> "ByteReader":
        if length < 0 or self.pos + length > self.end:
            raise DecodeError(f"Section/frame length {length} exceeds remaining bytes")
        sub = ByteReader(self.buf, self.pos, self.pos + length)
        self.pos += length
        return sub

    def read_u32(self) -> int:
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
                raise DecodeError("Signed LEB128 integer too long")

    def read_s64(self) -> int:
        result = 0
        shift = 0
        count = 0
        while True:
            b = self.read_byte()
            count += 1
            if count > 10:
                raise DecodeError("s64 LEB128 exceeds maximum 10 bytes")
            if count == 10:
                sign_neg = (b & 0x01) != 0
                spare = b & 0x7E
                if (not sign_neg and spare != 0x00) or (sign_neg and spare != 0x7E):
                    raise DecodeError("Invalid unused bits in 10th byte of s64 LEB128")
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if shift < 64 and (b & 0x40):
                    result |= -(1 << shift)
                elif count == 10 and (b & 0x01):
                    result -= 1 << 64
                return result

    def read_name(self) -> str:
        n = self.read_u32()
        raw = self.read_bytes(n)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError("Invalid UTF-8 name in WebAssembly binary") from exc

    def read_limits(self) -> Limits:
        flags = self.read_byte()
        if flags == 0x00:
            minimum = self.read_u32()
            return Limits(minimum=minimum, maximum=None)
        if flags == 0x01:
            minimum = self.read_u32()
            maximum = self.read_u32()
            return Limits(minimum=minimum, maximum=maximum)
        raise DecodeError(f"Invalid limits flag: 0x{flags:02x}")

    def read_table_type(self) -> TableType:
        elem = ValType.from_byte(self.read_byte())
        if elem != ValType.FUNCREF:
            raise DecodeError(f"Table element type must be funcref, got {elem}")
        return TableType(elem_type=elem, limits=self.read_limits())

    def read_global_type(self) -> GlobalType:
        vt = ValType.from_byte(self.read_byte())
        mut_byte = self.read_byte()
        if mut_byte not in (0x00, 0x01):
            raise DecodeError(f"Invalid global mutability flag: 0x{mut_byte:02x}")
        return GlobalType(val_type=vt, mutable=(mut_byte == 0x01))

    def read_block_sig(self) -> BlockSignature:
        peek = self.buf[self.pos] if self.pos < self.end else -1
        if peek == 0x40:
            self.pos += 1
            return BlockSignature(kind="empty")
        if peek in (0x7F, 0x7E, 0x7D, 0x7C, 0x70):
            self.pos += 1
            return BlockSignature(kind="valtype", val_type=ValType.from_byte(peek))
        idx = self.read_s32()
        if idx < 0:
            raise DecodeError(f"Invalid negative block type index: {idx}")
        return BlockSignature(kind="typeidx", type_idx=idx)


def decode_expr(reader: ByteReader, allow_nested: bool = True) -> tuple[Instruction, ...]:
    insns: list[Instruction] = []
    depth = 1
    while depth > 0:
        if reader.at_end():
            raise DecodeError("Unexpected EOF inside instruction sequence (missing 0x0B end)")
        op = reader.read_byte()

        if op in (0x02, 0x03, 0x04):
            if not allow_nested:
                raise DecodeError("Control blocks not permitted in constant expression")
            name = {0x02: "block", 0x03: "loop", 0x04: "if"}[op]
            sig = reader.read_block_sig()
            insns.append(Instruction(name, sig))
            depth += 1
        elif op == 0x05:
            if depth <= 1:
                raise DecodeError("Unexpected 'else' at top-level function frame")
            insns.append(Instruction("else"))
        elif op == 0x0B:
            depth -= 1
            if depth > 0:
                insns.append(Instruction("end"))
        elif op in (0x0C, 0x0D):
            insns.append(Instruction("br" if op == 0x0C else "br_if", reader.read_u32()))
        elif op == 0x0E:
            vec_len = reader.read_u32()
            targets = tuple(reader.read_u32() for _ in range(vec_len))
            default_target = reader.read_u32()
            insns.append(Instruction("br_table", (targets, default_target)))
        elif op == 0x10:
            insns.append(Instruction("call", reader.read_u32()))
        elif op == 0x11:
            type_idx = reader.read_u32()
            table_idx = reader.read_u32()
            insns.append(Instruction("call_indirect", (type_idx, table_idx)))
        elif op in (0x20, 0x21, 0x22):
            name = {0x20: "local.get", 0x21: "local.set", 0x22: "local.tee"}[op]
            insns.append(Instruction(name, reader.read_u32()))
        elif op in (0x23, 0x24):
            name = "global.get" if op == 0x23 else "global.set"
            insns.append(Instruction(name, reader.read_u32()))
        elif op in (0x25, 0x26):
            name = "table.get" if op == 0x25 else "table.set"
            insns.append(Instruction(name, reader.read_u32()))
        elif op in MEM_OPCODES:
            align = reader.read_u32()
            offset = reader.read_u32()
            insns.append(Instruction(MEM_OPCODES[op], MemArg(align=align, offset=offset)))
        elif op in (0x3F, 0x40):
            mem_idx = reader.read_byte()
            if mem_idx != 0x00:
                raise DecodeError("Non-zero memory index byte in memory.size/grow")
            insns.append(Instruction("memory.size" if op == 0x3F else "memory.grow", 0))
        elif op == 0x41:
            insns.append(Instruction("i32.const", reader.read_s32()))
        elif op == 0x42:
            insns.append(Instruction("i64.const", reader.read_s64()))
        elif op == 0xD0:
            rt = ValType.from_byte(reader.read_byte())
            if rt != ValType.FUNCREF:
                raise DecodeError("ref.null requires reference type")
            insns.append(Instruction("ref.null", rt))
        elif op == 0xD2:
            insns.append(Instruction("ref.func", reader.read_u32()))
        elif op in SIMPLE_OPCODES:
            insns.append(Instruction(SIMPLE_OPCODES[op]))
        else:
            raise DecodeError(f"Unsupported or unknown opcode: 0x{op:02x}")

    return tuple(insns)


def decode_module(raw: bytes) -> Module:
    if len(raw) < 8:
        raise DecodeError("Binary module shorter than 8-byte header")
    if raw[:4] != WASM_MAGIC:
        raise DecodeError("Invalid WebAssembly magic header")
    if raw[4:8] != WASM_VERSION:
        raise DecodeError("Unsupported WebAssembly binary version")

    reader = ByteReader(raw, 8)
    mod = Module()
    last_sec_id = 0
    declared_func_types: list[int] = []

    while not reader.at_end():
        sec_id = reader.read_byte()
        sec_len = reader.read_u32()
        sec = reader.subreader(sec_len)

        if sec_id == 0:
            # Custom section: require valid UTF-8 name, ignore remaining payload
            sec.read_name()
            continue

        if sec_id > 11:
            raise DecodeError(f"Unknown section id: {sec_id}")
        if sec_id <= last_sec_id:
            raise DecodeError(f"Out-of-order or duplicate section {sec_id} after {last_sec_id}")
        last_sec_id = sec_id

        if sec_id == 1:  # Type section
            count = sec.read_u32()
            for _ in range(count):
                tag = sec.read_byte()
                if tag != 0x60:
                    raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02x}")
                p_len = sec.read_u32()
                params = tuple(ValType.from_byte(sec.read_byte()) for _ in range(p_len))
                r_len = sec.read_u32()
                results = tuple(ValType.from_byte(sec.read_byte()) for _ in range(r_len))
                mod.types.append(FuncType(params=params, results=results))
        elif sec_id == 2:  # Import section
            count = sec.read_u32()
            for _ in range(count):
                mod_name = sec.read_name()
                field_name = sec.read_name()
                kind_byte = sec.read_byte()
                if kind_byte == 0x00:
                    mod.imports.append(ImportDesc(mod_name, field_name, "func", sec.read_u32()))
                elif kind_byte == 0x01:
                    mod.imports.append(ImportDesc(mod_name, field_name, "table", sec.read_table_type()))
                elif kind_byte == 0x02:
                    mod.imports.append(ImportDesc(mod_name, field_name, "mem", sec.read_limits()))
                elif kind_byte == 0x03:
                    mod.imports.append(ImportDesc(mod_name, field_name, "global", sec.read_global_type()))
                else:
                    raise DecodeError(f"Unknown import descriptor kind: 0x{kind_byte:02x}")
        elif sec_id == 3:  # Function section
            count = sec.read_u32()
            declared_func_types = [sec.read_u32() for _ in range(count)]
        elif sec_id == 4:  # Table section
            count = sec.read_u32()
            for _ in range(count):
                mod.tables.append(sec.read_table_type())
        elif sec_id == 5:  # Memory section
            count = sec.read_u32()
            for _ in range(count):
                mod.memories.append(sec.read_limits())
        elif sec_id == 6:  # Global section
            count = sec.read_u32()
            for _ in range(count):
                gt = sec.read_global_type()
                init = decode_expr(sec, allow_nested=False)
                mod.globals.append(GlobalDef(global_type=gt, init_expr=init))
        elif sec_id == 7:  # Export section
            count = sec.read_u32()
            for _ in range(count):
                name = sec.read_name()
                kind_b = sec.read_byte()
                kind_map = {0x00: "func", 0x01: "table", 0x02: "mem", 0x03: "global"}
                if kind_b not in kind_map:
                    raise DecodeError(f"Unknown export kind: 0x{kind_b:02x}")
                mod.exports.append(ExportDesc(name=name, kind=kind_map[kind_b], index=sec.read_u32()))
        elif sec_id == 8:  # Start section
            mod.start_func = sec.read_u32()
        elif sec_id == 9:  # Element section
            count = sec.read_u32()
            for _ in range(count):
                flags = sec.read_u32()
                if flags == 0:
                    table_idx = 0
                elif flags == 2:
                    table_idx = sec.read_u32()
                else:
                    raise DecodeError(f"Unsupported element segment mode: {flags}")
                offset_expr = decode_expr(sec, allow_nested=False)
                if flags == 2:
                    elem_kind = sec.read_byte()
                    if elem_kind != 0x00:
                        raise DecodeError(f"Unsupported elemkind: 0x{elem_kind:02x}")
                fn_cnt = sec.read_u32()
                fn_idxs = tuple(sec.read_u32() for _ in range(fn_cnt))
                mod.elems.append(ElemSegment(table_idx=table_idx, offset_expr=offset_expr, func_indices=fn_idxs))
        elif sec_id == 10:  # Code section
            count = sec.read_u32()
            if count != len(declared_func_types):
                raise DecodeError(
                    f"Code section count ({count}) does not match function section count ({len(declared_func_types)})"
                )
            for idx in range(count):
                body_size = sec.read_u32()
                body_reader = sec.subreader(body_size)
                local_decl_cnt = body_reader.read_u32()
                locals_list: list[ValType] = []
                for _ in range(local_decl_cnt):
                    rep = body_reader.read_u32()
                    vt = ValType.from_byte(body_reader.read_byte())
                    if len(locals_list) + rep > 50_000:
                        raise DecodeError("Too many local variables in function")
                    locals_list.extend([vt] * rep)
                insns = decode_expr(body_reader, allow_nested=True)
                if not body_reader.at_end():
                    raise DecodeError("Trailing bytes after function body end")
                mod.functions.append(
                    FunctionBody(
                        type_idx=declared_func_types[idx],
                        locals=tuple(locals_list),
                        body=insns,
                    )
                )
        elif sec_id == 11:  # Data section
            count = sec.read_u32()
            for _ in range(count):
                mode = sec.read_u32()
                if mode == 0:
                    mem_idx = 0
                elif mode == 2:
                    mem_idx = sec.read_u32()
                else:
                    raise DecodeError(f"Unsupported data segment mode: {mode}")
                offset_expr = decode_expr(sec, allow_nested=False)
                byte_len = sec.read_u32()
                init_bytes = sec.read_bytes(byte_len)
                mod.datas.append(DataSegment(mem_idx=mem_idx, offset_expr=offset_expr, init_bytes=init_bytes))

        if not sec.at_end():
            raise DecodeError(f"Section {sec_id} left {sec.remaining()} unread trailing bytes")

    if len(declared_func_types) != len(mod.functions):
        raise DecodeError("Function declarations missing corresponding code section")
    return mod
