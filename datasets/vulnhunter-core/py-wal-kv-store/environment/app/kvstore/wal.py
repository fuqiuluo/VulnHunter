"""Binary write-ahead log with framed records and reopen recovery."""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

WAL_MAGIC = b"VKVWAL01"
WAL_VERSION = 1

FILE_HEADER_STRUCT = struct.Struct(">8sHHQ")
FRAME_META_STRUCT = struct.Struct(">BQQQII")
CRC_STRUCT = struct.Struct(">I")
FRAME_HEADER_SIZE = FRAME_META_STRUCT.size + CRC_STRUCT.size

MAX_KEY_BYTES = 4096
MAX_VAL_BYTES = 16 * 1024 * 1024


class WALError(RuntimeError):
    """Base error for write-ahead log operations."""


class WALCorruptionError(WALError):
    """Raised when a WAL header or record frame fails structural validation."""


class RecordType(IntEnum):
    BEGIN = 1
    PUT = 2
    DELETE = 3
    SAVEPOINT = 4
    ROLLBACK_SP = 5
    COMMIT = 6
    ABORT = 7
    CHECKPOINT = 8


@dataclass(frozen=True)
class WALRecord:
    rec_type: RecordType
    lsn: int
    tx_id: int
    ts: int
    key: str
    value: bytes = b""


@dataclass
class CommittedBatch:
    tx_id: int
    commit_ts: int
    records: list[WALRecord]


@dataclass
class RecoveryReport:
    checkpoint_ts: int
    committed: list[CommittedBatch]
    next_lsn: int
    next_tx_id: int
    replayed_frames: int
    truncated_bytes: int


def _frame_checksum(meta: bytes, payload: bytes, key_len: int) -> int:
    crc = zlib.crc32(meta)
    return zlib.crc32(payload[:key_len], crc) & 0xFFFFFFFF


class WAL:
    """Manages binary framed write-ahead logging and startup log replay."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._fd: int | None = None
        self._next_lsn: int = 1
        self._checkpoint_ts: int = 0
        self._open_or_init()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def next_lsn(self) -> int:
        return self._next_lsn

    @property
    def checkpoint_ts(self) -> int:
        return self._checkpoint_ts

    def advance_lsn_floor(self, min_next_lsn: int) -> None:
        if min_next_lsn > self._next_lsn:
            self._next_lsn = min_next_lsn

    def _open_or_init(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            size = os.fstat(fd).st_size
            if size == 0:
                self._write_all(fd, FILE_HEADER_STRUCT.pack(WAL_MAGIC, WAL_VERSION, 0, 0))
                os.fsync(fd)
            elif size < FILE_HEADER_STRUCT.size:
                raise WALCorruptionError("Truncated WAL file header")
            else:
                magic, version, _flags, cp_ts = FILE_HEADER_STRUCT.unpack(os.pread(fd, FILE_HEADER_STRUCT.size, 0))
                if magic != WAL_MAGIC or version != WAL_VERSION:
                    raise WALCorruptionError("Unrecognized WAL magic or format version")
                self._checkpoint_ts = cp_ts
                os.lseek(fd, 0, os.SEEK_END)
        except Exception:
            os.close(fd)
            raise
        self._fd = fd

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view, written = memoryview(data), 0
        while written < len(view):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise WALError("Short write while appending to WAL")
            written += n

    def _require_fd(self) -> int:
        if self._fd is None:
            raise WALError("WAL is closed")
        return self._fd

    def append(self, rec_type: RecordType, *, tx_id: int, ts: int = 0, key: str = "", value: bytes = b"") -> WALRecord:
        fd = self._require_fd()
        key_bytes = key.encode("utf-8")
        if len(key_bytes) > MAX_KEY_BYTES or len(value) > MAX_VAL_BYTES:
            raise WALError("Key or value exceeds maximum frame size")
        lsn = self._next_lsn
        self._next_lsn += 1
        payload = key_bytes + value
        meta = FRAME_META_STRUCT.pack(int(rec_type), lsn, tx_id, ts, len(key_bytes), len(value))
        crc = _frame_checksum(meta, payload, len(key_bytes))
        os.lseek(fd, 0, os.SEEK_END)
        self._write_all(fd, meta + CRC_STRUCT.pack(crc) + payload)
        return WALRecord(rec_type=rec_type, lsn=lsn, tx_id=tx_id, ts=ts, key=key, value=value)

    def sync(self) -> None:
        os.fsync(self._require_fd())

    def recover(self) -> RecoveryReport:
        fd = self._require_fd()
        total_size = os.fstat(fd).st_size
        if total_size < FILE_HEADER_STRUCT.size:
            raise WALCorruptionError("WAL file smaller than header")
        magic, version, _flags, cp_ts = FILE_HEADER_STRUCT.unpack(os.pread(fd, FILE_HEADER_STRUCT.size, 0))
        if magic != WAL_MAGIC or version != WAL_VERSION:
            raise WALCorruptionError("Invalid WAL header magic or version")
        self._checkpoint_ts = cp_ts

        offset, replayed, truncated_bytes = FILE_HEADER_STRUCT.size, 0, 0
        staged_ops: list[WALRecord] = []
        savepoints: list[tuple[str, int]] = []
        committed: list[CommittedBatch] = []
        max_committed_tx = 0

        while offset < total_size:
            raw_frame_hdr = os.pread(fd, FRAME_HEADER_SIZE, offset)
            if len(raw_frame_hdr) < FRAME_HEADER_SIZE:
                truncated_bytes = total_size - offset
                os.ftruncate(fd, offset)
                break
            meta_bytes = raw_frame_hdr[: FRAME_META_STRUCT.size]
            (expected_crc,) = CRC_STRUCT.unpack(raw_frame_hdr[FRAME_META_STRUCT.size :])
            raw_type, lsn, tx_id, ts, key_len, val_len = FRAME_META_STRUCT.unpack(meta_bytes)
            try:
                rec_type = RecordType(raw_type)
            except ValueError as exc:
                raise WALCorruptionError(f"Unknown record type {raw_type} at {offset}") from exc
            if key_len > MAX_KEY_BYTES or val_len > MAX_VAL_BYTES:
                raise WALCorruptionError(f"Oversized frame lengths at offset {offset}")

            payload_len = key_len + val_len
            payload = os.pread(fd, payload_len, offset + FRAME_HEADER_SIZE)
            if len(payload) < payload_len:
                truncated_bytes = total_size - offset
                os.ftruncate(fd, offset)
                break
            if _frame_checksum(meta_bytes, payload, key_len) != expected_crc:
                raise WALCorruptionError(f"Frame checksum mismatch at offset {offset} (lsn={lsn})")
            try:
                key = payload[:key_len].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WALCorruptionError(f"Invalid UTF-8 key in WAL at offset {offset}") from exc

            rec = WALRecord(rec_type, lsn, tx_id, ts, key, payload[key_len:])
            offset += FRAME_HEADER_SIZE + payload_len
            replayed += 1

            if rec_type in (RecordType.PUT, RecordType.DELETE):
                staged_ops.append(rec)
            elif rec_type == RecordType.SAVEPOINT:
                savepoints.append((rec.key, len(staged_ops)))
            elif rec_type == RecordType.ROLLBACK_SP:
                for idx in range(len(savepoints) - 1, -1, -1):
                    if savepoints[idx][0] == rec.key:
                        del staged_ops[savepoints[idx][1] :]
                        del savepoints[idx + 1 :]
                        break
            elif rec_type == RecordType.ABORT:
                staged_ops = [op for op in staged_ops if op.tx_id != rec.tx_id]
                savepoints.clear()
            elif rec_type == RecordType.COMMIT:
                committed.append(CommittedBatch(rec.tx_id, rec.ts, list(staged_ops)))
                staged_ops.clear()
                savepoints.clear()
                max_committed_tx = max(max_committed_tx, rec.tx_id)

        os.lseek(fd, offset, os.SEEK_SET)
        self._next_lsn = len(committed) + 1
        return RecoveryReport(cp_ts, committed, self._next_lsn, max_committed_tx + 1, replayed, truncated_bytes)

    def reset(self, checkpoint_ts: int, *, next_lsn: int | None = None) -> None:
        fd = self._require_fd()
        retained_lsn = next_lsn if next_lsn is not None else self._next_lsn
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            self._write_all(tmp_fd, FILE_HEADER_STRUCT.pack(WAL_MAGIC, WAL_VERSION, 0, checkpoint_ts))
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        os.replace(tmp_path, self._path)
        os.close(fd)
        self._fd = os.open(self._path, os.O_RDWR, 0o600)
        os.lseek(self._fd, 0, os.SEEK_END)
        self._checkpoint_ts = checkpoint_ts
        self._next_lsn = max(1, retained_lsn)

    def close(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)
