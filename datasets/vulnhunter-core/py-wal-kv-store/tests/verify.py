#!/usr/bin/env python3
"""Deterministic verifier for task: py-wal-kv-store."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType


@contextlib.contextmanager
def loaded_kvstore(app_dir: Path) -> Iterator[ModuleType]:
    """Load kvstore package from app_dir with sys.modules registered prior to exec_module."""
    saved_path = list(sys.path)
    saved_mods = {
        k: sys.modules.pop(k)
        for k in list(sys.modules.keys())
        if k == "kvstore" or k.startswith("kvstore.")
    }
    try:
        sys.path.insert(0, str(app_dir))
        pkg_dir = app_dir / "kvstore"
        pkg_init = pkg_dir / "__init__.py"
        spec = importlib.util.spec_from_file_location(
            "kvstore",
            pkg_init,
            submodule_search_locations=[str(pkg_dir)],
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load kvstore package from {pkg_dir}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["kvstore"] = mod
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.path[:] = saved_path
        for k in list(sys.modules.keys()):
            if k == "kvstore" or k.startswith("kvstore."):
                sys.modules.pop(k, None)
        sys.modules.update(saved_mods)


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in /app/report.json: {exc}"
    if not isinstance(data, dict):
        return False, "report.json root must be a JSON object"

    raw_entries: list[str] = []
    raw_files = data.get("files")
    if isinstance(raw_files, str):
        raw_entries.append(raw_files)
    elif isinstance(raw_files, list):
        raw_entries.extend(str(item) for item in raw_files)
    if isinstance(data.get("file"), str):
        raw_entries.append(str(data["file"]))

    names = {
        Path(tok).name
        for entry in raw_entries
        for tok in re.findall(r"[\w./-]+\.py", entry)
    }
    if not ({"wal.py", "mvcc.py"} <= names and bool({"acl.py", "tx.py"} & names)):
        return (
            False,
            f"Expected report.json files to cover wal.py, mvcc.py, and acl.py/tx.py, got {sorted(names)}",
        )

    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) < 3:
        return False, "Expected at least 3 documented findings in report.json"
    for item in findings:
        text = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item).strip()
        if len(text) < 20 or "placeholder" in text.lower():
            return False, f"Finding entry is too brief or invalid: {text!r}"

    summary = data.get("summary")
    if not isinstance(summary, str) or len(summary.strip()) < 20 or "placeholder" in summary.lower():
        return False, "Missing or insufficient 'summary' field in report.json"

    return True, "Technical review report validated"


def check_regression_suite(app_dir: Path, orig_app: Path) -> tuple[bool, str]:
    suite_file = app_dir / "tests" / "test_store.py"
    if not suite_file.is_file():
        return False, "Missing /app/tests/test_store.py"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(app_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    pass_run = subprocess.run(
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            str(app_dir / "tests"),
            "-p",
            "test_*.py",
            "-v",
        ],
        capture_output=True,
        text=True,
        cwd=str(app_dir),
        env=env,
        timeout=30,
    )
    if pass_run.returncode != 0:
        return False, f"tests/test_store.py failed against updated kvstore:\n{pass_run.stderr}"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        shutil.copytree(orig_app / "kvstore", tmp / "kvstore")
        shutil.copytree(app_dir / "tests", tmp / "tests")
        env_orig = os.environ.copy()
        env_orig["PYTHONPATH"] = str(tmp)
        env_orig["PYTHONDONTWRITEBYTECODE"] = "1"
        fail_run = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                str(tmp / "tests"),
                "-p",
                "test_*.py",
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp),
            env=env_orig,
            timeout=30,
        )
        if fail_run.returncode == 0:
            return False, "tests/test_store.py unexpectedly passed against unmodified original kvstore"

    return True, "Regression test suite passes on updated code and fails on original unmodified code"


def _verify_acl_savepoints_and_isolation(kv: ModuleType) -> tuple[bool, str]:
    Engine = kv.Engine
    Principal = kv.Principal
    AccessDeniedError = kv.AccessDeniedError

    iam_admin = Principal.user("iam-admin")
    alice = Principal.user("alice", roles=["pay-eng"])
    bob = Principal.user("bob", roles=["auditor"])

    with tempfile.TemporaryDirectory() as tmp_str:
        store_dir = Path(tmp_str) / "acl_store"
        with Engine.open(store_dir) as eng:
            eng.grant_policy("iam-root", prefix="/orgs/acme", permissions=["grant"], subject="iam-admin")
            eng.grant_policy("alice-pub-read", prefix="/orgs/acme/public", permissions=["read"], subject="alice")
            eng.put("/orgs/acme/public/readme", b"hello")

            snap_before = eng.snapshot()

            tx = eng.begin(principal=iam_admin)
            tx.savepoint("sp1")
            tx.set_policy(
                "pay-eng-rw",
                prefix="/orgs/acme/projects/pay",
                permissions=["read", "write", "list"],
                role="pay-eng",
            )
            # Intra-transaction policy visibility before commit
            tx.put("/orgs/acme/projects/pay/secrets/hmac", b"hmac-v1", principal=alice)
            if tx.get("/orgs/acme/projects/pay/secrets/hmac", principal=alice) != b"hmac-v1":
                return False, "Intra-transaction grant + secret read failed before commit"
            tx.release_savepoint("sp1")

            tx.savepoint("sp2")
            # Same (subject, prefix) bucket as alice-pub-read + new subject grant for bob
            tx.set_policy(
                "alice-pub-elevated",
                prefix="/orgs/acme/public",
                permissions=["write", "delete", "grant"],
                subject="alice",
            )
            tx.set_policy(
                "bob-pay-temp",
                prefix="/orgs/acme/projects/pay",
                permissions=["read", "write"],
                subject="bob",
            )
            tx.put("/orgs/acme/public/temp", b"transient", principal=alice)
            if tx.get("/orgs/acme/projects/pay/secrets/hmac", principal=bob) != b"hmac-v1":
                return False, "Expected temporary grant inside sp2 to be visible prior to rollback"

            tx.rollback_to("sp2")

            # Immediately after rollback_to(sp2), rolled-back grants must be inactive inside tx
            if tx.check_access(bob, "/orgs/acme/projects/pay/secrets/hmac", "read"):
                return False, "Grant added after sp2 remained active inside transaction after rollback_to('sp2')"
            if tx.check_access(alice, "/orgs/acme/public/readme", "write"):
                return False, "Subject bucket grant added after sp2 remained active after rollback_to('sp2')"
            try:
                tx.put("/orgs/acme/public/after_rb", b"nope", principal=alice)
                return False, "Write succeeded inside tx using privilege rolled back at sp2"
            except AccessDeniedError:
                pass

            # Released sp1 grant must still work inside tx
            tx.put("/orgs/acme/projects/pay/secrets/rot", b"rot-v1", principal=alice)

            # Pre-commit snapshot must remain isolated from in-flight tx
            if snap_before.check_access(alice, "/orgs/acme/projects/pay/secrets/hmac", "read"):
                return False, "Pre-commit snapshot leaked uncommitted ACL grant"
            tx.commit()

            snap_after = eng.snapshot()
            if snap_before.check_access(alice, "/orgs/acme/projects/pay/secrets/hmac", "read"):
                return False, "Historical snapshot leaked post-snapshot ACL grant after commit"
            if snap_after.get("/orgs/acme/projects/pay/secrets/hmac", principal=alice) != b"hmac-v1":
                return False, "Post-commit snapshot failed to see committed secret and grant"
            if snap_after.get("/orgs/acme/projects/pay/secrets/rot", principal=alice) != b"rot-v1":
                return False, "Post-commit snapshot missing write from released savepoint sp1"
            snap_before.close()
            snap_after.close()

            # Post-commit enforcement: rolled-back sp2 grants MUST NOT be active
            if eng.check_access(bob, "/orgs/acme/projects/pay/secrets/hmac", "read"):
                return False, "Rolled-back savepoint grant for bob remained active after outer commit"
            if eng.check_access(alice, "/orgs/acme/public/readme", "write"):
                return False, "Rolled-back savepoint grant on shared subject bucket remained active after commit"
            try:
                eng.get("/orgs/acme/projects/pay/secrets/hmac", principal=bob)
                return False, "bob read secret using rolled-back savepoint grant"
            except AccessDeniedError:
                pass
            try:
                eng.put("/orgs/acme/public/readme", b"tamper", principal=alice)
                return False, "alice wrote to /orgs/acme/public using rolled-back savepoint grant"
            except AccessDeniedError:
                pass

            # Full ABORT on existing (subject, prefix) and (role, prefix) buckets
            tx_ab = eng.begin(principal=iam_admin)
            tx_ab.set_policy(
                "alice-pub-abort",
                prefix="/orgs/acme/public",
                permissions=["write", "delete"],
                subject="alice",
            )
            tx_ab.set_policy(
                "pay-eng-abort-del",
                prefix="/orgs/acme/projects/pay",
                permissions=["delete", "grant"],
                role="pay-eng",
            )
            if not tx_ab.check_access(alice, "/orgs/acme/public/readme", "write"):
                return False, "Expected intra-tx grant visibility before abort"
            tx_ab.abort()

            if eng.check_access(alice, "/orgs/acme/public/readme", "write"):
                return False, "Aborted grant on existing subject bucket remained active in ACL cache"
            if eng.check_access(alice, "/orgs/acme/projects/pay/secrets/hmac", "delete"):
                return False, "Aborted grant on existing role bucket remained active in ACL cache"
            if eng.get("/orgs/acme/public/readme", principal=alice) != b"hello":
                return False, "Pre-existing read grant was lost after transaction abort"

            # Deny policy removal inside rolled-back savepoint must preserve deny enforcement
            eng.grant_policy(
                "pay-locked-deny",
                prefix="/orgs/acme/projects/pay/locked",
                permissions=["write"],
                role="pay-eng",
                effect="deny",
            )
            tx_deny = eng.begin(principal=iam_admin)
            tx_deny.savepoint("sp_deny")
            tx_deny.remove_policy("pay-locked-deny")
            tx_deny.put("/orgs/acme/projects/pay/locked/k", b"temp", principal=alice)
            tx_deny.rollback_to("sp_deny")
            tx_deny.commit()

            if eng.check_access(alice, "/orgs/acme/projects/pay/locked/k", "write"):
                return False, "Deny rule removed inside rolled-back savepoint was not restored"

    return True, "ACL savepoint/abort consistency verified"


def _verify_wal_integrity_and_recovery(kv: ModuleType) -> tuple[bool, str]:
    Engine = kv.Engine
    Principal = kv.Principal
    WALError = kv.WALError

    bob = Principal.user("bob")

    # Part 1: Value-byte corruption inside WAL frame payload must NOT load silently
    with tempfile.TemporaryDirectory() as tmp_str:
        wal_dir = Path(tmp_str) / "wal_crc"
        target_secret = b"vkv-super-secret-value-payload-987654"
        tampered_secret = b"vkv-super-secret-value-payload-087654"

        with Engine.open(wal_dir) as eng:
            eng.put("/orgs/acme/secrets/first", b"intact-first")
            eng.put("/orgs/acme/secrets/target", target_secret)

        wal_path = wal_dir / "wal.log"
        raw_wal = bytearray(wal_path.read_bytes())
        pos = raw_wal.find(target_secret)
        if pos < 0:
            return False, "Expected committed value payload inside wal.log"
        raw_wal[pos : pos + len(target_secret)] = tampered_secret
        wal_path.write_bytes(bytes(raw_wal))

        corrupted_detected = False
        try:
            with Engine.open(wal_dir) as reopened:
                loaded_val = reopened.get("/orgs/acme/secrets/target")
                if loaded_val == tampered_secret or loaded_val is not None:
                    return False, "Engine silently loaded WAL record with corrupted value bytes"
                corrupted_detected = True
        except (WALError, ValueError):
            corrupted_detected = True

        if not corrupted_detected:
            return False, "WAL value-byte corruption was not detected during recovery"

    # Part 2: Interleaved uncommitted tx + committed tx with savepoints + torn EOF frame
    with tempfile.TemporaryDirectory() as tmp_str:
        rec_dir = Path(tmp_str) / "wal_recover"
        eng = Engine.open(rec_dir)
        try:
            eng.put("/orgs/acme/secrets/base", b"v0")

            # tx1 starts and writes uncommitted data + uncommitted ACL policy, never commits
            tx1 = eng.begin()
            tx1.put("/orgs/acme/secrets/uncommitted_tx1", b"phantom-data")
            tx1.set_policy(
                "uncommitted-bob-grant",
                prefix="/orgs/acme",
                permissions=["read", "write"],
                subject="bob",
            )

            # tx2 interleaves, uses savepoints, and commits cleanly
            tx2 = eng.begin()
            tx2.put("/orgs/acme/secrets/tx2_main", b"committed-main")
            tx2.savepoint("sp_keep")
            tx2.put("/orgs/acme/secrets/tx2_kept", b"committed-kept")
            tx2.release_savepoint("sp_keep")
            tx2.savepoint("sp_drop")
            tx2.put("/orgs/acme/secrets/tx2_dropped", b"rolled-back")
            tx2.rollback_to("sp_drop")
            tx2.commit()
            committed_tx2_id = tx2.tx_id

            # tx3 writes a record that will be torn at EOF without committing
            tx3 = eng.begin()
            tx3.put("/orgs/acme/secrets/tx3_torn", b"torn-tail-record-bytes-xyz")
        finally:
            eng.close()

        wal_path = rec_dir / "wal.log"
        orig_size = wal_path.stat().st_size
        with open(wal_path, "r+b") as wf:
            wf.truncate(orig_size - 6)

        with Engine.open(rec_dir) as eng2:
            if eng2.get("/orgs/acme/secrets/base") != b"v0":
                return False, "Baseline committed key missing after torn-tail WAL recovery"
            if eng2.get("/orgs/acme/secrets/tx2_main") != b"committed-main":
                return False, "Committed tx2 key missing after interleaved WAL recovery"
            if eng2.get("/orgs/acme/secrets/tx2_kept") != b"committed-kept":
                return False, "Released savepoint key in tx2 missing after WAL recovery"
            if eng2.get("/orgs/acme/secrets/tx2_dropped") is not None:
                return False, "Savepoint-rolled-back key in tx2 materialized after WAL recovery"
            if eng2.get("/orgs/acme/secrets/uncommitted_tx1") is not None:
                return False, "Uncommitted interleaved tx1 record materialized after WAL recovery"
            if eng2.check_access(bob, "/orgs/acme/secrets/base", "read"):
                return False, "Uncommitted interleaved tx1 ACL grant materialized after WAL recovery"
            if eng2.get("/orgs/acme/secrets/tx3_torn") is not None:
                return False, "Torn uncommitted tail transaction materialized after WAL recovery"

            tx4 = eng2.begin()
            if tx4.tx_id <= committed_tx2_id:
                tx4.abort()
                return False, f"Recovered next_tx_id={tx4.tx_id} collided with committed tx_id={committed_tx2_id}"
            tx4.put("/orgs/acme/secrets/post_recover", b"v4-durable")
            tx4.commit()

        # Verify strictly monotonic LSNs across all frames on disk after recovery + new writes
        raw_bytes = wal_path.read_bytes()
        pos = 20
        frame_lsns: list[int] = []
        meta_struct = struct.Struct(">BQQQII")
        while pos + 37 <= len(raw_bytes):
            _rtype, lsn, _txid, _ts, klen, vlen = meta_struct.unpack_from(raw_bytes, pos)
            frame_end = pos + 37 + klen + vlen
            if frame_end > len(raw_bytes):
                return False, "Untruncated partial frame remained in wal.log after recovery"
            frame_lsns.append(lsn)
            pos = frame_end
        if pos != len(raw_bytes):
            return False, "Trailing garbage bytes remained in wal.log after recovery"
        if not frame_lsns or any(a >= b for a, b in zip(frame_lsns, frame_lsns[1:])):
            return False, f"Non-monotonic LSN sequence in wal.log after recovery: {frame_lsns}"

        with Engine.open(rec_dir) as eng3:
            if eng3.get("/orgs/acme/secrets/post_recover") != b"v4-durable":
                return False, "Post-recovery transaction failed to persist across subsequent reopen"
            if eng3.get("/orgs/acme/secrets/uncommitted_tx1") is not None:
                return False, "Uncommitted record reappeared on second reopen"

    return True, "WAL checksum and per-transaction recovery verified"


def _verify_mvcc_compaction_and_tombstones(kv: ModuleType) -> tuple[bool, str]:
    Engine = kv.Engine
    Principal = kv.Principal
    AccessDeniedError = kv.AccessDeniedError

    bob = Principal.user("bob")

    # Scenario A: Tombstone older than watermark must NOT uncover shadowed older live versions
    with tempfile.TemporaryDirectory() as tmp_str:
        comp_dir = Path(tmp_str) / "mvcc_compact"
        with Engine.open(comp_dir) as eng:
            eng.put("/orgs/acme/secrets/permanently_gone", b"stale-secret-v1")
            eng.put("/orgs/acme/secrets/recreated", b"old-secret-v1")
            eng.grant_policy("bob-temp", prefix="/orgs/acme/secrets", permissions=["read"], subject="bob")

            eng.delete("/orgs/acme/secrets/permanently_gone")
            eng.delete("/orgs/acme/secrets/recreated")
            eng.revoke_policy("bob-temp")

            eng.put("/orgs/acme/secrets/active", b"live-v1")
            snap_mid = eng.snapshot()

            eng.put("/orgs/acme/secrets/recreated", b"new-secret-v2")
            eng.checkpoint()

            # Historical snapshot at watermark (where both keys & grant were deleted)
            if snap_mid.get("/orgs/acme/secrets/permanently_gone") is not None:
                return False, "Checkpoint resurrected deleted key in historical snapshot"
            if snap_mid.get("/orgs/acme/secrets/recreated") is not None:
                return False, "Checkpoint uncovered pre-delete version beneath tombstone for historical snapshot"
            if snap_mid.check_access(bob, "/orgs/acme/secrets/active", "read"):
                return False, "Checkpoint resurrected revoked ACL policy in historical snapshot"
            if snap_mid.get("/orgs/acme/secrets/active") != b"live-v1":
                return False, "Historical snapshot lost live key during checkpoint"

            # Current state checks
            if eng.get("/orgs/acme/secrets/permanently_gone") is not None:
                return False, "Checkpoint resurrected permanently deleted key in live MVCC store"
            if eng.get("/orgs/acme/secrets/recreated") != b"new-secret-v2":
                return False, "Checkpoint corrupted recreated key version chain"
            if eng.check_access(bob, "/orgs/acme/secrets/active", "read"):
                return False, "Checkpoint resurrected revoked ACL policy in live engine"

            snap_mid.close()
            eng.checkpoint()

            if eng.get("/orgs/acme/secrets/permanently_gone") is not None:
                return False, "Second checkpoint resurrected permanently deleted key"
            try:
                eng.get("/orgs/acme/secrets/active", principal=bob)
                return False, "bob accessed secret after revoked policy compaction"
            except AccessDeniedError:
                pass

        with Engine.open(comp_dir) as reopened:
            if reopened.get("/orgs/acme/secrets/permanently_gone") is not None:
                return False, "Post-checkpoint reopen resurrected deleted secret"
            if reopened.get("/orgs/acme/secrets/recreated") != b"new-secret-v2":
                return False, "Post-checkpoint reopen returned wrong value for recreated key"
            if reopened.get("/orgs/acme/secrets/active") != b"live-v1":
                return False, "Post-checkpoint reopen lost live key"
            if reopened.check_access(bob, "/orgs/acme/secrets/active", "read"):
                return False, "Post-checkpoint reopen resurrected revoked ACL policy"

    # Scenario B: Active snapshot predating a delete must still read pre-delete version across checkpoint
    with tempfile.TemporaryDirectory() as tmp_str:
        pin_dir = Path(tmp_str) / "mvcc_pinned"
        with Engine.open(pin_dir) as eng:
            eng.put("/orgs/acme/secrets/pinned", b"before-del")
            snap_early = eng.snapshot()
            eng.delete("/orgs/acme/secrets/pinned")
            eng.put("/orgs/acme/secrets/keeper", b"stay")
            eng.checkpoint()

            if snap_early.get("/orgs/acme/secrets/pinned") != b"before-del":
                return False, "Active pre-delete snapshot lost visibility during checkpoint"
            if eng.get("/orgs/acme/secrets/pinned") is not None:
                return False, "Live engine still sees deleted key after checkpoint"
            snap_early.close()

        with Engine.open(pin_dir) as reopened2:
            if reopened2.get("/orgs/acme/secrets/pinned") is not None:
                return False, "Deleted key persisted as live in checkpoint image when early snapshot was open"
            if reopened2.get("/orgs/acme/secrets/keeper") != b"stay":
                return False, "Keeper key missing after reopen"

    return True, "MVCC tombstone compaction and snapshot retention verified"


def check_runtime_policy(app_dir: Path) -> tuple[bool, str]:
    with loaded_kvstore(app_dir) as kv:
        required = (
            "Engine",
            "Transaction",
            "Snapshot",
            "ACLIndex",
            "MVCCStore",
            "WAL",
            "Principal",
            "AccessDeniedError",
            "WriteConflictError",
            "TransactionStateError",
            "WALError",
            "WALCorruptionError",
        )
        missing = [sym for sym in required if not hasattr(kv, sym)]
        if missing:
            return False, f"Missing required public symbols in kvstore: {missing}"

        for check_fn in (
            _verify_acl_savepoints_and_isolation,
            _verify_wal_integrity_and_recovery,
            _verify_mvcc_compaction_and_tombstones,
        ):
            ok, msg = check_fn(kv)
            if not ok:
                return False, msg

    return True, "All ACL, WAL, MVCC, savepoint, and snapshot runtime checks passed"


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    ok_suite, msg_suite = check_regression_suite(app_dir, tests_dir / "orig_app")
    results["regression_suite"] = {"passed": ok_suite, "message": msg_suite}
    if not ok_suite:
        return False, results

    ok_pol, msg_pol = check_runtime_policy(app_dir)
    results["runtime_policy"] = {"passed": ok_pol, "message": msg_pol}
    if not ok_pol:
        return False, results

    return True, results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    tests_dir = Path(__file__).resolve().parent
    reward_dir = Path(args.reward_dir)
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, tests_dir)
    (reward_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
