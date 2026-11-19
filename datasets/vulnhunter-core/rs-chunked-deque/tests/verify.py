#!/usr/bin/env python3
"""Deterministic verifier for task: rs-chunked-deque."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE_FILES = {"raw_chunk.rs", "deque.rs", "drain.rs", "iter.rs"}

HIDDEN_RUST_SUITE = r"""
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chunked_deque::raw_chunk::live_chunk_allocations;
use chunked_deque::{wire, ChunkedDeque};

const VALID_MAGIC: u64 = 0xCAFE_BABE_5A17_900D;

struct AuditState {
    drop_counts: Vec<AtomicUsize>,
    corrupt_magic_drops: AtomicUsize,
    clone_calls: AtomicUsize,
    panic_on_clone_call: usize,
}

impl AuditState {
    fn new(max_ids: usize, panic_on_clone_call: usize) -> Arc<Self> {
        let mut drop_counts = Vec::with_capacity(max_ids);
        for _ in 0..max_ids {
            drop_counts.push(AtomicUsize::new(0));
        }
        Arc::new(Self {
            drop_counts,
            corrupt_magic_drops: AtomicUsize::new(0),
            clone_calls: AtomicUsize::new(0),
            panic_on_clone_call,
        })
    }
}

struct TrackedItem {
    magic: u64,
    id: usize,
    panic_on_drop: bool,
    state: Arc<AuditState>,
}

impl TrackedItem {
    fn new(id: usize, panic_on_drop: bool, state: &Arc<AuditState>) -> Self {
        Self {
            magic: VALID_MAGIC,
            id,
            panic_on_drop,
            state: Arc::clone(state),
        }
    }
}

impl Clone for TrackedItem {
    fn clone(&self) -> Self {
        assert_eq!(self.magic, VALID_MAGIC, "cloned from uninitialized TrackedItem");
        let n = self.state.clone_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.state.panic_on_clone_call > 0 && n == self.state.panic_on_clone_call {
            panic!("scheduled clone panic at call {n}");
        }
        // Assign slot id `100 + n` to cloned copies so each instance has a unique lifecycle slot.
        Self {
            magic: VALID_MAGIC,
            id: 100 + n,
            panic_on_drop: false,
            state: Arc::clone(&self.state),
        }
    }
}

impl Drop for TrackedItem {
    fn drop(&mut self) {
        if self.magic != VALID_MAGIC {
            self.state.corrupt_magic_drops.fetch_add(1, Ordering::SeqCst);
            return;
        }
        // Poison magic on drop so any second drop on the same slot is caught as corrupt/double drop!
        self.magic = 0xDEAD_DEAD_DEAD_DEAD;
        if self.id < self.state.drop_counts.len() {
            self.state.drop_counts[self.id].fetch_add(1, Ordering::SeqCst);
        }
        if self.panic_on_drop && !std::thread::panicking() {
            panic!("scheduled destructor panic for id {}", self.id);
        }
    }
}

#[test]
fn v1_segmented_architecture_and_functional_parity() {
    let base_live = live_chunk_allocations();
    {
        let mut dq = ChunkedDeque::with_chunk_capacity(4);
        for i in 0..18i64 {
            dq.push_back(i * 10);
        }
        let st = dq.stats();
        assert_eq!(st.total_len, 18);
        assert_eq!(st.chunk_capacity, 4);
        assert_eq!(st.chunk_count, 5, "must maintain segmented chunks of capacity 4");
        assert!(live_chunk_allocations() >= base_live + 5);

        dq.push_front(-10);
        dq.insert(5, 999);
        assert_eq!(dq.remove(5), Some(999));
        assert_eq!(dq.pop_front(), Some(-10));

        let mut cur = dq.cursor();
        let mut flat = Vec::new();
        while let Some(sl) = cur.next_contiguous_slice() {
            flat.extend_from_slice(sl);
        }
        assert_eq!(flat, (0..18i64).map(|x| x * 10).collect::<Vec<_>>());

        dq.compact();
        assert_eq!(dq.chunk_count(), 5);

        let mut bytes_dq = ChunkedDeque::with_chunk_capacity(3);
        for b in 0..8u8 {
            bytes_dq.push_back(vec![b, b ^ 0x55, b.wrapping_add(7)]);
        }
        let raw = wire::encode_records(&bytes_dq);
        let restored = wire::decode_records(&raw).expect("wire roundtrip");
        assert_eq!(restored, bytes_dq);
    }
    assert_eq!(live_chunk_allocations(), base_live, "all heap chunks must be freed on drop");
}

#[test]
fn v2_into_iter_and_clear_drop_panic_no_double_drop() {
    // Part A: IntoIter::drop unwinds when element 4 panics
    let state = AuditState::new(32, 0);
    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    for id in 0..11 {
        dq.push_back(TrackedItem::new(id, id == 4, &state));
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        let mut it = dq.into_iter();
        assert_eq!(it.next().unwrap().id, 0);
        assert_eq!(it.next_back().unwrap().id, 10);
        // Dropping `it` here drops remaining items 1..=9; id=4 panics!
    }));
    assert!(res.is_err(), "expected panic from id=4 destructor");
    assert_eq!(
        state.corrupt_magic_drops.load(Ordering::SeqCst),
        0,
        "detected double-drop or uninitialized drop during IntoIter unwind"
    );
    for id in 0..11 {
        assert_eq!(
            state.drop_counts[id].load(Ordering::SeqCst),
            1,
            "item {id} must be dropped exactly once across IntoIter unwind"
        );
    }

    // Part B: ChunkedDeque::clear() unwinds when element 5 panics, then `dq2` itself is dropped
    let state2 = AuditState::new(32, 0);
    let mut dq2 = ChunkedDeque::with_chunk_capacity(4);
    for id in 0..10 {
        dq2.push_back(TrackedItem::new(id, id == 5, &state2));
    }
    let res2 = catch_unwind(AssertUnwindSafe(|| {
        dq2.clear();
    }));
    assert!(res2.is_err(), "expected panic during clear()");
    drop(dq2);
    assert_eq!(
        state2.corrupt_magic_drops.load(Ordering::SeqCst),
        0,
        "detected double-drop when dropping deque after panicking clear()"
    );
    for id in 0..10 {
        assert_eq!(
            state2.drop_counts[id].load(Ordering::SeqCst),
            1,
            "item {id} must be dropped exactly once across clear() unwind + deque drop"
        );
    }
}

#[test]
fn v3_drain_panic_unwind_and_mem_forget_soundness() {
    // Part A: Drain::drop unwinds when an unconsumed drained element's Drop panics
    let state = AuditState::new(32, 0);
    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    for id in 0..14 {
        dq.push_back(TrackedItem::new(id, id == 6, &state));
    }
    let res = catch_unwind(AssertUnwindSafe(|| {
        let mut d = dq.drain(3..10);
        assert_eq!(d.next().unwrap().id, 3);
        // Remaining drained 4..10 dropped when `d` drops; id=6 panics!
    }));
    assert!(res.is_err(), "expected destructor panic inside Drain::drop");
    assert_eq!(
        dq.len(),
        dq.iter().count(),
        "deque len metadata out of sync with chunks after Drain panic"
    );
    drop(dq);
    assert_eq!(
        state.corrupt_magic_drops.load(Ordering::SeqCst),
        0,
        "detected double-drop or uninitialized drop after Drain::drop panic"
    );
    for id in 0..14 {
        assert_eq!(
            state.drop_counts[id].load(Ordering::SeqCst),
            1,
            "item {id} must be dropped exactly once across Drain unwind + parent drop"
        );
    }

    // Part B: Safe caller calls std::mem::forget(drain)
    let state_forget = AuditState::new(32, 0);
    let mut dq_forget = ChunkedDeque::with_chunk_capacity(4);
    for id in 0..10 {
        dq_forget.push_back(TrackedItem::new(id, false, &state_forget));
    }
    let mut d = dq_forget.drain(2..7);
    assert_eq!(d.next().unwrap().id, 2);
    std::mem::forget(d);
    // `dq_forget` must still be 100% memory-safe to read and drop without double-dropping id=2!
    let surviving_ids: Vec<usize> = dq_forget.iter().map(|x| x.id).collect();
    assert!(surviving_ids.iter().all(|&id| id < 2 || id >= 7));
    drop(dq_forget);
    assert_eq!(
        state_forget.corrupt_magic_drops.load(Ordering::SeqCst),
        0,
        "mem::forget(Drain) caused double-drop or uninitialized drop on parent ChunkedDeque"
    );
    assert_eq!(state_forget.drop_counts[2].load(Ordering::SeqCst), 1);
}

#[test]
fn v4_extend_from_slice_and_clone_panic_no_uninit_drop() {
    let state = AuditState::new(256, 6);
    let mut source = Vec::new();
    for id in 0..10 {
        source.push(TrackedItem::new(id, false, &state));
    }

    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    // Pre-populate 2 items so extend_from_slice partially fills chunk 0 (2 slots),
    // fills chunk 1, and panics mid-clone on the 6th clone call!
    dq.push_back(TrackedItem::new(50, false, &state));
    dq.push_back(TrackedItem::new(51, false, &state));

    let res = catch_unwind(AssertUnwindSafe(|| {
        dq.extend_from_slice(&source);
    }));
    assert!(res.is_err(), "expected scheduled panic on 6th clone");
    assert_eq!(
        dq.len(),
        dq.iter().count(),
        "total_len desynchronized after panicking extend_from_slice"
    );
    assert_eq!(dq.len(), 7, "2 initial + 5 succeeded clones must remain intact");

    drop(dq);
    drop(source);

    assert_eq!(
        state.corrupt_magic_drops.load(Ordering::SeqCst),
        0,
        "extend_from_slice dropped uninitialized 0xA5 slots during panic unwind!"
    );
    for id in 0..10 {
        assert_eq!(state.drop_counts[id].load(Ordering::SeqCst), 1);
    }
    for clone_num in 1..=5 {
        assert_eq!(
            state.drop_counts[100 + clone_num].load(Ordering::SeqCst),
            1,
            "succeeded clone #{clone_num} must be dropped exactly once"
        );
    }
}

#[test]
fn v5_zst_and_wrapped_ring_split_off() {
    // Part A: Zero-Sized Types (default constructor + all operations + zero heap allocs)
    static ZST_CREATED: AtomicUsize = AtomicUsize::new(0);
    static ZST_DROPS: AtomicUsize = AtomicUsize::new(0);
    #[derive(Debug, PartialEq, Eq)]
    struct ZstToken(());
    impl ZstToken {
        fn make() -> Self {
            ZST_CREATED.fetch_add(1, Ordering::SeqCst);
            ZstToken(())
        }
    }
    impl Clone for ZstToken {
        fn clone(&self) -> Self {
            Self::make()
        }
    }
    impl Drop for ZstToken {
        fn drop(&mut self) {
            ZST_DROPS.fetch_add(1, Ordering::SeqCst);
        }
    }

    ZST_CREATED.store(0, Ordering::SeqCst);
    ZST_DROPS.store(0, Ordering::SeqCst);
    let alloc_before = live_chunk_allocations();
    {
        let mut zdq = ChunkedDeque::<ZstToken>::new();
        for _ in 0..70 {
            zdq.push_back(ZstToken::make());
        }
        zdq.push_front(ZstToken::make());
        assert_eq!(zdq.pop_front(), Some(ZstToken::make()));
        assert_eq!(zdq.pop_back(), Some(ZstToken::make()));
        let zright = zdq.split_off(30);
        assert_eq!(zdq.len(), 30);
        assert_eq!(zright.len(), 39);
        for tok in zdq.iter_mut() {
            *tok = ZstToken::make();
        }
        let _ = zdq.drain(5..15).collect::<Vec<_>>();
    }
    assert_eq!(
        live_chunk_allocations(),
        alloc_before,
        "ZST chunks must not leak or allocate zero-sized heap blocks"
    );
    assert_eq!(ZST_DROPS.load(Ordering::SeqCst), ZST_CREATED.load(Ordering::SeqCst));

    // Part B: Wrapped-ring `split_off` with TrackedItem (catches non-modular base_ptr copy!)
    let state = AuditState::new(64, 0);
    let mut wdq = ChunkedDeque::with_chunk_capacity(4);
    for id in 0..4 {
        wdq.push_back(TrackedItem::new(id, false, &state));
    }
    // Advance head to 2 in chunk 0
    assert_eq!(wdq.pop_front().unwrap().id, 0);
    assert_eq!(wdq.pop_front().unwrap().id, 1);
    // Wrap around physical end of chunk 0 and spill into chunk 1
    for id in 4..10 {
        wdq.push_back(TrackedItem::new(id, false, &state));
    }
    // Logical contents: [2, 3, 4, 5] (chunk 0 with head=2!) ++ [6, 7, 8, 9] (chunk 1)
    let right = wdq.split_off(2);
    let left_ids: Vec<usize> = wdq.iter().map(|x| x.id).collect();
    let right_ids: Vec<usize> = right.iter().map(|x| x.id).collect();
    assert_eq!(left_ids, vec![2, 3], "wrapped split_off corrupted left half");
    assert_eq!(right_ids, vec![4, 5, 6, 7, 8, 9], "wrapped split_off corrupted right half");

    drop(wdq);
    drop(right);
    assert_eq!(
        state.corrupt_magic_drops.load(Ordering::SeqCst),
        0,
        "wrapped split_off read uninitialized slots or duplicated elements!"
    );
    for id in 0..10 {
        assert_eq!(state.drop_counts[id].load(Ordering::SeqCst), 1);
    }
}
"""


def cargo_env() -> dict[str, str]:
    env = os.environ.copy()
    cargo_bin = Path.home() / ".cargo" / "bin"
    if cargo_bin.is_dir():
        env["PATH"] = f"{cargo_bin}:{env.get('PATH', '')}"
    return env


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    raw_blobs: list[str] = []
    for key in ("files", "file"):
        val = data.get(key)
        if isinstance(val, str):
            raw_blobs.append(val)
        elif isinstance(val, list):
            raw_blobs.extend(json.dumps(x) if isinstance(x, dict) else str(x) for x in val)

    findings = data.get("findings")
    if isinstance(findings, list):
        for item in findings:
            raw_blobs.append(json.dumps(item) if isinstance(item, dict) else str(item))

    mentioned = {
        Path(tok).name
        for blob in raw_blobs
        for tok in re.findall(r"[\w./-]+\.rs", blob)
    }
    matched_core = mentioned & CORE_FILES
    if len(matched_core) < 2:
        return False, f"Expected report.json to reference at least 2 core crate files from {sorted(CORE_FILES)}, got {sorted(mentioned)}"

    if not isinstance(findings, list) or len(findings) < 2:
        return False, "Expected at least 2 findings in report.json"
    for entry in findings:
        txt = json.dumps(entry) if isinstance(entry, dict) else str(entry)
        if len(txt.strip()) < 15:
            return False, f"Finding entry too brief: {txt!r}"

    return True, f"Report validated (covered {sorted(matched_core)})"


def check_architecture_not_bypassed(app_dir: Path) -> tuple[bool, str]:
    raw_chunk = app_dir / "src" / "raw_chunk.rs"
    deque_rs = app_dir / "src" / "deque.rs"
    if not raw_chunk.is_file() or not deque_rs.is_file():
        return False, "Missing src/raw_chunk.rs or src/deque.rs"
    rc_txt = raw_chunk.read_text(encoding="utf-8", errors="replace")
    dq_txt = deque_rs.read_text(encoding="utf-8", errors="replace")
    if "alloc" not in rc_txt or "dealloc" not in rc_txt:
        return False, "src/raw_chunk.rs must retain manual chunk allocation (alloc/dealloc)"
    if "VecDeque" in dq_txt:
        return False, "ChunkedDeque in src/deque.rs must use RawChunk segments rather than wrapping VecDeque"
    return True, "Segmented RawChunk architecture preserved"


def run_cargo_test(work_dir: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["cargo", "test", "--offline", "--manifest-path", str(work_dir / "Cargo.toml")]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=cargo_env(),
        timeout=120,
    )


def verify(app_dir: Path, orig_dir: Path) -> tuple[bool, dict]:
    details: dict = {}

    ok_rep, msg_rep = check_report(app_dir)
    details["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, details

    ok_arch, msg_arch = check_architecture_not_bypassed(app_dir)
    details["architecture"] = {"passed": ok_arch, "message": msg_arch}
    if not ok_arch:
        return False, details

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        # 1. Run agent's own crate + test suite in isolated copy
        patched_copy = tmp / "patched_app"
        shutil.copytree(app_dir, patched_copy, ignore=shutil.ignore_patterns("target"))
        agent_run = run_cargo_test(patched_copy)
        if agent_run.returncode != 0:
            details["agent_tests"] = {
                "passed": False,
                "message": f"cargo test --offline failed on /app:\n{(agent_run.stdout + agent_run.stderr)[-1200:]}",
            }
            return False, details

        # 2. Verify agent added regression tests that fail on original unmodified code
        orig_with_agent_tests = tmp / "orig_check"
        shutil.copytree(orig_dir, orig_with_agent_tests, ignore=shutil.ignore_patterns("target"))
        if (patched_copy / "tests").is_dir():
            shutil.rmtree(orig_with_agent_tests / "tests", ignore_errors=True)
            shutil.copytree(patched_copy / "tests", orig_with_agent_tests / "tests")
        orig_run = run_cargo_test(orig_with_agent_tests)
        if orig_run.returncode == 0:
            details["agent_tests"] = {
                "passed": False,
                "message": "Agent test suite in /app/tests passed on unmodified original code (missing regression coverage)",
            }
            return False, details
        details["agent_tests"] = {
            "passed": True,
            "message": "Agent test suite passes on updated code and fails on original unmodified code",
        }

        # 3. Inject hidden deterministic verifier soundness suite and run all 5 test groups
        suite_path = patched_copy / "tests" / "vh_hidden_soundness.rs"
        suite_path.parent.mkdir(parents=True, exist_ok=True)
        suite_path.write_text(HIDDEN_RUST_SUITE, encoding="utf-8")
        hidden_run = run_cargo_test(patched_copy, ["--test", "vh_hidden_soundness", "--", "--test-threads=1"])
        if hidden_run.returncode != 0:
            details["soundness_suite"] = {
                "passed": False,
                "message": f"Hidden soundness suite failed:\n{(hidden_run.stdout + hidden_run.stderr)[-1800:]}",
            }
            return False, details

        details["soundness_suite"] = {
            "passed": True,
            "message": "All 5 hidden lifecycle, unwind, ZST, mem::forget, and wrapped split_off checks passed",
        }

    return True, details


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    reward_dir = Path(args.reward_dir).resolve()
    orig_dir = Path(__file__).resolve().parent / "orig_app"
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, orig_dir)
    out = {"passed": passed, "details": details}
    (reward_dir / "details.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
