#!/usr/bin/env python3
"""Deterministic verifier for task: rs-mvcc-ssi-engine."""

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
import tomllib

CORE_FILES = {"version_store.rs", "predicate.rs", "ssi.rs", "txn.rs", "gc.rs"}

HIDDEN_RUST_SUITE = r"""
use std::collections::BTreeMap;
use std::ops::Bound;

use mvcc_ssi::{
    IsolationError, Key, SavepointId, ScheduleStep, SeqNo, SsiEngine, StepResult, TxId, TxStatus,
    Value,
};

#[test]
fn h1_serializable_workloads_no_false_positives() {
    // 1. Disjoint concurrent read-write transactions must all commit
    let mut eng = SsiEngine::new();
    let seed = eng.begin();
    for i in 0..6u8 {
        eng.put(seed, [b'p', b':', b'0' + i], [b'0']).unwrap();
    }
    eng.commit(seed).unwrap();

    let mut txs = Vec::new();
    for i in 0..6u8 {
        let tx = eng.begin();
        let k = [b'p', b':', b'0' + i];
        assert_eq!(eng.get(tx, k).unwrap(), Some(vec![b'0']));
        eng.put(tx, k, [b'1' + i]).unwrap();
        txs.push(tx);
    }
    for tx in txs {
        eng.commit(tx).expect("disjoint concurrent rw transactions must commit");
    }

    // 2. Concurrent read-only snapshots under heavy writes + vacuum must not false-abort
    let mut eng2 = SsiEngine::new();
    let s0 = eng2.begin();
    eng2.put(s0, b"x", b"0").unwrap();
    eng2.put(s0, b"y", b"0").unwrap();
    eng2.commit(s0).unwrap();

    // t_ro, t_piv, t_out share the same initial snapshot (serializable as t_ro -> t_piv -> t_out)
    let t_ro = eng2.begin();
    let t_piv = eng2.begin();
    let t_out = eng2.begin();

    assert_eq!(eng2.get(t_piv, b"y").unwrap(), Some(b"0".to_vec()));
    eng2.put(t_out, b"y", b"1").unwrap();
    eng2.commit(t_out).unwrap();

    eng2.put(t_piv, b"x", b"1").unwrap();
    eng2.commit(t_piv).unwrap();

    let _ = eng2.vacuum();
    assert_eq!(eng2.get(t_ro, b"x").unwrap(), Some(b"0".to_vec()));
    assert_eq!(eng2.get(t_ro, b"y").unwrap(), Some(b"0".to_vec()));
    eng2.commit(t_ro)
        .expect("concurrent read-only snapshot preceding all writes must commit cleanly");

    // 3. Valid sequential T1 -> T2 -> T3 chains (non-concurrent SIRead locks must not conflict)
    for step in 1..=5u8 {
        let tx = eng2.begin();
        let xv = eng2.get(tx, b"x").unwrap().unwrap();
        let yv = eng2.get(tx, b"y").unwrap().unwrap();
        assert!(!xv.is_empty() && !yv.is_empty());
        let _ = eng2.scan_range(tx, ..).unwrap();
        eng2.put(tx, b"x", [b'0' + step]).unwrap();
        eng2.put(tx, b"y", [b'a' + step]).unwrap();
        eng2.commit(tx).expect("serial transaction chain must always commit");
    }

    // 4. Rolled-back savepoint uncommitted writes must NOT cause false ww or ssi aborts
    let mut eng3 = SsiEngine::new();
    let init = eng3.begin();
    eng3.put(init, b"x", b"0").unwrap();
    eng3.put(init, b"y", b"0").unwrap();
    eng3.commit(init).unwrap();

    let t1 = eng3.begin();
    let t2 = eng3.begin();

    // T1 reads y=0; T2 reads x=0 and writes y=1 (so T1 --rw--> T2)
    assert_eq!(eng3.get(t1, b"y").unwrap(), Some(b"0".to_vec()));
    assert_eq!(eng3.get(t2, b"x").unwrap(), Some(b"0".to_vec()));
    eng3.put(t2, b"y", b"1").unwrap();

    // T1 enters savepoint and tentatively writes x=99 (which would form T2 --rw--> T1 if committed)
    let sp = eng3.savepoint(t1).unwrap();
    eng3.put(t1, b"x", b"99").unwrap();
    eng3.put(t1, b"hot", b"tentative").unwrap();

    // A concurrent reader also inspects x while x=99 is uncommitted on T1
    let t_peek = eng3.begin();
    assert_eq!(eng3.get(t_peek, b"x").unwrap(), Some(b"0".to_vec()));

    // T1 rolls back savepoint, completely undoing x=99 and hot=tentative
    eng3.rollback_to_savepoint(t1, sp).unwrap();

    // Another writer can now write "hot" without WriteWriteConflict
    let t_hot = eng3.begin();
    eng3.put(t_hot, b"hot", b"committed").expect("rolled-back key lock must be released");
    eng3.commit(t_hot).unwrap();

    // T2 commits y=1, and T1 writes disjoint key z=1 and MUST commit (serial order T1 -> T2)
    eng3.commit(t2).unwrap();
    eng3.commit(t_peek).unwrap();
    eng3.put(t1, b"z", b"1").unwrap();
    eng3.commit(t1)
        .expect("rolled-back tentative write in savepoint must not cause false SerializationFailure");
}

#[test]
fn h2_phantom_range_insert_write_skew_and_bounds() {
    // Part A: Classic phantom write-skew on brand-new keys in half-open range
    let mut eng = SsiEngine::new();
    let t1 = eng.begin();
    let t2 = eng.begin();

    assert!(eng.scan_range(t1, b"dept:eng:"..b"dept:eng;").unwrap().is_empty());
    assert!(eng.scan_range(t2, b"dept:eng:"..b"dept:eng;").unwrap().is_empty());

    eng.put(t1, b"dept:eng:alice", b"oncall").unwrap();
    eng.put(t2, b"dept:eng:bob", b"oncall").unwrap();

    eng.commit(t1).unwrap();
    assert_eq!(
        eng.commit(t2),
        Err(IsolationError::SerializationFailure),
        "concurrent phantom inserts into overlapping empty range must not both commit"
    );
    assert_eq!(
        eng.export_committed_snapshot(),
        vec![(b"dept:eng:alice".to_vec(), b"oncall".to_vec())]
    );

    // Part B: Unbounded upper range (`start..`) phantom insert conflict
    let mut eng_unb = SsiEngine::new();
    let u1 = eng_unb.begin();
    let u2 = eng_unb.begin();
    assert!(eng_unb.scan_range(u1, &b"log:2026:"[..]..).unwrap().is_empty());
    assert!(eng_unb.scan_range(u2, &b"log:2026:"[..]..).unwrap().is_empty());
    eng_unb.put(u1, b"log:2026:001", b"a").unwrap();
    eng_unb.put(u2, b"log:2026:002", b"b").unwrap();
    eng_unb.commit(u1).unwrap();
    assert_eq!(eng_unb.commit(u2), Err(IsolationError::SerializationFailure));

    // Part C: Inclusive upper bound (`..=end`) catches exact endpoint insert
    let mut eng_inc = SsiEngine::new();
    let i1 = eng_inc.begin();
    let i2 = eng_inc.begin();
    assert!(eng_inc.scan_range(i1, ..=&b"cap:max"[..]).unwrap().is_empty());
    assert_eq!(eng_inc.get(i2, b"marker").unwrap(), None);
    eng_inc.put(i1, b"marker", b"1").unwrap();
    eng_inc.put(i2, b"cap:max", b"hit").unwrap();
    eng_inc.commit(i1).unwrap();
    assert_eq!(
        eng_inc.commit(i2),
        Err(IsolationError::SerializationFailure),
        "exact endpoint of inclusive range ..=cap:max must conflict"
    );

    // Part D: Excluded bounds `(Excluded(k0), Excluded(k9))` must NOT falsely conflict at k0 or k9
    let mut eng_exc = SsiEngine::new();
    let e1 = eng_exc.begin();
    let e2 = eng_exc.begin();
    assert!(eng_exc
        .scan_range(
            e1,
            (
                Bound::Excluded(b"m:0".to_vec()),
                Bound::Excluded(b"m:9".to_vec()),
            )
        )
        .unwrap()
        .is_empty());
    assert_eq!(eng_exc.get(e2, b"flag").unwrap(), None);
    eng_exc.put(e1, b"flag", b"set").unwrap();
    eng_exc.put(e2, b"m:0", b"low_boundary").unwrap();
    eng_exc.put(e2, b"m:9", b"high_boundary").unwrap();
    eng_exc.commit(e1).unwrap();
    eng_exc
        .commit(e2)
        .expect("writes on excluded range endpoints m:0 and m:9 must not conflict");
}

#[test]
fn h3_savepoint_branch_write_skew_preserved() {
    // Part A: Point SIRead inside rolled-back savepoint drives outer control-flow write
    let mut eng = SsiEngine::new();
    let t1 = eng.begin();
    let t2 = eng.begin();

    let sp1 = eng.savepoint(t1).unwrap();
    let seen_a = eng.get(t1, b"guard:a").unwrap();
    eng.put(t1, b"scratch:1", b"discard").unwrap();
    eng.rollback_to_savepoint(t1, sp1).unwrap();
    if seen_a.is_none() {
        eng.put(t1, b"guard:b", b"claimed_by_t1").unwrap();
    }

    let sp2 = eng.savepoint(t2).unwrap();
    let seen_b = eng.get(t2, b"guard:b").unwrap();
    eng.put(t2, b"scratch:2", b"discard").unwrap();
    eng.rollback_to_savepoint(t2, sp2).unwrap();
    if seen_b.is_none() {
        eng.put(t2, b"guard:a", b"claimed_by_t2").unwrap();
    }

    eng.commit(t1).unwrap();
    assert_eq!(
        eng.commit(t2),
        Err(IsolationError::SerializationFailure),
        "rolling back savepoint must preserve SIRead locks for outer control-flow branches"
    );
    assert_eq!(
        eng.export_committed_snapshot(),
        vec![(b"guard:b".to_vec(), b"claimed_by_t1".to_vec())]
    );

    // Part B: Range SIRead + outbound write-before-read conflict recorded inside rolled-back savepoint
    let mut eng2 = SsiEngine::new();
    let seed = eng2.begin();
    eng2.put(seed, b"k1", b"0").unwrap();
    eng2.commit(seed).unwrap();

    let r1 = eng2.begin();
    let r2 = eng2.begin();

    assert_eq!(eng2.get(r2, b"k1").unwrap(), Some(b"0".to_vec()));
    eng2.put(r2, b"slot:5", b"new").unwrap();
    eng2.commit(r2).unwrap();

    // r1 scans slot:0..slot:9 inside a savepoint (observing empty snapshot and recording r1 --rw--> r2),
    // then rolls back the savepoint and mutates k1 (forming r2 --rw--> r1).
    let sp = eng2.savepoint(r1).unwrap();
    let rows = eng2.scan_range(r1, b"slot:0"..b"slot:9").unwrap();
    assert!(rows.is_empty());
    eng2.put(r1, b"temp", b"x").unwrap();
    eng2.rollback_to_savepoint(r1, sp).unwrap();

    if rows.is_empty() {
        eng2.put(r1, b"k1", b"1").unwrap();
    }
    assert_eq!(
        eng2.commit(r1),
        Err(IsolationError::SerializationFailure),
        "outbound rw-antidependency recorded inside rolled-back savepoint must survive rollback"
    );
}

#[test]
fn h4_three_tx_dangerous_structure_and_read_only_anomaly_across_vacuum() {
    // Scenario A: Classic 3-tx Cahill dangerous structure (T1 --rw--> T2 --rw--> T3)
    // where T3 commits FIRST, vacuum() runs, and then T2 & T1 attempt to commit.
    let mut eng = SsiEngine::new();
    let seed = eng.begin();
    eng.put(seed, b"x", b"0").unwrap();
    eng.put(seed, b"y", b"0").unwrap();
    eng.put(seed, b"z", b"0").unwrap();
    eng.commit(seed).unwrap();

    let t1 = eng.begin();
    let t2 = eng.begin();
    let t3 = eng.begin();

    assert_eq!(eng.get(t1, b"x").unwrap(), Some(b"0".to_vec()));
    assert_eq!(eng.get(t2, b"y").unwrap(), Some(b"0".to_vec()));
    assert_eq!(eng.get(t3, b"z").unwrap(), Some(b"0".to_vec()));

    // T3 writes y=1 (T2 --rw--> T3) and commits first!
    eng.put(t3, b"y", b"1").unwrap();
    eng.commit(t3).unwrap();

    // Run vacuum while T1 and T2 are still active!
    let _ = eng.vacuum();

    eng.put(t2, b"x", b"1").unwrap(); // T1 --rw--> T2
    eng.put(t1, b"z", b"1").unwrap(); // T3 --rw--> T1

    assert_eq!(
        eng.commit(t2),
        Err(IsolationError::SerializationFailure),
        "pivot T2 must retain committed out-conflict to T3 across vacuum()"
    );
    // With T2 aborted, T3 -> T1 is serializable and T1 must commit cleanly!
    eng.commit(t1).unwrap();

    // Scenario B: T3 commits first, vacuum() runs BEFORE T1 writes z (testing T3 SIRead retention!),
    // T2 commits second, vacuum() runs again, and T1 tries to commit third!
    let mut eng2 = SsiEngine::new();
    let s = eng2.begin();
    eng2.put(s, b"x", b"0").unwrap();
    eng2.put(s, b"y", b"0").unwrap();
    eng2.put(s, b"z", b"0").unwrap();
    eng2.commit(s).unwrap();

    let a1 = eng2.begin();
    let a2 = eng2.begin();
    let a3 = eng2.begin();

    assert_eq!(eng2.get(a3, b"z").unwrap(), Some(b"0".to_vec()));
    eng2.put(a3, b"y", b"1").unwrap();
    eng2.commit(a3).unwrap();

    let _ = eng2.vacuum();

    // Now a2 reads y (0, skipping a3 -> a2 --rw--> a3), writes x=1, and commits (no in_conflict yet!)
    assert_eq!(eng2.get(a2, b"y").unwrap(), Some(b"0".to_vec()));
    eng2.put(a2, b"x", b"1").unwrap();
    eng2.commit(a2).unwrap();

    let _ = eng2.vacuum();

    // Now a1 reads x (0, skipping a2 -> a1 --rw--> a2) and writes z=1 (conflicting with a3's SIRead on z!)
    assert_eq!(eng2.get(a1, b"x").unwrap(), Some(b"0".to_vec()));
    eng2.put(a1, b"z", b"1").unwrap();
    assert_eq!(
        eng2.commit(a1),
        Err(IsolationError::SerializationFailure),
        "3-tx cycle with late reader/writer T1 across intermediate vacuum() passes must abort T1"
    );

    // Scenario C: Read-Only Transaction Anomaly across vacuum() after T3 is eligible for eviction
    let mut eng3 = SsiEngine::new();
    let s3 = eng3.begin();
    eng3.put(s3, b"x", b"0").unwrap();
    eng3.put(s3, b"y", b"0").unwrap();
    eng3.commit(s3).unwrap(); // seq = 1

    let p_piv = eng3.begin(); // snap = 1
    let p_out = eng3.begin(); // snap = 1
    assert_eq!(eng3.get(p_piv, b"y").unwrap(), Some(b"0".to_vec()));
    eng3.put(p_out, b"y", b"1").unwrap();
    eng3.commit(p_out).unwrap(); // seq = 2

    // Read-only transaction begins at snap = 2 (sees p_out's y=1)
    let p_ro = eng3.begin();
    assert_eq!(eng3.get(p_ro, b"y").unwrap(), Some(b"1".to_vec()));

    // Pivot writes x=1 and commits at seq = 3
    eng3.put(p_piv, b"x", b"1").unwrap();
    eng3.commit(p_piv).unwrap(); // seq = 3

    // Vacuum at min_active_snapshot = 2 (reclaims p_out @ 2, keeps p_piv @ 3)
    let _ = eng3.vacuum();

    // p_ro reads x=0 (predating p_piv @ 3) and attempts read-only commit -> non-serializable!
    assert_eq!(eng3.get(p_ro, b"x").unwrap(), Some(b"0".to_vec()));
    assert_eq!(
        eng3.commit(p_ro),
        Err(IsolationError::SerializationFailure),
        "read-only anomaly must be rejected even after T_out (@2) was vacuumed"
    );
}

#[test]
fn h5_mvcc_horizon_tombstones_and_serializability_equivalence_checker() {
    // Part A: Active snapshot S with versions [V1 @ S-1, V2 @ S+2] must NOT lose V1 on vacuum()
    let mut eng = SsiEngine::new();
    let t_v1 = eng.begin();
    eng.put(t_v1, b"acct", b"v1").unwrap();
    eng.commit(t_v1).unwrap(); // seq = 1

    let t_pad = eng.begin();
    eng.put(t_pad, b"pad", b"1").unwrap();
    eng.commit(t_pad).unwrap(); // seq = 2 (S)

    // Active snapshot S = 2
    let t_snap = eng.begin();
    assert_eq!(eng.tx_snapshot(t_snap), Some(SeqNo::new(2)));

    let t_pad2 = eng.begin();
    eng.put(t_pad2, b"pad", b"2").unwrap();
    eng.commit(t_pad2).unwrap(); // seq = 3 (S + 1)

    let t_v2 = eng.begin();
    eng.put(t_v2, b"acct", b"v2").unwrap();
    eng.commit(t_v2).unwrap(); // seq = 4 (S + 2)

    let _ = eng.vacuum();
    assert_eq!(
        eng.get(t_snap, b"acct").unwrap(),
        Some(b"v1".to_vec()),
        "vacuum() pruned V1 @ S-1 even though newer V2 @ S+2 is invisible to active snapshot S!"
    );
    eng.commit(t_snap).unwrap();

    // Part B: Tombstone resurrection checks ([V0 @ S-5, Tombstone @ S-2] and [V0, Tombstone, V2 @ S+1])
    let mut eng_tomb = SsiEngine::new();
    let tv0 = eng_tomb.begin();
    eng_tomb.put(tv0, b"gone", b"resurrected_bug").unwrap();
    eng_tomb.put(tv0, b"reborn", b"old_val").unwrap();
    eng_tomb.commit(tv0).unwrap(); // seq = 1

    let tdel = eng_tomb.begin();
    eng_tomb.delete(tdel, b"gone").unwrap();
    eng_tomb.delete(tdel, b"reborn").unwrap();
    eng_tomb.commit(tdel).unwrap(); // seq = 2

    let t_bump = eng_tomb.begin();
    eng_tomb.put(t_bump, b"keep", b"ok").unwrap();
    eng_tomb.commit(t_bump).unwrap(); // seq = 3

    // Hold snapshot S = 3, then write reborn = "new_val" @ 4 and run vacuum()
    let snap3 = eng_tomb.begin();
    let treborn = eng_tomb.begin();
    eng_tomb.put(treborn, b"reborn", b"new_val").unwrap();
    eng_tomb.commit(treborn).unwrap(); // seq = 4

    let _ = eng_tomb.vacuum();
    assert_eq!(
        eng_tomb.get(snap3, b"gone").unwrap(),
        None,
        "tombstone GC resurrected deleted V0 on key 'gone'"
    );
    assert_eq!(
        eng_tomb.get(snap3, b"reborn").unwrap(),
        None,
        "snapshot S=3 between Tombstone@2 and V2@4 must observe None after vacuum()"
    );
    eng_tomb.commit(snap3).unwrap();

    // Quiescent vacuum must drop 'gone' completely without resurrecting V0
    let _ = eng_tomb.vacuum();
    assert_eq!(
        eng_tomb.export_committed_snapshot(),
        vec![
            (b"keep".to_vec(), b"ok".to_vec()),
            (b"reborn".to_vec(), b"new_val".to_vec()),
        ]
    );

    // Part C: Deterministic Randomized Small-Keyspace Serializability Equivalence Checker
    run_randomized_serializability_checker();
}

#[derive(Clone, Debug)]
enum RecordedOp {
    Get {
        key: Key,
        observed: Option<Value>,
    },
    Scan {
        start: Bound<Key>,
        end: Bound<Key>,
        observed: Vec<(Key, Value)>,
    },
    Put {
        key: Key,
        value: Value,
    },
    Delete {
        key: Key,
    },
    Savepoint {
        sp: SavepointId,
    },
    Rollback {
        sp: SavepointId,
    },
}

fn bound_matches(start: &Bound<Key>, end: &Bound<Key>, k: &[u8]) -> bool {
    let lo = match start {
        Bound::Included(s) => k >= s.as_slice(),
        Bound::Excluded(s) => k > s.as_slice(),
        Bound::Unbounded => true,
    };
    let hi = match end {
        Bound::Included(e) => k <= e.as_slice(),
        Bound::Excluded(e) => k < e.as_slice(),
        Bound::Unbounded => true,
    };
    lo && hi
}

fn replay_tx_serial(state: &mut BTreeMap<Key, Value>, ops: &[RecordedOp]) -> bool {
    let mut sp_snapshots: BTreeMap<SavepointId, BTreeMap<Key, Value>> = BTreeMap::new();
    for op in ops {
        match op {
            RecordedOp::Get { key, observed } => {
                if state.get(key) != observed.as_ref() {
                    return false;
                }
            }
            RecordedOp::Scan {
                start,
                end,
                observed,
            } => {
                let actual: Vec<(Key, Value)> = state
                    .iter()
                    .filter(|(k, _)| bound_matches(start, end, k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if &actual != observed {
                    return false;
                }
            }
            RecordedOp::Put { key, value } => {
                state.insert(key.clone(), value.clone());
            }
            RecordedOp::Delete { key } => {
                state.remove(key);
            }
            RecordedOp::Savepoint { sp } => {
                sp_snapshots.insert(*sp, state.clone());
            }
            RecordedOp::Rollback { sp } => {
                if let Some(saved) = sp_snapshots.get(sp) {
                    *state = saved.clone();
                } else {
                    return false;
                }
            }
        }
    }
    true
}

fn exists_equivalent_serial_order(
    initial: &BTreeMap<Key, Value>,
    committed_traces: &[Vec<RecordedOp>],
    final_snapshot: &[(Key, Value)],
    used: &mut [bool],
    order: &mut Vec<usize>,
) -> bool {
    if order.len() == committed_traces.len() {
        let mut state = initial.clone();
        for &idx in order.iter() {
            if !replay_tx_serial(&mut state, &committed_traces[idx]) {
                return false;
            }
        }
        let expected_final: Vec<(Key, Value)> =
            state.into_iter().collect();
        return expected_final == final_snapshot;
    }

    for i in 0..committed_traces.len() {
        if !used[i] {
            used[i] = true;
            order.push(i);
            if exists_equivalent_serial_order(
                initial,
                committed_traces,
                final_snapshot,
                used,
                order,
            ) {
                return true;
            }
            order.pop();
            used[i] = false;
        }
    }
    false
}

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn gen_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }
}

fn run_randomized_serializability_checker() {
    let keys: Vec<Key> = (0..4u8).map(|i| vec![b'k', b'0' + i]).collect();
    let mut rng = XorShift64(0x5EED_CAFE_2026_7711);
    let mut total_committed = 0usize;

    for sched_id in 0..220usize {
        let mut eng = SsiEngine::new();
        let mut initial_map = BTreeMap::new();

        // Seed 0..=3 initial keys
        let seed_tx = eng.begin();
        for k in &keys {
            if rng.gen_usize(2) == 0 {
                let v = vec![b's', b'0' + (rng.gen_usize(4) as u8)];
                eng.put(seed_tx, k, &v).unwrap();
                initial_map.insert(k.clone(), v);
            }
        }
        eng.commit(seed_tx).unwrap();

        let num_tx = 3 + rng.gen_usize(3); // 3..=5 concurrent transactions
        let mut tx_ids: Vec<Option<TxId>> = vec![None; num_tx];
        let mut sp_stacks: Vec<Vec<SavepointId>> = vec![Vec::new(); num_tx];
        let mut traces: Vec<Vec<RecordedOp>> = vec![Vec::new(); num_tx];
        let mut digests: Vec<u8> = vec![0u8; num_tx];
        let mut committed_traces: Vec<Vec<RecordedOp>> = Vec::new();

        let steps = 20 + rng.gen_usize(12);
        for _ in 0..steps {
            if rng.gen_usize(8) == 0 {
                let _ = eng.vacuum();
                continue;
            }

            let slot = rng.gen_usize(num_tx);
            if tx_ids[slot].is_none() {
                // Begin at most once per slot
                if traces[slot].is_empty() {
                    tx_ids[slot] = Some(eng.begin());
                } else {
                    continue;
                }
            }
            let tx = tx_ids[slot].unwrap();

            match rng.gen_usize(7) {
                0 => {
                    // Point read
                    let k = &keys[rng.gen_usize(keys.len())];
                    let obs = eng.get(tx, k).unwrap();
                    if let Some(ref b) = obs {
                        digests[slot] = digests[slot].wrapping_add(b[0]);
                    } else {
                        digests[slot] = digests[slot].wrapping_add(7);
                    }
                    traces[slot].push(RecordedOp::Get {
                        key: k.clone(),
                        observed: obs,
                    });
                }
                1 => {
                    // Range scan with varied bound styles
                    let i1 = rng.gen_usize(keys.len());
                    let i2 = rng.gen_usize(keys.len());
                    let (lo_idx, hi_idx) = if i1 <= i2 { (i1, i2) } else { (i2, i1) };
                    let start = match rng.gen_usize(3) {
                        0 => Bound::Included(keys[lo_idx].clone()),
                        1 => Bound::Excluded(keys[lo_idx].clone()),
                        _ => Bound::Unbounded,
                    };
                    let end = match rng.gen_usize(3) {
                        0 => Bound::Excluded(keys[hi_idx].clone()),
                        1 => Bound::Included(keys[hi_idx].clone()),
                        _ => Bound::Unbounded,
                    };
                    let obs = eng.scan_range(tx, (start.clone(), end.clone())).unwrap();
                    digests[slot] = digests[slot].wrapping_add(obs.len() as u8);
                    traces[slot].push(RecordedOp::Scan {
                        start,
                        end,
                        observed: obs,
                    });
                }
                2 | 3 => {
                    // Put derived from prior observed reads
                    let k = &keys[rng.gen_usize(keys.len())];
                    let val = vec![b'v', b'0' + (slot as u8), digests[slot]];
                    if eng.put(tx, k, &val).is_ok() {
                        traces[slot].push(RecordedOp::Put {
                            key: k.clone(),
                            value: val,
                        });
                    }
                }
                4 => {
                    // Delete
                    let k = &keys[rng.gen_usize(keys.len())];
                    if eng.delete(tx, k).is_ok() {
                        traces[slot].push(RecordedOp::Delete { key: k.clone() });
                    }
                }
                5 => {
                    // Create savepoint + immediate read inside savepoint
                    let sp = eng.savepoint(tx).unwrap();
                    sp_stacks[slot].push(sp);
                    traces[slot].push(RecordedOp::Savepoint { sp });
                    let k = &keys[rng.gen_usize(keys.len())];
                    let obs = eng.get(tx, k).unwrap();
                    digests[slot] = digests[slot].wrapping_add(obs.as_ref().map_or(3, |v| v.len() as u8));
                    traces[slot].push(RecordedOp::Get {
                        key: k.clone(),
                        observed: obs,
                    });
                }
                _ => {
                    // Rollback to a valid savepoint if present, then branch-put
                    if let Some(sp) = sp_stacks[slot].pop() {
                        eng.rollback_to_savepoint(tx, sp).unwrap();
                        traces[slot].push(RecordedOp::Rollback { sp });
                        let k = &keys[rng.gen_usize(keys.len())];
                        let val = vec![b'b', digests[slot]];
                        if eng.put(tx, k, &val).is_ok() {
                            traces[slot].push(RecordedOp::Put {
                                key: k.clone(),
                                value: val,
                            });
                        }
                    }
                }
            }
        }

        // Attempt to commit all active transactions in randomized order
        for slot in 0..num_tx {
            if let Some(tx) = tx_ids[slot].take() {
                if rng.gen_usize(10) == 0 {
                    eng.abort(tx).unwrap();
                    assert_eq!(eng.tx_status(tx), Some(TxStatus::Aborted));
                } else if eng.commit(tx).is_ok() {
                    total_committed += 1;
                    committed_traces.push(std::mem::take(&mut traces[slot]));
                }
            }
            if rng.gen_usize(3) == 0 {
                let _ = eng.vacuum();
            }
        }

        let final_snapshot = eng.export_committed_snapshot();
        let mut used = vec![false; committed_traces.len()];
        let mut order = Vec::with_capacity(committed_traces.len());
        assert!(
            exists_equivalent_serial_order(
                &initial_map,
                &committed_traces,
                &final_snapshot,
                &mut used,
                &mut order,
            ),
            "Schedule #{sched_id} violated Serializable Snapshot Isolation!\nInitial: {initial_map:?}\nCommitted traces: {committed_traces:?}\nFinal: {final_snapshot:?}"
        );
    }

    assert!(
        total_committed >= 300,
        "Engine aborted too aggressively ({total_committed} committed across 220 schedules)"
    );

    // Sanity check schedule runner API still operates cleanly
    let mut sched_eng = SsiEngine::new();
    let res = sched_eng.run_schedule(&[
        ScheduleStep::Begin { slot: 1 },
        ScheduleStep::Put {
            slot: 1,
            key: b"s".to_vec(),
            value: b"1".to_vec(),
        },
        ScheduleStep::Commit { slot: 1 },
    ]);
    assert!(matches!(res[2], StepResult::Committed(Ok(_))));
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

    if not isinstance(data, dict):
        return False, "report.json root must be a JSON object"

    raw_blobs: list[str] = []
    for key in ("files", "file", "affected_files"):
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
        return (
            False,
            f"Expected report.json to reference at least 2 core crate files from {sorted(CORE_FILES)}, got {sorted(mentioned)}",
        )

    if not isinstance(findings, list) or len(findings) < 2:
        return False, "Expected at least 2 findings in report.json"
    for entry in findings:
        txt = json.dumps(entry) if isinstance(entry, dict) else str(entry)
        if len(txt.strip()) < 15:
            return False, f"Finding entry too brief: {txt!r}"

    return True, f"Report validated (covered {sorted(matched_core)})"


def check_architecture_preserved(app_dir: Path) -> tuple[bool, str]:
    cargo_toml = app_dir / "Cargo.toml"
    if not cargo_toml.is_file():
        return False, "Missing Cargo.toml"
    try:
        manifest = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid Cargo.toml: {exc}"

    deps = manifest.get("dependencies") or {}
    dev_deps = manifest.get("dev-dependencies") or {}
    if deps or dev_deps:
        return False, "Cargo.toml must retain zero external crate dependencies"

    expected_structs = {
        "version_store.rs": "struct VersionStore",
        "predicate.rs": "struct PredicateTable",
        "ssi.rs": "struct SsiTable",
        "engine.rs": "struct SsiEngine",
    }
    for fname, marker in expected_structs.items():
        fpath = app_dir / "src" / fname
        if not fpath.is_file():
            return False, f"Missing required module src/{fname}"
        content = fpath.read_text(encoding="utf-8", errors="replace")
        if marker not in content:
            return False, f"src/{fname} must retain `{marker}`"

    for fname in ("lib.rs", "types.rs", "txn.rs", "gc.rs"):
        if not (app_dir / "src" / fname).is_file():
            return False, f"Missing required module src/{fname}"

    return True, "Multi-module MVCC + SSI crate architecture with zero external dependencies preserved"


def run_cargo_test(work_dir: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["cargo", "test", "--offline", "--manifest-path", str(work_dir / "Cargo.toml")]
    if extra_args:
        cmd.extend(extra_args)
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=cargo_env(),
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        out_str = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err_str = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(
            cmd,
            returncode=124,
            stdout=out_str,
            stderr=err_str + "\ncargo test timed out after 120s",
        )


def verify(app_dir: Path, orig_dir: Path) -> tuple[bool, dict]:
    details: dict = {}

    ok_rep, msg_rep = check_report(app_dir)
    details["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, details

    ok_arch, msg_arch = check_architecture_preserved(app_dir)
    details["architecture"] = {"passed": ok_arch, "message": msg_arch}
    if not ok_arch:
        return False, details

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        # 1. Run agent's crate and test suite in an isolated copy
        patched_copy = tmp / "patched_app"
        shutil.copytree(
            app_dir,
            patched_copy,
            ignore=shutil.ignore_patterns("target", "Cargo.lock"),
        )
        agent_run = run_cargo_test(patched_copy)
        if agent_run.returncode != 0:
            details["agent_tests"] = {
                "passed": False,
                "message": f"cargo test --offline failed on /app:\n{(agent_run.stdout + agent_run.stderr)[-1500:]}",
            }
            return False, details

        # 2. Verify agent added regression tests that fail on original unmodified code
        orig_with_agent_tests = tmp / "orig_check"
        shutil.copytree(
            orig_dir,
            orig_with_agent_tests,
            ignore=shutil.ignore_patterns("target", "Cargo.lock"),
        )
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

        # 3. Inject hidden deterministic SSI + MVCC + randomized equivalence suite
        suite_path = patched_copy / "tests" / "vh_hidden_ssi.rs"
        suite_path.parent.mkdir(parents=True, exist_ok=True)
        suite_path.write_text(HIDDEN_RUST_SUITE, encoding="utf-8")
        hidden_run = run_cargo_test(
            patched_copy,
            ["--test", "vh_hidden_ssi", "--", "--test-threads=1"],
        )
        if hidden_run.returncode != 0:
            details["hidden_ssi_suite"] = {
                "passed": False,
                "message": f"Hidden SSI verification suite failed:\n{(hidden_run.stdout + hidden_run.stderr)[-2000:]}",
            }
            return False, details

        details["hidden_ssi_suite"] = {
            "passed": True,
            "message": "All 5 hidden SSI, range-predicate, savepoint, vacuum, and 220-schedule serializability equivalence checks passed",
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
