use std::ops::Bound;

use mvcc_ssi::{IsolationError, ScheduleStep, SeqNo, SsiEngine, StepResult, TxStatus};

#[test]
fn basic_crud_and_read_your_own_writes() {
    let mut eng = SsiEngine::new();
    assert_eq!(eng.latest_commit_seq(), SeqNo::ZERO);

    let t1 = eng.begin();
    assert_eq!(eng.get(t1, b"alpha").unwrap(), None);
    eng.put(t1, b"alpha", b"v1").unwrap();
    eng.put(t1, b"beta", b"v2").unwrap();
    assert_eq!(eng.get(t1, b"alpha").unwrap(), Some(b"v1".to_vec()));

    eng.put(t1, b"alpha", b"v1_updated").unwrap();
    eng.delete(t1, b"beta").unwrap();
    assert_eq!(eng.get(t1, b"alpha").unwrap(), Some(b"v1_updated".to_vec()));
    assert_eq!(eng.get(t1, b"beta").unwrap(), None);

    let c1 = eng.commit(t1).unwrap();
    assert_eq!(c1, SeqNo::new(1));
    assert_eq!(eng.tx_status(t1), Some(TxStatus::Committed { commit_seq: c1 }));
    assert_eq!(eng.commit(t1), Err(IsolationError::TxNotActive));

    let mut t2 = eng.transaction();
    assert_eq!(t2.get(b"alpha").unwrap(), Some(b"v1_updated".to_vec()));
    assert_eq!(t2.get(b"beta").unwrap(), None);
    t2.put(b"gamma", b"transient").unwrap();
    t2.abort().unwrap();

    let t3 = eng.begin();
    assert_eq!(eng.get(t3, b"gamma").unwrap(), None);
    eng.commit(t3).unwrap();
}

#[test]
fn snapshot_isolation_and_ordered_range_scans() {
    let mut eng = SsiEngine::new();
    let seed = eng.begin();
    for (k, v) in [
        (&b"k:10"[..], &b"ten"[..]),
        (b"k:20", b"twenty"),
        (b"k:30", b"thirty"),
        (b"k:40", b"forty"),
    ] {
        eng.put(seed, k, v).unwrap();
    }
    eng.commit(seed).unwrap();

    let reader = eng.begin();
    let writer = eng.begin();
    eng.put(writer, b"k:20", b"twenty_v2").unwrap();
    eng.put(writer, b"k:25", b"twenty_five").unwrap();
    eng.delete(writer, b"k:30").unwrap();

    assert_eq!(
        eng.scan_range(writer, b"k:10"..b"k:40").unwrap(),
        vec![
            (b"k:10".to_vec(), b"ten".to_vec()),
            (b"k:20".to_vec(), b"twenty_v2".to_vec()),
            (b"k:25".to_vec(), b"twenty_five".to_vec()),
        ]
    );
    eng.commit(writer).unwrap();

    assert_eq!(
        eng.scan_range(reader, b"k:10"..b"k:40").unwrap(),
        vec![
            (b"k:10".to_vec(), b"ten".to_vec()),
            (b"k:20".to_vec(), b"twenty".to_vec()),
            (b"k:30".to_vec(), b"thirty".to_vec()),
        ]
    );
    eng.commit(reader).unwrap();
}

#[test]
fn first_updater_and_first_committer_write_write_conflicts() {
    let mut eng = SsiEngine::new();
    let init = eng.begin();
    eng.put(init, b"shared", b"0").unwrap();
    eng.commit(init).unwrap();

    let t1 = eng.begin();
    let t2 = eng.begin();
    eng.put(t1, b"shared", b"1").unwrap();
    assert_eq!(eng.put(t2, b"shared", b"2"), Err(IsolationError::WriteWriteConflict));

    eng.abort(t1).unwrap();
    eng.put(t2, b"shared", b"2").unwrap();

    let t3 = eng.begin();
    eng.commit(t2).unwrap();
    assert_eq!(eng.put(t3, b"shared", b"3"), Err(IsolationError::WriteWriteConflict));
    eng.abort(t3).unwrap();
    assert_eq!(eng.export_committed_snapshot(), vec![(b"shared".to_vec(), b"2".to_vec())]);
}

#[test]
fn two_tx_write_skew_on_existing_keys_detected() {
    let mut eng = SsiEngine::new();
    let setup = eng.begin();
    eng.put(setup, b"acct:checking", b"100").unwrap();
    eng.put(setup, b"acct:savings", b"100").unwrap();
    eng.commit(setup).unwrap();

    let t1 = eng.begin();
    let t2 = eng.begin();
    assert_eq!(eng.get(t1, b"acct:checking").unwrap(), Some(b"100".to_vec()));
    assert_eq!(eng.get(t1, b"acct:savings").unwrap(), Some(b"100".to_vec()));
    assert_eq!(eng.get(t2, b"acct:checking").unwrap(), Some(b"100".to_vec()));
    assert_eq!(eng.get(t2, b"acct:savings").unwrap(), Some(b"100".to_vec()));

    eng.put(t1, b"acct:checking", b"0").unwrap();
    eng.put(t2, b"acct:savings", b"0").unwrap();

    eng.commit(t1).unwrap();
    assert_eq!(eng.commit(t2), Err(IsolationError::SerializationFailure));
    assert_eq!(eng.tx_status(t2), Some(TxStatus::Aborted));
    assert_eq!(
        eng.export_committed_snapshot(),
        vec![
            (b"acct:checking".to_vec(), b"0".to_vec()),
            (b"acct:savings".to_vec(), b"100".to_vec()),
        ]
    );
}

#[test]
fn range_scan_conflict_on_existing_key_update() {
    let mut eng = SsiEngine::new();
    let setup = eng.begin();
    eng.put(setup, b"item:1", b"active").unwrap();
    eng.put(setup, b"item:2", b"active").unwrap();
    eng.put(setup, b"summary", b"2").unwrap();
    eng.commit(setup).unwrap();

    let t1 = eng.begin();
    let t2 = eng.begin();
    assert_eq!(eng.scan_range(t1, b"item:0"..b"item:9").unwrap().len(), 2);
    eng.put(t1, b"summary", b"verified-2").unwrap();

    let _ = eng.get(t2, b"summary").unwrap();
    eng.delete(t2, b"item:1").unwrap();

    eng.commit(t1).unwrap();
    assert_eq!(eng.commit(t2), Err(IsolationError::SerializationFailure));
}

#[test]
fn nested_savepoints_undo_writes_and_invalidate_inner() {
    let mut eng = SsiEngine::new();
    let tx = eng.begin();
    eng.put(tx, b"cfg:mode", b"initial").unwrap();
    let sp_outer = eng.savepoint(tx).unwrap();

    eng.put(tx, b"cfg:mode", b"outer_override").unwrap();
    eng.put(tx, b"cfg:temp", b"1").unwrap();
    let sp_inner = eng.savepoint(tx).unwrap();

    eng.put(tx, b"cfg:mode", b"inner_override").unwrap();
    eng.put(tx, b"cfg:deep", b"2").unwrap();
    assert_eq!(eng.get(tx, b"cfg:mode").unwrap(), Some(b"inner_override".to_vec()));

    eng.rollback_to_savepoint(tx, sp_inner).unwrap();
    assert_eq!(eng.get(tx, b"cfg:mode").unwrap(), Some(b"outer_override".to_vec()));
    assert_eq!(eng.get(tx, b"cfg:deep").unwrap(), None);
    assert_eq!(eng.get(tx, b"cfg:temp").unwrap(), Some(b"1".to_vec()));

    eng.rollback_to_savepoint(tx, sp_outer).unwrap();
    assert_eq!(eng.rollback_to_savepoint(tx, sp_inner), Err(IsolationError::InvalidSavepoint));
    assert_eq!(eng.get(tx, b"cfg:mode").unwrap(), Some(b"initial".to_vec()));
    assert_eq!(eng.get(tx, b"cfg:temp").unwrap(), None);
    eng.commit(tx).unwrap();
}

#[test]
fn basic_vacuum_reclaims_overwritten_versions_and_schedule_runner() {
    let mut eng = SsiEngine::new();
    for rev in 1..=4u8 {
        let tx = eng.begin();
        eng.put(tx, b"counter", [b'0' + rev]).unwrap();
        eng.commit(tx).unwrap();
    }
    assert_eq!(eng.stats().total_committed_versions, 4);

    let vac = eng.vacuum();
    assert_eq!(vac.versions_reclaimed, 3);
    assert_eq!(eng.stats().total_committed_versions, 1);

    let steps = vec![
        ScheduleStep::Begin { slot: 0 },
        ScheduleStep::ScanRange {
            slot: 0,
            start: Bound::Included(b"a".to_vec()),
            end: Bound::Excluded(b"z".to_vec()),
        },
        ScheduleStep::Put {
            slot: 0,
            key: b"counter".to_vec(),
            value: b"5".to_vec(),
        },
        ScheduleStep::Commit { slot: 0 },
        ScheduleStep::Vacuum,
    ];
    let out = eng.run_schedule(&steps);
    assert!(matches!(out[3], StepResult::Committed(Ok(_))));
    assert_eq!(eng.export_committed_snapshot(), vec![(b"counter".to_vec(), b"5".to_vec())]);
}
