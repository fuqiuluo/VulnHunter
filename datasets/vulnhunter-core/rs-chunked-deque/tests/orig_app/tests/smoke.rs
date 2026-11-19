use chunked_deque::{wire, ChunkedDeque};

#[test]
fn push_pop_across_multiple_chunks() {
    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    for i in 0..18 {
        dq.push_back(i);
    }
    assert_eq!(dq.len(), 18);
    assert_eq!(dq.chunk_count(), 5);

    for i in (100..106).rev() {
        dq.push_front(i);
    }
    assert_eq!(dq.len(), 24);
    assert_eq!(dq.front(), Some(&100));
    assert_eq!(dq.back(), Some(&17));

    for expected in 100..106 {
        assert_eq!(dq.pop_front(), Some(expected));
    }
    for expected in (0..18).rev() {
        assert_eq!(dq.pop_back(), Some(expected));
    }
    assert!(dq.is_empty());
    assert_eq!(dq.chunk_count(), 0);
}

#[test]
fn insert_remove_and_retain() {
    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    dq.extend_from_slice(&[10, 20, 30, 40, 50, 60, 70]);
    dq.insert(3, 35);
    assert_eq!(dq.iter().copied().collect::<Vec<_>>(), vec![10, 20, 30, 35, 40, 50, 60, 70]);

    assert_eq!(dq.remove(2), Some(30));
    dq.retain(|x| x % 20 == 0);
    assert_eq!(dq.iter().copied().collect::<Vec<_>>(), vec![20, 40, 60]);
}

#[test]
fn drain_and_double_ended_iterators() {
    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    dq.extend(0..14);
    let mid: Vec<_> = dq.drain(4..10).collect();
    assert_eq!(mid, vec![4, 5, 6, 7, 8, 9]);
    assert_eq!(dq.iter().copied().collect::<Vec<_>>(), vec![0, 1, 2, 3, 10, 11, 12, 13]);

    for x in dq.iter_mut() {
        *x *= 2;
    }
    let rev: Vec<_> = dq.into_iter().rev().collect();
    assert_eq!(rev, vec![26, 24, 22, 20, 6, 4, 2, 0]);
}

#[test]
fn split_off_and_wire_roundtrip() {
    let mut dq = ChunkedDeque::with_chunk_capacity(4);
    for i in 0..10u8 {
        dq.push_back(vec![i, i + 1]);
    }
    let right = dq.split_off(6);
    assert_eq!(dq.len(), 6);
    assert_eq!(right.len(), 4);
    assert_eq!(right[0], vec![6, 7]);

    let encoded = wire::encode_records(&dq);
    let decoded = wire::decode_records(&encoded).expect("valid wire frame");
    assert_eq!(decoded, dq);
}
