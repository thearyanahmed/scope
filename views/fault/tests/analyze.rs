#![allow(clippy::unwrap_used)]
use fault::{diff, heatmap, jsonl, stats, working_set};
use telemetry::trace::{Entry, Header, Region, Trace, Writer};
use telemetry::{FaultRecord, fault_flags};

const P: u64 = 4096;

fn trace(faults: &[(u64, u64, u32, u16, u32)]) -> Vec<u8> {
    let h = Header {
        page_size: P as u32,
        t0_unix_ns: 0,
        regions: vec![Region { host_base: 0x7f00_0000_0000, size: 64 * P, file_offset: 0 }],
    };
    let mut w = Writer::new(Vec::new(), &h).unwrap();
    for &(ts, page, resolve, flags, tid) in faults {
        w.push(&Entry {
            fault: FaultRecord { ts_ns: ts, offset: page * P, page_size: P as u32, resolve_ns: resolve, flags },
            tid,
        })
        .unwrap();
    }
    w.into_inner()
}

#[test]
fn stats_and_working_set() {
    let b = trace(&[
        (0, 9, 0, fault_flags::PREFETCHED, 0),
        (1_000, 3, 100, 0, 11),
        (2_000, 0, 300, fault_flags::WRITE, 12),
        (3_000, 3, 200, fault_flags::ZEROED, 11),
        (9_000_000, 7, 1000, 0, 11),
    ]);
    let t = Trace::parse(&b).unwrap();
    let s = stats(&t);
    assert_eq!((s.faults, s.prefetched, s.writes, s.zeroed), (4, 1, 1, 1));
    assert_eq!(s.unique_pages, 4);
    assert_eq!(s.touched_bytes, 4 * P);
    assert!((s.touched_pct - 6.25).abs() < 1e-9);
    assert_eq!(s.first_fault_ns, Some(1_000));
    assert_eq!(s.total_stall_ns, 1600);
    assert_eq!(s.resolve_max_ns, Some(1000));
    assert_eq!(s.resolve_p50_ns, Some(300));
    assert_eq!(s.per_thread[&11], 3);

    assert_eq!(working_set(&t, None), [9 * P, 3 * P, 0, 7 * P]);
    assert_eq!(working_set(&t, Some(1_000_000)), [9 * P, 3 * P, 0]);
}

#[test]
fn diff_overlap() {
    let d = diff(&[0, P, 2 * P, 3 * P], &[P, 2 * P, 3 * P, 4 * P]);
    assert_eq!(d.common, 3);
    assert!((d.jaccard_pct - 60.0).abs() < 1e-9);
    assert!((d.a_covered_by_b_pct - 75.0).abs() < 1e-9);
    assert_eq!(diff(&[], &[]).jaccard_pct, 100.0);
}

#[test]
fn heatmap_cells() {
    let b = trace(&[(10, 0, 1, 0, 0), (20, 1, 1, 0, 0), (30, 63, 1, 0, 0)]);
    let t = Trace::parse(&b).unwrap();
    let h = heatmap::build(&t, 8, 4);
    // 64 pages over 32 cells: 2 pages each
    assert_eq!(h.pages_per_cell, 2);
    assert_eq!(h.cells.len(), 32);
    assert_eq!(h.cells[0], Some(10), "earliest touch in the cell wins");
    assert_eq!(h.cells[31], Some(30));
    assert_eq!(h.cells.iter().filter(|c| c.is_some()).count(), 2);
    let svg = heatmap::svg(&h, "a <b>");
    assert!(svg.contains("a &lt;b&gt;") && svg.matches("<rect").count() == 3);
    assert_eq!(heatmap::ansi(&h).lines().count(), 4);
}

#[test]
fn jsonl_roundtrip() {
    let b = trace(&[(1, 2, 3, fault_flags::WRITE, 4)]);
    let t = Trace::parse(&b).unwrap();
    let mut out = vec![];
    jsonl::export(&t, &mut out).unwrap();
    let mut back = vec![];
    assert_eq!(jsonl::import(&out[..], &mut back).unwrap(), 1);
    assert_eq!(back, b);
}

#[test]
fn mapped_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("t.sft");
    std::fs::write(&p, trace(&[(1, 2, 3, 0, 0)])).unwrap();
    let m = fault::Mapped::open(&p).unwrap();
    assert_eq!(m.trace().unwrap().len(), 1);
}
