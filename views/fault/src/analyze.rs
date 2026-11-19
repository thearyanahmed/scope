use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use telemetry::fault_flags;
use telemetry::trace::Trace;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Stats {
    pub faults: u64,
    pub prefetched: u64,
    pub zeroed: u64,
    pub writes: u64,
    pub unique_pages: u64,
    pub page_size: u32,
    pub mem_bytes: u64,
    /// unique pages × page size: what the guest actually needed.
    pub touched_bytes: u64,
    pub touched_pct: f64,
    pub first_fault_ns: Option<u64>,
    pub last_fault_ns: Option<u64>,
    pub resolve_p50_ns: Option<u32>,
    pub resolve_p99_ns: Option<u32>,
    pub resolve_max_ns: Option<u32>,
    /// Σ resolve time of demand faults: an upper bound on vCPU stall, since faults on
    /// different vCPUs can overlap.
    pub total_stall_ns: u64,
    /// demand faults per faulting thread (0 = unknown thread).
    pub per_thread: BTreeMap<u32, u64>,
}

fn pct(sorted: &[u32], p: f64) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    Some(sorted[i])
}

pub fn stats(t: &Trace) -> Stats {
    let mut s = Stats { page_size: t.header.page_size, mem_bytes: t.header.mem_size(), ..Default::default() };
    let mut pages = HashSet::new();
    let mut lat = vec![];
    for e in t.iter() {
        let f = e.fault;
        pages.insert(f.offset);
        if f.flags & fault_flags::PREFETCHED != 0 {
            s.prefetched += 1;
            continue;
        }
        s.faults += 1;
        s.writes += u64::from(f.flags & fault_flags::WRITE != 0);
        s.zeroed += u64::from(f.flags & fault_flags::ZEROED != 0);
        s.first_fault_ns = Some(s.first_fault_ns.map_or(f.ts_ns, |v| v.min(f.ts_ns)));
        s.last_fault_ns = Some(s.last_fault_ns.map_or(f.ts_ns, |v| v.max(f.ts_ns)));
        s.total_stall_ns += u64::from(f.resolve_ns);
        *s.per_thread.entry(e.tid).or_insert(0) += 1;
        lat.push(f.resolve_ns);
    }
    lat.sort_unstable();
    s.resolve_p50_ns = pct(&lat, 0.50);
    s.resolve_p99_ns = pct(&lat, 0.99);
    s.resolve_max_ns = lat.last().copied();
    s.unique_pages = pages.len() as u64;
    s.touched_bytes = s.unique_pages * u64::from(s.page_size);
    if s.mem_bytes > 0 {
        s.touched_pct = s.touched_bytes as f64 * 100.0 / s.mem_bytes as f64;
    }
    s
}

/// Unique pages (memory-file offsets, page aligned) first touched within
/// `window_ns` of the trace start, in first-touch order. None = whole trace.
pub fn working_set(t: &Trace, window_ns: Option<u64>) -> Vec<u64> {
    let ps = u64::from(t.header.page_size.max(1));
    let mut seen = HashSet::new();
    let mut out = vec![];
    for e in t.iter() {
        if window_ns.is_some_and(|w| e.fault.ts_ns > w) {
            break;
        }
        let page = e.fault.offset / ps * ps;
        if seen.insert(page) {
            out.push(page);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Diff {
    pub a_pages: usize,
    pub b_pages: usize,
    pub common: usize,
    /// |A ∩ B| / |A ∪ B|.
    pub jaccard_pct: f64,
    /// share of A's working set that B also touched: how well a prefetch built from A covers B.
    pub a_covered_by_b_pct: f64,
}

pub fn diff(a: &[u64], b: &[u64]) -> Diff {
    let sa: HashSet<_> = a.iter().collect();
    let sb: HashSet<_> = b.iter().collect();
    let common = sa.intersection(&sb).count();
    let union = sa.len() + sb.len() - common;
    let p = |n: usize, d: usize| if d == 0 { 100.0 } else { n as f64 * 100.0 / d as f64 };
    Diff {
        a_pages: sa.len(),
        b_pages: sb.len(),
        common,
        jaccard_pct: p(common, union),
        a_covered_by_b_pct: p(common, sa.len()),
    }
}
