//! Rendering for `scope flame`. Input is plain telemetry types, so a profile
//! recorded on one host renders anywhere (and tests need no eBPF).

use serde::{Deserialize, Serialize};
use std::fmt::Write;
use telemetry::{ExitRecord, StackSample, VcpuStates};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Profile {
    pub vm: String,
    pub elapsed_ns: u64,
    pub freq_hz: u64,
    pub stacks: Vec<StackSample>,
    pub exits: Vec<ExitRecord>,
    pub timeline: Vec<VcpuStates>,
    /// exit-site guest pcs; biased toward instructions that cause exits.
    pub guest: Vec<StackSample>,
    pub warnings: Vec<String>,
}

fn vcpu_label(v: Option<u32>, tid: u32) -> String {
    v.map_or_else(|| format!("tid {tid}"), |i| format!("vcpu{i}"))
}

/// thread;frame;frame samples
pub fn vmm_folded(p: &Profile) -> Vec<String> {
    export::folded::fold(&p.stacks, |s| vec![s.thread.clone()])
}

/// vcpuN;REASON microseconds-out-of-guest
pub fn exits_folded(p: &Profile) -> Vec<String> {
    let mut v: Vec<String> = p
        .exits
        .iter()
        .filter(|e| e.total_ns >= 1000)
        .map(|e| format!("{};{} {}", vcpu_label(e.vcpu, e.tid), e.reason.replace(';', "_"), e.total_ns / 1000))
        .collect();
    v.sort();
    v
}

pub fn guest_folded(p: &Profile) -> Vec<String> {
    export::folded::fold(&p.guest, |s| vec![s.thread.clone()])
}

pub fn svg(lines: &[String], title: &str, count_name: &str) -> std::io::Result<String> {
    let mut o = inferno::flamegraph::Options::default();
    o.title = title.to_owned();
    o.count_name = count_name.to_owned();
    // folded lines from fold() are already sorted; inferno still requires it.
    let mut sorted = lines.to_vec();
    sorted.sort();
    let mut out = vec![];
    inferno::flamegraph::from_lines(&mut o, sorted.iter().map(String::as_str), &mut out)?;
    String::from_utf8(out).map_err(std::io::Error::other)
}

/// Upper bound of the bucket containing quantile `q` of a log2 histogram.
pub fn hist_quantile(hist: &[u64], q: f64) -> Option<u64> {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return None;
    }
    let want = (total as f64 * q).ceil().max(1.0) as u64;
    let mut acc = 0;
    for (i, n) in hist.iter().enumerate() {
        acc += n;
        if acc >= want {
            return Some(1u64 << (i + 1).min(63));
        }
    }
    None
}

/// Exits merged across vCPUs, sorted by time out of guest.
pub fn exit_table(p: &Profile) -> String {
    let mut by: std::collections::BTreeMap<&str, (u64, u64, Vec<u64>)> = Default::default();
    for e in &p.exits {
        let r = by.entry(&e.reason).or_insert((0, 0, vec![0; e.hist.len()]));
        r.0 += e.count;
        r.1 += e.total_ns;
        for (a, b) in r.2.iter_mut().zip(&e.hist) {
            *a += b;
        }
    }
    let total: u64 = by.values().map(|v| v.1).sum();
    let mut rows: Vec<_> = by.into_iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1.1));
    let secs = p.elapsed_ns as f64 / 1e9;
    let mut s = format!(
        "{:<24} {:>10} {:>9} {:>10} {:>7} {:>9} {:>9}\n",
        "exit reason", "count", "per s", "total ms", "share", "p50 <=", "p99 <="
    );
    for (reason, (count, ns, hist)) in rows {
        let us = |v: Option<u64>| v.map_or("-".into(), |n| format!("{:.1}us", n as f64 / 1e3));
        let _ = writeln!(
            s,
            "{:<24} {:>10} {:>9.0} {:>10.2} {:>6.1}% {:>9} {:>9}",
            reason,
            count,
            if secs > 0.0 { count as f64 / secs } else { 0.0 },
            ns as f64 / 1e6,
            if total > 0 { ns as f64 * 100.0 / total as f64 } else { 0.0 },
            us(hist_quantile(&hist, 0.5)),
            us(hist_quantile(&hist, 0.99)),
        );
    }
    s
}

pub fn timeline_table(p: &Profile) -> String {
    let mut s =
        format!("{:<8} {:>8} {:>8} {:>8} {:>8}   (share of recording)\n", "vcpu", "guest", "kvm", "vmm", "off-cpu");
    for t in &p.timeline {
        let all = (t.in_guest_ns + t.in_kernel_ns + t.in_vmm_ns + t.off_cpu_ns).max(1) as f64;
        let pc = |v: u64| format!("{:.1}%", v as f64 * 100.0 / all);
        let _ = writeln!(
            s,
            "{:<8} {:>8} {:>8} {:>8} {:>8}",
            vcpu_label(t.vcpu, t.tid),
            pc(t.in_guest_ns),
            pc(t.in_kernel_ns),
            pc(t.in_vmm_ns),
            pc(t.off_cpu_ns)
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use telemetry::StackKind;

    fn profile() -> Profile {
        let st = |frames: &[&str], w| StackSample {
            tid: 2,
            thread: "firecracker".into(),
            kind: StackKind::Vmm,
            frames: frames.iter().map(|s| s.to_string()).collect(),
            weight: w,
        };
        let mut hist = vec![0; 32];
        hist[10] = 90; // ~1-2us
        hist[16] = 10; // ~64-128us
        Profile {
            vm: "vm1".into(),
            elapsed_ns: 2_000_000_000,
            freq_hz: 99,
            stacks: vec![
                st(&["main", "event_loop", "virtio_block::process_queue"], 40),
                st(&["main", "event_loop", "epoll_wait"], 10),
            ],
            exits: vec![
                ExitRecord {
                    tid: 5,
                    vcpu: Some(0),
                    reason: "IO_INSTRUCTION".into(),
                    code: 30,
                    count: 100,
                    total_ns: 9_000_000,
                    hist: hist.clone(),
                },
                ExitRecord {
                    tid: 6,
                    vcpu: Some(1),
                    reason: "IO_INSTRUCTION".into(),
                    code: 30,
                    count: 100,
                    total_ns: 1_000_000,
                    hist,
                },
                ExitRecord {
                    tid: 5,
                    vcpu: Some(0),
                    reason: "HLT".into(),
                    code: 12,
                    count: 4,
                    total_ns: 500,
                    hist: vec![0; 32],
                },
            ],
            timeline: vec![VcpuStates {
                tid: 5,
                vcpu: Some(0),
                in_guest_ns: 600,
                in_kernel_ns: 100,
                in_vmm_ns: 200,
                off_cpu_ns: 100,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn folds() {
        let p = profile();
        assert_eq!(
            vmm_folded(&p),
            ["firecracker;main;event_loop;epoll_wait 10", "firecracker;main;event_loop;virtio_block::process_queue 40"]
        );
        // sub-microsecond totals are dropped from the exit graph
        assert_eq!(exits_folded(&p), ["vcpu0;IO_INSTRUCTION 9000", "vcpu1;IO_INSTRUCTION 1000"]);
    }

    #[test]
    fn tables() {
        let p = profile();
        let t = exit_table(&p);
        let io = t.lines().nth(1).unwrap();
        assert!(io.starts_with("IO_INSTRUCTION"), "{t}");
        assert!(io.contains(" 200 ") && io.contains("100.0%"), "{io}");
        assert!(io.contains("2.0us") && io.contains("131.1us"), "{io}");
        let tl = timeline_table(&p);
        assert!(tl.contains("vcpu0") && tl.contains("60.0%") && tl.contains("20.0%"), "{tl}");
    }

    #[test]
    fn quantiles() {
        let mut h = vec![0; 32];
        assert_eq!(hist_quantile(&h, 0.5), None);
        h[3] = 1;
        h[5] = 1;
        assert_eq!(hist_quantile(&h, 0.5), Some(16));
        assert_eq!(hist_quantile(&h, 1.0), Some(64));
    }

    #[test]
    fn renders_svg() {
        let s = svg(&vmm_folded(&profile()), "vm1 vmm", "samples").unwrap();
        assert!(s.contains("<svg") && s.contains("virtio_block::process_queue"));
    }
}
