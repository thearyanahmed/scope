//! Firecracker's own metrics.
//!
//! Firecracker writes one JSON object per line to `metrics_path` every 60 s
//! (or on the FlushMetrics action). Counters (`SharedIncMetric`) are written
//! as the delta since the previous flush; gauges (`SharedStoreMetric`) as the
//! current value. Scope sums the deltas so views see monotonic counters.
//!
//! The file is written by the VMM, which a guest escape could control, so
//! input is bounded: lines over [`MAX_LINE`] and keys past [`MAX_KEYS`] are dropped.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;
use telemetry::{
    Event, FcSample, Privilege, Sample, SampleData, Source, SourceError, StopToken, VmId, VmSet,
    mono_ns,
};

pub const MAX_LINE: usize = 1 << 20;
pub const MAX_KEYS: usize = 4096;

/// SharedStoreMetric fields, from firecracker's logger/metrics.rs. Everything
/// else numeric is treated as a SharedIncMetric (delta per flush).
pub fn is_gauge(key: &str) -> bool {
    let last = key.rsplit('.').next().unwrap_or(key);
    key == "utc_timestamp_ms"
        || key.starts_with("latencies_us.")
        || key == "seccomp.num_faults"
        || (key.starts_with("signals.") && last != "sigpipe")
        || last == "min_us"
        || last == "max_us"
}

fn flatten(prefix: &str, v: &serde_json::Value, out: &mut Vec<(String, u64)>) {
    if out.len() >= MAX_KEYS {
        return;
    }
    match v {
        serde_json::Value::Object(m) => {
            for (k, v) in m {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&key, v, out);
            }
        }
        serde_json::Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                out.push((prefix.to_owned(), n));
            }
        }
        _ => {}
    }
}

/// Folds flush lines into running totals.
#[derive(Debug, Default, Clone)]
pub struct Accumulator {
    pub sample: FcSample,
}

impl Accumulator {
    pub fn push_line(&mut self, line: &str) -> Result<(), String> {
        if line.len() > MAX_LINE {
            return Err(format!("metrics line of {} bytes exceeds {MAX_LINE}", line.len()));
        }
        let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let mut kv = vec![];
        flatten("", &v, &mut kv);
        for (k, n) in kv {
            if is_gauge(&k) {
                self.sample.gauges.insert(k, n);
            } else if self.sample.counters.len() < MAX_KEYS || self.sample.counters.contains_key(&k) {
                *self.sample.counters.entry(k).or_insert(0) += n;
            }
        }
        self.sample.flushes += 1;
        Ok(())
    }
}

/// Follows a growing file. Handles truncation and partial trailing lines.
#[derive(Debug)]
pub struct Tail {
    f: File,
    pos: u64,
    buf: Vec<u8>,
}

impl Tail {
    /// Start near the end so the newest flush is read once, not the whole history.
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        let start = len.saturating_sub(64 * 1024);
        f.seek(SeekFrom::Start(start))?;
        let mut t = Self { f, pos: start, buf: vec![] };
        if start > 0 {
            // drop the partial line we landed in.
            t.read_lines()?;
            t.buf.clear();
        }
        Ok(t)
    }

    /// Complete lines appended since the last call.
    pub fn read_lines(&mut self) -> std::io::Result<Vec<String>> {
        let len = self.f.metadata()?.len();
        if len < self.pos {
            self.f.seek(SeekFrom::Start(0))?;
            self.pos = 0;
            self.buf.clear();
        }
        let mut chunk = vec![];
        self.pos += self.f.read_to_end(&mut chunk)? as u64;
        self.buf.extend_from_slice(&chunk);
        let mut lines = vec![];
        while let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            if line.len() <= MAX_LINE {
                lines.push(String::from_utf8_lossy(&line).trim().to_owned());
            }
        }
        if self.buf.len() > MAX_LINE {
            self.buf.clear();
        }
        Ok(lines.into_iter().filter(|l| !l.is_empty()).collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Fifo,
    Missing,
    Other,
}

pub fn kind(path: &std::path::Path) -> Kind {
    #[cfg(unix)]
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Err(_) => Kind::Missing,
        Ok(m) if m.is_file() => Kind::File,
        #[cfg(unix)]
        Ok(m) if m.file_type().is_fifo() => Kind::Fifo,
        Ok(_) => Kind::Other,
    }
}

/// Reads the metrics file of every VM that has one.
#[derive(Debug)]
pub struct Metrics {
    pub interval: Duration,
    /// read FIFOs too. Only safe when nothing else (an orchestrator) reads them:
    /// each flush goes to one reader, so scope would steal data.
    pub own_fifo: bool,
}

impl Default for Metrics {
    fn default() -> Self {
        Self { interval: Duration::from_secs(5), own_fifo: false }
    }
}

struct Watched {
    path: PathBuf,
    tail: Tail,
    acc: Accumulator,
}

impl Source for Metrics {
    fn name(&self) -> &'static str {
        "metrics"
    }

    fn needs(&self) -> &'static [Privilege] {
        &[Privilege::PtraceRead]
    }

    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError> {
        let mut watched: BTreeMap<VmId, Watched> = BTreeMap::new();
        loop {
            let current = vms.snapshot();
            watched.retain(|id, w| current.iter().any(|v| &v.id == id && v.metrics_path.as_ref() == Some(&w.path)));
            for vm in current {
                let Some(path) = vm.metrics_path.clone() else { continue };
                if !watched.contains_key(&vm.id) {
                    let ok = match kind(&path) {
                        Kind::File => true,
                        Kind::Fifo => self.own_fifo,
                        Kind::Missing | Kind::Other => false,
                    };
                    // todo: a fifo blocks on open until a writer exists; open it non-blocking
                    // when own_fifo is set. firecracker holds the write end, so this is fine in practice.
                    let Some(tail) = ok.then(|| Tail::open(&path).ok()).flatten() else { continue };
                    watched.insert(vm.id.clone(), Watched { path, tail, acc: Accumulator::default() });
                }
                let Some(w) = watched.get_mut(&vm.id) else { continue };
                let Ok(lines) = w.tail.read_lines() else { continue };
                let mut changed = false;
                for l in lines {
                    changed |= w.acc.push_line(&l).is_ok();
                }
                if changed {
                    let ev = Event::Sample(
                        vm.id.clone(),
                        Sample { ts_ns: mono_ns(), data: SampleData::Firecracker(w.acc.sample.clone()) },
                    );
                    if out.send(ev).is_err() {
                        return Ok(());
                    }
                }
            }
            if !stop.sleep(self.interval) {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/metrics/v1.flush.jsonl")).unwrap()
    }

    #[test]
    fn counters_accumulate_gauges_replace() {
        let mut a = Accumulator::default();
        for l in fixture().lines() {
            a.push_line(l).unwrap();
        }
        let s = &a.sample;
        assert_eq!(s.flushes, 2);
        assert_eq!(s.counters["net_eth0.rx_rate_limiter_throttled"], 3 + 4);
        assert_eq!(s.counters["block_rootfs.rate_limiter_throttled_events"], 1);
        assert_eq!(s.counters["vcpu.exit_io_out"], 100 + 250);
        assert_eq!(s.counters["vcpu.exit_io_out_agg.sum_us"], 50 + 60);
        assert_eq!(s.gauges["vcpu.exit_io_out_agg.max_us"], 9);
        assert_eq!(s.gauges["seccomp.num_faults"], 0);
        assert_eq!(s.gauges["signals.sigsegv"], 0);
        assert_eq!(s.counters["signals.sigpipe"], 2);
        assert_eq!(s.gauges["utc_timestamp_ms"], 1763500120000);
        assert!(!s.counters.contains_key("utc_timestamp_ms"));
    }

    #[test]
    fn bounded_input() {
        let mut a = Accumulator::default();
        assert!(a.push_line(&"x".repeat(MAX_LINE + 1)).is_err());
        let wide: String = format!("{{{}}}", (0..MAX_KEYS + 10).map(|i| format!("\"k{i}\":1")).collect::<Vec<_>>().join(","));
        a.push_line(&wide).unwrap();
        assert_eq!(a.sample.counters.len(), MAX_KEYS);
    }

    #[test]
    fn tail_follows_partial_lines_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("m");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "{{\"a\":1}}").unwrap();
        let mut t = Tail::open(&p).unwrap();
        assert_eq!(t.read_lines().unwrap(), ["{\"a\":1}"]);
        write!(f, "{{\"a\":").unwrap();
        assert!(t.read_lines().unwrap().is_empty(), "partial line waits");
        writeln!(f, "2}}").unwrap();
        assert_eq!(t.read_lines().unwrap(), ["{\"a\":2}"]);
        // rotated in place
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "{{\"a\":3}}").unwrap();
        assert_eq!(t.read_lines().unwrap(), ["{\"a\":3}"]);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_not_read_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("fifo");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid nul-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(kind(&p), Kind::Fifo);
        assert_eq!(kind(&dir.path().join("nope")), Kind::Missing);
    }
}
