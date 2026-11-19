use crate::thresholds::{Level, Thresholds, level};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use telemetry::{Event, FcSample, HostSample, KvmSample, ProcSample, SampleData, Vm, VmEvent, VmId, VmInfo};

/// 5 minutes at the default 1 s refresh.
pub const HISTORY: usize = 300;

#[derive(Debug, Default)]
pub struct Model {
    pub thresholds: Thresholds,
    vms: BTreeMap<VmId, VmState>,
    host: (Option<HostSample>, Option<HostSample>),
}

/// previous and latest (timestamp, sample).
type Pair<T> = (Option<(u64, T)>, Option<(u64, T)>);

#[derive(Debug)]
struct VmState {
    vm: Vm,
    proc: Pair<ProcSample>,
    kvm: Pair<KvmSample>,
    fc: Option<FcSample>,
    info: Option<VmInfo>,
    history: VecDeque<Point>,
}

/// One sparkline point.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Point {
    pub cpu_pct: f64,
    pub wait_pct: f64,
    pub rss_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct VcpuRow {
    pub index: u32,
    pub tid: u32,
    /// on-cpu share of wall time.
    pub run_pct: f64,
    pub wait_pct: f64,
    pub guest_pct: f64,
}

/// What `top` shows per VM. Rates are per second over the last interval;
/// `None` means not measured yet (first sample) or not available.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Row {
    pub id: String,
    pub pid: u32,
    pub jailed: bool,
    pub uptime_s: Option<u64>,
    pub vcpu_count: usize,
    /// 100 = one full core.
    pub cpu_pct: Option<f64>,
    pub guest_pct: Option<f64>,
    /// cpu time in firecracker itself: device emulation, api, kvm exits handled in kernel.
    pub vmm_pct: Option<f64>,
    pub vcpus: Vec<VcpuRow>,
    pub max_wait_pct: Option<f64>,
    pub throttle_pct: Option<f64>,
    pub throttled_per_s: Option<f64>,
    pub rss_bytes: Option<u64>,
    pub pss_bytes: Option<u64>,
    pub mem_current: Option<u64>,
    pub mem_max: Option<u64>,
    pub mem_pct: Option<f64>,
    pub oom_kills: Option<u64>,
    /// oom kills during the last interval.
    pub new_oom_kills: Option<u64>,
    pub disk_read_bps: Option<f64>,
    pub disk_write_bps: Option<f64>,
    /// guest-perspective: rx = into the guest (host tap tx).
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub net_drops_per_s: Option<f64>,
    pub exits_per_s: Option<f64>,
    pub halt_exits_per_s: Option<f64>,
    pub mem_size_mib: Option<u64>,
    pub fc_throttle_events: Option<u64>,
    pub level: Level,
    pub flags: Vec<(String, Level)>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Header {
    pub vm_count: usize,
    pub host_cpu_pct: Option<f64>,
    pub ncpus: u32,
    pub vcpus: usize,
    /// vCPUs per host core.
    pub cpu_overcommit: Option<f64>,
    pub guest_mem_bytes: u64,
    pub host_mem_bytes: u64,
    pub host_mem_available: u64,
    pub mem_overcommit: Option<f64>,
}

fn rate(d: u64, dt_ns: u64) -> f64 {
    d as f64 * 1e9 / dt_ns as f64
}

fn pct(d_ns: u64, dt_ns: u64) -> f64 {
    d_ns as f64 * 100.0 / dt_ns as f64
}

/// Counters can go backwards when a process or cgroup is recreated; treat that as zero.
fn delta(a: u64, b: u64) -> u64 {
    b.saturating_sub(a)
}

fn shift<T>(slot: &mut (Option<T>, Option<T>), v: T) {
    slot.0 = slot.1.take();
    slot.1 = Some(v);
}

impl Model {
    pub fn new(thresholds: Thresholds) -> Self {
        Self { thresholds, ..Default::default() }
    }

    pub fn apply(&mut self, ev: &Event) {
        match ev {
            Event::Vm(VmEvent::Appeared(vm)) => match self.vms.get_mut(&vm.id) {
                Some(s) => s.vm = (**vm).clone(),
                None => {
                    self.vms.insert(
                        vm.id.clone(),
                        VmState {
                            vm: (**vm).clone(),
                            proc: (None, None),
                            kvm: (None, None),
                            fc: None,
                            info: None,
                            history: VecDeque::with_capacity(HISTORY),
                        },
                    );
                }
            },
            Event::Vm(VmEvent::Gone(id)) => {
                self.vms.remove(id);
            }
            Event::Host(h) => shift(&mut self.host, *h),
            Event::Sample(id, s) => {
                let Some(st) = self.vms.get_mut(id) else { return };
                match &s.data {
                    SampleData::Proc(p) => {
                        shift(&mut st.proc, (s.ts_ns, p.clone()));
                        let r = row(st, &self.thresholds, None);
                        if st.history.len() == HISTORY {
                            st.history.pop_front();
                        }
                        st.history.push_back(Point {
                            cpu_pct: r.cpu_pct.unwrap_or(0.0),
                            wait_pct: r.max_wait_pct.unwrap_or(0.0),
                            rss_bytes: r.rss_bytes.unwrap_or(0),
                        });
                    }
                    SampleData::Kvm(k) => shift(&mut st.kvm, (s.ts_ns, k.clone())),
                    SampleData::Firecracker(f) => st.fc = Some(f.clone()),
                    SampleData::Info(i) => st.info = Some(i.clone()),
                }
            }
            Event::Exit(..) | Event::Stack(..) | Event::Timeline(..) | Event::Fault(..) => {}
        }
    }

    /// `now_ms` is wall-clock unix ms for uptime; None leaves uptime empty (replays).
    pub fn rows(&self, now_ms: Option<u64>) -> Vec<Row> {
        self.vms.values().map(|s| row(s, &self.thresholds, now_ms)).collect()
    }

    pub fn row(&self, id: &VmId, now_ms: Option<u64>) -> Option<Row> {
        self.vms.get(id).map(|s| row(s, &self.thresholds, now_ms))
    }

    pub fn vm(&self, id: &VmId) -> Option<&Vm> {
        self.vms.get(id).map(|s| &s.vm)
    }

    pub fn info(&self, id: &VmId) -> Option<&VmInfo> {
        self.vms.get(id).and_then(|s| s.info.as_ref())
    }

    pub fn firecracker(&self, id: &VmId) -> Option<&FcSample> {
        self.vms.get(id).and_then(|s| s.fc.as_ref())
    }

    pub fn history(&self, id: &VmId) -> impl Iterator<Item = &Point> {
        self.vms.get(id).into_iter().flat_map(|s| s.history.iter())
    }

    pub fn header(&self) -> Header {
        let mut h = Header { vm_count: self.vms.len(), ..Default::default() };
        if let Some(cur) = self.host.1 {
            h.ncpus = cur.ncpus;
            h.host_mem_bytes = cur.mem_total_bytes;
            h.host_mem_available = cur.mem_available_bytes;
            if let Some(prev) = self.host.0 {
                let busy = delta(prev.busy_ns, cur.busy_ns);
                let total = busy + delta(prev.idle_ns, cur.idle_ns);
                h.host_cpu_pct = (total > 0).then(|| pct(busy, total));
            }
        }
        for s in self.vms.values() {
            h.vcpus += s.info.as_ref().and_then(|i| i.vcpu_count).map_or(s.vm.vcpus.len(), |n| n as usize);
            // configured size when the api told us, else what is resident.
            h.guest_mem_bytes += s
                .info
                .as_ref()
                .and_then(|i| i.mem_size_mib)
                .map(|m| m << 20)
                .or_else(|| s.proc.1.as_ref().and_then(|p| p.1.mem).map(|m| m.rss_bytes))
                .unwrap_or(0);
        }
        if h.ncpus > 0 {
            h.cpu_overcommit = Some(h.vcpus as f64 / h.ncpus as f64);
        }
        if h.host_mem_bytes > 0 {
            h.mem_overcommit = Some(h.guest_mem_bytes as f64 / h.host_mem_bytes as f64);
        }
        h
    }
}

fn row(s: &VmState, th: &Thresholds, now_ms: Option<u64>) -> Row {
    let vm = &s.vm;
    let mut r = Row {
        id: vm.id.0.clone(),
        pid: vm.pid,
        jailed: vm.jailed,
        uptime_s: now_ms.map(|n| n.saturating_sub(vm.started_ms) / 1000),
        vcpu_count: vm.vcpus.len(),
        mem_size_mib: s.info.as_ref().and_then(|i| i.mem_size_mib),
        ..Default::default()
    };

    if let Some((_, cur)) = &s.proc.1 {
        r.rss_bytes = cur.mem.map(|m| m.rss_bytes);
        r.pss_bytes = cur.mem.map(|m| m.pss_bytes);
        if let Some(cg) = &cur.cgroup {
            r.mem_current = cg.mem_current;
            r.mem_max = cg.mem_max;
            r.oom_kills = Some(cg.mem_events.oom_kill);
            if let (Some(c), Some(m)) = (cg.mem_current, cg.mem_max) {
                r.mem_pct = (m > 0).then(|| c as f64 * 100.0 / m as f64);
            }
        }
    }

    if let (Some((t0, a)), Some((t1, b))) = (&s.proc.0, &s.proc.1) {
        let dt = t1.saturating_sub(*t0);
        if dt > 0 {
            proc_rates(&mut r, a, b, dt);
        }
    }

    if let (Some((t0, a)), Some((t1, b))) = (&s.kvm.0, &s.kvm.1) {
        let dt = t1.saturating_sub(*t0);
        let d = |k: &str| Some(delta(*a.vm.get(k)?, *b.vm.get(k)?));
        if dt > 0 {
            r.exits_per_s = d("exits").map(|v| rate(v, dt));
            // x86 counts hlt as halt_exits; arm64 counts wfi traps as wfi_exit_stat.
            r.halt_exits_per_s = d("halt_exits").or_else(|| d("wfi_exit_stat")).map(|v| rate(v, dt));
        }
    }

    if let Some(fc) = &s.fc {
        let t: u64 = fc
            .counters
            .iter()
            .filter(|(k, _)| k.ends_with("rate_limiter_throttled") || k.ends_with("rate_limiter_throttled_events"))
            // aggregates ("net.", "block.") would double count the per-device objects.
            .filter(|(k, _)| !k.starts_with("net.") && !k.starts_with("block."))
            .map(|(_, v)| *v)
            .sum();
        r.fc_throttle_events = Some(t);
    }

    flag(&mut r, th);
    r
}

fn proc_rates(r: &mut Row, a: &ProcSample, b: &ProcSample, dt: u64) {
    r.cpu_pct = Some(pct(delta(a.cpu.total_ns(), b.cpu.total_ns()), dt));
    let guest = delta(a.cpu.guest_ns, b.cpu.guest_ns);
    r.guest_pct = Some(pct(guest, dt));
    r.vmm_pct = Some(pct(delta(a.cpu.total_ns(), b.cpu.total_ns()).saturating_sub(guest), dt));

    r.vcpus = b
        .vcpus
        .iter()
        .map(|v| {
            let prev = a.vcpus.iter().find(|p| p.tid == v.tid);
            let d = |f: fn(&telemetry::VcpuTimes) -> u64| prev.map_or(0, |p| delta(f(p), f(v)));
            VcpuRow {
                index: v.index,
                tid: v.tid,
                run_pct: pct(d(|x| x.sched.run_ns), dt),
                wait_pct: pct(d(|x| x.sched.wait_ns), dt),
                guest_pct: pct(d(|x| x.cpu.guest_ns), dt),
            }
        })
        .collect();
    r.max_wait_pct = r.vcpus.iter().map(|v| v.wait_pct).reduce(f64::max);

    if let (Some(x), Some(y)) = (&a.cgroup, &b.cgroup) {
        r.throttle_pct = Some(pct(delta(x.cpu.throttled_usec, y.cpu.throttled_usec) * 1000, dt));
        r.throttled_per_s = Some(rate(delta(x.cpu.nr_throttled, y.cpu.nr_throttled), dt));
        r.new_oom_kills = Some(delta(x.mem_events.oom_kill, y.mem_events.oom_kill));
    }

    if let (Some(x), Some(y)) = (&a.io, &b.io) {
        r.disk_read_bps = Some(rate(delta(x.read_bytes, y.read_bytes), dt));
        r.disk_write_bps = Some(rate(delta(x.write_bytes, y.write_bytes), dt));
    } else if let (Some(x), Some(y)) = (&a.cgroup, &b.cgroup) {
        r.disk_read_bps = Some(rate(delta(x.io.rbytes, y.io.rbytes), dt));
        r.disk_write_bps = Some(rate(delta(x.io.wbytes, y.io.wbytes), dt));
    }

    if !b.net.is_empty() {
        let (mut rx, mut tx, mut drops) = (0, 0, 0);
        for n in &b.net {
            let Some(p) = a.net.iter().find(|p| p.name == n.name) else { continue };
            // host tap tx is what the guest receives.
            rx += delta(p.tx_bytes, n.tx_bytes);
            tx += delta(p.rx_bytes, n.rx_bytes);
            drops += delta(p.rx_dropped + p.tx_dropped, n.rx_dropped + n.tx_dropped);
        }
        r.net_rx_bps = Some(rate(rx, dt));
        r.net_tx_bps = Some(rate(tx, dt));
        r.net_drops_per_s = Some(rate(drops, dt));
    }
}

fn flag(r: &mut Row, th: &Thresholds) {
    let mut add = |name: &str, v: Option<f64>, t: (f64, f64)| {
        if let Some(v) = v {
            let l = level(v, t);
            if l != Level::Ok {
                r.flags.push((name.to_owned(), l));
            }
        }
    };
    add("wait", r.max_wait_pct, th.wait_pct);
    add("throttle", r.throttle_pct, th.throttle_pct);
    add("mem", r.mem_pct, th.mem_pct);
    add("exits", r.exits_per_s, th.exits_per_s);
    if r.new_oom_kills.is_some_and(|k| k > 0) {
        r.flags.push(("oom_kill".into(), Level::Crit));
    }
    r.level = r.flags.iter().map(|f| f.1).max().unwrap_or(Level::Ok);
}
