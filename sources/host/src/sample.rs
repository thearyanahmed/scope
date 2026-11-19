//! Per-VM and host-wide counters at a fixed interval.

use crate::{Root, parse};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;
use telemetry::{
    Cgroup, CpuTimes, Event, HostSample, NetDev, Privilege, ProcSample, Sample, SampleData, Source, SourceError,
    StopToken, ThreadTimes, VcpuTimes, Vm, VmSet, mono_ns,
};

fn cpu(root: &Root, st: parse::Stat) -> CpuTimes {
    CpuTimes {
        user_ns: root.ticks_to_ns(st.utime),
        system_ns: root.ticks_to_ns(st.stime),
        guest_ns: root.ticks_to_ns(st.guest_time),
    }
}

fn task(root: &Root, pid: u32, tid: u32) -> Option<(CpuTimes, telemetry::SchedStat)> {
    let st = parse::stat(&root.read(format!("proc/{pid}/task/{tid}/stat")).ok()?)?;
    // schedstat is missing when the kernel lacks CONFIG_SCHED_INFO; keep cpu times anyway.
    let sched = root
        .read(format!("proc/{pid}/task/{tid}/schedstat"))
        .ok()
        .and_then(|s| parse::schedstat(&s))
        .unwrap_or_default();
    Some((cpu(root, st), sched))
}

/// None means the process is gone; discovery will report it.
pub fn sample_vm(root: &Root, vm: &Vm) -> Option<ProcSample> {
    let pid = vm.pid;
    let st = parse::stat(&root.read(format!("proc/{pid}/stat")).ok()?)?;

    let vcpus = vm
        .vcpus
        .iter()
        .filter_map(|v| {
            let (cpu, sched) = task(root, pid, v.tid)?;
            Some(VcpuTimes { index: v.index, tid: v.tid, cpu, sched })
        })
        .collect();
    let threads = vm
        .threads
        .iter()
        .filter_map(|t| {
            let (cpu, sched) = task(root, pid, t.tid)?;
            Some(ThreadTimes { tid: t.tid, name: t.name.clone(), cpu, sched })
        })
        .collect();

    Some(ProcSample {
        cpu: cpu(root, st),
        vcpus,
        threads,
        // these three need ptrace-read; EACCES leaves them None rather than failing the row.
        mem: root.read(format!("proc/{pid}/smaps_rollup")).ok().map(|s| parse::smaps_rollup(&s)),
        io: root.read(format!("proc/{pid}/io")).ok().map(|s| parse::proc_io(&s)),
        net: vm.taps.iter().filter_map(|t| net(root, t)).collect(),
        cgroup: vm.cgroup.as_deref().and_then(cgroup),
    })
}

fn net(root: &Root, tap: &str) -> Option<NetDev> {
    // tap names come from fdinfo; refuse anything that could walk out of sysfs.
    if tap.is_empty() || tap.contains('/') || tap.contains("..") {
        return None;
    }
    let base = format!("sys/class/net/{tap}/statistics");
    let r = |f: &str| root.read_u64(format!("{base}/{f}")).unwrap_or(0);
    root.path(&base).is_dir().then(|| NetDev {
        name: tap.to_owned(),
        rx_bytes: r("rx_bytes"),
        tx_bytes: r("tx_bytes"),
        rx_packets: r("rx_packets"),
        tx_packets: r("tx_packets"),
        rx_dropped: r("rx_dropped"),
        tx_dropped: r("tx_dropped"),
    })
}

/// `dir` is already a host path (see discovery).
fn cgroup(dir: &Path) -> Option<Cgroup> {
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok();
    let mut cpu = parse::cpu_stat(&read("cpu.stat")?);
    cpu.max = read("cpu.max").and_then(|s| parse::cpu_max(&s));
    Some(Cgroup {
        cpu,
        mem_current: read("memory.current").and_then(|s| s.trim().parse().ok()),
        mem_max: read("memory.max").and_then(|s| parse::mem_max(&s)),
        mem_events: read("memory.events").map(|s| parse::mem_events(&s)).unwrap_or_default(),
        io: read("io.stat").map(|s| parse::io_stat(&s)).unwrap_or_default(),
    })
}

pub fn sample_host(root: &Root) -> HostSample {
    let ps = root.read("proc/stat").map(|s| parse::proc_stat(&s)).unwrap_or_default();
    let (total, avail) = root.read("proc/meminfo").map(|s| parse::meminfo(&s)).unwrap_or_default();
    HostSample {
        ts_ns: mono_ns(),
        ncpus: ps.ncpus,
        busy_ns: root.ticks_to_ns(ps.busy_ticks),
        idle_ns: root.ticks_to_ns(ps.idle_ticks),
        mem_total_bytes: total,
        mem_available_bytes: avail,
    }
}

/// Emits one `Sample` per VM, then one `Host` event, every `interval`.
/// The host event marks the end of a tick for consumers that batch.
#[derive(Debug)]
pub struct Sampler {
    pub root: Root,
    pub interval: Duration,
}

impl Sampler {
    pub fn new(root: Root) -> Self {
        Self { root, interval: Duration::from_secs(1) }
    }

    pub fn tick(&self, vms: &VmSet, out: &Sender<Event>) -> bool {
        for vm in vms.snapshot() {
            let ts_ns = mono_ns();
            if let Some(s) = sample_vm(&self.root, &vm) {
                let ev = Event::Sample(vm.id.clone(), Sample { ts_ns, data: SampleData::Proc(s) });
                if out.send(ev).is_err() {
                    return false;
                }
            }
        }
        out.send(Event::Host(sample_host(&self.root))).is_ok()
    }
}

impl Source for Sampler {
    fn name(&self) -> &'static str {
        "host"
    }

    fn needs(&self) -> &'static [Privilege] {
        &[Privilege::PtraceRead]
    }

    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError> {
        while self.tick(&vms, &out) && stop.sleep(self.interval) {}
        Ok(())
    }
}
