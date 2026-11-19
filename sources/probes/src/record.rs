//! `scope flame`: attach, wait, drain maps into events.

use crate::decode::{Arch, decode};
use crate::symbols::Syms;
use crate::{Error, tracefs};
use aya::maps::{Array, HashMap as BpfHashMap, StackTraceMap};
use aya::programs::perf_event::{PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent};
use aya::programs::{PerfEvent, TracePoint};
use aya::{Ebpf, include_bytes_aligned};
use probe_abi::{ExitKey, ExitVal, GuestKey, StackKey, Timeline, VcpuState, cfg, state};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use telemetry::{ExitRecord, StackKind, StackSample, StopToken, VcpuStates, Vm};

pub(crate) static OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/scope-probes"));

#[derive(Debug, Clone)]
pub struct Guest {
    pub vmlinux: PathBuf,
    pub kaslr: u64,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub duration: Duration,
    pub freq: u64,
    pub stacks: bool,
    pub exits: bool,
    /// read guest pcs at exit. Only with the operator's explicit --guest.
    pub guest: Option<Guest>,
    pub debug_file: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Recording {
    pub stacks: Vec<StackSample>,
    pub exits: Vec<ExitRecord>,
    pub timeline: Vec<VcpuStates>,
    pub guest: Vec<StackSample>,
    pub warnings: Vec<String>,
    pub elapsed: Duration,
}

fn e<E: std::fmt::Display>(ctx: &'static str) -> impl FnOnce(E) -> Error {
    move |x| Error(format!("{ctx}: {x}"))
}

pub(crate) fn load() -> Result<Ebpf, Error> {
    Ebpf::load(OBJECT).map_err(e("load ebpf object (needs CAP_BPF + CAP_PERFMON, or root)"))
}

/// (st_dev, st_ino) of our pid namespace, so the programs report pids as /proc shows them.
fn pidns() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata("/proc/self/ns/pid").ok()?;
    Some((m.dev(), m.ino()))
}

pub(crate) fn set_cfg(ebpf: &mut Ebpf, vals: &[(u32, u64)]) -> Result<(), Error> {
    let mut a: Array<_, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").ok_or(Error::new("no CONFIG map"))?).map_err(e("CONFIG"))?;
    for i in 0..cfg::LEN {
        a.set(i, &u64::MAX, 0).map_err(e("CONFIG set"))?;
    }
    if let Some((dev, ino)) = pidns() {
        a.set(cfg::NS_DEV, &dev, 0).map_err(e("CONFIG set"))?;
        a.set(cfg::NS_INO, &ino, 0).map_err(e("CONFIG set"))?;
    }
    for (i, v) in vals {
        a.set(*i, v, 0).map_err(e("CONFIG set"))?;
    }
    Ok(())
}

pub(crate) fn mono_now() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out pointer. bpf_ktime_get_ns reads the same clock.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn attach_tp(ebpf: &mut Ebpf, prog: &str, cat: &str, name: &str) -> Result<(), Error> {
    let p: &mut TracePoint =
        ebpf.program_mut(prog).ok_or(Error::new("missing program"))?.try_into().map_err(e("program type"))?;
    p.load().map_err(e("load tracepoint"))?;
    p.attach(cat, name).map(|_| ()).map_err(|x| Error(format!("attach {cat}:{name}: {x}")))
}

pub fn record(vm: &Vm, o: &Options, stop: &StopToken) -> Result<Recording, Error> {
    let mut rec = Recording::default();
    let arch = Arch::HOST.ok_or(Error::new("unsupported host arch"))?;
    let mut ebpf = load()?;

    let mut conf = vec![(cfg::GUEST, u64::from(o.guest.is_some()))];
    if o.exits {
        let tfs = tracefs::root()
            .ok_or(Error::new("tracefs not mounted at /sys/kernel/tracing or /sys/kernel/debug/tracing"))?;
        let f = tracefs::read(&tfs, "kvm", "kvm_exit")
            .ok_or(Error::new("no kvm:kvm_exit tracepoint (kvm module loaded?)"))?;
        let (primary, aux, pc) = arch.exit_fields();
        let off = |n: &str| tracefs::find(&f, n).map(|f| u64::from(f.offset));
        conf.push((cfg::EXIT_REASON_OFF, off(primary).ok_or(Error(format!("kvm_exit has no {primary}")))?));
        if let Some(a) = off(aux) {
            conf.push((cfg::EXIT_AUX_OFF, a));
        }
        if let Some(p) = off(pc) {
            conf.push((cfg::EXIT_PC_OFF, p));
        }
        let s = tracefs::read(&tfs, "sched", "sched_switch").ok_or(Error::new("no sched:sched_switch"))?;
        let soff = |n: &str| {
            tracefs::find(&s, n).map(|f| u64::from(f.offset)).ok_or(Error(format!("sched_switch has no {n}")))
        };
        conf.push((cfg::SWITCH_PREV_PID_OFF, soff("prev_pid")?));
        conf.push((cfg::SWITCH_NEXT_PID_OFF, soff("next_pid")?));
    }
    set_cfg(&mut ebpf, &conf)?;

    {
        let mut tg: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.map_mut("TGIDS").ok_or(Error::new("no TGIDS"))?).map_err(e("TGIDS"))?;
        tg.insert(&vm.pid, &1, 0).map_err(e("TGIDS insert"))?;
    }
    {
        let mut vc: BpfHashMap<_, u32, VcpuState> =
            BpfHashMap::try_from(ebpf.map_mut("VCPU").ok_or(Error::new("no VCPU"))?).map_err(e("VCPU"))?;
        for v in &vm.vcpus {
            vc.insert(&v.tid, &VcpuState::NEW, 0).map_err(e("VCPU insert"))?;
        }
    }

    if o.stacks {
        let p: &mut PerfEvent =
            ebpf.program_mut("sample").ok_or(Error::new("missing sample"))?.try_into().map_err(e("program type"))?;
        p.load().map_err(e("load perf_event"))?;
        for cpu in aya::util::online_cpus().map_err(|(m, x)| Error(format!("{m}: {x}")))? {
            p.attach(
                PerfEventConfig::Software(SoftwareEvent::CpuClock),
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(o.freq),
                false,
            )
            .map_err(e("attach perf_event"))?;
        }
    }
    if o.exits {
        attach_tp(&mut ebpf, "kvm_exit", "kvm", "kvm_exit")?;
        attach_tp(&mut ebpf, "kvm_entry", "kvm", "kvm_entry")?;
        attach_tp(&mut ebpf, "sched_switch", "sched", "sched_switch")?;
        if let Err(x) = attach_tp(&mut ebpf, "kvm_userspace_exit", "kvm", "kvm_userspace_exit") {
            rec.warnings.push(format!("timeline will fold vmm time into kernel: {x}"));
        }
    }

    let t0 = Instant::now();
    let _ = stop.sleep(o.duration);
    rec.elapsed = t0.elapsed();

    let names: HashMap<u32, String> = vm
        .vcpus
        .iter()
        .map(|v| (v.tid, format!("fc_vcpu {}", v.index)))
        .chain(vm.threads.iter().map(|t| (t.tid, t.name.clone())))
        .collect();
    let vcpu_of: HashMap<u32, u32> = vm.vcpus.iter().map(|v| (v.tid, v.index)).collect();
    let syms = Syms::new();

    if o.stacks {
        drain_stacks(&ebpf, vm, o, &syms, &names, &mut rec)?;
    }
    if o.exits {
        let ex: BpfHashMap<_, ExitKey, ExitVal> =
            BpfHashMap::try_from(ebpf.map("EXITS").ok_or(Error::new("no EXITS"))?).map_err(e("EXITS"))?;
        for r in ex.iter() {
            let (k, v) = r.map_err(e("EXITS iter"))?;
            rec.exits.push(ExitRecord {
                tid: k.tid,
                vcpu: vcpu_of.get(&k.tid).copied(),
                reason: decode(arch, k.reason),
                code: k.reason,
                count: v.count,
                total_ns: v.total_ns,
                hist: v.hist.to_vec(),
            });
        }
        rec.exits.sort_by_key(|a| std::cmp::Reverse(a.total_ns));

        let now = mono_now();
        let tl: BpfHashMap<_, u32, Timeline> =
            BpfHashMap::try_from(ebpf.map("TIMELINE").ok_or(Error::new("no TIMELINE"))?).map_err(e("TIMELINE"))?;
        let vc: BpfHashMap<_, u32, VcpuState> =
            BpfHashMap::try_from(ebpf.map("VCPU").ok_or(Error::new("no VCPU"))?).map_err(e("VCPU"))?;
        for v in &vm.vcpus {
            let mut ns = tl.get(&v.tid, 0).map(|t| t.ns).unwrap_or([0; state::COUNT]);
            // the state each vcpu is in right now has not been closed by a transition yet.
            if let Ok(s) = vc.get(&v.tid, 0)
                && (s.state as usize) < state::COUNT
            {
                ns[s.state as usize] += now.saturating_sub(s.since_ns);
            }
            rec.timeline.push(VcpuStates {
                tid: v.tid,
                vcpu: Some(v.index),
                in_guest_ns: ns[state::GUEST as usize],
                in_kernel_ns: ns[state::KERNEL as usize],
                in_vmm_ns: ns[state::VMM as usize],
                off_cpu_ns: ns[state::OFF as usize],
            });
        }
    }
    if let Some(g) = &o.guest {
        let gp: BpfHashMap<_, GuestKey, u64> =
            BpfHashMap::try_from(ebpf.map("GUEST_PCS").ok_or(Error::new("no GUEST_PCS"))?).map_err(e("GUEST_PCS"))?;
        let entries: Vec<(GuestKey, u64)> = gp.iter().filter_map(Result::ok).collect();
        let pcs: Vec<u64> = entries.iter().map(|(k, _)| k.pc).collect::<HashSet<_>>().into_iter().collect();
        let m = syms.guest(&g.vmlinux, g.kaslr, &pcs);
        for (k, n) in entries {
            rec.guest.push(StackSample {
                tid: k.tid,
                thread: names.get(&k.tid).cloned().unwrap_or_default(),
                kind: StackKind::GuestExitSite,
                frames: vec![m[&k.pc].clone()],
                weight: n,
            });
        }
    }
    Ok(rec)
}

fn drain_stacks(
    ebpf: &Ebpf,
    vm: &Vm,
    o: &Options,
    syms: &Syms,
    names: &HashMap<u32, String>,
    rec: &mut Recording,
) -> Result<(), Error> {
    let counts: BpfHashMap<_, StackKey, u64> =
        BpfHashMap::try_from(ebpf.map("COUNTS").ok_or(Error::new("no COUNTS"))?).map_err(e("COUNTS"))?;
    let stacks = StackTraceMap::try_from(ebpf.map("STACKS").ok_or(Error::new("no STACKS"))?).map_err(e("STACKS"))?;
    let frames = |id: i32| -> Vec<u64> {
        if id < 0 {
            return vec![];
        }
        // bpf stacks are innermost-first; flamegraphs want the root first.
        stacks.get(&(id as u32), 0).map(|s| s.frames().iter().rev().map(|f| f.ip).collect()).unwrap_or_default()
    };
    let mut raw = vec![];
    let (mut uips, mut kips) = (HashSet::new(), HashSet::new());
    let mut lost = 0u64;
    for r in counts.iter() {
        let (k, n) = r.map_err(e("COUNTS iter"))?;
        let (u, kf) = (frames(k.user), frames(k.kernel));
        lost += u64::from(k.user < 0 && k.kernel < 0) * n;
        uips.extend(u.iter().copied());
        kips.extend(kf.iter().copied());
        raw.push((k, u, kf, n));
    }
    if lost > 0 {
        rec.warnings.push(format!("{lost} samples without any stack (stack map full or unwinding failed)"));
    }
    let uips: Vec<u64> = uips.into_iter().collect();
    let kips: Vec<u64> = kips.into_iter().collect();
    let (um, warn) = syms.user(vm.pid, o.debug_file.as_deref(), &uips);
    rec.warnings.extend(warn);
    let km = syms.kernel(&kips);
    if !uips.is_empty() && uips.iter().all(|a| um[a].starts_with("0x")) {
        rec.warnings
            .push("no user symbols resolved: firecracker release binaries are stripped; pass --debug-file".into());
    }
    for (k, u, kf, n) in raw {
        let mut fr: Vec<String> = u.iter().map(|a| um[a].clone()).collect();
        fr.extend(kf.iter().map(|a| km[a].clone()));
        rec.stacks.push(StackSample {
            tid: k.tid,
            thread: names.get(&k.tid).cloned().unwrap_or_else(|| format!("tid {}", k.tid)),
            kind: if u.is_empty() { StackKind::HostKernel } else { StackKind::Vmm },
            frames: fr,
            weight: n,
        });
    }
    Ok(())
}
