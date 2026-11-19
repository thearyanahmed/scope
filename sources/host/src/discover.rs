//! Find firecracker processes and describe them without talking to them.

use crate::{Root, parse};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;
use telemetry::{
    Event, Privilege, Source, SourceError, StopToken, ThreadKind, Vcpu, Vm, VmEvent, VmId, VmSet, VmmThread,
};

/// firecracker's default when `--api-sock` is absent (and `--no-api` is not given).
const DEFAULT_API_SOCK: &str = "/run/firecracker.socket";

/// comm is the executable basename truncated to 15 bytes, so a renamed
/// binary like `firecracker-v1.10` still starts with this.
fn is_firecracker(comm: &str) -> bool {
    comm.trim_end().starts_with("firecracker")
}

pub fn discover(root: &Root) -> Vec<Vm> {
    let Ok(dir) = std::fs::read_dir(root.path("proc")) else { return vec![] };
    let btime = root.read("proc/stat").map(|s| parse::proc_stat(&s).btime).unwrap_or(0);
    let mut out: Vec<Vm> = dir
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| root.read(format!("proc/{pid}/comm")).is_ok_and(|c| is_firecracker(&c)))
        // a process can exit between readdir and here; skip it, the next scan will agree.
        .filter_map(|pid| describe(root, pid, btime))
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn describe(root: &Root, pid: u32, btime: u64) -> Option<Vm> {
    let args = parse::cmdline(&root.read_bytes(format!("proc/{pid}/cmdline")).ok()?);
    let st = parse::stat(&root.read(format!("proc/{pid}/stat")).ok()?)?;

    let proc_root = root.path(format!("proc/{pid}/root"));
    let jailed =
        std::fs::read_link(&proc_root).map(|t| t != Path::new("/")).unwrap_or(false) || parent_is_jailer(root, st.ppid);

    let resolve = |p: &str| resolve(root, pid, p);
    let api_sock = if parse::has_flag(&args, "--no-api") {
        None
    } else {
        Some(resolve(parse::flag(&args, "--api-sock").unwrap_or(DEFAULT_API_SOCK)))
    };
    let config_file = parse::flag(&args, "--config-file").map(resolve);
    let metrics_path = parse::flag(&args, "--metrics-path")
        .map(resolve)
        .or_else(|| config_metrics_path(config_file.as_deref()?).map(|p| resolve(&p)));

    let (vcpus, threads) = threads(root, pid);
    let started_ms = btime * 1000 + st.starttime * 1000 / root.clk_tck.max(1);

    Some(Vm {
        id: parse::flag(&args, "--id").map(|s| VmId(s.to_owned())).unwrap_or_else(|| VmId::from_pid(pid)),
        pid,
        jailed,
        root: proc_root,
        api_sock,
        metrics_path,
        config_file,
        vcpus,
        threads,
        taps: taps(root, pid),
        cgroup: root
            .read(format!("proc/{pid}/cgroup"))
            .ok()
            .and_then(|s| parse::cgroup_v2(&s))
            .map(|p| root.path(Path::new("sys/fs/cgroup").join(p.trim_start_matches('/')))),
        started_ms,
    })
}

/// Paths firecracker was given are relative to its root (absolute) or its cwd (relative).
/// Going through /proc/<pid>/{root,cwd} makes them readable from the host even inside a jail.
fn resolve(root: &Root, pid: u32, p: &str) -> PathBuf {
    match p.strip_prefix('/') {
        Some(abs) => root.path(format!("proc/{pid}/root")).join(abs),
        None => root.path(format!("proc/{pid}/cwd")).join(p),
    }
}

fn parent_is_jailer(root: &Root, ppid: u32) -> bool {
    root.read(format!("proc/{ppid}/comm")).is_ok_and(|c| c.trim() == "jailer")
}

/// `metrics.metrics_path` from a firecracker `--config-file`.
fn config_metrics_path(cfg: &Path) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(cfg).ok()?).ok()?;
    v.get("metrics")?.get("metrics_path")?.as_str().map(str::to_owned)
}

fn threads(root: &Root, pid: u32) -> (Vec<Vcpu>, Vec<VmmThread>) {
    let mut vcpus = vec![];
    let mut threads = vec![];
    let Ok(dir) = std::fs::read_dir(root.path(format!("proc/{pid}/task"))) else {
        return (vcpus, threads);
    };
    for tid in dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok()) {
        let Ok(comm) = root.read(format!("proc/{pid}/task/{tid}/comm")) else { continue };
        let comm = comm.trim_end().to_owned();
        // thread names set by firecracker: "fc_vcpu {index}" (vstate/vcpu.rs), "fc_api".
        if let Some(i) = comm.strip_prefix("fc_vcpu").and_then(|r| r.trim().parse().ok()) {
            vcpus.push(Vcpu { index: i, tid });
            continue;
        }
        let kind = if tid == pid {
            ThreadKind::Vmm
        } else if comm == "fc_api" {
            ThreadKind::Api
        } else {
            ThreadKind::Other
        };
        threads.push(VmmThread { tid, name: comm, kind });
    }
    vcpus.sort_by_key(|v| v.index);
    threads.sort_by_key(|t| t.tid);
    (vcpus, threads)
}

fn taps(root: &Root, pid: u32) -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(root.path(format!("proc/{pid}/fdinfo"))) else { return vec![] };
    let mut out: Vec<String> = dir
        .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
        .filter_map(|s| parse::fdinfo_iff(&s))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Re-scans periodically and keeps [`VmSet`] in sync.
///
/// `Appeared` is also sent when a known VM changes (vCPU threads only exist
/// after InstanceStart, taps can be hot-plugged), so consumers treat it as upsert.
#[derive(Debug)]
pub struct Discovery {
    pub root: Root,
    pub interval: Duration,
}

impl Discovery {
    pub fn new(root: Root) -> Self {
        Self { root, interval: Duration::from_secs(2) }
    }
}

/// Diff two scans. Returned events, applied in order, turn `old` into `new`.
pub fn diff(old: &BTreeMap<VmId, Vm>, new: &[Vm]) -> Vec<Event> {
    let mut evs = vec![];
    let new_ids: BTreeMap<&VmId, &Vm> = new.iter().map(|v| (&v.id, v)).collect();
    for id in old.keys() {
        // a reused id with a new pid is a different VM.
        if new_ids.get(id).is_none_or(|n| n.pid != old[id].pid) {
            evs.push(Event::Vm(VmEvent::Gone(id.clone())));
        }
    }
    for vm in new {
        if old.get(&vm.id) != Some(vm) {
            evs.push(Event::Vm(VmEvent::Appeared(Box::new(vm.clone()))));
        }
    }
    evs
}

impl Source for Discovery {
    fn name(&self) -> &'static str {
        "discovery"
    }

    fn needs(&self) -> &'static [Privilege] {
        &[Privilege::PtraceRead]
    }

    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError> {
        let mut known: BTreeMap<VmId, Vm> = BTreeMap::new();
        loop {
            let now = discover(&self.root);
            for ev in diff(&known, &now) {
                replay_apply(&vms, &mut known, &ev);
                if out.send(ev).is_err() {
                    return Ok(());
                }
            }
            if !stop.sleep(self.interval) {
                return Ok(());
            }
        }
    }
}

fn replay_apply(vms: &VmSet, known: &mut BTreeMap<VmId, Vm>, ev: &Event) {
    match ev {
        Event::Vm(VmEvent::Appeared(vm)) => {
            known.insert(vm.id.clone(), (**vm).clone());
            vms.insert((**vm).clone());
        }
        Event::Vm(VmEvent::Gone(id)) => {
            known.remove(id);
            vms.remove(id);
        }
        _ => {}
    }
}
