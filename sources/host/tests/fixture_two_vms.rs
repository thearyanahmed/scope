#![allow(clippy::unwrap_used)]
use host::{Root, discover, sample_host, sample_vm};
use std::collections::BTreeMap;
use std::path::PathBuf;
use telemetry::{Event, ThreadKind, VmEvent, VmId};

fn root() -> Root {
    Root::at(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/host/two-vms"))
}

#[test]
fn discovers_plain_and_jailed() {
    let r = root();
    let vms = discover(&r);
    let ids: Vec<&str> = vms.iter().map(|v| v.id.0.as_str()).collect();
    assert_eq!(ids, ["pid-1000", "vm-b"]);

    let a = &vms[0];
    assert!(!a.jailed);
    assert_eq!(a.api_sock.as_deref(), Some(r.path("proc/1000/cwd/fc-a.sock").as_path()));
    assert_eq!(a.metrics_path.as_deref(), Some(r.path("proc/1000/root/tmp/fc-a.metrics").as_path()));
    assert_eq!(a.vcpus.iter().map(|v| (v.index, v.tid)).collect::<Vec<_>>(), [(0, 1002), (1, 1003)]);
    assert_eq!(a.threads.iter().map(|t| t.kind).collect::<Vec<_>>(), [ThreadKind::Vmm, ThreadKind::Api]);
    assert_eq!(a.taps, ["tap-a0"]);
    // btime 1763500000 s + starttime 5000 ticks / 100
    assert_eq!(a.started_ms, 1_763_500_050_000);

    let b = &vms[1];
    assert!(b.jailed);
    assert_eq!(b.api_sock.as_deref(), Some(r.path("proc/2000/root/run/firecracker.socket").as_path()));
    // metrics path comes from the config file inside the jail
    assert_eq!(b.metrics_path.as_deref(), Some(r.path("proc/2000/root/metrics.fifo").as_path()));
    assert!(b.metrics_path.as_ref().unwrap().exists(), "jail path must resolve through the root symlink");
    assert_eq!(b.taps, ["tap-b0", "tap-b1"]);
    assert_eq!(b.cgroup.as_deref(), Some(r.path("sys/fs/cgroup/firecracker/vm-b").as_path()));
}

#[test]
fn samples_vm() {
    let r = root();
    let vms = discover(&r);
    let b = sample_vm(&r, &vms[1]).unwrap();

    assert_eq!(b.cpu.user_ns, 4_000_000_000);
    assert_eq!(b.cpu.guest_ns, 3_500_000_000);
    assert_eq!(b.vcpus.len(), 2);
    assert_eq!(b.vcpus[0].sched.wait_ns, 900_000_000);
    assert_eq!(b.mem.unwrap().rss_bytes, 524288 * 1024);
    let cg = b.cgroup.unwrap();
    assert_eq!((cg.cpu.nr_throttled, cg.cpu.max), (40, Some((200000, 100000))));
    assert_eq!(cg.mem_max, Some(603979776));
    assert_eq!(cg.mem_events.max, 3);
    assert_eq!(cg.io.wbytes, 2097152);
    // tap-b1 has no sysfs entry; it is skipped, not zero-filled
    assert_eq!(b.net.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["tap-b0"]);
    assert_eq!(b.net[0].tx_dropped, 2);

    let a = sample_vm(&r, &vms[0]).unwrap();
    assert!(a.cgroup.is_none(), "user.slice has no files in the fixture");
    assert_eq!(a.io.unwrap().write_bytes, 8192);
}

#[test]
fn host_totals() {
    let h = sample_host(&root());
    assert_eq!(h.ncpus, 4);
    assert_eq!(h.mem_total_bytes, 8_000_000 * 1024);
    assert_eq!(h.busy_ns, (4000 + 1000 + 10 + 20 + 30) * 10_000_000);
}

#[test]
fn vanished_vm_yields_no_sample() {
    let r = root();
    let mut vm = discover(&r).remove(0);
    vm.pid = 999_999;
    assert!(sample_vm(&r, &vm).is_none());
}

#[test]
fn diff_reports_changes() {
    let r = root();
    let now = discover(&r);
    let empty = BTreeMap::new();
    assert_eq!(host::discover::diff(&empty, &now).len(), 2);

    let mut known: BTreeMap<VmId, _> = now.iter().map(|v| (v.id.clone(), v.clone())).collect();
    assert!(host::discover::diff(&known, &now).is_empty());

    // same id, new pid: gone then appeared
    known.get_mut(&VmId("vm-b".into())).unwrap().pid = 1;
    let evs = host::discover::diff(&known, &now);
    assert!(matches!(&evs[0], Event::Vm(VmEvent::Gone(id)) if id.0 == "vm-b"));
    assert!(matches!(&evs[1], Event::Vm(VmEvent::Appeared(v)) if v.pid == 2000));

    // vm removed
    let evs = host::discover::diff(&known, &now[..1]);
    assert_eq!(evs.len(), 1);
}
