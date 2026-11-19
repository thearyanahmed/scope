#![allow(clippy::unwrap_used)]
use telemetry::*;
use top::{Level, Model, Thresholds};

fn vm() -> Vm {
    Vm {
        id: VmId("vm1".into()),
        pid: 10,
        jailed: true,
        root: "/proc/10/root".into(),
        api_sock: None,
        metrics_path: None,
        config_file: None,
        vcpus: vec![Vcpu { index: 0, tid: 11 }, Vcpu { index: 1, tid: 12 }],
        threads: vec![],
        taps: vec!["tap0".into()],
        cgroup: Some("/sys/fs/cgroup/fc/vm1".into()),
        started_ms: 1_000,
    }
}

const S: u64 = 1_000_000_000;

/// one second of a VM that burns 1.5 cores, 1.2 of them in the guest.
fn proc(t: u64) -> ProcSample {
    let v = |index, tid, run, wait| VcpuTimes {
        index,
        tid,
        cpu: CpuTimes { user_ns: run, system_ns: 0, guest_ns: run * 8 / 10 },
        sched: SchedStat { run_ns: run, wait_ns: wait, timeslices: 0 },
    };
    ProcSample {
        cpu: CpuTimes { user_ns: t * 1_200_000_000, system_ns: t * 300_000_000, guest_ns: t * 1_200_000_000 },
        vcpus: vec![v(0, 11, t * 900_000_000, t * 50_000_000), v(1, 12, t * 600_000_000, t * 300_000_000)],
        threads: vec![],
        mem: Some(Mem { rss_bytes: 512 << 20, pss_bytes: 500 << 20 }),
        io: Some(ProcIo { read_bytes: t * 4096, write_bytes: t * 8192, ..Default::default() }),
        net: vec![NetDev { name: "tap0".into(), rx_bytes: t * 100, tx_bytes: t * 1000, rx_dropped: t, ..Default::default() }],
        cgroup: Some(Cgroup {
            cpu: CgroupCpu { throttled_usec: t * 100_000, nr_throttled: t * 10, ..Default::default() },
            mem_current: Some(900),
            mem_max: Some(1000),
            mem_events: MemEvents { oom_kill: t, ..Default::default() },
            ..Default::default()
        }),
    }
}

fn sample(t: u64, data: SampleData) -> Event {
    Event::Sample(VmId("vm1".into()), Sample { ts_ns: t * S, data })
}

#[test]
fn first_sample_has_no_rates() {
    let mut m = Model::default();
    m.apply(&Event::Vm(VmEvent::Appeared(Box::new(vm()))));
    m.apply(&sample(1, SampleData::Proc(proc(1))));
    let r = &m.rows(Some(11_000))[0];
    assert_eq!(r.cpu_pct, None);
    assert_eq!(r.uptime_s, Some(10));
    assert_eq!(r.rss_bytes, Some(512 << 20));
    assert_eq!(r.mem_pct, Some(90.0));
    assert_eq!(r.level, Level::Warn, "90% of memory.max is past the 85% warn line");
}

#[test]
fn rates_over_one_interval() {
    let mut m = Model::new(Thresholds::default());
    m.apply(&Event::Vm(VmEvent::Appeared(Box::new(vm()))));
    m.apply(&sample(1, SampleData::Proc(proc(1))));
    m.apply(&sample(2, SampleData::Proc(proc(2))));
    let r = &m.rows(None)[0];

    let close = |a: Option<f64>, b: f64| assert!((a.unwrap() - b).abs() < 1e-6, "{a:?} != {b}");
    close(r.cpu_pct, 150.0);
    close(r.guest_pct, 120.0);
    close(r.vmm_pct, 30.0);
    close(Some(r.vcpus[1].wait_pct), 30.0);
    close(r.max_wait_pct, 30.0);
    close(r.throttle_pct, 10.0);
    close(r.disk_write_bps, 8192.0);
    // guest rx comes from host tap tx
    close(r.net_rx_bps, 1000.0);
    close(r.net_tx_bps, 100.0);
    assert_eq!(r.new_oom_kills, Some(1));

    let names: Vec<_> = r.flags.iter().map(|(n, l)| (n.as_str(), *l)).collect();
    assert_eq!(names, [("wait", Level::Crit), ("throttle", Level::Warn), ("mem", Level::Warn), ("oom_kill", Level::Crit)]);
    assert_eq!(r.level, Level::Crit);
    assert_eq!(m.history(&VmId("vm1".into())).count(), 2);
}

#[test]
fn kvm_exits_and_header() {
    let mut m = Model::default();
    m.apply(&Event::Vm(VmEvent::Appeared(Box::new(vm()))));
    let kvm = |exits| {
        SampleData::Kvm(KvmSample { vm: [("exits".to_owned(), exits), ("halt_exits".to_owned(), exits / 2)].into(), ..Default::default() })
    };
    m.apply(&sample(1, kvm(1000)));
    m.apply(&sample(3, kvm(301_000)));
    m.apply(&sample(3, SampleData::Info(VmInfo { vcpu_count: Some(2), mem_size_mib: Some(1024), ..Default::default() })));
    let host = |t: u64, busy, idle| Event::Host(HostSample { ts_ns: t, ncpus: 4, busy_ns: busy, idle_ns: idle, mem_total_bytes: 4 << 30, mem_available_bytes: 1 << 30 });
    m.apply(&host(1, 0, 0));
    m.apply(&host(2, 3 * S, S));

    let r = &m.rows(None)[0];
    assert_eq!(r.exits_per_s, Some(150_000.0));
    assert_eq!(r.halt_exits_per_s, Some(75_000.0));
    assert_eq!(r.flags, [("exits".to_owned(), Level::Warn)]);

    let h = m.header();
    assert_eq!(h.host_cpu_pct, Some(75.0));
    assert_eq!(h.cpu_overcommit, Some(0.5));
    assert_eq!(h.mem_overcommit, Some(0.25));
}

#[test]
fn gone_removes_row() {
    let mut m = Model::default();
    m.apply(&Event::Vm(VmEvent::Appeared(Box::new(vm()))));
    m.apply(&Event::Vm(VmEvent::Gone(VmId("vm1".into()))));
    assert!(m.rows(None).is_empty());
    // samples for an unknown vm are dropped, not resurrected
    m.apply(&sample(1, SampleData::Proc(proc(1))));
    assert!(m.rows(None).is_empty());
}
