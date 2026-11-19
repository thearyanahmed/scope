//! Prometheus text format, version 0.0.4.
//!
//! Exports raw monotonic counters, not rates: Prometheus computes rates
//! itself, and a scrape interval that differs from scope's refresh would
//! otherwise alias. See <https://prometheus.io/docs/instrumenting/exposition_formats/>.

use std::collections::BTreeMap;
use std::fmt::Write;
use telemetry::{Event, FcSample, HostSample, KvmSample, ProcSample, SampleData, Vm, VmEvent, VmId, VmInfo};

#[derive(Debug, Default)]
struct VmState {
    vm: Option<Vm>,
    proc: Option<ProcSample>,
    kvm: Option<KvmSample>,
    fc: Option<FcSample>,
    info: Option<VmInfo>,
}

/// Latest value of everything, folded from events.
#[derive(Debug, Default)]
pub struct State {
    vms: BTreeMap<VmId, VmState>,
    host: Option<HostSample>,
}

impl State {
    pub fn apply(&mut self, ev: &Event) {
        match ev {
            Event::Vm(VmEvent::Appeared(vm)) => self.vms.entry(vm.id.clone()).or_default().vm = Some((**vm).clone()),
            Event::Vm(VmEvent::Gone(id)) => {
                self.vms.remove(id);
            }
            Event::Host(h) => self.host = Some(*h),
            Event::Sample(id, s) => {
                let Some(st) = self.vms.get_mut(id) else { return };
                match &s.data {
                    SampleData::Proc(p) => st.proc = Some(p.clone()),
                    SampleData::Kvm(k) => st.kvm = Some(k.clone()),
                    SampleData::Firecracker(f) => st.fc = Some(f.clone()),
                    SampleData::Info(i) => st.info = Some(i.clone()),
                }
            }
            _ => {}
        }
    }

    pub fn render(&self) -> String {
        let mut w = Writer::default();
        if let Some(h) = &self.host {
            w.family("scope_host_cpu_seconds_total", "counter", "host cpu time from /proc/stat");
            w.sample("scope_host_cpu_seconds_total", &[("mode", "busy")], secs(h.busy_ns));
            w.sample("scope_host_cpu_seconds_total", &[("mode", "idle")], secs(h.idle_ns));
            w.family("scope_host_memory_bytes", "gauge", "host memory from /proc/meminfo");
            w.sample("scope_host_memory_bytes", &[("kind", "total")], h.mem_total_bytes as f64);
            w.sample("scope_host_memory_bytes", &[("kind", "available")], h.mem_available_bytes as f64);
            w.family("scope_host_cpus", "gauge", "online cpus");
            w.sample("scope_host_cpus", &[], h.ncpus as f64);
        }

        w.family("scope_vm_info", "gauge", "one series per discovered firecracker process");
        for (id, s) in &self.vms {
            let Some(vm) = &s.vm else { continue };
            let pid = vm.pid.to_string();
            let version = s.info.as_ref().and_then(|i| i.vmm_version.clone()).unwrap_or_default();
            let jailed = if vm.jailed { "true" } else { "false" };
            w.sample("scope_vm_info", &[("vm", &id.0), ("pid", &pid), ("jailed", jailed), ("version", &version)], 1.0);
        }

        self.vm_families(&mut w);
        w.out
    }

    fn vm_families(&self, w: &mut Writer) {
        type Get = fn(&VmState, &mut Vec<(Vec<(&'static str, String)>, f64)>);
        let families: &[(&str, &str, &str, Get)] = &[
            ("scope_vm_cpu_seconds_total", "counter", "process cpu time; guest is a subset of user", |s, o| {
                if let Some(p) = &s.proc {
                    o.push((vec![("mode", "user".into())], secs(p.cpu.user_ns)));
                    o.push((vec![("mode", "system".into())], secs(p.cpu.system_ns)));
                    o.push((vec![("mode", "guest".into())], secs(p.cpu.guest_ns)));
                }
            }),
            ("scope_vcpu_run_seconds_total", "counter", "vcpu thread on-cpu time (schedstat)", |s, o| {
                for v in s.proc.iter().flat_map(|p| &p.vcpus) {
                    o.push((vec![("vcpu", v.index.to_string())], secs(v.sched.run_ns)));
                }
            }),
            ("scope_vcpu_wait_seconds_total", "counter", "vcpu thread runnable but waiting for a cpu (schedstat)", |s, o| {
                for v in s.proc.iter().flat_map(|p| &p.vcpus) {
                    o.push((vec![("vcpu", v.index.to_string())], secs(v.sched.wait_ns)));
                }
            }),
            ("scope_vcpu_guest_seconds_total", "counter", "vcpu thread time in guest mode", |s, o| {
                for v in s.proc.iter().flat_map(|p| &p.vcpus) {
                    o.push((vec![("vcpu", v.index.to_string())], secs(v.cpu.guest_ns)));
                }
            }),
            ("scope_vm_memory_bytes", "gauge", "firecracker process memory (smaps_rollup)", |s, o| {
                if let Some(m) = s.proc.as_ref().and_then(|p| p.mem) {
                    o.push((vec![("kind", "rss".into())], m.rss_bytes as f64));
                    o.push((vec![("kind", "pss".into())], m.pss_bytes as f64));
                }
            }),
            ("scope_vm_disk_bytes_total", "counter", "process block io (/proc/<pid>/io)", |s, o| {
                if let Some(io) = s.proc.as_ref().and_then(|p| p.io) {
                    o.push((vec![("dir", "read".into())], io.read_bytes as f64));
                    o.push((vec![("dir", "write".into())], io.write_bytes as f64));
                }
            }),
            ("scope_vm_tap_bytes_total", "counter", "host tap counters; host rx is guest tx", |s, o| {
                for n in s.proc.iter().flat_map(|p| &p.net) {
                    o.push((vec![("tap", n.name.clone()), ("dir", "rx".into())], n.rx_bytes as f64));
                    o.push((vec![("tap", n.name.clone()), ("dir", "tx".into())], n.tx_bytes as f64));
                }
            }),
            ("scope_vm_tap_dropped_total", "counter", "host tap drops", |s, o| {
                for n in s.proc.iter().flat_map(|p| &p.net) {
                    o.push((vec![("tap", n.name.clone()), ("dir", "rx".into())], n.rx_dropped as f64));
                    o.push((vec![("tap", n.name.clone()), ("dir", "tx".into())], n.tx_dropped as f64));
                }
            }),
            ("scope_vm_cgroup_throttled_seconds_total", "counter", "cgroup cpu.stat throttled_usec", |s, o| {
                if let Some(c) = s.proc.as_ref().and_then(|p| p.cgroup.as_ref()) {
                    o.push((vec![], c.cpu.throttled_usec as f64 / 1e6));
                }
            }),
            ("scope_vm_cgroup_throttled_periods_total", "counter", "cgroup cpu.stat nr_throttled", |s, o| {
                if let Some(c) = s.proc.as_ref().and_then(|p| p.cgroup.as_ref()) {
                    o.push((vec![], c.cpu.nr_throttled as f64));
                }
            }),
            ("scope_vm_cgroup_memory_bytes", "gauge", "cgroup memory.current and memory.max", |s, o| {
                if let Some(c) = s.proc.as_ref().and_then(|p| p.cgroup.as_ref()) {
                    if let Some(v) = c.mem_current {
                        o.push((vec![("kind", "current".into())], v as f64));
                    }
                    if let Some(v) = c.mem_max {
                        o.push((vec![("kind", "max".into())], v as f64));
                    }
                }
            }),
            ("scope_vm_cgroup_oom_kills_total", "counter", "cgroup memory.events oom_kill", |s, o| {
                if let Some(c) = s.proc.as_ref().and_then(|p| p.cgroup.as_ref()) {
                    o.push((vec![], c.mem_events.oom_kill as f64));
                }
            }),
            ("scope_vm_kvm_total", "counter", "kvm debugfs per-vm counters, raw names", |s, o| {
                for (k, v) in s.kvm.iter().flat_map(|k| &k.vm) {
                    o.push((vec![("stat", k.clone())], *v as f64));
                }
            }),
            ("scope_vm_firecracker_total", "counter", "firecracker metrics counters, summed since scope started", |s, o| {
                for (k, v) in s.fc.iter().flat_map(|f| &f.counters) {
                    o.push((vec![("metric", k.clone())], *v as f64));
                }
            }),
            ("scope_vm_firecracker", "gauge", "firecracker metrics gauges, last value", |s, o| {
                for (k, v) in s.fc.iter().flat_map(|f| &f.gauges) {
                    o.push((vec![("metric", k.clone())], *v as f64));
                }
            }),
        ];
        for (name, kind, help, get) in families {
            let mut any = false;
            for (id, s) in &self.vms {
                let mut rows = vec![];
                get(s, &mut rows);
                for (labels, v) in rows {
                    if !any {
                        w.family(name, kind, help);
                        any = true;
                    }
                    let mut l: Vec<(&str, &str)> = vec![("vm", &id.0)];
                    l.extend(labels.iter().map(|(k, v)| (*k, v.as_str())));
                    w.sample(name, &l, v);
                }
            }
        }
    }
}

fn secs(ns: u64) -> f64 {
    ns as f64 / 1e9
}

#[derive(Default)]
struct Writer {
    out: String,
}

impl Writer {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], v: f64) {
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (k, val)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{k}=\"{}\"", escape(val));
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {v}");
    }
}

/// Label values come from process cmdlines and metrics files, so they are
/// escaped per the exposition format: backslash, double quote, newline.
pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use telemetry::*;

    fn vm(id: &str) -> Vm {
        Vm {
            id: VmId(id.into()),
            pid: 7,
            jailed: true,
            root: "/".into(),
            api_sock: None,
            metrics_path: None,
            config_file: None,
            vcpus: vec![],
            threads: vec![],
            taps: vec![],
            cgroup: None,
            started_ms: 0,
        }
    }

    #[test]
    fn renders_and_escapes() {
        let mut s = State::default();
        s.apply(&Event::Vm(VmEvent::Appeared(Box::new(vm("a\"b\\\nc")))));
        s.apply(&Event::Sample(
            VmId("a\"b\\\nc".into()),
            Sample {
                ts_ns: 0,
                data: SampleData::Proc(ProcSample {
                    cpu: CpuTimes { user_ns: 2_500_000_000, system_ns: 0, guest_ns: 1_000_000_000 },
                    vcpus: vec![VcpuTimes { index: 0, tid: 8, sched: SchedStat { wait_ns: 500_000_000, ..Default::default() }, ..Default::default() }],
                    ..Default::default()
                }),
            },
        ));
        s.apply(&Event::Host(HostSample { ncpus: 4, ..Default::default() }));
        let out = s.render();
        assert!(out.contains(r#"scope_vm_info{vm="a\"b\\\nc",pid="7",jailed="true",version=""} 1"#), "{out}");
        assert!(out.contains(r#"scope_vm_cpu_seconds_total{vm="a\"b\\\nc",mode="user"} 2.5"#), "{out}");
        assert!(out.contains(r#"scope_vcpu_wait_seconds_total{vm="a\"b\\\nc",vcpu="0"} 0.5"#), "{out}");
        assert!(out.contains("scope_host_cpus 4"));
        // families with no samples are omitted entirely
        assert!(!out.contains("scope_vm_kvm_total"));
        // every TYPE line is unique
        let types: Vec<_> = out.lines().filter(|l| l.starts_with("# TYPE")).collect();
        let mut dedup = types.clone();
        dedup.dedup();
        assert_eq!(types.len(), dedup.len());
    }

    #[test]
    fn gone_vm_disappears() {
        let mut s = State::default();
        s.apply(&Event::Vm(VmEvent::Appeared(Box::new(vm("x")))));
        s.apply(&Event::Vm(VmEvent::Gone(VmId("x".into()))));
        assert!(!s.render().contains("vm=\"x\""));
    }
}
