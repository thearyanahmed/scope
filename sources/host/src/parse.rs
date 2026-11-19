//! Pure parsers for kernel text formats. No I/O; each takes file contents.
//! Field references are to proc(5) and the cgroup v2 admin guide.

use telemetry::{CgroupCpu, CgroupIo, Mem, MemEvents, ProcIo, SchedStat};

/// Fields of /proc/<pid>/stat (and task/<tid>/stat) that scope uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stat {
    pub ppid: u32,
    pub utime: u64,
    pub stime: u64,
    pub starttime: u64,
    pub guest_time: u64,
}

/// comm may contain spaces and ')' ("fc_vcpu 0"), so split after the last ')'.
pub fn stat(s: &str) -> Option<Stat> {
    let rest = &s[s.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // f[0] is field 3 (state); field n is f[n - 3].
    let n = |i: usize| f.get(i - 3).and_then(|v| v.parse::<u64>().ok());
    Some(Stat {
        ppid: n(4)? as u32,
        utime: n(14)?,
        stime: n(15)?,
        starttime: n(22)?,
        // guest_time appeared in 2.6.24; absent fields mean zero.
        guest_time: n(43).unwrap_or(0),
    })
}

pub fn schedstat(s: &str) -> Option<SchedStat> {
    let mut it = s.split_whitespace().map(|v| v.parse::<u64>().ok());
    Some(SchedStat { run_ns: it.next()??, wait_ns: it.next()??, timeslices: it.next()?? })
}

pub fn cmdline(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
}

/// Value of `--name value` or `--name=value`.
pub fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().map(String::as_str);
        }
        if let Some(v) = a.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
            return Some(v);
        }
    }
    None
}

pub fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// tun/tap fds expose the interface name in fdinfo as `iff:\t<name>`.
pub fn fdinfo_iff(s: &str) -> Option<String> {
    s.lines().find_map(|l| l.strip_prefix("iff:")).map(|v| v.trim().to_owned())
}

/// cgroup v2 path from /proc/<pid>/cgroup (`0::/path`). v1 hierarchies are ignored.
pub fn cgroup_v2(s: &str) -> Option<String> {
    s.lines().find_map(|l| l.strip_prefix("0::")).map(|p| p.trim().to_owned())
}

/// `key value` lines as used by cpu.stat, memory.events, /proc/<pid>/io, smaps_rollup.
pub fn kv(s: &str) -> impl Iterator<Item = (&str, u64)> {
    s.lines().filter_map(|l| {
        let mut it = l.split_whitespace();
        let k = it.next()?.trim_end_matches(':');
        let v = it.next()?.parse().ok()?;
        Some((k, v))
    })
}

pub fn cpu_stat(s: &str) -> CgroupCpu {
    let mut c = CgroupCpu::default();
    for (k, v) in kv(s) {
        match k {
            "usage_usec" => c.usage_usec = v,
            "nr_periods" => c.nr_periods = v,
            "nr_throttled" => c.nr_throttled = v,
            "throttled_usec" => c.throttled_usec = v,
            _ => {}
        }
    }
    c
}

/// `cpu.max` is `<quota|max> <period>`.
pub fn cpu_max(s: &str) -> Option<(u64, u64)> {
    let mut it = s.split_whitespace();
    let quota = it.next()?.parse().ok()?;
    let period = it.next()?.parse().ok()?;
    Some((quota, period))
}

pub fn mem_max(s: &str) -> Option<u64> {
    s.trim().parse().ok()
}

pub fn mem_events(s: &str) -> MemEvents {
    let mut e = MemEvents::default();
    for (k, v) in kv(s) {
        match k {
            "low" => e.low = v,
            "high" => e.high = v,
            "max" => e.max = v,
            "oom" => e.oom = v,
            "oom_kill" => e.oom_kill = v,
            _ => {}
        }
    }
    e
}

/// io.stat lines: `MAJ:MIN rbytes=.. wbytes=.. rios=.. wios=.. dbytes=.. dios=..`.
pub fn io_stat(s: &str) -> CgroupIo {
    let mut io = CgroupIo::default();
    for tok in s.split_whitespace() {
        let Some((k, v)) = tok.split_once('=') else { continue };
        let Ok(v) = v.parse::<u64>() else { continue };
        match k {
            "rbytes" => io.rbytes += v,
            "wbytes" => io.wbytes += v,
            "rios" => io.rios += v,
            "wios" => io.wios += v,
            _ => {}
        }
    }
    io
}

pub fn proc_io(s: &str) -> ProcIo {
    let mut io = ProcIo::default();
    for (k, v) in kv(s) {
        match k {
            "rchar" => io.rchar = v,
            "wchar" => io.wchar = v,
            "syscr" => io.syscr = v,
            "syscw" => io.syscw = v,
            "read_bytes" => io.read_bytes = v,
            "write_bytes" => io.write_bytes = v,
            _ => {}
        }
    }
    io
}

/// smaps_rollup reports kB.
pub fn smaps_rollup(s: &str) -> Mem {
    let mut m = Mem::default();
    for (k, v) in kv(s) {
        match k {
            "Rss" => m.rss_bytes = v * 1024,
            "Pss" => m.pss_bytes = v * 1024,
            _ => {}
        }
    }
    m
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcStat {
    pub ncpus: u32,
    pub busy_ticks: u64,
    pub idle_ticks: u64,
    pub btime: u64,
}

pub fn proc_stat(s: &str) -> ProcStat {
    let mut p = ProcStat::default();
    for l in s.lines() {
        let mut it = l.split_whitespace();
        match it.next() {
            Some("cpu") => {
                let v: Vec<u64> = it.filter_map(|x| x.parse().ok()).collect();
                // user nice system idle iowait irq softirq steal [guest guest_nice]
                // guest time is already folded into user/nice, so it is not added again.
                let g = |i: usize| v.get(i).copied().unwrap_or(0);
                p.busy_ticks = g(0) + g(1) + g(2) + g(5) + g(6) + g(7);
                p.idle_ticks = g(3) + g(4);
            }
            Some(c) if c.starts_with("cpu") => p.ncpus += 1,
            Some("btime") => p.btime = it.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    p
}

/// (MemTotal, MemAvailable) in bytes.
pub fn meminfo(s: &str) -> (u64, u64) {
    let (mut total, mut avail) = (0, 0);
    for (k, v) in kv(s) {
        match k {
            "MemTotal" => total = v * 1024,
            "MemAvailable" => avail = v * 1024,
            _ => {}
        }
    }
    (total, avail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_space_and_paren_in_comm() {
        let s = "4242 (fc_vcpu (0)) S 4200 4242 4200 0 -1 4194624 0 0 0 0 150 30 0 0 20 0 3 0 1234 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 120 0";
        let st = stat(s).unwrap();
        assert_eq!(st.ppid, 4200);
        assert_eq!((st.utime, st.stime, st.starttime, st.guest_time), (150, 30, 1234, 120));
    }

    #[test]
    fn stat_without_guest_time() {
        let s = "1 (init) S 0 1 1 0 -1 0 0 0 0 0 5 6 0 0 20 0 1 0 7 0 0";
        assert_eq!(stat(s).unwrap().guest_time, 0);
        assert!(stat("garbage").is_none());
    }

    #[test]
    fn flags_both_forms() {
        let a = cmdline(b"/usr/bin/firecracker\0--id=vm1\0--api-sock\0/run/fc.sock\0--no-seccomp\0");
        assert_eq!(flag(&a, "--id"), Some("vm1"));
        assert_eq!(flag(&a, "--api-sock"), Some("/run/fc.sock"));
        assert_eq!(flag(&a, "--config-file"), None);
        assert!(has_flag(&a, "--no-seccomp"));
        // prefix of another flag must not match
        assert_eq!(flag(&a, "--i"), None);
    }

    #[test]
    fn small_formats() {
        assert_eq!(schedstat("100 20 3\n").unwrap(), SchedStat { run_ns: 100, wait_ns: 20, timeslices: 3 });
        assert_eq!(fdinfo_iff("pos:\t0\nflags:\t02\nmnt_id:\t9\niff:\ttap0\n").as_deref(), Some("tap0"));
        assert_eq!(cgroup_v2("0::/firecracker/vm1\n").as_deref(), Some("/firecracker/vm1"));
        assert_eq!(cgroup_v2("12:cpu,cpuacct:/x\n"), None);
        assert_eq!(cpu_max("max 100000\n"), None);
        assert_eq!(cpu_max("200000 100000\n"), Some((200000, 100000)));
        assert_eq!(mem_max("max\n"), None);
        assert_eq!(mem_max("536870912\n"), Some(536870912));
    }

    #[test]
    fn io_stat_sums_devices() {
        let io =
            io_stat("8:0 rbytes=10 wbytes=20 rios=1 wios=2 dbytes=0 dios=0\n259:0 rbytes=5 wbytes=5 rios=1 wios=1\n");
        assert_eq!(io, CgroupIo { rbytes: 15, wbytes: 25, rios: 2, wios: 3 });
    }

    #[test]
    fn proc_stat_counts_cpus() {
        let p = proc_stat(
            "cpu  10 1 5 100 4 1 1 2 3 0\ncpu0 5 0 2 50 2 0 0 1 0 0\ncpu1 5 1 3 50 2 1 1 1 3 0\nintr 0\nbtime 1700000000\n",
        );
        assert_eq!(p, ProcStat { ncpus: 2, busy_ticks: 20, idle_ticks: 104, btime: 1700000000 });
    }
}
