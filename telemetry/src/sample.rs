//! Periodic measurements. Counters are monotonically increasing totals;
//! views compute rates from consecutive samples.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// Monotonic nanoseconds on the source's clock.
    pub ts_ns: u64,
    pub data: SampleData,
}

// samples move once through a channel; boxing the big variant would cost more than it saves.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleData {
    Proc(ProcSample),
    Kvm(KvmSample),
    Firecracker(FcSample),
    Info(VmInfo),
}

/// Everything read from /proc, cgroupfs and sysfs for one VM.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcSample {
    pub cpu: CpuTimes,
    pub vcpus: Vec<VcpuTimes>,
    pub threads: Vec<ThreadTimes>,
    pub mem: Option<Mem>,
    pub io: Option<ProcIo>,
    pub net: Vec<NetDev>,
    pub cgroup: Option<Cgroup>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuTimes {
    pub user_ns: u64,
    pub system_ns: u64,
    /// time the kernel accounted as running guest code (KVM_RUN in guest mode).
    /// included in `user_ns` by the kernel.
    pub guest_ns: u64,
}

impl CpuTimes {
    pub fn total_ns(&self) -> u64 {
        self.user_ns + self.system_ns
    }
}

/// From `/proc/<pid>/task/<tid>/schedstat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedStat {
    pub run_ns: u64,
    /// time runnable but waiting for a cpu: the noisy-neighbour signal.
    pub wait_ns: u64,
    pub timeslices: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcpuTimes {
    pub index: u32,
    pub tid: u32,
    pub cpu: CpuTimes,
    pub sched: SchedStat,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadTimes {
    pub tid: u32,
    pub name: String,
    pub cpu: CpuTimes,
    pub sched: SchedStat,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mem {
    pub rss_bytes: u64,
    pub pss_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcIo {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// Host-side tap counters. host rx = guest tx.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetDev {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cgroup {
    pub cpu: CgroupCpu,
    pub mem_current: Option<u64>,
    /// None when `memory.max` is "max".
    pub mem_max: Option<u64>,
    pub mem_events: MemEvents,
    pub io: CgroupIo,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupCpu {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    pub throttled_usec: u64,
    /// (quota_usec, period_usec) from `cpu.max`; None when unlimited.
    pub max: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
}

/// Summed over all devices in `io.stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupIo {
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
}

/// Raw per-VM and per-vCPU counters from KVM debugfs, keyed by file name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvmSample {
    pub vm: BTreeMap<String, u64>,
    pub vcpus: BTreeMap<u32, BTreeMap<String, u64>>,
}

/// Firecracker's own metrics, flattened to dotted keys (`net_eth0.rx_bytes_count`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcSample {
    /// firecracker emits deltas per flush; these are summed since scope started reading.
    pub counters: BTreeMap<String, u64>,
    /// last value seen.
    pub gauges: BTreeMap<String, u64>,
    pub flushes: u64,
}

/// Static facts fetched once from the API socket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmInfo {
    pub vmm_version: Option<String>,
    pub state: Option<String>,
    pub vcpu_count: Option<u32>,
    pub mem_size_mib: Option<u64>,
    pub drives: Vec<String>,
    pub ifaces: Vec<String>,
}

/// Host-wide totals, used for header and overcommit ratios.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSample {
    pub ts_ns: u64,
    pub ncpus: u32,
    pub busy_ns: u64,
    pub idle_ns: u64,
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
}
