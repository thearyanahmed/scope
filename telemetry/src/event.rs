use crate::{HostSample, Sample, Vm, VmId};
use serde::{Deserialize, Serialize};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Vm(VmEvent),
    Host(HostSample),
    Sample(VmId, Sample),
    Exit(VmId, ExitRecord),
    Stack(VmId, StackSample),
    Timeline(VmId, VcpuStates),
    Fault(VmId, FaultRecord),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmEvent {
    Appeared(Box<Vm>),
    Gone(VmId),
}

pub const HIST_BUCKETS: usize = 32;

/// Aggregated kvm exits for one (vcpu thread, reason).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitRecord {
    pub tid: u32,
    pub vcpu: Option<u32>,
    /// decoded, arch-specific, e.g. "IO_INSTRUCTION" or "DABT_LOW".
    pub reason: String,
    pub code: u32,
    pub count: u64,
    /// time outside the guest attributed to this reason.
    pub total_ns: u64,
    /// bucket i counts exits with latency in [2^i, 2^(i+1)) ns.
    pub hist: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StackKind {
    /// firecracker userspace.
    Vmm,
    HostKernel,
    /// guest pc at exit; biased toward exit sites.
    GuestExitSite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackSample {
    pub tid: u32,
    pub thread: String,
    pub kind: StackKind,
    /// outermost frame first.
    pub frames: Vec<String>,
    pub weight: u64,
}

/// Where one vCPU spent its time during a recording.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcpuStates {
    pub tid: u32,
    pub vcpu: Option<u32>,
    pub in_guest_ns: u64,
    /// exited, handled in kvm without returning to firecracker.
    pub in_kernel_ns: u64,
    /// exited to firecracker for device emulation (KVM_RUN returned).
    pub in_vmm_ns: u64,
    pub off_cpu_ns: u64,
}

pub mod fault_flags {
    pub const WRITE: u16 = 1 << 0;
    pub const MINOR: u16 = 1 << 1;
    pub const PREFETCHED: u16 = 1 << 2;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRecord {
    pub ts_ns: u64,
    /// offset into guest memory (not a host address).
    pub offset: u64,
    pub page_size: u32,
    pub resolve_ns: u32,
    pub flags: u16,
}

/// log2 bucket for a latency, saturating at the last bucket.
pub fn hist_bucket(ns: u64) -> usize {
    if ns == 0 {
        return 0;
    }
    (63 - ns.leading_zeros() as usize).min(HIST_BUCKETS - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn buckets() {
        assert_eq!(hist_bucket(0), 0);
        assert_eq!(hist_bucket(1), 0);
        assert_eq!(hist_bucket(2), 1);
        assert_eq!(hist_bucket(1023), 9);
        assert_eq!(hist_bucket(1024), 10);
        assert_eq!(hist_bucket(u64::MAX), HIST_BUCKETS - 1);
    }

    #[test]
    fn event_json_roundtrip() {
        let ev = Event::Sample(
            VmId("vm1".into()),
            Sample {
                ts_ns: 5,
                data: SampleData::Proc(ProcSample {
                    cpu: CpuTimes { user_ns: 1, system_ns: 2, guest_ns: 1 },
                    ..Default::default()
                }),
            },
        );
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.starts_with(r#"{"sample":["vm1""#), "{s}");
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
    }
}
