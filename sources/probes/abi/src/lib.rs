//! Map keys/values shared by `ebpf/` (kernel side) and `sources/probes` (loader).
//! Every type is `repr(C)` with explicit padding so both sides agree byte for byte.

#![no_std]

/// `CONFIG` array slots, filled by userspace before attach.
pub mod cfg {
    /// kvm_exit: offset of the primary reason field (x86 `exit_reason`, arm64 `esr_ec`).
    pub const EXIT_REASON_OFF: u32 = 0;
    /// kvm_exit: offset of the secondary field (x86 `isa`, arm64 `ret`). u64::MAX if absent.
    pub const EXIT_AUX_OFF: u32 = 1;
    /// kvm_exit: offset of the guest pc (x86 `guest_rip`, arm64 `vcpu_pc`).
    pub const EXIT_PC_OFF: u32 = 2;
    pub const SWITCH_PREV_PID_OFF: u32 = 3;
    pub const SWITCH_NEXT_PID_OFF: u32 = 4;
    /// nonzero: record guest pcs at exit (`--guest`).
    pub const GUEST: u32 = 5;
    /// byte offset of `address` in `struct vm_fault`.
    pub const VMF_ADDRESS_OFF: u32 = 6;
    /// st_dev / st_ino of scope's /proc/self/ns/pid. When set, programs report
    /// pids in that namespace, matching what scope reads from /proc.
    pub const NS_DEV: u32 = 7;
    pub const NS_INO: u32 = 8;
    pub const LEN: u32 = 10;
}

/// vCPU states for the timeline.
pub mod state {
    pub const GUEST: u32 = 0;
    pub const KERNEL: u32 = 1;
    pub const VMM: u32 = 2;
    pub const OFF: u32 = 3;
    pub const UNKNOWN: u32 = 4;
    pub const COUNT: usize = 4;
}

pub const HIST_BUCKETS: usize = 32;

/// `COUNTS` key: one cpu-clock sample bucket. Stack ids < 0 mean "not captured".
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StackKey {
    pub tgid: u32,
    pub tid: u32,
    pub user: i32,
    pub kernel: i32,
}

/// `EXITS` key. `reason` packs the arch-specific fields: `primary | aux << 16`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExitKey {
    pub tid: u32,
    pub reason: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExitVal {
    pub count: u64,
    pub total_ns: u64,
    pub hist: [u64; HIST_BUCKETS],
}

impl ExitVal {
    pub const ZERO: Self = Self { count: 0, total_ns: 0, hist: [0; HIST_BUCKETS] };
}

/// `VCPU` value: per-vCPU-thread state machine. Present only for vCPU tids,
/// which doubles as the filter for the kvm and sched programs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VcpuState {
    pub state: u32,
    /// state to return to when switched back in.
    pub saved: u32,
    pub since_ns: u64,
    /// set at kvm_exit, cleared at kvm_entry.
    pub exit_ns: u64,
    pub exit_reason: u32,
    pub _pad: u32,
}

impl VcpuState {
    pub const NEW: Self =
        Self { state: state::UNKNOWN, saved: state::UNKNOWN, since_ns: 0, exit_ns: 0, exit_reason: 0, _pad: 0 };
}

/// `TIMELINE` value: ns per state, indexed by `state::*`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Timeline {
    pub ns: [u64; state::COUNT],
}

/// `GUEST_PCS` key.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuestKey {
    pub tid: u32,
    pub _pad: u32,
    pub pc: u64,
}

/// `FAULT_PENDING` value: a uffd fault in flight on one thread.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PendingFault {
    pub ts_ns: u64,
    pub address: u64,
}

/// `FAULTS` ring buffer record.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultEvent {
    pub ts_ns: u64,
    pub address: u64,
    pub wait_ns: u64,
    pub tid: u32,
    pub _pad: u32,
}

#[cfg(all(feature = "user", target_os = "linux"))]
mod pod {
    use super::*;
    // SAFETY: all are repr(C), Copy, and have no implicit padding (checked below).
    unsafe impl aya::Pod for StackKey {}
    unsafe impl aya::Pod for ExitKey {}
    unsafe impl aya::Pod for ExitVal {}
    unsafe impl aya::Pod for VcpuState {}
    unsafe impl aya::Pod for Timeline {}
    unsafe impl aya::Pod for GuestKey {}
    unsafe impl aya::Pod for PendingFault {}
    unsafe impl aya::Pod for FaultEvent {}
}

const _: () = {
    assert!(size_of::<StackKey>() == 16);
    assert!(size_of::<ExitKey>() == 8);
    assert!(size_of::<ExitVal>() == 16 + 8 * HIST_BUCKETS);
    assert!(size_of::<VcpuState>() == 32);
    assert!(size_of::<GuestKey>() == 16);
    assert!(size_of::<FaultEvent>() == 32);
};

/// log2 latency bucket, shared so kernel and userspace histograms line up.
#[inline(always)]
pub fn bucket(ns: u64) -> usize {
    if ns == 0 {
        return 0;
    }
    let b = 63 - ns.leading_zeros() as usize;
    if b >= HIST_BUCKETS { HIST_BUCKETS - 1 } else { b }
}
