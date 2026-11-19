//! scope's kernel-side programs. One object; the loader attaches only what a
//! command needs. Tracepoint field offsets are not hardcoded: userspace reads
//! them from tracefs `format` files and writes them into `CONFIG`.

#![no_std]
#![no_main]

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};
use aya_ebpf::macros::{kprobe, kretprobe, map, perf_event, tracepoint};
use aya_ebpf::maps::{Array, HashMap, RingBuf, StackTrace};
use aya_ebpf::programs::tracing::StackIdContext;
use aya_ebpf::programs::{PerfEventContext, ProbeContext, RetProbeContext, TracePointContext};
use probe_abi::{
    ExitKey, ExitVal, FaultEvent, GuestKey, PendingFault, StackKey, Timeline, VcpuState, bucket, cfg, state,
};

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(cfg::LEN, 0);
/// firecracker pids (tgids) being profiled.
#[map]
static TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);
/// vCPU tid -> state machine. Membership is the vCPU filter.
#[map]
static VCPU: HashMap<u32, VcpuState> = HashMap::with_max_entries(4096, 0);
#[map]
static STACKS: StackTrace = StackTrace::with_max_entries(16384, 0);
#[map]
static COUNTS: HashMap<StackKey, u64> = HashMap::with_max_entries(65536, 0);
#[map]
static EXITS: HashMap<ExitKey, ExitVal> = HashMap::with_max_entries(16384, 0);
#[map]
static TIMELINE: HashMap<u32, Timeline> = HashMap::with_max_entries(4096, 0);
#[map]
static GUEST_PCS: HashMap<GuestKey, u64> = HashMap::with_max_entries(65536, 0);
/// pids whose uffd faults are traced (scope fault record).
#[map]
static FAULT_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static FAULT_PENDING: HashMap<u32, PendingFault> = HashMap::with_max_entries(4096, 0);
#[map]
static FAULTS: RingBuf = RingBuf::with_byte_size(1 << 22, 0);

#[inline(always)]
fn conf(i: u32) -> u64 {
    CONFIG.get(i).copied().unwrap_or(u64::MAX)
}

#[inline(always)]
fn ids() -> (u32, u32) {
    let v = bpf_get_current_pid_tgid();
    ((v >> 32) as u32, v as u32)
}

#[inline(always)]
fn now() -> u64 {
    // SAFETY: helper with no preconditions.
    unsafe { bpf_ktime_get_ns() }
}

#[inline(always)]
fn add(map: &HashMap<StackKey, u64>, k: &StackKey) {
    match map.get_ptr_mut(k) {
        // SAFETY: pointer from the map lookup is valid for this program invocation.
        // one key = one thread, which can't run on two cpus at once, so no atomics needed.
        Some(v) => unsafe { *v += 1 },
        None => {
            let _ = map.insert(k, &1, 0);
        }
    }
}

// ---------------------------------------------------------------- sampler

#[perf_event]
pub fn sample(ctx: PerfEventContext) -> u32 {
    let (tgid, tid) = ids();
    // SAFETY: map lookup returns a reference valid for this invocation.
    if unsafe { TGIDS.get(&tgid) }.is_none() {
        return 0;
    }
    let user = ctx.get_stackid(&STACKS, BPF_F_USER_STACK as u64).map_or(-1, |v| v as i32);
    let kernel = ctx.get_stackid(&STACKS, 0).map_or(-1, |v| v as i32);
    add(&COUNTS, &StackKey { tgid, tid, user, kernel });
    0
}

// ---------------------------------------------------------------- vcpu timeline + exits

#[inline(always)]
fn transition(s: &mut VcpuState, tid: u32, to: u32, t: u64) {
    if s.state < state::COUNT as u32 {
        let d = t.saturating_sub(s.since_ns);
        match TIMELINE.get_ptr_mut(&tid) {
            // SAFETY: valid map pointer, single writer per tid.
            Some(tl) => unsafe { (*tl).ns[s.state as usize & 3] += d },
            None => {
                let mut tl = Timeline::default();
                tl.ns[s.state as usize & 3] = d;
                let _ = TIMELINE.insert(&tid, &tl, 0);
            }
        }
    }
    s.state = to;
    s.since_ns = t;
}

#[inline(always)]
fn read_u32(ctx: &TracePointContext, slot: u32) -> u32 {
    let off = conf(slot);
    if off == u64::MAX {
        return 0;
    }
    // SAFETY: offset comes from the tracepoint's own format file; read_at uses probe_read.
    unsafe { ctx.read_at::<u32>(off as usize) }.unwrap_or(0)
}

#[tracepoint(category = "kvm", name = "kvm_exit")]
pub fn kvm_exit(ctx: TracePointContext) -> u32 {
    let (_, tid) = ids();
    let Some(s) = VCPU.get_ptr_mut(&tid) else { return 0 };
    let t = now();
    let reason = (read_u32(&ctx, cfg::EXIT_REASON_OFF) & 0xffff) | (read_u32(&ctx, cfg::EXIT_AUX_OFF) << 16);
    // SAFETY: valid map pointer, single writer per tid.
    let s = unsafe { &mut *s };
    transition(s, tid, state::KERNEL, t);
    s.exit_ns = t;
    s.exit_reason = reason;

    if conf(cfg::GUEST) == 1 {
        let off = conf(cfg::EXIT_PC_OFF);
        if off != u64::MAX {
            // SAFETY: as in read_u32.
            let pc = unsafe { ctx.read_at::<u64>(off as usize) }.unwrap_or(0);
            let k = GuestKey { tid, _pad: 0, pc };
            match GUEST_PCS.get_ptr_mut(&k) {
                // SAFETY: valid map pointer.
                Some(v) => unsafe { *v += 1 },
                None => {
                    let _ = GUEST_PCS.insert(&k, &1, 0);
                }
            }
        }
    }
    0
}

#[tracepoint(category = "kvm", name = "kvm_entry")]
pub fn kvm_entry(_ctx: TracePointContext) -> u32 {
    let (_, tid) = ids();
    let Some(s) = VCPU.get_ptr_mut(&tid) else { return 0 };
    let t = now();
    // SAFETY: valid map pointer, single writer per tid.
    let s = unsafe { &mut *s };
    transition(s, tid, state::GUEST, t);
    if s.exit_ns != 0 {
        let d = t.saturating_sub(s.exit_ns);
        let k = ExitKey { tid, reason: s.exit_reason };
        match EXITS.get_ptr_mut(&k) {
            // SAFETY: valid map pointer.
            Some(v) => unsafe {
                (*v).count += 1;
                (*v).total_ns += d;
                (*v).hist[bucket(d) & 31] += 1;
            },
            None => {
                let mut v = ExitVal::ZERO;
                v.count = 1;
                v.total_ns = d;
                v.hist[bucket(d) & 31] = 1;
                let _ = EXITS.insert(&k, &v, 0);
            }
        }
        s.exit_ns = 0;
    }
    0
}

/// KVM_RUN returned to firecracker: device emulation (io/mmio) happens in userspace now.
#[tracepoint(category = "kvm", name = "kvm_userspace_exit")]
pub fn kvm_userspace_exit(_ctx: TracePointContext) -> u32 {
    let (_, tid) = ids();
    if let Some(s) = VCPU.get_ptr_mut(&tid) {
        // SAFETY: valid map pointer, single writer per tid.
        transition(unsafe { &mut *s }, tid, state::VMM, now());
    }
    0
}

#[tracepoint(category = "sched", name = "sched_switch")]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    let t = now();
    let prev = read_u32(&ctx, cfg::SWITCH_PREV_PID_OFF);
    let next = read_u32(&ctx, cfg::SWITCH_NEXT_PID_OFF);
    if let Some(s) = VCPU.get_ptr_mut(&prev) {
        // SAFETY: valid map pointer; this cpu is the only one touching prev right now.
        let s = unsafe { &mut *s };
        s.saved = s.state;
        transition(s, prev, state::OFF, t);
    }
    if let Some(s) = VCPU.get_ptr_mut(&next) {
        // SAFETY: as above for next.
        let s = unsafe { &mut *s };
        if s.state == state::OFF {
            let back = s.saved;
            transition(s, next, back, t);
        }
    }
    0
}

// ---------------------------------------------------------------- passive uffd faults

/// handle_userfault(struct vm_fault *vmf, unsigned long reason): the faulting
/// thread enters here and sleeps until the handler resolves the page.
#[kprobe]
pub fn uffd_enter(ctx: ProbeContext) -> u32 {
    let (tgid, tid) = ids();
    // SAFETY: map lookup.
    if unsafe { FAULT_TGIDS.get(&tgid) }.is_none() {
        return 0;
    }
    let Some(vmf) = ctx.arg::<u64>(0) else { return 0 };
    let off = conf(cfg::VMF_ADDRESS_OFF);
    if off == u64::MAX {
        return 0;
    }
    // SAFETY: vmf is a kernel pointer argument; probe_read handles faults.
    let address = unsafe { aya_ebpf::helpers::bpf_probe_read_kernel((vmf + off) as *const u64) }.unwrap_or(0);
    let _ = FAULT_PENDING.insert(&tid, &PendingFault { ts_ns: now(), address }, 0);
    0
}

#[kretprobe]
pub fn uffd_exit(_ctx: RetProbeContext) -> u32 {
    let (_, tid) = ids();
    // SAFETY: map lookup.
    let Some(p) = (unsafe { FAULT_PENDING.get(&tid) }).copied() else { return 0 };
    let _ = FAULT_PENDING.remove(&tid);
    let ev = FaultEvent { ts_ns: p.ts_ns, address: p.address, wait_ns: now().saturating_sub(p.ts_ns), tid, _pad: 0 };
    let _ = FAULTS.output(&ev, 0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// helpers like bpf_probe_read_kernel and get_stackid on kernels we target require a gpl license.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
