//! Passive `scope fault record`: observe uffd faults of a VM whose handler is
//! someone else. kprobe on handle_userfault() marks entry; the kretprobe fires
//! when the handler has resolved the page and the thread wakes, so the
//! difference is the vCPU's stall.
//!
//! Offsets: the trace format wants memory-file offsets, but a passive observer
//! only sees host addresses. Each fault's mapping is looked up in
//! /proc/<pid>/maps; regions are laid out in host-address order. That matches
//! the snapshot file exactly for single-region VMs and is approximate otherwise.

use crate::Error;
use crate::record::{load, mono_now, set_cfg};
use aya::maps::{HashMap as BpfHashMap, RingBuf};
use aya::programs::KProbe;
use probe_abi::{FaultEvent, cfg};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use telemetry::trace::{Entry, Header, Region};
use telemetry::{FaultRecord, StopToken, Vm};

/// `address` in `struct vm_fault`: after vma (8), gfp_mask (4 + 4 pad) / flags + gfp_mask, pgoff (8).
/// Same offset in 5.10 and 6.x layouts on 64-bit. todo: read it from BTF.
pub const VMF_ADDRESS_OFF: u64 = 24;

#[derive(Debug, Default)]
pub struct Captured {
    pub header: Option<Header>,
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
}

fn maps_entry(pid: u32, addr: u64) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    s.lines().find_map(|l| {
        let (a, b) = l.split_whitespace().next()?.split_once('-')?;
        let (a, b) = (u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(b, 16).ok()?);
        (addr >= a && addr < b).then_some((a, b - a))
    })
}

/// `on_ready` runs once the probes are attached; faults before that are not seen.
pub fn record(
    vm: &Vm,
    page_size: u32,
    duration: Option<Duration>,
    stop: &StopToken,
    on_ready: impl FnOnce(),
) -> Result<Captured, Error> {
    let mut ebpf = load()?;
    set_cfg(&mut ebpf, &[(cfg::VMF_ADDRESS_OFF, VMF_ADDRESS_OFF)])?;
    {
        let mut m: BpfHashMap<_, u32, u8> =
            BpfHashMap::try_from(ebpf.map_mut("FAULT_TGIDS").ok_or(Error::new("no FAULT_TGIDS"))?)
                .map_err(|x| Error(x.to_string()))?;
        m.insert(&vm.pid, &1, 0).map_err(|x| Error(x.to_string()))?;
    }
    for (prog, what) in [("uffd_enter", "kprobe"), ("uffd_exit", "kretprobe")] {
        let p: &mut KProbe = ebpf
            .program_mut(prog)
            .ok_or(Error::new("missing program"))?
            .try_into()
            .map_err(|x| Error(format!("{x}")))?;
        p.load().map_err(|x| Error(format!("load {what}: {x}")))?;
        p.attach("handle_userfault", 0).map_err(|x| Error(format!("attach {what} handle_userfault: {x}")))?;
    }
    let mut ring =
        RingBuf::try_from(ebpf.take_map("FAULTS").ok_or(Error::new("no FAULTS"))?).map_err(|x| Error(x.to_string()))?;

    on_ready();
    let start = Instant::now();
    let mut raw: Vec<FaultEvent> = vec![];
    let mut drain = |raw: &mut Vec<FaultEvent>| {
        let mut got = false;
        while let Some(item) = ring.next() {
            if item.len() >= size_of::<FaultEvent>() {
                // SAFETY: the kernel side wrote exactly one FaultEvent per record; read_unaligned
                // because ring buffer records are only 8-byte aligned by convention.
                raw.push(unsafe { (item.as_ptr() as *const FaultEvent).read_unaligned() });
                got = true;
            }
        }
        got
    };
    while !stop.is_stopped() && duration.is_none_or(|d| start.elapsed() < d) {
        if !drain(&mut raw) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // events committed between the last poll and stop.
    drain(&mut raw);

    let mut out = Captured::default();
    if raw.is_empty() {
        // tells "no faults happened" apart from "entered but never returned" (handler stuck).
        let pending = ebpf
            .map("FAULT_PENDING")
            .and_then(|m| BpfHashMap::<_, u32, probe_abi::PendingFault>::try_from(m).ok())
            .map_or(0, |m| m.keys().count());
        out.warnings.push(format!("no uffd faults observed for pid {} ({pending} still in flight)", vm.pid));
        return Ok(out);
    }
    let mut regions: Vec<(u64, u64)> = vec![];
    for f in &raw {
        if !regions.iter().any(|(b, s)| f.address >= *b && f.address < b + s) {
            match maps_entry(vm.pid, f.address) {
                Some(r) => regions.push(r),
                None => out.warnings.push(format!("fault at {:#x} outside any mapping", f.address)),
            }
        }
    }
    regions.sort();
    if regions.len() > 1 {
        out.warnings.push(format!(
            "{} memory regions: offsets assume the snapshot file follows host address order",
            regions.len()
        ));
    }
    let mut off = 0;
    let header_regions: Vec<Region> = regions
        .iter()
        .map(|(b, s)| {
            let r = Region { host_base: *b, size: *s, file_offset: off };
            off += s;
            r
        })
        .collect();

    let t0 = raw.iter().map(|f| f.ts_ns).min().unwrap_or(0);
    let unix_now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let header = Header {
        page_size,
        t0_unix_ns: unix_now.saturating_sub(mono_now().saturating_sub(t0)),
        regions: header_regions.clone(),
    };
    let ps = u64::from(page_size);
    raw.sort_by_key(|f| f.ts_ns);
    for f in raw {
        let Some(r) = header_regions.iter().find(|r| f.address >= r.host_base && f.address < r.host_base + r.size)
        else {
            continue;
        };
        out.entries.push(Entry {
            fault: FaultRecord {
                ts_ns: f.ts_ns - t0,
                offset: (r.file_offset + f.address - r.host_base) / ps * ps,
                page_size,
                resolve_ns: f.wait_ns.min(u64::from(u32::MAX)) as u32,
                flags: 0,
            },
            tid: f.tid,
        });
    }
    out.header = Some(header);
    Ok(out)
}
