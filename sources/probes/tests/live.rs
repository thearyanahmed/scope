#![allow(clippy::unwrap_used)]
//! Live eBPF tests against the running kernel. Need root (CAP_BPF + CAP_PERFMON)
//! and a kernel with BTF; no KVM needed. They profile this test process itself.
//! Run: cargo test -p probes --features ebpf --test live (as root).

#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use telemetry::{StopToken, ThreadKind, Vcpu, Vm, VmId, VmmThread};

    fn tid() -> u32 {
        // SAFETY: gettid has no preconditions.
        unsafe { libc::syscall(libc::SYS_gettid) as u32 }
    }

    fn me(vcpus: Vec<Vcpu>) -> Vm {
        Vm {
            id: VmId("self".into()),
            pid: std::process::id(),
            jailed: false,
            root: "/".into(),
            api_sock: None,
            metrics_path: None,
            config_file: None,
            vcpus,
            threads: vec![VmmThread { tid: std::process::id(), name: "main".into(), kind: ThreadKind::Vmm }],
            taps: vec![],
            cgroup: None,
            started_ms: 0,
        }
    }

    fn privileged() -> bool {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        if !root {
            eprintln!("skipping: needs root");
        }
        root
    }

    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn scope_test_spin_here(stop: &AtomicBool) -> u64 {
        let mut x = 0u64;
        while !stop.load(Ordering::Relaxed) {
            x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
        x
    }

    #[test]
    fn samples_and_symbolizes_own_stacks() {
        if !privileged() {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let h = std::thread::spawn(move || {
            tx.send(tid()).unwrap();
            scope_test_spin_here(&s2)
        });
        let spinner = rx.recv().unwrap();
        let opts = probes::record::Options {
            duration: Duration::from_millis(1500),
            freq: 199,
            stacks: true,
            exits: false,
            guest: None,
            debug_file: None,
        };
        let rec = probes::record::record(&me(vec![Vcpu { index: 0, tid: spinner }]), &opts, &StopToken::new()).unwrap();
        stop.store(true, Ordering::Relaxed);
        h.join().unwrap();

        let total: u64 = rec.stacks.iter().filter(|s| s.tid == spinner).map(|s| s.weight).sum();
        assert!(total > 50, "expected ~300 samples of the spinning thread, got {total}; warnings {:?}", rec.warnings);
        let named: u64 = rec
            .stacks
            .iter()
            .filter(|s| s.tid == spinner && s.frames.iter().any(|f| f.contains("scope_test_spin_here")))
            .map(|s| s.weight)
            .sum();
        assert!(
            named * 2 > total,
            "spin function should dominate: {named}/{total}; sample frames {:?}",
            rec.stacks.first()
        );
        assert!(rec.stacks.iter().any(|s| s.thread == "fc_vcpu 0"));
    }

    #[test]
    fn passive_fault_capture_sees_uffd_faults() {
        use std::os::fd::AsFd;
        use uffd::sys;
        if !privileged() {
            return;
        }
        const PAGE: usize = 4096;
        let Ok(fd) = sys::create(0) else {
            eprintln!("skipping: no userfaultfd");
            return;
        };
        // SAFETY: anonymous private mapping owned by this test.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE * 32,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } as *mut u8;
        sys::register(fd.as_fd(), base as u64, (PAGE * 32) as u64).unwrap();

        // a minimal handler: zero-fill every fault. scope only observes it.
        let fd = Arc::new(fd);
        let hstop = StopToken::new();
        let (hfd, hs) = (fd.clone(), hstop.clone());
        let handler = std::thread::spawn(move || {
            use std::os::fd::AsRawFd;
            let mut buf = [0u8; 32];
            while !hs.is_stopped() {
                let mut p = libc::pollfd { fd: hfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                // SAFETY: one valid pollfd / buffer.
                if unsafe { libc::poll(&mut p, 1, 50) } <= 0
                    || unsafe { libc::read(hfd.as_raw_fd(), buf.as_mut_ptr().cast(), 32) } != 32
                {
                    continue;
                }
                if let sys::Msg::PageFault { address, .. } = sys::decode(&buf) {
                    std::thread::sleep(Duration::from_micros(200));
                    sys::zeropage(hfd.as_fd(), address & !(PAGE as u64 - 1), PAGE as u64).unwrap();
                }
            }
        });

        let stop = StopToken::new();
        let s2 = stop.clone();
        let base_addr = base as usize;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let rec = std::thread::spawn(move || {
            probes::faults::record(&me(vec![]), PAGE as u32, Some(Duration::from_secs(30)), &s2, move || {
                ready_tx.send(()).unwrap()
            })
        });
        ready_rx.recv_timeout(Duration::from_secs(20)).expect("probes attached");
        for i in [5usize, 1, 9] {
            // SAFETY: inside the registered mapping; blocks until the handler zero-fills it.
            assert_eq!(unsafe { *((base_addr + i * PAGE) as *const u8) }, 0);
        }
        stop.stop();
        let cap = rec.join().unwrap().unwrap();
        hstop.stop();
        handler.join().unwrap();

        let h = cap.header.unwrap_or_else(|| panic!("no faults captured: {:?}", cap.warnings));
        let offs: Vec<u64> = cap.entries.iter().map(|e| e.fault.offset).collect();
        let region =
            h.regions.iter().find(|r| r.host_base <= base as u64 && (base as u64) < r.host_base + r.size).unwrap();
        let expect: Vec<u64> = [5u64, 1, 9]
            .iter()
            .map(|i| region.file_offset + (base as u64 - region.host_base) + i * PAGE as u64)
            .collect();
        assert_eq!(offs, expect, "warnings: {:?}", cap.warnings);
        assert!(cap.entries.iter().all(|e| e.fault.resolve_ns >= 200_000), "wait covers the handler's 200us delay");
        assert!(cap.entries.iter().all(|e| e.tid == tid()));
        // SAFETY: mapping created above.
        unsafe { libc::munmap(base.cast(), PAGE * 32) };
    }
}
