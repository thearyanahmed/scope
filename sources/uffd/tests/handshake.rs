#![allow(clippy::unwrap_used)]
//! Plays firecracker's side of the uffd handshake against the real handler.
//! Linux only; needs userfaultfd (root, or vm.unprivileged_userfaultfd=1, or 5.11+ user-mode-only).

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use telemetry::trace::Entry;
    use telemetry::{StopToken, fault_flags};
    use uffd::handler::{Handler, accept, bind};
    use uffd::sys;

    const PAGE: usize = 4096;
    const PAGES: usize = 16;

    #[test]
    fn serves_records_and_zero_fills_removed_pages() {
        let uffd = match sys::create(sys::UFFD_FEATURE_EVENT_REMOVE | sys::UFFD_FEATURE_THREAD_ID) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("skipping: userfaultfd unavailable: {e}");
                return;
            }
        };
        // SAFETY: fresh anonymous private mapping, unmapped at the end of the test.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE * PAGES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } as *mut u8;
        assert_ne!(base as *mut libc::c_void, libc::MAP_FAILED);
        sys::register(uffd.as_fd(), base as u64, (PAGE * PAGES) as u64).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mem_path = dir.path().join("mem");
        let mut mem = std::fs::File::create(&mem_path).unwrap();
        for i in 0..PAGES {
            mem.write_all(&[i as u8 + 1; PAGE]).unwrap();
        }
        drop(mem);

        let sock = dir.path().join("uffd.sock");
        let listener = bind(&sock, None).unwrap();
        assert!(bind(&sock, None).is_err(), "an existing path must never be replaced");

        let stop = StopToken::new();
        let seen: Arc<Mutex<Vec<Entry>>> = Arc::default();
        let (stop2, seen2) = (stop.clone(), seen.clone());
        let h = std::thread::spawn(move || {
            let (fd, maps, _conn) = accept(&listener).unwrap();
            let mem = std::fs::File::open(&mem_path).unwrap();
            let mut handler = Handler::new(fd, maps, &mem, move |e: &Entry| seen2.lock().unwrap().push(*e)).unwrap();
            handler.run(&stop2).unwrap();
            handler.summary
        });

        // firecracker's message: region json + the uffd.
        let body = format!(
            r#"[{{"base_host_virt_addr":{},"size":{},"offset":0,"page_size":{PAGE}}}]"#,
            base as u64,
            PAGE * PAGES
        );
        let conn = UnixStream::connect(&sock).unwrap();
        sys::send_with_fd(conn.as_fd(), body.as_bytes(), uffd.as_raw_fd()).unwrap();

        // SAFETY: all offsets are inside the mapping; reads/writes block until the handler serves them.
        unsafe {
            assert_eq!(*base.add(3 * PAGE + 10), 4);
            assert_eq!(*base.add(0), 1);
            assert_eq!(*base.add(7 * PAGE + PAGE - 1), 8);
            *base.add(5 * PAGE) = 0xee;
            assert_eq!(*base.add(5 * PAGE + 1), 6);
            // balloon-style removal, then touch again: must come back zeroed, not from the file.
            assert_eq!(libc::madvise(base.add(3 * PAGE).cast(), PAGE, libc::MADV_DONTNEED), 0);
            assert_eq!(*base.add(3 * PAGE + 10), 0);
        }

        stop.stop();
        let summary = h.join().unwrap();
        // SAFETY: mapping created above.
        unsafe { libc::munmap(base.cast(), PAGE * PAGES) };

        let seen = seen.lock().unwrap();
        let offs: Vec<u64> = seen.iter().map(|e| e.fault.offset / PAGE as u64).collect();
        assert_eq!(offs, [3, 0, 7, 5, 3]);
        assert_eq!(seen[3].fault.flags & fault_flags::WRITE, fault_flags::WRITE);
        assert_eq!(seen[4].fault.flags & fault_flags::ZEROED, fault_flags::ZEROED);
        // SAFETY: gettid has no preconditions.
        let me = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        assert!(seen.iter().all(|e| e.tid == me || e.tid == 0), "ptid is our thread when THREAD_ID is on");
        assert!(seen.windows(2).all(|w| w[0].fault.ts_ns <= w[1].fault.ts_ns));
        assert_eq!((summary.faults, summary.removes, summary.zero_filled), (5, 1, 1));
    }
}
