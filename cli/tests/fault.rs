#![allow(clippy::unwrap_used)]
use std::process::Command;
use telemetry::trace::{Entry, Header, Region, Writer};
use telemetry::{FaultRecord, fault_flags};

fn scope(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_scope")).args(args).output().unwrap();
    assert!(out.status.success(), "{:?}: {}", args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn write_trace(p: &std::path::Path, pages: &[u64]) {
    let h = Header {
        page_size: 4096,
        t0_unix_ns: 0,
        regions: vec![Region { host_base: 0, size: 256 * 4096, file_offset: 0 }],
    };
    let mut w = Writer::new(std::fs::File::create(p).unwrap(), &h).unwrap();
    for (i, pg) in pages.iter().enumerate() {
        let f = FaultRecord {
            ts_ns: i as u64 * 1000,
            offset: pg * 4096,
            page_size: 4096,
            resolve_ns: 2000,
            flags: fault_flags::WRITE,
        };
        w.push(&Entry { fault: f, tid: 7 }).unwrap();
    }
}

#[test]
fn offline_commands() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("a.sft"), d.path().join("b.sft"));
    write_trace(&a, &[1, 2, 3, 4]);
    write_trace(&b, &[2, 3, 4, 5]);
    let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());

    let s: serde_json::Value = serde_json::from_str(&scope(&["fault", "show", a, "--json"])).unwrap();
    assert_eq!(s["faults"], 4);
    assert_eq!(s["unique_pages"], 4);
    assert!(scope(&["fault", "show", a]).contains("working set     4 pages"));

    let ws = d.path().join("a.ws");
    scope(&["fault", "ws", a, "-o", ws.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(&ws).unwrap(), "# scope ws v1 page_size=4096\n0x1000\n0x2000\n0x3000\n0x4000\n");

    let diff: serde_json::Value = serde_json::from_str(&scope(&["fault", "diff", a, b, "--json"])).unwrap();
    assert_eq!(diff["common"], 3);

    let svg = d.path().join("h.svg");
    scope(&["fault", "heatmap", a, "--svg", svg.to_str().unwrap()]);
    assert!(std::fs::read_to_string(&svg).unwrap().starts_with("<svg"));

    let jsonl = d.path().join("a.jsonl");
    std::fs::write(&jsonl, scope(&["fault", "export", a])).unwrap();
    let back = d.path().join("back.sft");
    scope(&["fault", "import", jsonl.to_str().unwrap(), "-o", back.to_str().unwrap()]);
    assert_eq!(std::fs::read(a).unwrap(), std::fs::read(&back).unwrap());
}

/// `scope fault serve` end to end: this test plays firecracker, then interrupts scope
/// and checks the trace it flushed on the way out.
#[cfg(target_os = "linux")]
#[test]
fn serve_records_until_interrupted() {
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd};
    use uffd::sys;
    const PAGE: usize = 4096;

    let Ok(fd) = sys::create(0) else {
        eprintln!("skipping: userfaultfd unavailable");
        return;
    };
    let d = tempfile::tempdir().unwrap();
    let mem = d.path().join("mem");
    std::fs::File::create(&mem).unwrap().write_all(&[0x5a; PAGE * 8]).unwrap();
    let (sock, trace) = (d.path().join("u.sock"), d.path().join("t.sft"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_scope"))
        .args([
            "fault",
            "serve",
            "--socket",
            sock.to_str().unwrap(),
            "--mem",
            mem.to_str().unwrap(),
            "--trace",
            trace.to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // SAFETY: anonymous private mapping owned by this test.
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * 8,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } as *mut u8;
    sys::register(fd.as_fd(), base as u64, (PAGE * 8) as u64).unwrap();
    let conn = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    let body =
        format!(r#"[{{"base_host_virt_addr":{},"size":{},"offset":0,"page_size":4096}}]"#, base as u64, PAGE * 8);
    sys::send_with_fd(conn.as_fd(), body.as_bytes(), fd.as_raw_fd()).unwrap();
    // SAFETY: inside the mapping; each read blocks until scope serves the page.
    unsafe {
        assert_eq!(*base.add(2 * PAGE), 0x5a);
        assert_eq!(*base.add(6 * PAGE), 0x5a);
    }
    // SAFETY: plain kill(2) on our child.
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    assert!(child.wait().unwrap().success());
    assert!(!sock.exists(), "scope removes the socket it created");

    let s: serde_json::Value =
        serde_json::from_str(&scope(&["fault", "show", trace.to_str().unwrap(), "--json"])).unwrap();
    assert_eq!(s["faults"], 2);
    // SAFETY: mapping created above.
    unsafe { libc::munmap(base.cast(), PAGE * 8) };
}
