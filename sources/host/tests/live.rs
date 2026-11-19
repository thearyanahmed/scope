#![allow(clippy::unwrap_used)]
//! Live discovery against the running kernel's /proc (linux only).
//!
//! The binary re-executes itself under the name `firecracker` with threads
//! named like firecracker's, so discovery sees a realistic process without
//! needing KVM. Run: `cargo test -p host --test live`. Opening a tap needs
//! CAP_NET_ADMIN; without it the tap assertions are skipped.

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("live: skipped (linux only)");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::var_os("SCOPE_FAKE_FC").is_some() {
        linux::fake_firecracker();
    } else {
        linux::run();
        println!("live: ok");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use host::{Root, discover, sample_vm};
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const TAP: &str = "scopetap0";

    pub fn fake_firecracker() {
        let tap = open_tap();
        for i in 0..2 {
            std::thread::Builder::new()
                .name(format!("fc_vcpu {i}"))
                .spawn(move || {
                    // vcpu 0 spins so the sampler has cpu time to see.
                    loop {
                        if i == 1 {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                })
                .unwrap();
        }
        std::thread::Builder::new()
            .name("fc_api".into())
            .spawn(|| {
                loop {
                    std::thread::park();
                }
            })
            .unwrap();
        println!("ready tap={}", tap.is_some());
        std::thread::sleep(Duration::from_secs(30));
        drop(tap);
    }

    /// TUNSETIFF with IFF_TAP | IFF_NO_PI. Returns None without CAP_NET_ADMIN.
    fn open_tap() -> Option<std::fs::File> {
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        let f = std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun").ok()?;
        let mut ifr = [0u8; 40];
        ifr[..TAP.len()].copy_from_slice(TAP.as_bytes());
        let flags: u16 = 0x0002 | 0x1000;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        // SAFETY: ifr is a valid, writable struct ifreq-sized buffer for the duration of the call.
        let rc = unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) };
        (rc == 0).then_some(f)
    }

    pub fn run() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("firecracker");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let mut child = Command::new(&exe)
            .args(["--id", "live-test", "--api-sock", "/tmp/scope-live.sock"])
            .env("SCOPE_FAKE_FC", "1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().unwrap()), &mut line).unwrap();
        let has_tap = line.contains("tap=true");

        let result = std::panic::catch_unwind(|| check(child.id(), has_tap));
        let _ = child.kill();
        let _ = child.wait();
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    fn check(pid: u32, has_tap: bool) {
        let root = Root::live();
        let deadline = Instant::now() + Duration::from_secs(5);
        let vm = loop {
            let found = discover(&root).into_iter().find(|v| v.pid == pid && v.vcpus.len() == 2);
            if let Some(vm) = found {
                break vm;
            }
            assert!(Instant::now() < deadline, "fake firecracker {pid} not discovered");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(vm.id.0, "live-test");
        assert!(vm.api_sock.as_ref().unwrap().ends_with("tmp/scope-live.sock"));
        assert!(vm.threads.iter().any(|t| t.kind == telemetry::ThreadKind::Api));
        assert!(vm.started_ms > 1_600_000_000_000, "start time {} looks wrong", vm.started_ms);
        if has_tap {
            assert_eq!(vm.taps, [TAP]);
        } else {
            println!("live: no CAP_NET_ADMIN, tap check skipped");
        }

        let a = sample_vm(&root, &vm).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let b = sample_vm(&root, &vm).unwrap();
        let spin = |s: &telemetry::ProcSample| s.vcpus[0].sched.run_ns;
        assert!(spin(&b) > spin(&a), "spinning vcpu thread shows no run time");
        assert!(b.cpu.total_ns() > a.cpu.total_ns());
        assert!(b.mem.unwrap().rss_bytes > 0, "smaps_rollup unreadable");
        if has_tap {
            assert_eq!(b.net.len(), 1);
        }
    }
}
