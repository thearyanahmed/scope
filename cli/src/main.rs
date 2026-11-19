mod faultcmd;
mod flamecmd;
mod hub;
mod topcmd;
// only the ebpf commands select a single vm so far.
#[cfg_attr(not(all(target_os = "linux", feature = "ebpf")), allow(dead_code))]
mod vmsel;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

/// Read-only observability for Firecracker microVMs.
#[derive(Debug, Parser)]
#[command(name = "scope", version)]
struct Cli {
    /// Read /proc and /sys under this directory instead of / (fixtures, containers).
    #[arg(long, global = true, default_value = "/")]
    root: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// What are the microVMs on this host doing right now?
    Top(topcmd::Args),
    /// Why is this VM (or its VMM) slow? Records stacks, exits and a vCPU timeline.
    Flame(flamecmd::Args),
    /// Which pages does a restored snapshot touch, in what order, how slowly?
    #[command(subcommand)]
    Fault(faultcmd::Cmd),
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = s.find(|c: char| !c.is_ascii_digit() && c != '.').map_or((s, "s"), |i| s.split_at(i));
    let n: f64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" => n,
        "m" => n * 60.0,
        _ => return Err(format!("bad duration unit in {s:?}; use ms, s or m")),
    };
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("duration must be positive: {s:?}"));
    }
    Ok(Duration::from_secs_f64(secs))
}

/// Stop `token` on SIGINT/SIGTERM so long-running commands can flush their output.
pub fn on_interrupt(token: telemetry::StopToken) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static HIT: AtomicBool = AtomicBool::new(false);
    extern "C" fn handle(_: libc::c_int) {
        // only async-signal-safe work here: one atomic store.
        HIT.store(true, Ordering::SeqCst);
    }
    // SAFETY: handle is a valid extern "C" fn that only touches an atomic.
    unsafe {
        libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle as *const () as libc::sighandler_t);
    }
    std::thread::spawn(move || {
        while !HIT.load(Ordering::SeqCst) {
            if !token.sleep(std::time::Duration::from_millis(100)) {
                return;
            }
        }
        token.stop();
    });
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = if cli.root == std::path::Path::new("/") { host::Root::live() } else { host::Root::at(&cli.root) };
    match cli.cmd {
        Cmd::Top(a) => topcmd::run(root, a),
        Cmd::Flame(a) => flamecmd::run(root, a),
        Cmd::Fault(c) => faultcmd::run(root, c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("5h").is_err());
    }
}
