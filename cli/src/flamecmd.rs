use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// VM id, pid-<pid>, or pid.
    vm: String,
    #[arg(long, default_value = "10s", value_parser = crate::parse_duration)]
    duration: Duration,
    /// cpu-clock sampling frequency for the VMM flamegraph.
    #[arg(long, default_value_t = 99)]
    freq: u64,
    /// Directory for vmm.svg, exits.svg (and guest.svg). Default: scope-flame-<vm>.
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// svg: write graphs to --out; folded: print folded stacks; json: print the whole profile.
    #[arg(long, default_value = "svg", value_parser = ["svg", "folded", "json"])]
    format: String,
    #[arg(long)]
    no_stacks: bool,
    #[arg(long)]
    no_exits: bool,
    /// Separate debug info for a stripped firecracker binary.
    #[arg(long)]
    debug_file: Option<PathBuf>,
    /// Also read the guest program counter at every exit (an exit-site profile, biased toward
    /// exit-causing instructions). Reads guest state: needs this explicit flag.
    #[arg(long, requires = "vmlinux")]
    guest: bool,
    /// Guest kernel image with symbols, for --guest.
    #[arg(long)]
    vmlinux: Option<PathBuf>,
    /// Guest KASLR offset (hex) for --guest; 0 when the guest boots with nokaslr.
    #[arg(long, default_value = "0")]
    kaslr: String,
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
pub fn run(_: host::Root, _: Args) -> anyhow::Result<()> {
    anyhow::bail!("scope flame needs a linux build with the `ebpf` feature")
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub fn run(root: host::Root, a: Args) -> anyhow::Result<()> {
    use anyhow::Context;
    use telemetry::Privilege;
    crate::vmsel::require(&root, &[Privilege::CapBpf, Privilege::CapPerfmon])?;
    let vm = crate::vmsel::find(&root, &a.vm)?;
    if vm.vcpus.is_empty() && !a.no_exits {
        eprintln!("scope: {} has no vcpu threads yet (not started?); exit profile will be empty", vm.id);
    }
    let guest = if a.guest {
        let vmlinux = a.vmlinux.clone().context("--guest needs --vmlinux")?;
        let kaslr = u64::from_str_radix(a.kaslr.trim_start_matches("0x"), 16).context("--kaslr is hex")?;
        let what = format!(
            "reading the guest program counter at each vm exit of {} (pid {}) for {:?}, symbolized against {}",
            vm.id,
            vm.pid,
            a.duration,
            vmlinux.display()
        );
        eprintln!("scope: --guest: {what}");
        audit(&what);
        Some(probes::record::Guest { vmlinux, kaslr })
    } else {
        None
    };
    let opts = probes::record::Options {
        duration: a.duration,
        freq: a.freq,
        stacks: !a.no_stacks,
        exits: !a.no_exits,
        guest,
        debug_file: a.debug_file.clone(),
    };
    let stop = telemetry::StopToken::new();
    crate::on_interrupt(stop.clone());
    eprintln!("scope: recording {} (pid {}) for {:?}, ctrl-c to stop early", vm.id, vm.pid, a.duration);
    let rec = probes::record::record(&vm, &opts, &stop).map_err(anyhow::Error::msg)?;
    let p = flame::Profile {
        vm: vm.id.0.clone(),
        elapsed_ns: rec.elapsed.as_nanos() as u64,
        freq_hz: a.freq,
        stacks: rec.stacks,
        exits: rec.exits,
        timeline: rec.timeline,
        guest: rec.guest,
        warnings: rec.warnings,
    };
    for w in &p.warnings {
        eprintln!("scope: warning: {w}");
    }
    match a.format.as_str() {
        "json" => println!("{}", serde_json::to_string(&p)?),
        "folded" => {
            for l in flame::vmm_folded(&p).iter().chain(&flame::exits_folded(&p)).chain(&flame::guest_folded(&p)) {
                println!("{l}");
            }
        }
        _ => {
            let dir = a.out.clone().unwrap_or_else(|| PathBuf::from(format!("scope-flame-{}", vm.id)));
            std::fs::create_dir_all(&dir)?;
            let write = |name: &str, lines: Vec<String>, title: String, unit: &str| -> anyhow::Result<()> {
                if lines.is_empty() {
                    return Ok(());
                }
                let path = dir.join(name);
                std::fs::write(&path, flame::svg(&lines, &title, unit)?)?;
                eprintln!("scope: wrote {}", path.display());
                Ok(())
            };
            write("vmm.svg", flame::vmm_folded(&p), format!("{} vmm cpu ({} Hz)", p.vm, a.freq), "samples")?;
            write("exits.svg", flame::exits_folded(&p), format!("{} time out of guest by exit reason", p.vm), "us")?;
            write(
                "guest.svg",
                flame::guest_folded(&p),
                format!("{} guest exit-site profile (biased to exit points)", p.vm),
                "exits",
            )?;
            if !p.exits.is_empty() {
                print!("{}\n{}", flame::exit_table(&p), flame::timeline_table(&p));
            }
        }
    }
    Ok(())
}

/// One line to syslog (LOG_AUTH) whenever guest state is read.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn audit(what: &str) {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let Ok(msg) = std::ffi::CString::new(format!("uid {uid} {what}")) else { return };
    // SAFETY: static nul-terminated ident and format; msg is a valid C string passed as %s.
    unsafe {
        libc::openlog(c"scope".as_ptr(), libc::LOG_PID, libc::LOG_AUTH);
        libc::syslog(libc::LOG_NOTICE, c"%s".as_ptr(), msg.as_ptr());
        libc::closelog();
    }
}
