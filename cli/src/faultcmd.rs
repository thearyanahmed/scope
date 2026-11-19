use anyhow::{Context, bail};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Be firecracker's uffd handler for a snapshot restore and record every fault.
    /// This is the one scope command that affects a VM: if it stops, the guest stalls.
    Serve(ServeArgs),
    /// Summary: fault count, working set size, resolve latency, stall.
    Show {
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write the working set (first-touch order) as a .ws file.
    Ws {
        trace: PathBuf,
        /// Only pages first touched within this long of the start.
        #[arg(long, value_parser = crate::parse_duration)]
        window: Option<Duration>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Guest memory coloured by first-touch time.
    Heatmap {
        trace: PathBuf,
        #[arg(long, default_value_t = 64)]
        cols: usize,
        #[arg(long, default_value_t = 32)]
        rows: usize,
        /// Write SVG here instead of drawing in the terminal.
        #[arg(long)]
        svg: Option<PathBuf>,
    },
    /// Working-set overlap of two traces (snapshot / prefetch stability).
    Diff {
        a: PathBuf,
        b: PathBuf,
        #[arg(long, value_parser = crate::parse_duration)]
        window: Option<Duration>,
        #[arg(long)]
        json: bool,
    },
    /// Print a trace as JSON lines.
    Export { trace: PathBuf },
    /// Convert JSON lines (header line + entries) into a trace.
    Import {
        jsonl: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct ServeArgs {
    /// Unix socket firecracker connects to (mem_backend.backend_path). Must not exist.
    #[arg(long)]
    socket: PathBuf,
    /// Snapshot memory file (mem_file_path from /snapshot/create).
    #[arg(long)]
    mem: PathBuf,
    /// Where to write the fault trace.
    #[arg(long)]
    trace: PathBuf,
    /// chown the socket to UID:GID, for a jailed firecracker.
    #[arg(long, value_name = "UID:GID")]
    chown: Option<String>,
    /// Populate these pages (a .ws file) right after the handshake.
    #[arg(long, value_name = "WS")]
    prefetch: Option<PathBuf>,
}

fn open(p: &std::path::Path) -> anyhow::Result<fault::Mapped> {
    fault::Mapped::open(p).with_context(|| format!("open {}", p.display()))
}

pub fn run(c: Cmd) -> anyhow::Result<()> {
    match c {
        Cmd::Serve(a) => serve(a),
        Cmd::Show { trace, json } => {
            let m = open(&trace)?;
            let s = fault::stats(&m.trace().map_err(anyhow::Error::msg)?);
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
                return Ok(());
            }
            let ms = |v: Option<u64>| v.map_or("-".into(), |n| format!("{:.3} ms", n as f64 / 1e6));
            let us = |v: Option<u32>| v.map_or("-".into(), |n| format!("{:.1} us", f64::from(n) / 1e3));
            println!(
                "faults          {} demand, {} prefetched, {} writes, {} zero-filled",
                s.faults, s.prefetched, s.writes, s.zeroed
            );
            println!(
                "working set     {} pages = {} of {} ({:.2}%)",
                s.unique_pages,
                top::ui::bytes(s.touched_bytes),
                top::ui::bytes(s.mem_bytes),
                s.touched_pct
            );
            println!("first fault     {}", ms(s.first_fault_ns));
            println!("last fault      {}", ms(s.last_fault_ns));
            println!(
                "resolve         p50 {}  p99 {}  max {}",
                us(s.resolve_p50_ns),
                us(s.resolve_p99_ns),
                us(s.resolve_max_ns)
            );
            println!("stall (sum)     {}", ms(Some(s.total_stall_ns)));
            for (tid, n) in &s.per_thread {
                println!("  thread {:>8}  {n} faults", if *tid == 0 { "unknown".into() } else { tid.to_string() });
            }
            Ok(())
        }
        Cmd::Ws { trace, window, out } => {
            let m = open(&trace)?;
            let t = m.trace().map_err(anyhow::Error::msg)?;
            let ws = fault::working_set(&t, window.map(|d| d.as_nanos() as u64));
            std::fs::write(&out, telemetry::trace::ws::encode(t.header.page_size, &ws))?;
            eprintln!("scope: {} pages -> {}", ws.len(), out.display());
            Ok(())
        }
        Cmd::Heatmap { trace, cols, rows, svg } => {
            let m = open(&trace)?;
            let h = fault::heatmap::build(&m.trace().map_err(anyhow::Error::msg)?, cols, rows);
            match svg {
                Some(p) => std::fs::write(p, fault::heatmap::svg(&h, &trace.display().to_string()))?,
                None => {
                    print!("{}", fault::heatmap::ansi(&h));
                    println!(
                        "{} pages/cell, dark = early, yellow = late ({:.1} ms), · = untouched",
                        h.pages_per_cell,
                        h.max_ns as f64 / 1e6
                    );
                }
            }
            Ok(())
        }
        Cmd::Diff { a, b, window, json } => {
            let (ma, mb) = (open(&a)?, open(&b)?);
            let w = window.map(|d| d.as_nanos() as u64);
            let wa = fault::working_set(&ma.trace().map_err(anyhow::Error::msg)?, w);
            let wb = fault::working_set(&mb.trace().map_err(anyhow::Error::msg)?, w);
            let d = fault::diff(&wa, &wb);
            if json {
                println!("{}", serde_json::to_string_pretty(&d)?);
            } else {
                println!("a {} pages, b {} pages, common {}", d.a_pages, d.b_pages, d.common);
                println!("overlap {:.1}% (jaccard), a covered by b {:.1}%", d.jaccard_pct, d.a_covered_by_b_pct);
            }
            Ok(())
        }
        Cmd::Export { trace } => {
            let m = open(&trace)?;
            fault::jsonl::export(
                &m.trace().map_err(anyhow::Error::msg)?,
                std::io::BufWriter::new(std::io::stdout().lock()),
            )?;
            Ok(())
        }
        Cmd::Import { jsonl, out } => {
            let r = std::io::BufReader::new(std::fs::File::open(&jsonl)?);
            let n = fault::jsonl::import(r, std::io::BufWriter::new(std::fs::File::create(&out)?))
                .map_err(anyhow::Error::msg)?;
            eprintln!("scope: {n} records -> {}", out.display());
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn serve(_: ServeArgs) -> anyhow::Result<()> {
    bail!("fault serve needs linux (userfaultfd)")
}

#[cfg(target_os = "linux")]
fn serve(a: ServeArgs) -> anyhow::Result<()> {
    use telemetry::trace::Writer;
    use uffd::handler::{Handler, accept, bind};

    let owner = a
        .chown
        .as_deref()
        .map(|s| -> anyhow::Result<(u32, u32)> {
            let (u, g) = s.split_once(':').context("--chown wants UID:GID")?;
            Ok((u.parse()?, g.parse()?))
        })
        .transpose()?;
    let prefetch = match &a.prefetch {
        Some(p) => telemetry::trace::ws::decode(&std::fs::read_to_string(p)?).map_err(anyhow::Error::msg)?.1,
        None => vec![],
    };
    let mem = std::fs::File::open(&a.mem).with_context(|| format!("open {}", a.mem.display()))?;
    let listener = bind(&a.socket, owner).with_context(|| format!("bind {}", a.socket.display()))?;
    eprintln!("scope: waiting for firecracker on {}", a.socket.display());
    let stop = telemetry::StopToken::new();
    crate::on_interrupt(stop.clone());
    let res = (|| -> anyhow::Result<uffd::handler::Summary> {
        let (fd, maps, _conn) = accept(&listener)?;
        eprintln!("scope: firecracker connected, {} regions", maps.len());
        let mut handler = Handler::new(fd, maps, &mem)?;
        let out = std::io::BufWriter::new(std::fs::File::create(&a.trace)?);
        let mut w = Writer::new(out, &handler.header())?;
        let mut werr = None;
        let mut sink = |e: &telemetry::trace::Entry| {
            if let Err(x) = w.push(e) {
                werr.get_or_insert(x);
            }
        };
        handler.prefetch(&prefetch, &mut sink)?;
        handler.run(&stop, &mut sink)?;
        if let Some(e) = werr {
            return Err(e).context("write trace");
        }
        w.flush()?;
        Ok(handler.summary.clone())
    })();
    // we created this socket in bind(); removing it is ours to do.
    let _ = std::fs::remove_file(&a.socket);
    let s = res?;
    eprintln!(
        "scope: {} faults, {} prefetched, {} zero-filled, {} -> {}",
        s.faults,
        s.prefetched,
        s.zero_filled,
        top::ui::bytes(s.bytes),
        a.trace.display()
    );
    Ok(())
}
