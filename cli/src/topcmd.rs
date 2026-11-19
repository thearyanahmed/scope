use crate::hub::Hub;
use anyhow::{Context, bail};
use host::Root;
use serde::Serialize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use telemetry::Event;
use top::{Header, Model, Row};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Refresh interval.
    #[arg(long, default_value = "1s", value_parser = crate::parse_duration)]
    interval: Duration,
    /// Take one measurement (two samples, one interval apart), print it and exit.
    #[arg(long)]
    once: bool,
    /// Print JSON instead of drawing the TUI. Without --once, one document per refresh.
    #[arg(long)]
    json: bool,
    /// Feed a recorded session instead of reading the live host.
    #[arg(long, value_name = "FILE")]
    replay: Option<PathBuf>,
    /// Also write every event to FILE as JSON lines, for later --replay.
    #[arg(long, value_name = "FILE")]
    record: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct Snapshot<'a> {
    header: Header,
    vms: &'a [Row],
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

pub fn run(root: Root, a: Args) -> anyhow::Result<()> {
    if !a.json {
        bail!("the interactive TUI is not wired yet; use --json"); // todo: views/top ui
    }
    let mut hub = Hub::new();
    let live = a.replay.is_none();
    match &a.replay {
        Some(p) => {
            let f = std::fs::File::open(p).with_context(|| format!("open {}", p.display()))?;
            let r = replay::Replay::from_reader(f).map_err(anyhow::Error::msg)?;
            hub.spawn(Box::new(if a.once { r } else { r.paced(a.interval) }));
        }
        None => {
            // scan once before the sampler starts, else its first tick races discovery
            // and sees no vms. discovery re-announces them later; Appeared is an upsert.
            for vm in host::discover(&root) {
                hub.vms.insert(vm);
            }
            hub.spawn(Box::new(host::Discovery::new(root.clone())));
            hub.spawn(Box::new(host::Sampler { root: root.clone(), interval: a.interval }));
        }
    }
    hub.seal();

    let mut rec = match &a.record {
        Some(p) => Some(replay::Recorder::new(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("create {}", p.display()))?,
        ))),
        None => None,
    };

    let mut model = Model::default();
    for vm in hub.vms.snapshot() {
        let ev = Event::Vm(telemetry::VmEvent::Appeared(Box::new(vm)));
        // recordings must start with the vms, or a replay drops the first samples.
        if let Some(r) = rec.as_mut() {
            r.write(&ev)?;
        }
        model.apply(&ev);
    }
    let mut ticks = 0;
    let out = std::io::stdout();
    // the sampler ends each tick with a Host event; render on that boundary.
    while let Ok(ev) = hub.rx.recv() {
        if let Some(r) = rec.as_mut() {
            r.write(&ev)?;
        }
        let tick = matches!(ev, Event::Host(_));
        model.apply(&ev);
        if !tick {
            continue;
        }
        ticks += 1;
        // one tick only has absolute values; rates need a second.
        if a.once && ticks < 2 {
            continue;
        }
        let rows = model.rows(live.then(now_ms));
        serde_json::to_writer(out.lock(), &Snapshot { header: model.header(), vms: &rows })?;
        println!();
        if a.once {
            break;
        }
    }
    hub.shutdown();
    Ok(())
}
