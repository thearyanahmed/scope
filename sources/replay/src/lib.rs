//! Recorded sessions: one [`Event`] per line, JSON encoded.
//!
//! `Replay` is a [`Source`] so views and exporters can be exercised without
//! KVM. `Recorder` writes the same format from a live session.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::Sender;
use std::time::Duration;
use telemetry::{Event, Privilege, Source, SourceError, StopToken, VmEvent, VmSet};

pub fn parse_line(line: &str) -> Result<Option<Event>, serde_json::Error> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return Ok(None);
    }
    serde_json::from_str(t).map(Some)
}

pub fn read_all(r: impl Read) -> Result<Vec<Event>, String> {
    let mut out = Vec::new();
    for (i, line) in BufReader::new(r).lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if let Some(ev) = parse_line(&line).map_err(|e| format!("line {}: {e}", i + 1))? {
            out.push(ev);
        }
    }
    Ok(out)
}

/// Apply a vm lifecycle event to the shared set, as discovery would.
pub fn apply(vms: &VmSet, ev: &Event) {
    match ev {
        Event::Vm(VmEvent::Appeared(vm)) => vms.insert((**vm).clone()),
        Event::Vm(VmEvent::Gone(id)) => {
            vms.remove(id);
        }
        _ => {}
    }
}

#[derive(Debug)]
pub struct Replay {
    events: Vec<Event>,
    /// sleep after each host sample, which marks the end of one refresh tick.
    pace: Option<Duration>,
}

impl Replay {
    pub fn new(events: Vec<Event>) -> Self {
        Self { events, pace: None }
    }

    pub fn from_reader(r: impl Read) -> Result<Self, String> {
        Ok(Self::new(read_all(r)?))
    }

    pub fn paced(mut self, d: Duration) -> Self {
        self.pace = Some(d);
        self
    }
}

impl Source for Replay {
    fn name(&self) -> &'static str {
        "replay"
    }

    fn needs(&self) -> &'static [Privilege] {
        &[]
    }

    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError> {
        for ev in self.events {
            if stop.is_stopped() {
                break;
            }
            apply(&vms, &ev);
            let tick = matches!(ev, Event::Host(_));
            if out.send(ev).is_err() {
                break;
            }
            if let (true, Some(d)) = (tick, self.pace)
                && !stop.sleep(d)
            {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Recorder<W: Write> {
    w: W,
}

impl<W: Write> Recorder<W> {
    pub fn new(w: W) -> Self {
        Self { w }
    }

    pub fn write(&mut self, ev: &Event) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.w, ev)?;
        self.w.write_all(b"\n")
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use telemetry::{HostSample, Vm, VmId};

    fn vm(id: &str) -> Vm {
        Vm {
            id: VmId(id.into()),
            pid: 42,
            jailed: false,
            root: "/".into(),
            api_sock: None,
            metrics_path: None,
            config_file: None,
            vcpus: vec![],
            threads: vec![],
            taps: vec![],
            cgroup: None,
            started_ms: 0,
        }
    }

    #[test]
    fn record_then_replay() {
        let evs = vec![
            Event::Vm(VmEvent::Appeared(Box::new(vm("a")))),
            Event::Host(HostSample { ts_ns: 1, ncpus: 4, ..Default::default() }),
            Event::Vm(VmEvent::Gone(VmId("a".into()))),
        ];
        let mut rec = Recorder::new(Vec::new());
        for e in &evs {
            rec.write(e).unwrap();
        }
        let buf = rec.into_inner();
        let replay = Replay::from_reader(&buf[..]).unwrap();

        let (tx, rx) = mpsc::channel();
        let vms = VmSet::new();
        Box::new(replay).run(vms.clone(), tx, StopToken::new()).unwrap();
        let got: Vec<Event> = rx.iter().collect();
        assert_eq!(got, evs);
        assert!(vms.is_empty());
    }

    #[test]
    fn skips_comments_and_reports_bad_line() {
        assert!(parse_line("# hi").unwrap().is_none());
        let err = read_all("\n{bad}\n".as_bytes()).unwrap_err();
        assert!(err.starts_with("line 2"), "{err}");
    }
}
