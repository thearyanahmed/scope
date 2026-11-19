//! Runs sources on threads and funnels their events into one channel.

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use telemetry::{Event, Source, StopToken, VmSet};

#[derive(Debug)]
pub struct Hub {
    pub vms: VmSet,
    pub stop: StopToken,
    pub rx: Receiver<Event>,
    tx: Option<mpsc::Sender<Event>>,
    /// errors from sources that gave up. Collected rather than printed so the TUI can show them.
    pub errors: Arc<Mutex<Vec<String>>>,
    threads: Vec<(&'static str, JoinHandle<()>)>,
}

impl Hub {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self { vms: VmSet::new(), stop: StopToken::new(), rx, tx: Some(tx), errors: Arc::default(), threads: vec![] }
    }

    pub fn spawn(&mut self, src: Box<dyn Source>) {
        let name = src.name();
        let (vms, stop, errors) = (self.vms.clone(), self.stop.clone(), self.errors.clone());
        let Some(tx) = self.tx.clone() else { return };
        let h = std::thread::Builder::new()
            .name(format!("scope-{name}"))
            .spawn(move || {
                // a failing source degrades the view; it must not take the others down.
                if let Err(e) = src.run(vms, tx, stop) {
                    errors.lock().unwrap_or_else(|p| p.into_inner()).push(e.to_string());
                }
            })
            .expect("spawn source thread");
        self.threads.push((name, h));
    }

    /// Drop our sender so `rx` closes once every source has exited.
    pub fn seal(&mut self) {
        self.tx = None;
    }

    pub fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn shutdown(mut self) {
        self.stop.stop();
        self.seal();
        // drain so senders blocked on nothing can finish; mpsc is unbounded so this is cheap.
        while self.rx.try_recv().is_ok() {}
        for (_, h) in self.threads.drain(..) {
            let _ = h.join();
        }
    }
}
