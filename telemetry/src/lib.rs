//! Types shared by every scope source, view and exporter.
//!
//! Nothing in this crate performs I/O. Sources produce [`Event`]s, views
//! consume them, and the wire format for recorded sessions is these types
//! serialized as JSON lines.

mod event;
mod privilege;
mod sample;
mod stop;
pub mod trace;
mod vm;
mod vmset;

pub use event::*;
pub use privilege::*;
pub use sample::*;
pub use stop::*;
pub use vm::*;
pub use vmset::*;

use std::sync::mpsc::Sender;

/// Anything that watches VMs and emits events.
///
/// A source runs on its own thread until `stop` fires or `out` is closed.
pub trait Source: Send {
    fn name(&self) -> &'static str;
    fn needs(&self) -> &'static [Privilege];
    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError>;
}

#[derive(Debug)]
pub struct SourceError {
    pub source: &'static str,
    pub message: String,
}

impl SourceError {
    pub fn new(source: &'static str, message: impl Into<String>) -> Self {
        Self { source, message: message.into() }
    }
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.source, self.message)
    }
}

impl std::error::Error for SourceError {}

/// Monotonic nanoseconds since the first call in this process.
/// Every live source stamps samples with this so views can diff them.
pub fn mono_ns() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}
