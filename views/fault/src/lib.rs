//! Views over a fault trace: stats, working set, heatmap, diff, JSON lines.

pub mod analyze;
pub mod heatmap;
pub mod jsonl;

pub use analyze::{Diff, Stats, diff, stats, working_set};

use std::path::Path;

/// A trace file mapped into memory. Keeps the mapping alive for borrowed [`telemetry::trace::Trace`]s.
#[derive(Debug)]
pub struct Mapped(memmap2::Mmap);

impl Mapped {
    pub fn open(p: &Path) -> std::io::Result<Self> {
        let f = std::fs::File::open(p)?;
        // SAFETY: read-only private mapping; a concurrent writer appending to a live trace
        // only extends it, and Trace::parse ignores a partial trailing record.
        Ok(Self(unsafe { memmap2::Mmap::map(&f) }?))
    }

    pub fn trace(&self) -> Result<telemetry::trace::Trace<'_>, telemetry::trace::DecodeError> {
        telemetry::trace::Trace::parse(&self.0)
    }
}
