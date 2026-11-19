//! Machine-readable outputs. JSON lines is `replay::Recorder`; this crate
//! adds Prometheus text exposition and folded stacks.

pub mod folded;
pub mod prom;
pub mod serve;

pub use prom::State;
