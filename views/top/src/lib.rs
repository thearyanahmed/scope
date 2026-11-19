//! `scope top`. [`Model`] folds events into per-VM rates; [`ui`] renders it.
//! The model has no terminal dependency so `--once --json` and tests use it directly.

pub mod model;
pub mod thresholds;
pub mod ui;

pub use model::{Header, Model, Row, VcpuRow};
pub use thresholds::{Level, Thresholds};
