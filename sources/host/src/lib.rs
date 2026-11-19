//! Host-side view of firecracker processes.
//!
//! Every read goes through [`Root`], so tests point it at a fixture tree
//! (`fixtures/host/...`) and live runs point it at `/`.

pub mod discover;
pub mod parse;
pub mod privileges;
pub mod root;
pub mod sample;

pub use discover::{Discovery, discover};
pub use root::Root;
pub use sample::{Sampler, sample_host, sample_vm};
