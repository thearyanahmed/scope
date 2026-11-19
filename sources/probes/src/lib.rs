//! `scope flame` and passive `scope fault record`: eBPF on the host side.
//!
//! Pure pieces (tracefs format parsing, exit reason decoding) build everywhere.
//! The loader needs linux and the `ebpf` feature.

pub mod decode;
pub mod tracefs;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod faults;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod record;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod symbols;

/// True when this build can load eBPF programs.
pub const AVAILABLE: bool = cfg!(all(target_os = "linux", feature = "ebpf"));

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn new(m: impl Into<String>) -> Self {
        Self(m.into())
    }
}
