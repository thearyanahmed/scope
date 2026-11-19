use std::io;
use std::path::{Path, PathBuf};

/// Filesystem root that /proc and /sys are read from.
#[derive(Debug, Clone)]
pub struct Root {
    pub dir: PathBuf,
    /// USER_HZ, the unit of utime/stime/starttime in /proc/<pid>/stat.
    pub clk_tck: u64,
}

impl Root {
    pub fn live() -> Self {
        Self { dir: "/".into(), clk_tck: clk_tck() }
    }

    /// Fixture trees are captured from hosts where USER_HZ is 100, which is
    /// the value on every mainstream x86_64 and arm64 kernel config.
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into(), clk_tck: 100 }
    }

    pub fn path(&self, rel: impl AsRef<Path>) -> PathBuf {
        let rel = rel.as_ref();
        self.dir.join(rel.strip_prefix("/").unwrap_or(rel))
    }

    pub fn read(&self, rel: impl AsRef<Path>) -> io::Result<String> {
        std::fs::read_to_string(self.path(rel))
    }

    pub fn read_bytes(&self, rel: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        std::fs::read(self.path(rel))
    }

    pub fn read_u64(&self, rel: impl AsRef<Path>) -> io::Result<u64> {
        let s = self.read(rel)?;
        s.trim().parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a u64"))
    }

    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        ticks.saturating_mul(1_000_000_000 / self.clk_tck.max(1))
    }
}

#[cfg(unix)]
fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as u64 } else { 100 }
}

#[cfg(not(unix))]
fn clk_tck() -> u64 {
    100
}
