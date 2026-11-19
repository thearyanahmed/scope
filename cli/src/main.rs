mod hub;
mod topcmd;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

/// Read-only observability for Firecracker microVMs.
#[derive(Debug, Parser)]
#[command(name = "scope", version)]
struct Cli {
    /// Read /proc and /sys under this directory instead of / (fixtures, containers).
    #[arg(long, global = true, default_value = "/")]
    root: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// What are the microVMs on this host doing right now?
    Top(topcmd::Args),
}

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = s.find(|c: char| !c.is_ascii_digit() && c != '.').map_or((s, "s"), |i| s.split_at(i));
    let n: f64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" => n,
        "m" => n * 60.0,
        _ => return Err(format!("bad duration unit in {s:?}; use ms, s or m")),
    };
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("duration must be positive: {s:?}"));
    }
    Ok(Duration::from_secs_f64(secs))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = if cli.root == std::path::Path::new("/") { host::Root::live() } else { host::Root::at(&cli.root) };
    match cli.cmd {
        Cmd::Top(a) => topcmd::run(root, a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("5h").is_err());
    }
}
