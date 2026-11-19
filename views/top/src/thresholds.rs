use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    #[default]
    Ok,
    Warn,
    Crit,
}

/// When a row turns amber or red. Percentages are 0..=100.
///
/// Defaults are starting points, not tuned values; a config file can
/// override them later (todo).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    /// worst vCPU's share of wall time spent runnable but not running.
    pub wait_pct: (f64, f64),
    /// share of wall time the cgroup was throttled.
    pub throttle_pct: (f64, f64),
    /// memory.current as share of memory.max.
    pub mem_pct: (f64, f64),
    pub exits_per_s: (f64, f64),
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            wait_pct: (10.0, 25.0),
            throttle_pct: (5.0, 20.0),
            mem_pct: (85.0, 95.0),
            exits_per_s: (50_000.0, 200_000.0),
        }
    }
}

pub fn level(v: f64, (warn, crit): (f64, f64)) -> Level {
    if v >= crit {
        Level::Crit
    } else if v >= warn {
        Level::Warn
    } else {
        Level::Ok
    }
}
