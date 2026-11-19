//! Check privileges up front so a command can say exactly what is missing.

use crate::Root;
use telemetry::Privilege;

const CAP_SYS_PTRACE: u32 = 19;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Creds {
    pub euid: u32,
    pub cap_eff: u64,
}

/// Parse `Uid:` and `CapEff:` from /proc/self/status.
pub fn creds(status: &str) -> Creds {
    let mut c = Creds::default();
    for l in status.lines() {
        if let Some(v) = l.strip_prefix("Uid:") {
            // real, effective, saved, fs
            c.euid = v.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(u32::MAX);
        } else if let Some(v) = l.strip_prefix("CapEff:") {
            c.cap_eff = u64::from_str_radix(v.trim(), 16).unwrap_or(0);
        }
    }
    c
}

impl Creds {
    fn has(&self, cap: u32) -> bool {
        self.cap_eff & (1 << cap) != 0
    }

    /// Ok means granted. PtraceRead is reported as granted for non-root too,
    /// because same-uid access works and can only be judged per process.
    pub fn grants(&self, p: Privilege, root: &Root) -> bool {
        match p {
            Privilege::PtraceRead | Privilege::ApiSocket => true,
            Privilege::Debugfs => root.path("sys/kernel/debug/kvm").is_dir(),
            Privilege::CapBpf => self.has(CAP_BPF) || self.has(CAP_SYS_ADMIN),
            Privilege::CapPerfmon => self.has(CAP_PERFMON) || self.has(CAP_SYS_ADMIN),
        }
    }

    pub fn can_ptrace_any(&self) -> bool {
        self.euid == 0 || self.has(CAP_SYS_PTRACE)
    }
}

/// Privileges from `needs` that this process lacks.
pub fn missing(root: &Root, needs: &[Privilege]) -> Vec<Privilege> {
    let c = std::fs::read_to_string("/proc/self/status").map(|s| creds(&s)).unwrap_or_default();
    needs.iter().copied().filter(|p| !c.grants(*p, root)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let c = creds("Name:\tscope\nUid:\t1000\t0\t0\t0\nCapEff:\t000001c000000000\n");
        assert_eq!(c.euid, 0);
        assert!(c.has(CAP_BPF) && c.has(CAP_PERFMON));
        assert!(!c.has(CAP_SYS_ADMIN));
        let root = Root::at("/nonexistent");
        assert!(c.grants(Privilege::CapBpf, &root));
        assert!(!c.grants(Privilege::Debugfs, &root));
    }
}
