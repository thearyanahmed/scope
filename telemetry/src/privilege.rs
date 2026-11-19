use serde::{Deserialize, Serialize};

/// What a source needs from the host. Checked before a command starts so
/// failures name the missing capability instead of surfacing as EPERM later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Privilege {
    /// read /proc/<pid>/{io,fdinfo,smaps_rollup}: same uid + ptrace-read, or CAP_SYS_PTRACE.
    PtraceRead,
    /// /sys/kernel/debug is root-only and must be mounted.
    Debugfs,
    CapBpf,
    CapPerfmon,
    /// connect to a firecracker api socket (file permission on the socket).
    ApiSocket,
}

impl Privilege {
    pub fn describe(self) -> &'static str {
        match self {
            Self::PtraceRead => "ptrace-read access to firecracker processes (same uid, or CAP_SYS_PTRACE)",
            Self::Debugfs => "read access to /sys/kernel/debug/kvm (root, debugfs mounted)",
            Self::CapBpf => "CAP_BPF (or CAP_SYS_ADMIN on kernels < 5.8)",
            Self::CapPerfmon => "CAP_PERFMON (or CAP_SYS_ADMIN on kernels < 5.8)",
            Self::ApiSocket => "write permission on the firecracker api socket",
        }
    }
}
