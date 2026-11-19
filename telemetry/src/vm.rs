use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Stable identifier: firecracker `--id` when given, else `pid-<pid>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VmId(pub String);

impl VmId {
    pub fn from_pid(pid: u32) -> Self {
        Self(format!("pid-{pid}"))
    }
}

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vm {
    pub id: VmId,
    pub pid: u32,
    pub jailed: bool,
    /// `/proc/<pid>/root`; in-jail paths resolve under it.
    pub root: PathBuf,
    /// Paths as firecracker sees them (inside the jail if jailed).
    pub api_sock: Option<PathBuf>,
    pub metrics_path: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub vcpus: Vec<Vcpu>,
    pub threads: Vec<VmmThread>,
    pub taps: Vec<String>,
    /// Absolute cgroup v2 directory on the host, e.g. `/sys/fs/cgroup/firecracker/vm1`.
    pub cgroup: Option<PathBuf>,
    /// Unix epoch milliseconds.
    pub started_ms: u64,
}

impl Vm {
    /// Translate a path seen by firecracker into one readable from the host.
    pub fn host_path(&self, p: &std::path::Path) -> PathBuf {
        let rel = p.strip_prefix("/").unwrap_or(p);
        self.root.join(rel)
    }

    pub fn tids(&self) -> impl Iterator<Item = u32> + '_ {
        self.vcpus.iter().map(|v| v.tid).chain(self.threads.iter().map(|t| t.tid))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vcpu {
    pub index: u32,
    pub tid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmmThread {
    pub tid: u32,
    pub name: String,
    pub kind: ThreadKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadKind {
    /// main thread: runs the device-emulation event loop.
    Vmm,
    Api,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_path_joins_under_root() {
        let vm = Vm {
            id: VmId("a".into()),
            pid: 1,
            jailed: true,
            root: "/proc/1/root".into(),
            api_sock: None,
            metrics_path: None,
            config_file: None,
            vcpus: vec![],
            threads: vec![],
            taps: vec![],
            cgroup: None,
            started_ms: 0,
        };
        assert_eq!(vm.host_path("/run/fc.sock".as_ref()), PathBuf::from("/proc/1/root/run/fc.sock"));
        assert_eq!(vm.host_path("rel.sock".as_ref()), PathBuf::from("/proc/1/root/rel.sock"));
    }
}
