//! Resolve the `<vm>` argument: a firecracker --id, `pid-<pid>`, or a bare pid.

use anyhow::bail;
use telemetry::Vm;

pub fn find(root: &host::Root, sel: &str) -> anyhow::Result<Vm> {
    let vms = host::discover(root);
    let pid: Option<u32> = sel.parse().ok();
    if let Some(vm) = vms.iter().find(|v| v.id.0 == sel || Some(v.pid) == pid) {
        return Ok(vm.clone());
    }
    let known: Vec<_> = vms.iter().map(|v| format!("{} (pid {})", v.id, v.pid)).collect();
    if known.is_empty() {
        bail!("no firecracker processes found under {}", root.dir.display());
    }
    bail!("no vm {sel:?}; running: {}", known.join(", "))
}

/// Fail early, naming exactly what is missing.
pub fn require(root: &host::Root, needs: &[telemetry::Privilege]) -> anyhow::Result<()> {
    let missing = host::privileges::missing(root, needs);
    if missing.is_empty() {
        return Ok(());
    }
    let list: Vec<_> = missing.iter().map(|p| format!("  - {}", p.describe())).collect();
    bail!("missing privileges:\n{}", list.join("\n"))
}
