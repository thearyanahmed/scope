//! KVM statistics from debugfs.
//!
//! Each VM gets `/sys/kernel/debug/kvm/<pid>-<vm fd>/` holding one file per
//! counter (`exits`, `halt_exits`, `io_exits`, ... on x86; `exits`,
//! `wfi_exit_stat`, `mmio_exit_user`, ... on arm64) and `vcpuN/` subdirs.
//! Names differ by arch and kernel version, so every file holding a single
//! unsigned integer is collected as-is and interpretation is left to views.
//! Histogram files (several numbers) and signed values are skipped.
//!
//! debugfs is root-only. [`available`] lets callers degrade gracefully.

use host::Root;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;
use telemetry::{Event, KvmSample, Privilege, Sample, SampleData, Source, SourceError, StopToken, VmSet, mono_ns};

const DIR: &str = "sys/kernel/debug/kvm";

pub fn available(root: &Root) -> bool {
    std::fs::read_dir(root.path(DIR)).is_ok()
}

/// debugfs dir for a pid. Firecracker creates one VM per process.
pub fn vm_dir(root: &Root, pid: u32) -> Option<PathBuf> {
    let prefix = format!("{pid}-");
    std::fs::read_dir(root.path(DIR))
        .ok()?
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(&prefix)))
        .map(|e| e.path())
}

fn counters(dir: &Path) -> BTreeMap<String, u64> {
    let Ok(rd) = std::fs::read_dir(dir) else { return BTreeMap::new() };
    rd.filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| {
            let v = std::fs::read_to_string(e.path()).ok()?.trim().parse::<u64>().ok()?;
            Some((e.file_name().to_str()?.to_owned(), v))
        })
        .collect()
}

pub fn sample(root: &Root, pid: u32) -> Option<KvmSample> {
    let dir = vm_dir(root, pid)?;
    let mut vcpus = BTreeMap::new();
    for e in std::fs::read_dir(&dir).ok()?.filter_map(Result::ok) {
        let Some(i) = e.file_name().to_str().and_then(|n| n.strip_prefix("vcpu")?.parse::<u32>().ok()) else {
            continue;
        };
        let c = counters(&e.path());
        if !c.is_empty() {
            vcpus.insert(i, c);
        }
    }
    Some(KvmSample { vm: counters(&dir), vcpus })
}

#[derive(Debug)]
pub struct Kvm {
    pub root: Root,
    pub interval: Duration,
}

impl Kvm {
    pub fn new(root: Root) -> Self {
        Self { root, interval: Duration::from_secs(1) }
    }
}

impl Source for Kvm {
    fn name(&self) -> &'static str {
        "kvm"
    }

    fn needs(&self) -> &'static [Privilege] {
        &[Privilege::Debugfs]
    }

    fn run(self: Box<Self>, vms: VmSet, out: Sender<Event>, stop: StopToken) -> Result<(), SourceError> {
        if !available(&self.root) {
            return Err(SourceError::new("kvm", format!("cannot read /{DIR}: {}", Privilege::Debugfs.describe())));
        }
        loop {
            for vm in vms.snapshot() {
                if let Some(s) = sample(&self.root, vm.pid) {
                    let ev = Event::Sample(vm.id, Sample { ts_ns: mono_ns(), data: SampleData::Kvm(s) });
                    if out.send(ev).is_err() {
                        return Ok(());
                    }
                }
            }
            if !stop.sleep(self.interval) {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fixture() {
        let root = Root::at(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/host/two-vms"));
        assert!(available(&root));
        let s = sample(&root, 2000).unwrap();
        assert_eq!(s.vm["exits"], 123456);
        assert_eq!(s.vm["halt_exits"], 40000);
        assert!(!s.vm.contains_key("halt_poll_success_hist"), "histograms are skipped");
        assert_eq!(s.vcpus[&0]["exits"], 100000);
        assert!(!s.vcpus[&0].contains_key("tsc-offset"), "signed values are skipped");
        // pid 1000 has no debugfs dir (e.g. vm created by another kernel instance or not yet)
        assert!(sample(&root, 1000).is_none());
        // a pid that is a prefix of another must not match ("200" vs "2000-")
        assert!(sample(&root, 200).is_none());
    }
}
