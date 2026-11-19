//! Address -> name, via blazesym. User frames resolve through the target
//! process (blazesym reads /proc/<pid>/map_files, so jailed binaries work),
//! kernel frames through kallsyms.

use blazesym::Pid;
use blazesym::normalize::{Normalizer, UserMeta};
use blazesym::symbolize::source::{Elf, Kernel, Process, Source};
use blazesym::symbolize::{Input, Symbolized, Symbolizer};
use std::collections::HashMap;
use std::path::Path;

pub struct Syms {
    s: Symbolizer,
}

fn names(out: Vec<Symbolized<'_>>, addrs: &[u64], prefix: &str) -> HashMap<u64, String> {
    addrs
        .iter()
        .zip(out)
        .map(|(a, s)| {
            let n = match s.as_sym() {
                Some(sym) => format!("{prefix}{}", sym.name),
                None => format!("{prefix}{a:#x}"),
            };
            (*a, n)
        })
        .collect()
}

impl Syms {
    pub fn new() -> Self {
        Self { s: Symbolizer::new() }
    }

    /// `debug_file`: separate debug info for a stripped firecracker. Addresses are
    /// normalized to file offsets in the running binary, converted to virtual
    /// addresses with its program headers, then looked up in the debug file.
    pub fn user(&self, pid: u32, debug_file: Option<&Path>, addrs: &[u64]) -> (HashMap<u64, String>, Option<String>) {
        if let Some(dbg) = debug_file {
            match self.user_debug(pid, dbg, addrs) {
                Ok(m) => return (m, None),
                Err(e) => {
                    let (m, _) = self.user(pid, None, addrs);
                    return (m, Some(format!("--debug-file not used: {e}")));
                }
            }
        }
        let src = Source::from(Process::new(Pid::from(pid)));
        match self.s.symbolize(&src, Input::AbsAddr(addrs)) {
            Ok(out) => (names(out, addrs, ""), None),
            Err(e) => (addrs.iter().map(|a| (*a, format!("{a:#x}"))).collect(), Some(format!("user symbols: {e}"))),
        }
    }

    fn user_debug(&self, pid: u32, dbg: &Path, addrs: &[u64]) -> Result<HashMap<u64, String>, String> {
        let normalizer = Normalizer::new();
        let norm = normalizer.normalize_user_addrs(Pid::from(pid), addrs).map_err(|e| e.to_string())?;
        let exe = std::fs::read(format!("/proc/{pid}/exe")).map_err(|e| format!("read exe: {e}"))?;
        let loads = crate::symbols::pt_loads(&exe).ok_or("exe is not a 64-bit little-endian elf")?;
        let mut virt = Vec::with_capacity(addrs.len());
        for (off, meta) in &norm.outputs {
            let main = matches!(norm.meta.get(*meta), Some(UserMeta::Elf(e)) if e.path.file_name().is_some_and(|n| n.to_string_lossy().contains("firecracker")));
            let v = if main {
                loads.iter().find(|l| *off >= l.0 && *off < l.0 + l.2).map(|l| off - l.0 + l.1)
            } else {
                None
            };
            virt.push(v);
        }
        let want: Vec<u64> = virt.iter().flatten().copied().collect();
        let out =
            self.s.symbolize(&Source::from(Elf::new(dbg)), Input::VirtOffset(&want)).map_err(|e| e.to_string())?;
        let by_virt = names(out, &want, "");
        Ok(addrs
            .iter()
            .zip(virt)
            .map(|(a, v)| (*a, v.and_then(|v| by_virt.get(&v).cloned()).unwrap_or_else(|| format!("{a:#x}"))))
            .collect())
    }

    pub fn kernel(&self, addrs: &[u64]) -> HashMap<u64, String> {
        let src = Source::Kernel(Kernel::default());
        match self.s.symbolize(&src, Input::AbsAddr(addrs)) {
            Ok(out) => names(out, addrs, "[k] "),
            Err(_) => addrs.iter().map(|a| (*a, format!("[k] {a:#x}"))).collect(),
        }
    }

    /// Guest kernel pcs against the guest's vmlinux. `kaslr` is subtracted first.
    pub fn guest(&self, vmlinux: &Path, kaslr: u64, pcs: &[u64]) -> HashMap<u64, String> {
        let virt: Vec<u64> = pcs.iter().map(|p| p.wrapping_sub(kaslr)).collect();
        match self.s.symbolize(&Source::from(Elf::new(vmlinux)), Input::VirtOffset(&virt)) {
            Ok(out) => {
                let m = names(out, &virt, "[guest] ");
                pcs.iter().zip(&virt).map(|(p, v)| (*p, m[v].clone())).collect()
            }
            Err(_) => pcs.iter().map(|p| (*p, format!("[guest] {p:#x}"))).collect(),
        }
    }
}

/// (p_offset, p_vaddr, p_filesz) of each PT_LOAD in an ELF64 LE image.
pub fn pt_loads(b: &[u8]) -> Option<Vec<(u64, u64, u64)>> {
    if b.get(..4)? != b"\x7fELF" || *b.get(4)? != 2 || *b.get(5)? != 1 {
        return None;
    }
    let u16_at = |o: usize| b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
    let u32_at = |o: usize| b.get(o..o + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes);
    let u64_at = |o: usize| b.get(o..o + 8).and_then(|s| s.try_into().ok()).map(u64::from_le_bytes);
    let phoff = u64_at(0x20)? as usize;
    let (entsz, num) = (u16_at(0x36)? as usize, u16_at(0x38)? as usize);
    let mut out = vec![];
    for i in 0..num {
        let p = phoff + i * entsz;
        if u32_at(p)? == 1 {
            out.push((u64_at(p + 8)?, u64_at(p + 16)?, u64_at(p + 32)?));
        }
    }
    Some(out)
}
