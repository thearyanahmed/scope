//! Tracepoint field layouts from tracefs `format` files, so programs never
//! hardcode offsets that move between kernels and arches.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

/// Parse lines like `field:unsigned int exit_reason; offset:8; size:4; signed:0;` (tab separated).
pub fn parse_format(s: &str) -> Vec<Field> {
    s.lines()
        .filter_map(|l| {
            let l = l.trim();
            let decl = l.strip_prefix("field:")?.split(';').next()?;
            // the name is the last token, minus any array suffix: "char prev_comm[16]".
            let name = decl.split_whitespace().last()?.split('[').next()?.to_owned();
            let num = |key: &str| l.split(';').find_map(|p| p.trim().strip_prefix(key)?.trim().parse().ok());
            Some(Field { name, offset: num("offset:")?, size: num("size:")? })
        })
        .collect()
}

pub fn find<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields.iter().find(|f| f.name == name)
}

/// tracefs is at /sys/kernel/tracing on 4.1+; older setups only mount it under debugfs.
pub fn root() -> Option<PathBuf> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.join("events").is_dir())
}

pub fn read(root: &Path, category: &str, name: &str) -> Option<Vec<Field>> {
    std::fs::read_to_string(root.join("events").join(category).join(name).join("format")).ok().map(|s| parse_format(&s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/../../fixtures/tracefs/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn x86_kvm_exit() {
        let f = parse_format(&fixture("x86_64.kvm_exit.format"));
        assert_eq!(find(&f, "exit_reason").map(|f| (f.offset, f.size)), Some((8, 4)));
        assert_eq!(find(&f, "guest_rip").map(|f| (f.offset, f.size)), Some((16, 8)));
        assert_eq!(find(&f, "isa").map(|f| f.offset), Some(24));
        assert_eq!(find(&f, "common_pid").map(|f| f.offset), Some(4));
    }

    #[test]
    fn arm64_kvm_exit_and_sched_switch() {
        let f = parse_format(&fixture("aarch64.kvm_exit.format"));
        assert_eq!(find(&f, "esr_ec").map(|f| f.offset), Some(12));
        assert_eq!(find(&f, "vcpu_pc").map(|f| (f.offset, f.size)), Some((16, 8)));
        let s = parse_format(&fixture("sched_switch.format"));
        assert_eq!(find(&s, "prev_comm").map(|f| (f.offset, f.size)), Some((8, 16)));
        assert_eq!(find(&s, "prev_pid").map(|f| f.offset), Some(24));
        assert_eq!(find(&s, "next_pid").map(|f| f.offset), Some(56));
    }
}
