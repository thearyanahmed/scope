//! The region list firecracker sends with the uffd. Validated because it
//! comes from the VMM process and drives raw memory copies.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub base_host_virt_addr: u64,
    pub size: u64,
    /// offset of this region in the snapshot memory file.
    pub offset: u64,
    pub page_size: u64,
}

impl Mapping {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base_host_virt_addr && addr - self.base_host_virt_addr < self.size
    }

    pub fn file_offset(&self, addr: u64) -> u64 {
        self.offset + (addr - self.base_host_virt_addr)
    }
}

/// Wire shape. `page_size_kib` is what firecracker sent before `page_size` (bytes) replaced it.
#[derive(Deserialize)]
struct Wire {
    base_host_virt_addr: u64,
    size: u64,
    offset: u64,
    page_size: Option<u64>,
    page_size_kib: Option<u64>,
}

pub const MAX_REGIONS: usize = 4096;

pub fn parse_mappings(body: &[u8]) -> Result<Vec<Mapping>, String> {
    let wire: Vec<Wire> = serde_json::from_slice(body).map_err(|e| format!("region json: {e}"))?;
    if wire.is_empty() || wire.len() > MAX_REGIONS {
        return Err(format!("{} regions", wire.len()));
    }
    let mut out = Vec::with_capacity(wire.len());
    for w in wire {
        let ps = match (w.page_size, w.page_size_kib) {
            (Some(b), _) => b,
            (None, Some(k)) => k.checked_mul(1024).ok_or("page size overflow")?,
            (None, None) => return Err("region without page size".into()),
        };
        if !ps.is_power_of_two() || !(4096..=1 << 30).contains(&ps) {
            return Err(format!("page size {ps}"));
        }
        let m = Mapping { base_host_virt_addr: w.base_host_virt_addr, size: w.size, offset: w.offset, page_size: ps };
        if m.size == 0
            || !m.size.is_multiple_of(ps)
            || !m.base_host_virt_addr.is_multiple_of(ps)
            || !m.offset.is_multiple_of(ps)
        {
            return Err(format!("region {m:?} is not page aligned"));
        }
        if m.base_host_virt_addr.checked_add(m.size).is_none() || m.offset.checked_add(m.size).is_none() {
            return Err(format!("region {m:?} overflows"));
        }
        out.push(m);
    }
    // firecracker documents a single page size for all regions; the handler relies on it.
    if out.iter().any(|m| m.page_size != out[0].page_size) {
        return Err("regions with different page sizes".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_and_legacy_shapes() {
        let m = parse_mappings(br#"[{"base_host_virt_addr":140000000000000,"size":8192,"offset":0,"page_size":4096},
                                   {"base_host_virt_addr":140000001048576,"size":4096,"offset":8192,"page_size":4096}]"#)
        .unwrap();
        assert_eq!(m.len(), 2);
        assert!(m[1].contains(140000001048576 + 4095));
        assert!(!m[1].contains(140000001048576 + 4096));
        assert_eq!(m[1].file_offset(140000001048576 + 100), 8292);
        let legacy =
            parse_mappings(br#"[{"base_host_virt_addr":2097152,"size":2097152,"offset":0,"page_size_kib":2048}]"#)
                .unwrap();
        assert_eq!(legacy[0].page_size, 2 << 20);
    }

    #[test]
    fn rejects_bad_regions() {
        for bad in [
            &br#"[]"#[..],
            br#"[{"base_host_virt_addr":4096,"size":4096,"offset":0,"page_size":3000}]"#,
            br#"[{"base_host_virt_addr":4097,"size":4096,"offset":0,"page_size":4096}]"#,
            br#"[{"base_host_virt_addr":4096,"size":0,"offset":0,"page_size":4096}]"#,
            br#"[{"base_host_virt_addr":18446744073709547520,"size":8192,"offset":0,"page_size":4096}]"#,
            br#"[{"base_host_virt_addr":4096,"size":4096,"offset":0}]"#,
            br#"[{"base_host_virt_addr":4096,"size":4096,"offset":0,"page_size":4096},{"base_host_virt_addr":2097152,"size":2097152,"offset":4096,"page_size":2097152}]"#,
            b"not json",
        ] {
            assert!(parse_mappings(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
