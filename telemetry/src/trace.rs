//! `scope fault` trace format, version 1. Owned by scope; little-endian.
//!
//! ```text
//! header (32 bytes)
//!   0  magic        [u8; 8]  "SCOPEFLT"
//!   8  version      u16      1
//!   10 record_size  u16      32 (readers skip unknown trailing bytes when larger)
//!   12 page_size    u32
//!   16 t0_unix_ns   u64      wall clock at ts_ns == 0
//!   24 region_count u32
//!   28 reserved     u32
//! regions (24 bytes each)
//!   host_base u64, size u64, file_offset u64
//! records (record_size bytes each, append-only)
//!   0  ts_ns      u64  since t0
//!   8  offset     u64  into the guest memory file (snapshot mem file layout)
//!   16 resolve_ns u32
//!   20 tid        u32  faulting thread, 0 when the capture can't know it
//!   24 flags      u16  telemetry::fault_flags
//!   26 reserved   [u8; 6]
//! ```
//!
//! Fixed-size records let the handler write from its hot path without
//! framing and let viewers mmap the file and index it directly.
//! `offset` is a memory-file offset rather than a guest-physical address:
//! firecracker's uffd handshake gives host addresses and file offsets only.

use crate::FaultRecord;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

pub const MAGIC: &[u8; 8] = b"SCOPEFLT";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 32;
pub const REGION_SIZE: usize = 24;
pub const RECORD_SIZE: usize = 32;
/// a header claiming more regions than this is corrupt, not big.
pub const MAX_REGIONS: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Region {
    pub host_base: u64,
    pub size: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub page_size: u32,
    pub t0_unix_ns: u64,
    pub regions: Vec<Region>,
}

/// A fault record with the thread that took it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(flatten)]
    pub fault: FaultRecord,
    pub tid: u32,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_SIZE + self.regions.len() * REGION_SIZE);
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.extend_from_slice(&(RECORD_SIZE as u16).to_le_bytes());
        b.extend_from_slice(&self.page_size.to_le_bytes());
        b.extend_from_slice(&self.t0_unix_ns.to_le_bytes());
        b.extend_from_slice(&(self.regions.len() as u32).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        for r in &self.regions {
            b.extend_from_slice(&r.host_base.to_le_bytes());
            b.extend_from_slice(&r.size.to_le_bytes());
            b.extend_from_slice(&r.file_offset.to_le_bytes());
        }
        b
    }

    /// Total bytes covered by all regions.
    pub fn mem_size(&self) -> u64 {
        self.regions.iter().map(|r| r.file_offset + r.size).max().unwrap_or(0)
    }
}

pub fn encode_entry(e: &Entry) -> [u8; RECORD_SIZE] {
    let mut b = [0u8; RECORD_SIZE];
    b[0..8].copy_from_slice(&e.fault.ts_ns.to_le_bytes());
    b[8..16].copy_from_slice(&e.fault.offset.to_le_bytes());
    b[16..20].copy_from_slice(&e.fault.resolve_ns.to_le_bytes());
    b[20..24].copy_from_slice(&e.tid.to_le_bytes());
    b[24..26].copy_from_slice(&e.fault.flags.to_le_bytes());
    b
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    Version(u16),
    BadRecordSize(u16),
    TooManyRegions(u32),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "truncated header"),
            Self::BadMagic => write!(f, "not a scope fault trace"),
            Self::Version(v) => write!(f, "unsupported trace version {v}"),
            Self::BadRecordSize(s) => write!(f, "record size {s} smaller than {RECORD_SIZE}"),
            Self::TooManyRegions(n) => write!(f, "{n} regions"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// A decoded view over trace bytes (typically an mmap). Records are decoded lazily.
#[derive(Debug)]
pub struct Trace<'a> {
    pub header: Header,
    record_size: usize,
    records: &'a [u8],
}

impl<'a> Trace<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self, DecodeError> {
        if b.len() < HEADER_SIZE {
            return Err(DecodeError::TooShort);
        }
        if &b[..8] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let v = u16_at(b, 8);
        if v != VERSION {
            return Err(DecodeError::Version(v));
        }
        let rs = u16_at(b, 10);
        if (rs as usize) < RECORD_SIZE {
            return Err(DecodeError::BadRecordSize(rs));
        }
        let n = u32_at(b, 24);
        if n > MAX_REGIONS {
            return Err(DecodeError::TooManyRegions(n));
        }
        let start = HEADER_SIZE + n as usize * REGION_SIZE;
        if b.len() < start {
            return Err(DecodeError::TooShort);
        }
        let regions = (0..n as usize)
            .map(|i| {
                let o = HEADER_SIZE + i * REGION_SIZE;
                Region { host_base: u64_at(b, o), size: u64_at(b, o + 8), file_offset: u64_at(b, o + 16) }
            })
            .collect();
        let body = &b[start..];
        // a writer killed mid-record leaves a partial tail; ignore it.
        let whole = body.len() - body.len() % rs as usize;
        Ok(Self {
            header: Header { page_size: u32_at(b, 12), t0_unix_ns: u64_at(b, 16), regions },
            record_size: rs as usize,
            records: &body[..whole],
        })
    }

    pub fn len(&self) -> usize {
        self.records.len() / self.record_size
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, i: usize) -> Option<Entry> {
        let o = i.checked_mul(self.record_size)?;
        let r = self.records.get(o..o + RECORD_SIZE)?;
        Some(Entry {
            fault: FaultRecord {
                ts_ns: u64_at(r, 0),
                offset: u64_at(r, 8),
                resolve_ns: u32_at(r, 16),
                page_size: self.header.page_size,
                flags: u16_at(r, 24),
            },
            tid: u32_at(r, 20),
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = Entry> + '_ {
        (0..self.len()).filter_map(|i| self.get(i))
    }
}

/// Streams a trace: header first, then one record per call.
#[derive(Debug)]
pub struct Writer<W: Write> {
    w: W,
}

impl<W: Write> Writer<W> {
    pub fn new(mut w: W, h: &Header) -> io::Result<Self> {
        w.write_all(&h.encode())?;
        Ok(Self { w })
    }

    pub fn push(&mut self, e: &Entry) -> io::Result<()> {
        self.w.write_all(&encode_entry(e))
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }

    pub fn into_inner(self) -> W {
        self.w
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault_flags;

    fn header() -> Header {
        Header {
            page_size: 4096,
            t0_unix_ns: 42,
            regions: vec![
                Region { host_base: 0x7f00_0000_0000, size: 1 << 20, file_offset: 0 },
                Region { host_base: 0x7f10_0000_0000, size: 1 << 20, file_offset: 1 << 20 },
            ],
        }
    }

    fn entry(i: u64) -> Entry {
        Entry {
            fault: FaultRecord {
                ts_ns: i * 10,
                offset: i * 4096,
                page_size: 4096,
                resolve_ns: 7,
                flags: fault_flags::WRITE,
            },
            tid: 99,
        }
    }

    #[test]
    fn roundtrip() {
        let mut w = Writer::new(Vec::new(), &header()).unwrap();
        for i in 0..3 {
            w.push(&entry(i)).unwrap();
        }
        let mut bytes = w.into_inner();
        assert_eq!(bytes.len(), HEADER_SIZE + 2 * REGION_SIZE + 3 * RECORD_SIZE);
        // partial trailing record from a crashed writer
        bytes.extend_from_slice(&[1, 2, 3]);
        let t = Trace::parse(&bytes).unwrap();
        assert_eq!(t.header, header());
        assert_eq!(t.header.mem_size(), 2 << 20);
        assert_eq!(t.len(), 3);
        assert_eq!(t.iter().collect::<Vec<_>>(), (0..3).map(entry).collect::<Vec<_>>());
        assert!(t.get(3).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Trace::parse(b"short").unwrap_err(), DecodeError::TooShort);
        assert_eq!(Trace::parse(&[0u8; 64]).unwrap_err(), DecodeError::BadMagic);
        let mut h = header().encode();
        h[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Trace::parse(&h).unwrap_err(), DecodeError::TooManyRegions(u32::MAX));
        let mut h = header().encode();
        h[8] = 9;
        assert_eq!(Trace::parse(&h).unwrap_err(), DecodeError::Version(9));
    }

    #[test]
    fn larger_records_from_a_newer_writer_still_parse() {
        let mut b = header().encode();
        b[10..12].copy_from_slice(&40u16.to_le_bytes());
        let mut rec = encode_entry(&entry(1)).to_vec();
        rec.extend_from_slice(&[0xff; 8]);
        b.extend_from_slice(&rec);
        let t = Trace::parse(&b).unwrap();
        assert_eq!(t.get(0), Some(entry(1)));
    }
}
