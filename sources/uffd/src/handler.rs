//! The serve loop: accept firecracker, receive the uffd, answer page faults
//! from the memory file, record every fault.

use crate::ranges::Ranges;
use crate::sys::{self, CopyResult, Msg};
use crate::{Mapping, parse_mappings};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use telemetry::trace::{Entry, Header, Region};
use telemetry::{FaultRecord, StopToken, fault_flags};

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub faults: u64,
    pub prefetched: u64,
    pub zero_filled: u64,
    pub removes: u64,
    pub bytes: u64,
}

/// Bind the handler socket. Never unlinks an existing path: it may be another
/// handler's live socket, and a stale one is the operator's call to remove.
pub fn bind(path: &Path, owner: Option<(u32, u32)>) -> io::Result<UnixListener> {
    if path.symlink_metadata().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists; remove it first", path.display()),
        ));
    }
    let l = UnixListener::bind(path)?;
    // 0600: whoever can connect can feed us a uffd and region list.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    if let Some((uid, gid)) = owner {
        // jailed firecracker runs as the jail uid and must be able to connect.
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    Ok(l)
}

/// Accept one connection and run the handshake: region json + uffd fd.
/// Firecracker sometimes delivers the bytes before the fd, so retry a few times
/// like its example handler does.
pub fn accept(l: &UnixListener) -> io::Result<(OwnedFd, Vec<Mapping>, std::os::unix::net::UnixStream)> {
    let (stream, _) = l.accept()?;
    let mut body = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..5 {
        let (n, fd) = sys::recv_with_fd(stream.as_fd(), &mut buf)?;
        body.extend_from_slice(&buf[..n]);
        if let Some(fd) = fd {
            let maps = parse_mappings(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            return Ok((fd, maps, stream));
        }
        if n == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "peer sent no uffd"))
}

pub struct Handler {
    uffd: OwnedFd,
    maps: Vec<Mapping>,
    mem: memmap2::Mmap,
    page: u64,
    removed: Ranges,
    t0: Instant,
    pub summary: Summary,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("maps", &self.maps).field("summary", &self.summary).finish()
    }
}

/// Receives every resolved fault.
pub type Sink<'a> = &'a mut dyn FnMut(&Entry);

impl Handler {
    pub fn new(uffd: OwnedFd, maps: Vec<Mapping>, mem: &File) -> io::Result<Self> {
        let need = maps.iter().map(|m| m.offset + m.size).max().unwrap_or(0);
        let have = mem.metadata()?.len();
        if have < need {
            // copying past EOF of a mapped file would SIGBUS us, not error.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("memory file is {have} bytes, regions need {need}"),
            ));
        }
        // SAFETY: the file is opened read-only and mapped private; if someone truncates it
        // under us we can still SIGBUS, which is why the operator owns the snapshot files.
        let mem = unsafe { memmap2::MmapOptions::new().map(mem) }?;
        let page = maps[0].page_size;
        Ok(Self {
            uffd,
            maps,
            mem,
            page,
            removed: Ranges::default(),
            t0: Instant::now(),
            summary: Summary::default(),
        })
    }

    pub fn header(&self) -> Header {
        Header {
            page_size: self.page as u32,
            t0_unix_ns: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
                - self.t0.elapsed().as_nanos() as u64,
            regions: self
                .maps
                .iter()
                .map(|m| Region { host_base: m.base_host_virt_addr, size: m.size, file_offset: m.offset })
                .collect(),
        }
    }

    fn map_for(&self, addr: u64) -> Option<&Mapping> {
        self.maps.iter().find(|m| m.contains(addr))
    }

    /// Populate one page. Returns the flags to record, or None when it was already present.
    fn populate(&mut self, page_addr: u64, sink: Sink) -> io::Result<Option<(u64, u16)>> {
        let Some(m) = self.map_for(page_addr).copied() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("fault at {page_addr:#x} outside every region"),
            ));
        };
        let off = m.file_offset(page_addr);
        let zeroed = self.removed.contains(page_addr);
        loop {
            let r = if zeroed {
                self.zero(page_addr)?
            } else {
                // bounds were checked against the file size in new().
                let src = self.mem[off as usize..].as_ptr();
                sys::copy(self.uffd.as_fd(), page_addr, src, self.page)?
            };
            match r {
                CopyResult::Done => return Ok(Some((off, if zeroed { fault_flags::ZEROED } else { 0 }))),
                CopyResult::Exists => return Ok(None),
                // a remove/unmap is racing us; apply pending events, then retry.
                CopyResult::Again => {
                    let _ = self.step(None, sink)?;
                }
            }
        }
    }

    fn zero(&mut self, page_addr: u64) -> io::Result<CopyResult> {
        self.summary.zero_filled += 1;
        if self.page == 4096 {
            return sys::zeropage(self.uffd.as_fd(), page_addr, self.page);
        }
        // UFFDIO_ZEROPAGE does not support hugetlbfs; copy from a zero buffer instead.
        let zeros = vec![0u8; self.page as usize];
        sys::copy(self.uffd.as_fd(), page_addr, zeros.as_ptr(), self.page)
    }

    fn record(&self, off: u64, start: Instant, tid: u32, flags: u16, sink: Sink) {
        let e = Entry {
            fault: FaultRecord {
                ts_ns: start.duration_since(self.t0).as_nanos() as u64,
                offset: off,
                page_size: self.page as u32,
                resolve_ns: start.elapsed().as_nanos().min(u32::MAX as u128) as u32,
                flags,
            },
            tid,
        };
        sink(&e);
    }

    /// Eagerly populate file offsets (a `.ws` working set). Recorded with PREFETCHED.
    pub fn prefetch(&mut self, offsets: &[u64], sink: Sink) -> io::Result<()> {
        for &off in offsets {
            let Some(m) = self.maps.iter().find(|m| off >= m.offset && off - m.offset < m.size).copied() else {
                continue;
            };
            let addr = m.base_host_virt_addr + (off - m.offset) / self.page * self.page;
            let start = Instant::now();
            if let Some((off, flags)) = self.populate(addr, sink)? {
                self.summary.prefetched += 1;
                self.record(off, start, 0, flags | fault_flags::PREFETCHED, sink);
            }
        }
        Ok(())
    }

    /// Poll up to `wait`, then handle one batch. Returns false once firecracker has gone away.
    fn step(&mut self, wait: Option<Duration>, sink: Sink) -> io::Result<bool> {
        let mut pfd = libc::pollfd { fd: self.uffd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ms = wait.map_or(0, |d| d.as_millis().min(i32::MAX as u128) as i32);
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted { Ok(true) } else { Err(e) };
        }
        if rc == 0 {
            return Ok(true);
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 && pfd.revents & libc::POLLIN == 0 {
            return Ok(false);
        }
        let mut buf = [0u8; sys::MSG_SIZE * 16];
        // SAFETY: buf is valid for writes of its length.
        let n = unsafe { libc::read(self.uffd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(libc::EAGAIN) { Ok(true) } else { Err(e) };
        }
        if n == 0 {
            return Ok(false);
        }
        let start = Instant::now();
        let msgs: Vec<Msg> =
            buf[..n as usize].chunks_exact(sys::MSG_SIZE).filter_map(|c| c.try_into().ok().map(sys::decode)).collect();
        // removes first: a fault in the same batch may target a just-removed page.
        for m in &msgs {
            if let Msg::Remove { start, end } | Msg::Unmap { start, end } = *m {
                self.summary.removes += 1;
                self.removed.add(start, end);
            }
        }
        for m in msgs {
            if let Msg::PageFault { flags, address, ptid } = m {
                let page_addr = address & !(self.page - 1);
                if let Some((off, extra)) = self.populate(page_addr, sink)? {
                    self.summary.faults += 1;
                    self.summary.bytes += self.page;
                    let w = if flags & sys::UFFD_PAGEFAULT_FLAG_WRITE != 0 { fault_flags::WRITE } else { 0 };
                    self.record(off, start, ptid, w | extra, sink);
                }
            }
        }
        Ok(true)
    }

    /// Serve until firecracker exits (uffd hangs up) or `stop` fires.
    pub fn run(&mut self, stop: &StopToken, sink: Sink) -> io::Result<()> {
        while !stop.is_stopped() {
            match self.step(Some(Duration::from_millis(100)), sink) {
                Ok(true) => {}
                Ok(false) => break,
                // ESRCH/ENOENT: the vm is exiting mid-copy.
                Err(e) if matches!(e.raw_os_error(), Some(libc::ESRCH) | Some(libc::ENOENT)) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
