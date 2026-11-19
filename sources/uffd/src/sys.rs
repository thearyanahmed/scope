//! userfaultfd ABI from include/uapi/linux/userfaultfd.h. The ioctl numbers
//! use the asm-generic encoding, which x86_64 and aarch64 share:
//! `_IOWR(t, nr, size) = 3 << 30 | size << 16 | t << 8 | nr`.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

pub const UFFD_API: u64 = 0xAA;
pub const UFFDIO_API: libc::c_ulong = 0xC018_AA3F;
pub const UFFDIO_REGISTER: libc::c_ulong = 0xC020_AA00;
pub const UFFDIO_COPY: libc::c_ulong = 0xC028_AA03;
pub const UFFDIO_ZEROPAGE: libc::c_ulong = 0xC020_AA04;
pub const UFFDIO_WAKE: libc::c_ulong = 0x8010_AA02;

pub const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
pub const UFFD_FEATURE_EVENT_REMOVE: u64 = 1 << 3;
pub const UFFD_FEATURE_THREAD_ID: u64 = 1 << 8;
/// 5.11+: lets unprivileged callers create a uffd that only sees user faults.
pub const UFFD_USER_MODE_ONLY: libc::c_int = 1;

pub const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
pub const UFFD_EVENT_REMOVE: u8 = 0x15;
pub const UFFD_EVENT_UNMAP: u8 = 0x16;
pub const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1;

pub const MSG_SIZE: usize = 32;

#[repr(C)]
#[derive(Debug, Default)]
pub struct UffdioApi {
    pub api: u64,
    pub features: u64,
    pub ioctls: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UffdioRange {
    pub start: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UffdioRegister {
    pub range: UffdioRange,
    pub mode: u64,
    pub ioctls: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UffdioCopy {
    pub dst: u64,
    pub src: u64,
    pub len: u64,
    pub mode: u64,
    pub copy: i64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct UffdioZeropage {
    pub range: UffdioRange,
    pub mode: u64,
    pub zeropage: i64,
}

const _: () = {
    assert!(size_of::<UffdioApi>() == 24);
    assert!(size_of::<UffdioRegister>() == 32);
    assert!(size_of::<UffdioCopy>() == 40);
    assert!(size_of::<UffdioZeropage>() == 32);
};

/// Decoded `struct uffd_msg` (packed, 32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg {
    PageFault { flags: u64, address: u64, ptid: u32 },
    Remove { start: u64, end: u64 },
    Unmap { start: u64, end: u64 },
    Other(u8),
}

pub fn decode(b: &[u8; MSG_SIZE]) -> Msg {
    let u64_at = |o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
    match b[0] {
        UFFD_EVENT_PAGEFAULT => Msg::PageFault {
            flags: u64_at(8),
            address: u64_at(16),
            ptid: u32::from_ne_bytes(b[24..28].try_into().unwrap_or([0; 4])),
        },
        UFFD_EVENT_REMOVE => Msg::Remove { start: u64_at(8), end: u64_at(16) },
        UFFD_EVENT_UNMAP => Msg::Unmap { start: u64_at(8), end: u64_at(16) },
        e => Msg::Other(e),
    }
}

/// # Safety
/// `arg` must point to the struct the ioctl `req` expects.
unsafe fn ioctl<T>(fd: BorrowedFd<'_>, req: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    // SAFETY: forwarded from the caller.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), req as _, arg as *mut T) };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CopyResult {
    Done,
    /// page already present (another fault or a prefetch won the race).
    Exists,
    /// the mapping is changing (a remove/unmap event is pending): read events, then retry.
    Again,
}

fn classify(r: io::Result<()>) -> io::Result<CopyResult> {
    match r {
        Ok(()) => Ok(CopyResult::Done),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(CopyResult::Exists),
        Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => Ok(CopyResult::Again),
        Err(e) => Err(e),
    }
}

/// Copy `len` bytes from our address `src` into the faulting process at `dst`, and wake it.
pub fn copy(uffd: BorrowedFd<'_>, dst: u64, src: *const u8, len: u64) -> io::Result<CopyResult> {
    let mut c = UffdioCopy { dst, src: src as u64, len, mode: 0, copy: 0 };
    // SAFETY: c is a valid uffdio_copy; the kernel validates dst against the registered range
    // and reads len bytes from src, which the caller guarantees is mapped.
    classify(unsafe { ioctl(uffd, UFFDIO_COPY, &mut c) })
}

pub fn zeropage(uffd: BorrowedFd<'_>, dst: u64, len: u64) -> io::Result<CopyResult> {
    let mut z = UffdioZeropage { range: UffdioRange { start: dst, len }, mode: 0, zeropage: 0 };
    // SAFETY: z is a valid uffdio_zeropage.
    classify(unsafe { ioctl(uffd, UFFDIO_ZEROPAGE, &mut z) })
}

/// Create a userfaultfd (what firecracker does on its side). Used by tests and lab tooling.
pub fn create(features: u64) -> io::Result<OwnedFd> {
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: plain syscall; returns a new fd or -1.
    let mut fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) } as RawFd;
    if fd < 0 {
        // without CAP_SYS_PTRACE and vm.unprivileged_userfaultfd=0, only user-mode-only works.
        // SAFETY: as above.
        fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags | UFFD_USER_MODE_ONLY) } as RawFd;
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by the kernel and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut api = UffdioApi { api: UFFD_API, features, ioctls: 0 };
    // SAFETY: api is a valid uffdio_api.
    unsafe { ioctl(fd.as_fd_borrow(), UFFDIO_API, &mut api) }?;
    Ok(fd)
}

pub fn register(uffd: BorrowedFd<'_>, start: u64, len: u64) -> io::Result<()> {
    let mut r = UffdioRegister { range: UffdioRange { start, len }, mode: UFFDIO_REGISTER_MODE_MISSING, ioctls: 0 };
    // SAFETY: r is a valid uffdio_register.
    unsafe { ioctl(uffd, UFFDIO_REGISTER, &mut r) }
}

trait AsFdBorrow {
    fn as_fd_borrow(&self) -> BorrowedFd<'_>;
}

impl AsFdBorrow for OwnedFd {
    fn as_fd_borrow(&self) -> BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(self)
    }
}

/// Receive bytes and at most one fd (SCM_RIGHTS) from a unix stream.
pub fn recv_with_fd(sock: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    // u64 storage keeps the control buffer aligned for cmsghdr.
    let mut cbuf = [0u64; 8];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    // SAFETY: zeroed msghdr is a valid "empty" value; fields are filled below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = size_of_val(&cbuf) as _;
    // SAFETY: msg points at live buffers for the duration of the call.
    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fd = None;
    // SAFETY: CMSG_* walk the control buffer the kernel just filled, bounded by msg_controllen.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let p = libc::CMSG_DATA(c) as *const RawFd;
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / size_of::<RawFd>();
                for i in 0..count {
                    let raw = p.add(i).read_unaligned();
                    // keep the first fd; close any extras so a confused peer can't leak fds into us.
                    let owned = OwnedFd::from_raw_fd(raw);
                    if fd.is_none() {
                        fd = Some(owned);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((n as usize, fd))
}

/// Send bytes plus one fd. The firecracker side of the handshake; used by tests.
pub fn send_with_fd(sock: BorrowedFd<'_>, buf: &[u8], fd: RawFd) -> io::Result<()> {
    let mut cbuf = [0u64; 8];
    let mut iov = libc::iovec { iov_base: buf.as_ptr() as *mut _, iov_len: buf.len() };
    // SAFETY: as in recv_with_fd.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE is a pure size computation.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as _;
    // SAFETY: the control buffer is large enough for one fd (checked by CMSG_SPACE above).
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        (libc::CMSG_DATA(c) as *mut RawFd).write_unaligned(fd);
    }
    // SAFETY: msg points at live buffers.
    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
    if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
