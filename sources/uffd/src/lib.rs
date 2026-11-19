//! `scope fault serve`: scope as firecracker's page-fault handler.
//!
//! Protocol (firecracker `examples/uffd/uffd_utils.rs`): firecracker connects
//! to our unix socket during `PUT /snapshot/load` with `backend_type: Uffd`,
//! sends a JSON array of regions plus the userfaultfd over SCM_RIGHTS, then
//! resumes the guest. Every first touch of a page blocks the vCPU until we
//! `UFFDIO_COPY` it from the snapshot memory file. We record each fault.
//!
//! This is the one place scope affects a VM: if the handler stops, the guest
//! stalls. It only runs when the operator points firecracker at it.

pub mod mapping;
pub mod ranges;

#[cfg(target_os = "linux")]
pub mod handler;
#[cfg(target_os = "linux")]
pub mod sys;

pub use mapping::{Mapping, parse_mappings};
