// Copyright © 2026 Meridian
//
// SPDX-License-Identifier: Apache-2.0
//

//! Meridian cooperation seam: userfaultfd registration over guest RAM and
//! descriptor handoff to an external page-fault servicing process.
//!
//! When `--memory ...,uffd_handoff_socket=<path>` is configured, the VMM
//! registers every guest RAM region with one kernel `userfaultfd` descriptor
//! immediately after guest memory is created (before any payload is loaded
//! into guest RAM), then connects to the Unix socket at `<path>` and sends a
//! single message carrying:
//!
//! - a 4-byte little-endian length prefix,
//! - a JSON metadata document describing the registered regions and the
//!   truthful registration capabilities, and
//! - the `userfaultfd` descriptor itself as `SCM_RIGHTS` ancillary data.
//!
//! The peer must acknowledge the handoff with a single `0x01` byte before the
//! VMM proceeds to boot. Protocol version 2 then keeps the socket open for
//! sequenced EVICT requests; the VMM replies only after every requested
//! `MADV_DONTNEED` has completed and reports the exact errno for each PFN.
//! Faults on still-absent pages block until the peer resolves them (e.g. with
//! `UFFDIO_COPY`), which is exactly the demand-paging cooperation contract this
//! seam exists to provide.
//!
//! Every failure on this path is deterministic and fails VM creation: the
//! seam never silently degrades to unregistered guest memory.

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::Serialize;
use thiserror::Error;
use userfaultfd::{FeatureFlags, IoctlFlags, RegisterMode, Uffd, UffdBuilder};

/// Stable protocol identifier for the handoff metadata document.
pub const UFFD_HANDOFF_PROTOCOL: &str = "meridian-cloud-hypervisor-uffd-handoff";

/// Current handoff and post-handoff cooperation protocol version.
pub const UFFD_HANDOFF_VERSION: u32 = 2;

/// Acknowledgement byte the peer must send after receiving the handoff.
pub const UFFD_HANDOFF_ACK: u8 = 0x01;

#[derive(Debug, Error)]
pub enum UffdHandoffError {
    #[error("guest RAM has no eligible regions for userfaultfd handoff")]
    NoEligibleRegions,

    #[error("failed to create userfaultfd descriptor")]
    UffdCreate(#[source] userfaultfd::Error),

    #[error("failed to create minor-fault-capable userfaultfd descriptor")]
    UffdMinorCreate(#[source] std::io::Error),

    #[error(
        "failed to register guest RAM range (host_virt_addr {host_virt_addr:#x}, len {len}) \
         with userfaultfd"
    )]
    UffdRegister {
        host_virt_addr: usize,
        len: u64,
        #[source]
        source: userfaultfd::Error,
    },

    #[error("failed to connect to uffd handoff socket {path}")]
    SocketConnect {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to send uffd handoff payload")]
    SocketSend(#[source] std::io::Error),

    #[error("uffd handoff peer closed the socket before acknowledging the payload")]
    AckEof,

    #[error("failed to read uffd handoff acknowledgement")]
    AckRead(#[source] std::io::Error),

    #[error("uffd handoff peer returned unexpected acknowledgement byte {0:#x}")]
    AckUnexpected(u8),

    #[error("failed to spawn the uffd cooperation control thread")]
    CooperationThreadSpawn(#[source] std::io::Error),

    #[error("failed to serialize uffd handoff metadata")]
    Serialize(#[source] serde_json::Error),
}

/// One guest RAM region eligible for userfaultfd registration and handoff.
#[derive(Clone, Copy, Debug)]
pub struct UffdHandoffRegionSource {
    pub guest_phys_addr: u64,
    pub len: u64,
    pub host_virt_addr: usize,
    pub file_offset: u64,
    pub backing_dev: u64,
    pub backing_ino: u64,
    /// True when the region is mapped `MAP_SHARED`. A `MAP_PRIVATE` region is
    /// evictable by the owner (`MADV_DONTNEED` re-faults MISSING); a shared
    /// region is not (the page persists in the shared object).
    pub shared: bool,
}

/// Serialized per-region record in the handoff metadata document.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct UffdHandoffRegion {
    pub guest_phys_addr: u64,
    pub len: u64,
    pub host_virt_addr: u64,
    pub file_offset: u64,
    pub backing_dev: u64,
    pub backing_ino: u64,
    /// True when the region is mapped `MAP_SHARED` (not evictable via
    /// `MADV_DONTNEED`); false for `MAP_PRIVATE` (evictable).
    pub shared: bool,
}

/// Handoff metadata document sent ahead of the descriptor.
#[derive(Debug, Serialize)]
pub struct UffdHandoffMetadata {
    pub protocol: &'static str,
    pub version: u32,
    pub pid: u32,
    /// True when the descriptor could only be created with
    /// `UFFD_USER_MODE_ONLY`; kernel-mode faults (e.g. KVM guest access) will
    /// NOT be delivered on such a descriptor. Receivers must treat this as a
    /// degraded, non-closure configuration.
    pub user_mode_only: bool,
    /// True when every region was registered with
    /// `UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP`; false when
    /// only missing-page registration was possible.
    pub registered_write_protect: bool,
    pub regions: Vec<UffdHandoffRegion>,
}

struct CreatedUffd {
    uffd: Uffd,
    user_mode_only: bool,
}

fn create_uffd(minor: bool) -> Result<CreatedUffd, UffdHandoffError> {
    if minor {
        return create_uffd_minor();
    }
    // Prefer a descriptor that can observe kernel-mode faults (required for
    // KVM guest accesses). Fall back to a user-mode-only descriptor so the
    // handoff can still be exercised without privileges, reporting that
    // degraded truth explicitly in the metadata.
    let mut privileged = UffdBuilder::new();
    privileged
        .close_on_exec(true)
        .non_blocking(false)
        .user_mode_only(false)
        .require_features(FeatureFlags::empty())
        .require_ioctls(IoctlFlags::empty());
    if let Ok(uffd) = privileged.create() {
        return Ok(CreatedUffd {
            uffd,
            user_mode_only: false,
        });
    }

    let mut user_mode_only = UffdBuilder::new();
    user_mode_only
        .close_on_exec(true)
        .non_blocking(false)
        .user_mode_only(true)
        .require_features(FeatureFlags::empty())
        .require_ioctls(IoctlFlags::empty());
    let uffd = user_mode_only
        .create()
        .map_err(UffdHandoffError::UffdCreate)?;
    Ok(CreatedUffd {
        uffd,
        user_mode_only: true,
    })
}

/// Creates a userfaultfd with `UFFD_FEATURE_MINOR_SHMEM` enabled, needed so guest
/// RAM can be registered with `MINOR` mode and faults resolved via
/// `UFFDIO_CONTINUE` (the lazy-warm-pool seam). The `userfaultfd` 0.9 crate's
/// `UffdBuilder` cannot request that feature, so we run `UFFDIO_API` by hand and
/// wrap the descriptor. Prefers a kernel-fault-capable descriptor, then falls
/// back to user-mode-only.
fn create_uffd_minor() -> Result<CreatedUffd, UffdHandoffError> {
    use std::os::fd::FromRawFd;

    const UFFD_API_VALUE: u64 = 0xAA;
    const UFFD_FEATURE_MISSING_SHMEM: u64 = 1 << 3;
    const UFFD_FEATURE_MINOR_SHMEM: u64 = 1 << 9;
    // _IOWR(0xAA, 0x3F, struct uffdio_api { u64; 3 } = 24 bytes) on x86-64.
    // (Cast to the libc-specific request type at the call site: `c_ulong` on
    // glibc, `c_int` on musl.)
    const UFFDIO_API_REQUEST: u32 = 0xC018_AA3F;
    const UFFD_USER_MODE_ONLY: libc::c_int = 1;

    #[repr(C)]
    struct UffdioApi {
        api: u64,
        features: u64,
        ioctls: u64,
    }

    let mut last_err = std::io::Error::from_raw_os_error(libc::ENOSYS);
    for user_mode_only in [false, true] {
        let mut flags = libc::O_CLOEXEC;
        if user_mode_only {
            flags |= UFFD_USER_MODE_ONLY;
        }
        // SAFETY: the userfaultfd syscall returns a new owned descriptor or -errno.
        let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::c_long::from(flags)) };
        if fd < 0 {
            last_err = std::io::Error::last_os_error();
            continue;
        }
        let fd = fd as i32;
        let mut api = UffdioApi {
            api: UFFD_API_VALUE,
            features: UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_MINOR_SHMEM,
            ioctls: 0,
        };
        // SAFETY: `fd` is our freshly created userfaultfd; `api` is a valid struct.
        let rc = unsafe { libc::ioctl(fd, UFFDIO_API_REQUEST as _, std::ptr::from_mut(&mut api)) };
        if rc < 0 {
            last_err = std::io::Error::last_os_error();
            // SAFETY: closing our own descriptor.
            unsafe { libc::close(fd) };
            continue;
        }
        // SAFETY: a freshly created userfaultfd we exclusively own; transfer it.
        let uffd = unsafe { Uffd::from_raw_fd(fd) };
        return Ok(CreatedUffd {
            uffd,
            user_mode_only,
        });
    }
    Err(UffdHandoffError::UffdMinorCreate(last_err))
}

fn register_regions(
    uffd: &Uffd,
    regions: &[UffdHandoffRegionSource],
    minor: bool,
) -> Result<bool, UffdHandoffError> {
    if minor {
        // Lazy-warm-pool: register MISSING|MINOR so an unfilled page still
        // MISSING-faults (servicer fills the shared pool from the store) and any
        // fault can be resolved with `UFFDIO_CONTINUE` (sharing one physical copy
        // across guests). Copy-on-write on writes is handled by the kernel on the
        // MAP_PRIVATE backing, so no write-protect registration is used here.
        for region in regions {
            uffd.register_with_mode(
                region.host_virt_addr as *mut libc::c_void,
                region.len as usize,
                RegisterMode::MISSING | RegisterMode::MINOR,
            )
            .map_err(|source| UffdHandoffError::UffdRegister {
                host_virt_addr: region.host_virt_addr,
                len: region.len,
                source,
            })?;
        }
        return Ok(false);
    }
    // Try missing + write-protect registration across all regions first so
    // the descriptor can also serve as a dirty-page write-protect producer.
    // If any region rejects write-protect mode, fall back to missing-only
    // registration for every region and report that truth in the metadata.
    let mut write_protect = true;
    for region in regions {
        match uffd.register_with_mode(
            region.host_virt_addr as *mut libc::c_void,
            region.len as usize,
            RegisterMode::MISSING | RegisterMode::WRITE_PROTECT,
        ) {
            Ok(_) => {}
            Err(_) => {
                write_protect = false;
                break;
            }
        }
    }

    if write_protect {
        return Ok(true);
    }

    for region in regions {
        uffd.register_with_mode(
            region.host_virt_addr as *mut libc::c_void,
            region.len as usize,
            RegisterMode::MISSING,
        )
        .map_err(|source| UffdHandoffError::UffdRegister {
            host_virt_addr: region.host_virt_addr,
            len: region.len,
            source,
        })?;
    }

    Ok(false)
}

fn send_payload_with_fd(
    stream: &UnixStream,
    payload: &[u8],
    fd: libc::c_int,
) -> Result<(), UffdHandoffError> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    // Space for one SCM_RIGHTS control message carrying a single fd, with
    // u64 alignment guaranteed by the element type.
    const CMSG_CAPACITY: usize = 64;
    let mut cmsg_buf = [0u64; CMSG_CAPACITY / 8];

    // SAFETY: zero-initialized POD struct.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    // SAFETY: computing control length for one fd. The cast is
    // target-dependent: msg_controllen is size_t on glibc and socklen_t on
    // musl.
    #[allow(clippy::unnecessary_cast)]
    {
        // SAFETY: computing the ancillary buffer size for exactly one fd.
        msg.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as _;
    }
    assert!(msg.msg_controllen as usize <= CMSG_CAPACITY);

    // SAFETY: msg_control points at a buffer large enough for one cmsghdr.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    assert!(!cmsg.is_null());
    // SAFETY: cmsg points into cmsg_buf, which outlives this scope.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        // cmsg_len is size_t on glibc and socklen_t on musl.
        #[allow(clippy::unnecessary_cast)]
        {
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        }
        std::ptr::copy_nonoverlapping(
            &fd as *const libc::c_int as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<libc::c_int>(),
        );
    }

    // SAFETY: msg and all referenced buffers are valid for the call.
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if sent < 0 {
        return Err(UffdHandoffError::SocketSend(std::io::Error::last_os_error()));
    }
    if (sent as usize) != payload.len() {
        return Err(UffdHandoffError::SocketSend(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!(
                "short sendmsg: sent {sent} of {} payload bytes",
                payload.len()
            ),
        )));
    }

    Ok(())
}

/// Registers every region with one userfaultfd descriptor and hands the
/// descriptor plus metadata to the peer listening at `socket_path`.
///
/// Returns the metadata document that was sent, so callers can log the
/// truthful registration capabilities.
pub fn perform_uffd_handoff(
    regions: &[UffdHandoffRegionSource],
    socket_path: &Path,
    minor: bool,
) -> Result<UffdHandoffMetadata, UffdHandoffError> {
    if regions.is_empty() {
        return Err(UffdHandoffError::NoEligibleRegions);
    }

    let created = create_uffd(minor)?;
    let registered_write_protect = register_regions(&created.uffd, regions, minor)?;

    let metadata = UffdHandoffMetadata {
        protocol: UFFD_HANDOFF_PROTOCOL,
        version: UFFD_HANDOFF_VERSION,
        pid: std::process::id(),
        user_mode_only: created.user_mode_only,
        registered_write_protect,
        regions: regions
            .iter()
            .map(|region| UffdHandoffRegion {
                guest_phys_addr: region.guest_phys_addr,
                len: region.len,
                host_virt_addr: region.host_virt_addr as u64,
                file_offset: region.file_offset,
                backing_dev: region.backing_dev,
                backing_ino: region.backing_ino,
                shared: region.shared,
            })
            .collect(),
    };

    let document = serde_json::to_vec(&metadata).map_err(UffdHandoffError::Serialize)?;
    let mut payload = Vec::with_capacity(4 + document.len());
    payload.extend_from_slice(&(document.len() as u32).to_le_bytes());
    payload.extend_from_slice(&document);

    let mut stream =
        UnixStream::connect(socket_path).map_err(|source| UffdHandoffError::SocketConnect {
            path: socket_path.display().to_string(),
            source,
        })?;

    send_payload_with_fd(&stream, &payload, created.uffd.as_raw_fd())?;

    let mut ack = [0u8; 1];
    match stream.read(&mut ack) {
        Ok(0) => return Err(UffdHandoffError::AckEof),
        Ok(_) => {}
        Err(source) => return Err(UffdHandoffError::AckRead(source)),
    }
    if ack[0] != UFFD_HANDOFF_ACK {
        return Err(UffdHandoffError::AckUnexpected(ack[0]));
    }

    // Keep the control socket open and service post-handoff cooperation
    // commands (currently EVICT) for the lifetime of the VM. The peer (the
    // external page-fault servicer) decides which pages to evict; only the
    // mapping owner can drop them so the next guest access re-faults MISSING.
    let region_maps: Vec<CooperationRegion> = regions
        .iter()
        .map(|region| CooperationRegion {
            guest_phys_addr: region.guest_phys_addr,
            host_virt_addr: region.host_virt_addr as u64,
            len: region.len,
            shared: region.shared,
        })
        .collect();
    std::thread::Builder::new()
        .name("uffd-coop".to_string())
        .spawn(move || cooperation_loop(stream, &region_maps))
        .map_err(UffdHandoffError::CooperationThreadSpawn)?;

    // The peer now holds its own reference to the userfaultfd file object;
    // dropping our descriptor here does not tear down the registration.
    Ok(metadata)
}

/// One guest-memory region for translating evicted page-frame numbers to host
/// virtual addresses.
#[derive(Clone, Copy)]
struct CooperationRegion {
    guest_phys_addr: u64,
    host_virt_addr: u64,
    len: u64,
    shared: bool,
}

/// Cooperation control opcodes.
pub const COOP_OP_EVICT: u8 = 0x01;
pub const COOP_OP_EVICT_RESULT: u8 = 0x81;
pub const COOP_FRAME_VERSION: u8 = 0x02;
pub const COOP_EVICT_REQUEST_HEADER_BYTES: usize = 16;
pub const COOP_EVICT_RESPONSE_HEADER_BYTES: usize = 20;
pub const COOP_EVICT_RESULT_BYTES: usize = 12;
const COOP_PFN_BYTES: usize = std::mem::size_of::<u64>();
pub const COOP_MAX_EVICT_PFNS: u32 = 65_536;
const COOP_PAGE_SIZE: u64 = 4096;

type MadvisePage = fn(u64) -> Result<(), i32>;

fn system_madvise_page(host_va: u64) -> Result<(), i32> {
    // SAFETY: the caller validates that host_va names one full page inside a
    // handed-off guest-memory mapping.
    let result = unsafe {
        libc::madvise(
            host_va as *mut libc::c_void,
            COOP_PAGE_SIZE as usize,
            libc::MADV_DONTNEED,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}

fn evict_one_pfn(regions: &[CooperationRegion], pfn: u64, madvise_page: MadvisePage) -> i32 {
    let Some(gpa) = pfn.checked_mul(COOP_PAGE_SIZE) else {
        return libc::ERANGE;
    };
    let Some(gpa_end) = gpa.checked_add(COOP_PAGE_SIZE) else {
        return libc::ERANGE;
    };
    for region in regions {
        let Some(region_end) = region.guest_phys_addr.checked_add(region.len) else {
            continue;
        };
        if gpa < region.guest_phys_addr || gpa_end > region_end {
            continue;
        }
        if region.shared {
            return libc::EOPNOTSUPP;
        }
        let Some(host_va) = region
            .host_virt_addr
            .checked_add(gpa - region.guest_phys_addr)
        else {
            return libc::ERANGE;
        };
        return match madvise_page(host_va) {
            Ok(()) => 0,
            Err(errno) if errno > 0 => errno,
            Err(_) => libc::EIO,
        };
    }
    libc::ERANGE
}

fn write_evict_response(
    stream: &mut UnixStream,
    sequence: u64,
    frame_errno: i32,
    results: &[(u64, i32)],
) -> std::io::Result<()> {
    let result_count = u32::try_from(results.len()).expect("result count is request-bounded");
    let mut response = Vec::with_capacity(
        COOP_EVICT_RESPONSE_HEADER_BYTES + results.len() * COOP_EVICT_RESULT_BYTES,
    );
    response.push(COOP_OP_EVICT_RESULT);
    response.push(COOP_FRAME_VERSION);
    response.extend_from_slice(&0_u16.to_le_bytes());
    response.extend_from_slice(&sequence.to_le_bytes());
    response.extend_from_slice(&frame_errno.to_le_bytes());
    response.extend_from_slice(&result_count.to_le_bytes());
    for (pfn, errno) in results {
        response.extend_from_slice(&pfn.to_le_bytes());
        response.extend_from_slice(&errno.to_le_bytes());
    }
    stream.write_all(&response)
}

/// Reads and services version-2 cooperation commands until the peer closes the
/// socket. Each EVICT request is:
/// `[u8 op=0x01][u8 version=2][u16 reserved=0][u64 sequence_le]`
/// `[u32 count_le][u64 pfn_le]*count`.
///
/// The response is emitted only after every valid PFN has been attempted:
/// `[u8 op=0x81][u8 version=2][u16 reserved=0][u64 sequence_le]`
/// `[i32 frame_errno_le][u32 count_le][u64 pfn_le][i32 errno_le]*count`.
fn cooperation_loop(stream: UnixStream, regions: &[CooperationRegion]) {
    cooperation_loop_with_madvise(stream, regions, system_madvise_page);
}

fn cooperation_loop_with_madvise(
    mut stream: UnixStream,
    regions: &[CooperationRegion],
    madvise_page: MadvisePage,
) {
    let mut expected_sequence = 1_u64;
    loop {
        let mut header = [0_u8; COOP_EVICT_REQUEST_HEADER_BYTES];
        if stream.read_exact(&mut header).is_err() {
            return; // peer closed the control socket; VM teardown or done.
        }

        let op = header[0];
        let version = header[1];
        let reserved = u16::from_le_bytes(header[2..4].try_into().unwrap());
        let sequence = u64::from_le_bytes(header[4..12].try_into().unwrap());
        let count = u32::from_le_bytes(header[12..16].try_into().unwrap());
        let frame_errno = if op != COOP_OP_EVICT {
            libc::EOPNOTSUPP
        } else if version != COOP_FRAME_VERSION {
            libc::EPROTONOSUPPORT
        } else if reserved != 0 || sequence != expected_sequence {
            libc::EPROTO
        } else if count > COOP_MAX_EVICT_PFNS {
            libc::E2BIG
        } else {
            0
        };
        if frame_errno != 0 {
            let _ = write_evict_response(&mut stream, sequence, frame_errno, &[]);
            return;
        }

        let count = count as usize;
        let mut pfn_bytes = vec![0_u8; count * COOP_PFN_BYTES];
        if stream.read_exact(&mut pfn_bytes).is_err() {
            return;
        }
        let mut results = Vec::with_capacity(count);
        for chunk in pfn_bytes.as_chunks::<COOP_PFN_BYTES>().0 {
            let pfn = u64::from_le_bytes(*chunk);
            results.push((pfn, evict_one_pfn(regions, pfn, madvise_page)));
        }
        if write_evict_response(&mut stream, sequence, 0, &results).is_err() {
            return;
        }
        let Some(next_sequence) = expected_sequence.checked_add(1) else {
            return;
        };
        expected_sequence = next_sequence;
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use super::*;

    fn recv_payload_with_fd(stream: &UnixStream) -> (Vec<u8>, RawFd) {
        let mut buf = vec![0u8; 65536];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u64; 8];

        // SAFETY: zero-initialized POD struct.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        // msg_controllen is size_t on glibc and socklen_t on musl.
        #[allow(clippy::unnecessary_cast)]
        {
            msg.msg_controllen = std::mem::size_of_val(&cmsg_buf) as _;
        }

        // SAFETY: msg and buffers are valid for the call.
        let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
        assert!(
            received > 0,
            "recvmsg failed: {}",
            std::io::Error::last_os_error()
        );

        // SAFETY: kernel-initialized control buffer.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        assert!(!cmsg.is_null(), "no control message received");
        // SAFETY: cmsg validated non-null above.
        let (level, ty) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
        assert_eq!(level, libc::SOL_SOCKET);
        assert_eq!(ty, libc::SCM_RIGHTS);
        let mut fd: RawFd = -1;
        // SAFETY: control data carries exactly one fd.
        unsafe {
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                &mut fd as *mut RawFd as *mut u8,
                std::mem::size_of::<RawFd>(),
            );
        }
        assert!(fd >= 0);

        buf.truncate(received as usize);
        (buf, fd)
    }

    fn page_size() -> usize {
        // SAFETY: sysconf with a valid name.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    fn uffd_available() -> bool {
        let mut builder = UffdBuilder::new();
        builder
            .close_on_exec(true)
            .user_mode_only(true)
            .require_features(FeatureFlags::empty())
            .require_ioctls(IoctlFlags::empty());
        builder.create().is_ok()
    }

    struct AnonymousPrivateMapping {
        addr: *mut libc::c_void,
        size: usize,
    }

    impl AnonymousPrivateMapping {
        fn new(pages: usize) -> Self {
            let size = pages * COOP_PAGE_SIZE as usize;
            // SAFETY: anonymous private mapping with a checked non-zero length.
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(addr, libc::MAP_FAILED, "anonymous mmap failed");
            Self { addr, size }
        }

        fn region(&self) -> CooperationRegion {
            CooperationRegion {
                guest_phys_addr: 0,
                host_virt_addr: self.addr as u64,
                len: self.size as u64,
                shared: false,
            }
        }

        fn fill(&self, byte: u8) {
            // SAFETY: addr and size describe the live writable mapping.
            unsafe { std::ptr::write_bytes(self.addr.cast::<u8>(), byte, self.size) };
        }

        fn byte_at(&self, offset: usize) -> u8 {
            assert!(offset < self.size);
            // SAFETY: offset was checked against the live mapping length.
            unsafe { std::ptr::read_volatile(self.addr.cast::<u8>().add(offset)) }
        }
    }

    impl Drop for AnonymousPrivateMapping {
        fn drop(&mut self) {
            // SAFETY: unmapping the exact live mapping created by new().
            unsafe { libc::munmap(self.addr, self.size) };
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct EvictResponse {
        sequence: u64,
        frame_errno: i32,
        results: Vec<(u64, i32)>,
    }

    fn evict_request_header(
        op: u8,
        version: u8,
        reserved: u16,
        sequence: u64,
        count: u32,
    ) -> Vec<u8> {
        let mut request = Vec::with_capacity(COOP_EVICT_REQUEST_HEADER_BYTES);
        request.push(op);
        request.push(version);
        request.extend_from_slice(&reserved.to_le_bytes());
        request.extend_from_slice(&sequence.to_le_bytes());
        request.extend_from_slice(&count.to_le_bytes());
        request
    }

    fn evict_request(sequence: u64, pfns: &[u64]) -> Vec<u8> {
        let count = u32::try_from(pfns.len()).unwrap();
        let mut request =
            evict_request_header(COOP_OP_EVICT, COOP_FRAME_VERSION, 0, sequence, count);
        request.reserve(std::mem::size_of_val(pfns));
        for pfn in pfns {
            request.extend_from_slice(&pfn.to_le_bytes());
        }
        request
    }

    fn read_evict_response(stream: &mut UnixStream) -> EvictResponse {
        let mut header = [0_u8; COOP_EVICT_RESPONSE_HEADER_BYTES];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(header[0], COOP_OP_EVICT_RESULT);
        assert_eq!(header[1], COOP_FRAME_VERSION);
        assert_eq!(u16::from_le_bytes(header[2..4].try_into().unwrap()), 0);
        let sequence = u64::from_le_bytes(header[4..12].try_into().unwrap());
        let frame_errno = i32::from_le_bytes(header[12..16].try_into().unwrap());
        let count = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut result_bytes = vec![0_u8; count * COOP_EVICT_RESULT_BYTES];
        stream.read_exact(&mut result_bytes).unwrap();
        let results = result_bytes
            .as_chunks::<COOP_EVICT_RESULT_BYTES>()
            .0
            .iter()
            .map(|chunk| {
                (
                    u64::from_le_bytes(chunk[..8].try_into().unwrap()),
                    i32::from_le_bytes(chunk[8..12].try_into().unwrap()),
                )
            })
            .collect();
        EvictResponse {
            sequence,
            frame_errno,
            results,
        }
    }

    fn assert_peer_closed(stream: &mut UnixStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            result => panic!("expected peer closure, got {result:?}"),
        }
    }

    fn assert_invalid_header(request: &[u8], sequence: u64, frame_errno: i32) {
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || cooperation_loop(server, &[]));
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        client.write_all(request).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence,
                frame_errno,
                results: vec![],
            }
        );
        assert_peer_closed(&mut client);
        worker.join().unwrap();
    }

    fn assert_truncated_request_closes_without_response(request: &[u8]) {
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || cooperation_loop(server, &[]));
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        client.write_all(request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert_peer_closed(&mut client);
        worker.join().unwrap();
    }

    fn injected_madvise_failure(_host_va: u64) -> Result<(), i32> {
        Err(libc::EBUSY)
    }

    #[test]
    fn cooperation_v2_acks_only_after_every_page_is_evicted() {
        let mapping = AnonymousPrivateMapping::new(2);
        mapping.fill(0xA5);
        let regions = vec![mapping.region()];
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &regions, system_madvise_page);
        });

        client.write_all(&evict_request(1, &[0, 1])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![(0, 0), (1, 0)],
            }
        );
        assert_eq!(mapping.byte_at(0), 0);
        assert_eq!(mapping.byte_at(COOP_PAGE_SIZE as usize), 0);
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_zero_count_ack_is_a_sequenced_barrier() {
        let mapping = AnonymousPrivateMapping::new(1);
        mapping.fill(0xD4);
        let regions = vec![mapping.region()];
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &regions, system_madvise_page);
        });

        client.write_all(&evict_request(1, &[])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![],
            }
        );
        assert_eq!(mapping.byte_at(0), 0xD4);

        client.write_all(&evict_request(2, &[0])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 2,
                frame_errno: 0,
                results: vec![(0, 0)],
            }
        );
        assert_eq!(mapping.byte_at(0), 0);
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_reports_invalid_pfn_without_hiding_valid_results() {
        let mapping = AnonymousPrivateMapping::new(1);
        mapping.fill(0x5A);
        let regions = vec![mapping.region()];
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &regions, system_madvise_page);
        });

        client.write_all(&evict_request(1, &[0, 99])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![(0, 0), (99, libc::ERANGE)],
            }
        );
        assert_eq!(mapping.byte_at(0), 0);
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_reports_injected_madvise_failure() {
        let mapping = AnonymousPrivateMapping::new(1);
        mapping.fill(0xC3);
        let regions = vec![mapping.region()];
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &regions, injected_madvise_failure);
        });

        client.write_all(&evict_request(1, &[0])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![(0, libc::EBUSY)],
            }
        );
        assert_eq!(mapping.byte_at(0), 0xC3);
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_reports_shared_region_as_unsupported() {
        let mapping = AnonymousPrivateMapping::new(1);
        mapping.fill(0xB6);
        let mut region = mapping.region();
        region.shared = true;
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &[region], system_madvise_page);
        });

        client.write_all(&evict_request(1, &[0])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![(0, libc::EOPNOTSUPP)],
            }
        );
        assert_eq!(mapping.byte_at(0), 0xB6);
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_reports_pfn_and_region_overflow_as_range_errors() {
        let overflow_region = CooperationRegion {
            guest_phys_addr: COOP_PAGE_SIZE,
            host_virt_addr: 0,
            len: u64::MAX,
            shared: false,
        };
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &[overflow_region], system_madvise_page);
        });

        client.write_all(&evict_request(1, &[u64::MAX, 1])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![(u64::MAX, libc::ERANGE), (1, libc::ERANGE)],
            }
        );
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_rejects_invalid_opcode_and_closes() {
        assert_invalid_header(
            &evict_request_header(0x7f, COOP_FRAME_VERSION, 0, 1, 0),
            1,
            libc::EOPNOTSUPP,
        );
    }

    #[test]
    fn cooperation_v2_rejects_invalid_frame_version_and_closes() {
        assert_invalid_header(
            &evict_request_header(COOP_OP_EVICT, 1, 0, 1, 0),
            1,
            libc::EPROTONOSUPPORT,
        );
    }

    #[test]
    fn cooperation_v2_rejects_nonzero_reserved_and_closes() {
        assert_invalid_header(
            &evict_request_header(COOP_OP_EVICT, COOP_FRAME_VERSION, 1, 1, 0),
            1,
            libc::EPROTO,
        );
    }

    #[test]
    fn cooperation_v2_rejects_oversized_count_without_reading_body() {
        assert_invalid_header(
            &evict_request_header(
                COOP_OP_EVICT,
                COOP_FRAME_VERSION,
                0,
                1,
                COOP_MAX_EVICT_PFNS + 1,
            ),
            1,
            libc::E2BIG,
        );
    }

    #[test]
    fn cooperation_v2_rejects_non_monotonic_sequence() {
        let mapping = AnonymousPrivateMapping::new(1);
        mapping.fill(0x7D);
        let regions = vec![mapping.region()];
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &regions, system_madvise_page);
        });

        client.write_all(&evict_request(2, &[0])).unwrap();
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 2,
                frame_errno: libc::EPROTO,
                results: vec![],
            }
        );
        assert_eq!(mapping.byte_at(0), 0x7D);
        assert_peer_closed(&mut client);
        worker.join().unwrap();
    }

    #[test]
    fn cooperation_v2_truncated_header_and_body_close_without_response() {
        let header = evict_request_header(COOP_OP_EVICT, COOP_FRAME_VERSION, 0, 1, 2);
        assert_truncated_request_closes_without_response(&header[..8]);

        let mut truncated_body = header;
        truncated_body.extend_from_slice(&0_u64.to_le_bytes());
        assert_truncated_request_closes_without_response(&truncated_body);
    }

    #[test]
    fn cooperation_v2_accepts_fully_fragmented_request_io() {
        let mapping = AnonymousPrivateMapping::new(1);
        mapping.fill(0x4B);
        let regions = vec![mapping.region()];
        let (server, mut client) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            cooperation_loop_with_madvise(server, &regions, system_madvise_page);
        });

        for byte in evict_request(1, &[0]) {
            client.write_all(&[byte]).unwrap();
            std::thread::yield_now();
        }
        assert_eq!(
            read_evict_response(&mut client),
            EvictResponse {
                sequence: 1,
                frame_errno: 0,
                results: vec![(0, 0)],
            }
        );
        assert_eq!(mapping.byte_at(0), 0);
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn metadata_serializes_with_protocol_and_regions() {
        let metadata = UffdHandoffMetadata {
            protocol: UFFD_HANDOFF_PROTOCOL,
            version: UFFD_HANDOFF_VERSION,
            pid: 42,
            user_mode_only: true,
            registered_write_protect: false,
            regions: vec![UffdHandoffRegion {
                guest_phys_addr: 0,
                len: 4096,
                host_virt_addr: 0x7f00_0000_0000,
                file_offset: 0,
                backing_dev: 5,
                backing_ino: 9,
                shared: false,
            }],
        };

        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert_eq!(value["protocol"], UFFD_HANDOFF_PROTOCOL);
        assert_eq!(value["version"], 2);
        assert_eq!(value["user_mode_only"], true);
        assert_eq!(value["registered_write_protect"], false);
        assert_eq!(value["regions"][0]["len"], 4096);
        assert_eq!(value["regions"][0]["backing_ino"], 9);
    }

    #[test]
    fn handoff_rejects_empty_region_list() {
        let err = perform_uffd_handoff(&[], Path::new("/nonexistent-socket"), false).unwrap_err();
        assert!(matches!(err, UffdHandoffError::NoEligibleRegions));
    }

    #[test]
    fn handoff_fails_deterministically_when_socket_is_absent() {
        if !uffd_available() {
            eprintln!("skipping: userfaultfd unavailable on this host");
            return;
        }

        let size = page_size();
        let mapping = MappedMemfd::new(size);
        let err = perform_uffd_handoff(
            &[mapping.region_source()],
            Path::new("/nonexistent/uffd-handoff.sock"),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, UffdHandoffError::SocketConnect { .. }));
    }

    struct MappedMemfd {
        addr: *mut libc::c_void,
        size: usize,
        file: std::fs::File,
    }

    impl MappedMemfd {
        fn new(size: usize) -> Self {
            // SAFETY: FFI calls with valid arguments; failures are asserted.
            unsafe {
                let fd = libc::syscall(
                    libc::SYS_memfd_create,
                    c"uffd-handoff-test".as_ptr(),
                    libc::MFD_CLOEXEC,
                ) as RawFd;
                assert!(fd >= 0, "memfd_create failed");
                let file = std::fs::File::from_raw_fd(fd);
                file.set_len(size as u64).unwrap();
                let addr = libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                assert_ne!(addr, libc::MAP_FAILED, "mmap failed");
                Self { addr, size, file }
            }
        }

        fn region_source(&self) -> UffdHandoffRegionSource {
            use std::os::unix::fs::MetadataExt;
            let metadata = self.file.metadata().unwrap();
            UffdHandoffRegionSource {
                guest_phys_addr: 0,
                len: self.size as u64,
                host_virt_addr: self.addr as usize,
                file_offset: 0,
                backing_dev: metadata.dev(),
                backing_ino: metadata.ino(),
                // The test mapping above uses MAP_SHARED.
                shared: true,
            }
        }
    }

    impl Drop for MappedMemfd {
        fn drop(&mut self) {
            // SAFETY: unmapping the exact mapping created in new().
            unsafe {
                libc::munmap(self.addr, self.size);
            }
        }
    }

    #[test]
    fn handoff_roundtrip_delivers_registered_uffd_and_services_missing_fault() {
        if !uffd_available() {
            eprintln!("skipping: userfaultfd unavailable on this host");
            return;
        }

        let size = page_size();
        let mapping = MappedMemfd::new(size);
        let source = mapping.region_source();
        let mapping_addr = mapping.addr as usize;

        let dir = std::env::temp_dir().join(format!(
            "uffd-handoff-test-{}-{:x}",
            std::process::id(),
            mapping_addr
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("handoff.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let fill_byte = 0xAB_u8;
        let servicer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (payload, fd) = recv_payload_with_fd(&stream);

            assert!(payload.len() > 4);
            let document_len =
                u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            assert_eq!(payload.len(), 4 + document_len);
            let value: serde_json::Value = serde_json::from_slice(&payload[4..]).unwrap();
            assert_eq!(value["protocol"], UFFD_HANDOFF_PROTOCOL);
            assert_eq!(value["version"], 2);
            assert_eq!(
                value["regions"][0]["host_virt_addr"].as_u64().unwrap() as usize,
                mapping_addr
            );

            stream.write_all(&[UFFD_HANDOFF_ACK]).unwrap();

            // SAFETY: fd was received via SCM_RIGHTS and is owned here.
            let uffd = unsafe { Uffd::from_raw_fd(fd) };
            let event = uffd.read_event().unwrap().unwrap();
            match event {
                userfaultfd::Event::Pagefault { addr, .. } => {
                    let page =
                        vec![fill_byte; value["regions"][0]["len"].as_u64().unwrap() as usize];
                    // SAFETY: copying one full page into the registered range.
                    unsafe {
                        uffd.copy(page.as_ptr() as *mut libc::c_void, addr, page.len(), true)
                            .unwrap();
                    }
                }
                other => panic!("unexpected uffd event: {other:?}"),
            }
        });

        let metadata = perform_uffd_handoff(&[source], &socket_path, false).unwrap();
        assert_eq!(metadata.regions.len(), 1);
        assert_eq!(metadata.regions[0].host_virt_addr as usize, mapping_addr);

        // Touch the still-absent page: this must fault, get serviced by the
        // peer thread through the handed-off descriptor, and observe the
        // peer-provided fill byte.
        // SAFETY: reading the first byte of the registered mapping.
        let observed = unsafe { std::ptr::read_volatile(mapping_addr as *const u8) };
        assert_eq!(observed, fill_byte);

        servicer.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
