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
//! VMM proceeds to boot. Faults on still-absent pages then block until the
//! peer resolves them (e.g. with `UFFDIO_COPY`), which is exactly the
//! demand-paging cooperation contract this seam exists to provide.
//!
//! Every failure on this path is deterministic and fails VM creation: the
//! seam never silently degrades to unregistered guest memory.

use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::Serialize;
use thiserror::Error;
use userfaultfd::{FeatureFlags, IoctlFlags, RegisterMode, Uffd, UffdBuilder};

/// Stable protocol identifier for the handoff metadata document.
pub const UFFD_HANDOFF_PROTOCOL: &str = "meridian-cloud-hypervisor-uffd-handoff";

/// Current handoff protocol version.
pub const UFFD_HANDOFF_VERSION: u32 = 1;

/// Acknowledgement byte the peer must send after receiving the handoff.
pub const UFFD_HANDOFF_ACK: u8 = 0x01;

#[derive(Debug, Error)]
pub enum UffdHandoffError {
    #[error("guest RAM has no eligible regions for userfaultfd handoff")]
    NoEligibleRegions,

    #[error("failed to create userfaultfd descriptor")]
    UffdCreate(#[source] userfaultfd::Error),

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

fn create_uffd() -> Result<CreatedUffd, UffdHandoffError> {
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

fn register_regions(
    uffd: &Uffd,
    regions: &[UffdHandoffRegionSource],
) -> Result<bool, UffdHandoffError> {
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
) -> Result<UffdHandoffMetadata, UffdHandoffError> {
    if regions.is_empty() {
        return Err(UffdHandoffError::NoEligibleRegions);
    }

    let created = create_uffd()?;
    let registered_write_protect = register_regions(&created.uffd, regions)?;

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

    // The peer now holds its own reference to the userfaultfd file object;
    // dropping our descriptor here does not tear down the registration.
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::os::unix::net::UnixListener;

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
            }],
        };

        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert_eq!(value["protocol"], UFFD_HANDOFF_PROTOCOL);
        assert_eq!(value["version"], 1);
        assert_eq!(value["user_mode_only"], true);
        assert_eq!(value["registered_write_protect"], false);
        assert_eq!(value["regions"][0]["len"], 4096);
        assert_eq!(value["regions"][0]["backing_ino"], 9);
    }

    #[test]
    fn handoff_rejects_empty_region_list() {
        let err = perform_uffd_handoff(&[], Path::new("/nonexistent-socket")).unwrap_err();
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
            assert_eq!(value["version"], 1);
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

        let metadata = perform_uffd_handoff(&[source], &socket_path).unwrap();
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
