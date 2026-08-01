# userfaultfd handoff (Meridian cooperation seam)

This fork carries one narrow patch on top of upstream Cloud Hypervisor: an
explicit cooperation seam that lets an external process own guest-memory
page-fault servicing for file-backed guest RAM.

## What it does

When the VM is configured with:

```
--memory size=0,uffd_handoff_socket=/run/meridian/uffd.sock
--memory-zone id=mem0,size=2G,file=/proc/self/fd/20,shared=off
```

the VMM, immediately after creating guest memory and **before loading any
payload into guest RAM**:

1. creates one `userfaultfd` descriptor (preferring a descriptor that can
   observe kernel-mode faults; falling back to `UFFD_USER_MODE_ONLY` and
   reporting that truthfully),
2. registers every guest RAM region with it (`MISSING | WP` modes, falling
   back to `MISSING`-only and reporting that truthfully),
3. connects to the Unix socket at `uffd_handoff_socket`, and
4. sends a single message: a 4-byte little-endian length prefix, a JSON
   metadata document, and the `userfaultfd` descriptor as `SCM_RIGHTS`
   ancillary data, then waits for a one-byte `0x01` acknowledgement before
   boot proceeds.

The metadata document (`protocol: meridian-cloud-hypervisor-uffd-handoff`,
`version: 2`) carries, per region: guest physical address, length, host
virtual address, backing-file offset, backing `st_dev`/`st_ino`, and whether
the mapping is shared. The receiver can therefore verify that the running
mapping corresponds to the backing it owns and whether owner-side eviction is
supported. It also carries the truthful `user_mode_only` and
`registered_write_protect` capability flags.

Anonymous mappings are also accepted and report zero backing identity fields.
EVICT requires a private mapping; shared mappings remain valid for handoff
modes such as minor-fault servicing but report `EOPNOTSUPP` for eviction.

Version 2 is an incompatible protocol boundary. A version-1 receiver must
reject the metadata before acknowledging the initial handoff, and a version-2
receiver must reject version-1 metadata. There is no fallback or mixed-version
operation.

## Post-handoff EVICT protocol

After the initial one-byte acknowledgement, the same Unix socket carries
sequenced binary EVICT frames. Integers are little-endian. Requests begin with
this 16-byte header:

```
u8  op = 0x01
u8  version = 0x02
u16 reserved = 0
u64 sequence
u32 count
```

The header is followed by `count` `u64` page-frame numbers. `count` must not
exceed 65,536. Sequence numbers are strictly monotonic, beginning at 1, and
the VMM handles exactly one request at a time. A zero-count request is a valid
barrier: its acknowledgement confirms that every preceding request has
completed, and it advances the expected sequence.

The VMM attempts every PFN in a valid frame before writing this 20-byte
response header:

```
u8  op = 0x81
u8  version = 0x02
u16 reserved = 0
u64 echoed_sequence
i32 frame_errno
u32 result_count
```

When `frame_errno` is zero, the header is followed by `result_count` records of
`{ u64 pfn, i32 errno }` in request order. `result_count` exactly equals the
request count. A per-PFN errno of zero means `MADV_DONTNEED` completed;
`ERANGE` identifies an invalid PFN or checked-address overflow;
`EOPNOTSUPP` identifies a shared mapping; otherwise the VMM returns the actual
positive `madvise(2)` errno, using `EIO` only when the platform did not supply
one.

The receiver must keep only one batch in flight and must not update resident
accounting or accept another state transition until it has read and exactly
validated the matching response. Meridian applies a five-second response read
timeout.

## Failure semantics

Every failure on the initial handoff path fails VM creation deterministically:
missing socket, an absent or invalid acknowledgement, registration or
serialization errors, and failure to start the cooperation thread are all
hard errors. The seam never silently degrades to unregistered guest memory.

Post-handoff framing is also fail closed. An unsupported opcode returns
`EOPNOTSUPP`; a non-v2 frame returns `EPROTONOSUPPORT`; nonzero reserved bits
or an unexpected sequence return `EPROTO`; and an oversized count returns
`E2BIG`. Each such response echoes the received sequence, has zero per-PFN
results, and is followed by connection closure. A truncated header or body
cannot be acknowledged and closes the connection without a response. A valid
frame reports a result for every PFN even when individual evictions fail, and
the response is not written until all of them have been attempted.

`uffd_handoff_socket` is rejected in combination with memory hotplug
(`hotplug_size` / `hotplugged_size` at top level or on any zone), because
hotplugged regions would not be covered by the boot-time registration.

## Scope

Per the Meridian decision record (`meridian` repo,
`docs/design/decisions/2111-cloud-hypervisor-fork-cooperation-seam-for-1058.md`),
this patch intentionally adds nothing beyond the mapped-backend /
running-memory cooperation seam: no scheduler, control-plane, guest-agent,
multi-host, or storage behavior. Any expansion needs a new issue and
explicit scope approval.

In particular, Cloud Hypervisor only translates PFNs, performs the requested
owner-side `MADV_DONTNEED` calls for private mappings, and reports completion.
The external receiver remains responsible for victim selection, dirty-page
write protection/capture policy, resident accounting, retries, and deciding
whether a per-PFN or connection-level failure should stop the VM.

Patched surface:

- `vmm/src/uffd_handoff.rs` (new; protocol + registration + handoff + tests)
- `vmm/src/memory_manager.rs` (invoke handoff after guest memory creation)
- `vmm/src/vm_config.rs`, `vmm/src/config.rs` (config field, parsing,
  validation)
- `vmm/src/seccomp_filters.rs` (the vmm thread runs the uffd handoff under its
  active seccomp filter, so it must allow the `userfaultfd` syscall plus the
  `USERFAULTFD_IOC_NEW` and `UFFDIO_*` ioctls; the `userfaultfd` crate creates
  its context via `/dev/userfaultfd` + `USERFAULTFD_IOC_NEW`, not the
  `userfaultfd(2)` syscall)
- `cloud-hypervisor/src/main.rs`, `vmm/src/api/openapi/cloud-hypervisor.yaml`
  (help/API surface)
