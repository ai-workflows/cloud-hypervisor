# userfaultfd handoff (Meridian cooperation seam)

This fork carries one narrow patch on top of upstream Cloud Hypervisor: an
explicit cooperation seam that lets an external process own guest-memory
page-fault servicing for file-backed guest RAM.

## What it does

When the VM is configured with:

```
--memory size=0,uffd_handoff_socket=/run/meridian/uffd.sock
--memory-zone id=mem0,size=2G,file=/proc/self/fd/20,shared=on
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
`version: 1`) carries, per region: guest physical address, length, host
virtual address, backing-file offset, and backing `st_dev`/`st_ino` so the
receiver can verify the running mapping corresponds to the backing it owns.
It also carries the truthful `user_mode_only` and `registered_write_protect`
capability flags.

## Failure semantics

Every failure on this path fails VM creation deterministically: missing
socket, unacknowledged handoff, non-file-backed or non-shared RAM regions,
and registration errors are all hard errors. The seam never silently
degrades to unregistered guest memory.

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

Patched surface:

- `vmm/src/uffd_handoff.rs` (new; protocol + registration + handoff + tests)
- `vmm/src/memory_manager.rs` (invoke handoff after guest memory creation)
- `vmm/src/vm_config.rs`, `vmm/src/config.rs` (config field, parsing,
  validation)
- `vmm/src/seccomp_filters.rs` (`userfaultfd` syscall on the vmm thread)
- `cloud-hypervisor/src/main.rs`, `vmm/src/api/openapi/cloud-hypervisor.yaml`
  (help/API surface)
