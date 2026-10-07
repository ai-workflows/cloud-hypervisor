#!/usr/bin/env python3
# Copyright © 2026 The Cloud Hypervisor Authors
#
# SPDX-License-Identifier: Apache-2.0
"""End-to-end test of the userfaultfd handoff on a restore through a file-backed memory zone.

A parent guest boots with its RAM in a shared file (`--memory-zone id=mem0,file=<pool>,
shared=on`) and is snapshotted, so the snapshot carries no memory image. A child is restored
from that snapshot with the zone mapped private (`shared=off`) and `uffd_handoff_socket` set.
A test servicer receives the userfaultfd, acknowledges, and answers every MISSING fault with
UFFDIO_ZEROPAGE.

(a) tmpfs pool: the child resumes, and the handoff reports `user_mode_only=false`. Its
    `registered_write_protect` is reported, not required: on kernels with uffd-wp PTE markers a
    private shmem mapping accepts MISSING|WP, and nothing write-faults unless the servicer issues
    UFFDIO_WRITEPROTECT. Every fault the servicer sees is for a page that is a hole in the
    pool, and the pool's allocated blocks don't grow while the guest writes and reads RAM it
    never touched before. After the acknowledgement the VMM holds no userfaultfd descriptor.
(c) Then the servicer is killed: the guest keeps running, because with the last descriptor
    closed the kernel resolves the remaining faults itself.
(b) Regular disk-file pool: creating the child fails with the register error, because a
    private mapping of a regular file cannot be registered.

The guest is the same agent-less busybox guest as scripts/vmgenid-restore-test.py (Ubuntu
noble HWE kernel, fetched pinned). It needs /dev/kvm and vm.unprivileged_userfaultfd=1 (or
CAP_SYS_PTRACE), so the descriptor can serve faults that KVM takes in kernel mode.

usage: uffd-zone-restore-test.py --cloud-hypervisor PATH --ch-remote PATH [--work DIR]
"""

from __future__ import annotations

import argparse
import array
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("vmgenid_restore_test", HERE / "vmgenid-restore-test.py")
assert _spec and _spec.loader
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

PAGE = 4096
GUEST_MIB = 512
UFFD_EVENT_PAGEFAULT = 0x12
UFFDIO_ZEROPAGE = 0xC020AA04  # _IOWR(0xAA, 0x04, struct uffdio_zeropage), 32 bytes
UFFD_HANDOFF_ACK = b"\x01"

INIT = r"""#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /mnt && mount -t tmpfs -o size=400m tmpfs /mnt
exec </dev/ttyS0 >/dev/ttyS0 2>&1
echo READY
n=0
while read -r line; do
  case "$line" in
    touch*)
      # Write, then read back, RAM the guest has not used yet: tmpfs pages come from free RAM.
      n=$((n + 1))
      dd if=/dev/zero of=/mnt/f$n bs=1M count=${line#touch } 2>/dev/null
      cat /mnt/f$n > /dev/null
      echo "TOUCHED $n";;
    *) echo "PONG";;
  esac
done
"""


def log(message: str) -> None:
    print(f"[uffd-zone-test] {message}", flush=True)


def prepare(work: Path) -> tuple[Path, Path]:
    kernel, _ = common.prepare(work)  # fetches and checks the pinned kernel and busybox
    busybox = next(p for p in (work / "packages/bin/busybox", work / "packages/usr/bin/busybox") if p.exists())
    initramfs = work / "uffd-initramfs.cpio"
    initramfs.write_bytes(
        common.cpio_newc(
            [
                ("bin", 0o040755, b"", 0),
                ("dev", 0o040755, b"", 0),
                ("dev/console", 0o020600, b"", (5 << 8) | 1),
                ("proc", 0o040755, b"", 0),
                ("sys", 0o040755, b"", 0),
                ("init", 0o100755, INIT.encode(), 0),
                ("bin/busybox", 0o100755, busybox.read_bytes(), 0),
            ]
        )
    )
    return kernel, initramfs


# ---- the test servicer (runs as its own process: `--serve SOCKET LOG`) ------------------------


def serve(socket_path: str, log_path: str) -> None:
    out = open(log_path, "a", buffering=1)  # noqa: SIM115
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.listen(1)
    print(json.dumps({"listening": True}), file=out)
    connection, _ = listener.accept()
    fds = array.array("i")
    data = b""
    while len(data) < 4 or len(data) < 4 + struct.unpack("<I", data[:4])[0]:
        chunk, ancillary, _, _ = connection.recvmsg(65536, socket.CMSG_SPACE(4))
        if not chunk:
            raise SystemExit("VMM closed the handoff socket before the payload")
        data += chunk
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(payload[: len(payload) - len(payload) % fds.itemsize])
    metadata = json.loads(data[4 : 4 + struct.unpack("<I", data[:4])[0]])
    uffd = fds[0]
    print(json.dumps({"metadata": metadata}), file=out)
    connection.sendall(UFFD_HANDOFF_ACK)
    print(json.dumps({"acked": time.time()}), file=out)
    # Keep `connection` open: it is the VMM's cooperation (EVICT) socket for the VM's lifetime.
    while True:
        message = os.read(uffd, 32)
        if len(message) < 32 or message[0] != UFFD_EVENT_PAGEFAULT:
            continue
        _flags, address = struct.unpack_from("<QQ", message, 8)
        page = address & ~(PAGE - 1)
        request = bytearray(struct.pack("<QQQq", page, PAGE, 0, 0))
        try:
            fcntl.ioctl(uffd, UFFDIO_ZEROPAGE, request, True)
            result = "zeropage"
        except OSError as error:  # EEXIST: another vCPU's fault on the same page won the race
            result = f"errno {error.errno}"
        print(json.dumps({"fault": page, "result": result}), file=out)


def servicer_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---- the host side ---------------------------------------------------------------------------


def data_extents(path: Path) -> list[tuple[int, int]]:
    """The allocated [start, end) byte ranges of a sparse file (SEEK_DATA/SEEK_HOLE)."""
    extents = []
    with open(path, "rb") as handle:
        fd = handle.fileno()
        size = os.fstat(fd).st_size
        offset = 0
        while offset < size:
            try:
                start = os.lseek(fd, offset, os.SEEK_DATA)
            except OSError:
                break
            end = os.lseek(fd, start, os.SEEK_HOLE)
            extents.append((start, end))
            offset = end
    return extents


def is_hole(offset: int, extents: list[tuple[int, int]]) -> bool:
    return not any(start <= offset < end for start, end in extents)


def uffd_descriptors(pid: int) -> list[str]:
    found = []
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if "userfaultfd" in target:
            found.append(f"{fd} -> {target}")
    return found


def boot_parent(args: argparse.Namespace, kernel: Path, initramfs: Path, directory: Path, pool: Path) -> Path:
    pool.unlink(missing_ok=True)
    with open(pool, "wb") as handle:
        handle.truncate(GUEST_MIB << 20)
    snapshot = directory / "parent-snapshot"
    snapshot.mkdir()
    vmm = common.Vmm(
        args.cloud_hypervisor,
        args.ch_remote,
        directory,
        [
            "--kernel", str(kernel),
            "--initramfs", str(initramfs),
            "--cmdline", "console=ttyS0 loglevel=4 panic=-1",
            "--cpus", "boot=1",
            "--memory", "size=0",
            "--memory-zone", f"id=mem0,size={GUEST_MIB}M,file={pool},shared=on",
            "--serial", f"socket={directory / 'serial.sock'}",
            "--console", "off",
        ],
    )
    try:
        serial = common.Serial(directory / "serial.sock")
        serial.line("READY")
        serial.close()
        vmm.remote("pause")
        vmm.remote("snapshot", f"file://{snapshot}")
    finally:
        vmm.kill()
    return snapshot


def child_snapshot(parent: Path, directory: Path, handoff_socket: Path) -> Path:
    child = directory / "child-snapshot"
    shutil.rmtree(child, ignore_errors=True)
    shutil.copytree(parent, child)
    config = json.loads((child / "config.json").read_text())
    config["memory"]["zones"][0]["shared"] = False
    config["memory"]["uffd_handoff_socket"] = str(handoff_socket)
    (child / "config.json").write_text(json.dumps(config))
    return child


def start_servicer(directory: Path) -> tuple[subprocess.Popen, Path, Path]:
    handoff_socket = directory / "handoff.sock"
    handoff_socket.unlink(missing_ok=True)
    servicer_out = directory / "servicer.jsonl"
    servicer_out.unlink(missing_ok=True)
    servicer = subprocess.Popen([sys.executable, __file__, "--serve", str(handoff_socket), str(servicer_out)])
    deadline = time.monotonic() + 30
    while not any(entry.get("listening") for entry in servicer_log(servicer_out)):
        if time.monotonic() > deadline or servicer.poll() is not None:
            raise RuntimeError("test servicer did not start")
        time.sleep(0.05)
    return servicer, handoff_socket, servicer_out


def scenario_tmpfs(args: argparse.Namespace, kernel: Path, initramfs: Path, failures: list[str]) -> dict:
    directory = Path(tempfile.mkdtemp(prefix="uffd-zone-tmpfs-", dir=args.work))
    pool = Path("/dev/shm") / f"uffd-zone-pool-{os.getpid()}"
    result: dict = {"pool": str(pool)}
    try:
        parent = boot_parent(args, kernel, initramfs, directory, pool)
        extents = data_extents(pool)
        blocks_before = os.stat(pool).st_blocks
        result["pool_data_bytes"] = sum(end - start for start, end in extents)
        result["pool_blocks_before"] = blocks_before
        servicer, handoff_socket, servicer_out = start_servicer(directory)
        child = child_snapshot(parent, directory, handoff_socket)
        vmm = common.Vmm(args.cloud_hypervisor, args.ch_remote, directory, ["--restore", f"source_url=file://{child}"])
        try:
            serial = common.Serial(directory / "serial.sock")
            vmm.remote("resume")
            entries = servicer_log(servicer_out)
            metadata = next((e["metadata"] for e in entries if "metadata" in e), None)
            result["metadata"] = metadata
            if metadata is None:
                failures.append("(a) the servicer never received the handoff")
                return result
            result["registered_write_protect"] = metadata.get("registered_write_protect")
            log(f"(a) registered_write_protect={metadata.get('registered_write_protect')!r} (reported)")
            if metadata.get("user_mode_only"):
                failures.append("(a) the descriptor is user_mode_only: it cannot serve KVM's kernel-mode faults")
            region = metadata["regions"][0]
            if region.get("shared"):
                failures.append("(a) the child's zone is reported shared")
            held = uffd_descriptors(vmm.process.pid)
            result["vmm_uffd_fds_after_ack"] = held
            if held:
                failures.append(f"(a) the VMM still holds a userfaultfd after the ACK: {held}")

            serial.sock.sendall(b"touch 64\n")
            serial.line("TOUCHED 1", timeout=300)
            faults = [e["fault"] for e in servicer_log(servicer_out) if "fault" in e]
            offsets = [page - region["host_virt_addr"] + region["file_offset"] for page in faults]
            not_holes = [hex(o) for o in offsets if not is_hole(o, extents)]
            blocks_after = os.stat(pool).st_blocks
            result.update(faults=len(faults), fault_bytes=len(faults) * PAGE, pool_blocks_after=blocks_after)
            if not faults:
                failures.append("(a) no fault reached the servicer while the guest used untouched RAM")
            if not_holes:
                failures.append(f"(a) {len(not_holes)} faults were for pages the pool has: {not_holes[:5]}")
            if blocks_after != blocks_before:
                failures.append(f"(a) the pool grew from {blocks_before} to {blocks_after} blocks")

            # (c) Servicer death: the last descriptor closes and the kernel takes over the faults.
            servicer.send_signal(signal.SIGKILL)
            servicer.wait()
            serial.sock.sendall(b"touch 64\n")
            try:
                serial.line("TOUCHED 2", timeout=300)
                result["guest_after_servicer_death"] = "running"
            except (TimeoutError, EOFError) as error:
                result["guest_after_servicer_death"] = f"stuck: {error}"
                failures.append("(c) the guest stopped answering after the servicer died")
            if vmm.process.poll() is not None:
                failures.append(f"(c) the VMM exited ({vmm.process.returncode}) after the servicer died")
            result["pool_blocks_after_fallback"] = os.stat(pool).st_blocks
            serial.close()
        finally:
            vmm.kill()
            if servicer.poll() is None:
                servicer.kill()
    finally:
        pool.unlink(missing_ok=True)
        if not args.keep:
            shutil.rmtree(directory, ignore_errors=True)
    return result


def scenario_disk_file(args: argparse.Namespace, kernel: Path, initramfs: Path, failures: list[str]) -> dict:
    directory = Path(tempfile.mkdtemp(prefix="uffd-zone-disk-", dir=args.work))
    pool = directory / "pool"
    result: dict = {"pool": str(pool)}
    try:
        filesystem = subprocess.run(["stat", "-f", "-c", "%T", str(directory)], capture_output=True, text=True).stdout.strip()
        result["filesystem"] = filesystem
        if filesystem in ("tmpfs", "ramfs"):
            failures.append(f"(b) --work is on {filesystem}; it must be a regular disk filesystem")
            return result
        parent = boot_parent(args, kernel, initramfs, directory, pool)
        servicer, handoff_socket, servicer_out = start_servicer(directory)
        child = child_snapshot(parent, directory, handoff_socket)
        vmm = common.Vmm(args.cloud_hypervisor, args.ch_remote, directory, ["--restore", f"source_url=file://{child}"])
        try:
            try:
                code = vmm.process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                code = None
            text = (directory / "vmm.log").read_text(errors="replace")
            result["vmm_exit"] = code
            result["register_error"] = "failed to register guest RAM range" in text
            if code in (None, 0):
                failures.append(f"(b) creating the child did not fail (exit {code})")
            if not result["register_error"]:
                failures.append("(b) the VMM log does not show the register error")
            if any("metadata" in e for e in servicer_log(servicer_out)):
                failures.append("(b) the servicer received a handoff for an unregistrable region")
        finally:
            vmm.kill()
            servicer.kill()
    finally:
        if not args.keep:
            shutil.rmtree(directory, ignore_errors=True)
    return result


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == "--serve":
        serve(sys.argv[2], sys.argv[3])
        return 0
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--cloud-hypervisor", required=True)
    parser.add_argument("--ch-remote", required=True)
    parser.add_argument("--work", default=os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    parser.add_argument("--keep", action="store_true", help="keep each scenario's directory and VMM log")
    args = parser.parse_args()
    args.work = Path(args.work) / "uffd-zone-restore"
    args.work.mkdir(parents=True, exist_ok=True)
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise SystemExit("/dev/kvm is required")
    kernel, initramfs = prepare(args.work)

    failures: list[str] = []
    results = {
        "tmpfs_pool": scenario_tmpfs(args, kernel, initramfs, failures),
        "disk_file_pool": scenario_disk_file(args, kernel, initramfs, failures),
    }
    print(json.dumps(results, indent=2))
    for failure in failures:
        log(f"FAIL: {failure}")
    if not failures:
        tmpfs = results["tmpfs_pool"]
        log(
            f"PASS: {tmpfs['faults']} faults, all pool holes, pool blocks unchanged "
            f"(write-protect registered: {tmpfs.get('registered_write_protect')}) "
            f"({tmpfs['pool_blocks_before']}); no VMM uffd after the ACK; guest kept running after "
            "the servicer died; a regular-file pool is refused at registration"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
