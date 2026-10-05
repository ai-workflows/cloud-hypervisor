#!/usr/bin/env python3
# Copyright © 2026 The Cloud Hypervisor Authors
#
# SPDX-License-Identifier: Apache-2.0
"""End-to-end test of the VM generation ID device (`--vmgenid`) over snapshot/restore.

A guest with no agent (a busybox init that answers each line it reads on the serial console with
its kernel UUID and the count of "virtual machine fork" reseeds in its log) is booted, snapshotted
once, and restored from that snapshot twice. With `--vmgenid`:

- the guest kernel's `vmgenid` module binds the `VMGENCTR` ACPI device;
- each restore makes the kernel reseed its CRNG ("crng reseeded due to virtual machine fork")
  before the first read after resume;
- the two restored guests read different `/proc/sys/kernel/random/uuid` values.

The same run without `--vmgenid` is the control: no device, no fork reseed, and (usually) the two
restored guests read the same UUID because they share the snapshot's CRNG state.

The guest kernel is Ubuntu noble's HWE kernel (6.17.0-35-generic), fetched from a pinned
Ubuntu snapshot and checked by digest. Requires /dev/kvm.

usage: vmgenid-restore-test.py --cloud-hypervisor PATH --ch-remote PATH [--work DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu/20260707T000000Z/pool/main"
KERNEL_RELEASE = "6.17.0-35-generic"
PACKAGES = {
    "linux-image-unsigned": (
        f"{SNAPSHOT}/l/linux-hwe-6.17/linux-image-unsigned-6.17.0-35-generic_6.17.0-35.35~24.04.1_amd64.deb",
        "acec77e1ea782ac162be7b766757d6e831626b45687614a1363aa4131f48e585",
    ),
    "linux-modules-extra": (
        f"{SNAPSHOT}/l/linux-hwe-6.17/linux-modules-extra-6.17.0-35-generic_6.17.0-35.35~24.04.1_amd64.deb",
        "ea9b077e116e5b6f3895a9b80510330c2a81967fe143757c851b9bbe74ce8264",
    ),
    "busybox-static": (
        f"{SNAPSHOT}/b/busybox/busybox-static_1.36.1-6ubuntu3.1_amd64.deb",
        "944b2728f53ceb3916cec2c962873c9951e612408099601751db2a0a5d81e0ed",
    ),
}

INIT = r"""#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
exec </dev/ttyS0 >/dev/ttyS0 2>&1
if insmod /vmgenid.ko; then echo "VMGENID-MODULE loaded"; else echo "VMGENID-MODULE failed"; fi
# The ACPI devices the driver bound, e.g. VMGENCTR:00.
echo "VMGENID-BOUND $(ls /sys/bus/platform/drivers/vmgenid/ 2>/dev/null | grep : | tr '\n' ' ')"
# Wait until the CRNG is initialized: the fork reseed is logged only on a ready CRNG.
head -c 1 /dev/random >/dev/null
echo READY
while read -r line; do
  echo "UUID $(cat /proc/sys/kernel/random/uuid) FORKS $(dmesg | grep -c 'virtual machine fork')"
done
"""


def log(message: str) -> None:
    print(f"[vmgenid-test] {message}", flush=True)


def fetch(name: str, cache: Path) -> Path:
    url, digest = PACKAGES[name]
    path = cache / Path(url).name
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 (pinned https URL)
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"digest mismatch for {url}")
        path.write_bytes(data)
    return path


def cpio_newc(entries: list[tuple[str, int, bytes, int]]) -> bytes:
    """A newc archive of (name, mode, data, rdev) entries."""
    out = bytearray()
    for inode, (name, mode, data, rdev) in enumerate([*entries, ("TRAILER!!!", 0, b"", 0)], start=1):
        encoded = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, rdev >> 8, rdev & 0xFF, len(encoded), 0]
        out += b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded
        out += b"\0" * (-len(out) % 4) + data
        out += b"\0" * (-len(out) % 4)
    return bytes(out)


def prepare(work: Path) -> tuple[Path, Path]:
    cache = work / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    root = work / "packages"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    for name in PACKAGES:
        subprocess.run(["dpkg-deb", "-x", str(fetch(name, cache)), str(root)], check=True)
    kernel = root / "boot" / f"vmlinuz-{KERNEL_RELEASE}"
    module_zst = root / "lib" / "modules" / KERNEL_RELEASE / "kernel" / "drivers" / "virt" / "vmgenid.ko.zst"
    module = work / "vmgenid.ko"
    subprocess.run(["zstd", "-d", "-q", "-f", str(module_zst), "-o", str(module)], check=True)
    busybox = next(path for path in (root / "bin" / "busybox", root / "usr" / "bin" / "busybox") if path.exists())
    initramfs = work / "initramfs.cpio"
    initramfs.write_bytes(
        cpio_newc(
            [
                ("bin", 0o040755, b"", 0),
                ("dev", 0o040755, b"", 0),
                ("dev/console", 0o020600, b"", (5 << 8) | 1),
                ("proc", 0o040755, b"", 0),
                ("sys", 0o040755, b"", 0),
                ("init", 0o100755, INIT.encode(), 0),
                ("bin/busybox", 0o100755, busybox.read_bytes(), 0),
                ("vmgenid.ko", 0o100644, module.read_bytes(), 0),
            ]
        )
    )
    return kernel, initramfs


class Serial:
    """The guest's serial console, through Cloud Hypervisor's `--serial socket=`."""

    def __init__(self, path: Path, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(str(path))
                break
            except OSError:
                self.sock.close()
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        self.buffer = b""
        self.transcript: list[str] = []

    def line(self, prefix: str, timeout: float = 120) -> str:
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                text = raw.decode(errors="replace").strip("\r")
                self.transcript.append(text)
                if text.startswith(prefix):
                    return text
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no {prefix!r} line on the serial console; last lines: {self.transcript[-20:]}")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError(f"serial console closed; last lines: {self.transcript[-20:]}")
            self.buffer += chunk

    def ask(self) -> tuple[str, int]:
        self.sock.sendall(b"\n")
        _, uuid, _, forks = self.line("UUID ").split()
        return uuid, int(forks)

    def close(self) -> None:
        self.sock.close()


class Vmm:
    def __init__(self, binary: str, ch_remote: str, directory: Path, arguments: list[str]) -> None:
        self.ch_remote = ch_remote
        self.api = directory / "api.sock"
        for stale in (self.api, directory / "serial.sock"):
            stale.unlink(missing_ok=True)
        self.log = open(directory / "vmm.log", "ab")  # noqa: SIM115
        self.process = subprocess.Popen(
            [binary, "--api-socket", f"path={self.api}", *arguments], stdout=self.log, stderr=self.log
        )

    def remote(self, *arguments: str) -> None:
        deadline = time.monotonic() + 30
        while not self.api.exists():
            if time.monotonic() > deadline or self.process.poll() is not None:
                raise RuntimeError("Cloud Hypervisor API socket never appeared")
            time.sleep(0.05)
        subprocess.run([self.ch_remote, "--api-socket", str(self.api), *arguments], check=True)

    def kill(self) -> None:
        self.process.kill()
        self.process.wait()
        self.log.close()


def scenario(args: argparse.Namespace, kernel: Path, initramfs: Path, vmgenid: bool) -> dict:
    directory = Path(tempfile.mkdtemp(prefix=f"vmgenid-{'on' if vmgenid else 'off'}-", dir=args.work))
    serial_path = directory / "serial.sock"
    snapshot = directory / "snapshot"
    snapshot.mkdir()
    boot = [
        "--kernel", str(kernel),
        "--initramfs", str(initramfs),
        "--cmdline", "console=ttyS0 loglevel=5 panic=-1",
        "--cpus", "boot=1",
        "--memory", "size=512M",
        "--serial", f"socket={serial_path}",
        "--console", "off",
    ]
    if vmgenid:
        boot.append("--vmgenid")
    result: dict = {"vmgenid": vmgenid}
    vmm = Vmm(args.cloud_hypervisor, args.ch_remote, directory, boot)
    try:
        serial = Serial(serial_path)
        result["module"] = serial.line("VMGENID-MODULE")
        result["bound"] = serial.line("VMGENID-BOUND")
        serial.line("READY")
        result["parent"] = serial.ask()
        serial.close()
        vmm.remote("pause")
        vmm.remote("snapshot", f"file://{snapshot}")
    finally:
        vmm.kill()
    result["restores"] = []
    # Milliseconds from the restore request to the guest's first answer after resume, per restore
    # (informational: what the device adds to a restore).
    result["restore_to_answer_ms"] = []
    for _ in range(args.restores):
        started = time.monotonic()
        vmm = Vmm(args.cloud_hypervisor, args.ch_remote, directory, ["--restore", f"source_url=file://{snapshot}"])
        try:
            serial = Serial(serial_path)
            vmm.remote("resume")
            result["restores"].append(serial.ask())
            result["restore_to_answer_ms"].append(round((time.monotonic() - started) * 1000, 1))
            serial.close()
        finally:
            vmm.kill()
    if not args.keep:
        shutil.rmtree(directory, ignore_errors=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--cloud-hypervisor", required=True)
    parser.add_argument("--ch-remote", required=True)
    parser.add_argument("--work", default=os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    parser.add_argument("--keep", action="store_true", help="keep each scenario's directory and VMM log")
    parser.add_argument("--restores", type=int, default=2, help="restores per scenario (at least 2)")
    args = parser.parse_args()
    if args.restores < 2:
        raise SystemExit("--restores must be at least 2")
    args.work = Path(args.work) / "vmgenid-restore"
    args.work.mkdir(parents=True, exist_ok=True)
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise SystemExit("/dev/kvm is required")
    kernel, initramfs = prepare(args.work)

    on = scenario(args, kernel, initramfs, vmgenid=True)
    off = scenario(args, kernel, initramfs, vmgenid=False)
    print(json.dumps({"with": on, "control": off}, indent=2))

    failures = []
    if on["module"] != "VMGENID-MODULE loaded":
        failures.append(f"vmgenid module did not load: {on['module']}")
    if "VMGENCTR" not in on["bound"]:
        failures.append(f"vmgenid driver bound no VMGENCTR device: {on['bound']!r}")
    if on["parent"][1] != 0:
        failures.append("the booted guest already logged a VM fork reseed")
    for index, (uuid, forks) in enumerate(on["restores"], start=1):
        if forks != 1:
            failures.append(f"restore {index}: {forks} VM fork reseeds logged before the first read (want 1)")
        if uuid == on["parent"][0]:
            failures.append(f"restore {index}: read the UUID the parent read")
    if len({uuid for uuid, _ in on["restores"]}) != len(on["restores"]):
        failures.append("two restored guests read the same kernel UUID")
    if "VMGENCTR" in off["bound"] or any(forks for _, forks in off["restores"]):
        failures.append("without --vmgenid the guest still saw a VM generation device")
    log(
        "control without --vmgenid: the two restores read "
        + ("the same UUID (shared CRNG state)" if off["restores"][0][0] == off["restores"][1][0] else "different UUIDs")
    )
    for name, scenario_result in (("with --vmgenid", on), ("without", off)):
        times = sorted(scenario_result["restore_to_answer_ms"])
        log(f"restore to first answer {name}: median {times[len(times) // 2]} ms, all {times}")
    for failure in failures:
        log(f"FAIL: {failure}")
    if not failures:
        log("PASS: vmgenid bound, one fork reseed per restore, distinct UUIDs across two restores")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
