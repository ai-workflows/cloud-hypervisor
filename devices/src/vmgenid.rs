// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0
//

//! Virtual Machine Generation ID device.
//!
//! The device exposes a 128-bit generation ID in one page of guest physical memory and an ACPI
//! device (`_HID "VMGENCTR"`, `_CID "VM_Gen_Counter"`) whose `ADDR` object holds that page's
//! address, the interface Linux's `vmgenid` driver binds to. When the VM is restored from a
//! snapshot the VMM writes a fresh random ID before any vCPU runs and raises an ACPI
//! notification through the GED device (`Notify(\_SB_.VGEN, 0x80)`). The driver then reseeds the
//! kernel CRNG (`add_vmfork_randomness`) and emits a `NEW_VMGENID` uevent, so every VM restored
//! from the same snapshot diverges from the others.
//!
//! The page is not guest RAM: it is a private anonymous mapping placed in the platform MMIO
//! area, so writing a new ID never touches the snapshot's memory (which may be shared by many
//! restored VMs). Its address and current ID are carried in the device state, so a restore puts
//! the page back at the address the guest kernel already mapped.

use std::io;
use std::sync::Arc;

use acpi_tables::{Aml, AmlSink, aml};
use serde::{Deserialize, Serialize};
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::mmap::MmapRegion;
use vm_memory::{GuestAddress, VolatileMemory};
use vm_migration::{Migratable, MigratableError, Pausable, Snapshot, Snapshottable, Transportable};

/// Size of the generation ID in bytes.
pub const VMGENID_ID_SIZE: usize = 16;
/// Size of the guest physical region that holds the generation ID: one page.
pub const VMGENID_REGION_SIZE: u64 = 0x1000;

/// Device state carried in a snapshot or a migration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmGenIdState {
    /// Guest physical address of the page holding the ID.
    pub address: u64,
    /// The generation ID in force when the state was taken.
    pub generation_id: [u8; VMGENID_ID_SIZE],
}

pub struct VmGenId {
    id: String,
    address: GuestAddress,
    region: Arc<MmapRegion<AtomicBitmap>>,
    generation_id: [u8; VMGENID_ID_SIZE],
}

/// Fills `buffer` from the kernel's CSPRNG.
fn fill_random(buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        // SAFETY: the pointer and length describe the unfilled tail of `buffer`, which is valid
        // for writes for its whole length.
        let ret = unsafe {
            libc::getrandom(
                buffer[filled..].as_mut_ptr() as *mut libc::c_void,
                buffer.len() - filled,
                0,
            )
        };
        if ret < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        filled += ret as usize;
    }
    Ok(())
}

/// A random generation ID. All zeroes is never returned: it reads as "no ID" to some guests.
fn random_generation_id() -> io::Result<[u8; VMGENID_ID_SIZE]> {
    let mut generation_id = [0u8; VMGENID_ID_SIZE];
    while generation_id == [0u8; VMGENID_ID_SIZE] {
        fill_random(&mut generation_id)?;
    }
    Ok(generation_id)
}

impl VmGenId {
    /// Creates the device with its page at `address`. `generation_id` is the ID to expose: the
    /// one from the device state on a restore or a migration, or `None` for a new VM, which
    /// gets a random one.
    pub fn new(
        id: String,
        address: GuestAddress,
        generation_id: Option<[u8; VMGENID_ID_SIZE]>,
    ) -> io::Result<Self> {
        let region = MmapRegion::new(VMGENID_REGION_SIZE as usize)
            .map_err(|e| io::Error::other(format!("vmgenid region: {e}")))?;
        let generation_id = match generation_id {
            Some(generation_id) => generation_id,
            None => random_generation_id()?,
        };
        let device = VmGenId {
            id,
            address,
            region: Arc::new(region),
            generation_id,
        };
        device.write_generation_id()?;
        Ok(device)
    }

    /// Creates the device from its snapshot state (restore or migration): the page goes back to
    /// the same guest address and holds the same ID until `new_generation` is called.
    pub fn from_state(id: String, state: &VmGenIdState) -> io::Result<Self> {
        Self::new(id, GuestAddress(state.address), Some(state.generation_id))
    }

    /// The guest physical address of the ID page.
    pub fn address(&self) -> GuestAddress {
        self.address
    }

    /// The host mapping that backs the ID page. The VMM maps it into the guest at `address()`.
    pub fn region(&self) -> &Arc<MmapRegion<AtomicBitmap>> {
        &self.region
    }

    /// The generation ID currently exposed to the guest.
    pub fn generation_id(&self) -> [u8; VMGENID_ID_SIZE] {
        self.generation_id
    }

    /// Replaces the generation ID with a fresh random one and writes it to the guest page. The
    /// caller then notifies the guest (GED `VM_GENERATION_CHANGED`).
    pub fn new_generation(&mut self) -> io::Result<()> {
        let mut generation_id = random_generation_id()?;
        while generation_id == self.generation_id {
            generation_id = random_generation_id()?;
        }
        self.generation_id = generation_id;
        self.write_generation_id()
    }

    fn write_generation_id(&self) -> io::Result<()> {
        self.region
            .get_slice(0, VMGENID_ID_SIZE)
            .map_err(|e| io::Error::other(format!("vmgenid region: {e}")))?
            .copy_from(&self.generation_id);
        Ok(())
    }

    fn state(&self) -> VmGenIdState {
        VmGenIdState {
            address: self.address.0,
            generation_id: self.generation_id,
        }
    }
}

impl Aml for VmGenId {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        let low = (self.address.0 & 0xffff_ffff) as u32;
        let high = (self.address.0 >> 32) as u32;
        aml::Device::new(
            "_SB_.VGEN".into(),
            vec![
                &aml::Name::new("_HID".into(), &"VMGENCTR"),
                &aml::Name::new("_CID".into(), &"VM_Gen_Counter"),
                &aml::Name::new("_DDN".into(), &"VM_Gen_Counter"),
                // The driver evaluates ADDR: a package of the low and high 32 bits of the
                // address of the 16-byte ID.
                &aml::Name::new("ADDR".into(), &aml::Package::new(vec![&low, &high])),
            ],
        )
        .to_aml_bytes(sink);
    }
}

impl Pausable for VmGenId {}

impl Snapshottable for VmGenId {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn snapshot(&mut self) -> std::result::Result<Snapshot, MigratableError> {
        Snapshot::new_from_state(&self.state())
    }
}

impl Transportable for VmGenId {}
impl Migratable for VmGenId {}

#[cfg(test)]
mod tests {
    use vm_memory::Bytes;

    use super::*;

    const ADDRESS: u64 = 0x0000_3fff_fff0_0000;

    fn guest_bytes(device: &VmGenId) -> [u8; VMGENID_ID_SIZE] {
        let mut bytes = [0u8; VMGENID_ID_SIZE];
        device
            .region()
            .as_volatile_slice()
            .read_slice(&mut bytes, 0)
            .unwrap();
        bytes
    }

    #[test]
    fn a_new_device_exposes_a_random_nonzero_id_in_its_page() {
        let first = VmGenId::new("vmgenid".into(), GuestAddress(ADDRESS), None).unwrap();
        let second = VmGenId::new("vmgenid".into(), GuestAddress(ADDRESS), None).unwrap();
        assert_ne!(first.generation_id(), [0u8; VMGENID_ID_SIZE]);
        assert_ne!(first.generation_id(), second.generation_id());
        assert_eq!(guest_bytes(&first), first.generation_id());
        assert_eq!(first.address(), GuestAddress(ADDRESS));
    }

    #[test]
    fn a_new_generation_writes_a_different_id_to_the_page() {
        let mut device = VmGenId::new("vmgenid".into(), GuestAddress(ADDRESS), None).unwrap();
        let before = device.generation_id();
        device.new_generation().unwrap();
        assert_ne!(device.generation_id(), before);
        assert_eq!(guest_bytes(&device), device.generation_id());
    }

    #[test]
    fn the_state_round_trips_address_and_id() {
        let mut device = VmGenId::new("vmgenid".into(), GuestAddress(ADDRESS), None).unwrap();
        let state = device.state();
        assert_eq!(state.address, ADDRESS);
        let snapshot = device.snapshot().unwrap();
        let restored_state: VmGenIdState = snapshot.to_state().unwrap();
        assert_eq!(restored_state, state);
        // A restore (or a migration) puts the same ID back at the same address...
        let mut restored = VmGenId::from_state("vmgenid".into(), &restored_state).unwrap();
        assert_eq!(restored.address(), GuestAddress(ADDRESS));
        assert_eq!(guest_bytes(&restored), state.generation_id);
        // ...and only an explicit new generation changes it.
        restored.new_generation().unwrap();
        assert_ne!(guest_bytes(&restored), state.generation_id);
    }

    #[test]
    fn the_aml_names_the_device_the_linux_driver_binds_and_its_address() {
        let device = VmGenId::new("vmgenid".into(), GuestAddress(ADDRESS), None).unwrap();
        let mut aml = Vec::new();
        device.to_aml_bytes(&mut aml);

        let mut expected = Vec::new();
        aml::Device::new(
            "_SB_.VGEN".into(),
            vec![
                &aml::Name::new("_HID".into(), &"VMGENCTR"),
                &aml::Name::new("_CID".into(), &"VM_Gen_Counter"),
                &aml::Name::new("_DDN".into(), &"VM_Gen_Counter"),
                &aml::Name::new(
                    "ADDR".into(),
                    &aml::Package::new(vec![&0xfff0_0000u32, &0x3fffu32]),
                ),
            ],
        )
        .to_aml_bytes(&mut expected);
        assert_eq!(aml, expected);

        // The pieces the guest matches on, as raw AML: the device path, the IDs as strings, and
        // ADDR as a two-element package of (DWORD low, WORD high).
        let find = |needle: &[u8]| aml.windows(needle.len()).any(|w| w == needle);
        assert!(find(b"VGEN"));
        assert!(find(b"_HID\x0dVMGENCTR\x00"));
        assert!(find(b"_CID\x0dVM_Gen_Counter\x00"));
        assert!(find(&[
            b'A', b'D', b'D', b'R', 0x12, 0x0a, 0x02, 0x0c, 0x00, 0x00, 0xf0, 0xff, 0x0b, 0xff,
            0x3f
        ]));
    }
}
