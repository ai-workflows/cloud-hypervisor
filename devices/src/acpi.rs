// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use acpi_tables::{Aml, AmlSink, aml};
use log::{error, info, warn};
use vm_device::BusDevice;
use vm_device::interrupt::InterruptSourceGroup;
use vm_memory::GuestAddress;
use vmm_sys_util::eventfd::EventFd;

use super::AcpiNotificationFlags;

pub const GED_DEVICE_ACPI_SIZE: usize = 0x1;

/// A device for handling ACPI shutdown and reboot
pub struct AcpiShutdownDevice {
    exit_evt: EventFd,
    reset_evt: EventFd,
    vcpus_kill_signalled: Arc<AtomicBool>,
}

impl AcpiShutdownDevice {
    /// Constructs a device that will signal the given event when the guest requests it.
    pub fn new(
        exit_evt: EventFd,
        reset_evt: EventFd,
        vcpus_kill_signalled: Arc<AtomicBool>,
    ) -> AcpiShutdownDevice {
        AcpiShutdownDevice {
            exit_evt,
            reset_evt,
            vcpus_kill_signalled,
        }
    }
}

// Same I/O port used for shutdown and reboot
impl BusDevice for AcpiShutdownDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    fn write(&mut self, _base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data[0] == 1 {
            info!("ACPI Reboot signalled");
            if let Err(e) = self.reset_evt.write(1) {
                error!("Error triggering ACPI reset event: {e}");
            }
            // Spin until we are sure the reset_evt has been handled and that when
            // we return from the KVM_RUN we will exit rather than re-enter the guest.
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                // This is more effective than thread::yield_now() at
                // avoiding a priority inversion with the VMM thread
                thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        // The ACPI DSDT table specifies the S5 sleep state (shutdown) as value 5
        const S5_SLEEP_VALUE: u8 = 5;
        const SLEEP_STATUS_EN_BIT: u8 = 5;
        const SLEEP_VALUE_BIT: u8 = 2;
        if data[0] == (S5_SLEEP_VALUE << SLEEP_VALUE_BIT) | (1 << SLEEP_STATUS_EN_BIT) {
            info!("ACPI Shutdown signalled");
            if let Err(e) = self.exit_evt.write(1) {
                error!("Error triggering ACPI shutdown event: {e}");
            }
            // Spin until we are sure the reset_evt has been handled and that when
            // we return from the KVM_RUN we will exit rather than re-enter the guest.
            while !self.vcpus_kill_signalled.load(Ordering::SeqCst) {
                // This is more effective than thread::yield_now() at
                // avoiding a priority inversion with the VMM thread
                thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        None
    }
}

/// A device for handling ACPI GED event generation
pub struct AcpiGedDevice {
    interrupt: Arc<dyn InterruptSourceGroup>,
    notification_type: AcpiNotificationFlags,
    ged_irq: u32,
    address: GuestAddress,
    vm_generation_notify: bool,
}

impl AcpiGedDevice {
    pub fn new(
        interrupt: Arc<dyn InterruptSourceGroup>,
        ged_irq: u32,
        address: GuestAddress,
    ) -> AcpiGedDevice {
        AcpiGedDevice {
            interrupt,
            notification_type: AcpiNotificationFlags::NO_DEVICES_CHANGED,
            ged_irq,
            address,
            vm_generation_notify: false,
        }
    }

    /// Makes the GED event handler notify the VM generation ID device (`\_SB_.VGEN`) on
    /// `VM_GENERATION_CHANGED`. Only set when that device is in the DSDT.
    pub fn enable_vm_generation_notify(&mut self) {
        self.vm_generation_notify = true;
    }

    pub fn notify(
        &mut self,
        notification_type: AcpiNotificationFlags,
    ) -> Result<(), std::io::Error> {
        self.notification_type |= notification_type;
        self.interrupt.trigger(0)
    }

    pub fn irq(&self) -> u32 {
        self.ged_irq
    }
}

// I/O port reports what type of notification was made
impl BusDevice for AcpiGedDevice {
    // Spec has all fields as zero
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        data[0] = self.notification_type.bits();
        self.notification_type = AcpiNotificationFlags::NO_DEVICES_CHANGED;
    }
}

impl Aml for AcpiGedDevice {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        // Optional ESCN branch: bit VM_GENERATION_CHANGED notifies the VM generation ID device.
        let vm_generation_mask = AcpiNotificationFlags::VM_GENERATION_CHANGED.bits() as usize;
        let vm_generation_and = aml::And::new(&aml::Local(1), &aml::Local(0), &vm_generation_mask);
        let vm_generation_equal = aml::Equal::new(&aml::Local(1), &vm_generation_mask);
        let vm_generation_device = aml::Path::new("\\_SB_.VGEN");
        let vm_generation_notify = aml::Notify::new(&vm_generation_device, &0x80usize);
        let vm_generation_if = aml::If::new(&vm_generation_equal, vec![&vm_generation_notify]);
        let vm_generation_scan: Vec<&dyn Aml> = if self.vm_generation_notify {
            vec![&vm_generation_and, &vm_generation_if]
        } else {
            Vec::new()
        };
        aml::Device::new(
            "_SB_.GEC_".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
                &aml::Name::new("_UID".into(), &"Generic Event Controller"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.address.0,
                        self.address.0 + GED_DEVICE_ACPI_SIZE as u64 - 1,
                        None,
                    )]),
                ),
                &aml::OpRegion::new(
                    "GDST".into(),
                    aml::OpRegionSpace::SystemMemory,
                    &(self.address.0 as usize),
                    &GED_DEVICE_ACPI_SIZE,
                ),
                &aml::Field::new(
                    "GDST".into(),
                    aml::FieldAccessType::Byte,
                    aml::FieldLockRule::NoLock,
                    aml::FieldUpdateRule::WriteAsZeroes,
                    vec![aml::FieldEntry::Named(*b"GDAT", 8)],
                ),
                &aml::Method::new(
                    "ESCN".into(),
                    0,
                    true,
                    vec![
                        &aml::Store::new(&aml::Local(0), &aml::Path::new("GDAT")) as &dyn Aml,
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &aml::ONE),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &aml::ONE),
                            vec![&aml::MethodCall::new("\\_SB_.CPUS.CSCN".into(), vec![])],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &2usize),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &2usize),
                            vec![&aml::MethodCall::new("\\_SB_.MHPC.MSCN".into(), vec![])],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &4usize),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &4usize),
                            vec![&aml::MethodCall::new("\\_SB_.PHPR.PSCN".into(), vec![])],
                        ),
                        &aml::And::new(&aml::Local(1), &aml::Local(0), &8usize),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Local(1), &8usize),
                            vec![&aml::Notify::new(
                                &aml::Path::new("\\_SB_.PWRB"),
                                &0x80usize,
                            )],
                        ),
                    ]
                    .into_iter()
                    .chain(vm_generation_scan)
                    .collect(),
                ),
            ],
        )
        .to_aml_bytes(sink);
        aml::Device::new(
            "_SB_.GED_".into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0013"),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![&aml::Interrupt::new(
                        true,
                        true,
                        false,
                        false,
                        self.ged_irq,
                    )]),
                ),
                &aml::Method::new(
                    "_EVT".into(),
                    1,
                    true,
                    vec![&aml::MethodCall::new("\\_SB_.GEC_.ESCN".into(), vec![])],
                ),
            ],
        )
        .to_aml_bytes(sink);
    }
}

pub struct AcpiPmTimerDevice {
    start: Instant,
}

impl AcpiPmTimerDevice {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for AcpiPmTimerDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl BusDevice for AcpiPmTimerDevice {
    fn read(&mut self, _base: u64, _offset: u64, data: &mut [u8]) {
        if data.len() != std::mem::size_of::<u32>() {
            warn!("Invalid sized read of PM timer: {}", data.len());
            return;
        }
        let now = Instant::now();
        let since = now.duration_since(self.start);
        let nanos = since.as_nanos();

        const PM_TIMER_FREQUENCY_HZ: u128 = 3_579_545;
        const NANOS_PER_SECOND: u128 = 1_000_000_000;

        let counter = (nanos * PM_TIMER_FREQUENCY_HZ) / NANOS_PER_SECOND;
        let counter: u32 = (counter & 0xffff_ffff) as u32;

        data.copy_from_slice(&counter.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use vm_device::interrupt::{InterruptIndex, InterruptSourceConfig};

    use super::*;

    struct TestInterrupt {
        event_fd: EventFd,
    }

    impl InterruptSourceGroup for TestInterrupt {
        fn trigger(&self, _index: InterruptIndex) -> Result<(), std::io::Error> {
            self.event_fd.write(1)
        }
        fn update(
            &self,
            _index: InterruptIndex,
            _config: InterruptSourceConfig,
            _masked: bool,
            _set_gsi: bool,
        ) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn set_gsi(&self) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn notifier(&self, _index: InterruptIndex) -> Option<EventFd> {
            Some(self.event_fd.try_clone().unwrap())
        }
    }

    fn ged() -> (AcpiGedDevice, EventFd) {
        let event_fd = EventFd::new(0).unwrap();
        let interrupt = Arc::new(TestInterrupt {
            event_fd: event_fd.try_clone().unwrap(),
        });
        (
            AcpiGedDevice::new(interrupt, 5, GuestAddress(0xfe00_0000)),
            event_fd,
        )
    }

    fn aml_of(device: &AcpiGedDevice) -> Vec<u8> {
        let mut aml = Vec::new();
        device.to_aml_bytes(&mut aml);
        aml
    }

    // Notify (\_SB_.VGEN, 0x80): NotifyOp, root, DualNamePrefix, the two segments, then 0x80.
    const NOTIFY_VGEN: &[u8] = b"\x86\\\x2e_SB_VGEN\x0a\x80";

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_vm_generation_branch_is_emitted_only_when_enabled() {
        let (mut device, _event_fd) = ged();
        let without = aml_of(&device);
        assert!(!contains(&without, NOTIFY_VGEN));
        assert!(!contains(&without, b"VGEN"));

        device.enable_vm_generation_notify();
        let with = aml_of(&device);
        assert!(contains(&with, NOTIFY_VGEN));
        // The new branch tests bit 4 (VM_GENERATION_CHANGED): And (Local0, 0x10, Local1).
        assert!(contains(&with, b"\x7b\x60\x0a\x10\x61"));
        // The existing branches are unchanged.
        assert!(contains(&with, b"PWRB"));
        assert!(contains(&with, b"CSCN"));
    }

    #[test]
    fn a_vm_generation_notification_is_reported_once_and_raises_the_interrupt() {
        let (mut device, event_fd) = ged();
        device
            .notify(AcpiNotificationFlags::VM_GENERATION_CHANGED)
            .unwrap();
        assert_eq!(event_fd.read().unwrap(), 1);

        let mut data = [0u8; 1];
        device.read(0, 0, &mut data);
        assert_eq!(
            data[0],
            AcpiNotificationFlags::VM_GENERATION_CHANGED.bits(),
            "the guest's ESCN reads the VM generation bit"
        );
        device.read(0, 0, &mut data);
        assert_eq!(data[0], 0, "a read clears the pending notification");
    }
}
