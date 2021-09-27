#![cfg(target_arch = "aarch64")]

use std::{
    os::unix::prelude::RawFd,
    sync::{Arc, Mutex},
};

use kvm_bindings::{
    kvm_one_reg, kvm_reg_list, kvm_run, kvm_vcpu_init, KVMIO, KVM_ARM_VCPU_PSCI_0_2,
};
use nix::{ioctl_read, ioctl_readwrite, ioctl_write_ptr};

use super::Memory;
use crate::smolvm::{CpuExitReason, IoType};

ioctl_read!(kvm_get_one_reg, KVMIO, 0xab, kvm_one_reg);
ioctl_read!(kvm_set_one_reg, KVMIO, 0xac, kvm_one_reg);
ioctl_read!(kvm_arm_vcpu_init, KVMIO, 0xae, kvm_vcpu_init);
ioctl_read!(kvm_arm_preferred_target, KVMIO, 0xaf, kvm_vcpu_init);
ioctl_write_ptr!(kvm_get_reg_list, KVMIO, 0xb0, kvm_reg_list);

pub struct Cpu {
    vcpu_fd: RawFd,
    _memory: Arc<Mutex<Memory>>,
}

impl Cpu {
    pub fn new(
        _kvm_fd: RawFd,
        vm_fd: RawFd,
        _memory: Arc<Mutex<Memory>>,
    ) -> Result<Self, std::io::Error> {
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        vm_fd.get_preferred_target(&mut kvi)?;
        //kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu_fd.vcpu_init(&kvi)?;

        Ok(Self { vcpu_fd, _memory })
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExitReason, std::io::Error> {
        let mut exit = self.vcpu_fd.run()?;

        // match exit {
        // VcpuExit::SystemEvent(KVM_SYSTEM_EVENT_SHUTDOWN, 0) => {
        //     let core_reg_base: u64 = 0x6030_0000_0010_0000;
        //     let ip = self.vcpu_fd.get_one_reg(core_reg_base + 2 * 32)?;
        //     log::info!("Shutdown at 0x{:x}", ip)
        // }
        // e => {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let ip = self.vcpu_fd.get_one_reg(core_reg_base + 2 * 32)?;
        log::info!("Vcpu Exit {:?} at 0x{:x}", exit, ip);
        //     }
        // }

        Ok(exit)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        unsafe {
            kvm_set_one_reg(core_reg_base + 2 * 32, ip)?;
        }

        Ok(())
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let ip = kvm_get_one_reg(core_reg_base + 2 * 32)?;

        Ok(ip)
    }
}
