#![cfg(target_arch = "aarch64")]

use std::{
    os::unix::prelude::RawFd,
    sync::{Arc, Mutex},
};

use kvm_bindings::{
    kvm_one_reg, kvm_reg_list, kvm_run, kvm_vcpu_init, KVMIO, KVM_ARM_VCPU_PSCI_0_2,
    KVM_SYSTEM_EVENT_SHUTDOWN,
};
use nix::{ioctl_read, ioctl_write_ptr};

use super::Memory;
use crate::smolvm::CpuExitReason;

ioctl_read!(kvm_get_one_reg, KVMIO, 0xab, kvm_one_reg);
ioctl_read!(kvm_set_one_reg, KVMIO, 0xac, kvm_one_reg);
ioctl_read!(kvm_arm_vcpu_init, KVMIO, 0xae, kvm_vcpu_init);
ioctl_read!(kvm_arm_preferred_target, KVMIO, 0xaf, kvm_vcpu_init);
ioctl_write_ptr!(kvm_get_reg_list, KVMIO, 0xb0, kvm_reg_list);

pub struct Cpu {
    vcpu_fd: RawFd,
    vcpu_run: *mut kvm_run,
    vcpu_mmap_size: i32,
    _memory: Arc<Mutex<Memory>>,
}

impl Cpu {
    pub fn new(
        kvm_fd: RawFd,
        vm_fd: RawFd,
        _memory: Arc<Mutex<Memory>>,
    ) -> Result<Self, std::io::Error> {
        let vcpu_fd = unsafe { super::kvm_create_vcpu(vm_fd, 0)? };

        let vcpu_mmap_size = unsafe { super::kvm_get_vcpu_mmap_size(kvm_fd, 0)? };
        let vcpu_run = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                vcpu_mmap_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu_fd,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(super::last_os_error());
            }
            ptr as *mut kvm_run
        };

        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        unsafe { kvm_arm_preferred_target(kvm_fd, &mut kvi)? };
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        unsafe { kvm_arm_vcpu_init(vcpu_fd, &mut kvi)? };

        Ok(Self {
            vcpu_fd,
            vcpu_run,
            vcpu_mmap_size,
            _memory,
        })
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExitReason, std::io::Error> {
        let run = &mut unsafe { std::slice::from_raw_parts_mut(self.vcpu_run, 1) }[0];

        unsafe { super::kvm_run(self.vcpu_fd, 0)? };

        let exit_reason = match run.exit_reason {
            KVM_SYSTEM_EVENT_SHUTDOWN => {
                let core_reg_base: u64 = 0x6030_0000_0010_0000;
                let mut reg = kvm_one_reg {
                    id: core_reg_base + 2 * 32,
                    addr: 0,
                };
                unsafe { kvm_get_one_reg(self.vcpu_fd, &mut reg)? };
                log::error!("Vcpu Exit {:#x} at {:#x}", run.exit_reason, reg.addr);

                CpuExitReason::NotSupported
            }
            _ => {
                let core_reg_base: u64 = 0x6030_0000_0010_0000;
                let mut reg = kvm_one_reg {
                    id: core_reg_base + 2 * 32,
                    addr: 0,
                };
                unsafe { kvm_get_one_reg(self.vcpu_fd, &mut reg)? };
                log::error!("Vcpu Exit {:#x} at {:#x}", run.exit_reason, reg.addr);

                CpuExitReason::NotSupported
            }
        };

        Ok(exit_reason)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let mut reg = kvm_one_reg {
            id: core_reg_base + 2 * 32,
            addr: ip,
        };
        unsafe { kvm_set_one_reg(self.vcpu_fd, &mut reg)? };

        Ok(())
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let mut reg = kvm_one_reg {
            id: core_reg_base + 2 * 32,
            addr: 0,
        };
        unsafe { kvm_get_one_reg(self.vcpu_fd, &mut reg)? };

        Ok(reg.addr)
    }
}
