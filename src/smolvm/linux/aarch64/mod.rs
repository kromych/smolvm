#![cfg(target_arch = "aarch64")]

use std::{
    os::unix::prelude::RawFd,
    sync::{Arc, Mutex},
};

use kvm_bindings::{
    kvm_one_reg, kvm_reg_list, kvm_regs, kvm_run, kvm_vcpu_init, KVMIO, KVM_ARM_VCPU_PSCI_0_2,
    KVM_SYSTEM_EVENT_SHUTDOWN,
};
use nix::{ioctl_read, ioctl_write_ptr};

use super::Memory;
use crate::smolvm::CpuExitReason;

mod cpu;

use cpu::*;

#[repr(u64)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum CpuRegister {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    SP = 31,
    PC = 32,
    PSTATE = 33,
    SP_EL1 = 34,
    ELR_EL1 = 35,
    SPSR0 = 36,
    SPSR1 = 37,
    SPSR2 = 38,
    SPSR3 = 39,
    SPSR4 = 40,
}

ioctl_write_ptr!(kvm_get_one_reg, KVMIO, 0xab, kvm_one_reg);
ioctl_write_ptr!(kvm_set_one_reg, KVMIO, 0xac, kvm_one_reg);
ioctl_write_ptr!(kvm_arm_vcpu_init, KVMIO, 0xae, kvm_vcpu_init);
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
        unsafe { kvm_arm_preferred_target(vm_fd, &mut kvi)? };
        //kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        unsafe { kvm_arm_vcpu_init(vcpu_fd, &mut kvi)? };

        Ok(Self {
            vcpu_fd,
            vcpu_run,
            vcpu_mmap_size,
            _memory,
        })
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        // All interrupts masked
        self.set_one_reg(
            CpuRegister::PSTATE,
            (PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h) as u64,
        )?;

        // Set X0..X3 to zero
        self.set_one_reg(CpuRegister::X0, 0)?;
        self.set_one_reg(CpuRegister::X1, 0)?;
        self.set_one_reg(CpuRegister::X2, 0)?;
        self.set_one_reg(CpuRegister::X3, 0)?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExitReason, std::io::Error> {
        let run = &mut unsafe { std::slice::from_raw_parts_mut(self.vcpu_run, 1) }[0];

        unsafe { super::kvm_run(self.vcpu_fd, 0)? };

        let exit_reason = match run.exit_reason {
            KVM_SYSTEM_EVENT_SHUTDOWN => {
                log::error!("Shutdown at {:#x}", self.get_instruction_pointer()?);

                CpuExitReason::NotSupported
            }
            _ => {
                log::error!(
                    "Vcpu Exit {:#x} at {:#x}",
                    run.exit_reason,
                    self.get_instruction_pointer()?
                );

                CpuExitReason::NotSupported
            }
        };

        Ok(exit_reason)
    }

    fn get_raw_reg_id(reg_id: CpuRegister) -> u64 {
        match reg_id {
            CpuRegister::X0
            | CpuRegister::X1
            | CpuRegister::X2
            | CpuRegister::X3
            | CpuRegister::X4
            | CpuRegister::X5
            | CpuRegister::X6
            | CpuRegister::X7
            | CpuRegister::X8
            | CpuRegister::X9
            | CpuRegister::X10
            | CpuRegister::X11
            | CpuRegister::X12
            | CpuRegister::X13
            | CpuRegister::X14
            | CpuRegister::X15
            | CpuRegister::X16
            | CpuRegister::X17
            | CpuRegister::X18
            | CpuRegister::X19
            | CpuRegister::X20
            | CpuRegister::X21
            | CpuRegister::X22
            | CpuRegister::X23
            | CpuRegister::X24
            | CpuRegister::X25
            | CpuRegister::X26
            | CpuRegister::X27
            | CpuRegister::X28
            | CpuRegister::X29
            | CpuRegister::X30
            | CpuRegister::SP
            | CpuRegister::PC
            | CpuRegister::PSTATE => reg_id as u64 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
            CpuRegister::SP_EL1
            | CpuRegister::ELR_EL1
            | CpuRegister::SPSR0
            | CpuRegister::SPSR1
            | CpuRegister::SPSR2
            | CpuRegister::SPSR3
            | CpuRegister::SPSR4 => {
                todo!()
            }
        }
    }

    fn set_one_reg(&mut self, reg_id: CpuRegister, reg_value: u64) -> Result<(), std::io::Error> {
        let mut reg_value = reg_value;
        let mut reg = kvm_one_reg {
            id: Self::get_raw_reg_id(reg_id),
            addr: &mut reg_value as *mut u64 as u64,
        };

        unsafe { kvm_set_one_reg(self.vcpu_fd, &mut reg)? };

        Ok(())
    }

    fn get_one_reg(&self, reg_id: CpuRegister) -> Result<u64, std::io::Error> {
        let mut reg_value: u64 = 0;

        let mut reg = kvm_one_reg {
            id: Self::get_raw_reg_id(reg_id),
            addr: &mut reg_value as *mut u64 as u64,
        };

        unsafe { kvm_get_one_reg(self.vcpu_fd, &mut reg)? };

        Ok(reg_value)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        self.set_one_reg(CpuRegister::PC, ip)
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        self.get_one_reg(CpuRegister::PC)
    }
}
