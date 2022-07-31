#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

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
use crate::smolvm::{CpuExitReason, MmIoType};

mod cpu;

use cpu::*;

#[repr(u64)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum CpuRegister {
    X0 = 0 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X1 = 1 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X2 = 2 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X3 = 3 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X4 = 4 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X5 = 5 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X6 = 6 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X7 = 7 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X8 = 8 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X9 = 9 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X10 = 10 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X11 = 11 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X12 = 12 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X13 = 13 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X14 = 14 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X15 = 15 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X16 = 16 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X17 = 17 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X18 = 18 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X19 = 19 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X20 = 20 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X21 = 21 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X22 = 22 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X23 = 23 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X24 = 24 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X25 = 25 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X26 = 26 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X27 = 27 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X28 = 28 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X29 = 29 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    X30 = 30 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    SP = 31 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    PC = 32 * 2 + (REG_ARM64_CORE_BASE | REG_SIZE_U64),
    MIDR_EL1 = SYS_MIDR_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    MPIDR_EL1 = SYS_MPIDR_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    SCTLR_EL1 = SYS_SCTLR_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    TTBR0_EL1 = SYS_TTBR0_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    TTBR1_EL1 = SYS_TTBR1_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    ESR_EL1 = SYS_ESR_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    SPSR_EL1 = SYS_SPSR_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
    MAIR_EL1 = SYS_MAIR_EL1 + (REG_ARM64_SYSREG_BASE | REG_SIZE_U64),
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
        // self.set_one_reg(CpuRegister::SPSR_EL1, SPSR_INITIAL_VALUE)?;
        // self.set_one_reg(CpuRegister::SCTLR_EL1, SCTLR_INITIAL_VALUE)?;
        // self.set_one_reg(CpuRegister::MIDR_EL1, MIDR_EL1_INITIAL_VALUE)?;
        // self.set_one_reg(CpuRegister::TTBR0_EL1, 0)?;
        // self.set_one_reg(CpuRegister::TTBR1_EL1, 0)?;
        // self.set_one_reg(CpuRegister::ESR_EL1, 0)?;
        // self.set_one_reg(CpuRegister::MAIR_EL1, 0)?;

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
            KVM_EXIT_MMIO => unsafe {
                let mmio = &mut run.__bindgen_anon_1.mmio;
                let pa = mmio.phys_addr;
                let len = mmio.len as usize;
                let data = &mut mmio.data[..len];
                let writing_to_memory = mmio.is_write != 0;

                if !writing_to_memory {
                    match len {
                        1 => CpuExitReason::MmIo(MmIoType::ByteIn(
                            pa,
                            &mut *(&mut data[0] as *const _ as *mut u8),
                        )),
                        // 16 bit
                        2 => CpuExitReason::MmIo(MmIoType::WordIn(
                            pa,
                            &mut *(&mut data[0] as *const _ as *mut u16),
                        )),
                        // 32 bit
                        4 => CpuExitReason::MmIo(MmIoType::DoubleWordIn(
                            pa,
                            &mut *(&mut data[0] as *const _ as *mut u32),
                        )),
                        _ => CpuExitReason::NotSupported,
                    }
                } else {
                    match len {
                        1 => CpuExitReason::MmIo(MmIoType::ByteOut(pa, data[0] as u8)),
                        2 => CpuExitReason::MmIo(MmIoType::WordOut(
                            pa,
                            *(&mut data[0] as *const _ as *mut u16),
                        )),
                        4 => CpuExitReason::MmIo(MmIoType::DoubleWordOut(
                            pa,
                            *(&mut data[0] as *const _ as *mut u32),
                        )),
                        _ => CpuExitReason::NotSupported,
                    }
                }
            },
        };

        Ok(exit_reason)
    }

    fn set_one_reg(&mut self, reg_id: CpuRegister, reg_value: u64) -> Result<(), std::io::Error> {
        let mut reg_value = reg_value;
        let mut reg = kvm_one_reg {
            id: reg_id as u64,
            addr: &mut reg_value as *mut u64 as u64,
        };

        unsafe { kvm_set_one_reg(self.vcpu_fd, &mut reg)? };

        Ok(())
    }

    fn get_one_reg(&self, reg_id: CpuRegister) -> Result<u64, std::io::Error> {
        let mut reg_value: u64 = 0;

        let mut reg = kvm_one_reg {
            id: reg_id as u64,
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

    pub fn set_register(
        &mut self,
        regsiter: CpuRegister,
        value: u64,
    ) -> Result<(), std::io::Error> {
        self.set_one_reg(regsiter, value)
    }

    pub fn get_register(&mut self, regsiter: CpuRegister) -> Result<u64, std::io::Error> {
        self.get_one_reg(regsiter)
    }
}
