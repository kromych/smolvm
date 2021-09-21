#![cfg(target_arch = "aarch64")]

use super::Memory;
use kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
use kvm_ioctls::VcpuExit;
use kvm_ioctls::VcpuFd;
use std::sync::Arc;
use std::sync::Mutex;

pub struct Cpu {
    vcpu_fd: VcpuFd,
    _memory: Arc<Mutex<Memory>>,
}

impl Cpu {
    pub fn new(
        vm_fd: &kvm_ioctls::VmFd,
        _memory: Arc<Mutex<Memory>>,
    ) -> Result<Self, std::io::Error> {
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        vm_fd.get_preferred_target(&mut kvi)?;
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu_fd.vcpu_init(&kvi)?;

        Ok(Self { vcpu_fd, _memory })
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }

    pub fn run(&mut self) -> Result<VcpuExit, std::io::Error> {
        let result = self.vcpu_fd.run()?;
        Ok(result)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        self.vcpu_fd.set_one_reg(core_reg_base + 2 * 32, ip)?;

        Ok(())
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let ip = self.vcpu_fd.get_one_reg(core_reg_base + 2 * 32)?;

        Ok(ip)
    }
}
