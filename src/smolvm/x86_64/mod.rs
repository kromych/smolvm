#![cfg(target_arch = "x86_64")]

mod boot_params;
mod cpu;

use super::VirtualCpu;
pub use boot_params::*;
pub use cpu::*;
use kvm_ioctls::VcpuFd;

pub struct CpuX86_64 {
    vcpu_fd: VcpuFd,
    //memory: &'a mut super::Memory,
}

impl VirtualCpu for CpuX86_64 {
    fn new(vm_fd: &kvm_ioctls::VmFd, memory: &mut super::Memory) -> Result<Self, std::io::Error> {
        let vcpu_fd = vm_fd.create_vcpu(0)?;

        Ok(Self { vcpu_fd })
    }

    fn map(pfn: u64, virt_addr: u64) {
        todo!()
    }

    fn run() -> Result<(), std::io::Error> {
        todo!()
    }
}
