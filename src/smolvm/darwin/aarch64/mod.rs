#![cfg(target_arch = "aarch64")]

use ahv::HypervisorError;
use ahv::Register;
use ahv::VirtualCpu;
pub use ahv::VirtualCpuExitReason as CpuExit;

pub struct Cpu {
    vcpu: VirtualCpu,
}

impl Cpu {
    pub fn new(vcpu: VirtualCpu) -> Result<Self, HypervisorError> {
        Ok(Self { vcpu })
    }

    pub fn init(&mut self) -> Result<(), HypervisorError> {
        self.vcpu.set_register(Register::CPSR, 0x3c4)?;
        self.vcpu.set_trap_debug_exceptions(true)?;

        Ok(())
    }

    pub fn map(&self, _pfn: u64, _virt_addr: u64) {
        todo!()
    }

    pub fn run(&mut self) -> Result<CpuExit, HypervisorError> {
        let result = self.vcpu.run()?;
        Ok(result)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), HypervisorError> {
        self.vcpu.set_register(Register::PC, ip)
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, HypervisorError> {
        let ip = self.vcpu.get_register(Register::PC)?;
        Ok(ip)
    }
}
