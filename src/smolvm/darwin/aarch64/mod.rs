#![cfg(target_arch = "aarch64")]

pub use ahv::VirtualCpuExitReason as CpuExit;
use ahv::{HypervisorError, Register, VirtualCpu, VirtualCpuExitReason};

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

    pub fn run(&mut self) -> Result<CpuExit, HypervisorError> {
        let exit = self.vcpu.run()?;

        match exit {
            VirtualCpuExitReason::Exception { exception } => {
                let ec = (exception.syndrome >> 26) & 0x3f;
                let ip = self.vcpu.get_register(Register::PC)?;
                log::info!("Exception syndrome 0x{:x} at 0x{:x}", ec, ip);
                self.vcpu.set_register(Register::PC, ip + 4)?;
            }
            e => panic!("Unsupported Vcpu Exit {:?}", e),
        }

        Ok(exit)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), HypervisorError> {
        self.vcpu.set_register(Register::PC, ip)
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, HypervisorError> {
        let ip = self.vcpu.get_register(Register::PC)?;
        Ok(ip)
    }
}
