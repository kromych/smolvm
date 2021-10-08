#![cfg(target_arch = "aarch64")]

use crate::smolvm::CpuExitReason;
use ahv::{HypervisorError, Register, VirtualCpu, VirtualCpuExitReason};

pub struct Cpu {
    vcpu: VirtualCpu,
    mmio: [u8; 8],
}

impl Cpu {
    pub fn new(vcpu: VirtualCpu) -> Result<Self, HypervisorError> {
        Ok(Self { vcpu, mmio: [0; 8] })
    }

    pub fn init(&mut self) -> Result<(), HypervisorError> {
        self.vcpu.set_register(Register::CPSR, 0x3c4)?;
        self.vcpu.set_trap_debug_exceptions(true)?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExitReason, HypervisorError> {
        let exit = self.vcpu.run()?;

        match exit {
            VirtualCpuExitReason::Exception { exception } => {
                // https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-?lang=en
                let syndrome = exception.syndrome;
                let ec = (syndrome >> 26) & 0x3f;
                match ec {
                    0b100100 => {
                        // Data abort
                        // https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-?lang=en#fieldset_0-24_0_16
                        let instr_syndrome_valid = ((syndrome >> 24) & 1) != 0;
                        if instr_syndrome_valid {
                            let is_trapped_instr_32_bit = ((syndrome >> 25) & 1) != 0;
                            let access_size = (syndrome >> 22) & 0x3;
                            let sign_extend = (syndrome >> 21) & 0x1;
                            let register_transfer = (syndrome >> 16) & 0xf;
                            let register_is_64_bit = (syndrome >> 15) & 0x1;
                            let writing_to_memory = ((syndrome >> 6) & 0x1) == 1;
                            let data_fault_status_code = syndrome & 0x1f;

                            log::info!("is_trapped_instr_32_bit {},access_size 0x{:x},sign_extend 0x{:x},register_transfer 0x{:x},register_is_64_bit 0x{:x},writing_to_memory {},data_fault_status_code 0x{:x}",
                            is_trapped_instr_32_bit,
                            access_size,
                            sign_extend,
                            register_transfer,
                            register_is_64_bit,
                            writing_to_memory,
                            data_fault_status_code);

                            if is_trapped_instr_32_bit {
                                /*
                                    0b00	Byte
                                    0b01	Halfword
                                    0b10	Word
                                    0b11	Doubleword
                                */
                                if !writing_to_memory {
                                } else {
                                }
                            }
                        }
                    }
                    _ => {}
                }
                let ip = self.vcpu.get_register(Register::PC)?;
                log::info!(
                    "Exception syndrome 0x{:x} at 0x{:x}, virt.address 0x{:x}, phys.address 0x{:x}",
                    ec,
                    ip,
                    exception.virtual_address,
                    exception.physical_address
                );
                //self.vcpu.set_register(Register::PC, ip + 4)?;
            }
            e => panic!("Unsupported Vcpu Exit {:?}", e),
        }

        Ok(CpuExitReason::NotSupported)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), HypervisorError> {
        self.vcpu.set_register(Register::PC, ip)
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, HypervisorError> {
        let ip = self.vcpu.get_register(Register::PC)?;
        Ok(ip)
    }

    pub fn set_register(&mut self, reg: Register, value: u64) -> Result<(), HypervisorError> {
        self.vcpu.set_register(reg, value)
    }

    pub fn get_register(&mut self, reg: Register) -> Result<u64, HypervisorError> {
        let value = self.vcpu.get_register(reg)?;
        Ok(value)
    }
}
