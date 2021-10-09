#![cfg(target_arch = "aarch64")]

use crate::smolvm::{CpuExitReason, MmIoType};
use ahv::{HypervisorError, Register, SystemRegister, VirtualCpu, VirtualCpuExitReason};

// https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/SCTLR-EL1--System-Control-Register--EL1-?lang=en
const SCTLR_RESERVED_MUST_BE_1: u64 = (3 << 28) | (3 << 22) | (1 << 20) | (1 << 11);
const SCTLR_EE_LITTLE_ENDIAN: u64 = 0 << 25;
const SCTLR_EOE_LITTLE_ENDIAN: u64 = 0 << 24;
const SCTLR_TRAP_WFE: u64 = 1 << 18;
const SCTLR_TRAP_WFI: u64 = 1 << 16;
const SCTLR_I_CACHE_DISABLED: u64 = 0 << 12;
const SCTLR_EXCEPTION_EXIT_CONTEXT_SYNC: u64 = 1 << 11;
const SCTLR_STACK_ALIGNMENT_EL0: u64 = 1 << 4;
const SCTLR_STACK_ALIGNMENT: u64 = 1 << 3;
const SCTLR_D_CACHE_DISABLED: u64 = 0 << 2;
const SCTLR_MMU_DISABLED: u64 = 0 << 0;
const SCTLR_MMU_ENABLED: u64 = 1 << 0;

const SCTLR_INITIAL_VALUE: u64 = SCTLR_RESERVED_MUST_BE_1
    | SCTLR_EE_LITTLE_ENDIAN
    | SCTLR_TRAP_WFE
    | SCTLR_TRAP_WFI
    | SCTLR_EXCEPTION_EXIT_CONTEXT_SYNC
    | SCTLR_I_CACHE_DISABLED
    | SCTLR_D_CACHE_DISABLED
    | SCTLR_STACK_ALIGNMENT
    | SCTLR_STACK_ALIGNMENT_EL0
    | SCTLR_MMU_DISABLED;

// https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/MIDR-EL1--Main-ID-Register?lang=en
pub const MIDR_EL1_INITIAL_VALUE: u64 = 0x00000000410fd034;

pub struct Cpu {
    vcpu: VirtualCpu,
    mmio: u64,
    mmio_register_load: Option<Register>,
    sctrl_e1: u64,
}

impl Cpu {
    pub fn new(vcpu: VirtualCpu) -> Result<Self, HypervisorError> {
        Ok(Self {
            vcpu,
            mmio: 0,
            mmio_register_load: None,
            sctrl_e1: SCTLR_INITIAL_VALUE,
        })
    }

    pub fn init(&mut self) -> Result<(), HypervisorError> {
        self.vcpu.set_register(Register::CPSR, 0x3c4)?;

        log::info!("Setting MIDR_EL1 to 0x{:x}", MIDR_EL1_INITIAL_VALUE);
        self.vcpu
            .set_system_register(SystemRegister::MIDR_EL1, MIDR_EL1_INITIAL_VALUE)?;

        log::info!("Setting SCTLR_EL1 to 0x{:x}", &self.sctrl_e1);
        self.vcpu
            .set_system_register(SystemRegister::SCTLR_EL1, self.sctrl_e1)?;

        self.vcpu.set_trap_debug_exceptions(true)?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExitReason, HypervisorError> {
        // Finish pending MMIO if any
        if let Some(register) = self.mmio_register_load {
            self.set_register(register, self.mmio)?;
            self.mmio_register_load = None;
        }

        let vcpu_exit = self.vcpu.run()?;

        let exit = match vcpu_exit {
            VirtualCpuExitReason::Exception { exception } => {
                let syndrome = exception.syndrome;
                let ec = (syndrome >> 26) & 0x3f;

                // https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-?lang=en
                match ec {
                    0b011000 => {
                        // MSR, MRS, or System instruction
                        // https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-?lang=en#fieldset_0-24_0_13
                        CpuExitReason::NotSupported
                    }
                    0b100100 => {
                        // Data abort
                        // https://developer.arm.com/documentation/ddi0595/2021-09/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-?lang=en#fieldset_0-24_0_16
                        let instr_syndrome_valid = ((syndrome >> 24) & 1) != 0;
                        if instr_syndrome_valid {
                            let pa = exception.physical_address;
                            let va = exception.virtual_address;
                            let is_instr_32_bit = ((syndrome >> 25) & 1) == 1;
                            let access_size = (syndrome >> 22) & 0x3;
                            let sign_extend = ((syndrome >> 21) & 0x1) == 1;
                            let register_transfer = (syndrome >> 16) & 0x1f;
                            let register_is_64_bit = ((syndrome >> 15) & 0x1) == 1;
                            let writing_to_memory = ((syndrome >> 6) & 0x1) == 1;
                            let data_fault_status_code = syndrome & 0x1f;

                            if is_instr_32_bit && !register_is_64_bit {
                                if !writing_to_memory {
                                    self.mmio_register_load =
                                        Some(Self::get_register_by_index(register_transfer));
                                    match access_size {
                                        // 8 bit
                                        0b00 => CpuExitReason::MmIo(MmIoType::ByteIn(pa, unsafe {
                                            &mut *(&mut self.mmio as *const _ as *mut u8)
                                        })),
                                        // 16 bit
                                        0b01 => CpuExitReason::MmIo(MmIoType::WordIn(pa, unsafe {
                                            &mut *(&mut self.mmio as *const _ as *mut u16)
                                        })),
                                        // 32 bit
                                        0b10 => CpuExitReason::MmIo(MmIoType::DoubleWordIn(
                                            pa,
                                            unsafe {
                                                &mut *(&mut self.mmio as *const _ as *mut u32)
                                            },
                                        )),
                                        _ => CpuExitReason::NotSupported,
                                    }
                                } else {
                                    let value = if register_transfer != 0x1f {
                                        self.get_register(Self::get_register_by_index(
                                            register_transfer,
                                        ))?
                                    } else {
                                        /* The Zero register */
                                        0
                                    };
                                    match access_size {
                                        // 8 bit
                                        0b00 => {
                                            CpuExitReason::MmIo(MmIoType::ByteOut(pa, value as u8))
                                        }
                                        // 16 bit
                                        0b01 => {
                                            CpuExitReason::MmIo(MmIoType::WordOut(pa, value as u16))
                                        }
                                        // 32 bit
                                        0b10 => CpuExitReason::MmIo(MmIoType::DoubleWordOut(
                                            pa,
                                            value as u32,
                                        )),
                                        _ => CpuExitReason::NotSupported,
                                    }
                                }
                            } else {
                                CpuExitReason::NotSupported
                            }
                        } else {
                            CpuExitReason::NotSupported
                        }
                    }
                    _ => CpuExitReason::NotSupported,
                }
            }
            _ => CpuExitReason::NotSupported,
        };

        let ip = self.vcpu.get_register(Register::PC)?;
        if exit != CpuExitReason::NotSupported {
            // Advance the instruction pointer
            self.vcpu.set_register(Register::PC, ip + 4)?;
        } else {
            log::error!("Unsupported exit {:#x?} at 0x{:x}", vcpu_exit, ip);
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

    pub fn set_register(&mut self, reg: Register, value: u64) -> Result<(), HypervisorError> {
        self.vcpu.set_register(reg, value)
    }

    pub fn get_register(&mut self, reg: Register) -> Result<u64, HypervisorError> {
        let value = self.vcpu.get_register(reg)?;
        Ok(value)
    }

    fn get_register_by_index(index: u64) -> Register {
        match index {
            0 => Register::X0,
            1 => Register::X1,
            2 => Register::X2,
            3 => Register::X3,
            4 => Register::X4,
            5 => Register::X5,
            6 => Register::X6,
            7 => Register::X7,
            8 => Register::X8,
            9 => Register::X9,
            10 => Register::X10,
            11 => Register::X11,
            12 => Register::X12,
            13 => Register::X13,
            14 => Register::X14,
            15 => Register::X15,
            16 => Register::X16,
            17 => Register::X17,
            18 => Register::X18,
            19 => Register::X19,
            20 => Register::X20,
            21 => Register::X21,
            22 => Register::X22,
            23 => Register::X23,
            24 => Register::X24,
            25 => Register::X25,
            26 => Register::X26,
            27 => Register::X27,
            28 => Register::X28,
            29 => Register::X29, // a.k.a. FP
            30 => Register::X30, // a.k.a. LR
            // 31 means the Zero register
            _ => panic!("Invalid register index {}", index),
        }
    }
}
