#![allow(dead_code)]
#![allow(non_upper_case_globals)]

//! Copied from arch/arm64/include/uapi/asm/ptrace.h

/**
 * PSR bits
 */
pub const PSR_MODE_EL0t: u32 = 0x00000000;
pub const PSR_MODE_EL1t: u32 = 0x00000004;
pub const PSR_MODE_EL1h: u32 = 0x00000005;
pub const PSR_MODE_EL2t: u32 = 0x00000008;
pub const PSR_MODE_EL2h: u32 = 0x00000009;
pub const PSR_MODE_EL3t: u32 = 0x0000000c;
pub const PSR_MODE_EL3h: u32 = 0x0000000d;
pub const PSR_MODE_MASK: u32 = 0x0000000f;

/* AArch32 CPSR bits */
pub const PSR_MODE32_BIT: u32 = 0x00000010;

/* AArch64 SPSR bits */
pub const PSR_F_BIT: u32 = 0x00000040;
pub const PSR_I_BIT: u32 = 0x00000080;
pub const PSR_A_BIT: u32 = 0x00000100;
pub const PSR_D_BIT: u32 = 0x00000200;
pub const PSR_BTYPE_MASK: u32 = 0x00000c00;
pub const PSR_SSBS_BIT: u32 = 0x00001000;
pub const PSR_PAN_BIT: u32 = 0x00400000;
pub const PSR_UAO_BIT: u32 = 0x00800000;
pub const PSR_DIT_BIT: u32 = 0x01000000;
pub const PSR_TCO_BIT: u32 = 0x02000000;
pub const PSR_V_BIT: u32 = 0x10000000;
pub const PSR_C_BIT: u32 = 0x20000000;
pub const PSR_Z_BIT: u32 = 0x40000000;
pub const PSR_N_BIT: u32 = 0x80000000;

pub const PSR_BTYPE_SHIFT: u32 = 10;

/*
 * Groups of PSR bits
 */
pub const PSR_f: u32 = 0xff000000; /* Flags		*/
pub const PSR_s: u32 = 0x00ff0000; /* Status		*/
pub const PSR_x: u32 = 0x0000ff00; /* Extension		*/
pub const PSR_c: u32 = 0x000000ff; /* Control		*/

/* Convenience names for the values of PSTATE.BTYPE */
pub const PSR_BTYPE_NONE: u32 = 0b00 << PSR_BTYPE_SHIFT;
pub const PSR_BTYPE_JC: u32 = 0b01 << PSR_BTYPE_SHIFT;
pub const PSR_BTYPE_C: u32 = 0b10 << PSR_BTYPE_SHIFT;
pub const PSR_BTYPE_J: u32 = 0b11 << PSR_BTYPE_SHIFT;

pub const REG_ARM_COPROC_SHIFT: u64 = 16;

// Normal registers are mapped as coprocessor 16
pub const REG_ARM_CORE: u64 = 0x0010 << REG_ARM_COPROC_SHIFT;

pub const REG_ARM64: u64 = 0x6000000000000000;
pub const REG_ARM64_CORE_BASE: u64 = REG_ARM64 | REG_ARM_CORE;

pub const REG_SIZE_U8: u64 = 0x0000000000000000;
pub const REG_SIZE_U16: u64 = 0x0010000000000000;
pub const REG_SIZE_U32: u64 = 0x0020000000000000;
pub const REG_SIZE_U64: u64 = 0x0030000000000000;
pub const REG_SIZE_U128: u64 = 0x0040000000000000;
pub const REG_SIZE_U256: u64 = 0x0050000000000000;
pub const REG_SIZE_U512: u64 = 0x0060000000000000;
pub const REG_SIZE_U1024: u64 = 0x0070000000000000;
pub const REG_SIZE_U2048: u64 = 0x0080000000000000;
