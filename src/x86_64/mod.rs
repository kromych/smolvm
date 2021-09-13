#![cfg(target_arch = "x86_64")]

mod boot_params;
mod cpu;

pub use boot_params::*;
pub use cpu::*;
