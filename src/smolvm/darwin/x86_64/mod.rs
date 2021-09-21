#![cfg(target_arch = "x86_64")]

pub struct CpuExit {}
pub struct Cpu {}

impl Cpu {
    pub fn new() -> Result<Self, std::io::Error> {
        Ok(Self {})
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExit, std::io::Error> {
        Ok(CpuExit {})
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        Ok(())
    }

    pub fn get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        Ok(0)
    }
}
