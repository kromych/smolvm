#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{Cpu, CpuExit};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{Cpu, CpuExit};

pub use ahv::HypervisorError as HvError;

use ahv::{MemoryPermission, VirtualCpuExitReason, VirtualMachine};
use object::Architecture;
use std::sync::{Arc, Mutex};

pub struct Memory {
    base: *mut u8,
    size: usize,
}

impl Memory {
    pub fn new(base: *mut u8, size: usize) -> Self {
        Self { base, size }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base, self.size) }
    }

    pub fn as_slice_mut(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.base, self.size) }
    }
}

pub struct SmolVm {
    native_arch: Architecture,
    vm: VirtualMachine,
    cpu: Arc<Mutex<Cpu>>,
    memory: Arc<Mutex<Memory>>,
}

impl SmolVm {
    pub fn new(memory_size: usize) -> Result<Self, HvError> {
        #[cfg(target_arch = "x86_64")]
        let native_arch = Architecture::X86_64;

        #[cfg(target_arch = "aarch64")]
        let native_arch = Architecture::Aarch64;

        let mut vm = VirtualMachine::new(None)?;

        let handle = vm.allocate(memory_size)?;
        vm.map(handle, 0x10000, MemoryPermission::READ_WRITE_EXECUTE)?;
        let alloc = vm.get_allocation_slice(handle)?;
        let base = (alloc as *const _) as *mut u8;
        let size = alloc.len();

        let memory = Memory::new(base, size);

        let vcpu = vm.create_vcpu(None)?;

        let mut cpu = Cpu::new(vcpu)?;
        cpu.init()?;

        Ok(Self {
            native_arch,
            vm,
            cpu: Arc::new(Mutex::new(cpu)),
            memory: Arc::new(Mutex::new(memory)),
        })
    }
}

impl crate::smolvm::SmolVmT for SmolVm {
    fn get_native_arch(&self) -> object::Architecture {
        self.native_arch
    }

    fn get_memory(&self) -> std::sync::Arc<std::sync::Mutex<Memory>> {
        self.memory.clone()
    }

    fn get_cpu(&self) -> std::sync::Arc<std::sync::Mutex<Cpu>> {
        self.cpu.clone()
    }
}
