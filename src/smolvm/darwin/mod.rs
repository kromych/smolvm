#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{Cpu, CpuExit};

#[cfg(target_arch = "aarch64")]
mod aarch64;
pub use ahv::Register as CpuRegister;
use std::sync::{Arc, Mutex};

pub use ahv::HypervisorError as HvError;
use ahv::{MemoryPermission, VirtualMachine};

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::Cpu;
use super::{GpaSpan, MappedGpa, Memory};

pub struct SmolVm {
    cpu: Arc<Mutex<Cpu>>,
    memory: Arc<Mutex<Memory>>,
    vm: VirtualMachine,
}

impl SmolVm {
    pub fn new(memory_map: &[GpaSpan]) -> Result<Self, HvError> {
        let mut vm = VirtualMachine::new(None)?;
        let memory = {
            let mut memory_spans = Vec::new();

            for gpa_span in memory_map {
                let handle = vm.allocate(gpa_span.size)?;
                vm.map(handle, gpa_span.start, MemoryPermission::READ_WRITE_EXECUTE)?;
                let alloc = vm.get_allocation_slice(handle)?;
                let base = (alloc as *const _) as *mut u8;
                let size = alloc.len();

                memory_spans.push(MappedGpa {
                    memory: base,
                    gpa: gpa_span.start,
                    size,
                });
            }

            Memory::new(memory_spans)
        };

        let vcpu = vm.create_vcpu(None)?;
        let mut cpu = Cpu::new(vcpu)?;
        cpu.init()?;

        Ok(Self {
            vm,
            cpu: Arc::new(Mutex::new(cpu)),
            memory: Arc::new(Mutex::new(memory)),
        })
    }
}

impl crate::smolvm::SmolVmT for SmolVm {
    fn get_memory(&self) -> std::sync::Arc<std::sync::Mutex<Memory>> {
        self.memory.clone()
    }

    fn get_cpu(&self) -> std::sync::Arc<std::sync::Mutex<Cpu>> {
        self.cpu.clone()
    }
}
