use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
pub use kvm_ioctls::VcpuExit;

use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::Cpu;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::Cpu;

use super::{GpaSpan, MappedGpa, Memory};
use kvm_ioctls::VmFd;
pub use std::io::Error as HvError;
pub use VcpuExit as CpuExit;

pub struct SmolVm {
    cpu: Arc<Mutex<Cpu>>,
    memory: Arc<Mutex<Memory>>,
    _vm_fd: VmFd,
    _kvm_fd: Kvm,
}

impl SmolVm {
    pub fn new(gpa_map: &[GpaSpan]) -> Result<Self, std::io::Error> {
        let map_anonymous = |size: usize| -> *mut u8 {
            use std::ptr::null_mut;

            let addr = unsafe {
                libc::mmap(
                    null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            if addr == libc::MAP_FAILED {
                panic!("mmap failed.");
            }

            addr as *mut u8
        };

        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm()?;

        let mut spans = Vec::new();
        for (index, span) in gpa_map.iter().enumerate() {
            let mapped_gpa = MappedGpa {
                memory: map_anonymous(span.size),
                gpa: span.start,
                size: span.size,
            };

            unsafe {
                vm_fd.set_user_memory_region(kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: span.start,
                    memory_size: mapped_gpa.size as u64,
                    userspace_addr: mapped_gpa.memory as u64,
                    flags: 0,
                })?;
            }

            spans.push(mapped_gpa);
        }

        let memory = Arc::new(Mutex::new(Memory::new(spans)));
        let mut cpu = Cpu::new(&kvm_fd, &vm_fd, memory.clone())?;
        cpu.init()?;
        let cpu = Arc::new(Mutex::new(cpu));

        Ok(Self {
            cpu,
            memory,
            _vm_fd: vm_fd,
            _kvm_fd: kvm_fd,
        })
    }
}

impl crate::SmolVmT for SmolVm {
    fn get_memory(&self) -> std::sync::Arc<std::sync::Mutex<Memory>> {
        self.memory.clone()
    }

    fn get_cpu(&self) -> std::sync::Arc<std::sync::Mutex<Cpu>> {
        self.cpu.clone()
    }
}
