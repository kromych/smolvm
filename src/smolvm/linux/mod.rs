use kvm_bindings::{kvm_userspace_memory_region, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::Kvm;
pub use kvm_ioctls::VcpuExit;

use object::Architecture;

use std::sync::Arc;
use std::sync::Mutex;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::Cpu;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::Cpu;

use super::GpaSpan;
use kvm_ioctls::VmFd;
pub use std::io::Error as HvError;
pub use VcpuExit as CpuExit;

struct MappedGpa {
    memory: *mut u8,
    gpa: u64,
    size: usize,
}

pub struct Memory {
    spans: Vec<MappedGpa>,
}

impl Memory {
    pub fn new(vm_fd: &VmFd, gpa_map: &[GpaSpan]) -> Result<Self, std::io::Error> {
        let mut memory = Self { spans: Vec::new() };
        for (index, span) in gpa_map.iter().enumerate() {
            if memory.find_span(span.start).is_some() {
                panic!(
                    "Duplicated/overlapping entries in the memory map: GPA {:#x}",
                    span.start
                );
            }

            let mapped_gpa = MappedGpa {
                memory: Self::mmap_anonymous(span.size),
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

            memory.spans.push(mapped_gpa);
        }

        Ok(memory)
    }

    pub fn write(&mut self, gpa: u64, data: &[u8]) {
        if let Some(span) = self.find_span(gpa) {
            let span = unsafe {
                std::slice::from_raw_parts_mut(
                    (span.memory as u64 + (gpa - span.gpa)) as *mut u8,
                    span.size - (gpa as usize - span.gpa as usize),
                )
            };

            span[..data.len()].copy_from_slice(data);
        } else {
            panic!("Cannot write as GPA is invalid {:#x}", gpa);
        }
    }

    pub fn read(&self, gpa: u64, size: usize) -> &[u8] {
        if let Some(span) = self.find_span(gpa) {
            let span = unsafe {
                std::slice::from_raw_parts(
                    (span.memory as u64 + (gpa - span.gpa)) as *mut u8,
                    span.size - (gpa as usize - span.gpa as usize),
                )
            };

            if span.len() < size {
                panic!(
                    "Cannot read {} bytes at GPA {:#x}, only {} bytes available",
                    size,
                    gpa,
                    span.len()
                );
            }

            span
        } else {
            panic!("Cannot read as GPA is invalid {:#x}", gpa);
        }
    }

    pub fn is_gpa_valid(&self, gpa: u64) -> bool {
        self.find_span(gpa).is_some()
    }

    fn find_span(&self, gpa: u64) -> Option<&MappedGpa> {
        for span in &self.spans {
            if span.gpa <= gpa && gpa < span.gpa + span.size as u64 {
                return Some(span);
            }
        }

        None
    }

    fn mmap_anonymous(size: usize) -> *mut u8 {
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
    }
}

pub struct SmolVm {
    native_arch: Architecture,
    cpu: Arc<Mutex<Cpu>>,
    memory: Arc<Mutex<Memory>>,
}

impl SmolVm {
    pub fn new(gpa_map: &[GpaSpan]) -> Result<Self, std::io::Error> {
        #[cfg(target_arch = "x86_64")]
        let native_arch = Architecture::X86_64;

        #[cfg(target_arch = "aarch64")]
        let native_arch = Architecture::Aarch64;

        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm()?;
        let memory = Arc::new(Mutex::new(Memory::new(&vm_fd, gpa_map)?));
        let mut cpu = Cpu::new(&kvm_fd, &vm_fd, memory.clone())?;
        cpu.init()?;
        let cpu = Arc::new(Mutex::new(cpu));

        Ok(Self {
            native_arch,
            cpu,
            memory,
        })
    }
}

impl crate::SmolVmT for SmolVm {
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
