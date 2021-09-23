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

pub use std::io::Error as HvError;
pub use VcpuExit as CpuExit;

pub struct Memory {
    memory: *mut u8,
    memory_size: usize,
}

impl Memory {
    pub fn new(memory_size: usize) -> Result<Self, std::io::Error> {
        let memory = Self::mmap_anonymous(memory_size);

        Ok(Self {
            memory,
            memory_size,
        })
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.memory, self.memory_size) }
    }

    pub fn start_addr(&self) -> *const u8 {
        self.memory
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
    pub fn new(memory_size: usize) -> Result<Self, std::io::Error> {
        #[cfg(target_arch = "x86_64")]
        let native_arch = Architecture::X86_64;

        #[cfg(target_arch = "aarch64")]
        let native_arch = Architecture::Aarch64;

        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm()?;
        let memory = Arc::new(Mutex::new(Memory::new(memory_size)?));

        {
            let memory = memory.clone();
            let memory = memory.lock().unwrap();
            unsafe {
                vm_fd.set_user_memory_region(kvm_userspace_memory_region {
                    slot: 0,
                    guest_phys_addr: 0,
                    memory_size: memory_size as u64,
                    userspace_addr: memory.start_addr() as u64,
                    flags: 0,
                })?;
            }
        }

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
