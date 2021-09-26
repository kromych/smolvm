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

use self::x86_64::{BootE820Entry, BootParams, E820MemoryType, GpRegister};
use super::{GpaSpan, MappedGpa, Memory};
use kvm_ioctls::VmFd;
pub use std::io::Error as HvError;
use zerocopy::AsBytes;
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

        let params_slice = unsafe {
            std::slice::from_raw_parts(
                {
                    let mut params = BootParams::default();
                    params.e820_entries = spans.len() as u8;

                    for i in 0..params.e820_entries {
                        params.e820_table[i as usize] = BootE820Entry {
                            addr: spans[i as usize].gpa,
                            size: spans[i as usize].size,
                            type_: E820MemoryType::E820TypeRam,
                        }
                    }

                    params.setup_header.boot_flag = 0xaa55;
                    params.setup_header.header = 0x53726448;
                    params.setup_header.version = 0x20c;
                    params.setup_header.type_of_loader = 0xff;
                    params.setup_header.initrd_addr_max = 0x7fffffff;
                    params.setup_header.kernel_alignment = 0x200000;
                    params.setup_header.relocatable_kernel = 0x0;
                    // params.setup_header.cmd_line_ptr = 0x90000;
                    // params.setup_header.cmdline_size = 0x7ff;
                    params.setup_header.pref_address = 0x2000000;
                    params.setup_header.min_alignment = 0x15;

                    (&params as *const _) as *const u8
                },
                std::mem::size_of::<BootParams>(),
            )
        };

        let zero_page_gpa = 0x10000;
        let mut memory = Memory::new(spans);
        memory.write(zero_page_gpa, params_slice);

        let memory = Arc::new(Mutex::new(memory));

        let mut cpu = Cpu::new(&kvm_fd, &vm_fd, memory.clone())?;
        cpu.init()?;
        cpu.set_gp_register(GpRegister::Rsi, zero_page_gpa)?;
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
