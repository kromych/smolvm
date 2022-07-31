use std::{
    os::unix::prelude::RawFd,
    sync::{Arc, Mutex},
};

use kvm_bindings::{kvm_fpu, kvm_guest_debug, kvm_userspace_memory_region};

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{Cpu, CpuRegister};

#[cfg(target_arch = "aarch64")]
mod aarch64;
pub use std::io::Error as HvError;

use nix::{ioctl_read, ioctl_write_int_bad, ioctl_write_ptr, request_code_none};

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{Cpu, CpuRegister};
use super::{GpaSpan, MappedGpa, Memory};

pub fn last_os_error() -> std::io::Error {
    std::io::Error::from_raw_os_error(nix::errno::errno())
}

const KVMIO: u8 = 0xae;

ioctl_write_int_bad!(kvm_create_vm, request_code_none!(KVMIO, 0x1));
ioctl_write_int_bad!(kvm_get_vcpu_mmap_size, request_code_none!(KVMIO, 0x04));
ioctl_write_int_bad!(kvm_create_vcpu, request_code_none!(KVMIO, 0x41));
ioctl_write_ptr!(
    kvm_userspace_memory_region,
    KVMIO,
    0x46,
    kvm_userspace_memory_region
);
ioctl_write_int_bad!(kvm_run, request_code_none!(KVMIO, 0x80));
ioctl_read!(kvm_get_fpu, KVMIO, 0x8c, kvm_fpu);
ioctl_write_ptr!(kvm_set_fpu, KVMIO, 0x8d, kvm_fpu);
ioctl_write_ptr!(kvm_set_guest_debug, KVMIO, 0x9b, kvm_guest_debug);

fn open_kvm() -> std::io::Result<RawFd> {
    // Safe because we give a constant null-terminated string and verify the result.
    let ret = unsafe {
        libc::open(
            "/dev/kvm\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if ret < 0 {
        Err(last_os_error())
    } else {
        Ok(ret)
    }
}

pub struct SmolVm {
    cpu: Arc<Mutex<Cpu>>,
    memory: Arc<Mutex<Memory>>,
    _vm_fd: RawFd,
    _kvm_fd: RawFd,
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

        let kvm_fd = open_kvm()?;
        let vm_fd = unsafe {
            kvm_create_vm(kvm_fd, 36 /*vm type (PA bits = 32..36) */)
        }?;

        let mut spans = Vec::new();
        for (index, span) in gpa_map.iter().enumerate() {
            let mapped_gpa = MappedGpa {
                memory: map_anonymous(span.size),
                gpa: span.start,
                size: span.size,
            };

            unsafe {
                kvm_userspace_memory_region(
                    vm_fd,
                    &kvm_userspace_memory_region {
                        slot: index as u32,
                        guest_phys_addr: span.start,
                        memory_size: mapped_gpa.size as u64,
                        userspace_addr: mapped_gpa.memory as u64,
                        flags: 0,
                    } as *const _,
                )?;
            }

            spans.push(mapped_gpa);
        }

        let params_page: u64;

        #[cfg(target_arch = "x86_64")]
        let params_slice = {
            use self::x86_64::{BootE820Entry, BootParams, E820MemoryType};

            let params_slice = unsafe {
                std::slice::from_raw_parts(
                    {
                        let mut params = BootParams {
                            e820_entries: spans.len() as u8,
                            ..Default::default()
                        };

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

            params_slice
        };

        let mut memory = Memory::new(spans);

        #[cfg(target_arch = "x86_64")]
        {
            params_page = 0x10000;
            memory.write(params_page, params_slice);
        }

        let memory = Arc::new(Mutex::new(memory));

        let mut cpu = Cpu::new(kvm_fd, vm_fd, memory.clone())?;
        cpu.init()?;

        #[cfg(target_arch = "x86_64")]
        {
            cpu.set_gp_register(self::x86_64::CpuRegister::Rsi, params_page)?;
        }

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
