#![cfg(target_arch = "x86_64")]

mod boot_params;
mod cpu;

use std::{
    os::unix::prelude::RawFd,
    sync::{Arc, Mutex},
};

pub use boot_params::*;
pub use cpu::*;
use kvm_bindings::{
    kvm_cpuid2, kvm_cpuid_entry2, kvm_dtable, kvm_msr_entry, kvm_msrs, kvm_regs, kvm_run,
    kvm_segment, kvm_sregs, KVM_EXIT_HLT, KVM_EXIT_IO, KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT,
    KVM_EXIT_MMIO,
};
use raw_cpuid::CpuId;
use zerocopy::AsBytes;

use super::Memory;
use crate::smolvm::{CpuExitReason, IoType};

#[allow(dead_code)]
pub enum GpRegister {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

// The second entry matters for TSS and LDT only
fn get_x86_64_dtable_64bit_entry(kvm_entry: &kvm_segment) -> u64 {
    if kvm_entry.s == 0 {
        panic!("Invalid 64-bit entry")
    };

    let limit_low: u16 = (kvm_entry.limit & 0xffff) as u16;
    let base_low: u16 = (kvm_entry.base & 0xffff) as u16;
    let base_middle: u8 = ((kvm_entry.base >> 16) & 0xff) as u8;

    let limit_high: u8 = ((kvm_entry.limit >> 16) & 0xf) as u8;
    let attr = (kvm_entry.type_ as u16 & 0xf)
        | (kvm_entry.s as u16 & 0x1) << 4
        | (kvm_entry.dpl as u16 & 0x3) << 5
        | (kvm_entry.present as u16 & 0x1) << 7
        | (limit_high as u16 & 0xf) << 8
        | (kvm_entry.l as u16 & 0x1) << 13
        | (kvm_entry.db as u16 & 0x1) << 14
        | (kvm_entry.g as u16 & 0x1) << 15;

    let base_high: u8 = ((kvm_entry.base >> 24) & 0xff) as u8;

    limit_low as u64
        | ((base_low as u64) << 16)
        | ((base_middle as u64) << 32)
        | ((attr as u64) << 40)
        | ((base_high as u64) << 48)
}

fn get_x86_64_dtable_128bit_entry(kvm_entry: &kvm_segment) -> [u64; 2] {
    let limit_low: u16 = (kvm_entry.limit & 0xffff) as u16;
    let base_low: u16 = (kvm_entry.base & 0xffff) as u16;
    let base_middle: u8 = ((kvm_entry.base >> 16) & 0xff) as u8;

    let limit_high: u8 = ((kvm_entry.limit >> 16) & 0xf) as u8;
    let attr = (kvm_entry.type_ as u16 & 0xf)
        | (kvm_entry.s as u16 & 0x1) << 4
        | (kvm_entry.dpl as u16 & 0x3) << 5
        | (kvm_entry.present as u16 & 0x1) << 7
        | (limit_high as u16 & 0xf) << 8
        | (kvm_entry.l as u16 & 0x1) << 13
        | (kvm_entry.db as u16 & 0x1) << 14
        | (kvm_entry.g as u16 & 0x1) << 15;

    let base_high: u8 = ((kvm_entry.base >> 24) & 0xff) as u8;

    [
        limit_low as u64
            | ((base_low as u64) << 16)
            | ((base_middle as u64) << 32)
            | ((attr as u64) << 40)
            | ((base_high as u64) << 48),
        if kvm_entry.s == 0 {
            kvm_entry.base >> 32
        } else {
            panic!("Invalid 128-bit GDT entry")
        },
    ]
}

pub struct Cpu {
    kvm_fd: RawFd,
    vcpu_fd: RawFd,
    vcpu_run: *mut kvm_run,
    _vcpu_mmap_size: i32,
    memory: Arc<Mutex<Memory>>,
}

impl Cpu {
    pub fn new(
        kvm_fd: RawFd,
        vm_fd: RawFd,
        memory: Arc<Mutex<Memory>>,
    ) -> Result<Self, std::io::Error> {
        let vcpu_fd = unsafe {
            super::kvm_create_vcpu(vm_fd, 0 /* id */)?
        };

        let vcpu_mmap_size = unsafe { super::kvm_get_vcpu_mmap_size(kvm_fd, 0)? };
        let vcpu_run = unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                vcpu_mmap_size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu_fd,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(super::last_os_error());
            }
            ptr as *mut kvm_run
        };

        Ok(Self {
            kvm_fd,
            vcpu_fd,
            vcpu_run,
            _vcpu_mmap_size: vcpu_mmap_size,
            memory,
        })
    }

    fn setup_cpuid(&self) -> Result<(), std::io::Error> {
        let vcpu_fd = self.vcpu_fd;

        let host_cpu_id = CpuId::new();
        log::trace!("Host CPU: {:#x?}", host_cpu_id);

        // Inspect the default CPUID data
        //let guest_cpu_id = kvm_get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?.as_slice();

        // TODO For MP, need to set APIC ID properly

        // Set all supported CPUID features, no filtering.
        // Without that, the kernel would fail to set MSRs, etc as support for that
        // is communicated through CPUID
        unsafe {
            const KVM_CPUID_NENT: u32 = 256;

            #[repr(C)]
            struct KvmCpuid2Array {
                header: kvm_cpuid2,
                entries: [kvm_cpuid_entry2; KVM_CPUID_NENT as usize],
            }

            let mut cpu_id_entries = KvmCpuid2Array {
                header: kvm_cpuid2 {
                    nent: KVM_CPUID_NENT,
                    ..Default::default()
                },
                entries: [kvm_cpuid_entry2::default(); KVM_CPUID_NENT as usize],
            };

            super::kvm_get_supported_cpuid(self.kvm_fd, &mut cpu_id_entries.header as *mut _)?;
            super::kvm_set_cpuid2(vcpu_fd, &cpu_id_entries.header as *const _)?;
        }

        Ok(())
    }

    fn get_regs(&self) -> Result<kvm_regs, std::io::Error> {
        let mut regs = kvm_regs::default();
        unsafe {
            super::kvm_get_regs(self.vcpu_fd, &mut regs as *mut _)?;
        }

        Ok(regs)
    }

    fn set_regs(&self, regs: &kvm_regs) -> Result<(), std::io::Error> {
        unsafe {
            super::kvm_set_regs(self.vcpu_fd, regs as *const _)?;
        }

        Ok(())
    }

    fn get_sregs(&self) -> Result<kvm_sregs, std::io::Error> {
        let mut sregs = kvm_sregs::default();
        unsafe {
            super::kvm_get_sregs(self.vcpu_fd, &mut sregs as *mut _)?;
        }

        Ok(sregs)
    }

    fn set_sregs(&self, sregs: &kvm_sregs) -> Result<(), std::io::Error> {
        unsafe {
            super::kvm_set_sregs(self.vcpu_fd, sregs as *const _)?;
        }

        Ok(())
    }

    fn setup_long_mode(&mut self) -> Result<(), std::io::Error> {
        const STACK_TOP_OFFSET: u64 = 0x3fff0;
        const GDT_OFFSET: u64 = 0x4000;
        const TSS_OFFSET: u64 = 0x5000;
        const PML4T_OFFSET: u64 = 0x6000;
        const PDPT_OFFSET: u64 = 0x7000;
        const PDT_OFFSET: u64 = 0x8000;

        let mut memory = self.memory.lock().unwrap();

        let mut sregs = self.get_sregs()?;

        // Set up table registers
        {
            let data_seg = kvm_segment {
                selector: BOOT_CODE_DS,
                type_: DataSegmentType::ReadWriteAccessed as u8,
                limit: 0xfffff,
                present: 1,
                s: 1,
                g: 1,
                db: 1,
                ..kvm_segment::default()
            };
            let code_seg = kvm_segment {
                selector: BOOT_CODE_CS,
                type_: CodeSegmentType::ExecuteReadAccessed as u8,
                limit: 0xfffff,
                l: 1,
                present: 1,
                s: 1,
                g: 1,
                ..kvm_segment::default()
            };
            let system_seg = kvm_segment {
                present: 1,
                ..kvm_segment::default()
            };

            sregs.cs = code_seg;

            sregs.es = data_seg;
            sregs.ds = data_seg;
            sregs.fs = data_seg;
            sregs.gs = data_seg;
            sregs.ss = data_seg;

            sregs.ldt = kvm_segment {
                type_: SystemDescriptorTypes64::Ldt as u8,
                selector: BOOT_CODE_LDT,
                ..system_seg
            };
            sregs.tr = kvm_segment {
                type_: SystemDescriptorTypes64::TssBusy as u8,
                selector: BOOT_CODE_TSS,
                base: TSS_OFFSET,
                limit: 0x67,
                ..system_seg
            };

            sregs.gdt = kvm_dtable {
                base: GDT_OFFSET,
                limit: 0x7f,
                padding: [0; 3],
            };

            memory.write(
                GDT_OFFSET + (BOOT_CODE_CS_GDT_INDEX << 3) as u64,
                get_x86_64_dtable_64bit_entry(&sregs.cs).as_bytes(),
            );
            memory.write(
                GDT_OFFSET + (BOOT_CODE_SS_GDT_INDEX << 3) as u64,
                get_x86_64_dtable_64bit_entry(&sregs.ss).as_bytes(),
            );
            memory.write(
                GDT_OFFSET + (BOOT_CODE_TSS_GDT_INDEX << 3) as u64,
                get_x86_64_dtable_128bit_entry(&sregs.tr).as_bytes(),
            );
        }

        // Set up page tables for identical mapping of the first 4GiB
        {
            memory.write(
                PML4T_OFFSET,
                [PDPT_OFFSET | (PML4Flags::P | PML4Flags::RW).bits()].as_bytes(),
            );
            memory.write(
                PDPT_OFFSET,
                [PDT_OFFSET | (PDPTFlags::P | PDPTFlags::RW).bits()].as_bytes(),
            );

            for large_page_index in 0..PAGE_SIZE / std::mem::size_of::<u64>() as u64 {
                memory.write(
                    PDT_OFFSET + large_page_index * 8,
                    [((large_page_index as u64) * LARGE_PAGE_SIZE)
                        | (PDFlags::P | PDFlags::RW | PDFlags::PS).bits()]
                    .as_bytes(),
                );
            }
        }

        // Set up control registers and EFER
        {
            sregs.cr0 = CR0_PE | CR0_PG;
            sregs.cr3 = get_pfn(PML4T_OFFSET) << PAGE_SHIFT;
            sregs.cr4 = CR4_PAE;
            sregs.efer = EFER_LMA | EFER_LME | EFER_NXE | EFER_SCE;
        }

        self.set_sregs(&sregs)?;

        let mut regs = self.get_regs()?;
        regs.rsp = STACK_TOP_OFFSET;
        regs.rbp = STACK_TOP_OFFSET;
        regs.rflags = 2;
        self.set_regs(&regs)?;

        Ok(())
    }

    fn setup_msrs(&self) -> Result<(), std::io::Error> {
        const KVM_MSR_NENT: u32 = 2;

        #[repr(C)]
        struct KvmMsrs {
            header: kvm_msrs,
            entries: [kvm_msr_entry; KVM_MSR_NENT as usize],
        }

        let msrs = KvmMsrs {
            header: kvm_msrs {
                nmsrs: KVM_MSR_NENT,
                ..Default::default()
            },
            entries: [
                kvm_msr_entry {
                    index: MSR_IA32_CR_PAT,
                    data: MSR_IA32_CR_PAT_DEFAULT,
                    ..Default::default()
                },
                kvm_msr_entry {
                    index: MSR_IA32_MISC_ENABLE,
                    data: MSR_IA32_MISC_ENABLE_FAST_STR,
                    ..Default::default()
                },
            ],
        };

        unsafe {
            super::kvm_set_msrs(self.vcpu_fd, &msrs.header as *const _)?;
        }

        Ok(())
    }

    fn setup_fpu(&self) -> Result<(), std::io::Error> {
        unsafe {
            super::kvm_set_fpu(
                self.vcpu_fd,
                &kvm_bindings::kvm_fpu {
                    fcw: 0x37f,
                    mxcsr: 0x1f80,
                    ..Default::default()
                } as *const _,
            )?;
        }
        Ok(())
    }

    fn _setup_debug(&self) -> Result<(), std::io::Error> {
        // Single-step the guest
        unsafe {
            super::kvm_set_guest_debug(
                self.vcpu_fd,
                &kvm_bindings::kvm_guest_debug {
                    control: kvm_bindings::KVM_GUESTDBG_ENABLE
                        | kvm_bindings::KVM_GUESTDBG_SINGLESTEP,
                    ..Default::default()
                } as *const _,
            )?;
        }

        Ok(())
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        self.setup_cpuid()?;
        self.setup_msrs()?;
        self.setup_fpu()?;
        //self._setup_debug()?;
        self.setup_long_mode()?;

        Ok(())
    }

    pub fn set_gp_register(&mut self, gpr: GpRegister, v: u64) -> Result<(), std::io::Error> {
        let mut regs = self.get_regs()?;
        match gpr {
            GpRegister::Rax => regs.rax = v,
            GpRegister::Rcx => regs.rcx = v,
            GpRegister::Rdx => regs.rdx = v,
            GpRegister::Rbx => regs.rbx = v,
            GpRegister::Rsp => regs.rsp = v,
            GpRegister::Rbp => regs.rbp = v,
            GpRegister::Rsi => regs.rsi = v,
            GpRegister::Rdi => regs.rdi = v,
            GpRegister::R8 => regs.r8 = v,
            GpRegister::R9 => regs.r9 = v,
            GpRegister::R10 => regs.r10 = v,
            GpRegister::R11 => regs.r11 = v,
            GpRegister::R12 => regs.r12 = v,
            GpRegister::R13 => regs.r13 = v,
            GpRegister::R14 => regs.r14 = v,
            GpRegister::R15 => regs.r15 = v,
        }
        self.set_regs(&regs)?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<CpuExitReason, std::io::Error> {
        let run = &mut unsafe { std::slice::from_raw_parts_mut(self.vcpu_run, 1) }[0];

        unsafe { super::kvm_run(self.vcpu_fd, 0)? };

        let exit_reason = match run.exit_reason {
            KVM_EXIT_IO => unsafe {
                // Emulation through setting the ax register makes this code
                // being VERY slow. Fortunately, the kernel handles that
                // part of the emulation.
                let run_start = run as *mut kvm_run as *mut u8;
                let io = &run.__bindgen_anon_1.io;
                let port = io.port;
                let data_size = io.count as usize * io.size as usize;
                let data_ptr = run_start.offset(io.data_offset as isize);

                match u32::from(io.direction) {
                    KVM_EXIT_IO_IN => match data_size {
                        1 => CpuExitReason::Io(IoType::ByteIn(
                            port,
                            &mut std::slice::from_raw_parts_mut(data_ptr as *mut _, data_size)[0],
                        )),
                        2 => CpuExitReason::Io(IoType::WordIn(
                            port,
                            &mut std::slice::from_raw_parts_mut(data_ptr as *mut _, data_size)[0],
                        )),
                        _ => CpuExitReason::NotSupported,
                    },
                    KVM_EXIT_IO_OUT => match data_size {
                        1 => CpuExitReason::Io(IoType::ByteOut(
                            port,
                            std::slice::from_raw_parts(data_ptr as *const _, data_size)[0],
                        )),
                        2 => CpuExitReason::Io(IoType::WordOut(
                            port,
                            std::slice::from_raw_parts(data_ptr as *const _, data_size)[0],
                        )),
                        _ => CpuExitReason::NotSupported,
                    },
                    _ => CpuExitReason::NotSupported,
                }
            },
            KVM_EXIT_HLT => CpuExitReason::Halt,
            KVM_EXIT_MMIO => unsafe {
                let mmio = &mut run.__bindgen_anon_1.mmio;
                let _addr = mmio.phys_addr;
                let len = mmio.len as usize;
                let _data_slice = &mut mmio.data[..len];
                let _is_write = mmio.is_write != 0;

                CpuExitReason::NotSupported
            },
            _ => CpuExitReason::NotSupported,
        };

        if exit_reason == CpuExitReason::NotSupported {
            let regs = self.get_regs().unwrap_or_default();
            let sregs = self.get_sregs().unwrap_or_default();
            log::error!(
                "Exit {:#x}, registers {:x?}, system registers {:x?}",
                run.exit_reason,
                regs,
                sregs
            );
        }

        Ok(exit_reason)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        let mut regs = self.get_regs()?;
        regs.rip = ip;
        self.set_regs(&regs)?;

        Ok(())
    }

    pub fn _get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        let regs = self.get_regs()?;

        Ok(regs.rip)
    }
}
