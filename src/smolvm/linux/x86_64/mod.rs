#![cfg(target_arch = "x86_64")]

mod boot_params;
mod cpu;

pub use boot_params::*;
pub use cpu::*;

use super::Memory;
use crate::smolvm::CpuExitReason;
use kvm_bindings::{kvm_dtable, kvm_msr_entry, kvm_segment, Msrs};
use kvm_ioctls::{VcpuExit, VcpuFd};
use raw_cpuid::CpuId;
use std::sync::{Arc, Mutex};
use zerocopy::AsBytes;

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
    vcpu_fd: VcpuFd,
    memory: Arc<Mutex<Memory>>,
}

impl Cpu {
    pub fn new(
        kvm_fd: &kvm_ioctls::Kvm,
        vm_fd: &kvm_ioctls::VmFd,
        memory: Arc<Mutex<Memory>>,
    ) -> Result<Self, std::io::Error> {
        let host_cpu_id = CpuId::new();
        log::trace!("Host CPU: {:#x?}", host_cpu_id);

        let vcpu_fd = vm_fd.create_vcpu(0)?;

        // Inspect the default CPUID data
        //let guest_cpu_id = vcpu_fd.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?.as_slice();

        // Set all supported CPUID features, no filtering.
        // Without that, the kernel would fail to set MSRs, etc as support for that
        // is communicated through CPUID
        let cpu_id = kvm_fd.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
        vcpu_fd.set_cpuid2(&cpu_id)?;

        Ok(Self { vcpu_fd, memory })
    }

    pub fn init(&mut self) -> Result<(), std::io::Error> {
        const STACK_TOP_OFFSET: u64 = 0x3fff0;
        const GDT_OFFSET: u64 = 0x4000;
        const TSS_OFFSET: u64 = 0x5000;
        const PML4T_OFFSET: u64 = 0x6000;
        const PDPT_OFFSET: u64 = 0x7000;
        const PDT_OFFSET: u64 = 0x8000;

        let vcpu_fd = &self.vcpu_fd;
        let mut memory = self.memory.lock().unwrap();

        let mut sregs = vcpu_fd.get_sregs()?;

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

        vcpu_fd.set_sregs(&sregs)?;

        let msrs = Msrs::from_entries(&[kvm_msr_entry {
            index: MSR_CR_PAT,
            data: MSR_CR_PAT_DEFAULT,
            ..Default::default()
        }])
        .unwrap();
        vcpu_fd.set_msrs(&msrs)?;

        let mut regs = vcpu_fd.get_regs()?;
        regs.rsp = STACK_TOP_OFFSET;
        regs.rbp = STACK_TOP_OFFSET;
        regs.rflags = 2;
        vcpu_fd.set_regs(&regs)?;

        vcpu_fd.set_fpu(&kvm_bindings::kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        })?;

        // Single-step the guest
        // vcpu_fd.set_guest_debug(&kvm_bindings::kvm_guest_debug {
        //     control: kvm_bindings::KVM_GUESTDBG_ENABLE | kvm_bindings::KVM_GUESTDBG_SINGLESTEP,
        //     ..Default::default()
        // })?;

        Ok(())
    }

    pub fn run(
        &mut self,
        prev_exit_reason: &CpuExitReason,
    ) -> Result<CpuExitReason, std::io::Error> {
        match prev_exit_reason {
            CpuExitReason::IoByteIn(_, byte) => {
                let mut regs = self.vcpu_fd.get_regs()?;
                regs.rax = ((regs.rax >> 8) << 8) | *byte as u64;
                self.vcpu_fd.set_regs(&regs)?;
            }
            CpuExitReason::IoWordIn(_, word) => {
                let mut regs = self.vcpu_fd.get_regs()?;
                regs.rax = ((regs.rax >> 16) << 16) | *word as u64;
                self.vcpu_fd.set_regs(&regs)?;
            }
            _ => {}
        };

        let exit = self.vcpu_fd.run()?;

        let exit_reason = match &exit {
            VcpuExit::Hlt => CpuExitReason::Halt,
            VcpuExit::IoIn(port, data) => {
                if data.len() == 1 {
                    CpuExitReason::IoByteIn(*port, data[0])
                } else if data.len() == 2 {
                    CpuExitReason::IoWordIn(*port, data[0] as u16 | (data[1] as u16) << 8)
                } else {
                    CpuExitReason::NotSupported
                }
            }
            VcpuExit::IoOut(port, data) => {
                if data.len() == 1 {
                    CpuExitReason::IoByteOut(*port, data[0])
                } else if data.len() == 2 {
                    CpuExitReason::IoWordOut(*port, data[0] as u16 | (data[1] as u16) << 8)
                } else {
                    CpuExitReason::NotSupported
                }
            }
            _ => CpuExitReason::NotSupported,
        };

        if exit_reason == CpuExitReason::NotSupported {
            let regs = self.vcpu_fd.get_regs().unwrap_or_default();
            let sregs = self.vcpu_fd.get_sregs().unwrap_or_default();
            log::error!(
                "Exit {:#x?}, registers {:x?}, system registers {:x?}",
                exit,
                regs,
                sregs
            );
        }

        Ok(exit_reason)
    }

    pub fn set_instruction_pointer(&mut self, ip: u64) -> Result<(), std::io::Error> {
        let mut regs = self.vcpu_fd.get_regs()?;
        regs.rip = ip;
        self.vcpu_fd.set_regs(&regs)?;

        Ok(())
    }

    pub fn _get_instruction_pointer(&mut self) -> Result<u64, std::io::Error> {
        let regs = self.vcpu_fd.get_regs()?;

        Ok(regs.rip)
    }
}
