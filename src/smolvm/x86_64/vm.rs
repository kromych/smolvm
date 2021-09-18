use crate::x86_64::CR0_PE;
use crate::{
    boot_params::{
        BOOT_CODE_CS, BOOT_CODE_CS_GDT_INDEX, BOOT_CODE_DS, BOOT_CODE_LDT, BOOT_CODE_SS_GDT_INDEX,
        BOOT_CODE_TSS, BOOT_CODE_TSS_GDT_INDEX,
    },
    x86_64::{
        get_pfn, CodeSegmentType, DataSegmentType, PDFlags, PDPTFlags, PML4Flags, PTFlags,
        SystemDescriptorTypes64, PAGE_SHIFT,
    },
};
use kvm_bindings::{kvm_dtable, kvm_msr_entry, kvm_segment, kvm_userspace_memory_region, Msrs};
use kvm_ioctls::{Kvm, VcpuExit};
use libc::{c_void, memset};
use std::io::Write;
use x86_64::{
    CR0_PG, CR4_PAE, EFER_LMA, EFER_LME, EFER_NXE, EFER_SCE, MSR_CR_PAT, MSR_CR_PAT_DEFAULT,
};

fn get_x86_64_dtable_entry(kvm_entry: &kvm_segment) -> [u64; 2] {
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
            0
        },
    ]
}

fn x86_64bit_run_code(MEMORY_SIZE: usize) -> Result<(), std::io::Error> {
    const GDT_OFFSET: u64 = 0x2000;
    const TSS_OFFSET: u64 = 0x3000;
    const PML4T_OFFSET: u64 = 0x4000;
    const PDPT_OFFSET: u64 = 0x5000;
    const PDT_OFFSET: u64 = 0x6000;

    #[rustfmt::skip]
    let code = [
        0xf4, /* hlt */
    ];

    unsafe {
        // Get a mutable slice of `mem_size` from `load_addr`.
        // This is safe because we mapped it before.
        let mut slice = std::slice::from_raw_parts_mut(load_addr, MEMORY_SIZE);
        memset(load_addr as *mut c_void, 0x00, MEMORY_SIZE);

        slice.write_all(&code)?;
    }

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

        let cs_hw = get_x86_64_dtable_entry(&sregs.cs);
        let ss_hw = get_x86_64_dtable_entry(&sregs.ss);
        let tss_hw = get_x86_64_dtable_entry(&sregs.tr);

        let gdt = unsafe {
            std::slice::from_raw_parts_mut((load_addr as u64 + GDT_OFFSET) as *mut u64, 64)
        };

        gdt[BOOT_CODE_CS_GDT_INDEX as usize] = cs_hw[0];
        gdt[BOOT_CODE_SS_GDT_INDEX as usize] = ss_hw[0];
        gdt[BOOT_CODE_TSS_GDT_INDEX as usize] = tss_hw[0];
        gdt[(BOOT_CODE_TSS_GDT_INDEX + 1) as usize] = tss_hw[1];
    }

    // Set up page tables for identical mapping
    {
        let pml4t = unsafe {
            std::slice::from_raw_parts_mut((load_addr as u64 + PML4T_OFFSET) as *mut u64, 512)
        };
        let pdpt = unsafe {
            std::slice::from_raw_parts_mut((load_addr as u64 + PDPT_OFFSET) as *mut u64, 512)
        };
        let pdt = unsafe {
            std::slice::from_raw_parts_mut((load_addr as u64 + PDT_OFFSET) as *mut u64, 512)
        };

        pml4t[0] = PDPT_OFFSET | (PML4Flags::P | PML4Flags::RW).bits();
        pdpt[0] = PDT_OFFSET | (PDPTFlags::P | PDPTFlags::RW).bits();

        for large_page_index in 0..PAGE_SIZE / std::mem::size_of::<u64>() {
            pdt[large_page_index] = large_page_index * LARGE_PAGE_SIZE
                | (PDFlags::P | PDFlags::RW | PDFlags::PS).bits();
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
    vcpu_fd.set_msrs(&msrs).unwrap();

    let mut regs = vcpu_fd.get_regs()?;
    regs.rip = 0;
    regs.rax = 2;
    regs.rbx = 3;
    regs.rflags = 2;
    vcpu_fd.set_regs(&regs)?;

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::Hlt => {
                break;
            }
            // VcpuExit::Shutdown => {
            //     break;
            // }
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitflags::*;
    use kvm_ioctls::{Kvm, VcpuExit};
    use std::io::Write;

    #[test]
    /// Taken almost verbatim from the kvm-ioctl's unit tests
    fn test_x86_16bit_run_code() -> Result<(), std::io::Error> {
        use kvm_bindings::{
            kvm_guest_debug, kvm_guest_debug_arch, kvm_userspace_memory_region,
            KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_MEM_LOG_DIRTY_PAGES,
        };

        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;

        // This example is based on https://lwn.net/Articles/658511/
        #[rustfmt::skip]
            let code = [
                0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
                0x00, 0xd8, /* add %bl, %al */
                0x04, b'0', /* add $'0', %al */
                0xee, /* out %al, %dx */
                0xec, /* in %dx, %al */
                0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
                0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
                0xc6, 0x06, 0x00, 0x20, 0x00, /* movl $0, (0x2000); Dirty one page in guest mem. */
                0xf4, /* hlt */
            ];
        let expected_rips: [u64; 3] = [0x1003, 0x1005, 0x1007];

        let mem_size = 0x4000;
        let load_addr = crate::mmap_anonymous(mem_size);
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            vm.set_user_memory_region(mem_region)?;
        }

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write_all(&code)?;
        }

        let vcpu_fd = vm.create_vcpu(0)?;

        let mut vcpu_sregs = vcpu_fd.get_sregs()?;
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs)?;

        let mut vcpu_regs = vcpu_fd.get_regs()?;
        // Set the Instruction Pointer to the guest address where we loaded the code.
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd.set_regs(&vcpu_regs)?;

        let mut debug_struct = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP,
            pad: 0,
            arch: kvm_guest_debug_arch {
                debugreg: [0, 0, 0, 0, 0, 0, 0, 0],
            },
        };
        vcpu_fd.set_guest_debug(&debug_struct)?;

        let mut instr_idx = 0;
        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::IoOut(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], b'5');
                }
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], 0);
                }
                VcpuExit::Debug(debug) => {
                    if instr_idx == expected_rips.len() - 1 {
                        // Disabling debugging/single-stepping
                        debug_struct.control = 0;
                        vcpu_fd.set_guest_debug(&debug_struct)?;
                    } else if instr_idx >= expected_rips.len() {
                        unreachable!();
                    }
                    let vcpu_regs = vcpu_fd.get_regs()?;
                    assert_eq!(vcpu_regs.rip, expected_rips[instr_idx]);
                    assert_eq!(debug.exception, 1);
                    assert_eq!(debug.pc, expected_rips[instr_idx]);
                    // Check first 15 bits of DR6
                    let mask = (1 << 16) - 1;
                    assert_eq!(debug.dr6 & mask, 0b100111111110000);
                    // Bit 10 in DR7 is always 1
                    assert_eq!(debug.dr7, 1 << 10);
                    instr_idx += 1;
                }
                VcpuExit::Hlt => {
                    // The code snippet dirties 2 pages:
                    // * one when the code itself is loaded in memory;
                    // * and one more from the `movl` that writes to address 0x8000
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size)?;
                    let dirty_pages: u32 = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .sum();
                    assert_eq!(dirty_pages, 2);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }

        Ok(())
    }
}
