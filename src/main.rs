use object::{
    elf::FileHeader64,
    read::elf::{FileHeader, ProgramHeader},
    Architecture, Endianness, FileKind, Object, ObjectSection, SectionKind,
};

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

use std::fs;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

#[cfg(target_arch = "x86_64")]
mod x86_64;

mod boot_params;

fn disassemble_x86_64(bytes: &[u8], ip: u64) {
    use iced_x86::Formatter;

    let mut decoder = iced_x86::Decoder::with_ip(64, bytes, ip, iced_x86::DecoderOptions::NONE);
    let mut formatter = iced_x86::GasFormatter::new();

    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);
    formatter.options_mut().set_leading_zeros(true);

    let mut output = String::new();
    let mut instruction = iced_x86::Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        if instruction.is_invalid() {
            continue;
        }

        output.clear();
        formatter.format(&instruction, &mut output);

        let start_index = (instruction.ip() - ip) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];

        log::info!(
            "0x{:016x} {:40} # {:02x?}",
            instruction.ip(),
            output,
            instr_bytes
        );
    }
}

fn disassemble_aarch64(bytes: &[u8], ip: u64) {
    for maybe_decoded in bad64::disasm(bytes, ip) {
        if let Ok(decoded) = maybe_decoded {
            log::info!("0x{:016x}    {:40}", decoded.address(), decoded);
        }
    }
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

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
fn x86_64bit_run_code() -> Result<(), std::io::Error> {
    const MEMORY_SIZE: usize = 0x8000;

    const GDT_OFFSET: u64 = 0x2000;
    const TSS_OFFSET: u64 = 0x3000;
    const PML4T_OFFSET: u64 = 0x4000;
    const PDPT_OFFSET: u64 = 0x5000;
    const PDT_OFFSET: u64 = 0x6000;

    let kvm = Kvm::new()?;
    let vm = kvm.create_vm()?;

    #[rustfmt::skip]
    let code = [
        0xf4, /* hlt */
    ];

    let load_addr = crate::mmap_anonymous(MEMORY_SIZE);
    let slot: u32 = 0;
    let mem_region = kvm_userspace_memory_region {
        slot,
        guest_phys_addr: 0,
        memory_size: MEMORY_SIZE as u64,
        userspace_addr: load_addr as u64,
        flags: 0,
    };
    unsafe {
        vm.set_user_memory_region(mem_region)?;
    }

    unsafe {
        // Get a mutable slice of `mem_size` from `load_addr`.
        // This is safe because we mapped it before.
        let mut slice = std::slice::from_raw_parts_mut(load_addr, MEMORY_SIZE);
        memset(load_addr as *mut c_void, 0x00, MEMORY_SIZE);

        slice.write_all(&code)?;
    }

    let vcpu_fd = vm.create_vcpu(0)?;

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
        pdt[0] = 0 | (PDFlags::P | PDFlags::RW | PDFlags::PS).bits();

        // Don't need to map the paging tables unless they need to be modified
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

fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let kernel_path = "./kernels/linux-5.14-stable/x86_64/vmlinux";
    //"./kernels/linux-5.14-stable/aarch64/vmlinux";
    log::info!("Loading {}", kernel_path);

    let file = fs::File::open(&kernel_path)?;
    let file = unsafe { memmap2::Mmap::map(&file)? };

    let bin_data = &*file;
    log::info!("File size {} bytes", bin_data.len());

    let obj_file = object::File::parse(bin_data).unwrap();
    let obj_file_kind = object::FileKind::parse(bin_data).unwrap();

    log::info!("File kind {:?}", obj_file_kind);

    if obj_file_kind != FileKind::Elf64 {
        panic!("Only ELF64 files are supported");
    }

    let arch = obj_file.architecture();
    log::info!("Architecture {:?}", arch);

    if let Ok(elf) = FileHeader64::<Endianness>::parse(bin_data) {
        if let Ok(endian) = elf.endian() {
            if let Ok(segments) = elf.program_headers(endian, bin_data) {
                for (index, segment) in segments.iter().enumerate() {
                    let offset = segment.p_offset(endian);
                    let virt_addr = segment.p_vaddr(endian);
                    let phys_addr = segment.p_paddr(endian);
                    let file_size = segment.p_filesz(endian);
                    let memory_size = segment.p_memsz(endian);
                    let align = segment.p_align(endian);

                    log::info!(
                        "Segment #{}: offset 0x{:x}, virt.address 0x{:x}, phys.addr 0x{:x}, file size 0x{:x}, memory size 0x{:x}, align 0x{:x}",
                            index,
                            offset,
                            virt_addr,
                            phys_addr,
                            file_size,
                            memory_size,
                            align
                        );
                }
            }
        }
    }

    for section in obj_file.sections() {
        let name = section.name().unwrap_or_default();
        let address = section.address();
        let align = section.align();
        let kind = section.kind();
        let size = section.size();
        let reloc_count = section.relocations().count();

        log::info!(
            "Section {}, size 0x{:x}, address 0x{:x}, align 0x{:x}, kind {:?}, relocations {}",
            name,
            size,
            address,
            align,
            kind,
            reloc_count
        );

        let file_range = section.file_range();
        if let Some((offset, size_in_file)) = file_range {
            log::info!(
                "Offset 0x{:x}, size inside the file 0x{:x} bytes",
                offset,
                size_in_file
            );

            if kind == SectionKind::Text {
                let code_bytes = section.data_range(address, 32).unwrap_or_default();

                if let Some(code_bytes) = code_bytes {
                    if arch == Architecture::X86_64 {
                        disassemble_x86_64(code_bytes, address);
                    } else if arch == Architecture::Aarch64 {
                        disassemble_aarch64(code_bytes, address);
                    }
                }
            }
        }
    }

    let entry = obj_file.entry();
    log::info!("Entry point 0x{:x}", entry);

    // At the 64-bit entry, the Linux kernel expects
    // %rsi point at the boot_param structure, and the
    // segment selectors and descriptors prepared:
    // ES =0000 0000000000000000 00000000 00000000
    // CS =0010 0000000000000000 ffffffff 00af9b00 DPL=0 CS64 [-RA]
    // SS =0018 0000000000000000 ffffffff 00cf9300 DPL=0 DS   [-WA]
    // DS =0000 0000000000000000 00000000 00000000
    // FS =0000 0000000000000000 00000000 00000000
    // GS =0000 0000000000000000 00000000 00000000
    // LDT=0000 0000000000000000 00000000 00008200 DPL=0 LDT
    // TR =0040 fffff??????????? 00000067 00008900 DPL=0 TSS64-avl

    // if arch != Architecture::X86_64 {
    //     panic!("Unsupported architecture");
    // }

    x86_64bit_run_code()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitflags::*;
    use kvm_ioctls::{Kvm, VcpuExit};
    use std::io::Write;

    #[cfg(target_arch = "aarch64")]
    #[test]
    /// Taken almost verbatim from the kvm-ioctl's unit tests
    fn test_arm64_run_code() -> Result<(), std::io::Error> {
        use kvm_bindings::{
            kvm_userspace_memory_region, KVM_ARM_VCPU_PSCI_0_2, KVM_MEM_LOG_DIRTY_PAGES,
            KVM_SYSTEM_EVENT_SHUTDOWN,
        };

        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;
        #[rustfmt::skip]
        let code = [
            0x40, 0x20, 0x80, 0x52, /* mov w0, #0x102 */
            0x00, 0x01, 0x00, 0xb9, /* str w0, [x8]; test physical memory write */
            0x81, 0x60, 0x80, 0x52, /* mov w1, #0x304 */
            0x02, 0x00, 0x80, 0x52, /* mov w2, #0x0 */
            0x20, 0x01, 0x40, 0xb9, /* ldr w0, [x9]; test MMIO read */
            0x1f, 0x18, 0x14, 0x71, /* cmp w0, #0x506 */
            0x20, 0x00, 0x82, 0x1a, /* csel w0, w1, w2, eq */
            0x20, 0x01, 0x00, 0xb9, /* str w0, [x9]; test MMIO write */
            0x00, 0x80, 0xb0, 0x52, /* mov w0, #0x84000000 */
            0x00, 0x00, 0x1d, 0x32, /* orr w0, w0, #0x08 */
            0x02, 0x00, 0x00, 0xd4, /* hvc #0x0 */
            0x00, 0x00, 0x00, 0x14, /* b <this address>; shouldn't get here, but if so loop forever */
        ];

        let mem_size = 0x20000;
        let load_addr = mmap_anonymous(mem_size);
        let guest_addr: u64 = 0x10000;
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
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi)?;
        kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
        vcpu_fd.vcpu_init(&kvi)?;

        let core_reg_base: u64 = 0x6030_0000_0010_0000;
        let mmio_addr: u64 = guest_addr + mem_size as u64;

        // Set the PC to the guest address where we loaded the code.
        vcpu_fd.set_one_reg(core_reg_base + 2 * 32, guest_addr)?;

        // Set x8 and x9 to the addresses the guest test code needs
        vcpu_fd.set_one_reg(core_reg_base + 2 * 8, guest_addr + 0x10000)?;
        vcpu_fd.set_one_reg(core_reg_base + 2 * 9, mmio_addr)?;

        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, mmio_addr);
                    assert_eq!(data.len(), 4);
                    data[3] = 0x0;
                    data[2] = 0x0;
                    data[1] = 0x5;
                    data[0] = 0x6;
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, mmio_addr);
                    assert_eq!(data.len(), 4);
                    assert_eq!(data[3], 0x0);
                    assert_eq!(data[2], 0x0);
                    assert_eq!(data[1], 0x3);
                    assert_eq!(data[0], 0x4);
                    // The code snippet dirties one page at guest_addr + 0x10000.
                    // The code page should not be dirty, as it's not written by the guest.
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size)?;
                    let dirty_pages: u32 = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .sum();
                    assert_eq!(dirty_pages, 1);
                }
                VcpuExit::SystemEvent(type_, flags) => {
                    assert_eq!(type_, KVM_SYSTEM_EVENT_SHUTDOWN);
                    assert_eq!(flags, 0);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
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
