use object::{
    elf::FileHeader64,
    read::elf::{FileHeader, ProgramHeader},
    Architecture, Endianness, FileKind, Object, ObjectSection, SectionKind,
};

use crate::smolvm::SmolVm;
use std::fs;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

mod smolvm;

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

    let vm = SmolVm::new(64 * 1024 * 1024)?;

    Ok(())
}
