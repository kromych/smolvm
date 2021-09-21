#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::{Cpu, CpuExit, HvError, Memory, SmolVm};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{Cpu, CpuExit, HvError, Memory, SmolVm};

#[derive(PartialEq)]
pub enum VmRunnable {
    No,
    Yes,
}

use object::{
    elf::FileHeader64,
    read::elf::{FileHeader, ProgramHeader},
    Architecture, Endianness, FileKind, Object, ObjectSection, SectionKind,
};
use std::sync::Arc;
use std::sync::Mutex;

pub fn create_vm(memory_size: usize) -> Result<SmolVm, HvError> {
    SmolVm::new(memory_size)
}

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
    // for decoded in bad64::disasm(bytes, ip).flatten() {
    //     log::info!("0x{:016x}    {:40}", decoded.address(), decoded);
    // }
}

pub trait SmolVmT {
    fn get_native_arch(&self) -> Architecture;
    fn get_memory(&self) -> Arc<Mutex<Memory>>;
    fn get_cpu(&self) -> Arc<Mutex<Cpu>>;
    fn handle_exit(&mut self, exit: &CpuExit) -> Result<VmRunnable, HvError>;
    fn load_elf(&mut self, elf_data: &[u8]) {
        log::info!("File size {} bytes", elf_data.len());

        let obj_file = object::File::parse(elf_data).unwrap();
        let obj_file_kind = object::FileKind::parse(elf_data).unwrap();

        log::info!("File kind {:?}", obj_file_kind);

        if obj_file_kind != FileKind::Elf64 {
            panic!("Only ELF64 files are supported");
        }

        let arch = obj_file.architecture();
        log::info!("Architecture {:?}", arch);

        if let Ok(elf) = FileHeader64::<Endianness>::parse(elf_data) {
            if let Ok(endian) = elf.endian() {
                if let Ok(segments) = elf.program_headers(endian, elf_data) {
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
    }

    fn load_bin(&mut self, bin_data: &[u8], load_addr: u64) {
        log::info!("Loading binary data at 0x{:x}", load_addr);

        if self.get_native_arch() == Architecture::X86_64 {
            disassemble_x86_64(bin_data, load_addr);
        } else if self.get_native_arch() == Architecture::Aarch64 {
            disassemble_aarch64(bin_data, load_addr);
        }

        let memory = self.get_memory();
        let mut memory = memory.lock().unwrap();
        let memory = memory.as_slice_mut();
        if bin_data.len() + load_addr as usize > memory.len() {
            panic!("Out of memory");
        }

        for i in 0..bin_data.len() {
            memory[load_addr as usize + i] = bin_data[i];
        }

        let cpu = self.get_cpu();
        let mut cpu = cpu.lock().unwrap();
        cpu.set_instruction_pointer(load_addr).unwrap();
    }

    fn run(&mut self) -> Result<(), HvError> {
        {
            let cpu = self.get_cpu();
            let mut cpu = cpu.lock().unwrap();

            log::info!(
                "Starting execution at 0x{:x}",
                cpu.get_instruction_pointer()?
            );
        }

        loop {
            let cpu = self.get_cpu();
            let mut cpu = cpu.lock().unwrap();

            let ip = cpu.get_instruction_pointer()?;
            log::info!("Exit at 0x{:x}", ip);

            let exit = cpu.run()?;

            let vm_runnable = self.handle_exit(&exit)?;
            if vm_runnable == VmRunnable::No {
                break;
            }
        }

        Ok(())
    }
}
