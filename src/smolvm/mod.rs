use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
use kvm_ioctls::VcpuFd;
use kvm_ioctls::VmFd;

use self::x86_64::CpuX86_64;
use object::{
    elf::FileHeader64,
    read::elf::{FileHeader, ProgramHeader},
    Architecture, Endianness, FileKind, Object, ObjectSection, SectionKind,
};
use std::ops::Deref;
use std::ops::DerefMut;

#[cfg(target_arch = "x86_64")]
mod x86_64;

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

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.memory, self.memory_size) }
    }

    pub fn as_slice_mut(&mut self) -> &[u8] {
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

pub trait VirtualCpu {
    fn new(vm_fd: &VmFd, memory: &mut Memory) -> Result<Self, std::io::Error>
    where
        Self: Sized;
    fn map(pfn: u64, virt_addr: u64);
    fn run() -> Result<(), std::io::Error>;
}

pub struct _Vm<Cpu: VirtualCpu> {
    kvm_fd: Kvm,
    vm_fd: VmFd,
    cpu: Cpu,
    memory: Memory,
}

impl<Cpu: VirtualCpu> _Vm<Cpu> {
    pub fn new(memory_size: usize) -> Result<Self, std::io::Error> {
        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm()?;
        let mut memory = Memory::new(memory_size)?;
        let cpu = Cpu::new(&vm_fd, &mut memory)?;

        unsafe {
            vm_fd.set_user_memory_region(kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: memory_size as u64,
                userspace_addr: memory.start_addr() as u64,
                flags: 0,
            })?;
        }

        Ok(Self {
            kvm_fd,
            vm_fd,
            cpu,
            memory,
        })
    }

    pub fn load_elf(&mut self, bin_data: &[u8]) {
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
    }

    pub fn run(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

pub struct Vm(_Vm<CpuX86_64>);

impl Vm {
    pub fn new(memory_size: usize) -> Result<Self, std::io::Error> {
        Ok(Self(_Vm::new(memory_size)?))
    }
}

impl Deref for Vm {
    type Target = _Vm<CpuX86_64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Vm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
