use kvm_bindings::{kvm_userspace_memory_region, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::{Kvm, VcpuExit, VmFd};
use object::{
    elf::FileHeader64,
    read::elf::{FileHeader, ProgramHeader},
    Architecture, Endianness, FileKind, Object, ObjectSection, SectionKind,
};
use std::sync::Arc;
use std::sync::Mutex;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use self::x86_64::CpuX86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use self::aarch64::CpuAarch64;

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
    for decoded in bad64::disasm(bytes, ip).flatten() {
        log::info!("0x{:016x}    {:40}", decoded.address(), decoded);
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

pub trait VirtualCpu {
    fn new(vm_fd: &VmFd, memory: Arc<Mutex<Memory>>) -> Result<Self, std::io::Error>
    where
        Self: Sized;
    fn init(&self) -> Result<(), std::io::Error>;
    fn map(&self, pfn: u64, virt_addr: u64);
    fn set_instruction_pointer(&self, ip: u64) -> Result<(), std::io::Error>;
    fn get_instruction_pointer(&self) -> Result<u64, std::io::Error>;
    fn run(&self) -> Result<VcpuExit, std::io::Error>;
}

pub struct Vm<Cpu: VirtualCpu> {
    native_arch: Architecture,
    cpu: Cpu,
    memory: Arc<Mutex<Memory>>,
}

impl<Cpu: VirtualCpu> Vm<Cpu> {
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

        let cpu = Cpu::new(&vm_fd, memory.clone())?;
        cpu.init()?;

        Ok(Self {
            native_arch,
            cpu,
            memory,
        })
    }

    pub fn load_elf(&mut self, elf_data: &[u8]) {
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

    pub fn load_bin(&mut self, bin_data: &[u8], load_addr: u64) {
        log::info!("Loading binary data at 0x{:x}", load_addr);

        if self.native_arch == Architecture::X86_64 {
            disassemble_x86_64(bin_data, load_addr);
        } else if self.native_arch == Architecture::Aarch64 {
            disassemble_aarch64(bin_data, load_addr);
        }

        let mut memory = self.memory.lock().unwrap();
        let memory = &mut memory.as_slice_mut();
        if bin_data.len() + load_addr as usize > memory.len() {
            panic!("Out of memory");
        }

        for i in 0..bin_data.len() {
            memory[load_addr as usize + i] = bin_data[i];
        }
    }

    pub fn run(&mut self, ip: u64) -> Result<(), std::io::Error> {
        self.cpu.set_instruction_pointer(ip)?;

        log::info!("Starting execution at 0x{:x}", ip);

        loop {
            match self.cpu.run()? {
                VcpuExit::Hlt => {
                    log::info!(
                        "Execution halted at 0x{:x}",
                        self.cpu.get_instruction_pointer()?
                    );
                    break;
                }
                VcpuExit::SystemEvent(KVM_SYSTEM_EVENT_SHUTDOWN, 0) => {
                    log::info!(
                        "Execution halted at 0x{:x}",
                        self.cpu.get_instruction_pointer()?
                    );
                    break;
                }
                e => panic!("Unsupported Vcpu Exit {:?}", e),
            }
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
pub fn create_vm(memory_size: usize) -> Result<Vm<CpuAarch64>, std::io::Error> {
    Vm::new(memory_size)
}

#[cfg(target_arch = "x86_64")]
pub fn create_vm(memory_size: usize) -> Result<Vm<CpuX86_64>, std::io::Error> {
    Vm::new(memory_size)
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_halt() {
        let mut vm = super::create_vm(64 * 1024 * 1024).unwrap();
        vm.load_bin(&[0x90, 0x90, 0xf4], 0x10000);
        vm.run(0x10000).unwrap();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_halt() {
        let mut vm = super::create_vm(64 * 1024 * 1024).unwrap();
        vm.load_bin(&[0x02, 0x00, 0x00, 0xd4 /* hvc #0x0 */], 0x10000);
        vm.run(0x10000).unwrap();
    }
}
