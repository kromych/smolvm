use crate::smolvm::Vm;
use std::fs;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

mod smolvm;

fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let kernel_path = "./kernels/linux-5.14-stable/x86_64/vmlinux";
    //"./kernels/linux-5.14-stable/aarch64/vmlinux";
    log::info!("Opening {}", kernel_path);

    let file = fs::File::open(&kernel_path)?;
    let file = unsafe { memmap2::Mmap::map(&file)? };

    let mut vm = Vm::new(64 * 1024 * 1024)?;
    vm.load_elf(&*file);
    vm.run()?;

    Ok(())
}
