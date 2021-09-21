use smolvm::{HvError, SmolVmT};
use std::fs;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

mod smolvm;

fn main() -> Result<(), HvError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 {
        run_kernel(&args[1])?
    } else {
        run_until_halt()?
    }

    Ok(())
}

fn run_kernel(kernel_path: &str) -> Result<(), HvError> {
    log::info!("Opening {}", kernel_path);

    let file = fs::File::open(&kernel_path).unwrap();
    let file = unsafe { memmap2::Mmap::map(&file).unwrap() };

    let mut vm = smolvm::create_vm(64 * 1024 * 1024)?;
    vm.load_elf(&*file);
    vm.run()?;

    Ok(())
}

fn run_until_halt() -> Result<(), HvError> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut vm = smolvm::create_vm(64 * 1024 * 1024)?;
        vm.load_bin(&[0x90, 0x90, 0xf4], 0x10000);
        vm.run()?
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut vm = smolvm::create_vm(64 * 1024 * 1024)?;
        vm.load_bin(
            &[
                0x40, 0x00, 0x80, 0xD2, // mov x0, #2
                0x02, 0x00, 0x00, 0xD4, // hvc #0
                0x00, 0x00, 0x00, 0x14, /* b <this address> */
            ],
            0x20000,
        );
        vm.run()?
    }

    Ok(())
}
