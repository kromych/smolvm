use std::fs;

use smolvm::{HvError, SmolVmT};

use crate::smolvm::GpaSpan;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

mod smolvm;

fn main() -> Result<(), HvError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = std::env::args().collect::<Vec<_>>();

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

    #[cfg(target_arch = "x86_64")]
    let gpa_start = 0;
    #[cfg(target_arch = "aarch64")]
    let gpa_start = 0x1_000_0000;

    let mut vm = smolvm::create_vm(&[GpaSpan {
        start: gpa_start,
        size: 64 * 1024 * 1024,
    }])?;
    vm.load_kernel_elf(&*file);
    vm.run()?;

    Ok(())
}

fn run_until_halt() -> Result<(), HvError> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut vm = smolvm::create_vm(&[GpaSpan {
            start: 0,
            size: 64 * 1024 * 1024,
        }])?;
        vm.load_bin(&[0x90, 0x90, 0xf4], 0x10000);
        vm.run_once().map(|_| ())?
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut vm = smolvm::create_vm(&[GpaSpan {
            start: 0x80_000_000,
            size: 64 * 1024 * 1024,
        }])?;
        vm.load_bin(
            &[
                0x01, 0x00, 0x00, 0x10, /* adr x1, <this address> */
                0x22, 0x10, 0x00, 0xb9, /* str w2, [x1, #16]; write to this page */
                0x02, 0x00, 0x00, 0xb9, /* str w2, [x0]; This generates a MMIO Write.*/
                // 0x00, 0x80, 0xb0, 0x52, /* mov w0, #0x84000000 */
                // 0x00, 0x00, 0x1d, 0x32, /* orr w0, w0, #0x08 */
                // 0x02, 0x00, 0x00, 0xd4, /* hvc #0x0 */
                0x00, 0x00, 0x00, 0x14, /* b <this address> */
            ],
            0x80_000_000,
        );
        vm.run_once().map(|_| ())?
    }

    Ok(())
}
