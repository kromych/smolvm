use std::fs;

use smolvm::HvError;
use smolvm::SmolVmT;

use crate::smolvm::GpaSpan;
use clap::Parser;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

mod smolvm;

#[derive(Parser)]
struct Args {
    /// Path to the ELF binary (Linux kernel perhaps)
    kernel_path: Option<String>,
    /// Kernel command line
    kernel_cmd_line: Option<String>,
    /// Path to the Device Tree Blob
    dtb_path: Option<String>,
    /// Sets the level of debugging information
    log_level: Option<String>,
}

fn main() -> Result<(), HvError> {
    let args = Args::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        if let Some(level) = args.log_level {
            level
        } else {
            "info".to_string()
        },
    ))
    .init();

    if let Some(kernel_path) = args.kernel_path {
        log::info!("Kernel path {}", kernel_path);

        let command_line = args.kernel_cmd_line;
        let dtb_path = args.dtb_path;

        run_kernel(kernel_path, command_line, dtb_path)?;
    } else {
        log::info!("Path to the kernel was not specified, running a smol test");
        run_until_halt()?;
    }

    Ok(())
}

fn run_kernel(
    kernel_path: String,
    command_line: Option<String>,
    dtb_path: Option<String>,
) -> Result<(), HvError> {
    log::info!("Opening {}", kernel_path);

    let file = fs::File::open(&kernel_path).unwrap();
    let file = unsafe { memmap2::Mmap::map(&file).unwrap() };

    #[cfg(target_arch = "x86_64")]
    let gpa_start = 0;
    #[cfg(target_arch = "aarch64")]
    let gpa_start = 0x4000_0000;

    let mut vm = smolvm::create_vm(&[GpaSpan {
        start: gpa_start,
        size: 512 * 1024 * 1024,
    }])?;
    vm.load_kernel_elf(&file, command_line, dtb_path);
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
            start: 0x1000_0000,
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
            0x1000_0000,
        );
        vm.run_once().map(|_| ())?
    }

    Ok(())
}
