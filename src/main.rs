#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("Unsupported target architecture");

use kvm_ioctls::{Kvm, VcpuExit};
use std::io::Write;

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

#[cfg(target_arch = "aarch64")]
/// Taken almost verbatim from the kvm-ioctl's unit tests
fn test_run_code() -> Result<(), std::io::Error> {
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
/// Taken almost verbatim from the kvm-ioctl's unit tests
fn test_run_code() -> Result<(), std::io::Error> {
    use kvm_bindings::{
        kvm_guest_debug, kvm_guest_debug_arch, kvm_userspace_memory_region, KVM_GUESTDBG_ENABLE,
        KVM_GUESTDBG_SINGLESTEP, KVM_MEM_LOG_DIRTY_PAGES,
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
    let load_addr = mmap_anonymous(mem_size);
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

fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    test_run_code()?;
    Ok(())
}
