#[cfg(test)]
mod tests {
    use bitflags::*;
    use kvm_ioctls::{Kvm, VcpuExit};
    use std::io::Write;

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
}
