use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::Kvm;
use kvm_ioctls::VcpuFd;
use kvm_ioctls::VmFd;

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

pub struct SmolVm {
    kvm: Kvm,
    vm: VmFd,
    vcpu: VcpuFd,
    mem_region: kvm_userspace_memory_region,
    memory: *mut u8,
    memory_size: usize,
}

impl SmolVm {
    pub fn new(memory_size: usize) -> Result<Self, std::io::Error> {
        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;
        let vcpu = vm.create_vcpu(0)?;

        let memory = mmap_anonymous(memory_size);
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: 0,
            memory_size: memory_size as u64,
            userspace_addr: memory as u64,
            flags: 0,
        };
        unsafe {
            vm.set_user_memory_region(mem_region)?;
        }

        Ok(Self {
            kvm,
            vm,
            vcpu,
            mem_region,
            memory,
            memory_size,
        })
    }
}
