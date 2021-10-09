## Rust KVM Example

Adding `rustc` targets

```bash
$ rustup add target aarch64-unknown-linux-musl
$ cargo install cross
```

Installing required packages on Fedora
```bash
$ sudo snd install binutils-aarch64-linux-gnu
$ sudo snd install gcc-aarch64-linux-gnu
$ sudo snd install gcc-c++-aarch64-linux-gnu
$ sudo snd install musl-gcc
```

To build (add `--release` for the release build):
```bash
$ cargo build --target aarch64-unknown-linux-musl
```

To give the Hypervsior entitlement on Mac OS with a
self-signed certificate:
```
codesign -s - --entitlements ./app.entitlements --force 
```

The project depends on the `bad64` arm64 disassembler which requires
an arm64 C cross-compiler. To cross-compile for arm64, I used
the Linaro toolchain and set the environment variable:
```bash
export CC_aarch64_unknown_linux_musl=/opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc
```

For a reason unknown to me, cross-compiling on Fedora 34 also required the
glibc-devel-2.33-20.fc34.i686 (i.e. 32bit x86 glibc library) as the compiler
needed the `stubs-32.h` hedader (???).

To run the kernels with `qemu`:
```bash
# Linux kernel, x86_64
qemu-system-aarch64 -kernel kernels/linux-5.14-stable/x86_64/vmlinux -machine virt -nographic -accel kvm -cpu host

# MacOS, Apple Silicon
qemu-system-aarch64 -kernel kernels/linux-5.14-stable/aarch64/Image -machine virt,highmem=off -nographic -accel hvf -cpu host

# Linux kernel, aarch64
qemu-system-aarch64 -kernel kernels/linux-5.14-stable/aarch64/Image -machine virt,highmem=off -nographic -accel kvm -cpu host

```

For tracing, add `--trace "*"` options to the command-line
To dump the device tree block, append `,dumpdtb=out-file-name` to the machine model.
To convert the binary dtb file to a text form: `dtc -I dtb -O dts -o text.dts bin.dtb`

The aarch64 `smolkernel` run under `qemu` reports for select EL1 system registers:
```
PL011 ID 0x111014000df005b10
VBAR_EL1    0x0000000000000000
MIDR_EL1    0x00000000410fd034
MPIDR_EL1   0x0000000080000000
MDSCR_EL1   0x0000000000000000
SCTLR_EL1   0x0000000030d50998
SPSR_EL1    0x0000000000000000
TCR_EL1     0x0000000000000000
TTBR0_EL1   0x0000000000000000
TTBR1_EL1   0x0000000000000000
ESR_EL1     0x0000000000000000
ELR_EL1     0x0000000000000000
MAIR_EL1    0x0000000000000000
CPACR_EL1   0x0000000000000000
DAIF        0x00000000000003c0
```
