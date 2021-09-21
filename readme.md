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
