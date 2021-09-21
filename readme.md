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
