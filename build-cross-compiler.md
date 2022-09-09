Crosstools-NG: https://crosstool-ng.github.io/docs/os-setup/

```bash
git clone https://github.com/crosstool-ng/crosstool-ng.git
```

To build `crosstool-ng` on Mac OS X

```bash
brew install autoconf automake bash binutils gawk gmp gnu-sed help2man mpfr openssl pcre readline wget xz
brew install libtool ncurses

export PATH="/opt/homebrew/opt/ncurses/bin:/opt/homebrew/opt/binutils/bin/:/opt/homebrew/bin:$PATH"
export LDFLAGS="-L/opt/homebrew/opt/ncurses/lib"
export CPPFLAGS="-I/opt/homebrew/opt/ncurses/include"

cd crosstools-ng
./bootstrap
./configure --prefix=/Volumes/ct-ng/ct-ng
make
make install
```

To see the available samples and select an option:
```bash
ct-ng list-samples
ct-ng <a-sample>
```

To build a cross-toolchain:

```bash
export PATH="/opt/homebrew/bin:/Volumes/ct-ng/ct-ng/bin:$PATH"
ct-ng menuconfig
ct-ng build
```

Patches for GCC:

```diff
diff -ru a/gcc/config/host-darwin.c b/gcc/config/host-darwin.c
--- a/gcc/config/host-darwin.c	2021-04-08 13:56:28.000000000 +0200
+++ b/gcc/config/host-darwin.c	2021-04-20 23:05:04.000000000 +0200
@@ -22,6 +22,8 @@
 #include "coretypes.h"
 #include "diagnostic-core.h"
 #include "config/host-darwin.h"
+#include "hosthooks.h"
+#include "hosthooks-def.h"
 
 /* Yes, this is really supposed to work.  */
 /* This allows for a pagesize of 16384, which we have on Darwin20, but should
@@ -78,3 +80,5 @@
 
   return ret;
 }
+
+const struct host_hooks host_hooks = HOST_HOOKS_INITIALIZER;
```

For TARGET=aarch64-linux-musl support for {march,cpu,tune}=native has to be disabled:

```diff
diff -ru a/gcc/config/aarch64/aarch64.h b/gcc/config/aarch64/aarch64.h
--- a/gcc/config/aarch64/aarch64.h	2021-04-08 13:56:28.000000000 +0200
+++ b/gcc/config/aarch64/aarch64.h	2021-04-20 22:41:03.000000000 +0200
@@ -1200,7 +1200,7 @@
 #define MCPU_TO_MARCH_SPEC_FUNCTIONS \
   { "rewrite_mcpu", aarch64_rewrite_mcpu },
 
-#if defined(__aarch64__)
+#if defined(__aarch64__) && ! defined(__APPLE__)
 extern const char *host_detect_local_cpu (int argc, const char **argv);
 #define HAVE_LOCAL_CPU_DETECT
 # define EXTRA_SPEC_FUNCTION
```

If want to do that manually, start with
```
curl -L https://mirrors.kernel.org/gnu/gcc/gcc-10.3.0/gcc-10.3.0.tar.gz | tar xf -
cd gcc-10.3.0
contrib/download_prerequisites

mkdir build && cd build
../configure --prefix=/usr/local/gcc-10.3.0-aarch64-none-elf \
             --enable-checking=release \
             --target=aarch64-none-elf \
             --disable-nls \
             --disable-shared \
             --without-headers \
             --with-newlib \
             --disable-decimal-float \
             --disable-libgomp \
             --disable-libmudflap \
             --disable-libssp \
             --disable-libatomic \
             --disable-libquadmath \
             --disable-threads \
             --enable-languages=c \
             --disable-multilib \
             --disable-libgcc \
             --disable-libssp \
             --disable-libquadmath \
             --with-static-standard-libraries \
             --with-sysroot=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk \
             --program-suffix=aarch64-none-elf

make -j 16
sudo make install-strip
```

