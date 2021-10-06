TARGET=smolkernel

TOOLCHAIN=elf
CC=aarch64-unknown-$(TOOLCHAIN)-gcc
LD=aarch64-unknown-$(TOOLCHAIN)-ld
OBJCOPY=aarch64-unknown-$(TOOLCHAIN)-objcopy
CFLAGS=-ffreestanding -nostartfiles -static -g -march=armv8-a -mcmodel=large -mgeneral-regs-only \
		-fno-asynchronous-unwind-tables -fno-unwind-tables \
		-mbranch-protection=none
OBJCOPY_FLAGS :=-O binary -R .note -R .note.gnu.build-id -R .comment -S

.PHONY: all clean

all: $(TARGET).bin

clean:
	-rm $(TARGET).bin $(TARGET).elf ./*.o

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) $(OBJCOPY_FLAGS) $(TARGET).elf $(TARGET).bin

$(TARGET).elf: start.S kernel.c kernel.lds
	$(CC) $(CFLAGS) -c start.S
	$(CC) $(CFLAGS) -c kernel.c
	$(LD) -T kernel.lds -z max-page-size=4096 -o $(TARGET).elf start.o kernel.o
