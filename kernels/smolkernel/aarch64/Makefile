TARGET=smolkernel

CFLAGS=--target=$(TRIPLE) -O2 -g -ffreestanding -nostartfiles -static -march=armv8-a -mcmodel=large -mgeneral-regs-only \
		-fno-asynchronous-unwind-tables -fno-unwind-tables \
		-mbranch-protection=none -Wno-unused-command-line-argument
#       --save-temps
OBJCOPY_FLAGS :=-O binary -R .note -R .note.gnu.build-id -R .comment -S

.PHONY: all clean

all: $(TARGET).bin

clean:
	-rm -f $(TARGET).bin $(TARGET).elf ./*.o ./*.i ./*.s

$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) $(OBJCOPY_FLAGS) $(TARGET).elf $(TARGET).bin

$(TARGET).elf: start.S utils.S kernel.c printf.c pl011.c kernel.lds
	$(CC) $(CFLAGS) -c start.S
	$(CC) $(CFLAGS) -c utils.S
	$(CC) $(CFLAGS) -c kernel.c
	$(CC) $(CFLAGS) -c printf.c
	$(CC) $(CFLAGS) -c pl011.c
	$(LD) -static -T kernel.lds -z max-page-size=4096 -o $(TARGET).elf start.o utils.o kernel.o printf.o pl011.o
