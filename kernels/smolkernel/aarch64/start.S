	.arch armv8-a
	.file	"start.S"
    .extern start_kernel, relocate, clean_bss, _IMAGE_SIZE, _stack_top
	.global	_start

	.section ".head.text", "ax", @progbits

	.align 12
	nop
	bl _start
	.quad	0			// Image load offset from start of RAM, little-endian
	.quad	_IMAGE_SIZE	// Kernel size, little-endian
	.quad	0x0A		// Flags, little-endian: LE kernel(bit 0), 4K pages(bits 1-2), phys addr(bit 3)
	.quad	0			// Reserved
	.quad	0			// Reserved
	.quad	0			// Reserved
	.ascii	"ARM\x64"	// Signature

	.section ".init.text", "ax", @progbits

	.align	12
	.type	_start, %function
_start:
    adr     x20, _stack_top
    mov     sp, x20
	// bl relocate
	// bl clean_bss
	bl      start_kernel
1:
	b       1b
	.size	_start, .-_start

//     .bss

//     .align 4
// stack:
//     .skip   0x4000
// stack_top:

//    .fill   0x4000
