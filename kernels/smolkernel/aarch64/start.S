	.arch armv8-a
	.file	"start.S"
    .extern main, _IMAGE_SIZE
	.global	_start

	.section ".head.text", "ax"

	.align 16
	nop
	bl _start
	.quad	0			// Image load offset from start of RAM, little-endian
	.quad	_IMAGE_SIZE	// Kernel size, little-endian
	.quad	0x0A		// Flags, little-endian
	.quad	0			// Reserved
	.quad	0			// Reserved
	.quad	0			// Reserved
	.ascii	"ARM\x64"	// Signature

	.section ".init.text", "ax"

	.align	16
	.type	_start, %function
_start:
    adr     x20, stack
    mov     sp, x20
	bl      main
1:
	b       1b
	.size	_start, .-_start

    .bss

    .align 16
stack:
    .skip   0x4000
//    .fill   0x4000
