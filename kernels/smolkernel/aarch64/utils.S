	.arch armv8-a
	.file	"utils.S"

	.section ".text.utils", "ax", @progbits

	.align	4
	.global	arm_reg_current_el
	.type	arm_reg_current_el, %function
arm_reg_current_el:
    mrs     x0, CurrentEL
    ret
	.size	arm_reg_current_el, .-arm_reg_current_el

	.macro declare_reg_get name
	.align	4
	.global	arm_reg_\name
	.type	arm_reg_\name, %function
arm_reg_\name:
    mrs     x0, \name
    ret
	.size	arm_reg_\name, .-arm_reg_\name
	.endm

	declare_reg_get vbar_el1
	declare_reg_get rvbar_el1
	declare_reg_get midr_el1
	declare_reg_get mpidr_el1
    declare_reg_get mdscr_el1
	declare_reg_get sctlr_el1
	declare_reg_get spsr_el1
	declare_reg_get tcr_el1
	declare_reg_get ttbr0_el1
	declare_reg_get ttbr1_el1
	declare_reg_get esr_el1
	declare_reg_get elr_el1
	declare_reg_get mair_el1
    declare_reg_get cpacr_el1
    declare_reg_get daif
    declare_reg_get id_aa64mmfr0_el1
    declare_reg_get id_aa64mmfr1_el1
    declare_reg_get id_aa64mmfr2_el1
