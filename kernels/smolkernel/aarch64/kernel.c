#include <stdint.h>

#include "pl011.h"
#include "printf.h"
#include "utils.h"

void relocate(void* rel_begin, void* rel_end)
{
}

void clean_bss(void* bss_begin, void* bss_end)
{
}

struct pl011_t pl011 = {
    .base_addr = 0x9000000ULL,
    .id = 0
};

void _putchar(char ch)
{
    pl011_send_byte(&pl011, ch);
}

void start_kernel()
{
    pl011_init(&pl011);

    printf_("Hello, world, from EL %ld!\n", arm_reg_current_el() >> 2);
    printf_("PL011 ID 0x%016lx\n", pl011.id);
    printf_("VBAR_EL1 0x%016lx\n", arm_reg_vbar_el1());
    printf_("MIDR_EL1 0x%016lx\n", arm_reg_midr_el1());
    printf_("MPIDR_EL1 0x%016lx\n", arm_reg_mpidr_el1());
    printf_("MDSCR_EL1 0x%016lx\n", arm_reg_mdscr_el1());
    printf_("SCTLR_EL1 0x%016lx\n", arm_reg_sctlr_el1());
    printf_("SPSR_EL1 0x%016lx\n", arm_reg_spsr_el1());
    printf_("TCR_EL1 0x%016lx\n", arm_reg_tcr_el1());
    printf_("TTBR0_EL1 0x%016lx\n", arm_reg_ttbr0_el1());
    printf_("TTBR1_EL1 0x%016lx\n", arm_reg_ttbr1_el1());
    printf_("ESR_EL1 0x%016lx\n", arm_reg_esr_el1());
    printf_("ELR_EL1 0x%016lx\n", arm_reg_elr_el1());
    printf_("MAIR_EL1 0x%016lx\n", arm_reg_mair_el1());
    printf_("CPACR_EL1 0x%016lx\n", arm_reg_cpacr_el1());
    printf_("DAIF 0x%016lx\n", arm_reg_daif());
}
