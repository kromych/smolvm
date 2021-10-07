#include <stdint.h>

#include "printf.h"
#include "utils.h"

#define DR_OFFSET       0x000UL
#define FR_OFFSET       0x018UL
#define IBRD_OFFSET     0x024UL
#define FBRD_OFFSET     0x028UL
#define LCR_OFFSET      0x02cUL
#define CR_OFFSET       0x030UL
#define IMSC_OFFSET     0x038UL
#define ICR_OFFSET      0x044UL
#define DMACR_OFFSET    0x048UL
#define ID_OFFSET       0xFE0UL
#define UART_BASE       0x9000000ULL

void relocate(void)
{
}

uint32_t pl011_read(uint32_t offset)
{
    return *((volatile uint32_t*)(UART_BASE + offset));
}

uint32_t pl011_write(uint32_t offset, uint32_t value)
{
    *((volatile uint32_t*)(UART_BASE + offset)) = value;
}

uint64_t pl011_init()
{
    uint64_t id = 0;

    id |= pl011_read(ID_OFFSET + 0x00) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x04) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x08) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x0c) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x10) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x14) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x18) & 0xff;
    id <<= 8;
    id |= pl011_read(ID_OFFSET + 0x1c) & 0xff;

    pl011_write(IMSC_OFFSET, 0x00000000);
    pl011_write(ICR_OFFSET, 0x0000ffff);

    pl011_read(CR_OFFSET); // 0x00000300
    pl011_write(CR_OFFSET, 0x00000300);
    pl011_read(CR_OFFSET); // 0x00000300
    pl011_read(CR_OFFSET); // 0x00000300
    pl011_write(CR_OFFSET, 0x00000000);

    pl011_write(FBRD_OFFSET, 0x00000004);
    // new baudrate 0 (clk: 0hz, ibrd: 0, fbrd: 4)
    pl011_write(IBRD_OFFSET, 0x00000027);
    // new baudrate 0 (clk: 0hz, ibrd: 39, fbrd: 4)
    pl011_write(LCR_OFFSET, 0x00000070);

    pl011_write(CR_OFFSET, 0x00000300);
    pl011_read(CR_OFFSET); // 0x00000300
    pl011_write(CR_OFFSET, 0x00000301);

    return id;
}

void _putchar(char data)
{
    while (pl011_read(FR_OFFSET) != 0x00000090)
    {
        // Spin here
    }
    pl011_write(DR_OFFSET, data);
}

void start_kernel()
{
    uint64_t pl011_id;

    relocate();

    pl011_id = pl011_init();
    printf_("Hello, world, from EL %d!\n", arm_reg_current_el() >> 2);
    printf_("PL011 ID 0x%016llx\n", pl011_id);
    printf_("VBAR_EL1 0x%016llx\n", arm_reg_vbar_el1());
    printf_("MIDR_EL1 0x%016llx\n", arm_reg_midr_el1());
    printf_("MPIDR_EL1 0x%016llx\n", arm_reg_mpidr_el1());
    printf_("MDSCR_EL1 0x%016llx\n", arm_reg_mdscr_el1());
    printf_("SCTLR_EL1 0x%016llx\n", arm_reg_sctlr_el1());
    printf_("SPSR_EL1 0x%016llx\n", arm_reg_spsr_el1());
    printf_("TCR_EL1 0x%016llx\n", arm_reg_tcr_el1());
    printf_("TTBR0_EL1 0x%016llx\n", arm_reg_ttbr0_el1());
    printf_("TTBR1_EL1 0x%016llx\n", arm_reg_ttbr1_el1());
    printf_("ESR_EL1 0x%016llx\n", arm_reg_esr_el1());
    printf_("ELR_EL1 0x%016llx\n", arm_reg_elr_el1());
    printf_("MAIR_EL1 0x%016llx\n", arm_reg_mair_el1());
    printf_("CPACR_EL1 0x%016llx\n", arm_reg_cpacr_el1());
    printf_("DAIF 0x%016llx\n", arm_reg_daif());
}
