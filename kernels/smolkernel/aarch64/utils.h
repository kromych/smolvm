#pragma once

#include <stdint.h>

extern uint64_t arm_reg_current_el(void);
extern uint64_t arm_reg_vbar_el1(void);
extern uint64_t arm_reg_rvbar_el1(void);
extern uint64_t arm_reg_midr_el1(void);
extern uint64_t arm_reg_mpidr_el1(void);
extern uint64_t arm_reg_mdscr_el1(void);
extern uint64_t arm_reg_sctlr_el1(void);
extern uint64_t arm_reg_spsr_el1(void);
extern uint64_t arm_reg_tcr_el1(void);
extern uint64_t arm_reg_ttbr0_el1(void);
extern uint64_t arm_reg_ttbr1_el1(void);
extern uint64_t arm_reg_esr_el1(void);
extern uint64_t arm_reg_elr_el1(void);
extern uint64_t arm_reg_mair_el1(void);
extern uint64_t arm_reg_cpacr_el1(void);
extern uint64_t arm_reg_daif(void);
