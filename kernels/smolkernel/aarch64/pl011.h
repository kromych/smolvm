#pragma once

#include <stdint.h>

struct pl011_t
{
    uint64_t base_addr;
    uint64_t id;
};

extern void pl011_init(struct pl011_t *pl011);
extern void pl011_send_byte(const struct pl011_t *pl011, char data);
