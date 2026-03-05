#pragma once

#include <stdint.h>

struct shared_area_s {
    uint8_t uelf_log_lock;
};

extern struct shared_area_s shared_area;
