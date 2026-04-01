#include <stdio.h>
#include <stdint.h>
#include "../module.h"

// VERY SIMPLE RULE (demo version)
int cfi_check(uint64_t prev_pc, uint64_t curr_pc) {

    // allow sequential execution
    if (curr_pc == prev_pc + 1) {
        return 0;
    }

    // anything else = suspicious (simplified model)
    return 1;
}

detector_module_t cfi_module = {
    .name = "CFI-lite",
    .init = NULL,
    .check = cfi_check,
    .cleanup = NULL
};
