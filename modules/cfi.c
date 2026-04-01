#include <stdio.h>
#include <stdint.h>
#include "../module.h"

// simple state (reduces false positives)
static int initialized = 0;
static int warmup = 0;
static uint64_t last_pc = 0;

// ARM64 instruction size awareness
#define INSTR_SIZE 4

int cfi_check(uint64_t prev_pc, uint64_t curr_pc) {

    // ignore first sample
    if (!initialized) {
        initialized = 1;
        last_pc = curr_pc;
        return 0;
    }

    // warmup phase (VERY IMPORTANT for ptrace programs)
    if (warmup < 30) {
        warmup++;
        last_pc = curr_pc;
        return 0;
    }

    // allow normal sequential execution
    if (curr_pc == last_pc + INSTR_SIZE ||
        curr_pc == last_pc - INSTR_SIZE) {
        last_pc = curr_pc;
        return 0;
    }

    // allow function returns / jumps (very rough heuristic)
    // if jump is within reasonable distance, allow it
    int64_t diff = (int64_t)curr_pc - (int64_t)last_pc;
    if (diff < 0) diff = -diff;

    if (diff < 0x1000) {
        last_pc = curr_pc;
        return 0;
    }

    // otherwise suspicious
    last_pc = curr_pc;
    return 1;
}

detector_module_t cfi_module = {
    .name = "CFI-lite",
    .init = NULL,
    .check = cfi_check,
    .cleanup = NULL
};
