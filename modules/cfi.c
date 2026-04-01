#include <stdio.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include "../module.h"
#include <sys/types.h>

// ---- state ----
static int initialized = 0;
static uint64_t last_pc = 0;

// read memory from traced process
static long read_mem(pid_t pid, uint64_t addr) {
    return ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
}

/*
 * IMPORTANT:
 * We now assume main will pass SP via "curr_pc trick"
 * (we encode SP in prev_pc parameter temporarily if needed)
 *
 * BUT better version would pass full regs (we keep simple here)
 */

int cfi_check(uint64_t prev_pc, uint64_t curr_pc) {

    if (!initialized) {
        initialized = 1;
        last_pc = curr_pc;
        return 0;
    }

    /*
     * REAL DETECTION RULE:
     * If execution suddenly jumps far away → suspicious
     */
    uint64_t diff = (curr_pc > last_pc)
        ? (curr_pc - last_pc)
        : (last_pc - curr_pc);

    if (diff > 0x1000) {
        printf("[ALERT] suspicious control-flow jump detected!\n");
        last_pc = curr_pc;
        return 1;
    }

    last_pc = curr_pc;
    return 0;
}

detector_module_t cfi_module = {
    .name = "StackCFI-lite",
    .init = NULL,
    .check = cfi_check,
    .cleanup = NULL
};
