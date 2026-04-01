#include <stdio.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include "../module.h"

static uint64_t baseline_ret = 0;
static int initialized = 0;

/*
 * read stack memory
 */
static uint64_t read_mem(pid_t pid, uint64_t addr) {
    return ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
}

/*
 * REAL DETECTION:
 * compare saved return address on stack
 */
int cfi_check(pid_t pid, uint64_t pc, uint64_t sp) {

    uint64_t saved_ret = read_mem(pid, sp);

    if (!initialized) {
        baseline_ret = saved_ret;
        initialized = 1;
        return 0;
    }

    if (saved_ret != baseline_ret) {
        printf("\n[!!! CFI VIOLATION !!!]\n");
        printf("Return address corrupted!\n");
        printf("expected: 0x%lx\n", baseline_ret);
        printf("actual  : 0x%lx\n", saved_ret);
        printf("PC      : 0x%lx\n", pc);
        return 1;
    }

    return 0;
}

/*
 * module export
 */
detector_module_t cfi_module = {
    .name = "ShadowReturnCFI",
    .init = NULL,
    .check = cfi_check,
    .cleanup = NULL
};
