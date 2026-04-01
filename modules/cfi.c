#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include "../module.h"

static pid_t g_pid = 0;
static uint64_t expected_ret = 0;
static int initialized = 0;

/*
 * ARM64:
 * saved return address (LR) is stored at:
 * [SP]
 */
static uint64_t read_mem(uint64_t addr) {
    return ptrace(PTRACE_PEEKDATA, g_pid, (void*)addr, NULL);
}

/*
 * We detect:
 * stack return address != expected return address
 */
int cfi_check(uint64_t pid, uint64_t prev_pc, uint64_t curr_pc, uint64_t sp) {

    g_pid = (pid_t)pid;

    if (!initialized) {
        /*
         * First time we see execution:
         * capture correct return address baseline
         */
        expected_ret = read_mem(sp);
        initialized = 1;
        return 0;
    }

    uint64_t current_ret = read_mem(sp);

    if (current_ret != expected_ret) {
        printf("\n[!!! DETECTION !!!]\n");
        printf("Return address overwritten!\n");
        printf("Expected: 0x%lx\n", expected_ret);
        printf("Got     : 0x%lx\n", current_ret);
        return 1;
    }

    return 0;
}

/*
 * module export
 */
detector_module_t cfi_module = {
    .name = "ShadowStack-CFI",
    .init = NULL,
    .check = NULL,   // replaced in core (see below)
    .cleanup = NULL
};
