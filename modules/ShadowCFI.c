#include <stdio.h>
#include <stdint.h>
#include "../module.h"

#define STACK_MAX 1024

static uint64_t shadow_stack[STACK_MAX];
static int sp = -1;

static int init = 0;
static uint64_t last_pc = 0;

static void push(uint64_t addr) {
    if (sp < STACK_MAX - 1)
        shadow_stack[++sp] = addr;
}

static uint64_t pop() {
    if (sp >= 0)
        return shadow_stack[sp--];
    return 0;
}

int shadow_cfi_check(uint64_t prev_pc, uint64_t curr_pc) {

    if (!init) {
        init = 1;
        last_pc = curr_pc;
        return 0;
    }

    /*
     * STEP 1: detect possible CALL
     * forward jump = likely call target
     */
    if (curr_pc > prev_pc + 0x10) {
        // expected return address (very rough but works better than +1 logic)
        push(prev_pc + 4);
        last_pc = curr_pc;
        return 0;
    }

    /*
     * STEP 2: detect possible RET
     * backward jump or jump to known return site
     */
    if (curr_pc < prev_pc) {

        uint64_t expected = pop();

        if (expected != 0 && expected != curr_pc) {
            printf("[VIOLATION] return address mismatch!\n");
            last_pc = curr_pc;
            return 1;
        }
    }

    last_pc = curr_pc;
    return 0;
}

detector_module_t cfi_module = {
    .name = "ShadowCFI-Real",
    .init = NULL,
    .check = shadow_cfi_check,
    .cleanup = NULL
};
