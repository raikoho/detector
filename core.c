#include <stdio.h>
#include "module.h"

#define MAX_MODULES 10

static detector_module_t modules[MAX_MODULES];
static int module_count = 0;

void register_module(detector_module_t mod) {
    if (module_count < MAX_MODULES) {
        modules[module_count++] = mod;
    }
}

void run_modules(uint64_t prev_pc, uint64_t curr_pc) {
    for (int i = 0; i < module_count; i++) {
        if (modules[i].check(prev_pc, curr_pc)) {
            printf("[ALERT] %s detected control-flow violation!\n",
                   modules[i].name);
        }
    }
}
