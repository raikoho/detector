#include <stdio.h>
#include <stdint.h>
#include "module.h"

static detector_module_t module;

void register_module(detector_module_t m) {
    module = m;
}

void run_modules(uint64_t pid, uint64_t prev_pc, uint64_t curr_pc, uint64_t sp) {
    if (module.check) {
        module.check(pid, prev_pc, curr_pc, sp);
    }
}
