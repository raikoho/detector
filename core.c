#include "module.h"

static detector_module_t mod;

void register_module(detector_module_t m) {
    mod = m;
}

void run_modules(pid_t pid, uint64_t pc, uint64_t sp) {
    if (mod.check) {
        mod.check(pid, pc, sp);
    }
}
