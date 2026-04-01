#ifndef MODULE_H
#define MODULE_H

#include <stdint.h>

typedef struct {
    const char *name;
    void (*init)(void);
    int (*check)(uint64_t prev_pc, uint64_t curr_pc);
    void (*cleanup)(void);
} detector_module_t;

void register_module(detector_module_t mod);
void run_modules(uint64_t prev_pc, uint64_t curr_pc);

#endif
