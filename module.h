#ifndef MODULE_H
#define MODULE_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    const char *name;
    void (*init)(void);
    int (*check)(uint64_t pid, uint64_t prev_pc, uint64_t curr_pc, uint64_t sp);
    void (*cleanup)(void);
} detector_module_t;

void register_module(detector_module_t m);
void run_modules(uint64_t pid, uint64_t prev_pc, uint64_t curr_pc, uint64_t sp);

#endif
