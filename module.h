#ifndef MODULE_H
#define MODULE_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    const char *name;
    void (*init)(void);
    int (*check)(pid_t pid, uint64_t pc, uint64_t sp);
    void (*cleanup)(void);
} detector_module_t;

void register_module(detector_module_t m);
void run_modules(pid_t pid, uint64_t pc, uint64_t sp);

#endif
