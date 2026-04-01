#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include "module.h"
#include <sys/user.h>
#include <stdint.h>

uint64_t get_pc(pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    return regs.rip;
}

extern detector_module_t cfi_module;

uint64_t get_pc(pid_t pid); // platform-specific

int main(int argc, char *argv[]) {
    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    }

    wait(NULL);

    register_module(cfi_module);

    uint64_t prev_pc = 0;

    while (1) {
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(NULL);

        uint64_t pc = get_pc(pid);

        run_modules(prev_pc, pc);

        prev_pc = pc;
    }
}
