#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/ptrace.h>
#include <elf.h>

#include "module.h"

extern detector_module_t cfi_module;

struct user_pt_regs regs;

uint64_t get_regs(pid_t pid, uint64_t *sp_out) {
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

    *sp_out = regs.sp;
    return regs.pc;
}

int main(int argc, char *argv[]) {

    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    }

    wait(NULL);

    register_module(cfi_module);

    uint64_t prev_pc = 0;
    uint64_t sp = 0;

    for (int i = 0; i < 10000; i++) {

        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(NULL);

        uint64_t pc = get_regs(pid, &sp);

        run_modules(pid, prev_pc, pc, sp);

        prev_pc = pc;
    }

    return 0;
}
