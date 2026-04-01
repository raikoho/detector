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

/*
 * ARM64 register capture
 */
struct regs_pack {
    struct user_pt_regs regs;
};

uint64_t get_pc(pid_t pid) {
    struct iovec io;
    struct user_pt_regs regs;

    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

    return regs.pc;
}

/*
 * NEW: get stack pointer (IMPORTANT for real CFI later)
 */
uint64_t get_sp(pid_t pid) {
    struct iovec io;
    struct user_pt_regs regs;

    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

    return regs.sp;
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    }

    wait(NULL);

    register_module(cfi_module);

    uint64_t prev_pc = 0;
    int warmup = 0;

    while (1) {
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(NULL);

        uint64_t pc = get_pc(pid);

        /*
         * WARMUP → avoids startup noise (VERY IMPORTANT)
         */
        if (warmup < 50) {
            warmup++;
            prev_pc = pc;
            continue;
        }

        run_modules(prev_pc, pc);

        prev_pc = pc;
    }
}
