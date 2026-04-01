#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <linux/ptrace.h>
#include <elf.h>
#include <sys/types.h>

#include "module.h"

extern detector_module_t cfi_module;

struct user_pt_regs regs;

/*
 * Read PC + SP from traced process
 */
uint64_t get_regs(pid_t pid, uint64_t *sp_out) {
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) == -1) {
        perror("ptrace(GETREGSET)");
        return 0;
    }

    *sp_out = regs.sp;
    return regs.pc;
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
        perror("execl");
        return 1;
    }

    int status;
    uint64_t prev_pc = 0;
    uint64_t sp = 0;

    /*
     * Wait for child to stop at exec
     */
    waitpid(pid, &status, 0);

    register_module(cfi_module);

    /*
     * Start tracing
     */
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    while (1) {

        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("[*] Process exited normally (code=%d)\n", WEXITSTATUS(status));
            break;
        }

        if (WIFSIGNALED(status)) {
            printf("[!] Process killed by signal %d\n", WTERMSIG(status));
            break;
        }

        if (WIFSTOPPED(status)) {

            uint64_t pc = get_regs(pid, &sp);

            if (pc == 0) {
                break;
            }

            run_modules(pid, prev_pc, pc, sp);

            prev_pc = pc;

            /*
             * continue execution
             */
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        }
    }

    return 0;
}

