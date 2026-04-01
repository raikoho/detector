#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <linux/ptrace.h>
#include <elf.h>
#include <fcntl.h>
#include <string.h>

#include "module.h"
extern detector_module_t cfi_module;

struct user_pt_regs regs;

/*
 * read registers
 */
uint64_t get_regs(pid_t pid, uint64_t *sp_out) {
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

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
        return 1;
    }

    int status;
    uint64_t pc, sp;

    waitpid(pid, &status, 0);

    register_module(cfi_module);

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    while (1) {

        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("[*] Process exited normally\n");
            break;
        }

        if (WIFSTOPPED(status)) {

            pc = get_regs(pid, &sp);

            run_modules(pid, pc, sp);

            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        }
    }

    return 0;
}
