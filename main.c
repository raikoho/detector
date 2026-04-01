#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/ptrace.h>
#include <linux/elf.h>

uint64_t get_pc(pid_t pid) {
    struct iovec io;
    struct user_pt_regs regs;

    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

    return regs.pc;
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
