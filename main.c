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

/*
 * ELF range of executable code (.text)
 */
uint64_t text_start = 0;
uint64_t text_end   = 0;

struct user_pt_regs regs;

/*
 * Parse ELF to find .text range
 */
void load_elf_range(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open ELF");
        return;
    }

    Elf64_Ehdr eh;
    read(fd, &eh, sizeof(eh));

    lseek(fd, eh.e_shoff, SEEK_SET);

    Elf64_Shdr sh;

    for (int i = 0; i < eh.e_shnum; i++) {
        read(fd, &sh, sizeof(sh));

        if (sh.sh_flags & SHF_EXECINSTR) {
            if (text_start == 0 || sh.sh_addr < text_start)
                text_start = sh.sh_addr;

            if (sh.sh_addr + sh.sh_size > text_end)
                text_end = sh.sh_addr + sh.sh_size;
        }
    }

    close(fd);

    printf("[*] .text range: 0x%lx - 0x%lx\n", text_start, text_end);
}

/*
 * Get registers
 */
uint64_t get_regs(pid_t pid, uint64_t *sp_out) {
    struct iovec io;
    io.iov_base = &regs;
    io.iov_len = sizeof(regs);

    ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io);

    *sp_out = regs.sp;
    return regs.pc;
}

/*
 * REAL CFI CHECK
 */
void check_cfi(uint64_t pc) {
    if (pc < text_start || pc > text_end) {
        printf("\n[!!! CFI VIOLATION !!!]\n");
        printf("Execution outside .text segment!\n");
        printf("PC = 0x%lx\n", pc);
    }
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    load_elf_range(argv[1]);

    pid_t pid = fork();

    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
        return 1;
    }

    int status;
    uint64_t sp = 0;
    uint64_t pc;

    waitpid(pid, &status, 0);

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    while (1) {

        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("[*] Process exited normally\n");
            break;
        }

        if (WIFSTOPPED(status)) {

            pc = get_regs(pid, &sp);

            check_cfi(pc);

            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        }
    }

    return 0;
}
