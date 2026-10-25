#define _GNU_SOURCE

#include <errno.h>

// open, stat
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// fork, exec, free
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// clone
#include <sched.h>

// parser
#include <string.h>
#include <limits.h>

// elf inspection
#include <sys/mman.h>
#include <elf.h>

// syscall introspection
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

// available namespaces
#include <dirent.h>

#define STAGE_HOST 1
#define STAGE_CONTAINER 2

struct namespace {
    const char* proc_name;
    int flag;
    int stage;
    int fd;
};

// terminfo special case
char terminfo_suffix[PATH_MAX] = {0};
const char* terminfo_lib_fullpath = "/lib/x86_64-linux-gnu/libtinfo.so.6";
const char* terminfo_candidates_locations[] = {
    "/etc",
    "/lib",
    "/usr/lib",
    "/usr/share",
    NULL,
};

// path whitelisted for proxying. If ending with a '+', interpret as a prefix
const char* proxy_whitelist[] = {
    "/etc/terminfo",
    "/etc/terminfo/+",
    "/lib/terminfo",
    "/lib/terminfo/+",
    "/usr/share/terminfo",
    "/usr/share/terminfo/+",
    NULL,
};

// return 1 if prefix match. 0 otherwise
// if prefix does not end with '+', consider exact match only
// if the prefix is empty, consider not a match
int str_prefix_match(const char* prefix, const char* candidate) {
    int prefix_len;

    // Sanity
    if(prefix == NULL || candidate == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if(!prefix_len) {
        return 0;
    }

    // prefix ?
    if(prefix[prefix_len-1] == '+') {
        if(strncmp(prefix, candidate, prefix_len-1) == 0) {
            return 1;
        }
    }

    // exact match ?
    if(strcmp(prefix, candidate) == 0) {
        return 1;
    }

}

// wrapper around pidfd_open. Unsets the CLOEXEC flag as we need inheritance.
int pidfd_open(pid_t pid, unsigned int flags) {
    int fd = syscall(SYS_pidfd_open, pid, flags);
    if (fd < 0) {
        errno = -fd;
        return -1;
    }

    int fd_flags = fcntl (fd, F_GETFD);
    if (flags == -1) {
        close(fd);
        return -1;
    }

    int ret = fcntl (fd, F_SETFD, fd_flags & ~FD_CLOEXEC);
    if (ret == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

int proc_open_mem(pid_t pid) {
    char path[PATH_MAX];
    int fd;

    // open memory
    if(snprintf(path, PATH_MAX, "/proc/%d/mem", pid) < 0) {
        perror("snprintf");
        return -1;
    }

    fd = open(path, O_RDWR);
    if(fd == -1) {
        perror("open mem");
        return -1;
    }

    return fd;
}

int proc_read_data(int fd, void* src, void* dst, size_t len) {
    // read data
    if(lseek(fd, (long)src, SEEK_SET) == -1) {
        perror("seek mem");
        return -1;
    }

    if(read(fd, dst, len) == -1) {
        perror("read mem");
        return -1;
    }
}

int proc_write_data(int fd, void* src, void* dst, size_t len) {
    // write data
    if(lseek(fd, (long)dst, SEEK_SET) == -1) {
        perror("seek mem");
        return -1;
    }

    if(write(fd, src, len) == -1) {
        perror("write mem");
        return -1;
    }
}

// Read arbitrary data from PID's memory. Ptrace PEEKTEXT is too slow/risky to use
int proc_read_string(int fd, char* src, char* dst, size_t len) {
    if(proc_read_data(fd, src, dst, len) == -1) {
        return -1;
    }
    dst[len-1] = '\0';
    return 0;
}

int in_ld(unsigned long long int addr, unsigned int pid, char* loader) {
    static unsigned long long int begin_addr = 0;
    static unsigned long long int end_addr = 0;

    // handle statically linked binaries
    if (loader == NULL) {
        return 0;
    }

    // load + parse /proc/<pid>/maps
    if(begin_addr == 0) {
        int index = 0;
        size_t len;
        size_t read;
        FILE* fp;
        char* parsing = NULL;
        char* line = NULL;
        char* path = NULL;
        char* field = NULL;

        char* addrs = NULL;

        if(asprintf(&path, "/proc/%d/maps", pid) == -1) {
            perror("asprintf");
            exit(1);
        }

        fp = fopen(path, "r");
        if(!fp) {
            perror("fopen");
            exit(1);
        }

        while((read = getline(&line, &len, fp)) != -1) {
            parsing = line;
            for (index = 0; index<6; index++) {
                field = strtok(parsing, " \t\n");
                if (field == NULL)
                    break;

                // load addresses
                if(index == 0) {
                    addrs = field;
                    parsing = NULL;
                    continue;
                }

                // make sure this section is executable
                if(index == 1) {
                    if(strlen(field) < 3 || field[2] != 'x') {
                        break;
                    }
                }

                // is it our target ?
                if(index == 5) {
                    if(strcmp(loader, field) != 0) {
                        addrs = NULL;
                    }
                }
            }

            // If last loop was full AND we have match --> exit loop
            if(addrs != NULL && index == 6) {
                break;
            }

        }

        // parse addr field
        parsing = addrs;
        for(index = 0; index<2; index++) {
            field = strtok(parsing, "-");
            if(field == NULL) {
                break;
            }
            if(index == 0) {
                begin_addr = strtol(field, NULL, 16);;
            } else if (index == 1) {
                end_addr = strtol(field, NULL, 16);
            }
            parsing = NULL;
        }

        fclose(fp);
        free(line);
        free(path);
    }

    return addr >= begin_addr && addr < end_addr;
}

char* terminfo_build_suffix() {
    if(terminfo_suffix[0] != '\0') return terminfo_suffix;

    const char* termname;
    termname = getenv("TERM");
    if(!termname) {
        return NULL;
    }

    if(snprintf(terminfo_suffix, sizeof(terminfo_suffix), "terminfo/%c/%s", termname[0], termname) == -1) {
        perror("snprintf terminfo suffix");
        return NULL;
    }

    return terminfo_suffix;
}

int terminfo_need(int mem_fd, char* base_address) {
    char path[PATH_MAX];
    char** candidate;

    if(proc_read_string(mem_fd, base_address, path, sizeof(path)) == -1) {
        return 0;
    }

    if(strcmp(terminfo_lib_fullpath, path) == 0) {
        return 1;
    }

    return 0;
}

int terminfo_open() {
    char path[PATH_MAX];
    const char** candidate;
    char* suffix = terminfo_build_suffix();
    int fd;

    if(!suffix) {
        return -1;
    }

    for(candidate=terminfo_candidates_locations; *candidate; candidate++) {
        if(snprintf(path, sizeof(path), "%s/%s", *candidate, suffix) == -1) {
            continue;
        }
        if((fd = open(path, O_RDONLY)) != -1) {
            return fd;
        }
    }

    return -1;
}

int terminfo_is_descfile(char* path) {
    char* suffix = terminfo_build_suffix();
    return (suffix && strlen(path) > strlen(suffix) && !strcmp(path + strlen(path) - strlen(suffix), suffix));
}

int proxy_is_ok(const char *pathname) {
    const char** candidate;
    int candidate_len;

    for(candidate=proxy_whitelist; *candidate; candidate++) {
        if(str_prefix_match(*candidate, pathname) == 1) {
            return 1;
        }
    }

    return 0;
}

// run stat in parent, copy result to child
int proxy_stat(int mem_fd, const char *pathname, struct stat *buf) {
    struct stat src;
    int ret;

    ret = stat(pathname, &src);
    proc_write_data(mem_fd, &src, buf, sizeof(src));

    return ret;
}

// run access in parent, copy result to child
int proxy_access(int mem_fd, const char *pathname, int mode) {
    return access(pathname, mode);
}

// Wait for syscall. If regs is not NULL, load registers states into regs
int wait_for_syscall(pid_t child, struct user_regs_struct* regs) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
            if(regs)
                ptrace(PTRACE_GETREGS, child, NULL, regs);
            return 0;
        }
        if (WIFEXITED(status))
            return -1;
    }
}

// inject syscall in the container
// convention: process is *entering* a syscall
// FIXME: only trial syscalls, enough for our needs
int inject_syscall(pid_t pid, unsigned long long int nr, unsigned long long int rdi, unsigned long long int rsi) {
    struct user_regs_struct regs;

    // Grab current registers state
    if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace");
        return -1;
    }

    // inject call
    regs.orig_rax = nr;
    regs.rdi = rdi;
    regs.rsi = rsi;
    regs.rip -= 2;
    if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("inject_syscall: Failed to inject syscall registers");
        return -1;
    }

    // get return value
    if(wait_for_syscall(pid, &regs) == -1) exit(1);
    if(regs.rax < 0) {
        errno = -regs.rax;
        return -1;
    }

    // wait for next syscall *entry*
    if(wait_for_syscall(pid, NULL) == -1) exit(1);
}

// wrapper fo injecting 'setns' syscall in the container
int inject_setns(pid_t pid, int fd, int nstype) {
    return inject_syscall(pid, SYS_setns, fd, nstype);
}

// wrapper fo injecting 'close' syscall in the container
int inject_close(pid_t pid, int fd) {
    return inject_syscall(pid, SYS_close, fd, 0);
}

int resolve_path(char* target, char* buffer, int buffer_len) {
    int target_len = strlen(target);

    if (strchr(target, '/') != NULL) {
        strcpy(buffer, target);
        if (access(buffer, R_OK|X_OK) == 0) {
            return 0;
        } else {
            goto err;
        }
    } else {
        char* PATH = getenv("PATH");
        if (PATH == NULL) {
            goto err;
        }

        // Iterate over the path components
        int buffer_offset = 0;
        for (int i = 0; ; i++)
        {
            if (PATH[i] == ':' || PATH[i] == 0) {
                if (buffer_offset + target_len + 2 < buffer_len) {
                    buffer[buffer_offset++] = '/';
                    strcpy(buffer+buffer_offset, target);

                    if (access(buffer, R_OK|X_OK) == 0) {
                        return 0;
                    }
                }

                if (PATH[i] == 0) {
                    goto err;
                }

                buffer_offset = 0;
            } else {
                if (buffer_offset + target_len + 2 >= buffer_len) {
                    // Ignore this path chunk, it wont't fit
                    continue;
                }

                buffer[buffer_offset++] = PATH[i];
            }
        }

        goto err;
    }

    return 0;
err:
    buffer[0] = 0;
    return -1;
}

// Extracts the requested dynamic loader path (PT_INTERP) from an ELF binary.
char *get_elf_interpreter(const char *filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return NULL;
    }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd); // File descriptor can be closed immediately after mapping
    if (map == MAP_FAILED) {
        return NULL;
    }

    unsigned char *e_ident = (unsigned char *)map;
    char *interpreter = NULL;

    // Verify magic bytes (\x7fELF)
    if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
        goto out;
    }

    // Only support 64 bit binaries
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
        Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)map + ehdr->e_phoff);

        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == PT_INTERP) {
                if (phdr[i].p_offset + phdr[i].p_filesz <= st.st_size) {
                    char* raw_interpreter = strndup((char *)map + phdr[i].p_offset, phdr[i].p_filesz);
                    interpreter = canonicalize_file_name(raw_interpreter);
                    free(raw_interpreter);
                }
                break;
            }
        }
    } else {
        goto out;
    }

out:
    munmap(map, st.st_size);
    return interpreter;
}

pid_t create_child(char* command, char **argv) {
    pid_t child = fork();

    if(child == -1) {
        perror("fork");
        return 1;
    }

    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        execv(command, argv);
        perror("exec");
        exit(1);
    }
    return child;
}

int get_supported_namespaces() {
    DIR* dir = opendir("/proc/self/ns");
    if(dir == NULL) {
        perror("Failed to open /proc/self/ns");
        return -1;
    }

    int supported_namespaces = 0;
    while (1) {
        struct dirent* ent = readdir(dir);
        errno = 0;
        if (ent == NULL) {
            if (errno == 0) {
                break;
            } else {
                perror("Failed to read /proc/self/ns");
                return -1;
            }
        }

        if (strcmp("cgroup", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWCGROUP;
        }
        if (strcmp("ipc", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWIPC;
        }
        if (strcmp("net", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWNET;
        }
        if (strcmp("mnt", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWNS;
        }
        if (strcmp("pid", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWPID;
        }
        if (strcmp("time", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWTIME;
        }
        if (strcmp("user", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWUSER;
        }
        if (strcmp("uts", ent->d_name) == 0) {
            supported_namespaces |= CLONE_NEWUTS;
        }
    }

    return supported_namespaces;
}

int main(int argc, char** argv) {
    // parent vars
    int mem_fd;
    int target_fd = -1;
    int status;
    int insyscall = 0;
    int stage1_ns, stage2_ns;
    pid_t target_pid, child;
    char path[PATH_MAX];
    char command[PATH_MAX];
    struct user_regs_struct regs;
    struct user_regs_struct regs_in;
    struct user_regs_struct regs_out;
    struct namespace* ns;

    // special/favor treatment: terminfo
    int terminfo_enabled = 0;
    int terminfo_fd = 0;

    /* Parse arguments */
    if(argc <= 2) {
        fprintf(stderr, "Usage: %s TARGET_PID [command...]\n", argv[0]);
        exit(1);
    }

    target_pid = atoi(argv[1]);
    if(!target_pid) {
        fprintf(stderr, "Invalid TARGET_PID: %s\n", argv[1]);
        exit(1);
    }

    if (resolve_path(argv[2], command, PATH_MAX) != 0) {
        fprintf(stderr, "Command not found: %s\n", argv[2]);
        exit(1);
    }

    // Choreograph the namespace change dance
    // - CLONE_NEWPID always needs to be performed before the `fork` as the process can not change PID
    // - CLONE_NEWUSER needs to be done
    //   - before the fork when not root, to gain CAP_SYSADMIN
    //   - after the fork when root
    // - CLONE_NEWTIME requires actual root on the host

    int supported_namespaces = get_supported_namespaces();
    if (supported_namespaces == -1) {
        fprintf(stderr, "Failed to get the list of supported namespaces");
        exit(1);
    }

    if (geteuid() != 0 && !(supported_namespaces & CLONE_NEWUSER)) {
        fprintf(stderr, "User namespaces are not supported on this machine. Re-run as root.");
        exit(1);
    }

    stage1_ns = CLONE_NEWPID;
    stage2_ns = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS;

    if (geteuid() == 0) {
        stage2_ns |= CLONE_NEWUSER | CLONE_NEWTIME;
    } else {
        stage1_ns |= CLONE_NEWUSER;
    }

    // Mask unsupported namespaces
    stage1_ns &= supported_namespaces;
    stage2_ns &= supported_namespaces;

    // Locate the Dynamic loader
    char *loader = get_elf_interpreter(command);

    // Open and leak target fd. Will be used by setns
    // Opening in the parent allows us to know the FD number. Can be closed as soon as the child has forked.
    target_fd = pidfd_open(target_pid, 0);
    if (target_fd == -1) {
        perror("Failed to get a file descriptor on the target PID.");
        exit(1);
    }

    // Stage 1 netns change
    if(setns(target_fd, stage1_ns) == -1) {
        perror("setns");
        return 1;
    }

    // Open and leak terminfo fd
    // Opening in the parent allows us to know the FD number. Can be closed as soon as the child has forked.
    terminfo_fd = terminfo_open();

    // create child
    child = create_child(command, argv+2);

    // Close any leaked fd at this stage
    close(terminfo_fd);
    close(target_fd);

    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    // Wait until exec
    do {
        if(wait_for_syscall(child, NULL) == -1) break;
        if(wait_for_syscall(child, &regs) == -1) break;
    } while(regs.orig_rax != SYS_execve);

    // open child's memory
    mem_fd = proc_open_mem(child);
    if(mem_fd == -1) {
        return 1;
    }

    // wait until 1st syscall outside of ld, break on entry
    while(1) {
        if(wait_for_syscall(child, &regs_in) == -1) break;
        if(!in_ld(regs_in.rip, child, loader)) break;

        // detect special treatments
        if(regs_in.orig_rax == SYS_open) {
            if(terminfo_need(mem_fd, (char*)regs_in.rdi)) terminfo_enabled=1;
        }
        if(wait_for_syscall(child, &regs_in) == -1) break;
    }

    // At this point, we are *inside* a syscall, after ld
    if (loader) {
        free(loader);
    }

    // Stage 2 netns change
    if(inject_setns(child, target_fd, stage2_ns) < 0) {
        perror("inject_setns");
        exit(1);
    }

    if(inject_close(child, target_fd) == -1) {
        perror("inject_close");
        exit(1);
    }

    // Set user to root in the container context, drop any supplementary groups
    // best effort calls (no checks)
    inject_syscall(child, SYS_setreuid, 0, 0);
    inject_syscall(child, SYS_setregid, 0, 0);
    inject_syscall(child, SYS_setgroups, 0, 0);

    // Restore original syscall
    if(ptrace(PTRACE_SETREGS, child, NULL, &regs_in) == -1) {
        perror("ptrace");
        exit(1);
    }
    if(wait_for_syscall(child, NULL) == -1) exit(1);

    // At this point, we are *outside* any syscall

    // In theory, we are good to go. BUT, we still need to handle special treatment cases
    // like terminfo (loves this one...)
    if(terminfo_enabled && terminfo_fd != -1) {
        int done = 0;
        int dirty = 0;
        // let's cheat on terminfo's access/open
        while(!done) {
            dirty = 0;

            // wait for syscall entry+exit
            if(wait_for_syscall(child, &regs_in) == -1) break;
            if(wait_for_syscall(child, &regs_in) == -1) break;

            // proxy stat
            if(regs_in.orig_rax == SYS_stat) {
                if(proc_read_string(mem_fd, (char*)regs_in.rdi, path, sizeof(path)) != -1 && proxy_is_ok(path)) {
                    regs_in.rax = proxy_stat(mem_fd, path, (struct stat*)regs_in.rsi);
                    dirty = 1;
                }
            }

            // proxy access
            if(regs_in.orig_rax == SYS_access) {
                if(proc_read_string(mem_fd, (char*)regs_in.rdi, path, sizeof(path)) != -1 && proxy_is_ok(path)) {
                    regs_in.rax = proxy_access(mem_fd, path, (int)regs_in.rsi);
                    dirty = 1;
                }
            }

            // proxy open
            if(regs_in.orig_rax == SYS_open) {
                if(proc_read_string(mem_fd, (char*)regs_in.rdi, path, sizeof(path)) != -1 && proxy_is_ok(path) && terminfo_is_descfile(path)) {
                    // for this one, we cheat: it's already open. Much easier that forwarding the fd or proxying *all* syscalls...
                    regs_in.rax = terminfo_fd;
                    dirty = 1;
                    done = 1;
                }
            }

            // commit
            if(dirty && ptrace(PTRACE_SETREGS, child, NULL, &regs_in) == -1) {
                perror("ptrace");
                exit(1);
            }

            // KEEP THIS: you'll need it when debugging
            /*fprintf(stderr, "%lld(%lld, %lld)=%lld\n",
                regs_in.orig_rax,
                regs_in.rdi,
                regs_in.rsi,
                regs_in.rax
            );*/
        }
        if(wait_for_syscall(child, NULL) == -1) exit(1);
    }

    // exit
    ptrace(PTRACE_DETACH, child, 0, 0);
    waitpid(child, &status, 0);

    if(WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else {
        return 1;
    }
}
