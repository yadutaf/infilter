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

// syscall introspection
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>

#define STAGE_HOST 1
#define STAGE_CONTAINER 2

const char* ld_path_prefix = "/lib/x86_64-linux-gnu/ld+";
struct namespace {
    const char* proc_name;
    int flag;
    int stage;
    int fd;
};

struct namespace namespaces[] = {
    {"pid",  CLONE_NEWPID,  1, -1}, // PID actually changes on fork, hence stage 1
    {"ipc",  CLONE_NEWIPC,  1, -1},
    {"net",  CLONE_NEWNET,  1, -1},
    {"uts",  CLONE_NEWUTS,  1, -1},
    {"mnt",  CLONE_NEWNS,   2, -1},
    {"user", CLONE_NEWUSER, 2, -1},
    {NULL, 0, 0, 0},
};

// terminfo special case
char terminfo_suffix[255] = {0};
const char* terminfo_lib_fullpath = "/lib/x86_64-linux-gnu/libtinfo.so.5";
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

int proc_open_mem(pid_t pid) {
    char path[255];
    int fd;

    // open memory
    if(snprintf(path, 255, "/proc/%d/mem", pid) < 0) {
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

int in_ld(unsigned long long int addr, unsigned int pid) {
    static unsigned long long int begin_addr = 0;
    static unsigned long long int end_addr = 0;

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

                // is it out target ?
                if(index == 5) {
                    if(str_prefix_match(ld_path_prefix, field) != 1) {
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
    char path[255];
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
    char path[255];
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
        perror("ptrace");
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

pid_t create_child(char **argv) {
    pid_t child = fork();

    if(child == -1) {
        perror("fork");
        return 1;
    }
    
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        execvp(*argv, argv);
        perror("exec");
        exit(1);
    }
    return child;
}

int main(int argc, char** argv) { 
    // parent vars
    int mem_fd;
    int status;
    int insyscall = 0;
    pid_t pid, child;
    char path[255];
    struct user_regs_struct regs;
    struct user_regs_struct regs_in;
    struct user_regs_struct regs_out;
    struct namespace* ns;

    // special/favor treatment: terminfo
    int terminfo_enabled = 0;
    int terminfo_fd = 0;

    /* Parse arguments */
    if(argc <= 2) {
        fprintf(stderr, "Usage: %s PID [command...]\n", argv[0]);
        exit(1);
    }

    pid = atoi(argv[1]);
    if(!pid) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        exit(1);
    }

    /* Open + leak fds */
    for(ns = namespaces; ns->proc_name; ns++) {
        // grab a fd to the ns
        if(snprintf(path, 255, "/proc/%d/ns/%s", pid, ns->proc_name) < 0) {
            perror("snprintf");
            exit(1);
        }

        ns->fd = open(path, O_RDONLY);
        if(ns->fd < 0) {
            perror("open");
            exit(1);
        }
    }
    terminfo_fd = terminfo_open();

    // Mount all stage 1 namespaces now + close fds
    for(ns = namespaces; ns->proc_name; ns++) {
        if(ns->stage != STAGE_HOST)
            continue;

        if(setns(ns->fd, ns->flag) == -1) {
            perror("setns");
            return 1;
        }

        close(ns->fd);
        ns->fd = -1;
    }

    // create child
    child = create_child(argv+2);

    // Close any leaked fd at this stage
    for(ns = namespaces; ns->proc_name; ns++) {
        close(ns->fd);
    }
    close(terminfo_fd);

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
        if(!in_ld(regs_in.rip, child)) break;

        // detect special treatments
        if(regs_in.orig_rax == SYS_open) {
            if(terminfo_need(mem_fd, (char*)regs_in.rdi)) terminfo_enabled=1;
        }
        if(wait_for_syscall(child, &regs_in) == -1) break;
    }

    // At this point, we are *inside* a syscall

    // Switch child namespaces + cleanup
    for(ns = namespaces; ns->proc_name; ns++) {
        if(ns->stage != STAGE_CONTAINER)
            continue;
       
        if(inject_setns(child, ns->fd, ns->flag) == -1) {
            perror("inject_setns");
            exit(1);
        }

        if(inject_close(child, ns->fd) == -1) {
            perror("inject_close");
            exit(1);
        }

    }

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

    return status;
}

