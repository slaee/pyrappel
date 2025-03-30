#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <dlfcn.h>

// implement waitpid
pid_t waitpid(pid_t pid, int *status, int options) {
    pid_t (*real_waitpid)(pid_t pid, int *status, int options) = dlsym(RTLD_NEXT, "waitpid");
    return real_waitpid(pid, status, options);
}
