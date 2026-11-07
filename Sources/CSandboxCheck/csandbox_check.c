#include "csandbox_check.h"

#ifdef __APPLE__
#include <stddef.h>
#include <sys/types.h>

// Private libsystem_sandbox SPI, declared as WebKit's SandboxSPI.h does. sandbox_check is variadic,
// and on arm64 variadic arguments travel on the stack, so it cannot be called from Swift through a
// fixed-argument declaration; this file is the only caller.
enum sandbox_filter_type {
    SANDBOX_FILTER_NONE,
    SANDBOX_FILTER_PATH,
    SANDBOX_FILTER_GLOBAL_NAME,
};
extern const enum sandbox_filter_type SANDBOX_CHECK_NO_REPORT;
extern int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);

static int normalized(int result) {
    return result == 0 || result == 1 ? result : -1;
}

int agentguard_sandbox_is_sandboxed(int pid) {
    return normalized(sandbox_check(pid, NULL, SANDBOX_FILTER_NONE));
}

int agentguard_sandbox_check_path(int pid, const char *operation, const char *path) {
    return normalized(sandbox_check(pid, operation, (enum sandbox_filter_type)(SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT), path));
}

int agentguard_sandbox_check_global_name(int pid, const char *operation, const char *name) {
    return normalized(sandbox_check(pid, operation, (enum sandbox_filter_type)(SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT), name));
}
#else
int agentguard_sandbox_is_sandboxed(int pid) {
    (void)pid;
    return -1;
}

int agentguard_sandbox_check_path(int pid, const char *operation, const char *path) {
    (void)pid; (void)operation; (void)path;
    return -1;
}

int agentguard_sandbox_check_global_name(int pid, const char *operation, const char *name) {
    (void)pid; (void)operation; (void)name;
    return -1;
}
#endif
