#ifndef CSANDBOX_CHECK_H
#define CSANDBOX_CHECK_H

/// Returns 1 when process `pid` runs under a sandbox profile, 0 when it does not, -1 when unknown.
int agentguard_sandbox_is_sandboxed(int pid);

/// Asks how the sandbox of process `pid` decides `operation` on `path`, without logging a violation.
/// Returns 0 when allowed, 1 when denied, -2 when the path does not exist,
/// -1 when the system cannot answer or the object changes during the query.
int agentguard_sandbox_check_path(int pid, const char *operation, const char *path);

/// The same for an operation filtered by a global Mach service name, e.g. `mach-lookup`.
int agentguard_sandbox_check_global_name(int pid, const char *operation, const char *name);

#endif
