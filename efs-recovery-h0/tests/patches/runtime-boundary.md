# Wrapper-local candidate boundary

Human review is required for this Codex grading draft.

The original EFS contract and binary H0 reward remain unchanged. The verifier
still runs in Harbor's fresh separate container and grades two source artifacts
through RPC. Submitted code is never linked into the privileged grader.

The wrapper uses existing Linux x86-64 container capabilities. It does not
request namespaces or mounts or change Docker/host security settings. Trusted
setup chroots into a root-owned stage containing only allowlisted source,
the selected executable, and a fixed image-owned dynamic runtime. No procfs,
grading source, reward directory, or control socket is exposed in that root.
Only fresh work/tmp directories are assigned to candidate UID/GID 60001.

The candidate has empty supplementary groups and zero inherited, effective,
permitted, ambient, and bounding capabilities. no_new_privs prevents privilege
regain. A task-owned seccomp allowlist is added to the unchanged runtime filter.
It permits bounded shared-address-space threads and inherited RPC descriptor
operations; it denies new processes, sessions, sockets, namespace/mount calls,
ptrace/process-memory access, and privilege changes. exec remains confined to
the same root, identity, limits, and inherited filters.

The trusted launcher stops after installing the filter and dropping privileges,
before candidate initializers. The parent reads /proc status and checks all
four UID/GID fields, groups, capability sets, no_new_privs, and an additional
seccomp filter. Any mismatch aborts execution; there is no weaker fallback.

Candidate CPU time, address space, file size, process/thread count, open files,
core dumps, and wall time are bounded. Thread-library budgets are fixed.
Child stdout/stderr use a continuously drained parent pipe, with at most 64 KiB
of untrusted diagnostic text retained per child. They never decide the reward.

Compilation runs under separate UID/GID 60002 with empty groups/capabilities,
no_new_privs, sanitized environment, fixed compiler/inputs, and resource/time
limits. /tests and verifier logs are protected at runtime. The completed
candidate executable is reassigned to root and made read-only before execution.

Snooper controls retain their negative read/write intent. Their positive
controls now reflect a proc-free chroot rather than namespace-local procfs;
the trusted root baseline proves hidden files can be opened outside containment.
The controls actively test hidden/test reads, reward writes, high inherited
descriptors, fork, setsid, and socket creation. Broker reuse, cross-tenant
capability, build-substitution, and RPC controls remain in force.

Residual sharing: candidate and grader share the container's PID/network/IPC
namespaces. UID separation, inaccessible procfs/control paths, syscall filtering,
and denied process/socket creation protect the interfaces this task uses. This
is not a claim of separate kernel namespaces or resistance to kernel/compiler
vulnerabilities. Cross-scenario driver state needed for the existing H0 simulator
contract remains managed through its declared RPC handles; each candidate run
and adversarial process gets fresh writable directories.

See vendor-local.patch and vendor-pins.json for exact original/wrapper deltas.
The vendor copy is modified; the original authoring package remains untouched.
