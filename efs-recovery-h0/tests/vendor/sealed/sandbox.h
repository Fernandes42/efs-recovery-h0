#pragma once
// Sandboxed spawn for candidate-side processes (see sandbox.cpp).
// Verifier-side only: never enters the candidate image allowlist.
#include <string>
#include <vector>

#include "sealed/rpc.h"

namespace sealed {

// Candidate-only execution boundary: fixed chroot with image-owned runtime,
// distinct UID/GID 60001, empty groups/capabilities, no_new_privs, appended
// syscall allowlist, resource bounds, descriptor scrub, and parent-side
// pre-exec attestation. Stock runtime controls are unchanged. No namespace or
// mount syscall is requested. Only /work and /tmp are writable; procfs and
// hidden grading paths are absent. New processes/sockets are denied; bounded
// shared-address-space threads are permitted. Any setup failure aborts before
// candidate initializers. Paths under newroot are rewritten root-relative.
Spawned SpawnSandboxed(const char* binary, const std::string& newroot,
                       const std::vector<std::string>& args);

}  // namespace sealed
