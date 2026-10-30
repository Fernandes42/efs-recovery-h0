#!/bin/bash
# Oracle replay for efs/efs-recovery-h0.
#
# Copies the vetted oracle sources (ported reference, pinned revision)
# over the agent's candidate files, then rebuilds and runs the public
# signal. Runs in the AGENT container (/app is the bundle root).
# Human review required before this oracle is authoritative (Model Role
# rules); the port was proven STRICT_SUCCESS 291/291 via the
# fixed-input recipe path on the pinned revision.
set -eu
TASK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cp "$TASK_DIR/solution/efs_impl.h" /app/candidate/src/efs_impl.h
cp "$TASK_DIR/solution/efs_impl.cpp" /app/candidate/src/efs_impl.cpp
cmake --build /app/build
/app/build/public_tests
