#!/bin/sh
# Fixed-input verifier-side rebuild (F1-hardened).
#
# The old recipe ran `cmake -S <submission>` — trusting the submission's
# CMakeLists.txt, which executes arbitrary commands at configure time
# with grader permissions. This recipe never configures, builds, or
# executes anything from the submission tree. It copies ONLY the two
# allowlisted implementation files out of the submission into a fresh
# staging dir populated from the FROZEN verifier tree, verifies the
# frozen inputs against source_manifest.json, and builds with the
# verifier's pinned toolchain and flags.
#
# Usage: build_recipe.sh <submission_root> <verifier_root> <work_root>
# Result: <work_root>/build/{efs_candidate,public_tests}; public_tests
# runs the smoke + visible repro against the SUBMITTED implementation.
set -eu

SUB="${1:?usage: build_recipe.sh <submission_root> <verifier_root> <work_root>}"
VER="${2:?usage: build_recipe.sh <submission_root> <verifier_root> <work_root>}"
WORK="${3:?usage: build_recipe.sh <submission_root> <verifier_root> <work_root>}"

# 1. Submission allowlist: exactly the two implementation files. Any
# other submission content (CMakeLists, scripts, headers, binaries) is
# ignored — it can neither influence nor execute in this build.
for f in candidate/src/efs_impl.h candidate/src/efs_impl.cpp; do
  if [ ! -f "$SUB/$f" ]; then
    echo "build_recipe: submission missing $f" >&2
    exit 2
  fi
done
if [ -n "$(find "$SUB/candidate/src" -type f ! -name 'efs_impl.*' -print -quit)" ]; then
  echo "build_recipe: submission has non-allowlisted files" >&2
  exit 2
fi

# 2. Fresh staging from the frozen verifier tree (never from $SUB).
# Stage the full build closure (CMakeLists, headers, trusted + reference
# + grader + sealed + public-tests sources, docs, profiles): everything
# the configure step needs. Build outputs, reports, and prior staging
# are excluded. The submission contributes ONLY the two implementation
# files in step 4, after the frozen check.
rm -rf "$WORK/stage"
mkdir -p "$WORK/stage"
(cd "$VER" && find CMakeLists.txt include trusted reference grader sealed \
  public-tests docs profiles candidate/README.md -type f) | while IFS= read -r f; do
  mkdir -p "$WORK/stage/$(dirname "$f")"
  cp "$VER/$f" "$WORK/stage/$f"
done
mkdir -p "$WORK/stage/candidate/src"

# 3. Frozen-input check: every staged verifier file must hash-match the
# manifest pinned at authoring time. A tampered verifier tree fails here.
# Then the two submission impl files overwrite the staged copies: they
# are the untrusted input by design and are excluded from the check.
if ! python3 - "$VER/packaging/source_manifest.json" "$WORK/stage" <<'EOF'
import hashlib, json, sys
manifest, stage = sys.argv[1], sys.argv[2]
m = json.load(open(manifest))
bad = []
for e in m["files"]:
    p = e["path"]
    # Submission impl files are the untrusted input by design.
    if p in ("candidate/src/efs_impl.h", "candidate/src/efs_impl.cpp"):
        continue
    try:
        h = hashlib.sha256(open(stage + "/" + p, "rb").read()).hexdigest()
    except OSError:
        continue  # not a build input (reports/packaging); skip
    if h != e["sha256"]:
        bad.append(p)
if bad:
    print("build_recipe: frozen-input mismatch: " + ",".join(bad))
    sys.exit(1)
EOF
then
  exit 3
fi
cp "$SUB/candidate/src/efs_impl.h" "$SUB/candidate/src/efs_impl.cpp" \
  "$WORK/stage/candidate/src/"

# 4. Pinned toolchain, fixed flags. No submission-controlled input beyond
# the two compiled TUs (compiled as data; the compiler reads them, and
# nothing in them executes at build time).
cmake -S "$WORK/stage" -B "$WORK/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=20
cmake --build "$WORK/build" --target efs_candidate public_tests
"$WORK/build/public_tests"
