#!/bin/bash
set -o pipefail

# Use this file to install test dependencies and run the tests.
# It will be copied to /tests/test.sh and run from the working directory.

# Fail closed from the first line: any abort below leaves this 0 standing, and
# a report left by an earlier run in this container cannot be graded as if it
# were this one's. Until the reset is done, only system directories are
# searched: the agent can write /usr/local/bin, and an inherited PATH searches
# it first.
CODIMANGO_INHERITED_PATH=${PATH-}
PATH=/usr/sbin:/usr/bin:/sbin:/bin
CODIMANGO_REWARD_BASELINE=
finalize_reward_json() {
local PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ -z "${CODIMANGO_REWARD_BASELINE:-}" ]; then
rm -rf /logs/verifier/reward.txt 2>/dev/null || true
if [ -L /logs/verifier/reward.txt ] || { [ -e /logs/verifier/reward.txt ] && [ ! -f /logs/verifier/reward.txt ]; }; then
  echo "FATAL: could not remove /logs/verifier/reward.txt; refusing to grade" >&2
  exit 1
fi
printf '0' > /logs/verifier/reward.txt 2>/dev/null || true
if [ ! -f /logs/verifier/reward.txt ] || [ -L /logs/verifier/reward.txt ] || [ "$(cat /logs/verifier/reward.txt 2>/dev/null)" != '0' ]; then
  echo "FATAL: could not establish the 0 baseline in /logs/verifier/reward.txt; refusing to grade" >&2
  exit 1
fi
fi
# A reward.json still here would shadow the reward just written: harbor reads
# it first. Copy the reward into it.
# Remove a directory or symlink recreated during the tests without following it.
if [ -e /logs/verifier/reward.json ] || [ -L /logs/verifier/reward.json ]; then
  if [ ! -f /logs/verifier/reward.json ] || [ -L /logs/verifier/reward.json ]; then
    # reward.json FIRST: harbor reads it in preference to reward.txt, so one staged
# during the agent's turn would outrank every verdict written below.
rm -rf /logs/verifier/reward.json 2>/dev/null || true
if [ -e /logs/verifier/reward.json ] || [ -L /logs/verifier/reward.json ]; then
  if [ ! -f /logs/verifier/reward.json ] || [ -L /logs/verifier/reward.json ]; then
    echo "FATAL: /logs/verifier/reward.json could not be removed; refusing to grade" >&2
    exit 1
  fi
  printf '{"reward": 0.0}' > /logs/verifier/reward.json 2>/dev/null || true
  if [ "$(cat /logs/verifier/reward.json 2>/dev/null)" != '{"reward": 0.0}' ]; then
    echo "FATAL: /logs/verifier/reward.json could not be removed or zeroed; refusing to grade" >&2
    exit 1
  fi
fi
  fi
fi
if [ -f /logs/verifier/reward.json ] && [ ! -L /logs/verifier/reward.json ]; then
  CODIMANGO_FINAL_REWARD=0
  if [ -f /logs/verifier/reward.txt ] && [ ! -L /logs/verifier/reward.txt ]; then
    CODIMANGO_FINAL_REWARD=$(cat /logs/verifier/reward.txt 2>/dev/null)
  fi
  # Read it as harbor and TBR do, with Python's float(), and rewrite it as a JSON
  # number with the same digits; anything else becomes 0. Two exponent digits at
  # most keep it finite.
  CODIMANGO_FINAL_REWARD=${CODIMANGO_FINAL_REWARD#"${CODIMANGO_FINAL_REWARD%%[![:space:]]*}"}
  CODIMANGO_FINAL_REWARD=${CODIMANGO_FINAL_REWARD%"${CODIMANGO_FINAL_REWARD##*[![:space:]]}"}
  CODIMANGO_REWARD_NUMBER='^([+-]?)([0-9]*)(\.([0-9]*))?([eE][+-]?[0-9]{1,2})?$'
  CODIMANGO_JSON_REWARD=0.0
  if [[ "$CODIMANGO_FINAL_REWARD" =~ $CODIMANGO_REWARD_NUMBER ]] && [ -n "${BASH_REMATCH[2]}${BASH_REMATCH[4]}" ]; then
    CODIMANGO_REWARD_INT=${BASH_REMATCH[2]#"${BASH_REMATCH[2]%%[!0]*}"}
    CODIMANGO_JSON_REWARD="${BASH_REMATCH[1]#+}${CODIMANGO_REWARD_INT:-0}"
    if [ -n "${BASH_REMATCH[4]}" ]; then
      CODIMANGO_JSON_REWARD="$CODIMANGO_JSON_REWARD.${BASH_REMATCH[4]}"
    elif [ -z "${BASH_REMATCH[5]}" ]; then
      CODIMANGO_JSON_REWARD="$CODIMANGO_JSON_REWARD.0"
    fi
    CODIMANGO_JSON_REWARD="$CODIMANGO_JSON_REWARD${BASH_REMATCH[5]}"
  fi
  echo "NOTE: /logs/verifier/reward.json is still present at exit; copying the reward from reward.txt into it" >&2
  printf '{"reward": %s}' "$CODIMANGO_JSON_REWARD" > /logs/verifier/reward.json 2>/dev/null || true
  if [ "$(cat /logs/verifier/reward.json 2>/dev/null)" != "$(printf '{"reward": %s}' "$CODIMANGO_JSON_REWARD")" ]; then
    echo "FATAL: could not synchronize reward.json with reward.txt" >&2
    exit 1
  fi
fi
}
trap finalize_reward_json EXIT
mkdir -p /logs/verifier || exit 1
# Runtime ownership/mode repair also covers Harbor's writable log mount.
# The candidate and compiler identities must not own any trusted path.
if [ "$(id -u)" != 0 ] || [ "$(stat -c %u /tests)" != 0 ] || \
   [ "$(stat -c %u /logs/verifier)" = 60001 ] || \
   [ "$(stat -c %u /logs/verifier)" = 60002 ]; then
  echo "FATAL: trusted path ownership is unsuitable" >&2
  exit 1
fi
chmod 0700 /tests || exit 1
chmod go-rwx /logs/verifier || exit 1
# reward.json FIRST: harbor reads it in preference to reward.txt, so one staged
# during the agent's turn would outrank every verdict written below.
rm -rf /logs/verifier/reward.json 2>/dev/null || true
if [ -e /logs/verifier/reward.json ] || [ -L /logs/verifier/reward.json ]; then
  if [ ! -f /logs/verifier/reward.json ] || [ -L /logs/verifier/reward.json ]; then
    echo "FATAL: /logs/verifier/reward.json could not be removed; refusing to grade" >&2
    exit 1
  fi
  printf '{"reward": 0.0}' > /logs/verifier/reward.json 2>/dev/null || true
  if [ "$(cat /logs/verifier/reward.json 2>/dev/null)" != '{"reward": 0.0}' ]; then
    echo "FATAL: /logs/verifier/reward.json could not be removed or zeroed; refusing to grade" >&2
    exit 1
  fi
fi
rm -rf /logs/verifier/reward.txt 2>/dev/null || true
if [ -L /logs/verifier/reward.txt ] || { [ -e /logs/verifier/reward.txt ] && [ ! -f /logs/verifier/reward.txt ]; }; then
  echo "FATAL: could not remove /logs/verifier/reward.txt; refusing to grade" >&2
  exit 1
fi
printf '0' > /logs/verifier/reward.txt 2>/dev/null || true
if [ ! -f /logs/verifier/reward.txt ] || [ -L /logs/verifier/reward.txt ] || [ "$(cat /logs/verifier/reward.txt 2>/dev/null)" != '0' ]; then
  echo "FATAL: could not establish the 0 baseline in /logs/verifier/reward.txt; refusing to grade" >&2
  exit 1
fi
CODIMANGO_REWARD_BASELINE=1
# Diagnostics are for this run only, including early submission failures.
rm -f /logs/verifier/efs-harness.log /logs/verifier/efs-verdict.env \
  /logs/verifier/efs-evidence.json
rm -f /logs/verifier/ctrf.json
if [ -e /logs/verifier/ctrf.json ] || [ -L /logs/verifier/ctrf.json ]; then
  rm -rf /logs/verifier/ctrf.json 2>/dev/null || true
fi
if [ -e /logs/verifier/ctrf.json ] || [ -L /logs/verifier/ctrf.json ]; then
  echo "FATAL: a stale /logs/verifier/ctrf.json could not be removed; refusing to grade" >&2
  exit 1
fi
# The grader finds uv, pytest and the python of the image on the inherited PATH.
PATH=$CODIMANGO_INHERITED_PATH

# One temp directory, removed on every exit, so nothing is left behind in a
# container that persists into the next step's agent turn.
GRADER_TMP=
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 141' PIPE
trap 'exit 143' TERM
trap 'rm -rf "$GRADER_TMP"; finalize_reward_json' EXIT
GRADER_TMP=$(mktemp -d) || exit 1

# ---- EFS H0 grading pipeline (sealed RPC split) ----
# The fresh verifier owns grading, oracle, and counters. Candidate code is
# compiled under UID 60002, then runs only in the fixed chroot under UID 60001,
# without groups/capabilities, with no_new_privs and an additional syscall
# allowlist. The trusted parent attests the pre-exec boundary. The runtime's
# existing controls are unchanged; namespace creation and mounts are not used.
# Read-only staging excludes hidden sources; only work/tmp are writable.
# Grading accepts verifier-owned evidence, never candidate stdout or markers.
# Boundary setup failure has no less-restricted fallback.
EFS_VER=/tests/vendor
EFS_SUB=/app
EFS_WORK="$GRADER_TMP/efs-work"
EFS_VERDICT_FILE="$GRADER_TMP/efs-verdict.env"
EFS_HARNESS=/tests/harness-build/efs_harness
export EFS_VERDICT_FILE

# Only test.sh writes FAIL/INFRA here. PASS is written exclusively by
# the harness binary (separate process, root-owned file the sandboxed
# image cannot reach). test.sh can never upgrade a verdict.
efs_infra() {
  printf 'EFS_VERDICT=INFRA\nEFS_DETAIL=%s\nEFS_CHECKS=0\nEFS_FAILED=0\n' "$1" \
    > "$EFS_VERDICT_FILE"
}
efs_fail() {
  printf 'EFS_VERDICT=FAIL\nEFS_DETAIL=%s\nEFS_CHECKS=0\nEFS_FAILED=0\n' "$1" \
    > "$EFS_VERDICT_FILE"
}

# 0. Submitted sources must exist (docker cp lands them at the same
#    absolute paths the agent used).
if [ ! -f "$EFS_SUB/candidate/src/efs_impl.h" ] || \
   [ ! -f "$EFS_SUB/candidate/src/efs_impl.cpp" ]; then
  echo "EFS: missing submitted sources under $EFS_SUB/candidate/src" >&2
  efs_infra missing-submission
else
  # 1. Static anti-cheat scan on SUBMITTED sources (12 SuiteAntiCheat
  #    patterns + 8 runtime-extraction patterns: the sealed image links
  #    no oracle, but a driver reaching for dlsym/dlopen//proc/ptrace/
  #    process-spawn is a cheat signal, not honest code -- the reference
  #    and starter contain zero of them). Fail closed before any build.
  EFS_SCAN_HIT=""
  for pat in 'trusted/' 'reference/' 'admin_' 'SetDurableImage' \
      'RevokeEpoch' 'NonceUseCount' 'SetFailurePlan' 'grader/' \
      'dlsym' 'dlopen' '/proc/' 'ptrace' 'system(' 'popen(' 'execv' \
      'socket('; do
    if grep -qF "$pat" "$EFS_SUB/candidate/src/efs_impl.h" \
        "$EFS_SUB/candidate/src/efs_impl.cpp" 2>/dev/null; then
      EFS_SCAN_HIT="$EFS_SCAN_HIT $pat"
    fi
  done
  if [ -n "$EFS_SCAN_HIT" ]; then
    echo "EFS: anti-cheat scan hit:$EFS_SCAN_HIT" >&2
    efs_fail "anticheat$EFS_SCAN_HIT"
  elif [ ! -x "$EFS_HARNESS" ]; then
    echo "EFS: harness missing at $EFS_HARNESS" >&2
    efs_infra missing-harness
  else
    # 2. Frozen vendor gate: every non-impl file must exist and match
    #    the pinned manifest (impl files are the designated untrusted
    #    input and must merely exist). A drifted verifier tree fails
    #    here, before any submitted code is touched.
    if ! python3 - "$EFS_VER/packaging/source_manifest.json" "$EFS_VER" \
        <<'EOF' >"$GRADER_TMP/efs-vendor-gate.log" 2>&1
import hashlib, json, sys
manifest, ver = sys.argv[1], sys.argv[2]
m = json.load(open(manifest))
bad = []
for e in m["files"]:
    p = e["path"]
    if p in ("candidate/src/efs_impl.h", "candidate/src/efs_impl.cpp"):
        continue
    try:
        h = hashlib.sha256(open(ver + "/" + p, "rb").read()).hexdigest()
    except OSError:
        bad.append(p + " (missing)")
        continue
    if h != e["sha256"]:
        bad.append(p)
if bad:
    print("vendor drift: " + ",".join(bad))
    sys.exit(1)
print("vendor frozen-ok")
EOF
    then
      echo "EFS: vendor frozen gate failed:" >&2
      cat "$GRADER_TMP/efs-vendor-gate.log" >&2 || true
      efs_infra vendor-drift
    else
      # 3. Grade via the harness. It copies the submission into the
      #    staging input, stages/builds/spawns the sandboxed image,
      #    serves RPCs, runs the matrix + adversarial set verifier-side,
      #    and writes the verdict file itself (0600 root). Candidate code
      #    executes only inside the sandbox, as an unprivileged user.
      if "$EFS_HARNESS" "$EFS_VER" \
          "$EFS_SUB/candidate/src/efs_impl.h" \
          "$EFS_SUB/candidate/src/efs_impl.cpp" \
          "$EFS_VER/profiles/H0.json" "$EFS_VER/profiles/budgets.json" \
          "$EFS_WORK" "$EFS_VERDICT_FILE" \
          >"$GRADER_TMP/efs-harness.log" 2>&1; then
        EFS_HRC=0
      else
        EFS_HRC=$?
      fi
      # Preserve this run's first-hand diagnostics before private scratch is
      # removed. These are verifier-owned outputs, never candidate claims.
      cat "$GRADER_TMP/efs-harness.log"
      cp "$GRADER_TMP/efs-harness.log" /logs/verifier/efs-harness.log
      if [ -f "$EFS_VERDICT_FILE" ]; then
        cp "$EFS_VERDICT_FILE" /logs/verifier/efs-verdict.env
      fi
      if [ -f "$EFS_WORK/evidence/evidence_H0_sealed-candidate.json" ]; then
        cp "$EFS_WORK/evidence/evidence_H0_sealed-candidate.json" \
          /logs/verifier/efs-evidence.json
      fi
      # 4. Authenticate the verdict file: it must parse with strict
      #    finite case accounting, or the run is INFRA (a missing or
      #    malformed file can never read as a pass).
      EFS_AUTH_OK=0
      if [ -f "$EFS_VERDICT_FILE" ]; then
        if ! python3 - "$EFS_VERDICT_FILE" <<'EOF' >"$GRADER_TMP/efs-auth.log" 2>&1
import re, sys
kv = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if "=" in line:
        k, _, v = line.partition("=")
        kv[k.strip()] = v.strip()
v, d = kv.get("EFS_VERDICT"), kv.get("EFS_DETAIL")
c, f = kv.get("EFS_CHECKS"), kv.get("EFS_FAILED")
if v not in ("PASS", "FAIL", "INFRA"):
    sys.exit("bad verdict")
if not d or len(d) > 200 or not re.fullmatch(r"[A-Za-z0-9:_.+ \-]+", d):
    sys.exit("bad detail")
for name, val in (("checks", c), ("failed", f)):
    if val is None or not re.fullmatch(r"[0-9]{1,9}", val):
        sys.exit("bad " + name)
print("auth ok: %s %s checks=%s failed=%s" % (v, d, c, f))
EOF
        then
          echo "EFS: verdict file failed authentication:" >&2
          cat "$GRADER_TMP/efs-auth.log" >&2 || true
        else
          EFS_AUTH_OK=1
        fi
      else
        echo "EFS: verdict file missing after harness rc=$EFS_HRC" >&2
      fi
      if [ "$EFS_AUTH_OK" != 1 ]; then
        efs_infra "verdict-unauthenticated-rc=$EFS_HRC"
      elif [ "$EFS_HRC" != 0 ]; then
        # Harness already wrote FAIL/INFRA with evidence-backed detail;
        # a nonzero exit with a PASS file is a contradiction -> INFRA.
        if grep -q "^EFS_VERDICT=PASS$" "$EFS_VERDICT_FILE" 2>/dev/null; then
          echo "EFS: harness rc=$EFS_HRC contradicts PASS file" >&2
          efs_infra "pass-exit-contradiction"
        fi
      fi
    fi
  fi
fi
# EFS pipeline ends. test_outputs.py asserts on $EFS_VERDICT_FILE
# (PASS + strict-success detail + checks>=250 + failed==0);
# pytest collection/execution below is unchanged.


# The verifier supplies all pytest options. Inherited options must not select
# the same incomplete suite in both collection and execution. PYTHONPATH is
# cleared too: an inherited entry pointing at agent-written code could shadow
# pytest itself. Add the paths your tests import from in tests/conftest.py.
unset PYTEST_ADDOPTS PYTEST_PLUGINS PYTHONPATH PYTHONHOME

GRADER_PYTHON=(/opt/verifier-venv/bin/python)
SCORER_PYTHON=(/opt/verifier-venv/bin/python)

PYTEST_BOOTSTRAP='import os, sys
if sys.path and sys.path[0] == "":
    del sys.path[0]
import pytest
rc = 1
try:
    rc = int(pytest.main(sys.argv[1:]))
except BaseException:
    import traceback
    traceback.print_exc()
finally:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass
    try:
        with open(os.environ["CODIMANGO_PYTEST_RC_FILE"], "w") as fh:
            fh.write(str(rc))
    except Exception:
        pass
    os._exit(rc)'
PYTEST_HARDENING=(-c /dev/null --rootdir=/tests --confcutdir=/tests -p no:cacheprovider)
# The test files to grade. Collection and execution both read this list, so add
# a file here, never to only one of the two commands.
TEST_TARGETS=(/tests/test_outputs.py)

# Fix the expected tests BEFORE the run. -p no:warnings keeps the warnings
# summary from printing node-ids that would inflate the list.
CODIMANGO_PYTEST_RC_FILE="$GRADER_TMP/collect.rc" "${GRADER_PYTHON[@]}" -c "$PYTEST_BOOTSTRAP" \
  --collect-only -q -p no:warnings "${PYTEST_HARDENING[@]}" "${TEST_TARGETS[@]}" \
  >"$GRADER_TMP/collect.out" 2>"$GRADER_TMP/collect.err"
COLLECT_STATUS=$(cat "$GRADER_TMP/collect.rc" 2>/dev/null)
# 0 collected something, 5 collected nothing (graded 0 below). Anything else is
# a broken collection, which must not read as an empty suite.
if [ "$COLLECT_STATUS" != 0 ] && [ "$COLLECT_STATUS" != 5 ]; then
  echo "FATAL: collection failed (status ${COLLECT_STATUS:-unknown}); refusing to grade" >&2
  sed -n '1,40p' "$GRADER_TMP/collect.out" "$GRADER_TMP/collect.err" >&2
  exit 1
fi
# Ids come from stdout only; stderr carries what the tested code prints on import.
grep -E '^[^[:space:]]+::[^[:space:]]' "$GRADER_TMP/collect.out" | sort -u > "$GRADER_TMP/collected-ids"

# CTRF produces a standard test report in JSON format, which is what the reward
# below is computed from.
CODIMANGO_PYTEST_RC_FILE="$GRADER_TMP/run.rc" "${GRADER_PYTHON[@]}" -c "$PYTEST_BOOTSTRAP" \
  --ctrf /logs/verifier/ctrf.json "${PYTEST_HARDENING[@]}" "${TEST_TARGETS[@]}" -rA

# Grade from the CTRF report, never from a process exit status: anything running
# in this container can force a process to exit 0 -- two lines in a
# sitecustomize.py on sys.path are enough -- and the verifier stores reward.txt
# verbatim without re-checking. -S keeps a planted sitecustomize.py from running
# here, -I keeps a planted json.py in the working directory from being imported
# in place of the stdlib, and the parser writes the reward file itself rather
# than handing its own exit code back to the shell.
CODIMANGO_COLLECTED_IDS="$GRADER_TMP/collected-ids" CODIMANGO_PYTEST_STATUS="$(cat "$GRADER_TMP/run.rc" 2>/dev/null)" "${SCORER_PYTHON[@]}" -I -S - /logs/verifier/ctrf.json /logs/verifier/reward.txt <<'PY'
import json
import os
import sys
import tempfile

CTRF, REWARD = sys.argv[1], sys.argv[2]
# Set only by tracks whose test.sh pins the run; absent, the summary decides.
collected_ids_path = os.environ.get('CODIMANGO_COLLECTED_IDS')
pytest_status = os.environ.get('CODIMANGO_PYTEST_STATUS')


def function_id(node_id):
    node_id = node_id.strip()
    cut = node_id.find('[')
    if cut != -1 and node_id.endswith(']'):
        node_id = node_id[:cut]
    return node_id


def test_count(summary, name, required=False):
    value = summary[name] if required else summary.get(name, 0)
    # bool is an int subclass; numeric strings and fractions are not counts.
    if type(value) is not int or value < 0:
        raise ValueError(f'{name} must be a non-negative integer')
    return value


ran = []
try:
    with open(CTRF) as fh:
        results = json.load(fh)['results']
    summary = results['summary']
    total = test_count(summary, 'tests', required=True)
    counts = {name: test_count(summary, name, required=(name == 'passed'))
              for name in ('passed', 'failed', 'skipped', 'pending', 'other')}
    if sum(counts.values()) != total:
        raise ValueError('summary counts do not add up to tests')
    bad = counts['failed'] + counts['pending'] + counts['other']
    passed = counts['passed']
    # Skips and xfails do not fail a task: pytest exits 0 on them, and CTRF
    # counts both under 'skipped', so requiring passed == total would score 0
    # for any suite containing a single skip. Requiring passed > 0 still
    # refuses a suite that skipped everything, which is otherwise free reward.
    ok = total > 0 and bad == 0 and passed > 0
    if 'tests' in results:
        tests = results['tests']
        if not isinstance(tests, list) or len(tests) != total:
            raise ValueError('test entries do not match the summary total')
        actual_counts = dict.fromkeys(counts, 0)
        for test in tests:
            if not isinstance(test, dict):
                raise ValueError('test entries must be objects')
            name, status = test.get('name'), test.get('status')
            if not isinstance(name, str) or not name.strip():
                raise ValueError('test names must be non-empty strings')
            if not isinstance(status, str) or status not in actual_counts:
                raise ValueError('unknown test status')
            ran.append(name)
            actual_counts[status] += 1
        if actual_counts != counts:
            raise ValueError('test entries disagree with the summary')
except Exception as exc:
    print(f'reward 0: cannot read {CTRF}: {exc}')
    ok = False

if ok and (collected_ids_path is not None or pytest_status is not None) and pytest_status != '0':
    print(f'reward 0: pytest exited {pytest_status or "without a status"}')
    ok = False

if ok and collected_ids_path is not None:
    try:
        with open(collected_ids_path) as fh:
            collected = {function_id(line) for line in fh if line.strip()}
    except OSError:
        collected = set()
    executed = {function_id(name) for name in ran if name.strip()}
    if not collected:
        # Missing identity evidence scores 0 rather than falling back to a
        # count: a count is exactly what running cheap cases in place of the
        # expensive ones clears.
        print('reward 0: the collected test ids are unavailable, so the run '
              'cannot be shown to be complete')
        ok = False
    elif collected != executed:
        print(f'reward 0: the tests that ran differ from the tests collected; '
              f'missing={sorted(collected - executed)[:10]} '
              f'unexpected={sorted(executed - collected)[:10]}')
        ok = False

with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(REWARD),
                                 prefix='.reward-', delete=False) as fh:
    pending_reward = fh.name
    fh.write('1' if ok else '0')
try:
    # Publish a complete file, replacing a symlink instead of following it.
    os.chmod(pending_reward, 0o644)
    os.replace(pending_reward, REWARD)
finally:
    if os.path.exists(pending_reward):
        os.unlink(pending_reward)
PY
