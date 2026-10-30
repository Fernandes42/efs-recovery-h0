"""Pytest reward assertions for efs/efs-recovery-h0.

Mechanical transcription of the canonical reward contract (see
WRAPPER_NOTES.md): the harness grades the submitted sources in a
sandboxed child image BEFORE pytest runs, writing $EFS_VERDICT_FILE
itself (0600 root; the sandboxed image cannot reach it). These tests
assert on that file. Collection is side-effect-free (the file is read
inside test bodies, never at import).

Reward mapping (binary): all collected tests pass -> 1, else 0.
  - Green (fixed driver): EFS_VERDICT=PASS (sealed STRICT_SUCCESS).
  - Red (faulty starter): EFS_VERDICT=FAIL -> tests fail -> 0.
  - Broken submission (no verdict): EFS_VERDICT=INFRA/FAIL -> 0.

Model Role note: grading content requires human review and ownership
(Josh). This file transcribes the existing oracle verdict verbatim
(STRICT_SUCCESS on H0) and adds no new assertion semantics.
"""

import os
import re


def _verdict():
    path = os.environ.get("EFS_VERDICT_FILE", "")
    if not path or not os.path.isfile(path):
        raise AssertionError(
            "verdict file missing (EFS_VERDICT_FILE=%r); "
            "the grading pipeline did not complete" % (path,))
    kv = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k.strip()] = v.strip()
    return kv


def test_h0_strict_success():
    """The submitted driver earns STRICT_SUCCESS on the sealed H0 matrix."""
    kv = _verdict()
    assert kv.get("EFS_VERDICT") == "PASS", (
        "expected PASS, got %r (detail=%r)"
        % (kv.get("EFS_VERDICT"), kv.get("EFS_DETAIL")))
    assert kv.get("EFS_DETAIL") == "strict-success", (
        "verdict PASS without strict-success detail (detail=%r)"
        % (kv.get("EFS_DETAIL"),))


def test_h0_case_accounting():
    """The verdict carries finite, matching case accounting."""
    kv = _verdict()
    for name in ("EFS_CHECKS", "EFS_FAILED"):
        val = kv.get(name)
        assert val is not None and re.fullmatch(r"[0-9]{1,9}", val), (
            "nonfinite case accounting %s=%r" % (name, val))
    checks, failed = int(kv["EFS_CHECKS"]), int(kv["EFS_FAILED"])
    assert checks >= 250, (
        "truncated matrix: checks=%d (expected >= 250)" % checks)
    assert failed == 0, (
        "failed=%d contradicts strict success" % failed)


def test_no_infrastructure_error():
    """The run produced a real grading verdict, not an infra failure."""
    kv = _verdict()
    assert kv.get("EFS_VERDICT") in ("PASS", "FAIL"), (
        "no grading verdict (detail=%r); infrastructure failure scores 0"
        % (kv.get("EFS_DETAIL"),))
