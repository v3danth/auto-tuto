#!/usr/bin/env bash
#
# Auto-Color detection harness runner (LAB/VM ONLY).
#
# What: drives the benign emulators and runs each detection, printing PASS/SKIP/FAIL.
# Why:  validates the DETECTION.md rules against reproduced *observables*, never
#       against a real implant.
# Where/how: run inside a throwaway VM/container. Some checks need root (auditd);
#       without it they SKIP. For deterministic CI coverage use the pytest suite
#       in tests/ instead -- this script is for behavioral validation in a lab.
#
set -u

cat <<'BANNER'
============================================================
 Auto-Color detection harness
 WARNING: run only in a throwaway VM/container, never on a
 host you care about. Some checks write to /tmp and spawn
 short-lived processes; they are benign but still lab-only.
============================================================
BANNER

HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "${HERE}/validate.py" "$@"
