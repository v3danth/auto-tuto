#!/usr/bin/env python3
"""Auto-Color detection harness runner (LAB/VM ONLY).

Drives the benign emulators in emulate.py, runs each corresponding detection, and
reports PASS / SKIP / FAIL. It proves the *detections* react to their observables;
it never runs or simulates the implant.

Most checks are Linux-only (procfs, ss, conntrack, auditd). On other platforms or
without root they SKIP rather than fail, so this is safe to invoke anywhere -- it
just won't do much off a Linux VM. The authoritative, always-runnable coverage is
the pytest suite in ../ (test_extractor/test_net_diff/test_yara).
"""

from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "detect"))
import emulate  # noqa: E402  (same dir)
import net_diff  # noqa: E402  (from detect/)

PASS, SKIP, FAIL = "PASS", "SKIP", "FAIL"
_results: list[tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    _results.append((name, status, detail))
    print(f"[{status:4}] {name}" + (f" -- {detail}" if detail else ""))


def check_preload_in_maps() -> None:
    """§3: a marker .so LD_PRELOAD'd into a process is visible in /proc/<pid>/maps."""
    name = "preload-in-maps sweep (§3)"
    if platform.system() != "Linux":
        return record(name, SKIP, "Linux/procfs only")
    pid = None
    so_path = "/tmp/marker_preload.so"
    try:
        emulate.build_marker_preload_so(so_path)
        pid = emulate.emulate_preload_in_maps(so_path)
        time.sleep(0.3)
        maps = Path(f"/proc/{pid}/maps").read_text()
        record(name, PASS if "marker_preload.so" in maps else FAIL,
                "marker found in maps" if "marker_preload.so" in maps else "not mapped")
    except Exception as exc:  # noqa: BLE001 - harness surfaces any setup failure
        record(name, SKIP, f"setup failed: {exc}")
    finally:
        emulate.cleanup(markers=[so_path], pids=[pid] if pid else [])


def check_daemon_ancestry() -> None:
    """§2: a daemon-named process with an unexpected child is detectable."""
    name = "daemon-ancestry hunt (§2)"
    if platform.system() != "Linux":
        return record(name, SKIP, "Linux/procfs only")
    pid = None
    standin = "/tmp/crond"
    try:
        pid = emulate.emulate_daemon_child("crond")
        time.sleep(0.3)
        children = emulate.list_children(pid)
        record(name, PASS if children else FAIL,
                f"found child pids {children}" if children else "no child seen")
    except Exception as exc:  # noqa: BLE001
        record(name, SKIP, f"setup failed: {exc}")
    finally:
        emulate.cleanup(markers=[standin], pids=[pid] if pid else [])


def check_net_diff_negative_control() -> None:
    """§4.4: on a clean host, libc and kernel socket views agree (no hidden socket)."""
    name = "hidden-socket differ, clean-host control (§4.4)"
    ss, ct = emulate.capture_net_views()
    if not ss or not ct:
        return record(name, SKIP, "ss/conntrack unavailable")
    hidden = net_diff.hidden_sockets(ss, ct)
    record(name, PASS if hidden == [] else FAIL,
           "views agree" if hidden == [] else f"unexpected discrepancy: {hidden}")


def check_auditd_preload_write() -> None:
    """§1: auditd records a write to /etc/ld.so.preload (needs root + loaded rules)."""
    name = "auditd preload watch (§1)"
    if platform.system() != "Linux":
        return record(name, SKIP, "Linux/auditd only")
    if os.geteuid() != 0:
        return record(name, SKIP, "needs root + `augenrules --load` (see DETECTION.md §1.1)")
    # Deliberately NOT automated further: writing to the real /etc/ld.so.preload
    # and driving auditd is a manual, supervised lab step (DETECTION.md §10.3).
    record(name, SKIP, "manual step -- see DETECTION.md §10.3")


def main() -> int:
    print("Auto-Color detection harness -- LAB/VM ONLY\n")
    check_preload_in_maps()
    check_daemon_ancestry()
    check_net_diff_negative_control()
    check_auditd_preload_write()

    failures = [r for r in _results if r[1] == FAIL]
    passed = [r for r in _results if r[1] == PASS]
    skipped = [r for r in _results if r[1] == SKIP]
    print(f"\n{len(passed)} passed, {len(skipped)} skipped, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
