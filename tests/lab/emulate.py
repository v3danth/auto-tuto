"""Benign observable emulators for the Auto-Color detection harness.

Each function reproduces ONE observable that a detection in DETECTION.md keys on,
using the most harmless means possible. None of this is the implant: there is no
C2, no hooking, no hiding, no persistence. These stand-ins exist only so the
detection rules can be fired and asserted in an isolated lab/VM.

LAB/VM ONLY. Several of these write to system paths or spawn processes; never run
them on a host you care about.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

MARKER_SO_SRC = Path(__file__).with_name("marker_preload.c")


def emulate_preload_write(preload_path: str = "/etc/ld.so.preload") -> str:
    """Append a harmless comment line to the ld.so.preload file.
    Why: produces the exact observable the Tier-1 auditd watch (§1) alerts on -- a
      write to ld.so.preload -- without installing any real preload entry.
    Where/how: run inside a throwaway VM, then assert `ausearch -k ldpreload_tamper`
      shows the event; the returned marker lets the caller remove the line again.
    Returns: the marker line that was written (for cleanup/matching).
    """
    marker = f"# detection-harness benign test write {int(time.time())}\n"
    with open(preload_path, "a", encoding="utf-8") as f:
        f.write(marker)
    return marker


def emulate_daemon_child(daemon_name: str = "crond", seconds: int = 300) -> int:
    """Start a process whose name mimics a daemon and give it an unexpected child.
    Why: reproduces the "system daemon with an unexpected child" pattern (§2) that
      the ancestry hunt flags, using an inert shell instead of a hijacked daemon.
    Where/how: run in a lab VM; feed the returned PID to the §2.1 triage loop and
      assert the child is listed; cleanup() kills the stand-in when done.
    Returns: the PID of the stand-in "daemon" (its child is a plain `sleep`).
    """
    standin = Path("/tmp") / daemon_name
    shutil.copy2("/bin/bash", standin)  # copied bash -> comm shows as daemon_name
    proc = subprocess.Popen([str(standin), "-c", f"sleep {seconds}"])
    return proc.pid


def build_marker_preload_so(out_path: str = "/tmp/marker_preload.so") -> str:
    """Compile the benign marker library (marker_preload.c) to a shared object.
    Why: gives Tier-3 (§3) a non-standard shared object to find mapped into a
      process, without any of the implant's hooks or payload.
    Where/how: build once in the lab; the .so only writes a marker on load, so it
      is safe to LD_PRELOAD; returns the path for emulate_preload_in_maps().
    Returns: the path to the built .so.
    """
    cc = os.environ.get("CC", "cc")
    subprocess.run(
        [cc, "-shared", "-fPIC", str(MARKER_SO_SRC), "-o", out_path],
        check=True,
    )
    return out_path


def emulate_preload_in_maps(marker_so: str, seconds: int = 300) -> int:
    """Launch a process with the marker library LD_PRELOAD'd into it.
    Why: produces the observable for the preload-in-maps sweep (§3) -- a library
      from a non-standard path present in a process's /proc/<pid>/maps.
    Where/how: lab VM; pass the returned PID to the §3 sweep and assert the marker
      .so appears; cleanup() terminates the process afterward.
    Returns: the PID of the host process carrying the preload.
    """
    env = dict(os.environ, LD_PRELOAD=marker_so)
    proc = subprocess.Popen(["sleep", str(seconds)], env=env)
    return proc.pid


def capture_net_views() -> tuple[str, str]:
    """Collect the libc (`ss -tanp`) and kernel (`conntrack -L -p tcp`) socket views.
    Why: feeds the hidden-socket differ (§4.4); on a clean host the two agree, which
      is the harness's negative control (hidden_sockets() must return []).
    Where/how: lab VM with conntrack available; hand both strings to
      detect.net_diff.hidden_sockets() and assert no discrepancy on a clean host.
    Returns: (ss_text, conntrack_text); either may be "" if the tool is missing.
    """
    def _run(cmd: list[str]) -> str:
        try:
            return subprocess.run(cmd, capture_output=True, text=True).stdout
        except (FileNotFoundError, OSError):
            return ""

    ss = _run(["ss", "-tanp"])
    conntrack = _run(["conntrack", "-L", "-p", "tcp"])
    return ss, conntrack


def list_children(pid: int) -> list[int]:
    """Return the PIDs whose parent is ``pid`` (the §2 ancestry check, in Python).
    Why: lets the harness assert emulate_daemon_child() produced a visible child
      without shelling out to a distro-specific `ps` invocation.
    Where/how: Linux lab VM; reads /proc/*/stat so it is not fooled by libc-level
      hiding and works wherever procfs is mounted.
    Returns: list of child PIDs (empty if none / not on Linux).
    """
    children: list[int] = []
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            fields = (entry / "stat").read_text().split()
            if int(fields[3]) == pid:  # field 4 (0-based 3) is PPID
                children.append(int(fields[0]))
        except (OSError, ValueError, IndexError):
            continue
    return children


def cleanup(markers: list[str] | None = None, pids: list[int] | None = None) -> None:
    """Remove files written and kill processes started by the emulators.
    Why: the lab must leave the VM in its pre-test state -- no stray preload lines,
      no lingering stand-in daemons -- so repeated runs stay deterministic.
    Where/how: called from the runner's teardown after each step; safe to call with
      partial state (missing files / already-dead PIDs are ignored).
    """
    for pid in pids or []:
        try:
            os.kill(pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
    for path in markers or []:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
