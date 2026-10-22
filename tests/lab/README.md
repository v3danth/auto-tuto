# Detection Harness (lab)

Benign validation harness for the detections in `../../DETECTION.md`. It proves
each rule reacts to the **observable** it keys on, by reproducing that observable
with a harmless stand-in. **There is no implant here** — no C2, no hooking, no
hiding, no persistence.

> **Run in a throwaway VM/container only.** The behavioral checks write to system
> paths and spawn short-lived processes. They are benign, but not for a host you
> care about. For deterministic, always-safe coverage, use the pytest suite in
> `../` instead.

## What it validates

| Check | DETECTION.md | Benign stand-in | Needs |
|-------|--------------|-----------------|-------|
| preload-in-maps sweep | §3 | `marker_preload.so` (writes one log line on load) LD_PRELOAD'd into `sleep` | Linux |
| daemon-ancestry hunt | §2 | `bash` copied to `/tmp/crond`, spawning a `sleep` child | Linux |
| hidden-socket differ (negative control) | §4.4 | real `ss` vs `conntrack` on a clean host → must agree | Linux, `ss`+`conntrack` |
| auditd preload watch | §1 | manual supervised write (see §10.3) | Linux, root, loaded rules |

The first three run automatically; the auditd check is a guided manual step
because it touches the real `/etc/ld.so.preload`.

## Files

- `marker_preload.c` — benign shared library; appends one line to `$MARKER_LOG` on load.
- `emulate.py` — the observable emulators (one function per observable).
- `validate.py` — runs the emulators + detections, prints `PASS / SKIP / FAIL`.
- `run_lab.sh` — wrapper with the lab-only banner.

## Run

```bash
# In a disposable Linux VM:
bash tests/lab/run_lab.sh

# Off Linux (e.g. a dev Mac), most checks SKIP cleanly:
python3 tests/lab/validate.py
```

Exit code is non-zero only on a real FAIL; SKIPs do not fail the run.

## What it deliberately does NOT do

- It does not build, stub, or run the Auto-Color implant.
- It does not reproduce the libc **hiding** behavior (that would mean writing
  hooking code). Instead it validates the *detection* of hiding — the
  `ss`-vs-`conntrack` discrepancy — which is the signal that matters.
- High-fidelity final validation (exact YARA byte offsets, the extractor against
  a true binary) uses an **existing captured sample** in isolation — obtained
  from threat intel, not authored here. The sample hashes are in
  `../../detect/auto_color.yar`.
