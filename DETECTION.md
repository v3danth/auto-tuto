# Auto-Color — Detection & Response Companion

> Companion to `SPECS.md`. Where that document describes the implant, this one
> describes how a defender finds it, confirms it, and removes it. It is written
> to be read on its own by a SOC analyst or IR responder.

## Document Information
- **Version:** 1.0
- **Classification:** Defensive / Threat Detection
- **Scope:** Linux (ELF64), the Auto-Color family as described in `SPECS.md`
- **Companion to:** `SPECS.md` §11 (Detection Signatures)

---

## 0. The core problem with `SPECS.md` §11

The IOC tables in `SPECS.md` are almost entirely **host paths and string
constants** (`/var/log/cross`, `libcext.so.2`, `/tmp/17EF88CF`, …). Those are
real, but they are the *weakest* class of indicator for this family because:

1. An operator changes a path or a filename in one `#define` and every one of
   those IOCs is dead, with zero change to behavior.
2. Worse, once `libcext.so.2` is loaded via `/etc/ld.so.preload`, the implant's
   own hooks **lie to any tool that uses libc** — `stat`, `open`, `fopen`,
   `readdir`, `access`, `unlink` on `/etc/ld.so.preload` all return the decoy
   (`.xxx`) or `ENOENT`. So `cat /etc/ld.so.preload` and `ls /var/log/cross`
   from a compromised host can report *clean*.

The durable detections are therefore **behavioral** and, critically,
**below the libc layer** where the hooks can't reach. That is what this document
leads with. Host-path IOCs are kept at the end as a secondary triage aid.

### Detection priority (most to least durable)

| Tier | Signal | Why it survives operator changes |
|------|--------|----------------------------------|
| 1 | Kernel-audit writes to `/etc/ld.so.preload` | auditd runs in-kernel; libc hooks can't intercept it |
| 2 | A system daemon spawning an unexpected child | the persistence mechanism *requires* this |
| 3 | A preload library loaded by a daemon's maps | the injection is observable in `/proc/<pid>/maps` |
| 4 | Hook-induced discrepancies (userland vs. kernel view) | the hooks themselves create the tell |
| 5 | Long-lived outbound TCP from a server-side daemon | the C2 channel has to exist somewhere |
| 6 | Host paths / filenames / YARA strings | trivially changed; good for confirmation, weak for discovery |

---

## 1. Tier 1 — Kernel audit on `/etc/ld.so.preload` (highest value)

The implant hooks libc so userland can't see the preload entry, **but auditd
collects events in the kernel**, before libc is involved. A write to
`/etc/ld.so.preload` is one of the highest-signal, lowest-noise events on a
Linux server — legitimate changes are rare and should always be change-managed.

### 1.1 auditd rules (`/etc/audit/rules.d/10-preload.rules`)

```
# Watch the preload file and its decoy target for any write/attribute change
-w /etc/ld.so.preload -p wa -k ldpreload_tamper
-w /etc/ld.so.preload.xxx -p wa -k ldpreload_decoy

# Watch the known install dir; survives even if hooks hide it from userland
-w /var/log/cross -p wa -k autocolor_dir

# Writes to ld config more broadly
-w /etc/ld.so.conf -p wa -k ldconfig_tamper
-w /etc/ld.so.conf.d/ -p wa -k ldconfig_tamper
```

Load and verify:

```bash
augenrules --load
auditctl -l | grep -E 'ldpreload|autocolor'
```

Hunt the resulting events (note: `ausearch` reads the kernel audit log, so the
libc hooks do **not** affect it):

```bash
ausearch -k ldpreload_tamper -i
ausearch -k autocolor_dir -i
```

> **Why this is the keystone detection:** the implant's entire userland-hiding
> strategy is defeated here because the observation point is in the kernel. If
> you deploy one thing from this document, deploy this.

### 1.2 Fleet-wide equivalent

If you run an EDR/eBPF agent (Falco, Tetragon, auditbeat, a commercial EDR),
express the same intent as a rule: **"write to `/etc/ld.so.preload` by any
process that is not the package manager."** Example Falco rule:

```yaml
- rule: ld.so.preload modified
  desc: Write to /etc/ld.so.preload outside package management
  condition: >
    (evt.type in (open, openat, rename, renameat, unlinkat) and
     fd.name = /etc/ld.so.preload and
     evt.is_open_write=true) and
    not proc.name in (dpkg, apt, rpm, yum, dnf, ldconfig)
  output: "ld.so.preload tampering (proc=%proc.name cmd=%proc.cmdline user=%user.name)"
  priority: CRITICAL
  tags: [persistence, T1574.006]
```

Maps to **MITRE ATT&CK T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking.**

---

## 2. Tier 2 — Daemon spawning an unexpected child

`SPECS.md` §10.3 installs an `__attribute__((constructor))` in `libcext.so.2`.
Because the library is preloaded into *every* dynamically linked process, that
constructor runs inside each targeted daemon (`cron`, `atd`, `auditd`, `acpid`,
…) and `fork()`s the implant. The behavioral invariant that cannot be removed
without redesigning the family: **a long-running system daemon becomes the
parent of a short-lived process it has no business launching.**

### 2.1 Live triage

```bash
# Children of the daemons named as targets in SPECS.md §10.1
for d in cron crond atd acpid auditd; do
  pgrep -x "$d" | while read -r pid; do
    echo "== $d ($pid) children =="
    ps --ppid "$pid" -o pid,ppid,comm,args 2>/dev/null
  done
done
```

A `cron` or `auditd` parenting `/bin/bash -i`, a process in `/var/log/cross`, or
any unexpected binary is a strong hit. Normal `cron` children are the jobs in
crontabs; anything else warrants a look.

### 2.2 Process-ancestry hunt (EDR / eBPF)

Pseudo-query, adapt to your platform:

```
process.parent.name in ("cron","crond","atd","acpid","auditd")
AND process.name not in (<allowlisted job interpreters>)
AND event.action = "exec"
```

Maps to **T1543.002 (persistence via system process)** + **T1574.006**.

---

## 3. Tier 3 — Preload library present in a daemon's address space

Even if the library filename is changed, the fact that *some* extra `.so` from a
non-standard path is mapped into system daemons is observable in
`/proc/<pid>/maps`. This reads the kernel-maintained maps, not a libc call.

```bash
# Any library mapped into daemons from a non-standard directory
for d in cron crond atd acpid auditd; do
  pgrep -x "$d" | while read -r pid; do
    awk '/\.so/ {print FILENAME": "$6}' "/proc/$pid/maps" 2>/dev/null
  done
done | sort -u | grep -vE '/(lib|lib64|usr/lib|usr/lib64)/'
```

Cross-check against `/etc/ld.so.preload` **read from a trusted vantage point**
(see §4). Any preload entry outside the distro's package database is suspect:

```bash
# On Debian/Ubuntu: is the preloaded lib owned by a package?
while read -r lib; do
  [ -n "$lib" ] && { dpkg -S "$lib" 2>/dev/null || echo "UNOWNED: $lib"; }
done < /etc/ld.so.preload
```

---

## 4. Tier 4 — Beating the hooks (confirmation & triage)

The hooks in `SPECS.md` §10.2 only intercept calls that **route through the
hooked libc in this process**. Four ways around them:

1. **Statically linked / non-libc tools.** A busybox built static, a Go or Rust
   binary, or anything issuing raw syscalls is not subject to `LD_PRELOAD`.
   ```bash
   busybox cat /etc/ld.so.preload     # static busybox bypasses the fopen hook
   busybox ls -la /var/log/cross
   ```
2. **Bypass the preload for a single command.** Clearing the loader's preload
   path for the child process means the malicious `.so` is never mapped into
   *that* process, so its hooks never run:
   ```bash
   LD_PRELOAD= env -i /path/to/static/busybox cat /etc/ld.so.preload
   ```
   (Note: this does not touch `/etc/ld.so.preload` itself, which the loader
   still honors; use a static tool for the read.)
3. **Offline / mounted inspection.** The hooks only exist on the *running*
   system. Mount the disk read-only from a rescue environment or another host
   and inspect `etc/ld.so.preload`, `var/log/cross/`, and the decoy
   `etc/ld.so.preload.xxx` directly. This is the authoritative view.
4. **Kernel-view cross-check for hidden connections.** The C2-hiding hook in
   §10.4 filters `/proc/net/tcp` reads through libc `open`. Compare a libc view
   against a kernel view:
   ```bash
   # libc view (may be filtered by the hook):
   ss -tanp

   # kernel view via eBPF/netlink from a static tool, or from conntrack:
   conntrack -L -p tcp 2>/dev/null
   # Any ESTABLISHED socket present in conntrack but absent from ss = hidden C2
   ```
   A discrepancy between the two is itself the detection — the hook *creates*
   the anomaly it is trying to hide.

---

## 5. Tier 5 — Network behavior

The protocol is a **custom binary** channel (`SPECS.md` §5, §7), not TLS, so
TLS fingerprinting (JA3/JA4) does not apply. Hunt on behavior instead:

- **Server-side daemons making outbound connections.** A host whose role is to
  *accept* connections (mail, web, auth) initiating long-lived *outbound* TCP to
  an unfamiliar IP is anomalous regardless of port.
- **Fixed-shape handshake.** §5.3 sends a 12-byte challenge (three XOR-derived
  DWORDs) immediately after connect, followed by a 16-byte header
  (`encryption_key|session_id|status_flag|payload_size`). The first-packet sizes
  are a candidate Suricata/Zeek heuristic:
  ```
  # Suricata (illustrative — tune thresholds to your baseline)
  alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Auto-Color custom C2 handshake";
    flow:established,to_server; dsize:12; flowbits:set,ac_challenge;
    threshold:type limit, track by_src, count 1, seconds 60;
    classtype:trojan-activity; sid:9000001; rev:1;)
  ```
  Treat this as a **hunting lead, not a blocking rule** — 12-byte first packets
  occur in benign traffic; pair it with the server-initiated-outbound context.
- **Beaconing.** The command loop (§7.2) holds a persistent socket; look for
  low-volume, long-duration flows that outlive normal request/response sessions.

---

## 6. Hardened YARA rule

The rule in `SPECS.md` §11.1 is serviceable but brittle: `5 of ($s*)` over six
easily-changed path strings, and it includes `$s3 = "/door-%d.log"` which
appears nowhere else in the spec. The version below separates **hard
behavioral/structural constants** (the crypto magic numbers and the decryption
key-update arithmetic, which are expensive for an operator to change) from
**soft path strings** (cheap to change), and requires at least one hard anchor.

```yara
import "elf"

rule AutoColor_Linux_Backdoor_v2 {
    meta:
        description = "Auto-Color Linux backdoor — structural + string detection"
        reference   = "SPECS.md; Unit 42 Auto-Color reporting"
        author      = "detection companion"
        severity    = "critical"
        // keep upstream hashes for provenance
        hash1 = "815b74947d3a78a1b7d2aece43596ddc0ffc264e26092f1f9b6409c62e1437d6"
        hash2 = "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43"

    strings:
        // --- HARD: crypto constants (SPECS.md §4.2 / §5.1) ---
        // key update:  key = 1023 * key - 0x70E52827
        $k_const = { 27 28 E5 70 }              // 0x70E52827, little-endian immediate
        // config path hash seed (SPECS.md §4.2.4): 0xCE7C0B42
        $h_seed  = { 42 0B 7C CE }
        // string-decrypt XOR key 0x1F combined with +123/-123 (SPECS.md §4.1)
        $sdec    = { 83 C0 7B 83 F0 1F 83 E8 7B }   // add 123; xor 0x1F; sub 123

        // --- SOFT: paths / names (cheap to change) ---
        $p1 = "/var/log/cross" ascii
        $p2 = "/tmp/cross" ascii
        $p3 = "/etc/ld.so.preload.xxx" ascii
        $p4 = "libcext.so.2" ascii
        $p5 = "config-err-" ascii
        $p6 = "/etc/ld.so.preload" ascii

    condition:
        uint32(0) == 0x464c457f and            // ELF magic
        filesize < 2MB and
        (
            // confident: any hard structural anchor + a couple of soft hits
            (any of ($k_const, $h_seed, $sdec) and 2 of ($p*))
            // or: a strong cluster of soft indicators alone
            or 4 of ($p*)
        )
}
```

Notes:
- The `$k_const` / `$h_seed` byte patterns are the little-endian encodings of
  the magic constants from the spec; verify the exact instruction encoding
  against a real sample before production use and widen to a `{ ?? }`-tolerant
  pattern if the compiler reorders operands.
- `import "elf"` lets you tighten further (e.g. `elf.type == elf.ET_DYN` for the
  library vs. `ET_EXEC`/`ET_DYN` PIE for the dropper) if you split into two
  rules.

---

## 7. Host-path IOCs (secondary — confirmation only)

Use these to **confirm** a hit from Tiers 1–5, not to discover infections
(remember §0: a live compromised host will hide most of them from libc tools —
read them per §4).

| Indicator | Type | Notes |
|-----------|------|-------|
| `/etc/ld.so.preload` entry for a non-package `.so` | Persistence | read via static tool or offline |
| `/etc/ld.so.preload.xxx` | Decoy | the "real" preload the hooks redirect to |
| `/var/log/cross/` | Install dir (root) | hidden from libc readdir on live host |
| `/var/log/cross/auto-color` | Dropper | |
| `/var/log/cross/config-err-*` | Encrypted C2 config | extract with the script in `SPECS.md` §11.3 |
| `/tmp/cross/` | Install dir (non-root "green" mode) | |
| `/tmp/.lock_<uid>` | Single-instance lock (flock) | |
| `/tmp/17EF88CF` | Filtered `/proc/net/tcp` scratch file | |
| SysV shm keyed via `ftok("/var/log/cross",'A')` | C2 IP tracking | `ipcs -m` |

```bash
ipcs -m    # look for a segment keyed off /var/log/cross (see SPECS.md §6.2)
```

---

## 8. Response & remediation

Order matters — the hooks fight back while the host is live.

1. **Isolate** the host at the network layer (don't rely on in-box firewalling;
   the implant can proxy and hide connections).
2. **Capture volatile state first** — `/proc/<pid>/maps`, `/proc/<pid>/exe`,
   open sockets (via `conntrack`/eBPF), and a memory image. The config and C2
   IPs live in the process and in the shm segment.
3. **Confirm persistence from a trusted vantage point** (static tools or offline
   mount, §4). Record the real `/etc/ld.so.preload` contents.
4. **Remove persistence before killing the process.** If you kill the implant
   first but leave `/etc/ld.so.preload` in place, the hijack constructor
   re-launches it the next time a target daemon starts. Remove the preload entry
   (offline, or with a static editor), delete the library and `/var/log/cross`,
   then reboot into a known-good state.
5. **Rotate credentials / audit lateral movement** — the reverse shell (§8.4),
   file transfer (§8.7) and proxy (§8.5) mean assume data access and pivoting.
6. **Preserve** the dropper and config for the extractor in `SPECS.md` §11.3 to
   recover C2 addresses, then block/sinkhole those across the fleet.

> Caveat: a self-destruct command (§8.3) cleans `/etc/ld.so.preload`,
> `/var/log/cross`, `/tmp/cross` and the library. Absence of host artifacts does
> **not** clear a host that tripped a Tier-1 auditd event — trust the kernel
> audit trail over the current filesystem state.

---

## 9. Quick deploy checklist

- [ ] auditd rules from §1.1 loaded fleet-wide; `ausearch -k ldpreload_tamper` wired to alerting
- [ ] Falco/EDR `ld.so.preload` write rule (§1.2) active
- [ ] Scheduled hunt for daemon-with-unexpected-child (§2)
- [ ] Preload-library-in-daemon-maps sweep (§3) in the hunt rotation
- [ ] `ss` vs `conntrack` discrepancy check (§4.4) scripted
- [ ] Server-initiated-outbound + 12-byte-handshake hunt (§5) in the SIEM
- [ ] `AutoColor_Linux_Backdoor_v2` YARA (§6) in the file-scan pipeline
- [ ] IR runbook (§8) references "remove persistence before kill"

---

## 10. Validating these detections

The detection *logic* ships with functional unit tests so you can prove it works
before relying on it — and keep it working as you tune it. The tests exercise the
detection tooling only; they do **not** run or simulate the implant.

### 10.1 What is tested

| Component | File | Tests |
|-----------|------|-------|
| Config/IOC extractor (§7, SPECS.md §11.3) | `detect/extractor.py` | `tests/test_extractor.py` |
| Hidden-socket differ (§4.4) | `detect/net_diff.py` | `tests/test_net_diff.py` |
| Hardened YARA rule (§6) | `detect/auto_color.yar` | `tests/test_yara.py` |

The fixtures are **inert**: the extractor tests generate ciphertext with a
test-only inverse of the documented transform; the YARA tests match the rule
against crafted byte blobs (ELF magic + constants + strings), not compiled
binaries. Nothing here produces or exercises a working backdoor.

### 10.2 Running the tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tests/requirements-dev.txt
pytest -q tests/
```

`yara-python` is optional — if it isn't installed, `tests/test_yara.py` is
skipped rather than failing, so the core suite runs anywhere Python does.

Expected: the extractor and net-diff tests pass with a stock Python; the YARA
tests additionally pass when `yara-python` (and a libyara build with the `elf`
module) is present.

### 10.3 Functional tests for the behavioral detections (lab VM)

The Tier 1–4 detections (auditd, process ancestry, preload-in-maps, hook bypass)
are validated against the *operating system*, not pure functions, so they belong
in a throwaway VM or container, never on a production host. A safe, implant-free
procedure:

1. **auditd rule fires (§1).** Load the rules, then write to the watched path
   with a benign editor and confirm the event:
   ```bash
   augenrules --load
   echo "# benign test write" >> /etc/ld.so.preload   # test VM only
   ausearch -k ldpreload_tamper -i | tail
   # cleanup: restore/remove the test line
   ```
   Asserts the kernel sees the write. (Remove the line afterward; do not leave a
   real preload entry in place.)

2. **Daemon-ancestry hunt flags an unexpected child (§2).** Rename a harmless
   sleeper to look like a daemon and have it fork a child, then run the hunt:
   ```bash
   cp /bin/sleep /tmp/crond && /tmp/crond 300 &   # stand-in "daemon"
   # run the §2.1 triage loop (add "crond" matching on cmdline) and confirm the
   # unexpected child is listed; kill the stand-in when done.
   ```
   This proves the *hunt* detects the pattern without any malicious code.

3. **Hook-bypass discrepancy (§4.4).** With no implant present, `ss` and
   `conntrack` should agree, i.e. `net_diff.hidden_sockets()` returns `[]`. Pipe
   real output through the module as a smoke test:
   ```bash
   python3 - <<'PY'
   import subprocess, sys; sys.path.insert(0, "detect"); import net_diff
   ss = subprocess.run(["ss","-tanp"], capture_output=True, text=True).stdout
   ct = subprocess.run(["conntrack","-L","-p","tcp"], capture_output=True, text=True).stdout
   print("hidden:", net_diff.hidden_sockets(ss, ct))   # [] on a clean host
   PY
   ```

> These three are **detection self-tests**, not malware tests: each confirms a
> detection reacts to a benign stand-in for the real behavior. Building a live
> implant to test against is out of scope by design.

