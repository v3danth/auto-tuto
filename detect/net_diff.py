"""Hidden-socket differ (DETECTION.md §4.4).

The Auto-Color preload library filters ``/proc/net/tcp`` reads that go through
libc, so a libc-based tool (``ss``) can under-report connections. The kernel
view (``conntrack -L``) is not subject to the hook. A connection present in the
kernel view but absent from the libc view is a candidate hidden C2 socket.

These parsers take the raw text of each command so the logic is unit-testable
with fixtures and needs no live host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# conntrack -L line: "... src=A dst=B sport=N dport=M ..." (established tcp)
_CT_DST = re.compile(r"\bdst=(\d+\.\d+\.\d+\.\d+)\b")
_CT_DPORT = re.compile(r"\bdport=(\d+)\b")

# An IPv4 "address:port" token (ss columns can be followed by a process column).
_IPV4_PORT = re.compile(r"^(\d+\.\d+\.\d+\.\d+):(\d+)$")


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


def parse_ss_peers(ss_text: str) -> set[Endpoint]:
    """Extract remote (peer) endpoints from ``ss -tanp`` output.

    Columns are: State Recv-Q Send-Q Local:Port Peer:Port [Process]. The peer is
    the 5th field; a trailing process column (``users:(...)``) is ignored.
    """
    peers: set[Endpoint] = set()
    for line in ss_text.splitlines():
        if line.lower().startswith("state") or not line.strip():
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        m = _IPV4_PORT.match(fields[4])
        if m:
            peers.add(Endpoint(m.group(1), int(m.group(2))))
    return peers


def parse_conntrack_peers(ct_text: str) -> set[Endpoint]:
    """Extract destination endpoints from ``conntrack -L -p tcp`` output."""
    peers: set[Endpoint] = set()
    for line in ct_text.splitlines():
        if "tcp" not in line.lower():
            continue
        dst = _CT_DST.search(line)
        dport = _CT_DPORT.search(line)
        if dst and dport:
            peers.add(Endpoint(dst.group(1), int(dport.group(1))))
    return peers


def hidden_sockets(ss_text: str, conntrack_text: str) -> list[Endpoint]:
    """Endpoints the kernel sees but the libc view hides (sorted, deterministic)."""
    kernel = parse_conntrack_peers(conntrack_text)
    libc = parse_ss_peers(ss_text)
    return sorted(kernel - libc, key=lambda e: (e.ip, e.port))
