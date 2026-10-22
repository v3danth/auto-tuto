"""Functional unit tests for detect/net_diff.py (hidden-socket differ)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detect"))

import net_diff  # noqa: E402

SS_OUT = """State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB  0      0      10.0.0.5:22       203.0.113.10:51515 users:(("sshd",pid=900,fd=3))
ESTAB  0      0      10.0.0.5:443      198.51.100.4:40001 users:(("nginx",pid=800,fd=9))
"""

# conntrack sees an extra established flow to 192.0.2.66:4443 that ss does not.
CONNTRACK_OUT = """tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=203.0.113.10 sport=22 dport=51515 src=203.0.113.10 dst=10.0.0.5 sport=51515 dport=22 [ASSURED] mark=0 use=1
tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=198.51.100.4 sport=443 dport=40001 [ASSURED]
tcp 6 299 ESTABLISHED src=10.0.0.5 dst=192.0.2.66 sport=55000 dport=4443 [ASSURED] mark=0 use=1
"""


def test_parse_ss_peers():
    peers = net_diff.parse_ss_peers(SS_OUT)
    assert net_diff.Endpoint("203.0.113.10", 51515) in peers
    assert net_diff.Endpoint("198.51.100.4", 40001) in peers
    assert len(peers) == 2  # header line ignored


def test_parse_conntrack_peers():
    peers = net_diff.parse_conntrack_peers(CONNTRACK_OUT)
    assert net_diff.Endpoint("192.0.2.66", 4443) in peers
    assert len(peers) == 3


def test_hidden_socket_detected():
    hidden = net_diff.hidden_sockets(SS_OUT, CONNTRACK_OUT)
    assert hidden == [net_diff.Endpoint("192.0.2.66", 4443)]


def test_no_false_positive_when_views_agree():
    # If ss also reports the extra flow, nothing is hidden.
    ss_full = SS_OUT + "ESTAB 0 0 10.0.0.5:55000 192.0.2.66:4443 users:(('cron',pid=5,fd=7))\n"
    assert net_diff.hidden_sockets(ss_full, CONNTRACK_OUT) == []
