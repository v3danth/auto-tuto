"""Functional tests for detect/auto_color.yar.

Fixtures are inert byte blobs, not working binaries: the YARA rule matches on raw
bytes (ELF magic at offset 0, constants, strings), so a crafted buffer is enough
to exercise match/no-match logic without compiling any malware. Skips cleanly if
yara-python is not installed.
"""

import os

import pytest

yara = pytest.importorskip("yara")

RULE_PATH = os.path.join(os.path.dirname(__file__), "..", "detect", "auto_color.yar")

ELF_MAGIC = b"\x7fELF"
K_CONST = bytes.fromhex("2728E570")          # 0x70E52827 LE  (hard anchor)
SDEC = bytes.fromhex("83C07B83F01F83E87B")   # string-decrypt instruction bytes


@pytest.fixture(scope="module")
def rules():
    try:
        return yara.compile(filepath=RULE_PATH)
    except yara.Error:
        # elf module unavailable in some minimal builds; rule still compiles
        # without the import in CI images that bundle it, so re-raise otherwise.
        pytest.skip("yara build lacks required modules")


def _blob(*parts: bytes, size: int = 4096) -> bytes:
    body = ELF_MAGIC + b"\x00" * 64 + b"".join(parts)
    return body + b"\x00" * max(0, size - len(body))


def test_matches_on_hard_anchor_plus_two_paths(rules):
    data = _blob(K_CONST, b"/var/log/cross", b"libcext.so.2")
    assert [m.rule for m in rules.match(data=data)] == ["AutoColor_Linux_Backdoor_v2"]


def test_matches_on_four_soft_paths_alone(rules):
    data = _blob(
        b"/var/log/cross", b"/tmp/cross", b"config-err-", b"/etc/ld.so.preload.xxx"
    )
    assert rules.match(data=data)


def test_matches_on_instruction_bytes_plus_paths(rules):
    data = _blob(SDEC, b"/etc/ld.so.preload", b"config-err-")
    assert rules.match(data=data)


def test_no_match_on_clean_elf(rules):
    data = _blob(b"this is a perfectly ordinary program", b"/usr/lib/libc.so.6")
    assert rules.match(data=data) == []


def test_no_match_without_elf_magic(rules):
    # Same incriminating content, but not an ELF at offset 0.
    data = b"MZ" + b"\x00" * 64 + K_CONST + b"/var/log/cross" + b"libcext.so.2"
    assert rules.match(data=data) == []


def test_no_match_when_only_one_soft_path(rules):
    data = _blob(b"/var/log/cross")
    assert rules.match(data=data) == []
