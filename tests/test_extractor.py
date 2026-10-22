"""Functional unit tests for detect/extractor.py.

No implant is involved: we generate inert ciphertext with a test-only inverse of
the documented decrypt transform, then assert the extractor recovers it. The
transform itself is already fully documented in SPECS.md; this helper exists
only to produce fixtures, not to add any capability.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detect"))

import extractor  # noqa: E402


def _encrypt_for_test(key: int, data: bytes) -> bytes:
    """Exact byte-wise inverse of extractor.decrypt (fixture generator only)."""
    out = bytearray(len(data))
    for i, b in enumerate(data):
        key = extractor._next_key(key)
        val = (b + (key >> 3)) & 0xFF
        val = (val ^ (key >> 11)) & 0xFF
        val = (val + (key >> 19)) & 0xFF
        out[i] = val
    return bytes(out)


@pytest.mark.parametrize("initial_key", [0x00000000, 0x01020304, 0xDEADBEEF, 0xFFFFFFFF])
def test_decrypt_is_inverse_of_encrypt(initial_key):
    plaintext = b"TCP://c2.example.test:4443\x00padding-bytes-\x01\x02\xff"
    ciphertext = _encrypt_for_test(initial_key, plaintext)
    assert ciphertext != plaintext  # it actually transformed something
    assert extractor.decrypt(initial_key, ciphertext) == plaintext


def test_decrypt_preserves_length_and_byte_range():
    out = extractor.decrypt(0x12345678, bytes(range(256)))
    assert len(out) == 256
    assert all(0 <= b <= 255 for b in out)


def test_decrypt_empty():
    assert extractor.decrypt(0xABCDEF01, b"") == b""


def test_extract_c2_urls_finds_all_and_ignores_noise():
    text = "junk TCP://1.2.3.4:8080 more TCP://host.bad.test:443 noTCP://x END"
    assert extractor.extract_c2_urls(text) == [
        "TCP://1.2.3.4:8080",
        "TCP://host.bad.test:443",
    ]


def test_extract_c2_urls_case_insensitive_scheme():
    assert extractor.extract_c2_urls("tcp://5.6.7.8:9000") == ["tcp://5.6.7.8:9000"]


def test_extract_c2_urls_none():
    assert extractor.extract_c2_urls("nothing to see here") == []


def _build_data_section(plaintext: bytes, initial_key: int) -> bytes:
    """Frame a fixture .data section per SPECS.md §4.2.1 (size@0x20, data@0x24)."""
    ciphertext = _encrypt_for_test(initial_key, plaintext)
    # The parser reads the initial key from the LAST 4 bytes of the ciphertext,
    # so append those 4 key bytes (big-endian) as the trailing block.
    key_tail = initial_key.to_bytes(4, "big")
    body = ciphertext + key_tail
    blob = bytearray(0x24)
    blob[0x20:0x24] = len(body).to_bytes(4, "big")
    return bytes(blob) + body


def test_parse_config_blob_framing():
    plaintext = b"TCP://10.0.0.9:1337"
    initial_key = 0x11223344
    section = _build_data_section(plaintext, initial_key)
    key, ciphertext = extractor.parse_config_blob(section)
    assert key == initial_key  # recovered from the last 4 bytes
    assert len(ciphertext) == len(plaintext) + 4


def test_parse_config_blob_rejects_bad_size():
    bad = bytearray(0x24)
    bad[0x20:0x24] = (0xFFFF).to_bytes(4, "big")  # claims way more than present
    with pytest.raises(ValueError):
        extractor.parse_config_blob(bytes(bad) + b"\x00\x00\x00\x00")


def test_extract_from_bytes_end_to_end():
    plaintext = b"TCP://evil.c2.test:4443"
    initial_key = 0x0BADF00D
    # Round-trip is only guaranteed when the appended key tail decrypts to
    # trailing bytes we ignore; we assert the C2 URL is recovered from the
    # decrypted leading content.
    section = _build_data_section(plaintext + b"\x00" * 4, initial_key)
    urls = extractor.extract_from_bytes(section)
    assert "TCP://evil.c2.test:4443" in urls
