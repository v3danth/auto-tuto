"""Auto-Color configuration/IOC extractor (defensive analysis tool).

Recovers the C2 address(es) from an Auto-Color sample so responders can block or
sinkhole them. This operates on the malware's *own* encrypted configuration; it
is an analysis aid, not part of any implant.

The decryption mirrors SPECS.md §4.2. The per-byte transform there is written
with full-width intermediates and a single trailing `& 0xFF`; the stepwise
masking below is equivalent for the output byte (for +, -, ^ the low 8 bits of
the result depend only on the low 8 bits of the operands), and it avoids
Python's signed/negative XOR semantics that a literal port would hit.
"""

from __future__ import annotations

import re

KEY_UPDATE_SUB = 0x70E52827
KEY_MULT = 1023
MASK32 = 0xFFFFFFFF

# TCP://host_or_ip:port  (SPECS.md §4.2.3 config content format)
_C2_RE = re.compile(r"TCP://[A-Za-z0-9.\-]+:\d+", re.IGNORECASE)


def _next_key(key: int) -> int:
    """Advance the keystream one step (SPECS.md §4.2)."""
    return (KEY_MULT * key - KEY_UPDATE_SUB) & MASK32


def decrypt(key: int, data: bytes) -> bytes:
    """Decrypt an Auto-Color config/payload blob.

    Args:
        key: initial 32-bit key (the last 4 bytes of the ciphertext, big-endian).
        data: ciphertext bytes.

    Returns:
        The decrypted plaintext bytes (same length as ``data``).
    """
    out = bytearray(len(data))
    for i, enc in enumerate(data):
        key = _next_key(key)
        val = (enc - (key >> 19)) & 0xFF
        val = (val ^ (key >> 11)) & 0xFF
        val = (val - (key >> 3)) & 0xFF
        out[i] = val
    return bytes(out)


def parse_config_blob(
    data_section: bytes, size_off: int = 0x20, data_off: int = 0x24
) -> tuple[int, bytes]:
    """Split a packed config blob into (initial_key, ciphertext).

    Framing per SPECS.md §4.2.1 / §11.3: a big-endian size at ``size_off``, the
    ciphertext starting at ``data_off``, and the initial key in the last 4 bytes
    of the ciphertext (big-endian).

    Raises:
        ValueError: if the declared size does not fit in ``data_section``.
    """
    if len(data_section) < data_off + 4:
        raise ValueError("data section too small to contain a config blob")
    size = int.from_bytes(data_section[size_off:data_off], "big")
    end = data_off + size
    if size < 4 or end > len(data_section):
        raise ValueError(f"declared config size {size} is out of range")
    ciphertext = data_section[data_off:end]
    key = int.from_bytes(ciphertext[-4:], "big")
    return key, ciphertext


def extract_c2_urls(text: str) -> list[str]:
    """Return every ``TCP://host:port`` C2 endpoint found in ``text``."""
    return _C2_RE.findall(text)


def extract_from_bytes(data_section: bytes) -> list[str]:
    """Convenience: parse + decrypt + pull C2 URLs from a raw .data section."""
    key, ciphertext = parse_config_blob(data_section)
    plaintext = decrypt(key, ciphertext).decode("utf-8", errors="ignore")
    return extract_c2_urls(plaintext)
