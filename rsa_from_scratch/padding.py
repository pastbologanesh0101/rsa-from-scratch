"""
PKCS#1 v1.5-style padding, implemented from scratch.

Two flavors, matching the real PKCS#1 v1.5 spec:

* Encryption padding (block type 0x02): the padding bytes are *random and
  non-zero*, generated with ``secrets``. This is what makes encrypting the
  same message twice produce different ciphertext -- it's the difference
  between "textbook RSA" (insecure: deterministic, malleable, leaks equal
  plaintexts) and padded RSA.

* Signature padding (block type 0x01): the padding bytes are fixed
  (0xFF), i.e. deterministic. Signatures are *supposed* to be
  deterministic here -- the security property we want is unforgeability,
  not hiding, and a verifier must be able to recompute the exact same
  padded block to check a signature.

Layout for a k-byte block (k = byte length of the modulus n):

    0x00 || BT || PS || 0x00 || D

  - BT is 0x02 (encryption) or 0x01 (signature)
  - PS is padding string, at least 8 bytes, filling out the block
  - D is the actual data (message chunk, or hash digest)
"""

from __future__ import annotations

import secrets

_MIN_PADDING_LEN = 8


def pkcs1_v15_pad(data: bytes, k: int, block_type: int) -> bytes:
    """Pad ``data`` to exactly ``k`` bytes, PKCS#1 v1.5 style.

    block_type must be 1 (signature, deterministic 0xFF padding) or
    2 (encryption, random non-zero padding).
    """
    if block_type not in (1, 2):
        raise ValueError("block_type must be 1 or 2")

    pad_len = k - 3 - len(data)
    if pad_len < _MIN_PADDING_LEN:
        raise ValueError(
            f"data too long ({len(data)} bytes) to pad into a {k}-byte block"
        )

    if block_type == 1:
        ps = bytes([0xFF]) * pad_len
    else:
        ps = bytearray()
        while len(ps) < pad_len:
            byte = secrets.token_bytes(1)
            if byte != b"\x00":
                ps += byte
        ps = bytes(ps)

    return b"\x00" + bytes([block_type]) + ps + b"\x00" + data


def pkcs1_v15_unpad(block: bytes, k: int, block_type: int) -> bytes:
    """Reverse of pkcs1_v15_pad. Raises ValueError if the block is malformed."""
    if len(block) != k:
        raise ValueError("padded block has wrong length")
    if block[0] != 0x00 or block[1] != block_type:
        raise ValueError("invalid padding: bad block header")

    # Find the 0x00 separator after the padding string, starting at index 2.
    try:
        sep_index = block.index(b"\x00", 2)
    except ValueError:
        raise ValueError("invalid padding: missing separator") from None

    pad_len = sep_index - 2
    if pad_len < _MIN_PADDING_LEN:
        raise ValueError("invalid padding: padding string too short")

    if block_type == 1:
        if block[2:sep_index] != bytes([0xFF]) * pad_len:
            raise ValueError("invalid padding: signature padding not all 0xFF")
    else:
        if b"\x00" in block[2:sep_index]:
            raise ValueError("invalid padding: zero byte found inside PS")

    return block[sep_index + 1 :]
