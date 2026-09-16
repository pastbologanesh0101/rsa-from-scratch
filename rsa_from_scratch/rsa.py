"""
High-level, padded RSA operations on arbitrary byte strings:

- encrypt / decrypt: PKCS#1 v1.5 encryption padding (randomized), with
  automatic chunking so messages longer than one RSA block still work.
- sign / verify: hash-then-sign. The message is hashed with SHA-256, the
  digest is padded with deterministic PKCS#1 v1.5 signature padding, and
  *that* padded block is what gets raised to the private exponent.

This is the API most callers should use -- prefer it over the raw
encrypt_int/decrypt_int in core.py, which offer no security properties on
their own.
"""

from __future__ import annotations

import hashlib

from .core import decrypt_int, encrypt_int
from .keygen import PrivateKey, PublicKey
from .padding import pkcs1_v15_pad, pkcs1_v15_unpad

# Max bytes of real data per PKCS#1 v1.5 block: k - 11 (3 header/sep bytes
# + at least 8 bytes of padding).
_MIN_OVERHEAD = 11


def _max_chunk_len(k: int) -> int:
    return k - _MIN_OVERHEAD


def encrypt(message: bytes, public_key: PublicKey) -> bytes:
    """Encrypt an arbitrary byte string.

    The message is split into chunks small enough to leave room for
    PKCS#1 v1.5 encryption padding, each chunk is padded and RSA-encrypted
    independently, and the fixed-width ciphertext blocks are concatenated.
    Because the padding is randomized, encrypting the same message twice
    yields different ciphertext.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")

    k = public_key.key_size_bytes
    max_chunk = _max_chunk_len(k)
    if max_chunk <= 0:
        raise ValueError("key too small to hold any padded data")

    if message == b"":
        chunks = [b""]
    else:
        chunks = [
            message[i : i + max_chunk] for i in range(0, len(message), max_chunk)
        ]

    out = bytearray()
    for chunk in chunks:
        padded = pkcs1_v15_pad(chunk, k, block_type=2)
        m_int = int.from_bytes(padded, "big")
        c_int = encrypt_int(m_int, public_key)
        out += c_int.to_bytes(k, "big")
    return bytes(out)


def decrypt(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    """Decrypt bytes produced by encrypt()."""
    k = private_key.key_size_bytes
    if len(ciphertext) % k != 0 or len(ciphertext) == 0:
        raise ValueError("ciphertext length is not a multiple of the key size")

    out = bytearray()
    for i in range(0, len(ciphertext), k):
        block = ciphertext[i : i + k]
        c_int = int.from_bytes(block, "big")
        m_int = decrypt_int(c_int, private_key)
        padded = m_int.to_bytes(k, "big")
        out += pkcs1_v15_unpad(padded, k, block_type=2)
    return bytes(out)


def sign(message: bytes, private_key: PrivateKey) -> bytes:
    """Hash-then-sign: SHA-256(message), pad, raise to the private exponent."""
    digest = hashlib.sha256(message).digest()
    k = private_key.key_size_bytes
    padded = pkcs1_v15_pad(digest, k, block_type=1)
    m_int = int.from_bytes(padded, "big")
    s_int = decrypt_int(m_int, private_key)  # "decrypt" = raise to d, same op
    return s_int.to_bytes(k, "big")


def verify(message: bytes, signature: bytes, public_key: PublicKey) -> bool:
    """Verify a signature produced by sign(). Returns True/False, never raises
    on a bad signature (tampering just makes verification fail)."""
    k = public_key.key_size_bytes
    if len(signature) != k:
        return False

    try:
        s_int = int.from_bytes(signature, "big")
        m_int = encrypt_int(s_int, public_key)  # "encrypt" = raise to e
        padded = m_int.to_bytes(k, "big")
        recovered_digest = pkcs1_v15_unpad(padded, k, block_type=1)
    except ValueError:
        return False

    expected_digest = hashlib.sha256(message).digest()
    # Constant-time-ish comparison to avoid trivial timing side channels.
    return len(recovered_digest) == len(
        expected_digest
    ) and _constant_time_equal(recovered_digest, expected_digest)


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
