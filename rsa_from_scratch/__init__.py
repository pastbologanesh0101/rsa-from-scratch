"""
rsa_from_scratch
================

A from-scratch, educational implementation of RSA public-key cryptography
using only Python's standard library (big integers + ``secrets`` for
cryptographically secure randomness).

This package is for **learning**, not production use. See the top-level
README.md for a full explanation of the math and the security caveats.
"""

from .keygen import PrivateKey, PublicKey, generate_keypair
from .core import encrypt_int, decrypt_int
from .padding import pkcs1_v15_pad, pkcs1_v15_unpad
from .rsa import encrypt, decrypt, sign, verify

__all__ = [
    "PrivateKey",
    "PublicKey",
    "generate_keypair",
    "encrypt_int",
    "decrypt_int",
    "pkcs1_v15_pad",
    "pkcs1_v15_unpad",
    "encrypt",
    "decrypt",
    "sign",
    "verify",
]
