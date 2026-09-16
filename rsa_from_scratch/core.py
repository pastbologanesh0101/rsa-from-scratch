"""
Raw ("textbook") RSA encrypt/decrypt on a single integer.

This is deliberately *not* exported as the main public API for encrypting
bytes, because textbook RSA on its own is insecure (deterministic, and
malleable -- see README.md for details). It's the mathematical core that
the padded encrypt/decrypt/sign/verify functions in rsa.py build on.
"""

from __future__ import annotations

from .keygen import PrivateKey, PublicKey


def encrypt_int(m: int, public_key: PublicKey) -> int:
    """c = m^e mod n"""
    if not 0 <= m < public_key.n:
        raise ValueError("message integer out of range for this key's modulus")
    return pow(m, public_key.e, public_key.n)


def decrypt_int(c: int, private_key: PrivateKey) -> int:
    """m = c^d mod n"""
    if not 0 <= c < private_key.n:
        raise ValueError("ciphertext integer out of range for this key's modulus")
    return pow(c, private_key.d, private_key.n)
