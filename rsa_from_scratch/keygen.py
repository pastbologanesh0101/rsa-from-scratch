"""
RSA key generation: choose primes p, q, derive n, e, d.

Uses the extended Euclidean algorithm to compute the modular inverse of e
modulo phi(n), rather than any library shortcut.
"""

from __future__ import annotations

from dataclasses import dataclass

from .primes import generate_prime

DEFAULT_PUBLIC_EXPONENT = 65537  # a common choice: small, and 2^16 + 1 is prime


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def key_size_bytes(self) -> int:
        """Size of the modulus n in bytes, rounded up."""
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    # p and q are kept only for reference/debugging; they are not required
    # for the raw decrypt operation once d is known.
    p: int
    q: int

    @property
    def key_size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Modular inverse of a mod m, via the extended Euclidean algorithm."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {m} (gcd={g})")
    return x % m


def generate_keypair(
    bits: int = 1024, e: int = DEFAULT_PUBLIC_EXPONENT
) -> tuple[PublicKey, PrivateKey]:
    """Generate an RSA keypair.

    ``bits`` is the bit length of *each* prime p and q, so the resulting
    modulus n is roughly ``2 * bits`` bits long. 1024-bit primes (-> a
    ~2048-bit modulus) are a reasonable, if slow-ish, educational default.
    Smaller sizes (e.g. 256-512 bit primes) are useful for fast unit tests.

    NOTE: this is for education. Real-world RSA key generation has extra
    hardening (e.g. avoiding p, q that are too close together, checking
    against known weak-modulus patterns) that this implementation skips
    for clarity.
    """
    if bits < 16:
        raise ValueError("bits must be >= 16 for e=65537 to make sense")

    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    if e >= phi or extended_gcd(e, phi)[0] != 1:
        # Extremely unlikely with e=65537 and reasonably sized primes, but
        # handle it deterministically instead of crashing.
        candidate = e if e % 2 == 1 else e + 1
        while extended_gcd(candidate, phi)[0] != 1 or candidate >= phi:
            candidate += 2
        e = candidate

    d = mod_inverse(e, phi)

    public_key = PublicKey(n=n, e=e)
    private_key = PrivateKey(n=n, d=d, p=p, q=q)
    return public_key, private_key
