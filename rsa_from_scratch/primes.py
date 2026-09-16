"""
Probabilistic primality testing (Miller-Rabin) and random prime generation.

Everything here uses only Python's arbitrary-precision integers and the
``secrets`` module for randomness -- no third-party crypto libraries.
"""

from __future__ import annotations

import secrets

# Small primes used to quickly reject obvious composites before paying for
# a full Miller-Rabin round.
_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97,
)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test.

    Returns False with certainty if ``n`` is composite, and True with
    probability at least ``1 - 4**-rounds`` if ``n`` is actually prime.
    With the default of 40 rounds, the chance of a false positive is
    astronomically small (well below 2**-80).
    """
    if n < 2:
        return False

    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 = 2^s * d with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random probable prime with exactly ``bits`` bits.

    The top bit is forced to 1 (so the number has exactly ``bits`` bits)
    and the bottom bit is forced to 1 (so it is odd), then we search
    upward for a value that passes Miller-Rabin.
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")

    while True:
        candidate = secrets.randbits(bits)
        # Force top bit (correct bit length) and bottom bit (odd).
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
