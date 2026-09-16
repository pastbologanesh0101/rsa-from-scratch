# RSA Implementation (from scratch)

A small, fully working implementation of the RSA public-key cryptosystem,
built from scratch in pure Python for **education**. No `cryptography`,
no `pycryptodome` -- just Python's built-in arbitrary-precision integers
and the `secrets` module for cryptographically secure randomness.

> **This is for learning how RSA works, not for protecting real secrets.**
> See [Security disclaimer](#security-disclaimer--for-education-only) below.

## What's implemented

- **Miller-Rabin primality test** (`rsa_from_scratch/primes.py`) -- a
  probabilistic test used to find large primes.
- **Random prime generation** of configurable bit length, built on top of
  Miller-Rabin.
- **Key generation** (`rsa_from_scratch/keygen.py`) -- picks primes `p`,
  `q`, computes `n = p*q` and `phi(n) = (p-1)(q-1)`, and derives the
  private exponent `d` as the modular inverse of the public exponent `e`
  modulo `phi(n)`, computed with the **extended Euclidean algorithm**
  (no shortcuts, no `pow(e, -1, phi)`).
- **Raw ("textbook") RSA** (`rsa_from_scratch/core.py`) -- the bare
  `c = m^e mod n` / `m = c^d mod n` operations. Exposed for learning, but
  deliberately not the recommended public API (see below).
- **PKCS#1 v1.5-style padding** (`rsa_from_scratch/padding.py`), built
  from scratch:
  - Encryption padding uses **random, non-zero padding bytes**, so the
    same message encrypted twice produces different ciphertext.
  - Signature padding uses fixed `0xFF` padding bytes (deterministic on
    purpose -- see below).
- **Padded encrypt/decrypt of arbitrary byte strings**
  (`rsa_from_scratch/rsa.py`) -- automatically splits long messages into
  blocks, pads and encrypts each one, and reassembles them on decrypt.
- **Hash-then-sign / verify** -- messages are hashed with `hashlib.sha256`
  before signing, so signatures are over a fixed-size digest regardless of
  message length.
- **`demo.py`** -- a CLI/demo script showing keygen -> encrypt -> decrypt
  and sign -> verify end to end.

## Quick start

```bash
# Full walkthrough with printed output at every step
python demo.py demo --bits 512

# Or use it as a tiny CLI
python demo.py keygen --bits 512
python demo.py encrypt --bits 512 --message "hello, RSA!"
python demo.py sign --bits 512 --message "hello, RSA!"
```

Or from Python:

```python
from rsa_from_scratch import generate_keypair, encrypt, decrypt, sign, verify

public_key, private_key = generate_keypair(bits=1024)  # ~2048-bit modulus

ciphertext = encrypt(b"attack at dawn", public_key)
plaintext = decrypt(ciphertext, private_key)
assert plaintext == b"attack at dawn"

signature = sign(b"pay Alice 100 coins", private_key)
assert verify(b"pay Alice 100 coins", signature, public_key)
assert not verify(b"pay Alice 900 coins", signature, public_key)  # tampered -> fails
```

## Running the tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
# or, if you have pytest installed:
pytest tests/ -v
```

The test suite uses small keys (128-256 bit primes) so it runs in a few
seconds; CI runs it on every push/PR via
[`.github/workflows/tests.yml`](.github/workflows/tests.yml) on Python
3.11 and 3.12.

## The math, briefly

### Key generation

1. Pick two large random primes `p` and `q` (found via repeated random
   sampling + Miller-Rabin testing -- prime numbers are dense enough that
   this converges quickly).
2. Compute the modulus `n = p * q`.
3. Compute Euler's totient `phi(n) = (p - 1) * (q - 1)`. Because `n` is a
   product of exactly two distinct primes, `phi(n)` counts exactly the
   integers in `[1, n)` that are coprime to `n`.
4. Pick a public exponent `e` (this project defaults to `65537`, a common
   choice: small enough for fast encryption, and its bit pattern
   `0b10000000000000001` keeps modular exponentiation cheap).
5. Compute the private exponent `d` as the modular inverse of `e` modulo
   `phi(n)`, i.e. the unique `d` such that `e * d ≡ 1 (mod phi(n))`. This
   project computes `d` with the **extended Euclidean algorithm**, which
   finds integers `x, y` such that `e*x + phi(n)*y = gcd(e, phi(n))`; when
   `gcd(e, phi(n)) = 1` (required for an inverse to exist), `x mod phi(n)`
   is exactly `d`.

The public key is `(n, e)`; the private key is `(n, d)` (this project also
keeps `p, q` around for reference, though they aren't needed once `d` is
known).

### Why encryption and decryption undo each other: Euler's theorem

Encryption computes `c = m^e mod n`; decryption computes `c^d mod n`.
Substituting, decryption computes `(m^e)^d mod n = m^(e*d) mod n`.

Because `d` was chosen so that `e*d ≡ 1 (mod phi(n))`, we can write
`e*d = 1 + k*phi(n)` for some integer `k`. **Euler's theorem** says that
for any `m` coprime to `n`, `m^phi(n) ≡ 1 (mod n)`. So:

```
m^(e*d) mod n = m^(1 + k*phi(n)) mod n = m * (m^phi(n))^k mod n = m * 1^k mod n = m mod n
```

That's the whole trick: `d` is defined precisely so that raising to `e`
then to `d` (or vice versa) is the identity function modulo `n`, and
Euler's theorem is why that congruence on the exponents translates into
an actual round trip on the message.

(For `m` that share a factor with `n`, a very similar argument via the
Chinese Remainder Theorem and Fermat's little theorem on `p` and `q`
separately shows the same round-trip property holds -- this is why RSA
correctness doesn't actually require every message to be coprime to `n`,
though in practice a random message essentially always is.)

### Why padding matters (not just "textbook RSA")

Raw/textbook RSA -- encrypting a message by treating it directly as the
integer `m` and computing `m^e mod n` -- is a *deterministic* function of
`m`. That's a real security problem even though the math above is sound:

- **Determinism leaks equality.** The same plaintext always produces the
  same ciphertext under the same key, so an attacker who sees two
  ciphertexts learns whether the underlying plaintexts are equal, and can
  mount chosen-plaintext dictionary attacks (e.g. try encrypting every
  plausible message and compare).
- **Malleability.** Textbook RSA is multiplicatively homomorphic:
  `Enc(m1) * Enc(m2) mod n = Enc(m1 * m2 mod n)`. An attacker who can get
  one message signed/decrypted can derive results for related messages
  without ever knowing the private key, breaking the intuitive notion
  that ciphertexts can't be tampered with meaningfully.
- **No structure/redundancy check.** There's nothing to verify that a
  decrypted value was actually a validly-encrypted message versus
  attacker-crafted garbage, which enables padding-oracle-style attacks in
  real protocols.

This project pads messages using a **PKCS#1 v1.5-style scheme** before
the raw RSA step:

```
0x00 || 0x02 || PS (random, non-zero bytes) || 0x00 || message
```

The random padding bytes mean two encryptions of the same message produce
different ciphertext (see `test_encryption_is_randomized` in
`tests/test_rsa.py`), which defeats the determinism problem above, and the
fixed structure (leading `0x00 0x02`, and a well-formed separator) gives
decryption something to validate, so garbled or tampered ciphertext is
rejected rather than silently "decrypting" to garbage.

(Real-world systems today generally use **OAEP** instead of PKCS#1 v1.5
for encryption, since PKCS#1 v1.5 has known padding-oracle vulnerabilities
in some deployment contexts -- see the security disclaimer below. This
project implements PKCS#1 v1.5 because it's simpler to build from scratch
and still clearly demonstrates *why padding is needed at all*, which is
the educational point.)

### Sign / verify: hash-then-sign

Signing is the same modular exponentiation, but with the roles of the
keys reversed (raise to the *private* exponent `d`) and applied to a
**hash of the message** rather than the message itself:

1. `digest = SHA-256(message)` -- a fixed-size (32-byte) fingerprint.
2. Pad the digest with **deterministic** PKCS#1 v1.5 signature padding
   (`0x00 || 0x01 || 0xFF...0xFF || 0x00 || digest`) -- deterministic here
   is correct and intentional, since a verifier must reconstruct the
   *exact* padded block to check the signature.
3. `signature = padded_digest^d mod n`.

Verification recomputes `padded_digest' = signature^e mod n`, unpads it,
and checks that the recovered digest equals `SHA-256(message)` computed
fresh from the message being checked. Hashing first means:

- Signatures are a fixed size regardless of message length.
- An attacker can't exploit RSA's multiplicative structure on the
  original message directly (they'd need to find another *message* whose
  hash relates multiplicatively to the original digest, which SHA-256's
  preimage resistance rules out in practice).

Any change to the message (or to the signature) changes the digest
comparison and verification fails -- see
`test_verify_fails_for_tampered_message` and
`test_verify_fails_for_tampered_signature` in `tests/test_rsa.py`.

## Project layout

```
rsa_from_scratch/
  primes.py    # Miller-Rabin + random prime generation
  keygen.py    # extended Euclidean algorithm, keypair generation
  core.py      # raw modpow encrypt_int/decrypt_int
  padding.py   # PKCS#1 v1.5-style padding (random for encryption, fixed for signing)
  rsa.py       # padded encrypt/decrypt (with chunking) + sign/verify
demo.py        # CLI / walkthrough script
tests/
  test_rsa.py  # unit tests
.github/workflows/tests.yml  # CI: runs tests on push/PR, Python 3.11 & 3.12
```

## Security disclaimer -- for education only

**Do not use this code to protect real secrets.** It is intentionally
written for clarity, not for production security. Specific things a real
RSA implementation needs that this project skips or simplifies:

- **Key size.** This project defaults to relatively small keys for demo
  speed (e.g. 512-bit primes -> ~1024-bit modulus in `demo.py`, and
  128-256 bit primes in tests). Real-world RSA requires **2048-bit keys
  at minimum** (3072+ recommended for longer-term security); anything
  smaller is breakable with modern factoring techniques and hardware.
- **Padding scheme.** This uses PKCS#1 v1.5, not OAEP. OAEP is generally
  preferred for new systems because PKCS#1 v1.5 has a history of
  padding-oracle attacks (e.g. the Bleichenbacher attack) in real network
  protocols where timing/error responses leak information. This project's
  padding logic has not been hardened against timing side channels.
- **No constant-time big-integer arithmetic.** Python's built-in `pow()`
  and integer operations are not guaranteed constant-time with respect to
  the private exponent, which matters for resisting timing attacks in
  adversarial settings.
- **No side-channel hardening in general** (blinding, etc.) that
  production libraries implement.
- **No hardening in prime generation** against weak-modulus patterns
  (e.g. requiring `p` and `q` be sufficiently far apart), beyond simply
  requiring `p != q`.

For anything that actually needs to be secure, use a vetted, actively
maintained library (e.g. `cryptography` in Python) instead of hand-rolled
crypto -- including this project.
