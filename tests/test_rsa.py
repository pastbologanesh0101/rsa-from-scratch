"""
Unit tests for rsa_from_scratch.

Key sizes are kept small (128-256 bit primes) so the whole suite runs
quickly, including in CI. This is fine for testing correctness of the
algorithm; real usage should use much larger keys (see README.md).
"""

from __future__ import annotations

import unittest

from rsa_from_scratch.keygen import (
    extended_gcd,
    generate_keypair,
    mod_inverse,
)
from rsa_from_scratch.primes import generate_prime, is_probable_prime
from rsa_from_scratch.padding import pkcs1_v15_pad, pkcs1_v15_unpad
from rsa_from_scratch.core import decrypt_int, encrypt_int
from rsa_from_scratch.rsa import decrypt, encrypt, sign, verify

# Known primes and composites for direct Miller-Rabin checks.
KNOWN_PRIMES = [
    2, 3, 5, 7, 11, 13, 97, 997, 7919, 104729,
    2**31 - 1,  # Mersenne prime
    1_000_000_007,
]
KNOWN_COMPOSITES = [
    0, 1, 4, 6, 8, 9, 100, 1024, 10**18,
    561,  # smallest Carmichael number (a known Miller-Rabin "trap" if implemented wrong)
    41041,  # another Carmichael number
]


class TestMillerRabin(unittest.TestCase):
    def test_known_primes_are_identified_as_prime(self):
        for p in KNOWN_PRIMES:
            with self.subTest(p=p):
                self.assertTrue(is_probable_prime(p), f"{p} should be prime")

    def test_known_composites_are_identified_as_composite(self):
        for c in KNOWN_COMPOSITES:
            with self.subTest(c=c):
                self.assertFalse(is_probable_prime(c), f"{c} should be composite")

    def test_carmichael_numbers_rejected(self):
        # Carmichael numbers pass Fermat's test for many bases but Miller-Rabin
        # (which checks strong pseudoprimality) should still reject them.
        for c in (561, 1105, 1729, 2465, 2821, 6601, 8911):
            with self.subTest(c=c):
                self.assertFalse(is_probable_prime(c))

    def test_generated_primes_are_actually_prime_and_right_size(self):
        for bits in (64, 128):
            with self.subTest(bits=bits):
                p = generate_prime(bits)
                self.assertTrue(is_probable_prime(p))
                self.assertEqual(p.bit_length(), bits)
                self.assertEqual(p % 2, 1)


class TestExtendedEuclid(unittest.TestCase):
    def test_extended_gcd_bezout_identity(self):
        cases = [(240, 46), (17, 5), (1, 1), (123456789, 987654321)]
        for a, b in cases:
            with self.subTest(a=a, b=b):
                g, x, y = extended_gcd(a, b)
                self.assertEqual(a * x + b * y, g)

    def test_mod_inverse_correctness(self):
        self.assertEqual((mod_inverse(3, 11) * 3) % 11, 1)
        self.assertEqual((mod_inverse(17, 3120) * 17) % 3120, 1)

    def test_mod_inverse_raises_when_not_coprime(self):
        with self.assertRaises(ValueError):
            mod_inverse(4, 8)


class TestKeyGeneration(unittest.TestCase):
    def test_keypair_satisfies_ed_congruent_1_mod_phi(self):
        for bits in (128, 256):
            with self.subTest(bits=bits):
                public_key, private_key = generate_keypair(bits=bits)
                phi = (private_key.p - 1) * (private_key.q - 1)
                self.assertEqual((public_key.e * private_key.d) % phi, 1)
                self.assertEqual(public_key.n, private_key.n)
                self.assertEqual(public_key.n, private_key.p * private_key.q)

    def test_small_bit_length_edge_case(self):
        # Very small keys should still produce a mathematically valid keypair.
        public_key, private_key = generate_keypair(bits=32)
        phi = (private_key.p - 1) * (private_key.q - 1)
        self.assertEqual((public_key.e * private_key.d) % phi, 1)
        # Round trip a tiny message through raw RSA math directly.
        m = 42
        c = encrypt_int(m, public_key)
        self.assertEqual(decrypt_int(c, private_key), m)


class TestPadding(unittest.TestCase):
    def test_pkcs1_pad_unpad_round_trip_encryption_block(self):
        k = 64
        data = b"hello world"
        padded = pkcs1_v15_pad(data, k, block_type=2)
        self.assertEqual(len(padded), k)
        self.assertEqual(pkcs1_v15_unpad(padded, k, block_type=2), data)

    def test_pkcs1_pad_unpad_round_trip_signature_block(self):
        k = 64
        digest = b"\x11" * 32
        padded = pkcs1_v15_pad(digest, k, block_type=1)
        self.assertEqual(len(padded), k)
        self.assertEqual(pkcs1_v15_unpad(padded, k, block_type=1), digest)

    def test_pkcs1_pad_rejects_data_too_long(self):
        with self.assertRaises(ValueError):
            pkcs1_v15_pad(b"x" * 100, 64, block_type=2)

    def test_pkcs1_unpad_rejects_corrupted_header(self):
        k = 64
        padded = bytearray(pkcs1_v15_pad(b"hi", k, block_type=2))
        padded[1] = 0x99  # corrupt the block type byte
        with self.assertRaises(ValueError):
            pkcs1_v15_unpad(bytes(padded), k, block_type=2)


class TestEncryptDecrypt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.private_key = generate_keypair(bits=256)

    def test_round_trip_arbitrary_messages(self):
        messages = [
            b"",
            b"a",
            b"hello, RSA!",
            b"\x00\x01\x02\x03\xff\xfe",  # bytes including null and 0xff
            b"x" * 20,  # near the single-block limit for a 256-bit-prime key
            b"y" * 200,  # spans multiple blocks
            "unicode text encoded: héllo wörld 🎉".encode("utf-8"),
        ]
        for message in messages:
            with self.subTest(message=message[:20]):
                ciphertext = encrypt(message, self.public_key)
                recovered = decrypt(ciphertext, self.private_key)
                self.assertEqual(recovered, message)

    def test_encryption_is_randomized(self):
        message = b"same message, different ciphertext"
        c1 = encrypt(message, self.public_key)
        c2 = encrypt(message, self.public_key)
        self.assertNotEqual(
            c1, c2, "PKCS#1 v1.5 encryption padding should be randomized"
        )
        # But both should still decrypt back to the original message.
        self.assertEqual(decrypt(c1, self.private_key), message)
        self.assertEqual(decrypt(c2, self.private_key), message)

    def test_decrypt_rejects_bit_flipped_ciphertext(self):
        message = b"integrity matters"
        ciphertext = bytearray(encrypt(message, self.public_key))
        ciphertext[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decrypt(bytes(ciphertext), self.private_key)


class TestSignVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.private_key = generate_keypair(bits=256)

    def test_sign_then_verify_succeeds(self):
        message = b"pay Alice 100 coins"
        signature = sign(message, self.private_key)
        self.assertTrue(verify(message, signature, self.public_key))

    def test_verify_fails_for_tampered_message(self):
        message = b"pay Alice 100 coins"
        signature = sign(message, self.private_key)
        tampered = b"pay Alice 900 coins"
        self.assertFalse(verify(tampered, signature, self.public_key))

    def test_verify_fails_for_tampered_signature(self):
        message = b"pay Alice 100 coins"
        signature = bytearray(sign(message, self.private_key))
        signature[-1] ^= 0x01
        self.assertFalse(verify(message, bytes(signature), self.public_key))

    def test_verify_fails_for_wrong_public_key(self):
        message = b"pay Alice 100 coins"
        signature = sign(message, self.private_key)
        other_public_key, _ = generate_keypair(bits=256)
        self.assertFalse(verify(message, signature, other_public_key))


if __name__ == "__main__":
    unittest.main()
