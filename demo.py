#!/usr/bin/env python3
"""
Demo / CLI for rsa_from_scratch.

Run with no arguments for a full keygen -> encrypt -> decrypt and
sign -> verify walkthrough printed to stdout:

    python demo.py

Or use it as a tiny CLI:

    python demo.py keygen --bits 512
    python demo.py encrypt --bits 512 --message "hello"
"""

from __future__ import annotations

import argparse
import sys
import time

from rsa_from_scratch import generate_keypair, encrypt, decrypt, sign, verify


def run_full_demo(bits: int) -> None:
    print(f"=== RSA from scratch: full demo (bits={bits} per prime) ===\n")

    print(f"[1/4] Generating a keypair ({bits}-bit primes p, q)...")
    t0 = time.time()
    public_key, private_key = generate_keypair(bits=bits)
    t1 = time.time()
    n_bits = public_key.n.bit_length()
    print(f"      done in {t1 - t0:.2f}s. n has {n_bits} bits.")
    print(f"      public key:  n={hex(public_key.n)[:40]}..., e={public_key.e}")
    print(f"      private key: d={hex(private_key.d)[:40]}...\n")

    message = b"Attack at dawn -- RSA from scratch demo message!"
    print(f"[2/4] Encrypting message: {message!r}")
    ciphertext1 = encrypt(message, public_key)
    ciphertext2 = encrypt(message, public_key)
    print(f"      ciphertext (run 1): {ciphertext1.hex()[:60]}...")
    print(f"      ciphertext (run 2): {ciphertext2.hex()[:60]}...")
    print(
        "      -> same plaintext, different ciphertext each time "
        f"({'OK, randomized padding works' if ciphertext1 != ciphertext2 else 'BUG: not randomized!'})\n"
    )

    print("[3/4] Decrypting...")
    recovered = decrypt(ciphertext1, private_key)
    print(f"      recovered: {recovered!r}")
    print(f"      matches original: {recovered == message}\n")

    print("[4/4] Sign -> verify...")
    signature = sign(message, private_key)
    print(f"      signature: {signature.hex()[:60]}...")
    ok = verify(message, signature, public_key)
    print(f"      verify(original message, signature): {ok}")

    tampered = message + b" NOT!"
    ok_tampered = verify(tampered, signature, public_key)
    print(f"      verify(tampered message, signature): {ok_tampered}")

    tampered_sig = bytearray(signature)
    tampered_sig[-1] ^= 0x01
    ok_tampered_sig = verify(message, bytes(tampered_sig), public_key)
    print(f"      verify(original message, tampered signature): {ok_tampered_sig}")

    print("\nDone. See README.md for the math behind each step.")


def main() -> int:
    parser = argparse.ArgumentParser(description="RSA from scratch demo/CLI")
    sub = parser.add_subparsers(dest="command")

    demo_p = sub.add_parser("demo", help="Run the full keygen/encrypt/decrypt/sign/verify walkthrough")
    demo_p.add_argument("--bits", type=int, default=512, help="Bit length of each prime (default 512)")

    keygen_p = sub.add_parser("keygen", help="Generate a keypair and print it")
    keygen_p.add_argument("--bits", type=int, default=512)

    enc_p = sub.add_parser("encrypt", help="Generate a key, encrypt, then decrypt a message")
    enc_p.add_argument("--bits", type=int, default=512)
    enc_p.add_argument("--message", type=str, default="hello, RSA!")

    sign_p = sub.add_parser("sign", help="Generate a key, sign, then verify a message")
    sign_p.add_argument("--bits", type=int, default=512)
    sign_p.add_argument("--message", type=str, default="hello, RSA!")

    args = parser.parse_args()

    if args.command is None or args.command == "demo":
        run_full_demo(getattr(args, "bits", 512))
        return 0

    if args.command == "keygen":
        public_key, private_key = generate_keypair(bits=args.bits)
        print(f"n = {public_key.n}")
        print(f"e = {public_key.e}")
        print(f"d = {private_key.d}")
        return 0

    if args.command == "encrypt":
        public_key, private_key = generate_keypair(bits=args.bits)
        message = args.message.encode("utf-8")
        ciphertext = encrypt(message, public_key)
        print(f"ciphertext (hex): {ciphertext.hex()}")
        recovered = decrypt(ciphertext, private_key)
        print(f"recovered: {recovered.decode('utf-8')}")
        return 0

    if args.command == "sign":
        public_key, private_key = generate_keypair(bits=args.bits)
        message = args.message.encode("utf-8")
        signature = sign(message, private_key)
        print(f"signature (hex): {signature.hex()}")
        print(f"verify: {verify(message, signature, public_key)}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
