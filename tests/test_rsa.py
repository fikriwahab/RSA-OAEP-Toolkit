"""Self-tests for RSA key generation and primitive operations."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from prng import random_int_below
from rsa import generate_keypair, rsaep, rsadp


TEST_BITS = 1024  # smaller modulus keeps the test loop reasonably fast


def test_keygen_relations():
    public_key, private_key = generate_keypair(TEST_BITS)
    n = public_key["n"]
    e = public_key["e"]
    d = private_key["d"]
    p = private_key["p"]
    q = private_key["q"]
    if p * q != n:
        raise AssertionError("n != p * q")
    phi = (p - 1) * (q - 1)
    if (e * d) % phi != 1:
        raise AssertionError("e * d mod phi is not 1")
    if n.bit_length() != TEST_BITS:
        raise AssertionError("modulus has wrong bit length: " + str(n.bit_length()))
    if private_key["dP"] != d % (p - 1):
        raise AssertionError("dP is incorrect")
    if private_key["dQ"] != d % (q - 1):
        raise AssertionError("dQ is incorrect")
    if (private_key["qInv"] * q) % p != 1:
        raise AssertionError("qInv is incorrect")


def test_primitive_round_trip():
    public_key, private_key = generate_keypair(TEST_BITS)
    n = public_key["n"]
    for _ in range(5):
        m = random_int_below(n - 1) + 1
        c = rsaep(public_key, m)
        m_back = rsadp(private_key, c)
        if m_back != m:
            raise AssertionError("primitive round trip failed")


def test_crt_matches_textbook():
    public_key, private_key = generate_keypair(TEST_BITS)
    textbook = {"n": private_key["n"], "d": private_key["d"]}
    for _ in range(3):
        m = random_int_below(public_key["n"] - 1) + 1
        c = rsaep(public_key, m)
        if rsadp(private_key, c) != rsadp(textbook, c):
            raise AssertionError("CRT decryption disagrees with textbook formula")


def main():
    print("[*] rsa: generating " + str(TEST_BITS) + "-bit keys for verification...")
    start = time.time()
    test_keygen_relations()
    test_primitive_round_trip()
    test_crt_matches_textbook()
    elapsed = time.time() - start
    print("[*] rsa: all checks passed in " + format(elapsed, ".2f") + "s")


if __name__ == "__main__":
    main()
