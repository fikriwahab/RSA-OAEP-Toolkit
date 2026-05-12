"""Self-tests for the pure Python SHA-256 implementation."""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from prng import random_bytes, random_int_below
from sha256 import sha256


def expect_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(label + ": expected " + expected.hex() + " but got " + actual.hex())


def test_known_vectors():
    expect_equal(
        sha256(b""),
        bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "empty input",
    )
    expect_equal(
        sha256(b"abc"),
        bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "short input",
    )
    expect_equal(
        sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        bytes.fromhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        "two-block input",
    )
    expect_equal(
        sha256(b"a" * 1000000),
        bytes.fromhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        "one million a's",
    )


def test_random_against_reference():
    for _ in range(20):
        size = random_int_below(2048)
        data = random_bytes(size)
        expect_equal(sha256(data), hashlib.sha256(data).digest(), "random size " + str(size))


def main():
    test_known_vectors()
    test_random_against_reference()
    print("[*] sha256: all checks passed")


if __name__ == "__main__":
    main()
