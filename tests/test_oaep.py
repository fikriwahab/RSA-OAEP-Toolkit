"""Self-tests for OAEP encoding and decoding."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from oaep import oaep_encode, oaep_decode, DecryptionError, HASH_LEN
from prng import random_bytes


K = 256  # 2048-bit modulus
MAX_MESSAGE = K - 2 * HASH_LEN - 2


def test_round_trip_various_lengths():
    for size in (0, 1, 16, 100, MAX_MESSAGE):
        message = random_bytes(size)
        encoded = oaep_encode(message, K)
        if len(encoded) != K:
            raise AssertionError("encoded length is " + str(len(encoded)))
        decoded = oaep_decode(encoded, K)
        if decoded != message:
            raise AssertionError("round trip failed for size " + str(size))


def test_message_too_long_raises():
    try:
        oaep_encode(b"\x00" * (MAX_MESSAGE + 1), K)
    except ValueError:
        return
    raise AssertionError("expected ValueError for oversized message")


def test_corrupted_ciphertext_raises():
    encoded = oaep_encode(b"hello world", K)
    tampered = bytearray(encoded)
    tampered[100] ^= 0xff
    try:
        oaep_decode(bytes(tampered), K)
    except DecryptionError:
        return
    raise AssertionError("expected DecryptionError for tampered input")


def test_wrong_length_raises():
    encoded = oaep_encode(b"hello", K)
    try:
        oaep_decode(encoded[:-1], K)
    except DecryptionError:
        return
    raise AssertionError("expected DecryptionError for wrong-length input")


def test_label_mismatch_raises():
    encoded = oaep_encode(b"payload", K, label=b"label-a")
    try:
        oaep_decode(encoded, K, label=b"label-b")
    except DecryptionError:
        return
    raise AssertionError("expected DecryptionError for label mismatch")


def test_label_round_trip():
    message = b"with a non-empty label"
    encoded = oaep_encode(message, K, label=b"context")
    decoded = oaep_decode(encoded, K, label=b"context")
    if decoded != message:
        raise AssertionError("label round trip failed")


def main():
    test_round_trip_various_lengths()
    test_message_too_long_raises()
    test_corrupted_ciphertext_raises()
    test_wrong_length_raises()
    test_label_mismatch_raises()
    test_label_round_trip()
    print("[*] oaep: all checks passed")


if __name__ == "__main__":
    main()
