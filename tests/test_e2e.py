"""End-to-end round-trip tests for every file in the samples directory."""

import hashlib
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from rsa import generate_keypair
from crypto import encrypt_file, decrypt_file
from oaep import DecryptionError


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
TEST_BITS = 2048


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def test_one_sample(public_key, private_key, sample_path):
    name = os.path.basename(sample_path)
    size = os.path.getsize(sample_path)
    print("[*] " + name + " (" + str(size) + " bytes)...", flush=True)
    start = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        cipher_path = os.path.join(tmp, name + ".enc")
        plain_back_path = os.path.join(tmp, name + ".dec")
        encrypt_file(sample_path, cipher_path, public_key)
        decrypt_file(cipher_path, plain_back_path, private_key)
        original_hash = file_hash(sample_path)
        recovered_hash = file_hash(plain_back_path)
        if original_hash != recovered_hash:
            raise AssertionError("round trip hash mismatch for " + name)
        recovered_size = os.path.getsize(plain_back_path)
        if recovered_size != size:
            raise AssertionError("round trip size mismatch for " + name)
    elapsed = time.time() - start
    print("    ok in " + format(elapsed, ".2f") + "s")


def _round_trip_with_payload(public_key, private_key, payload, expected_cipher_size):
    with tempfile.TemporaryDirectory() as tmp:
        plain_path = os.path.join(tmp, "plain.bin")
        cipher_path = os.path.join(tmp, "cipher.bin")
        recovered_path = os.path.join(tmp, "recovered.bin")
        with open(plain_path, "wb") as f:
            f.write(payload)
        encrypt_file(plain_path, cipher_path, public_key)
        cipher_size = os.path.getsize(cipher_path)
        if cipher_size != expected_cipher_size:
            raise AssertionError(
                "ciphertext size " + str(cipher_size)
                + " does not match expected " + str(expected_cipher_size)
            )
        decrypt_file(cipher_path, recovered_path, private_key)
        with open(recovered_path, "rb") as f:
            recovered = f.read()
        if recovered != payload:
            raise AssertionError("round trip payload mismatch")


def test_empty_file_round_trip(public_key, private_key):
    # edge case: 0-byte plaintext should round-trip to an identical empty file
    _round_trip_with_payload(public_key, private_key, b"", expected_cipher_size=0)


def test_single_byte_round_trip(public_key, private_key):
    # edge case: 1-byte plaintext fits in one OAEP block with maximum padding
    _round_trip_with_payload(public_key, private_key, b"X", expected_cipher_size=256)


def test_exactly_one_block_round_trip(public_key, private_key):
    # edge case: 190 bytes is the maximum plaintext per block, expect one ciphertext block
    payload = bytes(range(256))[:190]
    _round_trip_with_payload(public_key, private_key, payload, expected_cipher_size=256)


def test_just_over_one_block_round_trip(public_key, private_key):
    # edge case: 191 bytes forces a second OAEP block carrying a single byte
    payload = bytes(range(256))[:190] + b"!"
    _round_trip_with_payload(public_key, private_key, payload, expected_cipher_size=512)


def test_wrong_key_decryption_fails(public_key_a, private_key_b):
    # edge case: ciphertext produced under key A must not decrypt under key B
    with tempfile.TemporaryDirectory() as tmp:
        plain_path = os.path.join(tmp, "msg.bin")
        cipher_path = os.path.join(tmp, "msg.enc")
        recovered_path = os.path.join(tmp, "msg.dec")
        with open(plain_path, "wb") as f:
            f.write(b"sensitive payload that should not survive a key swap")
        encrypt_file(plain_path, cipher_path, public_key_a)
        try:
            decrypt_file(cipher_path, recovered_path, private_key_b)
        except DecryptionError:
            return
        raise AssertionError("decryption succeeded with the wrong private key")


def test_tampered_middle_block_fails(public_key, private_key):
    # edge case: flipping a byte inside a non-trailing ciphertext block must raise DecryptionError
    payload = b"first block padding " * 20
    with tempfile.TemporaryDirectory() as tmp:
        plain_path = os.path.join(tmp, "multi.bin")
        cipher_path = os.path.join(tmp, "multi.enc")
        recovered_path = os.path.join(tmp, "multi.dec")
        with open(plain_path, "wb") as f:
            f.write(payload)
        encrypt_file(plain_path, cipher_path, public_key)
        if os.path.getsize(cipher_path) < 512:
            raise AssertionError("expected at least two ciphertext blocks for a multi-block test")
        with open(cipher_path, "rb") as f:
            buffer = bytearray(f.read())
        buffer[100] ^= 0xff
        with open(cipher_path, "wb") as f:
            f.write(buffer)
        try:
            decrypt_file(cipher_path, recovered_path, private_key)
        except DecryptionError:
            return
        raise AssertionError("decryption succeeded despite a tampered ciphertext block")


def main():
    print("[*] e2e: generating " + str(TEST_BITS) + "-bit key pair...", flush=True)
    start = time.time()
    public_key, private_key = generate_keypair(TEST_BITS)
    print("    keypair ready in " + format(time.time() - start, ".2f") + "s")

    print("[*] e2e: edge case checks", flush=True)
    test_empty_file_round_trip(public_key, private_key)
    print("    empty file: ok")
    test_single_byte_round_trip(public_key, private_key)
    print("    single byte: ok")
    test_exactly_one_block_round_trip(public_key, private_key)
    print("    exactly one block (190 bytes): ok")
    test_just_over_one_block_round_trip(public_key, private_key)
    print("    just over one block (191 bytes): ok")
    print("    generating second key pair for wrong-key test...", flush=True)
    public_key_b, private_key_b = generate_keypair(TEST_BITS)
    test_wrong_key_decryption_fails(public_key, private_key_b)
    print("    wrong key rejected: ok")
    test_tampered_middle_block_fails(public_key, private_key)
    print("    tampered middle block rejected: ok")

    if os.path.isdir(SAMPLES_DIR):
        samples = []
        for name in sorted(os.listdir(SAMPLES_DIR)):
            path = os.path.join(SAMPLES_DIR, name)
            if os.path.isfile(path):
                samples.append(path)
        if samples:
            print("[*] e2e: round-trip every sample", flush=True)
            for sample in samples:
                test_one_sample(public_key, private_key, sample)
    print("[*] e2e: all checks passed")


if __name__ == "__main__":
    main()
