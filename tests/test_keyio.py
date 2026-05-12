"""Self-tests for key file serialization and parsing helpers."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from rsa import generate_keypair
from keyio import (
    save_public_key,
    save_private_key,
    load_key,
    to_public_key,
    to_private_key,
)


def test_public_key_round_trip():
    public_key, _ = generate_keypair(1024)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "pub.key")
        save_public_key(path, public_key)
        loaded = load_key(path)
        parsed = to_public_key(loaded)
        if parsed != public_key:
            raise AssertionError("public key round trip mismatch")


def test_private_key_round_trip():
    _, private_key = generate_keypair(1024)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "priv.key")
        save_private_key(path, private_key)
        loaded = load_key(path)
        parsed = to_private_key(loaded)
        for field in ("n", "d", "p", "q", "dP", "dQ", "qInv"):
            if parsed[field] != private_key[field]:
                raise AssertionError("private key field mismatch for " + field)


def test_private_key_without_crt_is_still_accepted():
    # CRT fields are optional in the file format by design.
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "plain_private.key")
        with open(path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN RSA-OAEP PRIVATE KEY-----\n")
            f.write("n=0f\n")
            f.write("d=03\n")
            f.write("-----END RSA-OAEP PRIVATE KEY-----\n")
        loaded = load_key(path)
        parsed = to_private_key(loaded)
        if parsed != {"n": 15, "d": 3}:
            raise AssertionError("unexpected private key parse result")


def test_invalid_format_raises():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "bad.key")
        with open(path, "w", encoding="utf-8") as f:
            f.write("not a key file\n")
        try:
            load_key(path)
        except ValueError:
            return
        raise AssertionError("expected ValueError for invalid key file format")


def test_missing_required_field_raises():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "missing.key")
        with open(path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN RSA-OAEP PUBLIC KEY-----\n")
            f.write("n=deadbeef\n")
            f.write("-----END RSA-OAEP PUBLIC KEY-----\n")
        try:
            load_key(path)
        except ValueError as exc:
            if "missing required field" not in str(exc):
                raise AssertionError("unexpected error text: " + str(exc))
            return
        raise AssertionError("expected ValueError for missing required field")


def test_type_conversion_rejects_wrong_type():
    with tempfile.TemporaryDirectory() as tmp:
        pub_path = os.path.join(tmp, "pub.key")
        priv_path = os.path.join(tmp, "priv.key")
        public_key, private_key = generate_keypair(1024)
        save_public_key(pub_path, public_key)
        save_private_key(priv_path, private_key)

        loaded_pub = load_key(pub_path)
        loaded_priv = load_key(priv_path)

        try:
            to_private_key(loaded_pub)
        except ValueError:
            pass
        else:
            raise AssertionError("expected to_private_key to reject a public key")

        try:
            to_public_key(loaded_priv)
        except ValueError:
            return
        raise AssertionError("expected to_public_key to reject a private key")


def main():
    test_public_key_round_trip()
    test_private_key_round_trip()
    test_private_key_without_crt_is_still_accepted()
    test_invalid_format_raises()
    test_missing_required_field_raises()
    test_type_conversion_rejects_wrong_type()
    print("[*] keyio: all checks passed")


if __name__ == "__main__":
    main()
