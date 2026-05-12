"""EME-OAEP encoding and decoding using SHA-256 as the hash function.

Implementation follows PKCS #1 v2.2 (RFC 8017) section 7.1. Decoding always
raises a single generic DecryptionError on any failure to avoid leaking
information about why a particular ciphertext was rejected.
"""

from sha256 import sha256, DIGEST_SIZE
from mgf1 import mgf1
from prng import random_bytes


HASH_LEN = DIGEST_SIZE


class DecryptionError(Exception):
    """Raised when an OAEP-encoded message cannot be successfully decoded."""


def _xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("xor inputs must have equal length")
    out = bytearray(len(a))
    for i in range(len(a)):
        out[i] = a[i] ^ b[i]
    return bytes(out)


def _const_time_eq(a, b):
    """Constant-time equality check for two byte strings of equal length."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def oaep_encode(message, k, label=b""):
    """Wrap a message with OAEP padding to produce a k-byte encoded block.

    The maximum supported message length is k - 2*hLen - 2 bytes, which is
    190 bytes when k is 256 (2048-bit modulus).
    """
    m_len = len(message)
    max_len = k - 2 * HASH_LEN - 2
    if max_len < 0:
        raise ValueError("modulus is too small for the chosen hash")
    if m_len > max_len:
        raise ValueError("message is too long for the given modulus size")
    label_hash = sha256(label)
    padding = b"\x00" * (max_len - m_len)
    data_block = label_hash + padding + b"\x01" + bytes(message)
    seed = random_bytes(HASH_LEN)
    db_mask = mgf1(seed, k - HASH_LEN - 1)
    masked_db = _xor_bytes(data_block, db_mask)
    seed_mask = mgf1(masked_db, HASH_LEN)
    masked_seed = _xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded, k, label=b""):
    """Recover the original message from an OAEP-padded block.

    Raises DecryptionError on any failure (length mismatch, label mismatch,
    invalid padding structure).
    """
    if k < 2 * HASH_LEN + 2 or len(encoded) != k:
        raise DecryptionError("decryption error")
    label_hash = sha256(label)
    leading_byte = encoded[0]
    masked_seed = encoded[1:1 + HASH_LEN]
    masked_db = encoded[1 + HASH_LEN:]
    seed_mask = mgf1(masked_db, HASH_LEN)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - HASH_LEN - 1)
    data_block = _xor_bytes(masked_db, db_mask)
    recovered_hash = data_block[:HASH_LEN]
    rest = data_block[HASH_LEN:]
    # Walk the entire tail to keep the comparison time mostly independent of
    # which condition fails first.
    separator_index = -1
    saw_unexpected_byte = False
    for i in range(len(rest)):
        byte = rest[i]
        if separator_index == -1:
            if byte == 0x01:
                separator_index = i
            elif byte != 0x00:
                saw_unexpected_byte = True
    hash_ok = _const_time_eq(recovered_hash, label_hash)
    if (
        leading_byte != 0
        or not hash_ok
        or separator_index == -1
        or saw_unexpected_byte
    ):
        raise DecryptionError("decryption error")
    return rest[separator_index + 1:]
