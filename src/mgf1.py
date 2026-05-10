"""Mask Generation Function 1 (MGF1) using SHA-256 as the underlying hash."""

from sha256 import sha256, DIGEST_SIZE


def mgf1(seed, mask_length):
    """Generate a mask of the requested length from the given seed.

    Output bytes are produced by hashing seed concatenated with a 4-byte
    big-endian counter, starting from zero, until the requested length is
    reached.
    """
    if mask_length < 0:
        raise ValueError("mask length must be non-negative")
    if mask_length > 0xffffffff * DIGEST_SIZE:
        raise ValueError("mask length is too large")
    output = bytearray()
    counter = 0
    while len(output) < mask_length:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        output += sha256(seed + counter_bytes)
        counter += 1
    return bytes(output[:mask_length])
