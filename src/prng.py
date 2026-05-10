"""Cryptographically secure random helpers, backed by the OS entropy source."""

import secrets


def random_bytes(n):
    """Return n random bytes."""
    if n < 0:
        raise ValueError("length must be non-negative")
    return secrets.token_bytes(n)


def random_int_below(n):
    """Return a random integer in the range [0, n)."""
    if n <= 0:
        raise ValueError("upper bound must be positive")
    return secrets.randbelow(n)


def random_bits(n):
    """Return a random unsigned integer of exactly n bits, with the top bit set."""
    if n < 1:
        raise ValueError("bit length must be positive")
    return secrets.randbits(n) | (1 << (n - 1))
