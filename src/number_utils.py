"""Modular arithmetic helpers and integer/octet-string conversion primitives."""


def ext_gcd(a, b):
    """Iterative extended Euclidean algorithm.

    Returns a tuple (g, x, y) such that a*x + b*y == g == gcd(a, b).
    The iterative form avoids Python's recursion limit for large inputs.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def mod_inverse(a, m):
    """Compute the modular multiplicative inverse of a modulo m."""
    if m <= 0:
        raise ValueError("modulus must be positive")
    g, x, _ = ext_gcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def i2osp(value, length):
    """Integer to octet string primitive (big-endian, fixed length)."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if value >= 1 << (8 * length):
        raise ValueError("integer is too large to fit in the given length")
    return value.to_bytes(length, byteorder="big")


def os2ip(octets):
    """Octet string to integer primitive (big-endian)."""
    return int.from_bytes(octets, byteorder="big")
