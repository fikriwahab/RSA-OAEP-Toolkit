"""Probable prime generation using the Miller-Rabin primality test."""

import secrets


# Small primes used as a fast pre-filter before running Miller-Rabin.
SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
    223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
    293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
    383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
    463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
    569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
    647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
    743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
    839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
    941, 947, 953, 967, 971, 977, 983, 991, 997,
)


def _trial_division(n):
    """Return False if n shares a factor with any small prime, True otherwise.

    Returns True (passes) if n equals one of the small primes itself.
    """
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True


def is_probably_prime(n, rounds=40):
    """Miller-Rabin probabilistic primality test.

    The probability of falsely accepting a composite is at most (1/4)**rounds.
    """
    if n < 2:
        return False
    if not _trial_division(n):
        return False
    if n < SMALL_PRIMES[-1] * SMALL_PRIMES[-1]:
        # Trial division has fully decided this range.
        return True
    # Write n - 1 as d * 2**r with d odd.
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # uniform in [2, n - 2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def generate_prime(bits):
    """Generate a probable prime of exactly the requested bit length.

    The two highest bits and the lowest bit are forced to 1. Forcing the top
    two bits guarantees that the product of two such primes is exactly twice
    the bit length, which is useful for RSA modulus construction.
    """
    if bits < 16:
        raise ValueError("bit length must be at least 16")
    top_bits_mask = (3 << (bits - 2)) | 1
    while True:
        candidate = secrets.randbits(bits) | top_bits_mask
        if is_probably_prime(candidate):
            return candidate
