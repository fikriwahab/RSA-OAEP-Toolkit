"""RSA key generation and primitive operations.

Private keys carry the Chinese Remainder Theorem parameters so that decryption
can run roughly four times faster than the textbook formulation.
"""

import math

from prime_gen import generate_prime
from number_utils import mod_inverse


PUBLIC_EXPONENT = 65537


def generate_keypair(bits=2048):
    """Generate a fresh (public_key, private_key) pair with the given modulus size.

    Both keys are returned as plain dictionaries. The private key includes the
    CRT parameters dP, dQ, and qInv in addition to n, d, p, and q.
    """
    if bits < 32 or bits % 2 != 0:
        raise ValueError("bit size must be even and at least 32")
    half = bits // 2
    min_distance = 1 << (half - 100)
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        if abs(p - q) <= min_distance:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(PUBLIC_EXPONENT, phi) != 1:
            continue
        d = mod_inverse(PUBLIC_EXPONENT, phi)
        public_key = {"n": n, "e": PUBLIC_EXPONENT}
        private_key = {
            "n": n,
            "d": d,
            "p": p,
            "q": q,
            "dP": d % (p - 1),
            "dQ": d % (q - 1),
            "qInv": mod_inverse(q, p),
        }
        return public_key, private_key


def rsaep(public_key, message_int):
    """RSA encryption primitive: c = m**e mod n."""
    n = public_key["n"]
    e = public_key["e"]
    if message_int < 0 or message_int >= n:
        raise ValueError("message representative out of range")
    return pow(message_int, e, n)


def rsadp(private_key, ciphertext_int):
    """RSA decryption primitive.

    Uses the CRT path when p, q, dP, dQ, and qInv are present, otherwise
    falls back to the direct m = c**d mod n form.
    """
    n = private_key["n"]
    if ciphertext_int < 0 or ciphertext_int >= n:
        raise ValueError("ciphertext representative out of range")
    has_crt = all(field in private_key for field in ("p", "q", "dP", "dQ", "qInv"))
    if has_crt:
        p = private_key["p"]
        q = private_key["q"]
        m_p = pow(ciphertext_int, private_key["dP"], p)
        m_q = pow(ciphertext_int, private_key["dQ"], q)
        h = (private_key["qInv"] * (m_p - m_q)) % p
        return m_q + h * q
    return pow(ciphertext_int, private_key["d"], n)
