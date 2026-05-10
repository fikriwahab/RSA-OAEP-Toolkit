"""Pure Python SHA-256, following the FIPS 180-4 specification."""


# First 32 bits of the fractional parts of the cube roots of the first 64 primes.
_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


# First 32 bits of the fractional parts of the square roots of the first 8 primes.
_H_INIT = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)


_MASK32 = 0xffffffff
DIGEST_SIZE = 32
BLOCK_SIZE = 64


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _ch(x, y, z):
    return (x & y) ^ ((~x) & z)


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _big_sigma1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _small_sigma0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _small_sigma1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def _pad(message):
    """Append the SHA-256 length-prefixed padding to the message."""
    bit_length = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) % BLOCK_SIZE != 56:
        padded.append(0x00)
    padded += bit_length.to_bytes(8, byteorder="big")
    return bytes(padded)


def _process_block(block, h):
    """Run the compression function on one 64-byte block, updating h in place."""
    w = [0] * 64
    for i in range(16):
        offset = i * 4
        w[i] = int.from_bytes(block[offset:offset + 4], byteorder="big")
    for i in range(16, 64):
        s0 = _small_sigma0(w[i - 15])
        s1 = _small_sigma1(w[i - 2])
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        t1 = (hh + _big_sigma1(e) + _ch(e, f, g) + _K[i] + w[i]) & _MASK32
        t2 = (_big_sigma0(a) + _maj(a, b, c)) & _MASK32
        hh = g
        g = f
        f = e
        e = (d + t1) & _MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & _MASK32
    h[0] = (h[0] + a) & _MASK32
    h[1] = (h[1] + b) & _MASK32
    h[2] = (h[2] + c) & _MASK32
    h[3] = (h[3] + d) & _MASK32
    h[4] = (h[4] + e) & _MASK32
    h[5] = (h[5] + f) & _MASK32
    h[6] = (h[6] + g) & _MASK32
    h[7] = (h[7] + hh) & _MASK32


def sha256(data):
    """Return the SHA-256 digest of data as a 32-byte string."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be a bytes-like object")
    padded = _pad(bytes(data))
    h = list(_H_INIT)
    for offset in range(0, len(padded), BLOCK_SIZE):
        _process_block(padded[offset:offset + BLOCK_SIZE], h)
    output = bytearray(DIGEST_SIZE)
    for i in range(8):
        output[i * 4:i * 4 + 4] = h[i].to_bytes(4, byteorder="big")
    return bytes(output)
